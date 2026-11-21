"""Security Center: fixes of the fourth review of PR 58 (against ead377e).

One block per finding. Every test started red. No Home Assistant instance,
no router: the center runs on in-memory stores, the module key comes from a
fake core binding.
"""

from __future__ import annotations

import asyncio
import copy
import logging
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from test_net_engine import make_hass
from test_security_center import (
    MODULE_KEY,
    RID1,
    T0,
    center_for,
    disks,  # noqa: F401 - fixture
    sec_disk,
)
from test_security_review2 import auth_event, poll_facts
from test_security_review3 import (
    forged,
    keyed_center,
    log_hints,
    other_hint,
    wifi_hint,
)

from custom_components.openwrt_router import security_center as sc
from custom_components.openwrt_router.const import (
    SEC_INCIDENT_AUTO_RESOLVE_SECONDS,
    SEC_INCIDENT_CAP,
)
from custom_components.openwrt_router.security_model import Availability
from custom_components.openwrt_router.security_rules import (
    DetectorResult,
    WifiAssocBurstDetector,
)
from custom_components.openwrt_router.security_trust import TrustState

QUOTA = 50  # decided: 50 hints from the syslog receiver, 50 from all others


def other_hints(center: Any) -> list[dict[str, Any]]:
    return [i for i in center.incidents.values() if i.get("from_logs") is not True]


def kinds(center: Any, kind: str) -> list[dict[str, Any]]:
    return [t for t in center.timeline if t["kind"] == kind]


# --- 1: two fixed quotas, no displacement between the classes -------------------------


async def test_review4_1a_syslog_flood_leaves_room_for_wifi_hints(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    for i in range(300):
        center._record(forged(i, T0 + i), T0 + i)
    assert len(log_hints(center)) == QUOTA == len(center.incidents)
    assert center.counters["incidents_log_quota_dropped"] == 300 - QUOTA
    assert len(kinds(center, "log_quota_reached")) == 1  # once per window
    for n in range(QUOTA):
        center._record(other_hint(n, T0 + 400 + n), T0 + 400 + n)
    assert len(other_hints(center)) == QUOTA
    assert len(center.incidents) == SEC_INCIDENT_CAP
    assert center.counters["incidents_other_quota_dropped"] == 0
    assert center.counters["incidents_cap_dropped"] == 0
    assert kinds(center, "other_quota_reached") == []


async def test_review4_1b_wifi_flood_neither_displaces_nor_blocks_firewall_hints(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    for i in range(10):
        center._record(forged(i, T0 + i), T0 + i)
    firewall = {i["id"] for i in log_hints(center)}
    # 100 findings of the other class: 40 Wi-Fi (their share since 1.46.2,
    # test_security_low1462) and drift
    for n in range(100):
        center._record(other_hint(n, T0 + 100 + n), T0 + 100 + n)
    assert firewall <= set(center.incidents)  # open firewall hints stand
    assert all(center.incidents[i]["status"] == "open" for i in firewall)
    assert len(other_hints(center)) == QUOTA
    assert center.counters["incidents_other_quota_dropped"] == 100 - QUOTA
    assert len(kinds(center, "other_quota_reached")) == 1
    # new firewall findings still get through, up to their own quota
    for i in range(100, 160):
        center._record(forged(i, T0 + 300 + i), T0 + 300 + i)
    assert len(log_hints(center)) == QUOTA
    assert center.counters["incidents_log_quota_dropped"] == 10 + 60 - QUOTA
    assert center.counters["incidents_cap_dropped"] == 0
    assert len(other_hints(center)) == QUOTA
    # no displacement any more: counter and timeline kind are gone
    assert "incidents_displaced" not in center.counters
    assert kinds(center, "log_displaced") == []
    limits = center.overview(actor=None, now=T0 + 900)["limits"]
    assert "incidents_displaced" not in limits
    assert limits["log_incident_quota"] == QUOTA
    assert limits["other_incident_quota"] == QUOTA
    assert limits["log_incidents"] == QUOTA
    assert limits["other_incidents"] == QUOTA
    assert limits["incidents_other_quota_dropped"] == 100 - QUOTA
    assert limits["incidents_log_quota_dropped"] == 10 + 60 - QUOTA
    counters = center.diagnostics()["counters"]
    assert counters["incidents_other_quota_dropped"] == 100 - QUOTA
    assert "incidents_displaced" not in counters


async def test_review4_1c_resolved_hints_make_room_within_their_class_only(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    for n in range(QUOTA):
        center._record(other_hint(n, T0 + n), T0 + n)
    for i in range(QUOTA):
        center._record(forged(i, T0 + 100 + i), T0 + 100 + i)
    ordered = sorted(other_hints(center), key=lambda i: i["last_seen"])
    ordered[0]["status"] = "resolved"
    ordered[1]["status"] = "resolved"
    for inc in ordered[2:5]:
        inc["status"] = "confirmed"  # confirmed hints count in their class
    resolved_log = min(log_hints(center), key=lambda i: i["last_seen"])
    resolved_log["status"] = "resolved"
    center._record(other_hint(500, T0 + 900), T0 + 900)
    assert ordered[0]["id"] not in center.incidents  # oldest resolved first
    assert ordered[1]["id"] in center.incidents
    center._record(other_hint(501, T0 + 901), T0 + 901)
    assert ordered[1]["id"] not in center.incidents
    before = set(center.incidents)
    center._record(other_hint(502, T0 + 902), T0 + 902)
    assert set(center.incidents) == before  # open and confirmed stay
    assert center.counters["incidents_other_quota_dropped"] == 1
    # the resolved log hint was not touched by the other class
    assert resolved_log["id"] in center.incidents
    assert center.counters["incidents_log_quota_dropped"] == 0


def _store_with(center: Any, plan: list[tuple[bool, str, float]]) -> dict[str, Any]:
    """A saved store whose hints follow ``plan`` (from_logs, status, last_seen)."""
    center._record(forged(0, T0), T0)
    center._record(wifi_hint(0, T0), T0)
    stored = center._data_to_save()
    templates = {bool(i["from_logs"]): i for i in stored["incidents"]}
    items = []
    for n, (from_logs, status, last) in enumerate(plan):
        item = copy.deepcopy(templates[from_logs])
        item["id"] = f"sec_{n:08x}"
        item["scope"] = f"{item['scope']}|{n}"
        item["status"] = status
        item["first_seen"] = last
        item["last_seen"] = last
        items.append(item)
    stored["incidents"] = items
    stored["timeline"] = []
    return stored


async def test_review4_1d_old_store_over_a_quota_loads_without_deleting(
    disks,  # noqa: F811
) -> None:
    plan = [(False, "open", T0 + n) for n in range(70)]
    plan += [(True, "open", T0 + 100 + n) for n in range(30)]
    stored = _store_with(await keyed_center(make_hass(), "r1"), plan)
    sec_disk(disks).data = stored
    center = await keyed_center(make_hass(), "r1")
    assert len(center.incidents) == 100  # nothing is deleted
    assert len(other_hints(center)) == 70
    assert all(i["status"] == "open" for i in center.incidents.values())
    # the full class takes no new hint; nothing open is removed
    center._record(other_hint(900, T0 + 900), T0 + 900)
    assert center.counters["incidents_other_quota_dropped"] == 1
    assert len(center.incidents) == 100
    # the store is full: a log hint waits until the other class heals
    center._record(forged(900, T0 + 901), T0 + 901)
    assert center.counters["incidents_cap_dropped"] == 1
    assert len(log_hints(center)) == 30
    # a resolved hint of the class above its quota makes room (healing)
    oldest = min(other_hints(center), key=lambda i: i["last_seen"])
    oldest["status"] = "resolved"
    center._record(forged(901, T0 + 902), T0 + 902)
    assert oldest["id"] not in center.incidents
    assert len(log_hints(center)) == 31
    assert len(other_hints(center)) == 69


async def test_review4_1e_store_above_the_cap_trims_the_class_above_its_quota(
    disks,  # noqa: F811
) -> None:
    # 105 hints: the log hints are the oldest, the other class is too big
    plan = [(True, "open", T0 + n) for n in range(45)]
    plan += [(False, "confirmed", T0 + 50 + n) for n in range(2)]
    plan += [(False, "open", T0 + 100 + n) for n in range(58)]
    stored = _store_with(await keyed_center(make_hass(), "r1"), plan)
    sec_disk(disks).data = stored
    center = await keyed_center(make_hass(), "r1")
    assert len(center.incidents) == SEC_INCIDENT_CAP
    assert len(log_hints(center)) == 45  # within its quota: untouched
    confirmed = [i for i in center.incidents.values() if i["status"] == "confirmed"]
    assert len(confirmed) == 2
    assert len(other_hints(center)) == 55
    # the five oldest OPEN hints of the class above its quota went
    kept = {i["last_seen"] for i in other_hints(center) if i["status"] == "open"}
    assert min(kept) == T0 + 105


# --- 2: a confirmed hint seen again: one entry per window -----------------------------


async def test_review4_2_seen_again_once_per_window_and_on_rising_severity(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    center._record(auth_event(RID1, now=T0), T0)
    (inc,) = center.incidents.values()
    inc["status"] = "confirmed"
    quiet = SEC_INCIDENT_AUTO_RESOLVE_SECONDS + 60
    now = T0 + 600
    # forged times jump a quiet time ahead each line, all within one poll
    last = T0
    for k in range(1, 6):
        last = T0 + k * quiet
        center._record(auth_event(RID1, now=last), now)
    assert len(kinds(center, "incident_seen_again")) == 1
    assert inc["seen_again_at"] == now
    # rising severity: always an entry, also within the window
    hot = replace(auth_event(RID1, now=last + 1), severity=sc.Severity.CRITICAL)
    center._record(hot, now + 1)
    assert len(kinds(center, "incident_seen_again")) == 2
    assert inc["severity"] == "critical"
    center._record(replace(hot, ts=last + quiet), now + 2)
    assert len(kinds(center, "incident_seen_again")) == 2  # same severity
    # the time of the last entry survives a restart ...
    await center.async_flush()
    again = await keyed_center(make_hass(), "r1")
    (back,) = again.incidents.values()
    assert back["seen_again_at"] == now + 1
    again._record(replace(hot, ts=last + 2 * quiet), now + 3)
    assert len(kinds(again, "incident_seen_again")) == 2
    # ... after the window the next quiet return gets its entry
    later = now + 1 + SEC_INCIDENT_AUTO_RESOLVE_SECONDS
    again._record(replace(hot, ts=last + 4 * quiet), later)
    assert len(kinds(again, "incident_seen_again")) == 3
    # a store from before the field loads
    stored = again._data_to_save()
    for item in stored["incidents"]:
        item.pop("seen_again_at", None)
    sec_disk(disks).data = stored
    old = await keyed_center(make_hass(), "r1")
    (loaded,) = old.incidents.values()
    assert loaded["seen_again_at"] is None


# --- 3: housekeeping resolves nothing while the module key is missing ----------------


async def test_review4_3_no_auto_resolve_without_module_key(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    center._record(auth_event(RID1, now=T0), T0)
    (inc,) = center.incidents.values()
    center._module_key = None  # the key went away (core unbound)
    late = T0 + SEC_INCIDENT_AUTO_RESOLVE_SECONDS + 3600
    center._housekeeping(late)
    center.on_poll(poll_facts("r1", late + 60))
    assert inc["status"] == "open"
    assert center.counters["incidents_resolved"] == 0
    assert kinds(center, "incident_resolved") == []
    center._module_key = MODULE_KEY
    center._housekeeping(late + 120)
    # 1.46.2: quiet for a day since the key returned, not since last_seen
    assert inc["status"] == "open"
    center._housekeeping(late + 120 + SEC_INCIDENT_AUTO_RESOLVE_SECONDS + 60)
    assert inc["status"] == "resolved"
    assert len(kinds(center, "incident_resolved")) == 1


# --- 4: the module key is tried again from the poll ----------------------------------


async def test_review4_4_module_key_retry_from_the_poll(
    disks,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass = make_hass()
    tasks: list[Any] = []
    hass.async_create_task = lambda coro, name=None: tasks.append(coro)

    async def run() -> None:
        while tasks:
            await tasks.pop(0)

    center = await center_for(hass, "r1", module_key=None)
    secret = "02:00:5e:10:00:01 192.168.1.20 laptop-anna"
    api = SimpleNamespace(
        installation_key_state=sc.InstallationKeyState.OK,
        async_get_module_key=AsyncMock(
            side_effect=[RuntimeError(secret), RuntimeError(secret), MODULE_KEY]
        ),
    )
    center._binding = sc._Binding(core=object(), api=api, events_ok=True)
    interval = sc.SEC_MODULE_KEY_RETRY_SECONDS
    assert 60 <= interval <= 900
    caplog.set_level(logging.DEBUG, logger=sc.__name__)
    center.on_poll(poll_facts("r1", T0))
    await run()
    assert api.async_get_module_key.await_count == 1
    center.on_poll(poll_facts("r1", T0 + 60))  # within the interval: no try
    await run()
    assert api.async_get_module_key.await_count == 1
    center._key_tried -= interval  # the interval is over
    center.on_poll(poll_facts("r1", T0 + 120))
    await run()
    assert api.async_get_module_key.await_count == 2
    assert not center.ready
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1  # once per "not ready" state
    assert "module key" in warnings[0].getMessage()
    for record in caplog.records:
        if record.levelno > logging.DEBUG:
            text = record.getMessage()
            assert "02:00:5e" not in text and "192.168" not in text
            assert "laptop" not in text
    center._key_tried -= interval
    center.on_poll(poll_facts("r1", T0 + 180))
    await run()
    assert center.ready and center.not_ready_reason is None
    center._key_tried -= interval
    center.on_poll(poll_facts("r1", T0 + 240))
    await run()
    assert api.async_get_module_key.await_count == 3  # no try once ready
    # an error of the retry never disturbs the poll
    center._module_key = None
    center._key_tried -= interval
    polls = center.counters["polls"]
    with patch.object(
        center, "_async_fetch_module_key", AsyncMock(side_effect=RuntimeError("x"))
    ):
        center.on_poll(poll_facts("r1", T0 + 300))
        await run()
    assert center.counters["polls"] == polls + 1


async def test_review4_4_no_retry_without_core_binding(
    disks,  # noqa: F811
) -> None:
    hass = make_hass()
    tasks: list[Any] = []
    hass.async_create_task = lambda coro, name=None: tasks.append(coro)
    center = await center_for(hass, "r1", module_key=None)
    center.on_poll(poll_facts("r1", T0))
    assert tasks == []  # no core: nothing to ask, nothing scheduled
    await asyncio.sleep(0)


# --- 5: no device indicator while not ready -----------------------------------------


def _results(mac: str, now: float) -> list[DetectorResult]:
    auth = auth_event(RID1, mac=mac, now=now)
    burst = WifiAssocBurstDetector()._event(
        router_id=RID1, now=now, key=(RID1, mac), client=mac
    )
    return [
        DetectorResult(
            detector_id=e.name,
            router_id=RID1,
            status=Availability.AVAILABLE,
            events=(e,),
        )
        for e in (auth, burst)
    ]


async def test_review4_5_no_indicator_before_the_module_key(
    disks,  # noqa: F811
) -> None:
    center = await center_for(make_hass(), "r1", module_key=None)
    mac = "02:00:5e:40:00:01"
    center._apply_results(_results(mac, T0), T0)
    record = center.trust.get(mac)
    assert record is None or not record.indicators
    assert center.trust.state(mac, T0) is not TrustState.SUSPICIOUS
    assert center.incidents == {} and center.timeline == []
    # the key arrives: the same findings bring the change and its hint
    center._module_key = MODULE_KEY
    center._apply_results(_results(mac, T0 + 60), T0 + 60)
    assert center.trust.state(mac, T0 + 60) is TrustState.SUSPICIOUS
    notes = [t for t in center.timeline if t.get("type") == "trust_suspicious"]
    assert len(notes) == 1
    assert any(i["category"] == "device" for i in center.incidents.values())
