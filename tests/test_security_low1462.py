"""Security Center 1.46.2: the four small open points of the check of 983521e.

One block per point; every test started red. No Home Assistant instance, no
router: the center runs on in-memory stores, the core binding is a fake.
Invented values only (MACs ``02:00:00:…``, RFC 5737 addresses).
"""

from __future__ import annotations

import copy
import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

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
from test_security_review3 import keyed_center

from custom_components.openwrt_router import security_center as sc
from custom_components.openwrt_router.const import SEC_INCIDENT_AUTO_RESOLVE_SECONDS
from custom_components.openwrt_router.security_rules import VlanDriftDetector
from custom_components.openwrt_router.security_trust import (
    NoticeKind,
    TrustNotice,
    TrustState,
)

DAY = SEC_INCIDENT_AUTO_RESOLVE_SECONDS
WIFI_QUOTA = 40  # decided: 10 of the 50 "other" places only for non-Wi-Fi hints


def kinds(center: Any, kind: str) -> list[dict[str, Any]]:
    return [t for t in center.timeline if t["kind"] == kind]


def mac(n: int) -> str:
    return f"02:00:00:00:{n // 256:02x}:{n % 256:02x}"


def wifi(n: int, ts: float) -> Any:
    return auth_event(RID1, mac=mac(n), now=ts)


def drift(n: int, ts: float) -> Any:
    return VlanDriftDetector()._event(
        router_id=RID1,
        now=ts,
        key=(RID1, f"drf_{n}", "vlan"),
        evidence=(f"drift_id=drf_{n}", "areas=vlan"),
    )


def trust(n: int, ts: float) -> Any:
    return TrustNotice(
        kind=NoticeKind.SUSPICIOUS,
        state=TrustState.SUSPICIOUS,
        at=ts,
        mac=mac(0x300 + n),
        indicators=("ip_churn", "hostname_change"),
    ).to_event(router_id=None)


def other(center: Any) -> list[dict[str, Any]]:
    return [i for i in center.incidents.values() if i.get("from_logs") is not True]


def wifi_hints(center: Any) -> list[dict[str, Any]]:
    return [i for i in center.incidents.values() if i.get("from_wifi") is True]


# --- 1: after the key returns, 24 quiet hours since then ---------------------------


async def test_low_1_no_auto_resolve_until_a_day_after_the_key_returned(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    center._record(auth_event(RID1, now=T0), T0)
    (old,) = center.incidents.values()
    center._module_key = None  # the key went away
    center._housekeeping(T0 + DAY + 3600)  # blind: nothing resolves
    assert old["status"] == "open"
    arrival = T0 + DAY + 7200
    center._module_key = MODULE_KEY  # the key is back
    center._housekeeping(arrival)
    assert old["status"] == "open"  # quiet since the key, not since last_seen
    center._record(wifi(7, arrival + 3600), arrival + 3600)
    young = next(i for i in center.incidents.values() if i is not old)
    center._housekeeping(arrival + DAY - 60)
    assert old["status"] == "open"
    center._housekeeping(arrival + DAY + 60)
    assert old["status"] == "resolved" and young["status"] == "open"
    center._housekeeping(arrival + 3600 + DAY + 60)  # since last_seen: later
    assert young["status"] == "resolved"
    assert len(kinds(center, "incident_resolved")) == 2


async def test_low_1_a_key_present_from_the_start_changes_nothing(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    center._record(auth_event(RID1, now=T0), T0)
    (inc,) = center.incidents.values()
    center._housekeeping(T0 + DAY + 60)
    assert inc["status"] == "resolved"


async def test_low_1_the_key_fetched_after_a_failure_counts_as_a_return(
    disks,  # noqa: F811
) -> None:
    hass = make_hass()
    tasks: list[Any] = []
    hass.async_create_task = lambda coro, name=None: tasks.append(coro)
    center = await keyed_center(hass, "r1")
    center._record(auth_event(RID1, now=T0), T0)
    (inc,) = center.incidents.values()
    center._module_key = None
    api = SimpleNamespace(
        installation_key_state=sc.InstallationKeyState.OK,
        async_get_module_key=AsyncMock(side_effect=[RuntimeError("x"), MODULE_KEY]),
    )
    center._binding = sc._Binding(core=object(), api=api, events_ok=True)
    await center._async_fetch_module_key()  # fails: not ready
    await center._async_fetch_module_key()  # the key arrives
    assert center.ready
    late = T0 + DAY + 600
    center._housekeeping(late)
    assert inc["status"] == "open"
    center._housekeeping(late + DAY + 60)
    assert inc["status"] == "resolved"


# --- 2: a missing core binding is tried again from the poll ------------------------


async def test_low_2_core_binding_retried_from_the_poll_one_warning(
    disks,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass = make_hass()
    tasks: list[Any] = []
    hass.async_create_task = lambda coro, name=None: tasks.append(coro)

    async def run() -> None:
        while tasks:
            await tasks.pop(0)

    secret = "02:00:00:00:09:01 192.0.2.9 host-example"
    core = SimpleNamespace(closed=False, loaded=False)
    api = SimpleNamespace(
        register_event_prefix=MagicMock(side_effect=[ValueError(secret), lambda: None]),
        register_audit_mandatory_types=MagicMock(return_value=lambda: None),
        subscribe=MagicMock(return_value=lambda: None),
        installation_key_state=sc.InstallationKeyState.OK,
        async_get_module_key=AsyncMock(return_value=MODULE_KEY),
    )
    get_api = AsyncMock(side_effect=[RuntimeError(secret), api, api])
    caplog.set_level(logging.DEBUG, logger=sc.__name__)
    with (
        patch(
            "custom_components.openwrt_router.enterprise_core.async_get_core",
            return_value=core,
        ),
        patch(
            "custom_components.openwrt_router.config_api.async_get_configuration_api",
            get_api,
        ),
    ):
        center = await center_for(hass, "r1", module_key=None)
        assert get_api.await_count == 1  # at start: no API
        assert center._binding.api is None and not center.ready
        interval = sc.SEC_MODULE_KEY_RETRY_SECONDS
        center.on_poll(poll_facts("r1", T0))
        await run()
        assert get_api.await_count == 1  # within the interval: no try
        center._core_tried -= interval
        center.on_poll(poll_facts("r1", T0 + 300))
        await run()
        assert get_api.await_count == 2  # API there, registration fails
        assert center._binding.api is api and not center._binding.events_ok
        center._core_tried -= interval
        center.on_poll(poll_facts("r1", T0 + 600))
        await run()
        assert get_api.await_count == 3
        assert center._binding.events_ok and center.ready
        center._core_tried -= interval
        center.on_poll(poll_facts("r1", T0 + 900))
        await run()
        assert get_api.await_count == 3  # bound: no more tries
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1, [r.getMessage() for r in warnings]
    assert "core" in warnings[0].getMessage()
    for record in caplog.records:
        if record.levelno > logging.DEBUG:
            text = record.getMessage()
            assert "02:00:00" not in text and "192.0.2" not in text
            assert "host-example" not in text
    assert center.counters["polls"] == 4


async def test_low_2_a_failing_retry_never_disturbs_the_poll(
    disks,  # noqa: F811
) -> None:
    hass = make_hass()
    tasks: list[Any] = []
    hass.async_create_task = lambda coro, name=None: tasks.append(coro)
    core = SimpleNamespace(closed=False, loaded=False)
    with patch(
        "custom_components.openwrt_router.enterprise_core.async_get_core",
        return_value=core,
    ):
        center = await center_for(hass, "r1", module_key=None)
        center._core_tried = None
        with patch.object(
            center, "_async_bind_core", AsyncMock(side_effect=RuntimeError("x"))
        ):
            center.on_poll(poll_facts("r1", T0))
            while tasks:
                await tasks.pop(0)
    assert center.counters["polls"] == 1
    assert center._binding.api is None


async def test_low_2_no_core_no_retry(
    disks,  # noqa: F811
) -> None:
    hass = make_hass()
    tasks: list[Any] = []
    hass.async_create_task = lambda coro, name=None: tasks.append(coro)
    center = await center_for(hass, "r1", module_key=None)
    center.on_poll(poll_facts("r1", T0))
    assert tasks == []  # no core running: nothing to bind, nothing scheduled


# --- 3: a device that became suspicious while blind gets its hint ------------------


def clients_facts(host: str, ip: str) -> Any:
    return SimpleNamespace(
        exclude=frozenset(),
        context=SimpleNamespace(clients={mac(0x401): {"ip": ip, "hostname": host}}),
    )


async def test_low_3_suspicious_while_blind_gets_its_hint_once_the_key_arrives(
    disks,  # noqa: F811
) -> None:
    center = await center_for(make_hass(), "r1", module_key=None)
    steps = [("dev-a", 10), ("dev-b", 11), ("dev-b", 12), ("dev-b", 13), ("dev-b", 14)]
    now = T0
    for k, (host, last) in enumerate(steps):
        now = T0 + 60 * k
        center._observe_clients(RID1, clients_facts(host, f"192.0.2.{last}"), now)
    assert center.trust.state(mac(0x401), now) is TrustState.SUSPICIOUS
    assert center.incidents == {}  # not ready: nothing recorded
    center._module_key = MODULE_KEY  # the key arrives
    center._housekeeping(now + 60)
    hints = [i for i in center.incidents.values() if i["category"] == "device"]
    assert len(hints) == 1 and hints[0]["status"] == "open"
    assert len([t for t in center.timeline if t.get("type") == "trust_suspicious"]) == 1
    center._housekeeping(now + 120)  # caught up once, not on every poll
    assert len(center.incidents) == 1
    assert center.counters["incidents_merged"] == 0


async def test_low_3_no_late_hint_for_a_device_no_longer_suspicious(
    disks,  # noqa: F811
) -> None:
    center = await center_for(make_hass(), "r1", module_key=None)
    steps = [("dev-a", 10), ("dev-b", 11), ("dev-b", 12), ("dev-b", 13), ("dev-b", 14)]
    now = T0
    for k, (host, last) in enumerate(steps):
        now = T0 + 60 * k
        center._observe_clients(RID1, clients_facts(host, f"192.0.2.{last}"), now)
    center._module_key = MODULE_KEY
    later = now + 2 * 3600  # the indicators have aged out of their window
    assert center.trust.state(mac(0x401), later) is not TrustState.SUSPICIOUS
    center._housekeeping(later)
    assert center.incidents == {}


# --- 4: 10 of the 50 "other" places only for non-Wi-Fi sources ---------------------


async def test_low_4_wifi_flood_fills_40_drift_and_trust_still_get_through(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    for n in range(100):
        center._record(wifi(n, T0 + n), T0 + n)
    assert len(wifi_hints(center)) == WIFI_QUOTA == len(other(center))
    assert center.counters["incidents_wifi_quota_dropped"] == 100 - WIFI_QUOTA
    assert center.counters["incidents_other_quota_dropped"] == 0
    assert len(kinds(center, "wifi_quota_reached")) == 1  # once per window
    center._record(drift(1, T0 + 200), T0 + 200)
    center._record(trust(1, T0 + 201), T0 + 201)
    cats = sorted(i["category"] for i in other(center) if not i["from_wifi"])
    assert cats == ["device", "vlan"]
    # non-Wi-Fi hints may use all 50 places
    for n in range(2, 10):
        center._record(drift(n, T0 + 300 + n), T0 + 300 + n)
    assert len(other(center)) == 50
    center._record(drift(99, T0 + 400), T0 + 400)
    assert center.counters["incidents_other_quota_dropped"] == 1
    # no displacement: every Wi-Fi hint stands
    assert len(wifi_hints(center)) == WIFI_QUOTA
    limits = center.overview(actor=None, now=T0 + 500)["limits"]
    assert limits["wifi_incident_quota"] == WIFI_QUOTA
    assert limits["wifi_incidents"] == WIFI_QUOTA
    assert limits["incidents_wifi_quota_dropped"] == 100 - WIFI_QUOTA
    assert limits["other_incident_quota"] == 50
    assert center.diagnostics()["counters"]["incidents_wifi_quota_dropped"] == 60


async def test_low_4_resolved_wifi_hints_make_room_only_for_wifi(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    for n in range(WIFI_QUOTA):
        center._record(wifi(n, T0 + n), T0 + n)
    oldest = min(wifi_hints(center), key=lambda i: i["last_seen"])
    oldest["status"] = "resolved"
    center._record(wifi(500, T0 + 900), T0 + 900)
    assert oldest["id"] not in center.incidents
    assert len(wifi_hints(center)) == WIFI_QUOTA
    assert center.counters["incidents_wifi_quota_dropped"] == 0


async def test_low_4_old_store_above_40_wifi_hints_keeps_them_all(
    disks,  # noqa: F811
) -> None:
    first = await keyed_center(make_hass(), "r1")
    first._record(wifi(0, T0), T0)
    stored = first._data_to_save()
    (template,) = stored["incidents"]
    template.pop("from_wifi", None)  # a store from before the reserve
    items = []
    for n in range(45):
        item = copy.deepcopy(template)
        item["id"] = f"sec_{n:08x}"
        item["scope"] = f"{item['scope']}|{n}"
        item["status"] = "resolved" if n < 2 else "open"
        item["last_seen"] = item["first_seen"] = T0 + n
        items.append(item)
    stored["incidents"] = items
    sec_disk(disks).data = stored
    center = await keyed_center(make_hass(), "r1")
    assert len(wifi_hints(center)) == 45  # by category: Wi-Fi, nothing deleted
    center._record(wifi(900, T0 + 900), T0 + 900)
    assert len(center.incidents) == 45  # 43 open: dropping 2 resolved is no room
    assert center.counters["incidents_wifi_quota_dropped"] == 1
    center._record(drift(1, T0 + 901), T0 + 901)
    assert len(center.incidents) == 46


# --- 1.49.3 review S1: no resolved Wi-Fi hint goes for a hint dropped anyway ------


async def test_s1_wifi_room_is_not_made_when_the_class_is_full_of_open_hints(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1")
    for n in range(WIFI_QUOTA):
        center._record(wifi(n, T0 + n), T0 + n)
    resolved = min(wifi_hints(center), key=lambda i: i["last_seen"])
    resolved["status"] = "resolved"
    center._record(drift(1, T0 + 100), T0 + 100)
    (template,) = [i for i in other(center) if not i["from_wifi"]]
    # an old store: 55 open non-Wi-Fi hints in the "other" class
    for n in range(55):
        item = copy.deepcopy(template)
        item["id"] = f"sec_old{n:05x}"
        item["scope"] = f"{item['scope']}|old{n}"
        center.incidents[item["id"]] = item
    before = set(center.incidents)
    center._record(wifi(900, T0 + 900), T0 + 900)
    assert resolved["id"] in center.incidents  # nothing lost for nothing
    assert set(center.incidents) == before  # the new hint was dropped
    assert center.counters["incidents_other_quota_dropped"] == 1
