"""Security Center wiring (release 1.46.0, part 1): security_center.py.

Mocks only: network intelligence and client stability run on the in-memory
store fakes of ``test_net_engine``; the enterprise core and the
configuration manager run on FakeDisks with the FakeConfigProvider
(``config_manager_kit``). No Home Assistant instance, no router, no network.
MACs are locally administered test values.
"""

from __future__ import annotations

import copy
import json
import logging
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import voluptuous as vol
from config_manager_kit import ON, cm_env, drain, macs, stop
from core_test_provider import (
    FakeConfigProvider,
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import (
    ADMIN_ID,
    USER_ID,
    FakeDisks,
    router_data,
    user_actor,
)
from test_client_engine import MS0, T0, client, data, setup
from test_net_engine import FakeDisk, FakeStore, make_hass

import custom_components.openwrt_router as integration
from custom_components.openwrt_router import (
    client_engine,
    net_engine,
    net_query,
    security_center,
    security_syslog,
)
from custom_components.openwrt_router.const import (
    CONFIG_BACKUP_SCHEDULE_OFF,
    DATA_SECURITY_CENTER,
    OPTION_CONFIG_BACKUP_SCHEDULE,
    SEC_INCIDENT_CAP,
    SEC_SAVE_DELAY_SECONDS,
    SEC_STORE_KEY,
)
from custom_components.openwrt_router.core_models import CoreEventType
from custom_components.openwrt_router.log_parser import (
    CATEGORY_WIFI,
    WIFI_CONNECTED,
    WIFI_PSK_MISMATCH,
    LogEvent,
)
from custom_components.openwrt_router.net_engine import async_get_net_intelligence
from custom_components.openwrt_router.security_center import (
    DriftNote,
    SecurityCenter,
    SecurityCenterError,
    async_get_security_center,
    async_release_security_center,
    async_setup_security_center,
    default_settings,
    merge_settings,
    settings_from_store,
)
from custom_components.openwrt_router.security_model import (
    MASK,
    SecCategory,
    SecurityEvent,
    event_type,
)
from custom_components.openwrt_router.security_trust import Indicator

M1 = "02:00:5E:10:00:01"
M2 = "02:00:5E:10:00:02"
M3 = "02:00:5E:10:00:03"
RID1 = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
RIDS = {"r1": RID1, "r2": RID2}
NO_SCHEDULE = {**ON, OPTION_CONFIG_BACKUP_SCHEDULE: CONFIG_BACKUP_SCHEDULE_OFF}
ADMIN = user_actor(ADMIN_ID)
PLAIN = user_actor(USER_ID)


# --- helpers -----------------------------------------------------------------------


@pytest.fixture
def disks() -> Any:
    """Fake disks for NI, client stability and the Security Center."""
    found: dict[str, FakeDisk] = {}

    def store(*args: Any, **kw: Any) -> FakeStore:
        key = args[2]
        disk = found.setdefault(key, FakeDisk())
        disk.path = f"/nonexistent/.storage/{key}"
        return FakeStore(disk, *args, **kw)

    with (
        patch.object(net_engine, "Store", store),
        patch.object(client_engine, "Store", store),
        patch.object(security_center, "Store", store),
    ):
        yield found


def sec_disk(found: dict[str, FakeDisk]) -> FakeDisk:
    return found.setdefault(SEC_STORE_KEY, FakeDisk())


def coordinator(uptime: int = 5000) -> Any:
    return SimpleNamespace(data=SimpleNamespace(uptime=uptime))


# The module key the core hands out (the same after a restart). Without it
# the center records no hint (review 3, #6), so the helper gives one.
MODULE_KEY = bytes(range(32))


async def center_for(
    hass: Any,
    *entries: str,
    enabled: bool = True,
    module_key: bytes | None = MODULE_KEY,
) -> SecurityCenter:
    """A center with the router ids of RIDS (no core needed for them).

    ``module_key`` stands in for the core's key while no core runs; None
    leaves the center "not ready".
    """
    center = SecurityCenter(hass)
    center.router_id_of = RIDS.get
    hass.data[DATA_SECURITY_CENTER] = center
    await center.async_load()
    for entry in entries:
        center.add_entry(entry, coordinator())
    if enabled:
        center.settings = merge_settings(center.settings, {"enabled": True})
        await center.async_activate()
        center._module_key = module_key
    return center


def wifi(kind: str, n: int, mac: str = M1, at: float | None = None) -> LogEvent:
    return LogEvent(
        category=CATEGORY_WIFI,
        kind=kind,
        log_id=n,
        time_ms=int(at * 1000) if at is not None else MS0 - 30_000 + n * 1000,
        mac=mac,
        interface="phy1-ap0",
    )


POLLS = 9


def scenario_polls() -> list[tuple[Any, float]]:
    """Nine polls: two clients, one PSK failure of M1 per poll, a new M3."""
    polls: list[tuple[Any, float]] = []
    for k in range(POLLS):
        now = T0 + k * 60
        clients = [client(M1, ip="192.0.2.10"), client(M2, hostname="tv")]
        if k >= 3:
            clients.append(client(M3))
        lines: tuple[LogEvent, ...] = ()
        if 1 <= k <= 7:
            lines = (wifi(WIFI_PSK_MISMATCH, 100 + k, at=now - 20),)
        if k == 4:
            lines += (wifi(WIFI_CONNECTED, 200, M3, at=now - 10),)
        polls.append((data(clients, lines), now))
    return polls


def ni_state(engine: Any, cs: Any, now: float) -> dict[str, Any]:
    """Everything NI and client stability show (incidents, counters, score)."""
    payload = copy.deepcopy(engine._payload())
    return {
        "payload": json.loads(json.dumps(payload, default=str)),
        "peek": [repr(i) for i in engine.machine.peek()],
        "summary": json.loads(
            json.dumps(net_query.summary(engine, str, now), default=str)
        ),
        "cs": json.loads(json.dumps(cs.history.to_dict(), default=str)),
    }


def security_event(name: str, ts: float, *, router_id: str | None = RID1) -> Any:
    return SecurityEvent(
        event_id=f"ev-{name}-{ts}",
        ts=ts,
        type=event_type(name),
        category=SecCategory.WIFI,
        router_id=router_id,
        client=M2,
        dedup_key=f"{name}|{M2}",
        evidence=("count=12",),
    )


# --- settings ------------------------------------------------------------------------


def test_every_setting_defaults_to_off() -> None:
    settings = default_settings()
    assert settings["enabled"] is False
    assert settings["log_path"] == "off"
    assert settings["keep_dns_names"] is False
    assert settings["syslog_port"] == 5514
    assert settings["thresholds"] == {} and settings["subnet_zones"] == {}


def test_settings_are_validated_and_damaged_values_fall_back() -> None:
    good = merge_settings(
        default_settings(),
        {
            "log_path": "collector",
            "thresholds": {"wifi_auth_repeat": 8},
            "subnet_zones": {"192.168.20.0/24": "IoT"},
        },
    )
    assert good["subnet_zones"] == {"192.168.20.0/24": "iot"}
    for bad in (
        {"log_path": "ftp"},
        {"syslog_port": 80},
        {"thresholds": {"no_such_detector": 3}},
        {"thresholds": {"wifi_auth_repeat": 0}},
        {"subnet_zones": {"not a subnet": "lan"}},
        {"unknown": True},
    ):
        with pytest.raises(vol.Invalid):
            merge_settings(default_settings(), bad)
    stored = settings_from_store(
        {"enabled": "yes", "log_path": "syslog", "syslog_port": "x"}
    )
    assert stored["enabled"] is False  # a broken value is off, not on
    assert stored["log_path"] == "syslog" and stored["syslog_port"] == 5514


async def test_thresholds_reach_the_detectors(disks) -> None:
    hass = make_hass()
    center = await center_for(hass, "r1", enabled=False)
    center.settings = merge_settings(
        center.settings,
        {"thresholds": {"wifi_auth_repeat": 9, "wifi_multi_ap_auth": 1}},
    )
    center._rebuild_detectors()
    by_id = {d.id: d for d in center.detectors.detectors}
    assert by_id["wifi_auth_repeat"].threshold == 9
    assert by_id["wifi_multi_ap_auth"].threshold == 2  # never below two APs


# --- default off ---------------------------------------------------------------------


async def test_default_off_reads_only_and_never_observes(disks) -> None:
    hass = make_hass()
    engine, _cs = await setup(hass, "r1")
    entry = SimpleNamespace(entry_id="r1")
    center = await async_setup_security_center(hass, entry, coordinator())
    assert async_get_security_center(hass) is center
    assert center.loaded and not center.active
    assert center not in engine._poll_observers
    for payload, now in scenario_polls():
        engine.ingest("r1", payload, now, interval=60.0)
    assert center.counters["polls"] == 0
    assert len(center.trust) == 0 and center.timeline == []
    await async_release_security_center(hass, "r1")
    disk = sec_disk(disks)
    assert disk.saves == [] and disk.delayed == []
    assert async_get_security_center(hass) is None


async def test_case22_regression_inactive_center_changes_nothing(disks) -> None:
    """Same polls three ways: no center, inactive center, active center."""

    async def run(mode: str) -> tuple[dict[str, Any], SecurityCenter | None]:
        found: dict[str, FakeDisk] = {}

        def store(*args: Any, **kw: Any) -> FakeStore:
            disk = found.setdefault(args[2], FakeDisk())
            return FakeStore(disk, *args, **kw)

        hass = make_hass()
        with (
            patch.object(net_engine, "Store", store),
            patch.object(client_engine, "Store", store),
            patch.object(security_center, "Store", store),
            patch.object(net_engine.time, "time", return_value=T0),
        ):
            engine, cs = await setup(hass, "r1")
            center = None
            if mode != "none":
                center = await center_for(hass, "r1", enabled=mode == "active")
            for payload, now in scenario_polls():
                engine.ingest("r1", payload, now, interval=60.0)
            state = ni_state(engine, cs, T0 + 600)
        return state, center

    none, _ = await run("none")
    inactive, idle = await run("inactive")
    active, center = await run("active")
    assert idle is not None and idle.counters["polls"] == 0
    assert center is not None and center.counters["polls"] == POLLS
    assert len(center.trust) == 3  # the active center did see the polls
    assert none["peek"], "the scenario must open NI incidents"
    for key in ("payload", "peek", "summary", "cs"):
        assert inactive[key] == none[key], key
        assert active[key] == none[key], key


# --- isolation of errors ---------------------------------------------------------------


async def test_throwing_detector_keeps_the_poll_and_the_data(
    disks, caplog: pytest.LogCaptureFixture
) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    center = await center_for(hass, "r1")
    with (
        patch.object(
            type(center.detectors),
            "evaluate",
            side_effect=RuntimeError(f"bug {M1} 192.0.2.10"),
        ),
        patch.object(
            type(center.trust), "observe", side_effect=ValueError(f"bad {M2}")
        ),
        caplog.at_level(logging.DEBUG),
    ):
        stored = [
            engine.ingest("r1", payload, now, interval=60.0)
            for payload, now in scenario_polls()
        ]
    assert sum(stored) > 0
    assert cs.history.live(M1) is not None  # client stability got every poll
    assert center.counters["errors"] >= 2 * POLLS and center.counters["polls"] == POLLS
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("Security Center" in r.getMessage() for r in warnings)
    for record in warnings:
        text = record.getMessage()
        assert M1 not in text and M2 not in text and "192.0.2.10" not in text
        assert record.exc_info is None or record.levelno < logging.WARNING
    assert "poll observer failed" not in caplog.text  # nothing reached NI


async def test_a_whole_failing_poll_hook_never_reaches_the_engine(disks) -> None:
    hass = make_hass()
    engine, _cs = await setup(hass, "r1")
    center = await center_for(hass, "r1")
    with patch.object(center, "_on_poll", side_effect=RuntimeError("boom")):
        stored = engine.ingest(
            "r1", data([client(M1)], (wifi(WIFI_PSK_MISMATCH, 1),)), T0, interval=60
        )
    assert stored == 1 and center.counters["errors"] == 1


async def test_setup_and_unload_survive_a_broken_center(
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass = make_hass()
    entry = SimpleNamespace(
        entry_id="e1", title=f"router {M1}", runtime_data=SimpleNamespace()
    )
    with (
        patch.object(
            integration, "_async_setup_entry_base", AsyncMock(return_value=True)
        ),
        patch.object(
            integration, "_async_unload_entry_base", AsyncMock(return_value=True)
        ),
        patch.object(
            security_center,
            "async_setup_security_center",
            AsyncMock(side_effect=RuntimeError(f"boom {M1}")),
        ),
        patch.object(
            security_center,
            "async_release_security_center",
            AsyncMock(side_effect=OSError(f"disk {M1}")),
        ),
        caplog.at_level(logging.WARNING),
    ):
        assert await integration.async_setup_entry(hass, entry) is True
        assert await integration.async_unload_entry(hass, entry) is True
    assert "Security Center setup failed (RuntimeError)" in caplog.text
    assert "Security Center release failed (OSError)" in caplog.text
    assert M1 not in caplog.text


async def test_failed_base_setup_does_not_start_the_center() -> None:
    hass = make_hass()
    entry = SimpleNamespace(entry_id="e1", runtime_data=SimpleNamespace())
    setup_mock = AsyncMock()
    with (
        patch.object(
            integration, "_async_setup_entry_base", AsyncMock(return_value=False)
        ),
        patch.object(security_center, "async_setup_security_center", setup_mock),
    ):
        assert await integration.async_setup_entry(hass, entry) is False
    setup_mock.assert_not_called()


# --- no extra router call --------------------------------------------------------------


async def test_active_center_adds_no_router_calls() -> None:
    import time as time_module

    import test_poll_no_ssh as model

    from custom_components.openwrt_router.api import OpenWrtAPI

    clients = {
        "freq": 5180,
        "clients": {
            M1.lower(): {
                "auth": True,
                "assoc": True,
                "authorized": True,
                "rate": {"rx": 433300, "tx": 866700},
                "signal": -60,
            }
        },
    }

    async def run(with_center: bool) -> tuple[int, SecurityCenter | None]:
        session = model._ubus_session()
        api = OpenWrtAPI(
            host="192.0.2.1",
            port=80,
            username="root",
            password="pw",
            session=session,
            protocol="http",
        )
        api._lldp_checked = True
        api._lldp_available = False
        api._lldp_last_fetch = time_module.monotonic()
        coord = model._make_coordinator(api)
        hass = make_hass()

        def store(*a: Any, **kw: Any) -> FakeStore:
            return FakeStore(FakeDisk(), *a, **kw)

        with (
            patch.object(net_engine, "Store", store),
            patch.object(client_engine, "Store", store),
            patch.object(security_center, "Store", store),
        ):
            engine = await async_get_net_intelligence(hass)
            engine.register("r1")
            await client_engine.async_get_client_stability(hass, engine)
            center = None
            if with_center:
                center = await center_for(hass, enabled=True)
                center.add_entry("r1", coord)
        model._MODE["empty_tables"] = False
        with (
            patch.dict(model.RESPONSES, {("hostapd.phy1-ap0", "get_clients"): clients}),
            patch(
                "custom_components.openwrt_router.api.asyncssh.connect",
                AsyncMock(side_effect=AssertionError("SSH must not be used")),
            ),
            patch("asyncio.open_connection", side_effect=OSError("no net")),
        ):
            for _n in range(3):
                coord.data = await coord._async_update_data()
                engine.async_ingest_coordinator("r1", coord)
        return session.post.call_count, center

    calls_without, _ = await run(False)
    calls_with, center = await run(True)
    assert calls_with == calls_without > 0
    assert center is not None and center.counters["polls"] == 3
    assert center.trust.get(M1) is not None  # it did work on the polls


# --- trust, incidents, persistence -------------------------------------------------------


async def test_polls_feed_the_trust_book_and_the_timeline(disks) -> None:
    hass = make_hass()
    engine, _cs = await setup(hass, "r1")
    center = await center_for(hass, "r1")
    for payload, now in scenario_polls():
        engine.ingest("r1", payload, now, interval=60.0)
    assert all(center.trust.get(m) is not None for m in (M1, M2, M3))
    kinds = {t["type"] for t in center.timeline if t["kind"] == "notice"}
    assert "trust_private_mac" in kinds or "trust_new_device" in kinds
    assert center.dirty and sec_disk(disks).delayed[0][1] == SEC_SAVE_DELAY_SECONDS
    # the PSK burst is covered by the NI incident: linked, no own incident
    ni_ids = {i.id for i in engine.machine.peek()}
    reused = [t for t in center.timeline if t["kind"] == "reused"]
    assert reused and set(reused[0]["linked"]) <= ni_ids
    assert not any(
        i["detector"] == "wifi_auth_repeat" for i in center.incidents.values()
    )
    assert center.counters["incidents_reused"] >= 1
    # NI incidents are untouched (still theirs, still open)
    assert all(
        i.status.value in ("active", "acknowledged") for i in engine.machine.peek()
    )


async def test_case18_ha_restart_persistence(disks) -> None:
    hass = make_hass()
    engine, _cs = await setup(hass, "r1")
    center = await center_for(hass, "r1")
    center._module_key = MODULE_KEY
    for payload, now in scenario_polls():
        engine.ingest("r1", payload, now, interval=60.0)
    now = T0 + 400
    center.trust.confirm(M1, now, name="Laptop")
    for k in range(4):
        center.baseline.observe(f"{RID1}|dns_rate|x", 10 + k, now + k * 60)
    event = security_event("wifi_assoc_burst", now)
    center._record(event, now)
    open_ids = {i for i, inc in center.incidents.items() if inc["status"] == "open"}
    assert len(open_ids) == 1
    assert center.detectors.state_size() > 0
    before_trust = center.trust.to_dict()
    before_baseline = center.baseline.to_dict()
    await async_release_security_center(hass, "r1")
    disk = sec_disk(disks)
    assert len(disk.saves) == 1
    saved = json.dumps(disk.saves[0])
    assert len(saved.encode()) <= 512 * 1024
    assert ADMIN_ID not in saved and USER_ID not in saved

    hass2 = make_hass()
    center2 = await center_for(hass2, "r1")
    center2._module_key = MODULE_KEY
    assert not center2.load_failed
    assert center2.trust.to_dict() == before_trust
    assert center2.trust.get(M1).name == "Laptop"
    assert center2.baseline.to_dict() == before_baseline
    assert set(center2.incidents) == open_ids
    assert center2.detectors.state_size() == 0  # windows start empty
    assert center2.settings["enabled"] is True
    # the same finding again merges into the stored incident (no duplicate)
    center2._record(security_event("wifi_assoc_burst", now + 60), now + 60)
    assert set(center2.incidents) == open_ids
    assert center2.counters["incidents_merged"] == 1
    inc = center2.incidents[next(iter(open_ids))]
    assert inc["count"] == 2 and inc["status"] == "open"


async def test_broken_store_sections_start_empty(disks) -> None:
    disk = sec_disk(disks)
    disk.data = {
        "settings": {"enabled": True},
        "trust": "garbage",
        "incidents": [{"id": "not-ours"}, 5],
        "timeline": [{"no": "ts"}],
        "counters": {"polls": -3},
    }
    hass = make_hass()
    center = await center_for(hass, "r1", enabled=False)
    assert center.enabled and center.incidents == {} and center.timeline == []
    assert center.counters["polls"] == 0


async def test_unreadable_store_is_kept_and_the_center_starts_empty(disks) -> None:
    disk = sec_disk(disks)
    disk.load_error = json.JSONDecodeError("broken", "{", 0)
    hass = make_hass()
    with patch.object(security_center, "_backup_file", return_value=True) as backup:
        center = await center_for(hass, "r1", enabled=False)
    assert center.loaded and center.load_failed
    backup.assert_called_once()
    assert center.incidents == {} and not center.enabled


async def test_incident_cap_drops_resolved_then_refuses_new(disks) -> None:
    hass = make_hass()
    center = await center_for(hass, "r1")
    for k in range(SEC_INCIDENT_CAP + 5):
        center._record(security_event(f"wifi_assoc_burst_{k}", T0 + k), T0 + k)
        if k < 3:
            center.incidents[next(reversed(center.incidents))]["status"] = "resolved"
    assert len(center.incidents) == SEC_INCIDENT_CAP
    assert all(i["status"] == "open" for i in center.incidents.values())
    # three resolved made room; open hints are never evicted for new ones
    assert center.counters["incidents_dropped"] == 3
    assert center.counters["incidents_cap_dropped"] == 2
    assert not any(
        i["detector"] in (f"wifi_assoc_burst_{SEC_INCIDENT_CAP + k}" for k in (3, 4))
        for i in center.incidents.values()
    )


async def test_store_is_trimmed_to_the_size_cap(disks) -> None:
    hass = make_hass()
    center = await center_for(hass, "r1")
    for k in range(2000):
        center._timeline(
            T0 + k,
            "notice",
            category="device",
            severity="info",
            router_id=RID1,
            text="x" * 400,
        )
    payload = center._data_to_save()
    assert center.last_save_bytes is not None
    assert center.last_save_bytes <= 512 * 1024
    assert len(payload["timeline"]) < 2000
    assert center.counters["store_trimmed"] == 1


async def test_router_forgotten_drops_its_state(disks) -> None:
    hass = make_hass()
    engine, _cs = await setup(hass, "r1")
    center = await center_for(hass, "r1")
    for payload, now in scenario_polls():
        engine.ingest("r1", payload, now, interval=60.0)
    center._record(security_event("wifi_assoc_burst", T0), T0)
    center._forget_router(RID1)
    assert center.incidents == {}
    assert all(t.get("router_id") != RID1 for t in center.timeline)
    assert center.detectors.state_size() == 0
    assert center.counters["routers_forgotten"] == 1


# --- example E: a config change shortly before ------------------------------------------


async def test_config_change_before_a_finding_is_linked_without_causality(
    disks,
) -> None:
    hass = make_hass()
    center = await center_for(hass, "r1")
    note = DriftNote(router_id=RID1, drift_id="drf_1", ts=T0, baseline="bkp_a")
    center.drifts[(RID1, "drf_1")] = note
    center._record(security_event("wifi_assoc_burst", T0 + 600), T0 + 600)
    inc = next(iter(center.incidents.values()))
    assert inc["drift_refs"] == ["drf_1"]
    assert "keine belegte Ursache" in inc["hint"]
    assert "Angriff" not in json.dumps(inc, ensure_ascii=False)
    # outside the window: no link
    center._record(security_event("wifi_deauth_cluster", T0 + 7200), T0 + 7200)
    late = [
        i for i in center.incidents.values() if i["detector"] == "wifi_deauth_cluster"
    ]
    assert late[0]["drift_refs"] == []


# --- overview and masking ---------------------------------------------------------------


async def test_overview_without_admin_is_masked(disks) -> None:
    hass = make_hass()
    engine, _cs = await setup(hass, "r1")
    center = await center_for(hass, "r1")
    for payload, now in scenario_polls():
        engine.ingest("r1", payload, now, interval=60.0)
    center.trust.set_name(M2, "Wohnzimmer TV")
    center._record(security_event("wifi_assoc_burst", T0 + 300), T0 + 300)
    view = center.overview(now=T0 + 400)
    text = json.dumps(view, ensure_ascii=False)
    secrets = (M1, M2, M3, "192.0.2.10", "Wohnzimmer TV", '"tv"')
    for secret in (*secrets, M1.lower(), M2.lower(), M3.lower()):
        assert secret not in text, secret
    assert view["admin_view"] is False
    tv = [d for d in view["devices"] if d["name_set"]]
    assert len(tv) == 1 and tv[0]["name"] is None and tv[0]["mac"].startswith("cli_")
    assert view["incidents"][0]["client_ref"].startswith("cli_")  # keyed
    center._module_key = None  # no module key: masked, never plain
    bare = center.overview(now=T0 + 400)
    assert [d["mac"] for d in bare["devices"] if d["name_set"]] == [MASK]
    # unknown is never healthy: sources are reported, nothing invented
    assert view["score"]["coverage"] is not None
    assert view["subnet_map"] == {"state": "omitted", "subnets": 0}
    fw = {d["id"]: d for d in view["detections"]}
    assert fw["fw_port_scan_hint"]["availability"] == "not_available"
    assert fw["fw_port_scan_hint"]["format_unconfirmed"] is True
    assert fw["dns_rate"]["format_unconfirmed"] is True
    assert fw["wifi_auth_repeat"]["format_unconfirmed"] is False


async def test_score_is_none_without_any_source(disks) -> None:
    hass = make_hass()
    center = await center_for(hass, enabled=False)
    view = center.overview(now=T0)
    assert view["score"]["score"] is None
    assert view["score"]["coverage"] == 0


async def test_log_paths_report_why_they_are_not_available(disks) -> None:
    hass = make_hass()
    center = await center_for(hass, "r1")
    for path, reason in (
        ("off", "disabled"),
        # settings set directly: no receiver was started (part 2 binds it)
        ("syslog", security_syslog.REASON_NOT_STARTED),
        ("collector", security_center.REASON_COLLECTOR),
    ):
        center.settings = merge_settings(center.settings, {"log_path": path})
        status = center.overview(now=T0)["log_path"]["status"]
        assert {s["availability"] for s in status} == {"not_available"}
        assert {s["reason"] for s in status} == {reason}


async def test_timeline_filters(disks) -> None:
    hass = make_hass()
    center = await center_for(hass, "r1", "r2")
    center._timeline(
        T0, "drift", category="config", severity="info", router_id=RID1, text="a"
    )
    center._timeline(
        T0 + 10,
        "notice",
        category="device",
        severity="warning",
        router_id=RID2,
        text="b",
    )
    center._timeline(
        T0 + 20,
        "notice",
        category="wifi",
        severity="critical",
        router_id=RID1,
        text="c",
    )

    def texts(**kw: Any) -> list[str]:
        return [t["text"] for t in center.overview(now=T0 + 30, **kw)["timeline"]]

    assert texts() == ["c", "b", "a"]
    assert texts(router_id=RID1) == ["c", "a"]
    assert texts(category="device") == ["b"]
    assert texts(severity="warning") == ["c", "b"]
    assert texts(since=T0 + 5, until=T0 + 15) == ["b"]
    assert texts(client=M1) == []  # a non-admin cannot filter by MAC


# --- core: drift (case 08), events, actions ----------------------------------------------


@pytest.fixture
def core_disks():
    with FakeDisks().patch() as fake:
        yield fake


class AreaProvider(FakeConfigProvider):
    """Fake provider that classifies the ``network`` config as a VLAN area."""

    async def async_compare(self, base, other, ctx, *, base_router, other_router):
        diff = await super().async_compare(
            base, other, ctx, base_router=base_router, other_router=other_router
        )
        changes = tuple(
            replace(c, area="vlan") if c.config == "network" else c
            for c in diff.changes
        )
        return replace(diff, changes=changes)


async def _drifted_poll(env: Any, index: int) -> None:
    env.provider.live(env.rid)["network"]["lan"]["ipaddr"] = f"10.0.{index}.1"
    env.coords[env.rid].poll(
        data=router_data(
            hostname="r1",
            macs=macs(0),
            wan={"wan_found": True, "interface": "wan", "proto": f"proto{index}"},
        )
    )


async def _core_center(env: Any, sec: FakeDisk, *, enabled: bool = True) -> Any:
    sec.data = {"settings": {**default_settings(), "enabled": enabled}}
    sec.path = "/nonexistent/.storage/sec"
    with patch.object(
        security_center, "Store", lambda *a, **kw: FakeStore(sec, *a, **kw)
    ):
        center = None
        for entry, coord in zip(env.entries, env.coords.values(), strict=True):
            center = await async_setup_security_center(env.hass, entry, coord)
    return center


async def test_case08_vlan_config_change(core_disks, tmp_path) -> None:
    env = await cm_env(
        core_disks, tmp_path, options=NO_SCHEDULE, provider=AreaProvider()
    )
    sec = FakeDisk()
    center = await _core_center(env, sec)
    assert center.active and center.module_key_available
    await env.runtime.async_backup_now(env.rid, actor=ADMIN)
    env.coords[env.rid].poll()
    await _drifted_poll(env, 1)
    env.clock.advance(seconds=301)
    await env.tick()
    await drain(env.hass)
    drift_events = env.core.audit.events(types=[CoreEventType.DRIFT_DETECTED.value])
    assert len(drift_events) == 1
    drift_id = drift_events[0].data["drift_id"]
    hints = [i for i in center.incidents.values() if i["category"] == "vlan"]
    assert len(hints) == 1
    hint = hints[0]
    assert hint["drift_refs"] == [drift_id]
    assert hint["router_id"] == env.rid
    assert "Konfigurationsänderung" in hint["title"] + hint["hint"]
    assert "vlan" in hint["hint"]
    assert center.drifts[(env.rid, drift_id)].areas == ["vlan"]
    view = center.overview(actor=None)
    text = json.dumps(view, ensure_ascii=False) + json.dumps(
        center.incidents, ensure_ascii=False
    )
    assert "Angriff" not in text and "angriff" not in text.lower()
    det = {d["id"]: d for d in view["detections"]}["vlan_segmentation_drift"]
    assert det["availability"] == "available"
    # exactly one security event on the core bus, in the security ring
    own = [
        e
        for e in env.core.audit.events(
            types=["security_center.vlan_segmentation_drift"]
        )
    ]
    assert len(own) == 1 and own[0].incident_ref == hint["id"]
    assert own[0].source == "security_center"
    # nothing new for the same drift on the next ticks
    env.clock.advance(seconds=120)
    await env.tick()
    await drain(env.hass)
    assert len([i for i in center.incidents.values() if i["category"] == "vlan"]) == 1
    assert env.router_calls() == []
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)


async def test_case08_without_configuration_manager_data_is_not_available(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options={})
    center = await _core_center(env, FakeDisk())
    view = center.overview(actor=None)
    det = {d["id"]: d for d in view["detections"]}["vlan_segmentation_drift"]
    assert det["availability"] == "not_available"
    assert det["reason"]
    assert "config.drift" in det["missing"]
    assert center.incidents == {}
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)


async def test_inactive_center_registers_nothing_with_the_core(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    listeners = env.core.audit.listener_count
    center = await _core_center(env, FakeDisk(), enabled=False)
    assert not center.active
    assert env.core.audit.listener_count == listeners
    assert "security_center" not in env.core.audit.registered_modules()
    await stop(env)


async def test_actions_need_an_admin_and_are_audited(core_disks, tmp_path) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    center = await _core_center(env, FakeDisk())
    center.trust.observe(SimpleNamespace(mac=M1, private_mac=None), T0)
    with pytest.raises(SecurityCenterError) as denied:
        await center.async_confirm_device(M1, actor=PLAIN)
    assert denied.value.reason == "not_admin"
    assert center.counters["actions_denied"] == 1
    assert center.trust.state(M1, T0 + 1).value != "known"

    await center.async_confirm_device(M1, actor=ADMIN, name="Laptop", now=T0 + 1)
    assert center.trust.state(M1, T0 + 2).value == "known"
    await center.async_set_device_name(M1, "Notebook", actor=ADMIN, now=T0 + 2)
    assert center.trust.get(M1).name == "Notebook"
    confirmed = env.core.audit.events(types=["security_center.trust_confirmed"])
    renamed = env.core.audit.events(types=["security_center.trust_renamed"])
    assert len(confirmed) == 1 and len(renamed) == 1
    stored = json.dumps([e.to_dict() for e in (*confirmed, *renamed)], default=str)
    assert M1 not in stored and M1.lower() not in stored
    assert "Laptop" not in stored and "Notebook" not in stored

    center._record(security_event("wifi_assoc_burst", T0, router_id=env.rid), T0)
    inc_id = next(iter(center.incidents))
    with pytest.raises(SecurityCenterError):
        await center.async_set_incident_status(inc_id, "resolved", actor=PLAIN)
    view = await center.async_set_incident_status(inc_id, "confirmed", actor=ADMIN)
    assert view["status"] == "confirmed"
    changed = env.core.audit.events(types=["security_center.incident_status_changed"])
    assert len(changed) == 1 and changed[0].incident_ref == inc_id
    with pytest.raises(SecurityCenterError):
        await center.async_set_incident_status(inc_id, "deleted", actor=ADMIN)
    # the store keeps no raw user ids
    payload = json.dumps(center._data_to_save())
    assert ADMIN_ID not in payload and USER_ID not in payload
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)


async def test_admin_sees_plain_identities_others_pseudonyms(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    center = await _core_center(env, FakeDisk())
    center.trust.observe(
        SimpleNamespace(mac=M1, private_mac=None, ip="192.0.2.10", hostname="pc"),
        T0,
    )
    center.trust.set_name(M1, "Laptop")
    center._record(security_event("wifi_assoc_burst", T0, router_id=env.rid), T0)
    api = env.api
    admin = await api.guard.async_verify_actor(ADMIN)
    plain = await api.guard.async_verify_actor(PLAIN)
    seen = center.overview(actor=admin, now=T0 + 1)
    assert seen["admin_view"] is True
    assert (
        seen["devices"][0]["mac"] == M1.lower()
        and seen["devices"][0]["name"] == "Laptop"
    )
    assert seen["incidents"][0]["client"] is None  # M2 is not in the book
    hidden = center.overview(actor=plain, now=T0 + 1)
    text = json.dumps(hidden, ensure_ascii=False)
    for secret in (M1, M2, M1.lower(), M2.lower(), "192.0.2.10", "Laptop", '"pc"'):
        assert secret not in text, secret
    assert hidden["devices"][0]["mac"].startswith("cli_")
    assert hidden["incidents"][0]["client_ref"].startswith("cli_")
    # the pseudonym of the incident filters the timeline
    ref = hidden["incidents"][0]["client_ref"]
    assert center.overview(actor=plain, client=ref, now=T0 + 1)["incidents"]
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)


async def test_settings_update_needs_an_admin_and_activates(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    sec = FakeDisk()
    center = await _core_center(env, sec, enabled=False)
    assert not center.active
    listeners = env.core.audit.listener_count
    with pytest.raises(SecurityCenterError):
        await center.async_update_settings({"enabled": True}, actor=PLAIN)
    assert env.core.audit.listener_count == listeners
    assert not center.enabled
    with pytest.raises(SecurityCenterError) as bad:
        await center.async_update_settings({"log_path": "ftp"}, actor=ADMIN)
    assert bad.value.reason == "invalid_settings"
    await center.async_update_settings({"log_path": "syslog"}, actor=ADMIN)
    assert not center.active and env.core.audit.listener_count == listeners
    assert env.core.audit.events(types=["security_center.settings_changed"]) == ()
    await center.async_update_settings(
        {"enabled": True, "log_path": "collector"}, actor=ADMIN
    )
    assert center.active and center.enabled
    changed = env.core.audit.events(types=["security_center.settings_changed"])
    assert len(changed) == 1
    await center.async_update_settings({"enabled": False}, actor=ADMIN)
    assert not center.active
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)
    assert sec.saves and sec.saves[-1]["settings"]["log_path"] == "collector"


async def test_router_forgotten_event_reaches_the_center(core_disks, tmp_path) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    center = await _core_center(env, FakeDisk())
    center._record(security_event("wifi_assoc_burst", T0, router_id=env.rid), T0)
    event = SimpleNamespace(
        source="core",
        ts=None,
        type=CoreEventType.ROUTER_FORGOTTEN.value,
        router_id=env.rid,
        data={},
    )
    with patch.object(security_center, "forgotten_router_id", return_value=env.rid):
        center._on_core_event(event)
    assert center.incidents == {}
    assert center.counters["routers_forgotten"] == 1
    await stop(env)


async def test_trust_indicators_from_findings_mark_suspicious(disks) -> None:
    hass = make_hass()
    center = await center_for(hass, "r1")
    center.trust.observe(SimpleNamespace(mac=M3, private_mac=None), T0)
    notices = center.trust.add_indicator(M3, Indicator.LOGIN_FAILURES, T0 + 1)
    notices += center.trust.add_indicator(M3, Indicator.PORT_SCAN, T0 + 2)
    events = center._apply_notices(notices, RID1, T0 + 2)
    assert center.trust.state(M3, T0 + 3).value == "suspicious"
    for event in events:
        center._record(event, T0 + 3)
    assert any(i["detector"] == "trust_suspicious" for i in center.incidents.values())
