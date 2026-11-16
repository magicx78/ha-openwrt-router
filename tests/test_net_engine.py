"""Tests for net_engine.py (P2): store, life cycle, ingest, diagnostics, poll cost.

The HA ``Store`` is replaced by an in-memory fake (``disk`` fixture), so a
"restart" is a new engine reading what the old one wrote. Log fixtures follow
the read-only live checks of 2026-11-16 (OpenWrt 25.12.1, hostapd standard
log level, many crond lines); MACs are locally administered test values.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.helpers.json import prepare_save_json

from custom_components.openwrt_router import (
    async_remove_entry,
    async_setup_entry,
    async_unload_entry,
    net_engine,
)
from custom_components.openwrt_router.const import (
    INTEL_MAX_STORE_BYTES,
    INTEL_SAVE_DELAY_SECONDS,
    INTEL_STORE_KEY,
    INTEL_STORE_MINOR_VERSION,
    INTEL_STORE_VERSION,
)
from custom_components.openwrt_router.coordinator import (
    LogBatch,
    OpenWrtCoordinatorData,
)
from custom_components.openwrt_router.diagnostics import (
    async_get_config_entry_diagnostics,
)
from custom_components.openwrt_router.log_parser import (
    CATEGORY_DHCP,
    CATEGORY_WIFI,
    DHCP_ACK,
    DHCP_NAK,
    WIFI_CONNECTED,
    WIFI_DISCONNECTED,
    WIFI_INACTIVITY,
    WIFI_PSK_MISMATCH,
    LogEvent,
)
from custom_components.openwrt_router.net_engine import (
    LOG_GAP_KIND,
    NetIntelligence,
    async_get_engine,
    async_get_net_intelligence,
    async_remove_router_data,
    async_unload_net_intelligence,
)
from custom_components.openwrt_router.net_events import (
    Category,
    IncidentStatus,
    NetEvent,
    Scope,
)
from custom_components.openwrt_router.net_rules import Evidence

T0 = 1_763_280_000.0  # 2025-11-16, HA time in seconds
MS0 = int(T0 * 1000)  # router time of the first line
MAC1 = "02:00:5e:10:00:01"
MAC2 = "02:00:5e:10:00:02"
IP1 = "192.0.2.51"
SSID = "Test-Net-xyz"


# --- fakes -------------------------------------------------------------------------


class FakeDisk:
    """What the fake Store keeps 'on disk' (survives a new engine)."""

    def __init__(self) -> None:
        self.data: Any = None
        self.load_error: BaseException | None = None
        self.saves: list[Any] = []
        self.delayed: list[tuple[Any, float]] = []
        self.save_gate: asyncio.Event | None = None
        self.created: list[tuple[Any, ...]] = []


class FakeStore:
    def __init__(self, disk: FakeDisk, hass: Any, version: int, key: str, **kw: Any):
        self.disk = disk
        disk.created.append((version, key, kw.get("minor_version")))

    async def async_load(self) -> Any:
        if self.disk.load_error is not None:
            raise self.disk.load_error
        return copy.deepcopy(self.disk.data)

    def async_delay_save(self, data_func: Any, delay: float = 0) -> None:
        self.disk.delayed.append((data_func, delay))

    async def async_save(self, data: Any) -> None:
        if self.disk.save_gate is not None:
            await self.disk.save_gate.wait()
        self.disk.data = json.loads(json.dumps(data))
        self.disk.saves.append(self.disk.data)


@pytest.fixture
def disk() -> Any:
    disk = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        yield disk


def make_hass() -> MagicMock:
    hass = MagicMock()
    hass.data = {}
    return hass


def wifi(kind: str, log_id: int, mac: str = MAC1, iface: str = "phy1-ap0") -> LogEvent:
    return LogEvent(
        category=CATEGORY_WIFI,
        kind=kind,
        log_id=log_id,
        time_ms=MS0 + log_id * 1000,
        mac=mac,
        interface=iface,
    )


def dhcp(kind: str, log_id: int) -> LogEvent:
    return LogEvent(
        category=CATEGORY_DHCP,
        kind=kind,
        log_id=log_id,
        time_ms=MS0 + log_id * 1000,
        mac=MAC2,
        interface="br-lan",
        ip=IP1,
    )


def poll(
    events: tuple[LogEvent, ...] = (),
    *,
    baseline: bool = False,
    first_id: int | None = None,
    last_id: int | None = None,
    missed: int = 0,
) -> SimpleNamespace:
    """A fresh coordinator data object with one log fetch."""
    ids = [e.log_id for e in events]
    last = last_id if last_id is not None else (max(ids) if ids else None)
    first = first_id if first_id is not None else (min(ids) if ids else None)
    batch = LogBatch(
        baseline=baseline,
        missed=missed,
        first_time_ms=MS0 + first * 1000 if first is not None else None,
        last_id=last,
        last_time_ms=MS0 + last * 1000 if last is not None else None,
    )
    return SimpleNamespace(new_log_events=tuple(events), new_log_batch=batch)


async def engine_for(hass: Any, *entry_ids: str) -> NetIntelligence:
    engine = await async_get_net_intelligence(hass)
    for entry_id in entry_ids:
        engine.register(entry_id)
    return engine


def as_json(value: Any) -> Any:
    return json.loads(json.dumps(value))


# --- store: load / save -------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_uses_the_planned_key_and_versions(disk: FakeDisk) -> None:
    await engine_for(make_hass())
    assert disk.created == [
        (INTEL_STORE_VERSION, INTEL_STORE_KEY, INTEL_STORE_MINOR_VERSION)
    ]
    assert INTEL_STORE_KEY == "openwrt_router.intelligence"


@pytest.mark.asyncio
async def test_empty_store_starts_clean(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    assert engine.loaded and not engine.load_failed
    assert len(engine.ring) == 0
    assert engine.machine.incidents() == []


@pytest.mark.asyncio
async def test_save_and_restart_restore_everything(disk: FakeDisk) -> None:
    hass = make_hass()
    engine = await engine_for(hass, "r1")
    stored = engine.ingest(
        "r1",
        poll(
            (
                wifi(WIFI_PSK_MISMATCH, 1),
                wifi(WIFI_INACTIVITY, 2),
                wifi(WIFI_CONNECTED, 3),
            )
        ),
        T0,
    )
    assert stored == 2  # "connected" is a count-only kind
    engine.machine.update(
        T0 + 60,
        [Evidence("wan_down", "r1", Scope.ROUTER, value=1, router="r1", kind="poll")],
    )
    await async_unload_net_intelligence(hass, "r1")  # last router: flush
    assert len(disk.saves) == 1

    restarted = await engine_for(make_hass(), "r1")
    assert as_json(restarted._payload()) == disk.data
    assert [e.kind for e in restarted.ring] == [
        "wifi.psk_mismatch",
        "wifi.inactivity_timeout",
    ]
    assert restarted.counters.hourly("r1", "wifi.connected", T0, 1) == 1
    [incident] = restarted.machine.incidents()
    assert incident.type == "wan_down"
    assert incident.status is IncidentStatus.ACTIVE
    # the full machine state is stored (tracks too, plan review P2-5)
    assert disk.data["machine"]["tracks"]
    assert disk.data["log_marks"] == {"r1": {"last_id": 3, "last_time_ms": MS0 + 3000}}
    # new events continue the id sequence
    restarted.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 4),)), T0 + 120)
    ids = [e.id for e in restarted.ring]
    assert len(set(ids)) == len(ids) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        json.JSONDecodeError("broken", "{", 0),
        NotImplementedError("foreign major version"),
        OSError("disk"),
    ],
)
async def test_unreadable_store_starts_empty_with_warning(
    disk: FakeDisk, caplog: pytest.LogCaptureFixture, error: BaseException
) -> None:
    disk.load_error = error
    with caplog.at_level(logging.WARNING, logger=net_engine.__name__):
        engine = await engine_for(make_hass(), "r1")
    assert engine.loaded and engine.load_failed
    assert "starting with an empty history" in caplog.text
    assert engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0) == 1


@pytest.mark.asyncio
async def test_store_of_unknown_shape_starts_empty_with_warning(
    disk: FakeDisk, caplog: pytest.LogCaptureFixture
) -> None:
    disk.data = ["not", "a", "dict"]
    with caplog.at_level(logging.WARNING, logger=net_engine.__name__):
        engine = await engine_for(make_hass(), "r1")
    assert engine.load_failed
    assert "unknown format" in caplog.text


@pytest.mark.asyncio
async def test_damaged_parts_of_a_store_are_skipped(disk: FakeDisk) -> None:
    disk.data = {
        "settings": {"max_events": -5, "retention_days": "x"},
        "seq": "junk",
        "events": [
            None,
            {"id": "r1:7", "ts": T0, "router": "r1", "category": "wifi", "kind": "k"},
        ],
        "machine": 5,
        "counters": {"r1": {"k": {"h": {"x": 1, str(int(T0 // 3600)): 2}}}},
        "log_marks": {"r1": {"last_id": True, "last_time_ms": MS0}, "r2": "junk"},
    }
    engine = await engine_for(make_hass(), "r1")
    assert not engine.load_failed
    assert engine.settings["max_events"] == 3000
    assert [e.id for e in engine.ring] == ["r1:7"]
    assert engine.counters.hourly("r1", "k", T0, 1) == 2
    assert engine._log_marks == {"r1": {"last_time_ms": MS0}}
    # the next event id does not collide with the stored one
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    assert [e.id for e in engine.ring][-1] == "r1:8"


@pytest.mark.asyncio
async def test_delayed_save_is_scheduled_once_per_window(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 2),)), T0 + 60)
    # HA moves a pending delayed write back on every call: call it once
    assert len(disk.delayed) == 1
    data_func, delay = disk.delayed[0]
    assert delay == INTEL_SAVE_DELAY_SECONDS == 300
    payload = data_func()  # HA writes: the window is over
    assert len(payload["events"]) == 2
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 3),)), T0 + 120)
    assert len(disk.delayed) == 2


@pytest.mark.asyncio
async def test_poll_without_new_log_data_schedules_no_save(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    engine.ingest("r1", SimpleNamespace(), T0)  # a poll without log read
    engine.ingest("r1", poll(last_id=None), T0 + 60)  # empty log answer
    assert disk.delayed == []


# --- store: 1.5 MB cap --------------------------------------------------------------


def _big_event(n: int) -> NetEvent:
    return NetEvent(
        id=f"r1:{n}",
        ts=T0 + n,
        router="r1",
        category=Category.WIFI,
        kind="wifi.psk_mismatch",
        subject={"mac": MAC1, "iface": "phy1-ap0"},
        params={"note": "x" * 600},
    )


def _ha_file_bytes(payload: dict[str, Any]) -> int:
    """Size of the file exactly as HA's Store would write it."""
    _mode, data = prepare_save_json(
        {
            "version": INTEL_STORE_VERSION,
            "minor_version": INTEL_STORE_MINOR_VERSION,
            "key": INTEL_STORE_KEY,
            "data": payload,
        }
    )
    return len(data if isinstance(data, bytes) else data.encode())


@pytest.mark.asyncio
async def test_store_is_capped_at_1_5_mb_dropping_the_oldest_events(
    disk: FakeDisk,
) -> None:
    engine = await engine_for(make_hass(), "r1")
    engine.machine.sync_clock(T0 + 3000)
    for n in range(3000):
        engine.ring.add(_big_event(n))
    assert _ha_file_bytes(engine._payload()) > INTEL_MAX_STORE_BYTES  # ~2.5 MB

    payload = engine._data_to_save()
    size = _ha_file_bytes(payload)
    assert size <= INTEL_MAX_STORE_BYTES == 1_500_000
    assert size > 0.9 * INTEL_MAX_STORE_BYTES  # trims no more than needed
    assert engine.last_save_bytes == size
    kept = [e["id"] for e in payload["events"]]
    assert kept[-1] == "r1:2999"  # the newest stay
    assert "r1:0" not in kept  # the oldest go
    assert engine.trimmed_events == 3000 - len(kept)
    assert [e.id for e in engine.ring] == kept  # memory agrees with the file


@pytest.mark.asyncio
async def test_store_under_the_cap_is_not_trimmed(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    engine.machine.sync_clock(T0 + 100)
    for n in range(100):
        engine.ring.add(_big_event(n))
    payload = engine._data_to_save()
    assert len(payload["events"]) == 100
    assert engine.trimmed_events == 0


@pytest.mark.asyncio
async def test_store_too_big_without_events_is_written_with_warning(
    disk: FakeDisk, caplog: pytest.LogCaptureFixture
) -> None:
    engine = await engine_for(make_hass(), "r1")
    engine.machine.update(
        T0, [Evidence("wan_down", "r1", Scope.ROUTER, value=1, kind="poll")]
    )
    with (
        patch.object(net_engine, "INTEL_MAX_STORE_BYTES", 100),
        caplog.at_level(logging.WARNING, logger=net_engine.__name__),
    ):
        payload = engine._data_to_save()
    assert payload["machine"]["incidents"]  # incidents are never trimmed
    assert "without any event" in caplog.text


# --- ingest ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_same_data_object_is_ingested_once(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    data = poll((wifi(WIFI_PSK_MISMATCH, 1),))
    assert engine.ingest("r1", data, T0) == 1
    assert engine.ingest("r1", data, T0 + 60) == 0  # failed poll: old data again
    assert len(engine.ring) == 1
    engine.register("r1")  # a reload starts over
    assert engine.ingest("r1", data, T0 + 120) == 1


@pytest.mark.asyncio
async def test_events_carry_subject_params_and_router_time(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    late = LogEvent(
        category=CATEGORY_WIFI,
        kind=WIFI_PSK_MISMATCH,
        log_id=2,
        time_ms=MS0 - 3_600_000,  # router clock an hour behind
        mac=MAC1,
        interface="phy1-ap0",
    )
    engine.ingest("r1", poll((dhcp(DHCP_NAK, 1), late, dhcp(DHCP_ACK, 3))), T0)
    nak, psk = list(engine.ring)
    assert nak.category is Category.DHCP and nak.kind == "dhcp.nak"
    assert nak.subject == {"mac": MAC2, "iface": "br-lan", "ip": IP1}
    assert nak.ts == T0 and nak.src_ts == (MS0 + 1000) / 1000
    assert not nak.clock_skew
    assert psk.clock_skew is True  # router time far from HA time
    assert engine.counters.hourly("r1", "dhcp.ack", T0, 1) == 1  # counted only


@pytest.mark.asyncio
async def test_baseline_without_mark_takes_no_history(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    stored = engine.ingest(
        "r1",
        poll((wifi(WIFI_PSK_MISMATCH, 1), wifi(WIFI_PSK_MISMATCH, 2)), baseline=True),
        T0,
    )
    assert stored == 0
    assert len(engine.ring) == 0
    assert engine._log_marks["r1"] == {"last_id": 2, "last_time_ms": MS0 + 2000}


@pytest.mark.asyncio
async def test_baseline_after_restart_fills_the_gap_from_the_mark(
    disk: FakeDisk,
) -> None:
    disk.data = {"log_marks": {"r1": {"last_id": 5, "last_time_ms": MS0 + 5000}}}
    engine = await engine_for(make_hass(), "r1")
    lines = tuple(wifi(WIFI_PSK_MISMATCH, i) for i in range(3, 9))  # 3..8
    stored = engine.ingest("r1", poll(lines, baseline=True), T0 + 60)
    assert stored == 3  # 6, 7, 8 fell into the gap; 3..5 were seen before
    assert [e.src_ts for e in engine.ring] == [
        (MS0 + i * 1000) / 1000 for i in (6, 7, 8)
    ]
    # gap lines keep their (earlier) router time as event time
    assert [e.ts for e in engine.ring] == [e.src_ts for e in engine.ring]
    assert all(e.kind != LOG_GAP_KIND for e in engine.ring)
    assert engine._log_marks["r1"] == {"last_id": 8, "last_time_ms": MS0 + 8000}


@pytest.mark.asyncio
async def test_baseline_starting_after_the_mark_records_a_log_gap(
    disk: FakeDisk,
) -> None:
    disk.data = {"log_marks": {"r1": {"last_id": 5, "last_time_ms": MS0 + 5000}}}
    engine = await engine_for(make_hass(), "r1")
    lines = (wifi(WIFI_PSK_MISMATCH, 50), wifi(WIFI_DISCONNECTED, 51))
    stored = engine.ingest("r1", poll(lines, baseline=True), T0 + 60)
    assert stored == 2  # the gap marker and the PSK line
    gap, psk = list(engine.ring)
    assert gap.kind == LOG_GAP_KIND and gap.category is Category.SYSTEM
    assert gap.params == {"gap_s": 45}
    assert psk.kind == "wifi.psk_mismatch"
    assert engine.counters.hourly("r1", LOG_GAP_KIND, T0 + 60, 1) == 1


@pytest.mark.asyncio
async def test_router_without_usable_time_keeps_id_only_mark(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    data = SimpleNamespace(
        new_log_events=(),
        new_log_batch=LogBatch(
            baseline=True, missed=0, first_time_ms=None, last_id=9, last_time_ms=None
        ),
    )
    engine.ingest("r1", data, T0)
    assert engine._log_marks["r1"] == {"last_id": 9}
    # a later baseline cannot be matched by time: takes nothing
    stored = engine.ingest(
        "r1", poll((wifi(WIFI_PSK_MISMATCH, 10),), baseline=True), T0 + 60
    )
    assert stored == 0


@pytest.mark.asyncio
async def test_engine_clock_never_goes_backwards(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1", "r2")
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    engine.ingest("r2", poll((wifi(WIFI_PSK_MISMATCH, 2),)), T0 - 30)  # 30 s back
    times = [e.ts for e in engine.ring]
    assert times == [T0, T0]
    assert engine.machine.last_now == T0


@pytest.mark.asyncio
async def test_large_clock_jump_back_shifts_events_with_the_machine(
    disk: FakeDisk,
) -> None:
    engine = await engine_for(make_hass(), "r1")
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 2),)), T0 - 86_400)
    first, second = list(engine.ring)
    assert first.ts == T0 - 86_400  # shifted by the same day
    assert second.ts == T0 - 86_400
    assert first.src_ts == (MS0 + 1000) / 1000  # router time untouched


@pytest.mark.asyncio
async def test_forward_jump_does_not_wipe_history(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    jump = T0 + 40 * 86_400
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 2),)), jump)
    assert len(engine.ring) == 2  # nothing pruned in the jump poll
    hour = int(T0 // 3600)
    assert engine.counters._data["r1"]["wifi.psk_mismatch"]["h"][hour] == 1
    engine._data_to_save()  # a save right after the jump keeps it too
    assert len(engine.ring) == 2
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 3),)), jump + 60)
    assert len(engine.ring) == 2  # normal time again: retention applies


@pytest.mark.asyncio
async def test_listener_never_raises(
    disk: FakeDisk, caplog: pytest.LogCaptureFixture
) -> None:
    engine = await engine_for(make_hass(), "r1")
    coordinator = SimpleNamespace(data=poll((wifi(WIFI_PSK_MISMATCH, 1),)))
    with patch.object(engine, "ingest", side_effect=RuntimeError("boom")):
        engine.async_ingest_coordinator("r1", coordinator)
    assert "could not process a poll" in caplog.text
    engine.async_ingest_coordinator("r1", coordinator)
    assert len(engine.ring) == 1


# --- life cycle: several entries ------------------------------------------------------


@pytest.mark.asyncio
async def test_unload_and_reload_of_several_entries(disk: FakeDisk) -> None:
    hass = make_hass()
    first = await engine_for(hass, "r1")
    assert await engine_for(hass, "r2") is first  # one engine per HA
    first.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    first.ingest("r2", poll((wifi(WIFI_PSK_MISMATCH, 1, MAC2),)), T0 + 1)

    await async_unload_net_intelligence(hass, "r1")
    assert async_get_engine(hass) is first  # r2 still feeds it
    assert first.routers == frozenset({"r2"})
    assert disk.saves == []
    assert len(first.ring) == 2  # an unloaded router's events stay

    # reload r1 while r2 runs: same engine, nothing lost
    assert await engine_for(hass, "r1") is first
    await async_unload_net_intelligence(hass, "r1")
    await async_unload_net_intelligence(hass, "r2")
    assert async_get_engine(hass) is None
    assert len(disk.saves) == 1  # the last unload writes, awaited
    await async_unload_net_intelligence(hass, "r2")  # nothing left: no-op

    second = await engine_for(hass, "r1", "r2")
    assert second is not first
    assert sorted(e.router for e in second.ring) == ["r1", "r2"]


@pytest.mark.asyncio
async def test_setup_racing_the_last_unload_waits_for_the_write(
    disk: FakeDisk,
) -> None:
    hass = make_hass()
    engine = await engine_for(hass, "r1")
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    disk.save_gate = asyncio.Event()
    unload = asyncio.create_task(async_unload_net_intelligence(hass, "r1"))
    await asyncio.sleep(0)
    setup = asyncio.create_task(engine_for(hass, "r1"))
    await asyncio.sleep(0)
    assert not setup.done()  # the new engine waits for the old one's write
    disk.save_gate.set()
    await unload
    fresh = await setup
    assert fresh is not engine
    assert len(fresh.ring) == 1


@pytest.mark.asyncio
async def test_remove_entry_with_running_engine(disk: FakeDisk) -> None:
    hass = make_hass()
    engine = await engine_for(hass, "r1", "r2")
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    engine.ingest("r2", poll((wifi(WIFI_PSK_MISMATCH, 1, MAC2),)), T0)
    engine.machine.update(
        T0,
        [Evidence("wan_down", "r1", Scope.ROUTER, value=1, router="r1", kind="poll")],
    )
    await async_unload_net_intelligence(hass, "r1")
    disk.delayed[0][0]()  # the pending write happened
    disk.delayed.clear()
    await async_remove_router_data(hass, "r1")
    assert [e.router for e in engine.ring] == ["r2"]
    assert "r1" not in engine.counters.to_dict()
    assert "r1" not in engine._log_marks
    assert engine.machine.incidents() == []
    assert len(disk.delayed) == 1  # the removal is written
    await async_remove_router_data(hass, "r1")  # nothing left to remove
    assert len(disk.delayed) == 1


@pytest.mark.asyncio
async def test_remove_last_entry_edits_the_store_directly(disk: FakeDisk) -> None:
    hass = make_hass()
    engine = await engine_for(hass, "r1", "r2")
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    engine.ingest("r2", poll((wifi(WIFI_PSK_MISMATCH, 1, MAC2),)), T0)
    await async_unload_net_intelligence(hass, "r1")
    await async_unload_net_intelligence(hass, "r2")
    assert len(disk.saves) == 1

    await async_remove_router_data(hass, "r2")  # HA: after the unload
    assert len(disk.saves) == 2
    assert [e["router"] for e in disk.data["events"]] == ["r1"]
    assert set(disk.data["log_marks"]) == {"r1"}
    assert async_get_engine(hass) is None  # no engine left behind

    await async_remove_router_data(hass, "unknown")  # nothing to delete
    assert len(disk.saves) == 2


# --- __init__ wiring ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_setup_registers_the_engine_listener_before_the_channel_plan(
    disk: FakeDisk,
) -> None:
    from test_init import _make_entry, _make_hass

    hass = _make_hass()
    hass.data = {}
    entry = _make_entry()
    mock_api = AsyncMock()
    mock_api.reset_acl_blocked = MagicMock()
    coordinator = MagicMock()
    coordinator.async_config_entry_first_refresh = AsyncMock()
    coordinator.data = OpenWrtCoordinatorData()
    with (
        patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ),
        patch("custom_components.openwrt_router.OpenWrtAPI", return_value=mock_api),
        patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=coordinator,
        ),
        patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl",
            AsyncMock(return_value=False),
        ),
        patch(
            "custom_components.openwrt_router.async_get_outage_tracker",
            return_value=MagicMock(),
        ),
        patch(
            "custom_components.openwrt_router.async_get_channel_plan_monitor",
            return_value=MagicMock(),
        ),
        patch("custom_components.openwrt_router.dr.async_get"),
        patch("custom_components.openwrt_router.er.async_get"),
        patch(
            "custom_components.openwrt_router.dr.async_entries_for_config_entry",
            return_value=[],
        ),
        patch(
            "custom_components.openwrt_router.er.async_entries_for_config_entry",
            return_value=[],
        ),
    ):
        assert await async_setup_entry(hass, entry) is True

    engine = async_get_engine(hass)
    assert engine is not None and engine.routers == frozenset({entry.entry_id})
    listeners = [c.args[0] for c in coordinator.async_add_listener.call_args_list]
    engine_listeners = [
        i
        for i, cb in enumerate(listeners)
        if getattr(cb, "func", None) == engine.async_ingest_coordinator
    ]
    assert len(engine_listeners) == 1
    assert engine_listeners[0] < len(listeners) - 1  # the channel plan stays last


@pytest.mark.asyncio
@pytest.mark.parametrize("unload_ok", [True, False])
async def test_unload_entry_awaits_the_engine_only_after_a_clean_unload(
    unload_ok: bool,
) -> None:
    hass = MagicMock()
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=unload_ok)
    entry = MagicMock()
    entry.entry_id = "r1"
    with patch(
        "custom_components.openwrt_router.async_unload_net_intelligence",
        AsyncMock(),
    ) as unload:
        assert await async_unload_entry(hass, entry) is unload_ok
    if unload_ok:
        unload.assert_awaited_once_with(hass, "r1")
    else:
        unload.assert_not_awaited()


@pytest.mark.asyncio
async def test_remove_entry_deletes_router_data_and_never_raises() -> None:
    hass = MagicMock()
    entry = MagicMock()
    entry.entry_id = "r1"
    with patch(
        "custom_components.openwrt_router.async_remove_router_data",
        AsyncMock(side_effect=[None, RuntimeError("disk")]),
    ) as remove:
        await async_remove_entry(hass, entry)
        await async_remove_entry(hass, entry)  # an error is only logged
    assert remove.await_count == 2


# --- diagnostics ----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_diagnostics_show_counts_only(
    disk: FakeDisk, mock_config_entry_with_runtime: Any
) -> None:
    hass = make_hass()
    entry = mock_config_entry_with_runtime
    engine = await engine_for(hass, entry.entry_id)
    events = (
        wifi(WIFI_PSK_MISMATCH, 1),
        wifi(WIFI_INACTIVITY, 2, MAC2, "phy0-ap0"),
        dhcp(DHCP_NAK, 3),
        wifi(WIFI_CONNECTED, 4),
    )
    with patch("time.time", return_value=T0):
        engine.ingest(entry.entry_id, poll(events), T0)
        engine.machine.update(
            T0,
            [
                Evidence(
                    "wifi_auth_failures",
                    MAC1,
                    Scope.CLIENT,
                    router=entry.entry_id,
                    count=3,
                    kind="wifi.psk_mismatch",
                    event_id=f"{entry.entry_id}:1",
                )
            ],
        )
        result = await async_get_config_entry_diagnostics(hass, entry)

    intel = result["intelligence"]
    assert intel["loaded"] is True
    assert intel["events_stored"] == 3
    assert intel["counts_by_category_24h"] == {"dhcp": 1, "wifi": 2}
    assert intel["counts_by_kind_24h"]["wifi.connected"] == 1
    assert intel["active_by_type"] == {"wifi_auth_failures": 1}
    assert intel["log_mark_stored"] is True
    assert intel["score"] is None and intel["coverage"] is None
    dump = json.dumps(result, default=str).lower()
    for secret in (MAC1, MAC2, IP1, SSID, "phy1-ap0", "br-lan", f"{entry.entry_id}:1"):
        assert secret.lower() not in json.dumps(intel).lower(), secret
    for secret in (MAC1, MAC2, IP1):
        assert secret.lower() not in dump, secret


@pytest.mark.asyncio
async def test_diagnostics_without_engine_or_with_engine_error(
    disk: FakeDisk, mock_config_entry_with_runtime: Any
) -> None:
    hass = make_hass()
    entry = mock_config_entry_with_runtime
    result = await async_get_config_entry_diagnostics(hass, entry)
    assert result["intelligence"] == {"loaded": False}
    engine = await engine_for(hass, entry.entry_id)
    with patch.object(engine, "diagnostics", side_effect=RuntimeError("x")):
        result = await async_get_config_entry_diagnostics(hass, entry)
    assert result["intelligence"] == {"loaded": True, "error": True}


# --- coordinator field ------------------------------------------------------------------------


def _log_line(log_id: int, msg: str) -> dict[str, Any]:
    return {
        "id": log_id,
        "time": MS0 + log_id * 1000,
        "priority": 6,
        "source": 1,
        "msg": msg,
    }


_CROND = "crond[1803]: USER root pid 9000 cmd /usr/bin/ha-collect"
_PSK = f"hostapd: phy1-ap0: AP-STA-POSSIBLE-PSK-MISMATCH {MAC1}"
_INACTIVE = (
    f"hostapd: phy0-ap0: STA {MAC2} IEEE 802.11: deauthenticated due to "
    "inactivity (timer DEAUTH/REMOVE)"
)
_CONNECTED = f"hostapd: phy1-ap0: AP-STA-CONNECTED {MAC1} auth_alg=sae"


def test_coordinator_hands_over_log_events_and_cursor_facts() -> None:
    from test_poll_no_ssh import _make_coordinator

    coordinator = _make_coordinator(AsyncMock())
    data = OpenWrtCoordinatorData()
    assert data.new_log_events == () and data.new_log_batch is None
    first = [_log_line(1, _CROND), _log_line(2, _PSK), _log_line(3, _CROND)]
    coordinator._process_log(first, data)
    # the baseline is handed over too; the engine decides what to take
    assert [e.kind for e in data.new_log_events] == [WIFI_PSK_MISMATCH]
    assert data.new_log_batch == LogBatch(
        baseline=True,
        missed=0,
        first_time_ms=MS0 + 1000,
        last_id=3,
        last_time_ms=MS0 + 3000,
    )

    data = OpenWrtCoordinatorData()
    second = [*first, _log_line(6, _INACTIVE), _log_line(7, _CONNECTED)]
    coordinator._process_log(second, data)
    assert [e.kind for e in data.new_log_events] == [WIFI_INACTIVITY, WIFI_CONNECTED]
    assert data.new_log_batch is not None
    assert data.new_log_batch.baseline is False
    assert data.new_log_batch.missed == 2
    assert data.new_log_batch.last_id == 7
    # never part of the exported data (MACs, IPs)
    exported = data.as_dict()
    assert "new_log_events" not in exported and "new_log_batch" not in exported


# --- poll cost: no extra router calls ------------------------------------------------------------


@pytest.mark.asyncio
async def test_engine_adds_no_router_calls() -> None:
    import time as time_module

    import test_poll_no_ssh as model

    from custom_components.openwrt_router.api import OpenWrtAPI

    answers = [
        [_log_line(1, _CROND), _log_line(2, _PSK)],
        [
            _log_line(1, _CROND),
            _log_line(2, _PSK),
            _log_line(3, _PSK),
            _log_line(4, _INACTIVE),
        ],
        [_log_line(i, _CROND) for i in range(1, 6)],
    ]

    async def run(with_engine: bool) -> tuple[int, NetIntelligence | None]:
        queue = list(answers)

        def log_read(_params: dict[str, Any]) -> Any:
            return {"log": queue.pop(0) if queue else []}

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
        coordinator = model._make_coordinator(api)
        engine: NetIntelligence | None = None
        if with_engine:
            with patch.object(
                net_engine, "Store", lambda *a, **kw: FakeStore(FakeDisk(), *a, **kw)
            ):
                engine = NetIntelligence(make_hass())
                await engine.async_load()
            engine.register("r1")
        model._MODE["empty_tables"] = False
        with (
            patch.dict(model.RESPONSES, {("log", "read"): log_read}),
            patch(
                "custom_components.openwrt_router.api.asyncssh.connect",
                AsyncMock(side_effect=AssertionError("SSH must not be used")),
            ),
            patch("asyncio.open_connection", side_effect=OSError("no net")),
        ):
            for n in range(6):
                coordinator.data = await coordinator._async_update_data()
                if engine is not None:
                    engine.async_ingest_coordinator("r1", coordinator)
        return session.post.call_count, engine

    calls_without, _ = await run(False)
    calls_with, engine = await run(True)
    assert calls_with == calls_without > 0
    assert engine is not None
    kinds = [e.kind for e in engine.ring]
    assert kinds == ["wifi.psk_mismatch", "wifi.inactivity_timeout"]


def test_machine_remove_router_keeps_incidents_shared_with_other_routers() -> None:
    from custom_components.openwrt_router.net_rules import AlarmMachine

    machine = AlarmMachine()

    def auth(router: str, n: int) -> Evidence:
        return Evidence(
            "wifi_auth_failures",
            MAC1,
            Scope.CLIENT,
            router=router,
            count=3,
            kind="wifi.psk_mismatch",
            event_id=f"{router}:{n}",
        )

    machine.update(T0, [auth("r1", 1), auth("r2", 1)])
    machine.update(
        T0,
        [Evidence("wan_down", "r1", Scope.ROUTER, value=1, router="r1", kind="poll")],
    )
    shared = [i for i in machine.incidents() if i.type == "wifi_auth_failures"]
    assert len(shared) == 1 and sorted(shared[0].routers) == ["r1", "r2"]

    assert machine.remove_router("r1") == 1  # only the router's own incident
    [left] = machine.incidents()
    assert left.type == "wifi_auth_failures" and left.routers == ["r2"]
    assert machine.remove_router("r1") == 0
