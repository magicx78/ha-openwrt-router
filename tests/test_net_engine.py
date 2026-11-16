"""Tests for net_engine.py (P2): store, life cycle, ingest, diagnostics, poll cost.

The HA ``Store`` is replaced by an in-memory fake (``disk`` fixture), so a
"restart" is a new engine reading what the old one wrote. Log fixtures follow
the read-only live checks of 2026-11-16 (OpenWrt 25.12.1, hostapd standard
log level, many crond lines); MACs are locally administered test values.
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import json
import logging
import tempfile
import time
from pathlib import Path
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
        self.load_gate: asyncio.Event | None = None
        self.created: list[tuple[Any, ...]] = []
        self.path = "/nonexistent/.storage/openwrt_router.intelligence"


class FakeStore:
    def __init__(self, disk: FakeDisk, hass: Any, version: int, key: str, **kw: Any):
        self.disk = disk
        self.path = disk.path
        disk.created.append((version, key, kw.get("minor_version")))

    async def async_load(self) -> Any:
        if self.disk.load_gate is not None:
            await self.disk.load_gate.wait()
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


@pytest.fixture
def store_dir() -> Any:
    """A scratch directory (``tempfile``: pytest's own base dir may be locked)."""
    with tempfile.TemporaryDirectory() as name:
        yield Path(name)


async def _run_in_executor(func: Any, *args: Any) -> Any:
    return func(*args)


def make_hass() -> MagicMock:
    hass = MagicMock()
    hass.data = {}
    hass.async_add_executor_job = AsyncMock(side_effect=_run_in_executor)
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
    batch = data.new_log_batch
    assert batch is not None
    # HA time right after the fetch (clock check, P3 review M1)
    assert batch.fetched_at is not None
    assert abs(batch.fetched_at - time.time()) < 60
    assert dataclasses.replace(batch, fetched_at=None) == LogBatch(
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

    # P3: the same replies also carry what the infrastructure detectors read
    # (localtime/uptime, service PIDs, carrier and error counters). Poll 2
    # restarts dnsmasq, poll 3 drops the wan and lan1 carriers (lan1 is a
    # client port: only counted, P3 review M6), poll 4 is a reboot.
    uptimes = [86_400, 86_460, 86_520, 86_580, 30, 90]
    pids = [100, 100, 222, 222, 7, 7]

    async def run(with_engine: bool) -> tuple[int, NetIntelligence | None]:
        queue = list(answers)
        poll = {"n": 0}

        def log_read(_params: dict[str, Any]) -> Any:
            return {"log": queue.pop(0) if queue else []}

        def system_info(_params: dict[str, Any]) -> Any:
            n = poll["n"]
            return {
                **model._SYSTEM_INFO,
                "uptime": uptimes[n],
                "localtime": 1_763_283_600 + n * 60,
            }

        def service_list(_params: dict[str, Any]) -> Any:
            instance = {"running": True, "pid": pids[poll["n"]]}
            return {"dnsmasq": {"instances": {"cfg01411c": instance}}}

        def device_status(params: dict[str, Any]) -> Any:
            devices = copy.deepcopy(model._DEVICES)
            for dev in devices.values():
                dev["carrier"] = True
                dev["statistics"].update(rx_errors=0, tx_errors=0)
            devices["lan1"]["carrier"] = poll["n"] != 3
            devices["wan"]["carrier"] = poll["n"] != 3
            name = params.get("name")
            return devices if name is None else devices.get(name)

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
            patch.dict(
                model.RESPONSES,
                {
                    ("log", "read"): log_read,
                    ("system", "info"): system_info,
                    ("service", "list"): service_list,
                    ("network.device", "status"): device_status,
                },
            ),
            patch(
                "custom_components.openwrt_router.api.asyncssh.connect",
                AsyncMock(side_effect=AssertionError("SSH must not be used")),
            ),
            patch("asyncio.open_connection", side_effect=OSError("no net")),
        ):
            for n in range(6):
                poll["n"] = n
                coordinator.data = await coordinator._async_update_data()
                if engine is not None:
                    engine.async_ingest_coordinator("r1", coordinator)
        return session.post.call_count, engine

    calls_without, _ = await run(False)
    calls_with, engine = await run(True)
    assert calls_with == calls_without > 0
    assert engine is not None
    kinds = sorted(e.kind for e in engine.ring)
    assert kinds == [
        "lan.port_down",
        "system.reboot",
        "system.service_restart",
        "wifi.inactivity_timeout",
        "wifi.psk_mismatch",
    ]
    [down] = [e for e in engine.ring if e.kind == "lan.port_down"]
    assert down.subject == {"port": "wan"}
    assert engine.counters.hourly("r1", "lan.port_down", time.time(), 1) == 2


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


# --- P2 review (2026-11-16) -------------------------------------------------------------

ULID1 = "01JD0000000000000000000001"  # config entry ids are 26-char ULIDs
ULID2 = "01JD0000000000000000000002"


def _ingest_series(
    engine: NetIntelligence, step: float, polls: int, *, mono: bool
) -> float:
    """``polls`` polls ``step`` s apart, an event every sixth; returns the end time."""
    now, clock = T0, 5_000.0
    for i in range(1, polls + 1):
        events = (wifi(WIFI_PSK_MISMATCH, i),) if i % 6 == 0 else ()
        data = poll(events, last_id=i)
        if mono:
            engine.ingest("r1", data, now, clock)
        else:
            engine.ingest("r1", data, now)
        now += step
        clock += step
    return now - step


@pytest.mark.asyncio
async def test_m1_slow_polls_keep_pruning_with_monotonic_time(disk: FakeDisk) -> None:
    # SSH fallback: 300 s interval plus the poll duration, 35 days long
    engine = await engine_for(make_hass(), "r1")
    end = _ingest_series(engine, 305, 35 * 86_400 // 305, mono=True)
    assert not engine.machine.prune_held
    buckets = engine.counters._data["r1"]["wifi.psk_mismatch"]
    assert len(buckets["h"]) <= 49  # hourly for 48 h only
    assert len(buckets["d"]) <= 31  # then daily for 30 days
    assert min(buckets["h"]) >= int(end // 3600) - 49


@pytest.mark.asyncio
async def test_m1_slow_polls_without_monotonic_time_hold_one_step_only(
    disk: FakeDisk,
) -> None:
    engine = await engine_for(make_hass(), "r1")
    _ingest_series(engine, 305, 5 * 86_400 // 305, mono=False)
    buckets = engine.counters._data["r1"]["wifi.psk_mismatch"]
    assert len(buckets["h"]) <= 50


def test_m1_machine_clock_jump_detection() -> None:
    from custom_components.openwrt_router.net_rules import AlarmMachine

    machine = AlarmMachine()
    machine.sync_clock(T0, 100.0)
    machine.sync_clock(T0 + 305, 405.0)  # slow poll: wall and monotonic agree
    assert not machine.prune_held
    machine.sync_clock(T0 + 40 * 86_400, 465.0)  # wall clock jumped 40 days
    assert machine.prune_held
    machine.update(T0 + 40 * 86_400)  # the same instant again: still held
    assert machine.prune_held
    machine.sync_clock(T0 + 40 * 86_400 + 60, 525.0)
    assert not machine.prune_held
    # no monotonic reference (first step after a restart): one step only
    restarted = AlarmMachine.from_dict(machine.to_dict())
    restarted.sync_clock(T0 + 42 * 86_400, 10.0)
    assert restarted.prune_held
    restarted.sync_clock(T0 + 42 * 86_400 + 305, 315.0)
    assert not restarted.prune_held
    # callers without monotonic time: a hold never lasts two steps
    legacy = AlarmMachine()
    legacy.sync_clock(T0)
    legacy.sync_clock(T0 + 305)
    assert legacy.prune_held
    legacy.sync_clock(T0 + 610)
    assert not legacy.prune_held


@pytest.mark.asyncio
async def test_m1_listener_passes_monotonic_time(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    coordinator = SimpleNamespace(data=poll((wifi(WIFI_PSK_MISMATCH, 1),)))
    with (
        patch.object(net_engine.time, "time", return_value=T0),
        patch.object(net_engine.time, "monotonic", return_value=42.0),
        patch.object(engine, "ingest") as ingest,
    ):
        engine.async_ingest_coordinator("r1", coordinator)
    # no config entry or interval on this coordinator: both unknown
    ingest.assert_called_once_with(
        "r1", coordinator.data, T0, 42.0, host=None, interval=None
    )


def _incident_dict(incident_id: str) -> dict[str, Any]:
    from custom_components.openwrt_router.net_rules import AlarmMachine

    machine = AlarmMachine()
    machine.update(
        T0,
        [Evidence("wan_down", "r1", Scope.ROUTER, value=1, router="r1", kind="poll")],
    )
    data = machine.to_dict()["incidents"][0]
    data["id"] = incident_id
    return data


@pytest.mark.asyncio
async def test_m2_huge_numbers_and_odd_digits_do_not_break_loading(
    disk: FakeDisk,
) -> None:
    event = {"router": "r1", "category": "wifi", "kind": "wifi.psk_mismatch"}
    disk.data = {
        "seq": 2,
        "events": [
            {**event, "id": "r1:1", "ts": 10**400},
            # superscript two: isdigit() is True, int() fails
            {**event, "id": "r1:\u00b2", "ts": T0},
            {**event, "id": "r1:3", "ts": T0, "src_ts": 10**400},
        ],
        "machine": {"incidents": [_incident_dict("inc-\u00b2")], "last_now": 10**400},
        "counters": {"r1": {"k": {"h": {str(10**400): 1, "\u00b2": 1}}}},
    }
    engine = await engine_for(make_hass(), "r1")
    assert engine.loaded and not engine.load_failed
    assert [e.id for e in engine.ring] == ["r1:\u00b2", "r1:3"]
    assert list(engine.ring)[-1].src_ts is None
    assert len(engine.machine.incidents()) == 1
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0 + 60)
    assert [e.id for e in engine.ring][-1] == "r1:4"


@pytest.mark.asyncio
async def test_m2_any_restore_error_starts_empty_and_marks_the_load_failed(
    disk: FakeDisk, caplog: pytest.LogCaptureFixture
) -> None:
    disk.data = {
        "events": [
            {"id": "r1:1", "ts": T0, "router": "r1", "category": "wifi", "kind": "k"}
        ],
        "log_marks": {"r1": {"last_id": 1}},
    }
    with (
        patch.object(
            net_engine.EventCounters, "from_dict", side_effect=RuntimeError("bug")
        ),
        caplog.at_level(logging.WARNING, logger=net_engine.__name__),
    ):
        engine = await engine_for(make_hass(), "r1")
    assert engine.loaded and engine.load_failed
    assert len(engine.ring) == 0 and engine._log_marks == {}
    assert "starting with an empty history" in caplog.text
    assert engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0) == 1


@pytest.mark.asyncio
async def test_m3_no_ingest_or_save_after_the_last_unload(disk: FakeDisk) -> None:
    hass = make_hass()
    engine = await engine_for(hass, "r1")
    await async_unload_net_intelligence(hass, "r1")
    assert len(disk.saves) == 1
    # a poll that was already under way reaches the orphaned engine
    assert engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0) == 0
    engine.schedule_save()
    assert disk.delayed == []
    assert len(engine.ring) == 0


@pytest.mark.asyncio
async def test_m3_unregistered_router_is_not_ingested(disk: FakeDisk) -> None:
    hass = make_hass()
    engine = await engine_for(hass, "r1", "r2")
    await async_unload_net_intelligence(hass, "r1")
    assert engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0) == 0
    assert engine.ingest("r2", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("load_error", "stored"),
    [
        (OSError("busy"), None),
        (NotImplementedError("newer major version"), None),
        (None, ["unknown", "shape"]),
    ],
)
async def test_m4_failed_load_backs_up_the_file_before_the_first_write(
    disk: FakeDisk, store_dir: Path, load_error: BaseException | None, stored: Any
) -> None:
    path = store_dir / "openwrt_router.intelligence"
    path.write_text('{"history": "precious"}', encoding="utf-8")
    disk.path = str(path)
    disk.load_error = load_error
    disk.data = stored
    hass = make_hass()
    engine = await engine_for(hass, "r1")
    assert engine.load_failed
    backup = store_dir / "openwrt_router.intelligence.bak"
    assert backup.read_text(encoding="utf-8") == '{"history": "precious"}'
    assert hass.async_add_executor_job.await_count == 1  # off the event loop
    # once: a later engine with a readable file does not copy again
    disk.load_error, disk.data = None, None
    backup.unlink()
    await async_unload_net_intelligence(hass, "r1")
    await engine_for(hass, "r1")
    assert not backup.exists()


@pytest.mark.asyncio
async def test_m4_good_load_or_missing_file_makes_no_backup(
    disk: FakeDisk, store_dir: Path
) -> None:
    path = store_dir / "openwrt_router.intelligence"
    path.write_text("{}", encoding="utf-8")
    disk.path = str(path)
    await engine_for(make_hass(), "r1")
    assert not (store_dir / "openwrt_router.intelligence.bak").exists()
    path.unlink()
    disk.load_error = OSError("gone")
    engine = await engine_for(make_hass(), "r1")  # nothing to back up: no error
    assert engine.load_failed
    assert not (store_dir / "openwrt_router.intelligence.bak").exists()


@pytest.mark.asyncio
async def test_m4_backup_error_is_only_logged(
    disk: FakeDisk, caplog: pytest.LogCaptureFixture
) -> None:
    disk.load_error = OSError("busy")
    hass = make_hass()
    hass.async_add_executor_job = AsyncMock(side_effect=OSError("disk full"))
    with caplog.at_level(logging.WARNING, logger=net_engine.__name__):
        engine = await engine_for(hass, "r1")
    assert engine.loaded and engine.load_failed
    assert "backup" in caplog.text


def _realistic_event(n: int) -> NetEvent:
    kinds = (
        ("wifi.psk_mismatch", {"mac": MAC1, "iface": "phy1-ap0"}, {}),
        ("wifi.inactivity_timeout", {"mac": MAC2, "iface": "phy0-ap0"}, {}),
        ("dhcp.nak", {"mac": MAC2, "iface": "br-lan", "ip": IP1}, {}),
        ("wifi.dfs_radar", {"iface": "phy1-ap0"}, {"frequency": 5500, "channel": 100}),
    )
    kind, subject, params = kinds[n % 4]
    router = (ULID1, ULID2)[n % 2]
    return NetEvent(
        id=f"{router}:{n}",
        ts=T0 + n * 37.123,
        router=router,
        category=Category.DHCP if kind.startswith("dhcp") else Category.WIFI,
        kind=kind,
        subject=subject,
        msg_key=kind,
        params=params,
        src_ts=T0 + n * 37.123 - 0.4,
    )


def test_k1_compact_event_round_trip_and_old_format() -> None:
    event = _realistic_event(0)
    compact = event.to_dict(compact=True)
    assert set(compact) == {
        "id",
        "ts",
        "router",
        "category",
        "kind",
        "subject",
        "src_ts",
    }
    assert NetEvent.from_dict(compact) == event
    assert NetEvent.from_dict(event.to_dict()) == event  # old, full records
    odd = NetEvent(
        id="x-1",
        ts=T0,
        router=ULID1,
        category=Category.SYSTEM,
        kind="system.log_gap",
        msg_key="",
        count=3,
        clock_skew=True,
    )
    assert NetEvent.from_dict(odd.to_dict(compact=True)) == odd


@pytest.mark.asyncio
async def test_k1_3000_realistic_events_fit_without_trimming(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), ULID1, ULID2)
    for n in range(3000):
        engine.ring.add(_realistic_event(n))
    end = T0 + 3000 * 37.123
    engine.machine.sync_clock(end)
    engine.machine.update(
        end,
        [
            Evidence(
                "wan_down", f"r{i}", Scope.ROUTER, value=1, router=ULID1, kind="poll"
            )
            for i in range(100)
        ],
    )
    payload = engine._data_to_save()
    assert len(payload["events"]) == 3000
    assert engine.trimmed_events == 0
    assert engine.last_save_bytes is not None
    assert engine.last_save_bytes <= INTEL_MAX_STORE_BYTES
    restarted = NetIntelligence(make_hass())
    restarted._restore(as_json(payload))
    assert list(restarted.ring) == list(engine.ring)


@pytest.mark.asyncio
async def test_k1_trim_serialises_the_rest_of_the_payload_once(
    disk: FakeDisk,
) -> None:
    engine = await engine_for(make_hass(), "r1")
    engine.machine.sync_clock(T0 + 3000)
    for n in range(3000):
        engine.ring.add(_big_event(n))
    with (
        patch.object(engine.machine, "to_dict", wraps=engine.machine.to_dict) as m,
        patch.object(engine.counters, "to_dict", wraps=engine.counters.to_dict) as c,
    ):
        payload = engine._data_to_save()
    assert engine.trimmed_events > 0
    assert m.call_count == 1 and c.call_count == 1
    assert _ha_file_bytes(payload) <= INTEL_MAX_STORE_BYTES


@pytest.mark.asyncio
async def test_k2_setup_failure_unregisters_the_router(disk: FakeDisk) -> None:
    _hass, entry, engine = await _setup_entry_with_engine()
    callbacks = [c.args[0] for c in entry.async_on_unload.call_args_list]
    unregister = [
        cb
        for cb in callbacks
        if getattr(cb, "func", None) == engine.unregister
        and getattr(cb, "args", ()) == (entry.entry_id,)
    ]
    assert len(unregister) == 1
    unregister[0]()
    assert engine.routers == frozenset()


@pytest.mark.asyncio
async def test_k3_gap_lines_are_not_marked_as_clock_skew(disk: FakeDisk) -> None:
    disk.data = {"log_marks": {"r1": {"last_id": 5, "last_time_ms": MS0 + 5000}}}
    engine = await engine_for(make_hass(), "r1")
    ahead = LogEvent(
        category=CATEGORY_WIFI,
        kind=WIFI_PSK_MISMATCH,
        log_id=9,
        time_ms=MS0 + 2 * 3_600_000 + 1000,  # router clock ahead of HA
        mac=MAC1,
        interface="phy1-ap0",
    )
    lines = (wifi(WIFI_PSK_MISMATCH, 5), wifi(WIFI_PSK_MISMATCH, 6), ahead)
    # HA was down for an hour: the gap line is old, but not skewed
    engine.ingest("r1", poll(lines, baseline=True), T0 + 3600)
    old, future = list(engine.ring)
    assert old.ts == (MS0 + 6000) / 1000
    assert old.clock_skew is False
    assert future.clock_skew is True
    # a normal line an hour off still counts as skewed
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 10),)), T0 + 3700)
    assert list(engine.ring)[-1].clock_skew is True


@pytest.mark.asyncio
async def test_k4_setup_racing_the_removal_of_the_last_entry(
    disk: FakeDisk,
) -> None:
    hass = make_hass()
    engine = await engine_for(hass, "r1", "r2")
    engine.ingest("r1", poll((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    engine.ingest("r2", poll((wifi(WIFI_PSK_MISMATCH, 1, MAC2),)), T0)
    await async_unload_net_intelligence(hass, "r1")
    await async_unload_net_intelligence(hass, "r2")

    disk.load_gate = asyncio.Event()
    disk.save_gate = asyncio.Event()  # the removal's write takes a while
    remove = asyncio.create_task(async_remove_router_data(hass, "r2"))
    await asyncio.sleep(0)
    setup = asyncio.create_task(engine_for(hass, "r1"))
    await asyncio.sleep(0)
    disk.load_gate.set()
    for _ in range(5):
        await asyncio.sleep(0)
    disk.save_gate.set()
    await remove
    fresh = await setup
    assert [e.router for e in fresh.ring] == ["r1"]  # r2 does not come back
    assert set(fresh._log_marks) == {"r1"}
    assert [e["id"].split(":")[0] for e in disk.data["events"]] == ["r1"]


@pytest.mark.asyncio
async def test_k4_removal_waits_for_an_engine_that_is_still_loading(
    disk: FakeDisk,
) -> None:
    disk.data = {
        "events": [
            {"id": "r1:1", "ts": T0, "router": "r1", "category": "wifi", "kind": "k"},
            {"id": "r2:2", "ts": T0, "router": "r2", "category": "wifi", "kind": "k"},
        ]
    }
    hass = make_hass()
    disk.load_gate = asyncio.Event()
    setup = asyncio.create_task(engine_for(hass, "r1"))
    await asyncio.sleep(0)
    remove = asyncio.create_task(async_remove_router_data(hass, "r2"))
    await asyncio.sleep(0)
    disk.load_gate.set()
    engine = await setup
    await remove
    assert [e.router for e in engine.ring] == ["r1"]


async def _setup_entry_with_engine() -> tuple[Any, Any, NetIntelligence]:
    from test_init import _make_entry, _make_hass

    hass = _make_hass()
    hass.data = {}
    hass.async_add_executor_job = AsyncMock(side_effect=_run_in_executor)
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
    assert engine is not None
    return hass, entry, engine
