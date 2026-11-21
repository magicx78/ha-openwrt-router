"""Traffic Analytics engine (plan 2026-11-20, §6.1, §6.2, §10): traffic_engine.py.

Mocks only: the core store runs on ``FakeDisks``, coordinators are
``FakeCoordinator`` objects with a MagicMock api, the enterprise core is
the real one on FakeDisks (end-to-end test). No Home Assistant instance,
no router, no network. Router ids and MACs are synthetic test values.
"""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from core_testkit import (
    FakeCoordinator,
    FakeDisks,
    FakeEntry,
    core_of,
    drain,
    router_data,
    setup_router,
)
from core_testkit import make_hass as core_make_hass

from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError
from custom_components.openwrt_router.const import (
    DATA_TRAFFIC_ANALYTICS,
    OPTION_TRAFFIC_ENABLED,
    OPTION_TRAFFIC_HISTORY_PROFILE,
    TRAFFIC_COARSE_STORE_KEY,
)
from custom_components.openwrt_router.core_masking import pseudonymise_identifier
from custom_components.openwrt_router.traffic_collect import (
    ExtraCallPlanner,
    OffloadState,
    PollState,
    Snapshot,
)
from custom_components.openwrt_router.traffic_const import (
    BLOCK_BUSY,
    BLOCK_NOT_DUE,
    BLOCK_PAUSED,
    BLOCK_POLL_RUNNING,
    BLOCK_POLL_SOON,
    BLOCK_SSH_FALLBACK,
    BLOCK_THROTTLED,
    CAP_NETDEV_COUNTERS,
    CAP_OFFLOAD_STATE,
    CAP_STATION_COUNTERS,
    MAX_QUEUE_ROUTERS,
    OPT_OFFLOAD_PROBE,
    OPT_STATION_DETAIL,
    OPT_SYSFS_FALLBACK,
    REASON_CORE_MISSING,
    REASON_MODULE_KEY_MISSING,
    REASON_PAUSED,
    REASON_PERMISSION_DENIED,
)
from custom_components.openwrt_router.traffic_engine import (
    EXTRA_OPTION_KEYS,
    TrafficEngine,
    TrafficSettingsError,
    async_apply_traffic_options,
    async_get_traffic_engine,
    async_release_traffic,
    async_setup_traffic,
    default_settings,
    merge_settings,
    options_from_entry,
    settings_from_store,
)
from custom_components.openwrt_router.traffic_model import (
    Coverage,
    Quality,
    Scope,
    Source,
    valid_client_ref,
    valid_router_id,
)

RID = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
KEY = bytes(range(32))
MAC1 = "02:00:5e:10:00:01"  # locally administered test values
MAC2 = "02:00:5e:10:00:02"
SIX_HOURS = 6 * 3600.0


class Clock:
    """Settable monotonic clock."""

    def __init__(self, t: float = 1_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def make_hass() -> Any:
    return core_make_hass()


def counters(rx: int, tx: int, speed: str = "1000F") -> dict[str, Any]:
    return {
        "rx_bytes": rx,
        "tx_bytes": tx,
        "rx_packets": rx // 100,
        "tx_packets": tx // 100,
        "rx_errors": 0,
        "tx_errors": 0,
        "rx_dropped": 0,
        "tx_dropped": 0,
        "speed": speed,
        "up": True,
        "carrier": True,
    }


def poll_data(
    mono: float,
    wan: tuple[int, int] = (1_000, 500),
    *,
    uptime: int = 5_000,
    clients: list[dict[str, Any]] | None = None,
) -> Any:
    """A gateway poll with WAN + one port counted and optional clients."""
    data = router_data()
    data.wan_status = {**data.wan_status, "l3_device": "wan"}
    data.uptime = uptime
    data.device_counters = {
        "lan1": counters(wan[0] // 10, wan[1] // 10),
        "wan": counters(*wan),
    }
    data.counters_sampled_mono = mono
    data.clients = list(clients or [])
    return data


def station(mac: str, rx: int | None, tx: int | None, radio: str = "phy0-ap0") -> dict:
    return {"mac": mac, "radio": radio, "rx_bytes": rx, "tx_bytes": tx}


def store_settings(disks: FakeDisks, settings: dict[str, Any]) -> None:
    disks[TRAFFIC_COARSE_STORE_KEY].data = {
        "version": 1,
        "minor_version": 1,
        "key": TRAFFIC_COARSE_STORE_KEY,
        "data": {"settings": settings},
    }


async def start(
    hass: Any,
    *,
    entry_id: str = "e1",
    coord: FakeCoordinator | None = None,
    rids: dict[str, str | None] | None = None,
    clock: Clock | None = None,
) -> tuple[TrafficEngine, FakeCoordinator]:
    """Engine with test seams, then ``async_setup_traffic`` for one entry."""
    engine = async_get_traffic_engine(hass)
    if engine is None:
        engine = TrafficEngine(hass)
        hass.data[DATA_TRAFFIC_ANALYTICS] = engine
        mapping = rids if rids is not None else {"e1": RID}
        engine.router_id_of = mapping.get
        engine.clock = clock or Clock()
        engine.wall = lambda: 1_800_000_000.0 + engine.clock()
    coord = coord or FakeCoordinator(poll_data(100.0))
    coord.update_interval = timedelta(seconds=60)
    coord.poll_running = False
    rid = engine.router_id_of(entry_id)
    await async_setup_traffic(
        hass, FakeEntry(entry_id, options=entry_options(rid)), coord
    )
    return engine, coord


# Options the next ``start`` gives its entry (set by ``enabled``).
_PENDING: dict[str, Any] = {}


@pytest.fixture(autouse=True)
def _reset_pending():
    _PENDING.clear()
    yield
    _PENDING.clear()


def option_map(on: bool = True, extras: dict[str, bool] | None = None) -> dict:
    """Config entry options of one router (traffic switch and extra calls)."""
    out: dict[str, Any] = {OPTION_TRAFFIC_ENABLED: on}
    for name, value in (extras or {}).items():
        out[EXTRA_OPTION_KEYS[name]] = value
    return out


def entry_options(rid: str | None) -> dict[str, Any]:
    if not _PENDING:
        return {}
    return option_map(True, _PENDING["routers"].get(rid))


def enabled(disks: FakeDisks, routers: dict[str, Any] | None = None) -> None:
    """Traffic on for the entries started next (extra calls per router id)."""
    _PENDING["routers"] = dict(routers or {})


async def two_polls(engine: TrafficEngine, coord: FakeCoordinator, hass: Any) -> None:
    coord.poll(data=poll_data(100.0, (1_000, 500), uptime=5_000))
    await drain(hass)
    engine.clock.t += 10
    coord.poll(data=poll_data(110.0, (1_000 + 1_250_000, 500 + 125_000), uptime=5_010))
    await drain(hass)


# --- default off ----------------------------------------------------------------------------


async def test_off_adds_no_listener_and_creates_nothing(disks: FakeDisks) -> None:
    hass = make_hass()
    engine, coord = await start(hass)
    assert not engine.enabled and not engine.active
    assert coord.listener_count == 0
    for _ in range(3):
        coord.poll()
    # a listener still called (e.g. one left over) returns at once
    engine._on_poll("e1")
    assert engine.queue_length == 0
    assert hass.tasks == [] and not hass.async_create_task.called
    assert engine.status == {} and len(engine.book) == 0
    assert engine.counters == {}
    # off: the store is neither read nor written (Phase K: the switch is an
    # entry option, so nothing has to be loaded)
    assert TRAFFIC_COARSE_STORE_KEY not in disks.options
    assert engine.loaded
    assert coord.router_calls() == []
    assert hass.fired == []
    assert engine.not_ready_reason is None and not engine.module_key_available
    assert engine.summary()["points"] == {"infra": 0, "client": 0}


@pytest.mark.parametrize(
    "stored",
    [
        {"v": 1, "enabled": True, "routers": {}},  # the Phase B-J switch
        {"enabled": "yes", "routers": {}},
        {"routers": {RID: {"offload_probe": True}}},
        "garbage",
        None,
    ],
)
async def test_stored_settings_never_switch_on(disks: FakeDisks, stored: Any) -> None:
    """Only the entry option switches on; an old stored ``enabled`` does not."""
    hass = make_hass()
    store_settings(disks, stored)
    engine, coord = await start(hass)
    assert not engine.active
    assert coord.listener_count == 0
    assert disks[TRAFFIC_COARSE_STORE_KEY].saves == []


@pytest.mark.parametrize(
    "options",
    [
        {OPTION_TRAFFIC_ENABLED: "yes"},
        {OPTION_TRAFFIC_ENABLED: 1},
        {"traffic_offload_probe": True},  # an extra call alone is not the switch
        {},
        None,
    ],
)
def test_odd_entry_options_stay_off(options: Any) -> None:
    opts = options_from_entry(options)
    assert opts.enabled is False
    assert opts.history_profile == "compact"
    assert not any(opts.extra().values())


def test_entry_options_read_profile_and_extras() -> None:
    opts = options_from_entry(
        {
            OPTION_TRAFFIC_ENABLED: True,
            OPTION_TRAFFIC_HISTORY_PROFILE: "standard",
            "traffic_station_detail": True,
        }
    )
    assert opts.enabled and opts.history_profile == "standard"
    assert opts.extra() == {
        OPT_STATION_DETAIL: True,
        OPT_SYSFS_FALLBACK: False,
        OPT_OFFLOAD_PROBE: False,
    }
    odd = options_from_entry(
        {OPTION_TRAFFIC_ENABLED: True, OPTION_TRAFFIC_HISTORY_PROFILE: "huge"}
    )
    assert odd.history_profile == "compact"


async def test_unreadable_store_runs_with_defaults_and_never_fails_setup(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    disks[TRAFFIC_COARSE_STORE_KEY].load_error = OSError("disk")
    enabled(disks)
    engine, coord = await start(hass)
    assert engine.load_failed and engine.active
    assert coord.listener_count == 1
    assert engine.settings == default_settings()


# --- on: snapshots and rates ------------------------------------------------------------------


async def test_on_samples_and_rates_from_coordinator_snapshot(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass)
    assert engine.active and coord.listener_count == 1
    assert engine.not_ready_reason == REASON_CORE_MISSING  # no core in this test
    await two_polls(engine, coord, hass)

    rates = {r.point.device: r for r in engine.rates_of(RID)}
    assert set(rates) == {"wan", "lan1"}
    wan = rates["wan"]
    assert wan.point.scope is Scope.WAN
    assert wan.quality is Quality.OK
    assert wan.rx_bps == 1_000_000.0 and wan.tx_bps == 100_000.0
    assert wan.interval_s == 10.0  # poll times, not processing times
    assert rates["lan1"].point.scope is Scope.INTERFACE
    assert engine.counters["processed_snapshots"] == 2
    status = engine.status[RID]
    assert status.devices == 2
    assert status.stations is None  # no module key: not ready, not "0"
    caps = engine.capabilities(RID)
    assert caps[CAP_NETDEV_COUNTERS] == {"state": "available", "reason": "ok"}
    assert caps[CAP_STATION_COUNTERS]["reason"] == REASON_MODULE_KEY_MISSING
    assert coord.router_calls() == []  # nothing switched on: no extra call


async def test_poll_without_device_counters_is_source_missing(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass)
    data = poll_data(100.0)
    data.device_counters = None
    coord.poll(data=data)
    await drain(hass)
    assert engine.status[RID].devices is None
    assert engine.capabilities(RID)[CAP_NETDEV_COUNTERS]["reason"] == "source_missing"
    assert len(engine.book) == 0


async def test_stations_only_with_module_key(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass)
    clients = [station(MAC1, 1_000, 2_000), station(MAC2, None, None, "phy1-ap0")]

    data = poll_data(100.0, clients=clients)
    coord.poll(data=data)
    await drain(hass)
    assert engine.status[RID].stations is None
    assert engine.book.client_count == 0  # no key: no station taken at all

    engine._module_key = KEY  # what the core hands out
    coord.poll(data=poll_data(110.0, clients=clients))
    await drain(hass)
    engine.clock.t += 10
    clients2 = [station(MAC1, 11_000, 4_000), station(MAC2, None, None, "phy1-ap0")]
    coord.poll(data=poll_data(120.0, clients=clients2))
    await drain(hass)

    status = engine.status[RID]
    assert (status.stations, status.stations_total) == (1, 2)
    assert status.stations_without_bytes == 1
    stations = [r for r in engine.rates_of(RID) if r.point.scope is Scope.STATION]
    assert len(stations) == 1
    rate = stations[0]
    assert rate.quality is Quality.OK and rate.source is Source.HOSTAPD
    assert rate.coverage is Coverage.PARTIAL
    assert rate.rx_bps == 8_000.0
    assert valid_client_ref(rate.point.client_ref)
    assert rate.point.client_ref == pseudonymise_identifier("client", MAC1, KEY)
    dumped = json.dumps([r.to_dict() for r in engine.rates_of(RID)])
    dumped += json.dumps(engine.summary())
    assert MAC1 not in dumped.lower() and MAC2 not in dumped.lower()


async def test_failed_poll_and_unknown_router_are_counted(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass, rids={"e1": None})
    coord.poll(success=False)
    coord.poll()
    assert engine.counters["polls_failed"] == 1
    assert engine.counters["router_id_missing"] == 1
    assert engine.queue_length == 0 and hass.tasks == []


# --- queue limit and drop counters (areas 26/27) -----------------------------------------------


async def test_queue_keeps_one_snapshot_per_router(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass)
    coord.poll(data=poll_data(100.0))
    coord.poll(data=poll_data(160.0))  # before the drain task ran
    assert engine.queue_length == 1
    assert engine.counters["dropped_snapshots"] == 1
    await drain(hass)
    assert engine.queue_length == 0
    assert engine.counters["processed_snapshots"] == 1
    assert engine._snapshots[RID].mono_s == 160.0  # the newer one won
    assert engine.summary()["counters"]["dropped_snapshots"] == 1


async def test_queue_is_bounded_by_router_count(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    engine, _coord = await start(hass)
    for i in range(MAX_QUEUE_ROUTERS + 3):
        rid = "rtr_" + f"{i + 16:032x}"
        snap = Snapshot(
            router_id=rid,
            mono_s=1.0,
            wall_s=None,
            uptime_s=None,
            stale=False,
            wan_device=None,
            devices=None,
        )
        engine._enqueue("e1", snap)
    assert engine.queue_length == MAX_QUEUE_ROUTERS
    assert engine.counters["dropped_snapshots"] == 3
    await engine.async_deactivate()
    assert engine.queue_length == 0
    assert all(t.done() for t in hass.tasks)


async def test_point_quotas_are_visible_in_the_summary(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass)
    engine.book._infra_per_router = 1
    coord.poll(data=poll_data(100.0))
    await drain(hass)
    summary = engine.summary()
    assert summary["points"] == {"infra": 1, "client": 0}
    assert summary["counters"]["dropped_points_infra"] == 1
    # the WAN device comes first and is never the one refused
    assert engine.book.has(engine.rates_of(RID)[0].point.point_id)
    assert engine.rates_of(RID)[0].point.scope is Scope.WAN


# --- switchable extra calls -------------------------------------------------------------------


async def test_offload_probe_runs_once_when_switched_on(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks, {RID: {OPT_OFFLOAD_PROBE: True}})
    engine, coord = await start(hass)
    probe = coord.api.async_traffic_offload_state = AsyncMock(
        return_value={"flow_offloading": True, "flow_offloading_hw": False}
    )
    coord.poll(data=poll_data(100.0))
    await drain(hass)
    assert probe.await_count == 1
    assert engine.offload[RID] == OffloadState(True, False)
    assert engine.capabilities(RID)[CAP_OFFLOAD_STATE]["state"] == "available"
    engine.clock.t += 60
    coord.poll(data=poll_data(160.0))
    await drain(hass)
    assert probe.await_count == 1  # every 6 h at most
    assert engine.blocked_counts[BLOCK_NOT_DUE] == 1
    # the other two calls stay off
    assert not coord.api.async_traffic_station_detail.called
    assert not coord.api.async_traffic_sysfs_counters.called
    assert engine.planner.counters["extra_calls"] == 1


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        ({"poll_running": True}, BLOCK_POLL_RUNNING),
        ({"ssh": True}, BLOCK_SSH_FALLBACK),
        ({"interval": 120}, BLOCK_THROTTLED),
        ({"late": 50.0}, BLOCK_POLL_SOON),
        ({"interval": None}, BLOCK_POLL_SOON),
    ],
)
async def test_extra_call_never_next_to_the_poll(
    disks: FakeDisks, setup: dict[str, Any], reason: str
) -> None:
    hass = make_hass()
    enabled(disks, {RID: {OPT_OFFLOAD_PROBE: True}})
    engine, coord = await start(hass)
    probe = coord.api.async_traffic_offload_state = AsyncMock(return_value={})
    coord.poll_running = setup.get("poll_running", False)
    coord.api.uses_ssh_fallback = setup.get("ssh", False)
    if "interval" in setup:
        interval = setup["interval"]
        coord.update_interval = (
            None if interval is None else timedelta(seconds=interval)
        )
    coord.poll(data=poll_data(100.0))
    engine.clock.t += setup.get("late", 0.0)  # processing runs late
    await drain(hass)
    assert probe.await_count == 0
    assert engine.blocked_counts == {reason: 1}


async def test_three_failures_pause_the_option(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks, {RID: {OPT_OFFLOAD_PROBE: True}})
    engine, coord = await start(hass)
    probe = coord.api.async_traffic_offload_state = AsyncMock(
        side_effect=OSError("down")
    )
    for n in range(3):
        engine.clock.t += SIX_HOURS + 1
        coord.poll(data=poll_data(100.0 + n))
        await drain(hass)
    engine.clock.t += 60  # inside the one-hour pause
    coord.poll(data=poll_data(200.0))
    await drain(hass)
    assert probe.await_count == 3
    assert engine.planner.counters["extra_failures"] == 3
    assert engine.planner.counters["extra_pauses"] == 1
    assert engine.blocked_counts[BLOCK_PAUSED] == 1
    assert engine.capabilities(RID)[CAP_OFFLOAD_STATE]["reason"] == REASON_PAUSED
    assert engine.planner.state(RID, OPT_OFFLOAD_PROBE).last_error == "OSError"


async def test_timeout_bounds_the_call(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks, {RID: {OPT_OFFLOAD_PROBE: True}})
    engine, coord = await start(hass)
    engine.planner.timeout_s = 0.01

    async def slow() -> dict[str, Any]:
        await asyncio.sleep(5)
        return {}

    coord.api.async_traffic_offload_state = slow
    coord.poll(data=poll_data(100.0))
    await drain(hass)
    state = engine.planner.state(RID, OPT_OFFLOAD_PROBE)
    assert state.last_error == "TimeoutError" and state.failures == 1
    assert engine.planner.in_flight == 0 and RID not in engine.planner.busy


async def test_missing_permission_is_reported(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks, {RID: {OPT_OFFLOAD_PROBE: True}})
    engine, coord = await start(hass)
    coord.api.async_traffic_offload_state = AsyncMock(
        side_effect=OpenWrtMethodNotFoundError("no acl")
    )
    coord.poll(data=poll_data(100.0))
    await drain(hass)
    cap = engine.capabilities(RID)[CAP_OFFLOAD_STATE]
    assert cap == {"state": "unavailable", "reason": REASON_PERMISSION_DENIED}
    assert RID not in engine.offload  # unknown stays unknown


async def test_at_most_two_extra_calls_in_flight() -> None:
    planner = ExtraCallPlanner()
    gate = asyncio.Event()
    rids = ["rtr_" + c * 32 for c in "abc"]

    async def call() -> int:
        await gate.wait()
        return 1

    for rid in rids:
        planner.reserve(rid, OPT_OFFLOAD_PROBE, 0.0)
    tasks = [
        asyncio.create_task(
            planner.run(rid, OPT_OFFLOAD_PROBE, call, clock=lambda: 0.0)
        )
        for rid in rids
    ]
    for _ in range(5):
        await asyncio.sleep(0)
    assert planner.in_flight == 2
    gate.set()
    outcomes = await asyncio.gather(*tasks)
    assert all(o.ok for o in outcomes)
    assert planner.peak_in_flight == 2
    assert planner.busy == set() and planner.in_flight == 0


async def test_one_traffic_call_per_router() -> None:
    planner = ExtraCallPlanner()
    poll = PollState(False, False, False, 60.0)
    planner.reserve(RID, OPT_OFFLOAD_PROBE, 0.0)
    assert (
        planner.blocked_reason(RID, OPT_SYSFS_FALLBACK, 0.0, enabled=True, poll=poll)
        == BLOCK_BUSY
    )
    assert (
        planner.blocked_reason(RID2, OPT_SYSFS_FALLBACK, 0.0, enabled=True, poll=poll)
        is None
    )


async def test_station_detail_needs_the_module_key(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks, {RID: {OPT_STATION_DETAIL: True}})
    engine, coord = await start(hass)
    detail = coord.api.async_traffic_station_detail = AsyncMock(
        return_value={"phy1-ap0": [{"mac": MAC2, "rx_bytes": 10, "tx_bytes": 20}]}
    )
    coord.poll(data=poll_data(100.0))
    await drain(hass)
    assert detail.await_count == 0  # not ready: no MAC without the key

    engine._module_key = KEY
    coord.poll(data=poll_data(110.0, clients=[station(MAC1, 1, 1)]))
    await drain(hass)
    assert detail.await_count == 1
    assert detail.await_args.args == (("phy0-ap0", "phy1-ap0"),)
    points = [
        (r.point.client_ref, r.source)
        for r in engine.latest.values()
        if r.point.scope is Scope.STATION
    ]
    assert (pseudonymise_identifier("client", MAC2, KEY), Source.IWINFO) in points
    assert (pseudonymise_identifier("client", MAC1, KEY), Source.HOSTAPD) in points


async def test_sysfs_fallback_reads_only_devices_without_counters(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    enabled(disks, {RID: {OPT_SYSFS_FALLBACK: True}})
    engine, coord = await start(hass)
    sysfs = coord.api.async_traffic_sysfs_counters = AsyncMock(
        return_value={"br-lan": {"rx_bytes": 10, "tx_bytes": 20}}
    )
    coord.poll(data=poll_data(100.0))
    await drain(hass)
    assert sysfs.await_args.args == (("br-lan",),)  # wan and lan1 have counters
    sources = {
        r.point.device: r.source
        for r in engine.latest.values()
        if r.point.device == "br-lan"
    }
    assert sources == {"br-lan": Source.SYSFS}


# --- settings -----------------------------------------------------------------------------------


CLIENT_A = "cli_" + "a" * 16
CLIENT_B = "cli_" + "b" * 16
USER = "0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize(
    "update",
    [
        {"enabled": True},  # the switch is an entry option now
        {"history_profile": "standard"},
        {"routers": {}},
        {"other": True},
        {"collector": True},
        {"collector": {"enabled": "yes", "user_id": USER}},
        {"collector": {"enabled": True}},  # no user: refused
        {"collector": {"user_id": "Admin"}},
        {"collector": {"user_id": USER, "token": "x"}},
        {"client_sensors": "cli_x"},
        {"client_sensors": ["aa:bb:cc:dd:ee:ff"]},  # never a MAC
        {"client_sensors": [f"cli_{i:016x}" for i in range(21)]},
        None,
    ],
)
def test_invalid_settings_are_refused(update: Any) -> None:
    with pytest.raises(TrafficSettingsError):
        merge_settings(default_settings(), update)


def test_settings_merge_collector_and_client_sensors() -> None:
    merged = merge_settings(default_settings(), {"collector": {"user_id": USER}})
    assert merged["collector"] == {"enabled": False, "user_id": USER}
    merged = merge_settings(merged, {"collector": {"enabled": True}})
    assert merged["collector"] == {"enabled": True, "user_id": USER}
    merged = merge_settings(merged, {"client_sensors": [CLIENT_B, CLIENT_A, CLIENT_B]})
    assert merged["client_sensors"] == [CLIENT_A, CLIENT_B]
    merged = merge_settings(merged, {"client_sensors": []})
    assert merged["client_sensors"] == []
    # tolerant read: broken parts fall back to off
    assert (
        settings_from_store(
            {"collector": {"enabled": True, "user_id": None}, "client_sensors": ["x"]}
        )
        == default_settings()
    )
    assert settings_from_store("garbage") == default_settings()


async def test_fleet_settings_only_while_on(disks: FakeDisks) -> None:
    hass = make_hass()
    engine, coord = await start(hass)
    with pytest.raises(TrafficSettingsError) as err:
        await engine.async_update_settings({"client_sensors": [CLIENT_A]})
    assert err.value.reason == "disabled"
    assert TRAFFIC_COARSE_STORE_KEY not in disks.options  # off: no store access
    assert not engine.active and coord.listener_count == 0


async def test_invalid_update_changes_nothing(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    engine, _coord = await start(hass)
    with pytest.raises(TrafficSettingsError):
        await engine.async_update_settings({"client_sensors": ["bad"]})
    assert disks[TRAFFIC_COARSE_STORE_KEY].saves == []
    assert engine.settings == default_settings()


async def test_switching_on_and_off_through_the_options(disks: FakeDisks) -> None:
    hass = make_hass()
    engine, coord = await start(hass)
    await async_apply_traffic_options(hass, "e1", {OPTION_TRAFFIC_ENABLED: True})
    assert engine.active and coord.listener_count == 1
    await two_polls(engine, coord, hass)
    assert len(engine.book) == 2
    await engine.async_update_settings({"client_sensors": [CLIENT_A]})
    assert disks[TRAFFIC_COARSE_STORE_KEY].saves[-1]["settings"] == {
        "v": 1,
        "collector": {"enabled": False, "user_id": None},
        "client_sensors": [CLIENT_A],
    }

    await async_apply_traffic_options(hass, "e1", {OPTION_TRAFFIC_ENABLED: False})
    assert not engine.active and coord.listener_count == 0
    assert len(engine.book) == 0 and engine.latest == {} and engine.status == {}
    coord.poll(data=poll_data(200.0))
    assert engine.queue_length == 0
    # switching off keeps the fleet settings (written, not deleted)
    assert disks[TRAFFIC_COARSE_STORE_KEY].saves[-1]["settings"]["client_sensors"] == [
        CLIENT_A
    ]


async def test_one_router_off_keeps_the_other_on(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    rids = {"e1": RID, "e2": RID2}
    engine, coord1 = await start(hass, rids=rids)
    _, coord2 = await start(hass, entry_id="e2", coord=FakeCoordinator(poll_data(1.0)))
    coord1.poll(data=poll_data(100.0))
    coord2.poll(data=poll_data(100.0))
    await drain(hass)
    assert set(engine.status) == {RID, RID2}

    await async_apply_traffic_options(hass, "e1", {OPTION_TRAFFIC_ENABLED: False})
    assert engine.active and engine.enabled_entries == ["e2"]
    assert coord1.listener_count == 0 and coord2.listener_count == 1
    assert set(engine.status) == {RID2}
    coord1.poll(data=poll_data(200.0))
    assert engine.queue_length == 0
    # unknown entry: nothing happens
    await async_apply_traffic_options(hass, "e9", {OPTION_TRAFFIC_ENABLED: True})
    assert engine.enabled_entries == ["e2"]


async def test_history_profile_is_the_largest_of_the_routers_on(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    enabled(disks)
    engine, _ = await start(hass, rids={"e1": RID, "e2": RID2})
    await start(hass, entry_id="e2", coord=FakeCoordinator(poll_data(1.0)))
    assert engine.history_profile == "compact"
    await async_apply_traffic_options(
        hass,
        "e2",
        {OPTION_TRAFFIC_ENABLED: True, OPTION_TRAFFIC_HISTORY_PROFILE: "standard"},
    )
    assert engine.history_profile == "standard"
    assert engine.series.profile.name == "standard"
    # a router that is off does not count
    await async_apply_traffic_options(
        hass,
        "e2",
        {OPTION_TRAFFIC_ENABLED: False, OPTION_TRAFFIC_HISTORY_PROFILE: "standard"},
    )
    assert engine.history_profile == "compact"
    assert engine.series.profile.name == "compact"


# --- shutdown -------------------------------------------------------------------------------------


async def test_release_of_last_entry_cleans_up_tasks_and_listener(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    enabled(disks, {RID: {OPT_OFFLOAD_PROBE: True}})
    engine, coord = await start(hass)
    started = asyncio.Event()

    async def hang() -> dict[str, Any]:
        started.set()
        await asyncio.Event().wait()
        return {}

    coord.api.async_traffic_offload_state = hang
    coord.poll(data=poll_data(100.0))
    await asyncio.wait_for(started.wait(), 1)  # the extra call is in flight
    engine.clock.t += 30
    coord.poll(data=poll_data(130.0))  # and a new drain task is queued
    assert engine.queue_length == 1

    await async_release_traffic(hass, "e1")
    assert coord.listener_count == 0
    assert DATA_TRAFFIC_ANALYTICS not in hass.data
    assert engine.closed and not engine.active
    assert all(t.done() for t in hass.tasks)
    assert engine.queue_length == 0 and len(engine.book) == 0
    assert engine.planner.in_flight == 0
    await engine.async_activate()  # a closed engine stays off
    assert not engine.active


async def test_release_of_one_entry_keeps_the_other(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    rids = {"e1": RID, "e2": RID2}
    engine, coord1 = await start(hass, rids=rids)
    _, coord2 = await start(hass, entry_id="e2", coord=FakeCoordinator(poll_data(1.0)))
    coord1.poll(data=poll_data(100.0))
    coord2.poll(data=poll_data(100.0))
    await drain(hass)
    assert set(engine.status) == {RID, RID2}

    await async_release_traffic(hass, "e1")
    assert async_get_traffic_engine(hass) is engine and engine.active
    assert coord1.listener_count == 0 and coord2.listener_count == 1
    assert set(engine.status) == {RID2}
    assert engine.rates_of(RID) == []
    await async_release_traffic(hass, "e2")
    assert coord2.listener_count == 0 and engine.closed


async def test_setup_twice_keeps_one_listener(disks: FakeDisks) -> None:
    hass = make_hass()
    enabled(disks)
    coord = FakeCoordinator(poll_data(1.0))
    engine, _ = await start(hass, coord=coord)
    await start(hass, coord=coord)  # entry reload
    assert coord.listener_count == 1 and engine.entry_count == 1


# --- end to end: runtime -> core -> engine ---------------------------------------------------------


async def test_end_to_end_with_the_real_core(disks: FakeDisks) -> None:
    hass = make_hass()
    entry = FakeEntry("e1")
    coord = await setup_router(hass, entry, poll_data(50.0))
    core_listeners = coord.listener_count
    engine = await async_setup_traffic(hass, entry, coord)
    assert coord.listener_count == core_listeners  # off: nothing added
    assert TRAFFIC_COARSE_STORE_KEY not in disks.options

    await async_apply_traffic_options(hass, "e1", {OPTION_TRAFFIC_ENABLED: True})
    assert engine.ready, engine.not_ready_reason
    assert engine.module_key_available
    assert coord.listener_count == core_listeners + 1
    rid = core_of(hass).registry.get_by_entry("e1").router_id
    assert valid_router_id(rid)

    clients = [station(MAC1, 1_000, 2_000)]
    coord.poll(data=poll_data(100.0, (1_000, 500), uptime=5_000, clients=clients))
    await drain(hass)
    clients = [station(MAC1, 11_000, 4_000)]
    coord.poll(
        data=poll_data(110.0, (1_251_000, 125_500), uptime=5_010, clients=clients)
    )
    await drain(hass)

    rates = {(r.point.scope, r.point.device): r for r in engine.rates_of(rid)}
    assert rates[(Scope.WAN, "wan")].quality is Quality.OK
    assert rates[(Scope.WAN, "wan")].rx_bps == 1_000_000.0
    sta = rates[(Scope.STATION, None)]
    assert sta.quality is Quality.OK and sta.rx_bps == 8_000.0
    assert valid_client_ref(sta.point.client_ref)
    assert engine.capabilities(rid)[CAP_STATION_COUNTERS]["state"] == "available"

    # the core asks the detector on its next poll (signature changed)
    coord.poll(data=poll_data(170.0, (1_300_000, 130_000), uptime=5_070))
    await drain(hass)
    caps = core_of(hass).registry.capabilities(rid)
    assert caps[CAP_NETDEV_COUNTERS].state.value == "available"

    text = json.dumps([r.to_dict() for r in engine.rates_of(rid)])
    text += json.dumps(engine.summary())
    assert MAC1 not in text.lower() and "192.168." not in text
    assert coord.router_calls() == []

    await async_release_traffic(hass, "e1")
    assert coord.listener_count == core_listeners
    assert engine.closed
