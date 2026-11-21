"""Traffic history store (Phase I; plan 2026-11-20 §5, task §14, §21 areas 23/24).

Pure parts (traffic_history): tiers fine (5 min) -> hour -> UTC day, rollup
once per fine bucket, retention and quotas per profile, resolution chosen
by window (<= 500 points), gaps stay None, export/import round trip, part
trimming. Store parts (traffic_store, engine): throttled writes, restart
survives, broken or older store files never fail the setup, module off
touches no history store, switching off keeps the history.
Plus the 30-day simulation (plan §5 size estimate). No router, no network.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from core_testkit import FakeDisks
from core_testkit import make_hass as core_make_hass
from homeassistant.helpers.json import prepare_save_json

from custom_components.openwrt_router.const import (
    TRAFFIC_COARSE_STORE_KEY,
    TRAFFIC_COARSE_STORE_MAX_BYTES,
    TRAFFIC_FINE_STORE_KEY,
    TRAFFIC_FINE_STORE_MAX_BYTES,
)
from custom_components.openwrt_router.traffic_const import (
    HISTORY_COARSE_SAVE_DELAY_S,
    HISTORY_FINE_SAVE_DELAY_S,
    HISTORY_MAX_QUERY_POINTS,
    HISTORY_PART_CLIENT,
    HISTORY_PART_INFRA,
    HISTORY_PROFILE_COMPACT,
    HISTORY_PROFILE_STANDARD,
    HISTORY_ROLLUP_DELAY_S,
    REASON_NO_DATA_YET,
)
from custom_components.openwrt_router.traffic_counters import Baseline, BaselineBook
from custom_components.openwrt_router.traffic_history import (
    PROFILES,
    TrafficHistory,
    point_from_dict,
)
from custom_components.openwrt_router.traffic_model import (
    Coverage,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
    Source,
)

RID = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
REF = "cli_" + "a" * 16
DAY = 86400
T0 = 1_800_000_000 - (1_800_000_000 % DAY)  # UTC midnight
WAN = MeasurementPoint(RID, Scope.WAN, device="wan")
LAN = MeasurementPoint(RID, Scope.PORT, device="lan1")
CLIENT = MeasurementPoint(None, Scope.CLIENT, client_ref=REF)


def rate(
    point: MeasurementPoint,
    wall: float,
    rx: int | None = 6_000,
    tx: int | None = 3_000,
    interval: float = 60.0,
    quality: Quality = Quality.OK,
) -> Rate:
    ok = quality in (Quality.OK, Quality.WRAP_32)
    return Rate(
        point,
        quality,
        interval_s=interval,
        rx_bps=rx * 8 / interval if ok and rx is not None else None,
        tx_bps=tx * 8 / interval if ok and tx is not None else None,
        rx_delta=rx if ok else None,
        tx_delta=tx if ok else None,
        coverage=Coverage.FULL,
        wall_s=wall,
        mono_s=wall,
    )


def feed(
    hist: TrafficHistory,
    point: MeasurementPoint,
    start: float,
    end: float,
    step: float = 60.0,
    rx: int = 6_000,
) -> None:
    t = start + step
    while t <= end:
        hist.add_rate(rate(point, t, rx=rx, interval=step))
        t += step


# --- profiles -------------------------------------------------------------------------


def test_profiles_follow_the_decisions() -> None:
    compact = PROFILES[HISTORY_PROFILE_COMPACT]
    standard = PROFILES[HISTORY_PROFILE_STANDARD]
    assert TrafficHistory().profile is compact  # F3: compact is the default
    # Vorgabe: hourly values in compact for 14 days (not 7)
    assert compact.infra.hour_s == 14 * DAY
    assert compact.infra.fine_s == 6 * 3600
    assert compact.infra.day_s >= 30 * DAY
    assert compact.persist_clients is False  # "nur Infrastruktur" on disk
    # standard: plan §5 table
    assert standard.infra.fine_s == DAY and standard.infra.hour_s == 7 * DAY
    assert standard.infra.day_s == 90 * DAY
    assert standard.client.fine_s == 6 * 3600 and standard.client.hour_s == 2 * DAY
    assert standard.client.day_s == 30 * DAY and standard.persist_clients


# --- aggregation (area 23) --------------------------------------------------------------


def test_fine_buckets_roll_up_once_into_hour_and_day() -> None:
    hist = TrafficHistory()
    feed(hist, WAN, T0, T0 + 3 * 3600)
    now = T0 + 3 * 3600
    assert hist.compact(now) is True
    assert hist.compact(now) is False  # idempotent: each fine bucket once
    hour = hist.window(WAN.point_id, 3 * 3600, end=now, resolution_s=3600)
    fine = hist.window(WAN.point_id, 3 * 3600, end=now, resolution_s=300)
    # stored hours plus the fine buckets not rolled yet: nothing lost, nothing twice
    assert sum(b.rx_bytes for b in hour.buckets if b.rx_bytes) == sum(
        b.rx_bytes for b in fine.buckets if b.rx_bytes
    )
    assert (
        hist.dropped()["rolled_buckets"] == (3 * 3600 - HISTORY_ROLLUP_DELAY_S) // 300
    )
    first = hour.buckets[0]
    assert first.start == T0 and first.resolution_s == 3600
    assert first.rx_bytes == 60 * 6_000 and first.covered_s == 3600.0
    assert first.samples == 12 * 5  # sum of the fine samples
    assert first.rx_peak_bps == pytest.approx(6_000 * 8 / 60)
    day = hist.window(WAN.point_id, DAY, end=now, resolution_s=DAY)
    assert day.buckets[0].start == T0
    assert day.buckets[0].rx_bytes == sum(b.rx_bytes or 0 for b in hour.buckets)


def test_recent_fine_buckets_wait_for_the_rollup_delay() -> None:
    hist = TrafficHistory()
    feed(hist, WAN, T0, T0 + 600)
    assert hist.compact(T0 + 600) is False
    assert hist.summary()["buckets_hour"] == 0  # nothing stored in the hour tier
    # ... but the hourly view still shows the newest minutes (merged on read)
    hour = hist.window(WAN.point_id, 3600, end=T0 + 600, resolution_s=3600)
    assert hour.buckets[-1].rx_bytes == 10 * 6_000


def test_late_rate_into_a_rolled_bucket_is_counted() -> None:
    hist = TrafficHistory()
    feed(hist, WAN, T0, T0 + 3600)
    hist.compact(T0 + 3 * 3600)
    hist.add_rate(rate(WAN, T0 + 120))
    assert hist.dropped()["late_after_rollup"] == 1


def test_window_resolution_by_window_and_profile() -> None:
    compact = TrafficHistory()
    standard = TrafficHistory(profile=HISTORY_PROFILE_STANDARD)
    for hist in (compact, standard):
        feed(hist, WAN, T0, T0 + 1800)
    end = T0 + 1800
    assert compact.window(WAN.point_id, 3600, end=end).resolution_s == 300
    assert standard.window(WAN.point_id, DAY, end=end).resolution_s == 300
    assert compact.window(WAN.point_id, DAY, end=end).resolution_s == 3600
    assert compact.window(WAN.point_id, 7 * DAY, end=end).resolution_s == 3600
    assert compact.window(WAN.point_id, 30 * DAY, end=end).resolution_s == DAY
    ninety = compact.window(WAN.point_id, 90 * DAY, end=end)
    assert ninety.resolution_s == DAY
    for hist in (compact, standard):
        for window_s in (3600, DAY, 7 * DAY, 14 * DAY, 30 * DAY, 90 * DAY):
            win = hist.window(WAN.point_id, window_s, end=end)
            assert len(win.buckets) <= HISTORY_MAX_QUERY_POINTS


def test_window_without_data_is_none_never_zero() -> None:
    hist = TrafficHistory()
    feed(hist, WAN, T0, T0 + 600)
    win = hist.window(WAN.point_id, 3600, end=T0 + 7200)
    assert win.reason == REASON_NO_DATA_YET
    assert all(b.rx_bytes is None and b.covered_s == 0 for b in win.buckets)
    assert win.total("rx_bytes") is None
    assert hist.window("tpt_" + "0" * 16, 3600, end=T0) is None


# --- retention and quotas (area 24) ------------------------------------------------------


def test_retention_per_tier_and_expiry_of_idle_points() -> None:
    hist = TrafficHistory()
    feed(hist, WAN, T0, T0 + DAY, step=300)
    now = T0 + DAY
    hist.compact(now)
    fine = hist.window(WAN.point_id, DAY, end=now, resolution_s=300)
    assert sum(1 for b in fine.buckets if b.covered_s > 0) <= 6 * 12 + 1  # 6 h
    hour = hist.window(WAN.point_id, DAY, end=now, resolution_s=3600)
    assert sum(1 for b in hour.buckets if b.covered_s > 0) >= 23
    # idle for longer than the longest tier: the point goes
    hist.compact(now + 32 * DAY)
    assert hist.points() == ()
    assert hist.dropped()["expired_points"] == 1


def test_client_quota_and_compact_keeps_no_client_on_disk() -> None:
    hist = TrafficHistory(max_clients=1)
    feed(hist, CLIENT, T0, T0 + 600)
    other = MeasurementPoint(None, Scope.CLIENT, client_ref="cli_" + "b" * 16)
    assert hist.add_rate(rate(other, T0 + 660)) is False
    assert hist.dropped()["dropped_points_client"] == 1
    feed(hist, WAN, T0, T0 + 600)
    fine, coarse = hist.export_fine(), hist.export_coarse()
    assert CLIENT.point_id not in json.dumps(fine)
    assert CLIENT.point_id not in json.dumps(coarse)
    assert WAN.point_id in json.dumps(fine)


def test_drop_router_keeps_history_forget_router_removes_it() -> None:
    hist = TrafficHistory()
    feed(hist, WAN, T0, T0 + 600)
    hist.drop_router(RID)  # entry unloaded or reloaded: evidence stays
    assert [p.point_id for p in hist.points()] == [WAN.point_id]
    hist.forget_router(RID)
    assert hist.points() == ()


def test_set_profile_trims_to_the_new_limits() -> None:
    hist = TrafficHistory(profile=HISTORY_PROFILE_STANDARD)
    feed(hist, WAN, T0, T0 + 20 * 3600, step=300)
    hist.set_profile(HISTORY_PROFILE_COMPACT)
    fine = hist.window(WAN.point_id, DAY, end=T0 + 20 * 3600, resolution_s=300)
    assert sum(1 for b in fine.buckets if b.covered_s > 0) <= 6 * 12 + 1


def test_trim_oldest_only_touches_its_part() -> None:
    hist = TrafficHistory(profile=HISTORY_PROFILE_STANDARD)
    feed(hist, WAN, T0, T0 + 6 * 3600, step=300)
    feed(hist, CLIENT, T0, T0 + 6 * 3600, step=300)
    hist.compact(T0 + 6 * 3600)
    before = hist.window(CLIENT.point_id, DAY, end=T0 + 6 * 3600, resolution_s=300)
    removed = hist.trim_oldest("fine", HISTORY_PART_INFRA, 10)
    assert removed == 10
    after = hist.window(CLIENT.point_id, DAY, end=T0 + 6 * 3600, resolution_s=300)
    assert before.buckets == after.buckets
    wan = hist.window(WAN.point_id, DAY, end=T0 + 6 * 3600, resolution_s=300)
    assert sum(1 for b in wan.buckets if b.covered_s > 0) == 72 - 10
    assert hist.dropped()["store_trimmed_infra"] == 10
    assert hist.trim_oldest("fine", HISTORY_PART_CLIENT, 1) == 1


# --- export / import --------------------------------------------------------------------


def test_export_import_round_trip_keeps_every_bucket() -> None:
    hist = TrafficHistory(profile=HISTORY_PROFILE_STANDARD)
    feed(hist, WAN, T0, T0 + 5 * 3600)
    feed(hist, CLIENT, T0, T0 + 5 * 3600, rx=1_200)  # peaks: 1 bit/s precision
    hist.add_rate(rate(LAN, T0 + 400, quality=Quality.GAP))  # mask only
    now = T0 + 5 * 3600
    hist.compact(now)
    fine = json.loads(json.dumps(hist.export_fine()))
    coarse = json.loads(json.dumps(hist.export_coarse()))
    again = TrafficHistory(profile=HISTORY_PROFILE_STANDARD)
    assert again.import_payload(fine, coarse) == 0
    assert again.points() == hist.points()
    for point in hist.points():
        for res in (300, 3600, DAY):
            a = hist.window(point.point_id, DAY, end=now, resolution_s=res)
            b = again.window(point.point_id, DAY, end=now, resolution_s=res)
            assert a.buckets == b.buckets, (point.scope, res)
            assert a.area_coverage == b.area_coverage
    # already rolled buckets are not rolled a second time after the restore
    assert again.compact(now) is False


def test_restore_leaves_a_gap_and_interpolates_nothing() -> None:
    hist = TrafficHistory()
    feed(hist, WAN, T0, T0 + 3600)
    again = TrafficHistory()
    again.import_payload(hist.export_fine(), hist.export_coarse())
    # HA was down for an hour; data continues afterwards
    feed(again, WAN, T0 + 7200, T0 + 7800)
    win = again.window(WAN.point_id, 3 * 3600, end=T0 + 7800, resolution_s=300)
    down = [b for b in win.buckets if T0 + 3600 <= b.start < T0 + 7200]
    assert down and all(b.rx_bytes is None and b.covered_s == 0 for b in down)


@pytest.mark.parametrize(
    ("fine", "coarse"),
    [
        (None, None),
        ("garbage", 7),
        ({"v": 99, "points": {}}, {"v": 99}),
        ({"v": 1, "points": "x"}, {"v": 1, "points": []}),
        (
            {"v": 1, "points": {"tpt_bad": {"p": [1, 2]}, "x": None}},
            {"v": 1, "points": {"tpt_" + "0" * 16: {"h": [1, "x"]}}},
        ),
    ],
)
def test_broken_or_foreign_payload_never_raises(fine: Any, coarse: Any) -> None:
    hist = TrafficHistory()
    invalid = hist.import_payload(fine, coarse)
    assert hist.points() == ()
    assert invalid >= 0


def test_a_point_whose_id_does_not_match_is_rejected() -> None:
    hist = TrafficHistory()
    feed(hist, WAN, T0, T0 + 600)
    fine = hist.export_fine()
    entry = fine["points"].pop(WAN.point_id)
    fine["points"]["tpt_" + "f" * 16] = entry
    again = TrafficHistory()
    assert again.import_payload(fine, None) == 1
    assert again.points() == ()


def test_point_from_dict_round_trip() -> None:
    for point in (WAN, LAN, CLIENT, MeasurementPoint(RID, Scope.VLAN, vlan_id=10)):
        assert point_from_dict(point.to_dict()) == point
    assert point_from_dict({"scope": "nope"}) is None


def test_baselines_export_and_restore() -> None:
    book = BaselineBook()
    base = Baseline(WAN.point_id, Source.NETDEV, 10.0, T0, 5000, (1, 2) + (None,) * 6)
    book.put(WAN, base, 10.0)
    exported = book.export()
    again = BaselineBook()
    assert again.restore(json.loads(json.dumps(exported)), now_mono=1.0) == 1
    restored = again.get(WAN.point_id)
    assert restored is not None and restored.restored and restored.mono_s is None
    assert restored.counters == base.counters
    assert again.restore([{"point": {"scope": "x"}}, "junk"], now_mono=1.0) == 0


# --- store and engine (restart, throttling, broken files, module off) -------------------

ENGINE_RID = "rtr_" + "1" * 32


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _store_settings(disks: FakeDisks, settings: Any, history: Any = None) -> None:
    data: dict[str, Any] = {"settings": settings}
    if history is not None:
        data["history"] = history
    disks[TRAFFIC_COARSE_STORE_KEY].data = {
        "version": 1,
        "minor_version": 1,
        "key": TRAFFIC_COARSE_STORE_KEY,
        "data": data,
    }


class _Clock:
    def __init__(self) -> None:
        self.t = 1_000.0

    def __call__(self) -> float:
        return self.t


async def _engine(hass: Any, *, wall0: float = float(T0)) -> Any:
    from core_testkit import FakeCoordinator, FakeEntry

    from custom_components.openwrt_router.const import DATA_TRAFFIC_ANALYTICS
    from custom_components.openwrt_router.traffic_engine import (
        TrafficEngine,
        async_setup_traffic,
    )

    engine = TrafficEngine(hass)
    hass.data[DATA_TRAFFIC_ANALYTICS] = engine
    engine.router_id_of = {"e1": ENGINE_RID}.get
    engine.clock = _Clock()
    engine.wall = lambda: wall0 + engine.clock()
    coord = FakeCoordinator(_poll(100.0, 0))
    from datetime import timedelta

    coord.update_interval = timedelta(seconds=60)
    coord.poll_running = False
    await async_setup_traffic(hass, FakeEntry("e1"), coord)
    return engine, coord


def _poll(mono: float, n: int) -> Any:
    from core_testkit import router_data

    data = router_data()
    data.wan_status = {**data.wan_status, "l3_device": "wan"}
    data.uptime = 5_000 + int(mono)
    total = 1_000 + n * 6_000_000
    data.device_counters = {
        "wan": {
            "rx_bytes": total,
            "tx_bytes": total // 10,
            "rx_packets": 0,
            "tx_packets": 0,
            "rx_errors": 0,
            "tx_errors": 0,
            "rx_dropped": 0,
            "tx_dropped": 0,
            "speed": "1000F",
            "up": True,
            "carrier": True,
        }
    }
    data.counters_sampled_mono = mono
    data.clients = []
    return data


async def _run_polls(engine: Any, coord: Any, hass: Any, count: int, step=60.0):
    from core_testkit import drain

    for _ in range(count):
        engine.clock.t += step
        engine._polls = getattr(engine, "_polls", 0) + 1
        coord.poll(data=_poll(engine.clock.t, engine._polls))
        await drain(hass)


async def test_module_off_opens_no_history_store(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, coord = await _engine(hass)
    for _ in range(3):
        coord.poll()
    assert TRAFFIC_FINE_STORE_KEY not in disks.options  # never created
    assert disks[TRAFFIC_COARSE_STORE_KEY].saves == []
    assert engine.series.points() == ()


async def test_history_survives_a_restart_and_writes_are_throttled(
    disks: FakeDisks,
) -> None:
    hass = core_make_hass()
    _store_settings(disks, {"v": 1, "enabled": True, "routers": {}})
    engine, coord = await _engine(hass)
    await _run_polls(engine, coord, hass, 90)  # 1.5 h
    fine, coarse = disks[TRAFFIC_FINE_STORE_KEY], disks[TRAFFIC_COARSE_STORE_KEY]
    # one pending delayed write per store at most, with the planned delays
    assert [d for _f, d in fine.delayed] == [HISTORY_FINE_SAVE_DELAY_S]
    assert [d for _f, d in coarse.delayed] == [HISTORY_COARSE_SAVE_DELAY_S]
    disks.flush_delayed()
    wan = next(p for p in engine.series.points() if p.scope is Scope.WAN)
    end = engine.wall()
    before = engine.series.window(wan.point_id, 7 * DAY, end=end)
    assert before.total("rx_bytes") is not None
    # HA restart: a new engine on the same files
    from custom_components.openwrt_router.traffic_engine import async_release_traffic

    await async_release_traffic(hass, "e1")
    hass2 = core_make_hass()
    engine2, _coord2 = await _engine(hass2)
    after = engine2.series.window(wan.point_id, 7 * DAY, end=end)
    assert after.buckets == before.buckets
    assert engine2.store.counters["baselines_restored"] == 1
    assert engine2.book.get(wan.point_id).restored


async def test_switching_off_writes_and_keeps_the_history(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, coord = await _engine(hass)
    await engine.async_update_settings({"enabled": True})
    await _run_polls(engine, coord, hass, 30)
    await engine.async_update_settings({"enabled": False})
    assert engine.series.points() == ()  # memory freed
    fine = disks[TRAFFIC_FINE_STORE_KEY].data["data"]
    coarse = disks[TRAFFIC_COARSE_STORE_KEY].data["data"]
    assert fine["history"]["points"]  # written, not deleted
    assert coarse["settings"]["enabled"] is False
    # a later settings change while off keeps the stored history unchanged
    stored = coarse["history"]
    await engine.async_update_settings({"routers": {}})
    assert disks[TRAFFIC_COARSE_STORE_KEY].data["data"]["history"] == stored
    # switching on again brings it back
    await engine.async_update_settings({"enabled": True})
    assert engine.series.points() != ()


@pytest.mark.parametrize("damage", ["load_error", "corrupt", "garbage", "future"])
async def test_broken_or_foreign_history_never_fails_the_setup(
    disks: FakeDisks, damage: str
) -> None:
    hass = core_make_hass()
    history = {"v": 1, "points": {"x": 1}}
    if damage == "future":
        history = {"v": 99, "points": {}}
    _store_settings(disks, {"v": 1, "enabled": True, "routers": {}}, history)
    fine = disks[TRAFFIC_FINE_STORE_KEY]
    if damage == "load_error":
        fine.data = {"version": 1, "minor_version": 1, "key": "k", "data": {}}
        fine.load_error = OSError("disk")
    elif damage == "corrupt":
        fine.data = {"version": 1, "minor_version": 1, "key": "k", "data": {}}
        fine.corrupt = True
    else:
        fine.data = {
            "version": 1,
            "minor_version": 1,
            "key": "k",
            "data": {"history": "garbage", "baselines": {"x": 1}},
        }
    engine, coord = await _engine(hass)
    assert engine.active and coord.listener_count == 1
    assert engine.series.points() == ()
    await _run_polls(engine, coord, hass, 3)
    assert engine.series.points() != ()  # runs on, starting empty
    if damage == "load_error":
        assert fine.backups == 1 and engine.store.counters["load_failed_fine"] == 1


async def test_store_from_before_phase_i_is_read(disks: FakeDisks) -> None:
    """Phases B-H wrote only the settings: no history section at all."""
    hass = core_make_hass()
    _store_settings(disks, {"v": 1, "enabled": True, "routers": {}})
    engine, _coord = await _engine(hass)
    assert engine.active and engine.counters["history_invalid_entries"] == 0


async def test_profile_setting_and_part_budgets(disks: FakeDisks, monkeypatch) -> None:
    from custom_components.openwrt_router import traffic_store

    hass = core_make_hass()
    engine, coord = await _engine(hass)
    await engine.async_update_settings(
        {"enabled": True, "history_profile": HISTORY_PROFILE_STANDARD}
    )
    assert engine.series.profile.name == HISTORY_PROFILE_STANDARD
    assert (
        disks[TRAFFIC_COARSE_STORE_KEY].data["data"]["settings"]["history_profile"]
        == HISTORY_PROFILE_STANDARD
    )
    with pytest.raises(ValueError):
        await engine.async_update_settings({"history_profile": "huge"})
    await _run_polls(engine, coord, hass, 120)
    tiny = {
        HISTORY_PROFILE_STANDARD: {"infra": 700, "client": 1_000, "rest": 10},
    }
    monkeypatch.setattr(traffic_store, "HISTORY_BUDGETS", tiny)
    payload = engine.store.fine_payload()
    wan = payload["history"]["points"]
    assert traffic_store.store_bytes(TRAFFIC_FINE_STORE_KEY, wan) <= 700
    assert "baselines" not in payload  # rest over its budget: left out
    trimmed = engine.series.dropped()
    assert trimmed["store_trimmed_infra"] > 0 and trimmed["store_trimmed_rest"] > 0


# --- 30-day simulation (plan §5 size estimate) -------------------------------------------
# The test feeds one 15-minute rate per point (split over three fully covered
# 5-minute buckets: the same buckets 60-s polls fill, at a fraction of the
# run time); scripts/traffic_history_sim.py runs the same fleet with 60-s
# polls and prints the figures of the report.

SIM_ROUTERS = 6
SIM_INFRA_PER_ROUTER = 17  # ~100 infrastructure points (plan §5 reference fleet)
SIM_CLIENTS = 150


def sim_points() -> tuple[list[MeasurementPoint], list[MeasurementPoint]]:
    infra = [
        MeasurementPoint(
            "rtr_" + f"{r:x}" * 32, Scope.PORT if i else Scope.WAN, device=f"lan{i}"
        )
        for r in range(1, SIM_ROUTERS + 1)
        for i in range(SIM_INFRA_PER_ROUTER)
    ]
    clients = [
        MeasurementPoint(None, Scope.CLIENT, client_ref=f"cli_{c:016x}")
        for c in range(SIM_CLIENTS)
    ]
    return infra, clients


def simulate(
    hist: TrafficHistory, first_day: int, days: int, step: int = 900
) -> dict[str, Any]:
    """Feed ``days`` of the reference fleet (busy evenings); measure."""
    infra, clients = sim_points()
    started = time.perf_counter()
    rates = 0
    begin = T0 + first_day * DAY
    for t in range(begin + step, begin + days * DAY + 1, step):
        load = 5 if (t // 3600) % 24 in range(18, 23) else 1
        for n, point in enumerate(infra):
            hist.add_rate(
                rate(
                    point,
                    t,
                    rx=load * (200_000 + n * 997),
                    tx=load * 40_000,
                    interval=step,
                )
            )
        for n, point in enumerate(clients):
            hist.add_rate(rate(point, t, rx=load * (5_000 + n), interval=step))
        rates += len(infra) + len(clients)
        if t % 3600 == 0:
            hist.compact(t)
    end = begin + days * DAY
    hist.compact(end)
    elapsed = time.perf_counter() - started
    fine = hist.export_fine()
    coarse = hist.export_coarse()
    return {
        "profile": hist.profile.name,
        "rates": rates,
        "points": len(hist.points()),
        "buckets_fine": hist.bucket_count("fine", HISTORY_PART_INFRA)
        + hist.bucket_count("fine", HISTORY_PART_CLIENT),
        "buckets_coarse": hist.bucket_count("coarse", HISTORY_PART_INFRA)
        + hist.bucket_count("coarse", HISTORY_PART_CLIENT),
        "points_on_disk": len(fine["points"]),
        "fine_bytes": len(prepare_save_json({"data": fine})[1]),
        "coarse_bytes": len(prepare_save_json({"data": coarse})[1]),
        "seconds": round(elapsed, 2),
        "end": end,
    }


@pytest.mark.parametrize("profile", [HISTORY_PROFILE_COMPACT, HISTORY_PROFILE_STANDARD])
def test_thirty_day_simulation_stays_bounded(profile: str) -> None:
    hist = TrafficHistory(profile=profile)
    out = simulate(hist, 0, 30)
    print("\nSIMULATION", json.dumps(out))
    infra_points = SIM_ROUTERS * SIM_INFRA_PER_ROUTER
    assert out["points"] == infra_points + SIM_CLIENTS
    assert out["fine_bytes"] < TRAFFIC_FINE_STORE_MAX_BYTES
    assert out["coarse_bytes"] < TRAFFIC_COARSE_STORE_MAX_BYTES
    prof = PROFILES[profile]
    assert out["points_on_disk"] == infra_points + (
        SIM_CLIENTS if prof.persist_clients else 0
    )
    # fixed bucket counts per tier: never more than retention / resolution + 1
    assert hist.bucket_count("fine", HISTORY_PART_INFRA) <= infra_points * (
        prof.infra.max_buckets(300)
    )
    assert hist.bucket_count("coarse", HISTORY_PART_INFRA) <= infra_points * (
        prof.infra.max_buckets(3600) + prof.infra.max_buckets(DAY)
    )
    # every window answers with at most 500 points; 30 days are covered
    wan = next(p for p in hist.points() if p.scope is Scope.WAN)
    end = out["end"]
    month = hist.window(wan.point_id, 30 * DAY, end=end)
    assert month.resolution_s == DAY and len(month.buckets) <= 31
    assert month.time_coverage > 0.95
    week = hist.window(wan.point_id, 7 * DAY, end=end)
    assert week.resolution_s == 3600 and week.time_coverage > 0.95
    # no unbounded growth: 10 more days add only daily buckets up to their cap
    more = simulate(hist, 30, 10)
    assert more["buckets_fine"] == out["buckets_fine"]
    day_cap = infra_points * prof.infra.max_buckets(DAY) + SIM_CLIENTS * (
        prof.client.max_buckets(DAY)
    )
    hour_cap = infra_points * prof.infra.max_buckets(3600) + SIM_CLIENTS * (
        prof.client.max_buckets(3600)
    )
    assert more["buckets_coarse"] <= day_cap + hour_cap
    assert more["fine_bytes"] < TRAFFIC_FINE_STORE_MAX_BYTES
    assert more["coarse_bytes"] < TRAFFIC_COARSE_STORE_MAX_BYTES
