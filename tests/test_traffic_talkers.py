"""Top-talker ranking (test area 15, plan 2026-11-20 §2.3): traffic_talkers.py.

Rankings per window and measuring area, observed bytes plus area and
coverage per row, partial lists marked, one client counted once across APs,
shares only where they mean something, bounded and deterministic. Also the
engine wiring (rates fill the ring, talkers read it). No router, no network.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from custom_components.openwrt_router.traffic_const import (
    CLIENT_VALUE_KIND,
    DIR_AMBIGUOUS_BRIDGE,
    DIR_PORT_ROLE_UNKNOWN,
    MAX_TALKERS,
    REASON_INSUFFICIENT_DATA,
    REASON_NO_DATA_FOR_WINDOW,
    REASON_POINTS_DROPPED,
    REASON_POINTS_OMITTED,
    REASON_SHARE_REFERENCE_NOT_FULL,
    REASON_UNKNOWN_WINDOW,
    REASON_USE_CLIENT_SCOPE,
    SUM_INTERFACES_OVERLAP,
    TALKER_WINDOWS,
)
from custom_components.openwrt_router.traffic_model import (
    Coverage,
    CoverageReason,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
)
from custom_components.openwrt_router.traffic_series import MemoryBucketRing
from custom_components.openwrt_router.traffic_talkers import (
    STATE_OK,
    STATE_UNAVAILABLE,
    TalkerBoard,
    clamp_limit,
    peak_episodes,
    rank_current,
)

RIDS = ["rtr_" + str(i) * 32 for i in range(1, 6)]
T0 = 1_800_000_000


def ref(n: int) -> str:
    return f"cli_{n:016x}"


def rate(
    point: MeasurementPoint,
    wall: float,
    rx: int | None,
    tx: int | None,
    interval: float = 300.0,
    quality: Quality = Quality.OK,
    coverage: Coverage = Coverage.FULL,
    reason: CoverageReason | None = None,
    rx_bps: float | None = None,
    tx_bps: float | None = None,
) -> Rate:
    ok = quality in (Quality.OK, Quality.WRAP_32)
    return Rate(
        point,
        quality,
        interval_s=interval,
        rx_bps=(rx_bps if rx_bps is not None else rx * 8 / interval)
        if ok and rx is not None
        else None,
        tx_bps=(tx_bps if tx_bps is not None else tx * 8 / interval)
        if ok and tx is not None
        else None,
        rx_delta=rx if ok else None,
        tx_delta=tx if ok else None,
        coverage=coverage,
        coverage_reason=reason,
        wall_s=wall,
        mono_s=wall,
    )


def fill(
    ring: MemoryBucketRing,
    point: MeasurementPoint,
    rx: int | None,
    tx: int | None,
    buckets: int = 1,
    **kw: Any,
) -> None:
    for i in range(buckets):
        ring.add_rate(rate(point, T0 + 300 * (i + 1), rx, tx, **kw))


def wan(n: int) -> MeasurementPoint:
    return MeasurementPoint(RIDS[n], Scope.WAN, device="wan")


END_1 = T0 + 300


# --- ranking basics -------------------------------------------------------------


def test_wan_download_ranking_with_shares_when_fully_covered() -> None:
    ring = MemoryBucketRing()
    fill(ring, wan(0), rx=3_000, tx=100)
    fill(ring, wan(1), rx=1_000, tx=900)
    board = TalkerBoard(ring)
    out = board.rank_window(Scope.WAN, "5m", "download", end=END_1)
    assert out.state == STATE_OK and not out.partial
    assert [r.observed_bytes for r in out.rows] == [3_000, 1_000]
    assert [r.share_pct for r in out.rows] == [75.0, 25.0]
    assert out.rows[0].counter == "rx"  # WAN download = RX
    assert out.rows[0].measuring_area == "wan:received_from_the_line"
    assert out.total is not None and out.total.rx_bytes == 4_000
    up = board.rank_window(Scope.WAN, "5m", "upload", end=END_1)
    assert [r.observed_bytes for r in up.rows] == [900, 100]


def test_partial_coverage_marks_list_and_drops_share() -> None:
    ring = MemoryBucketRing()
    fill(
        ring,
        wan(0),
        3_000,
        1,
        coverage=Coverage.PARTIAL,
        reason=CoverageReason.HW_OFFLOAD_UNKNOWN,
    )
    fill(ring, wan(1), 1_000, 1)
    out = TalkerBoard(ring).rank_window(Scope.WAN, "5m", "download", end=END_1)
    assert out.partial
    assert "hw_offload_unknown" in out.partial_reasons
    assert all(r.share_pct is None for r in out.rows)
    assert {r.share_reason for r in out.rows} == {REASON_SHARE_REFERENCE_NOT_FULL}
    assert out.rows[0].coverage is Coverage.PARTIAL
    assert out.rows[1].coverage is Coverage.FULL


def test_time_gap_makes_list_partial() -> None:
    ring = MemoryBucketRing()
    fill(ring, wan(0), 3_000, 1, interval=60)  # only 60 of 300 s
    out = TalkerBoard(ring).rank_window(Scope.WAN, "5m", "download", end=END_1)
    assert out.partial and "time_coverage_incomplete" in out.partial_reasons
    assert out.rows[0].time_coverage == 0.2
    assert out.rows[0].share_pct is None


def test_window_without_data_is_unavailable_not_empty() -> None:
    board = TalkerBoard(MemoryBucketRing())
    out = board.rank_window(Scope.CLIENT, "24h", "download", end=END_1)
    assert out.state == STATE_UNAVAILABLE
    assert out.reason == REASON_NO_DATA_FOR_WINDOW
    assert out.partial and out.rows == ()
    assert board.rank_window(Scope.WAN, "2h", "download", end=END_1).reason == (
        REASON_UNKNOWN_WINDOW
    )


@pytest.mark.parametrize("window", list(TALKER_WINDOWS))
def test_every_window_is_supported(window: str) -> None:
    ring = MemoryBucketRing()
    fill(ring, wan(0), 1_000, 1)
    out = TalkerBoard(ring).rank_window(Scope.WAN, window, "download", end=END_1)
    assert out.state == STATE_OK and out.window_s == TALKER_WINDOWS[window]
    assert out.rows[0].observed_bytes == 1_000
    assert out.partial == (window != "5m")  # longer windows: history too short


def test_window_only_counts_its_own_buckets() -> None:
    ring = MemoryBucketRing()
    fill(ring, wan(0), 1_000, 1, buckets=24)  # 2 h
    board = TalkerBoard(ring)
    end = T0 + 300 * 24
    assert (
        board.rank_window(Scope.WAN, "5m", "download", end=end).rows[0].value == 1_000
    )
    assert (
        board.rank_window(Scope.WAN, "1h", "download", end=end).rows[0].value == 12_000
    )
    assert (
        board.rank_window(Scope.WAN, "24h", "download", end=end).rows[0].value == 24_000
    )


# --- areas are never mixed -------------------------------------------------------


def test_scopes_have_separate_lists() -> None:
    ring = MemoryBucketRing()
    fill(ring, wan(0), 5_000, 1)
    fill(ring, MeasurementPoint(RIDS[0], Scope.INTERFACE, device="br-lan"), 9_000, 1)
    fill(
        ring,
        MeasurementPoint(RIDS[0], Scope.VLAN, device="br-lan.10", vlan_id=10),
        7_000,
        1,
    )
    board = TalkerBoard(ring)
    wans = board.rank_window(Scope.WAN, "5m", "rx", end=END_1)
    ifaces = board.rank_window(Scope.INTERFACE, "5m", "rx", end=END_1)
    vlans = board.rank_window(Scope.VLAN, "5m", "rx", end=END_1)
    assert [r.scope for r in wans.rows] == [Scope.WAN]
    assert [r.scope for r in ifaces.rows] == [Scope.INTERFACE]
    assert [r.vlan_id for r in vlans.rows] == [10]


def test_interfaces_have_no_download_and_no_overlapping_share() -> None:
    ring = MemoryBucketRing()
    fill(ring, MeasurementPoint(RIDS[0], Scope.INTERFACE, device="br-lan"), 9_000, 1)
    fill(ring, MeasurementPoint(RIDS[0], Scope.INTERFACE, device="eth0"), 4_000, 1)
    board = TalkerBoard(ring)
    down = board.rank_window(Scope.INTERFACE, "5m", "download", end=END_1)
    assert down.state == STATE_UNAVAILABLE and down.reason == DIR_AMBIGUOUS_BRIDGE
    rx = board.rank_window(Scope.INTERFACE, "5m", "rx", end=END_1)
    assert [r.value for r in rx.rows] == [9_000, 4_000]
    assert {r.share_reason for r in rx.rows} == {SUM_INTERFACES_OVERLAP}
    assert all(r.share_pct is None for r in rx.rows)


def test_ports_without_role_are_left_out_and_counted() -> None:
    ring = MemoryBucketRing()
    fill(ring, MeasurementPoint(RIDS[0], Scope.PORT, device="lan1"), 1_000, 1)
    out = TalkerBoard(ring).rank_window(Scope.PORT, "5m", "download", end=END_1)
    assert out.state == STATE_UNAVAILABLE
    assert out.omitted == {DIR_PORT_ROLE_UNKNOWN: 1}
    assert TalkerBoard(ring).rank_window(Scope.PORT, "5m", "rx", end=END_1).rows


def test_station_and_flow_scopes_are_not_ranked() -> None:
    board = TalkerBoard(MemoryBucketRing())
    assert board.rank_window(Scope.STATION, "5m", "download", end=END_1).reason == (
        REASON_USE_CLIENT_SCOPE
    )
    assert board.rank_window(Scope.FLOW, "5m", "download", end=END_1).reason == (
        "needs_flow_source"
    )


# --- clients: once across APs, never "internet" -------------------------------------


def test_client_at_two_aps_counts_once() -> None:
    ring = MemoryBucketRing()
    a = MeasurementPoint(RIDS[0], Scope.STATION, radio_id="phy0-ap0", client_ref=ref(1))
    b = MeasurementPoint(RIDS[1], Scope.STATION, radio_id="phy1-ap0", client_ref=ref(1))
    other = MeasurementPoint(
        RIDS[0], Scope.STATION, radio_id="phy0-ap0", client_ref=ref(2)
    )
    cov = {"coverage": Coverage.PARTIAL, "reason": CoverageReason.STATION_COUNTERS_ONLY}
    ring.add_rate(rate(a, T0 + 150, 10, 1_000, interval=150, **cov))
    ring.add_rate(rate(b, T0 + 300, 10, 2_000, interval=150, **cov))
    # the duplicate sighting at the other AP was made stale by the accounting
    ring.add_rate(rate(a, T0 + 300, None, None, quality=Quality.STALE_SOURCE, **cov))
    ring.add_rate(rate(other, T0 + 300, 10, 2_500, **cov))
    out = TalkerBoard(ring).rank_window(Scope.CLIENT, "5m", "download", end=END_1)
    assert [r.client_ref for r in out.rows] == [ref(1), ref(2)]
    assert [r.observed_bytes for r in out.rows] == [3_000, 2_500]
    assert len({r.client_ref for r in out.rows}) == len(out.rows)
    assert out.rows[0].measuring_area == CLIENT_VALUE_KIND
    assert out.rows[0].router_id is None
    assert out.partial and "station_counters_only" in out.partial_reasons
    assert all(r.share_pct is None for r in out.rows)  # never full: no share
    assert "internet" not in json.dumps(out.to_dict()).lower()


def test_current_ranking_counts_a_client_once() -> None:
    a = MeasurementPoint(RIDS[0], Scope.STATION, radio_id="phy0-ap0", client_ref=ref(1))
    b = MeasurementPoint(RIDS[1], Scope.STATION, radio_id="phy1-ap0", client_ref=ref(1))
    c = MeasurementPoint(RIDS[0], Scope.STATION, radio_id="phy0-ap0", client_ref=ref(2))
    cov = {"coverage": Coverage.PARTIAL, "reason": CoverageReason.STATION_COUNTERS_ONLY}
    rates = [
        rate(a, T0 + 60, 1, 600, interval=60, **cov),
        rate(b, T0 + 120, 1, 1_200, interval=60, **cov),  # newer: counts
        rate(c, T0 + 120, 1, 300, interval=60, **cov),
        rate(a, T0 + 120, None, None, quality=Quality.STALE_SOURCE, **cov),
    ]
    out = rank_current(rates, Scope.CLIENT, "download")
    assert [r.client_ref for r in out.rows] == [ref(1), ref(2)]
    assert [r.value for r in out.rows] == [160.0, 40.0]  # bit/s
    assert out.rows[0].router_id == RIDS[1]
    assert out.metric == "bps"
    assert all(r.share_pct is None for r in out.rows)


def test_current_ranking_of_wan_has_share_and_omits_invalid() -> None:
    rates = [
        rate(wan(0), T0 + 60, 750, 1, interval=60),
        rate(wan(1), T0 + 60, 250, 1, interval=60),
    ]
    out = rank_current(rates, Scope.WAN, "download")
    assert [r.share_pct for r in out.rows] == [75.0, 25.0]
    rates.append(rate(wan(2), T0 + 60, None, None, quality=Quality.GAP))
    out = rank_current(rates, Scope.WAN, "download")
    assert out.partial and REASON_POINTS_OMITTED in out.partial_reasons
    assert out.omitted == {"gap": 1}
    assert all(r.share_pct is None for r in out.rows)


# --- bounds and determinism -------------------------------------------------------


def test_top_n_is_capped_and_ties_are_deterministic() -> None:
    ring = MemoryBucketRing(max_clients=300)
    for n in range(120):
        point = MeasurementPoint(None, Scope.CLIENT, client_ref=ref(n))
        fill(ring, point, 1, 1_000 if n % 2 else 2_000)
    board = TalkerBoard(ring)
    out = board.rank_window(Scope.CLIENT, "5m", "download", end=END_1, limit=500)
    assert len(out.rows) == MAX_TALKERS and out.limit == MAX_TALKERS
    assert out.considered == 120
    values = [r.value for r in out.rows]
    assert values == sorted(values, reverse=True)
    ties = [r.point_id for r in out.rows if r.value == 2_000]
    assert ties == sorted(ties)
    again = TalkerBoard(ring).rank_window(
        Scope.CLIENT, "5m", "download", end=END_1, limit=50
    )
    assert [r.point_id for r in again.rows] == [r.point_id for r in out.rows]
    assert [r.rank for r in out.rows] == list(range(1, MAX_TALKERS + 1))


@pytest.mark.parametrize(
    ("raw", "expected"), [(0, 10), (-3, 10), (True, 10), ("5", 10), (7, 7), (99, 50)]
)
def test_limit_is_clamped(raw: Any, expected: int) -> None:
    assert clamp_limit(raw) == expected


def test_results_are_cached_by_source_version() -> None:
    ring = MemoryBucketRing()
    fill(ring, wan(0), 1_000, 1)
    board = TalkerBoard(ring)
    first = board.rank_window(Scope.WAN, "5m", "download", end=END_1)
    assert board.rank_window(Scope.WAN, "5m", "download", end=END_1) is first
    assert board.counters["cache_hits"] == 1
    ring.add_rate(rate(wan(0), T0 + 300, 1, 1, interval=10))
    assert board.rank_window(Scope.WAN, "5m", "download", end=END_1) is not first


def test_quota_drops_make_the_list_partial() -> None:
    ring = MemoryBucketRing(max_clients=1)
    fill(ring, MeasurementPoint(None, Scope.CLIENT, client_ref=ref(1)), 1, 10)
    fill(ring, MeasurementPoint(None, Scope.CLIENT, client_ref=ref(2)), 1, 20)
    out = TalkerBoard(ring).rank_window(Scope.CLIENT, "5m", "download", end=END_1)
    assert REASON_POINTS_DROPPED in out.partial_reasons
    assert len(out.rows) == 1


# --- recurring peaks -----------------------------------------------------------------


def test_recurring_peaks_count_episodes() -> None:
    ring = MemoryBucketRing()
    busy, calm = wan(0), wan(1)
    for i in range(24):
        spike = i in (3, 4, 10, 17)  # episodes: 3-4, 10, 17
        ring.add_rate(
            rate(busy, T0 + 300 * (i + 1), 375_000, 1, rx_bps=50e6 if spike else 10_000)
        )
        ring.add_rate(rate(calm, T0 + 300 * (i + 1), 375_000, 1, rx_bps=10_000))
    board = TalkerBoard(ring)
    out = board.rank_recurring_peaks(Scope.WAN, "24h", "download", end=T0 + 300 * 24)
    assert out.state == STATE_OK
    assert [r.point_id for r in out.rows] == [busy.point_id]
    assert out.rows[0].value == 3.0 and out.rows[0].peak_bps == 50e6
    assert out.considered == 2


def test_recurring_peaks_need_enough_buckets() -> None:
    ring = MemoryBucketRing()
    fill(ring, wan(0), 1_000, 1, buckets=5)
    out = TalkerBoard(ring).rank_recurring_peaks(
        Scope.WAN, "1h", "download", end=T0 + 1500
    )
    assert out.state == STATE_UNAVAILABLE and out.reason == REASON_INSUFFICIENT_DATA
    assert peak_episodes([], "rx") is None


# --- engine wiring -----------------------------------------------------------------


def test_engine_feeds_the_ring_and_exposes_talkers() -> None:
    from core_testkit import make_hass

    from custom_components.openwrt_router.traffic_engine import TrafficEngine

    engine = TrafficEngine(make_hass())
    engine.book.put(wan(0), None, 0.0)  # point known to the baseline book
    engine._keep_rates([rate(wan(0), T0 + 300, 4_000, 2_000)])
    assert engine.summary()["series"]["points_infra"] == 1
    out = engine.talkers.rank_window(Scope.WAN, "5m", "download", end=END_1)
    assert out.rows[0].observed_bytes == 4_000
    engine._drop_router(RIDS[0])
    # Phase I: an entry unload keeps the history (evidence survives a reload)
    assert engine.summary()["series"]["points_infra"] == 1
    engine.series.forget_router(RIDS[0])
    assert engine.summary()["series"]["points_infra"] == 0
