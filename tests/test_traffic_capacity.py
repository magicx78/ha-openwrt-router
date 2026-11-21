"""Capacity planning (test areas 21 interface capacity, 22 95th percentile).

traffic_capacity.py: P95 nearest rank (edge cases: too few points, gaps,
equal values), utilisation only against a known link speed and duplex,
"possible" bottlenecks only, cautious Theil-Sen trend marked as estimate.
No router, no network.
"""

from __future__ import annotations

import json
import math
from typing import Any

import pytest

from custom_components.openwrt_router.traffic_capacity import (
    LinkFacts,
    capacity_row,
    capacity_rows,
    link_bps,
    p95,
    theil_sen,
    trend,
)
from custom_components.openwrt_router.traffic_const import (
    CAP_STATE_APPROACHING,
    CAP_STATE_HEADROOM,
    CAP_STATE_INSUFFICIENT,
    CAP_STATE_NO_LINK,
    CAP_STATE_POSSIBLE_BOTTLENECK,
    CAP_STATE_POSSIBLE_UPLINK_BOTTLENECK,
    REASON_BEYOND_HORIZON,
    REASON_HALF_DUPLEX_SHARED,
    REASON_NO_LINK_SPEED,
    REASON_NOT_RISING,
    REASON_P95_FROM_COARSE,
    REASON_TREND_LOW_COVERAGE,
    REASON_TREND_TOO_SHORT,
)
from custom_components.openwrt_router.traffic_model import (
    Bucket,
    Coverage,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
)
from custom_components.openwrt_router.traffic_series import (
    MemoryBucketRing,
    SeriesWindow,
)

RID = "rtr_" + "1" * 32
T0 = 1_800_000_000 - 1_800_000_000 % 86400  # a UTC midnight
MBIT = 1_000_000.0
PORT = MeasurementPoint(RID, Scope.PORT, device="lan1")
WAN = MeasurementPoint(RID, Scope.WAN, device="wan")
GIG = LinkFacts(1000, "full")


def bucket(
    i: int,
    rx_bps: float | None,
    tx_bps: float | None = None,
    *,
    res: int = 300,
    covered: float | None = None,
    peak: float | None = None,
) -> Bucket:
    cov = float(res if covered is None else covered)
    return Bucket(
        start=T0 + i * res,
        resolution_s=res,
        rx_bytes=None if rx_bps is None else int(rx_bps * cov / 8),
        tx_bytes=None if tx_bps is None else int(tx_bps * cov / 8),
        rx_peak_bps=peak,
        covered_s=cov,
        samples=1,
    )


def window(
    point: MeasurementPoint, buckets: list[Bucket], window_s: int = 86400
) -> SeriesWindow:
    res = buckets[0].resolution_s if buckets else 300
    return SeriesWindow(
        point=point,
        window_s=window_s,
        end=float(T0 + window_s),
        resolution_s=res,
        buckets=tuple(buckets),
        depth_s=float(window_s),
        area_coverage=Coverage.FULL,
    )


# --- area 22: 95th percentile ------------------------------------------------------------


def test_p95_nearest_rank_exact() -> None:
    assert p95([float(v) for v in range(1, 101)]) == 95.0
    assert p95([float(v) for v in range(100, 0, -1)]) == 95.0  # order does not matter
    assert p95([float(v) for v in range(1, 21)]) == 19.0  # ceil(0.95 x 20) = 19
    assert p95([float(v) for v in range(1, 22)]) == 20.0  # ceil(19.95) = 20
    assert p95([7.0] * 20) == 7.0  # equal values
    assert p95([1.0] * 19 + [1000.0]) == 1.0  # one outlier above the 95th rank


def test_p95_needs_enough_points() -> None:
    assert p95([]) is None
    assert p95([1.0] * 19) is None


def test_p95_ignores_gappy_buckets() -> None:
    good = [bucket(i, 100 * MBIT) for i in range(20)]
    gaps = [bucket(20 + i, 900 * MBIT, covered=100) for i in range(5)]
    row = capacity_row(
        PORT, window(PORT, good + gaps), link=GIG, uplink=None, trend_window=None
    )
    rx = row.directions[0]
    assert rx.p95_bps == pytest.approx(100 * MBIT)
    assert row.usable_buckets == 20 and row.gappy_buckets == 5
    few = capacity_row(
        PORT, window(PORT, good[:19] + gaps), link=GIG, uplink=None, trend_window=None
    )
    assert few.directions[0].p95_bps is None
    assert few.directions[0].unavailable["p95_bps"] == "insufficient_data"
    assert few.state == CAP_STATE_INSUFFICIENT


def test_p95_from_coarse_buckets_is_marked_estimated() -> None:
    hourly = [bucket(i, 10 * MBIT, res=3600) for i in range(30)]
    row = capacity_row(
        PORT, window(PORT, hourly, 30 * 3600), link=GIG, uplink=None, trend_window=None
    )
    assert row.p95_estimated is True
    assert REASON_P95_FROM_COARSE in row.reasons


# --- area 21: interface capacity ---------------------------------------------------------


def test_utilisation_against_the_real_link() -> None:
    buckets = [
        bucket(i, 500 * MBIT if i % 2 else 300 * MBIT, 50 * MBIT, peak=800 * MBIT)
        for i in range(40)
    ]
    row = capacity_row(
        PORT, window(PORT, buckets), link=GIG, uplink=False, trend_window=None
    )
    rx, tx = row.directions
    assert rx.avg_bps == pytest.approx(400 * MBIT, rel=1e-6)
    assert rx.avg_pct == pytest.approx(40.0)
    assert rx.peak_pct == pytest.approx(80.0)
    assert rx.p95_pct == pytest.approx(50.0)
    assert tx.p95_pct == pytest.approx(5.0)
    assert row.link_mbps == 1000 and row.duplex == "full"
    assert row.state == CAP_STATE_HEADROOM


def test_without_link_speed_there_is_no_utilisation() -> None:
    buckets = [bucket(i, 900 * MBIT) for i in range(40)]
    row = capacity_row(
        PORT, window(PORT, buckets), link=None, uplink=None, trend_window=None
    )
    rx = row.directions[0]
    assert rx.p95_bps == pytest.approx(900 * MBIT)  # the rate is known
    assert rx.p95_pct is None and rx.avg_pct is None
    assert rx.unavailable["p95_pct"] == REASON_NO_LINK_SPEED
    assert row.state == CAP_STATE_NO_LINK  # high bandwidth alone: no bottleneck
    for bad in (LinkFacts(None, "full"), LinkFacts(0, "full"), LinkFacts(-10, None)):
        assert (
            capacity_row(
                PORT, window(PORT, buckets), link=bad, uplink=None, trend_window=None
            ).state
            == CAP_STATE_NO_LINK
        )
    assert link_bps(True) is None and link_bps(100) == 100 * MBIT


def test_vlan_netdevs_have_no_link_speed() -> None:
    vlan = MeasurementPoint(RID, Scope.VLAN, device="br-lan.10", vlan_id=10)
    buckets = [bucket(i, 10 * MBIT) for i in range(40)]
    row = capacity_row(
        vlan, window(vlan, buckets), link=GIG, uplink=False, trend_window=None
    )
    assert row.link_mbps is None and row.state == CAP_STATE_NO_LINK
    assert row.directions[0].p95_bps == pytest.approx(10 * MBIT)


def test_half_duplex_rx_and_tx_share_the_link() -> None:
    buckets = [bucket(i, 40 * MBIT, 40 * MBIT) for i in range(40)]
    half = LinkFacts(100, "half")
    row = capacity_row(
        PORT, window(PORT, buckets), link=half, uplink=None, trend_window=None
    )
    assert REASON_HALF_DUPLEX_SHARED in row.reasons
    assert row.shared_p95_pct == pytest.approx(80.0)
    assert row.directions[0].p95_pct is None  # per direction not meaningful
    assert row.state == CAP_STATE_APPROACHING
    full = capacity_row(
        PORT,
        window(PORT, buckets),
        link=LinkFacts(100, "full"),
        uplink=None,
        trend_window=None,
    )
    assert full.directions[0].p95_pct == pytest.approx(40.0)
    assert full.state == CAP_STATE_HEADROOM


@pytest.mark.parametrize(
    ("rate_mbit", "uplink", "state"),
    [
        (600, False, CAP_STATE_HEADROOM),
        (750, False, CAP_STATE_APPROACHING),
        (950, False, CAP_STATE_POSSIBLE_BOTTLENECK),
        (950, True, CAP_STATE_POSSIBLE_UPLINK_BOTTLENECK),
    ],
)
def test_assessment_levels(rate_mbit: float, uplink: bool, state: str) -> None:
    buckets = [bucket(i, rate_mbit * MBIT) for i in range(40)]
    row = capacity_row(
        PORT, window(PORT, buckets), link=GIG, uplink=uplink, trend_window=None
    )
    assert row.state == state
    assert "confirmed" not in json.dumps(row.to_dict())


def test_recurring_bottleneck_on_two_days() -> None:
    buckets = []
    for day in range(3):
        for i in range(288):
            busy = day < 2 and 240 <= i < 243  # 15 min near capacity, days 0 and 1
            buckets.append(bucket(day * 288 + i, 850 * MBIT if busy else 100 * MBIT))
    row = capacity_row(
        PORT,
        window(PORT, buckets, 3 * 86400),
        link=GIG,
        uplink=False,
        trend_window=None,
    )
    assert row.near_capacity_days == 2
    assert row.state == CAP_STATE_POSSIBLE_BOTTLENECK
    one = capacity_row(
        PORT,
        window(PORT, buckets[288:], 2 * 86400),
        link=GIG,
        uplink=False,
        trend_window=None,
    )
    assert one.near_capacity_days == 1 and one.state == CAP_STATE_HEADROOM


# --- trend --------------------------------------------------------------------------------


def daily(days: list[int], level: Any) -> SeriesWindow:
    # Entscheidung: hourly buckets, a full day of coverage per listed day
    hourly = [
        Bucket(
            start=T0 + d * 86400 + h * 3600,
            resolution_s=3600,
            rx_bytes=int(level(d) * 3600 / 8),
            tx_bytes=0,
            covered_s=3600.0,
        )
        for d in days
        for h in range(24)
    ]
    return window(WAN, hourly, 90 * 86400)


def test_theil_sen_is_robust_to_an_outlier() -> None:
    points = [(float(x), 2.0 * x + 1) for x in range(10)]
    points[5] = (5.0, 1000.0)
    slope, intercept = theil_sen(points)
    assert slope == pytest.approx(2.0) and intercept == pytest.approx(1.0)
    assert theil_sen([(1.0, 1.0)]) is None


def test_trend_is_an_estimate_with_its_data_base() -> None:
    win = daily(list(range(30)), lambda d: (100 + 10 * d) * MBIT)
    result = trend(win, link_bps(1000))
    assert result.state == "estimated" and result.estimate is True
    assert result.basis_days == 30 and result.span_days == 30
    assert result.slope_bps_per_day == pytest.approx(10 * MBIT)
    assert result.slope_pct_per_week == pytest.approx(7.0)
    # level 390 Mbit/s, 800 Mbit/s reached after 41 more days
    assert result.days_to_near_capacity == pytest.approx(41.0)
    assert 0 < result.confidence <= 0.8


def test_trend_needs_a_long_enough_series() -> None:
    short = trend(daily(list(range(10)), lambda d: d * MBIT), link_bps(1000))
    assert short.state == CAP_STATE_INSUFFICIENT
    assert short.reason == REASON_TREND_TOO_SHORT
    assert short.slope_bps_per_day is None and short.days_to_near_capacity is None
    sparse = trend(daily(list(range(0, 40, 2)), lambda d: d * MBIT), link_bps(1000))
    assert sparse.state == CAP_STATE_INSUFFICIENT
    assert sparse.reason == REASON_TREND_LOW_COVERAGE
    assert trend(None, None).reason == REASON_TREND_TOO_SHORT


def test_trend_without_rise_or_link_gives_no_date() -> None:
    flat = trend(daily(list(range(20)), lambda d: 100 * MBIT), link_bps(1000))
    assert flat.days_to_near_capacity is None
    assert flat.days_to_near_capacity_reason == REASON_NOT_RISING
    slow = trend(
        daily(list(range(20)), lambda d: (100 + 0.1 * d) * MBIT), link_bps(1000)
    )
    assert slow.days_to_near_capacity_reason == REASON_BEYOND_HORIZON
    nolink = trend(daily(list(range(20)), lambda d: (100 + d) * MBIT), None)
    assert nolink.slope_pct_per_week is None
    assert nolink.days_to_near_capacity_reason == REASON_NO_LINK_SPEED
    assert math.isfinite(nolink.slope_bps_per_day)


# --- over the history interface and the engine ----------------------------------------------


def test_capacity_rows_over_the_ring() -> None:
    ring = MemoryBucketRing()
    for i in range(30):
        for point, bps in ((WAN, 200 * MBIT), (PORT, 20 * MBIT)):
            ring.add_rate(
                Rate(
                    point,
                    Quality.OK,
                    interval_s=300.0,
                    rx_bps=bps,
                    tx_bps=bps / 2,
                    rx_delta=int(bps * 300 / 8),
                    tx_delta=int(bps * 150 / 8),
                    coverage=Coverage.FULL,
                    wall_s=T0 + 300 * (i + 1),
                )
            )
    rows = capacity_rows(
        ring,
        end=T0 + 300 * 30,
        links={WAN.point_id: GIG},
        uplink_ports={RID: frozenset()},
    )
    by_scope = {r.scope: r for r in rows}
    assert by_scope[Scope.WAN].directions[0].p95_pct == pytest.approx(20.0)
    assert by_scope[Scope.WAN].uplink is True
    assert by_scope[Scope.PORT].state == CAP_STATE_NO_LINK
    assert by_scope[Scope.PORT].uplink is False
    assert by_scope[Scope.WAN].trend.state == CAP_STATE_INSUFFICIENT
    assert capacity_rows(ring, end=T0, router_id="rtr_" + "9" * 32) == []


def test_engine_capacity_uses_poll_link_facts() -> None:
    from core_testkit import make_hass

    from custom_components.openwrt_router.traffic_engine import TrafficEngine

    engine = TrafficEngine(make_hass())
    engine.wall = lambda: float(T0 + 3600)
    assert engine.capacity() == []
    assert engine.link_facts() == {}
