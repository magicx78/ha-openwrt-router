"""History read interface and memory ring (plan 2026-11-20 §3.3, §5): traffic_series.

Buckets aligned, bytes split by overlap, unknown stays None, separate quotas
with visible drops, windows without data are unavailable with a reason.
No router, no network.
"""

from __future__ import annotations

import json

from custom_components.openwrt_router.traffic_const import (
    REASON_BEYOND_RETENTION,
    REASON_HISTORY_NOT_BUILT,
    REASON_HISTORY_SHORT,
    REASON_NO_DATA_YET,
    REASON_TIME_PARTIAL,
)
from custom_components.openwrt_router.traffic_model import (
    Coverage,
    CoverageReason,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
)
from custom_components.openwrt_router.traffic_series import (
    MemoryBucketRing,
    NoHistory,
)

RID = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
REF = "cli_" + "a" * 16
T0 = 1_800_000_000  # aligned to 300 s
WAN = MeasurementPoint(RID, Scope.WAN, device="wan")


def rate(
    point: MeasurementPoint,
    wall: float,
    rx: int | None = 6_000,
    tx: int | None = 3_000,
    interval: float = 60.0,
    quality: Quality = Quality.OK,
    coverage: Coverage = Coverage.FULL,
    reason: CoverageReason | None = None,
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
        coverage=coverage,
        coverage_reason=reason,
        wall_s=wall,
        mono_s=wall,
    )


def test_no_history_has_nothing() -> None:
    source = NoHistory()
    assert source.points() == ()
    assert source.window("tpt_" + "0" * 16, 3600, end=T0) is None
    assert source.reason == REASON_HISTORY_NOT_BUILT


def test_rate_is_split_over_bucket_boundaries() -> None:
    ring = MemoryBucketRing()
    # 60 s ending 30 s into the next bucket: 30 s in each
    ring.add_rate(rate(WAN, T0 + 330, rx=1001, tx=None, interval=60))
    win = ring.window(WAN.point_id, 600, end=T0 + 600)
    assert [b.start for b in win.buckets] == [T0, T0 + 300]
    assert [b.rx_bytes for b in win.buckets] == [500, 501]
    assert [b.tx_bytes for b in win.buckets] == [None, None]  # unknown, not 0
    assert [b.covered_s for b in win.buckets] == [30.0, 30.0]
    assert win.total("rx_bytes") == 1001
    assert win.total("tx_bytes") is None


def test_window_coverage_and_reasons() -> None:
    ring = MemoryBucketRing()
    for i in range(5):
        ring.add_rate(rate(WAN, T0 + 60 * (i + 1)))
    win = ring.window(WAN.point_id, 300, end=T0 + 300)
    assert win.time_coverage == 1.0
    assert win.coverage is Coverage.FULL
    assert win.reason is None
    longer = ring.window(WAN.point_id, 3600, end=T0 + 300)
    assert longer.coverage is Coverage.PARTIAL
    assert longer.reason == REASON_HISTORY_SHORT
    assert REASON_TIME_PARTIAL in longer.coverage_reasons
    empty = ring.window(WAN.point_id, 300, end=T0 + 3600)
    assert empty.coverage is Coverage.UNAVAILABLE
    assert empty.reason == REASON_NO_DATA_YET


def test_area_coverage_is_kept_apart_from_time() -> None:
    ring = MemoryBucketRing()
    for i in range(5):
        ring.add_rate(
            rate(
                WAN,
                T0 + 60 * (i + 1),
                coverage=Coverage.PARTIAL,
                reason=CoverageReason.HW_OFFLOAD_UNKNOWN,
            )
        )
    win = ring.window(WAN.point_id, 300, end=T0 + 300)
    assert win.time_coverage == 1.0
    assert win.coverage is Coverage.PARTIAL
    assert win.coverage_reasons == ("hw_offload_unknown",)


def test_invalid_rates_mark_but_never_cover() -> None:
    ring = MemoryBucketRing()
    ring.add_rate(rate(WAN, T0 + 10, quality=Quality.GAP))
    win = ring.window(WAN.point_id, 300, end=T0 + 300)
    (bucket,) = win.buckets
    assert bucket.covered_s == 0 and bucket.rx_bytes is None
    assert bucket.quality_mask != 0
    assert win.coverage is Coverage.UNAVAILABLE


def test_station_rates_become_one_client_point() -> None:
    ring = MemoryBucketRing()
    at_a = MeasurementPoint(RID, Scope.STATION, radio_id="phy0-ap0", client_ref=REF)
    at_b = MeasurementPoint(RID2, Scope.STATION, radio_id="phy1-ap0", client_ref=REF)
    ring.add_rate(rate(at_a, T0 + 60, rx=100, tx=1000))
    ring.add_rate(rate(at_b, T0 + 120, rx=200, tx=2000))
    ring.add_rate(rate(at_b, T0 + 120, quality=Quality.STALE_SOURCE))  # duplicate
    (point,) = ring.points()
    assert point.scope is Scope.CLIENT and point.router_id is None
    assert point.client_ref == REF
    win = ring.window(point.point_id, 300, end=T0 + 300)
    assert (win.total("rx_bytes"), win.total("tx_bytes")) == (300, 3000)


def test_separate_quotas_with_visible_drops() -> None:
    ring = MemoryBucketRing(max_infra_per_router=2, max_infra_total=3, max_clients=1)
    for i in range(3):
        ring.add_rate(
            rate(MeasurementPoint(RID, Scope.PORT, device=f"lan{i}"), T0 + 60)
        )
    assert ring.counters["dropped_points_infra"] == 1
    ring.add_rate(rate(MeasurementPoint(RID2, Scope.WAN, device="wan"), T0 + 60))
    ring.add_rate(rate(MeasurementPoint(RID2, Scope.PORT, device="lan1"), T0 + 60))
    assert ring.counters["dropped_points_infra"] == 2  # total quota
    # clients never take an infrastructure slot and vice versa
    c1 = MeasurementPoint(None, Scope.CLIENT, client_ref="cli_" + "1" * 16)
    c2 = MeasurementPoint(None, Scope.CLIENT, client_ref="cli_" + "2" * 16)
    assert ring.add_rate(rate(c1, T0 + 60))
    assert not ring.add_rate(rate(c2, T0 + 120))  # c1 is active: never displaced
    assert ring.counters["dropped_points_client"] == 1
    # after 24 h idle c1 may make room
    assert ring.add_rate(rate(c2, T0 + 60 + 86_401))
    assert ring.counters["replaced_client_points"] == 1
    summary = ring.summary()
    assert summary["points_infra"] == 3 and summary["points_client"] == 1


def test_ring_is_bounded_and_reports_retention() -> None:
    ring = MemoryBucketRing(max_buckets_infra=12)
    for i in range(60):  # 60 buckets of 300 s
        ring.add_rate(rate(WAN, T0 + 300 * i + 300, interval=300))
    win = ring.window(WAN.point_id, 86400, end=T0 + 300 * 60)
    assert len(win.buckets) == 12
    assert win.reason == REASON_BEYOND_RETENTION
    assert ring.summary()["buckets"] == 12
    # a rate older than the ring is dropped and counted
    ring.add_rate(rate(WAN, T0 + 300))
    assert ring.counters["late_rates"] == 1


def test_rates_without_wall_time_are_counted() -> None:
    ring = MemoryBucketRing()
    bad = Rate(WAN, Quality.OK, interval_s=60, rx_delta=1, tx_delta=1)
    assert not ring.add_rate(bad)
    assert ring.counters["rates_without_wall"] == 1


def test_long_gap_starts_over_and_flow_points_are_not_kept() -> None:
    ring = MemoryBucketRing(max_buckets_infra=4)
    ring.add_rate(rate(WAN, T0 + 60))
    ring.add_rate(rate(WAN, T0 + 86400))
    win = ring.window(WAN.point_id, 600, end=T0 + 86400)
    assert win.total("rx_bytes") == 6000
    assert ring.summary()["buckets"] <= 4
    assert not ring.add_rate(rate(MeasurementPoint(RID, Scope.FLOW), T0 + 60))


def test_summary_has_no_identifiers() -> None:
    ring = MemoryBucketRing()
    ring.add_rate(rate(MeasurementPoint(None, Scope.CLIENT, client_ref=REF), T0 + 60))
    text = json.dumps(ring.summary())
    assert "cli_" not in text and "tpt_" not in text and "rtr_" not in text
    ring.clear()
    assert len(ring) == 0 and ring.points() == ()
