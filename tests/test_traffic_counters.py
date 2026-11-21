"""Counter rules of Traffic Analytics (plan 2026-11-20, §3.4): traffic_counters.py.

Pure functions, no Home Assistant, no router, no network. Test areas 1-8:
interface RX/TX and rates, counter reset, overflow (wrap_32), router
restart, interface restart, measurement gaps, wrong or missing timestamps,
and the HA-restart rule 8. Plus the bounded baseline book (quotas).
Generic names only; router ids and client refs are synthetic.
"""

from __future__ import annotations

import math
from typing import Any

import pytest

from custom_components.openwrt_router.traffic_const import (
    COUNTER_32_RANGE,
    DEFAULT_LIMIT_STATION_BPS,
    DEFAULT_LIMIT_WIRED_BPS,
    MAX_INTERVAL_S,
    MIN_INTERVAL_S,
)
from custom_components.openwrt_router.traffic_counters import (
    Baseline,
    BaselineBook,
    as_counter,
    default_coverage,
    delta,
    finite_time,
    known_uptime,
    plausibility_limit,
    process_samples,
    rate_is_valid,
    restored_interval,
    router_restarted,
)
from custom_components.openwrt_router.traffic_model import (
    Coverage,
    CoverageReason,
    MeasurementPoint,
    Quality,
    Sample,
    Scope,
    Source,
)

RID = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
CREF = "cli_" + "a" * 16
CREF2 = "cli_" + "b" * 16

ETH = MeasurementPoint(RID, Scope.INTERFACE, device="eth0")
WAN = MeasurementPoint(RID, Scope.WAN, device="wan")
STA = MeasurementPoint(RID, Scope.STATION, radio_id="phy0-ap0", client_ref=CREF)


def sample(
    mono: Any,
    rx: Any,
    tx: Any,
    *,
    point: MeasurementPoint = ETH,
    uptime: Any = 10_000,
    wall: Any = None,
    source: Source = Source.NETDEV,
    link: int | None = None,
    duplex: str | None = None,
    **extra: Any,
) -> Sample:
    """One sample; ``wall`` defaults to a fixed epoch plus ``mono``."""
    if wall is None and isinstance(mono, int | float) and not isinstance(mono, bool):
        wall = 1_800_000_000.0 + mono if math.isfinite(mono) else None
    return Sample(
        point,
        mono,
        wall,
        rx_bytes=rx,
        tx_bytes=tx,
        link_mbps=link,
        duplex=duplex,
        source=source,
        router_uptime_s=uptime,
        **extra,
    )


def first(s: Sample) -> Baseline:
    """The baseline a first sample leaves."""
    result = delta(None, s)
    assert result.rate is not None
    assert result.rate.quality is Quality.FIRST_SAMPLE
    assert result.baseline is not None
    return result.baseline


def step(prev: Sample, cur: Sample, **kw: Any) -> Any:
    """Delta of ``cur`` against the baseline of ``prev``."""
    return delta(first(prev), cur, **kw)


def assert_no_rate(rate: Any, quality: Quality) -> None:
    assert rate is not None
    assert rate.quality is quality
    assert rate.rx_bps is None and rate.tx_bps is None
    assert rate.rx_delta is None and rate.tx_delta is None
    assert rate.coverage is Coverage.UNAVAILABLE
    assert not rate_is_valid(rate)


# --- area 1: interface RX/TX and rates -------------------------------------------------


def test_rate_in_bits_per_second() -> None:
    prev = sample(100.0, 1_000, 500, uptime=1_000)
    cur = sample(110.0, 1_000 + 1_250_000, 500 + 125_000, uptime=1_010)
    result = step(prev, cur)
    rate = result.rate
    assert rate.quality is Quality.OK
    assert rate_is_valid(rate)
    assert rate.interval_s == 10.0
    assert rate.rx_delta == 1_250_000
    assert rate.tx_delta == 125_000
    assert rate.rx_bps == 1_000_000.0  # 125 000 B/s x 8
    assert rate.tx_bps == 100_000.0
    assert rate.source is Source.NETDEV
    # the new baseline is the current read
    assert result.baseline.counters[0] == 1_251_000
    assert result.baseline.mono_s == 110.0


def test_secondary_counters_and_unknown_stays_none() -> None:
    prev = sample(0.0, 10, 20, rx_packets=1, tx_packets=2, rx_errors=0)
    cur = sample(30.0, 40, 50, rx_packets=4, tx_packets=8, rx_errors=3)
    rate = step(prev, cur).rate
    assert rate.rx_packets_delta == 3
    assert rate.tx_packets_delta == 6
    assert rate.rx_errors_delta == 3
    # never delivered -> unknown, never 0
    assert rate.tx_errors_delta is None
    assert rate.rx_dropped_delta is None
    assert rate.tx_dropped_delta is None


def test_one_direction_missing_gives_none_for_it_only() -> None:
    prev = sample(0.0, None, 100)
    cur = sample(10.0, None, 1_100)
    rate = step(prev, cur).rate
    assert rate.quality is Quality.OK
    assert rate.rx_bps is None and rate.rx_delta is None
    assert rate.tx_bps == 800.0


def test_direction_known_only_now_starts_a_new_baseline() -> None:
    prev = sample(0.0, None, 100)
    cur = sample(10.0, 500, None)
    result = step(prev, cur)
    assert_no_rate(result.rate, Quality.FIRST_SAMPLE)
    assert result.baseline.counters[0] == 500


def test_first_sample_has_no_rate() -> None:
    result = delta(None, sample(0.0, 1, 2))
    assert_no_rate(result.rate, Quality.FIRST_SAMPLE)
    assert result.baseline is not None


def test_zero_traffic_is_a_real_zero() -> None:
    rate = step(sample(0.0, 7, 7), sample(10.0, 7, 7)).rate
    assert rate.quality is Quality.OK
    assert rate.rx_bps == 0.0 and rate.tx_bps == 0.0


def test_coverage_of_interface_and_station() -> None:
    assert default_coverage(ETH) == (Coverage.UNKNOWN, None)
    assert default_coverage(STA) == (
        Coverage.PARTIAL,
        CoverageReason.STATION_COUNTERS_ONLY,
    )
    rate = step(
        sample(0.0, 0, 0, point=STA, source=Source.HOSTAPD),
        sample(10.0, 10, 10, point=STA, source=Source.HOSTAPD),
    ).rate
    assert rate.coverage is Coverage.PARTIAL
    assert rate.coverage_reason is CoverageReason.STATION_COUNTERS_ONLY


@pytest.mark.parametrize(
    "seq",
    [
        [(0, 100, 100), (10, 50, 200), (20, 60, 210)],
        [(0, 2**32 - 10, 0), (10, 5, 5)],
        [(0, 10, 10), (10, 10, 9), (20, 0, 0), (30, 1, 1)],
        [(0, 500, 500), (3, 400, 400), (10, 600, 600)],
    ],
)
@pytest.mark.parametrize("source", [Source.NETDEV, Source.HOSTAPD])
def test_never_a_negative_rate(seq: list[tuple[int, int, int]], source: Source) -> None:
    point = STA if source is Source.HOSTAPD else ETH
    book = BaselineBook()
    rates = []
    for mono, rx, tx in seq:
        rates += process_samples(
            book,
            [sample(float(mono), rx, tx, point=point, source=source)],
            now_mono=float(mono),
        )
    for rate in rates:
        for value in (
            rate.rx_bps,
            rate.tx_bps,
            rate.rx_delta,
            rate.tx_delta,
            rate.rx_packets_delta,
        ):
            assert value is None or value >= 0
        if not rate_is_valid(rate):
            assert rate.rx_bps is None and rate.tx_bps is None


# --- area 2: counter reset -------------------------------------------------------------


def test_netdev_decrease_is_counter_reset() -> None:
    prev = sample(0.0, 5_000, 5_000)
    cur = sample(10.0, 100, 6_000)  # RX went down, uptime grew: no restart
    result = step(prev, cur)
    assert_no_rate(result.rate, Quality.COUNTER_RESET)
    # new baseline from the current read; the next delta works again
    nxt = delta(result.baseline, sample(20.0, 1_100, 7_000))
    assert nxt.rate.quality is Quality.OK
    assert nxt.rate.rx_delta == 1_000


def test_reset_in_one_direction_drops_the_whole_rate() -> None:
    result = step(sample(0.0, 5_000, 5_000), sample(10.0, 6_000, 10))
    assert_no_rate(result.rate, Quality.COUNTER_RESET)


# --- area 3: overflow (wrap_32) --------------------------------------------------------


def test_netdev_never_wraps() -> None:
    prev = sample(0.0, 2**32 - 100, 0)
    cur = sample(10.0, 50, 10)
    assert_no_rate(step(prev, cur).rate, Quality.COUNTER_RESET)


@pytest.mark.parametrize("source", [Source.HOSTAPD, Source.IWINFO])
def test_station_counter_wraps_at_32_bit(source: Source) -> None:
    prev = sample(
        0.0, 2**32 - 1_000, 100, point=STA, source=source, rx_packets=2**32 - 1
    )
    cur = sample(10.0, 1_000, 200, point=STA, source=source, rx_packets=4)
    rate = step(prev, cur).rate
    assert rate.quality is Quality.WRAP_32
    assert rate_is_valid(rate)
    assert rate.rx_delta == 2_000
    assert rate.tx_delta == 100
    assert rate.rx_packets_delta == 5  # secondary counters wrap with it
    assert rate.rx_bps == 1_600.0


def test_wrap_needs_a_plausible_candidate() -> None:
    # candidate 2**32 - 1e9 > 2**31: a reconnect, not a wrap
    prev = sample(0.0, 3_000_000_000, 0, point=STA, source=Source.HOSTAPD)
    cur = sample(10.0, 2_000_000_000, 0, point=STA, source=Source.HOSTAPD)
    assert_no_rate(step(prev, cur).rate, Quality.COUNTER_RESET)


def test_wrap_over_the_rate_limit_is_a_reset() -> None:
    # 1 Mbit/s link: limit 131 250 B/s; the wrap candidate is 200 000 B/s
    prev = sample(0.0, 2**32 - 1_000_000, 0, point=STA, source=Source.HOSTAPD, link=1)
    cur = sample(10.0, 1_000_000, 0, point=STA, source=Source.HOSTAPD, link=1)
    assert_no_rate(step(prev, cur).rate, Quality.COUNTER_RESET)


def test_no_wrap_for_a_64_bit_previous_value() -> None:
    prev = sample(0.0, COUNTER_32_RANGE + 5, 0, point=STA, source=Source.HOSTAPD)
    cur = sample(10.0, 10, 0, point=STA, source=Source.HOSTAPD)
    assert_no_rate(step(prev, cur).rate, Quality.COUNTER_RESET)


# --- area 4: router restart ----------------------------------------------------------------


def test_router_restart_by_smaller_uptime() -> None:
    prev = sample(0.0, 9_000, 9_000, uptime=5_000)
    cur = sample(60.0, 10_000, 10_000, uptime=4_000)
    result = step(prev, cur)
    assert_no_rate(result.rate, Quality.ROUTER_RESTART)
    assert result.baseline.router_uptime_s == 4_000


def test_router_restart_by_uptime_smaller_than_interval() -> None:
    prev = sample(0.0, 9_000, 9_000, uptime=None)
    cur = sample(60.0, 10, 10, uptime=30)
    assert_no_rate(step(prev, cur).rate, Quality.ROUTER_RESTART)


def test_router_restart_from_caller_wins_over_counters() -> None:
    result = step(sample(0.0, 1, 1), sample(10.0, 2, 2), router_restart=True)
    assert_no_rate(result.rate, Quality.ROUTER_RESTART)


def test_uptime_zero_means_unknown_not_restart() -> None:
    prev = sample(0.0, 100, 100, uptime=5_000)
    cur = sample(10.0, 200, 200, uptime=0)
    rate = step(prev, cur).rate
    assert rate.quality is Quality.OK
    assert not router_restarted(5_000, 0, 10.0)
    assert not router_restarted(None, None, 10.0)
    assert router_restarted(5_000, 4_000, 10.0)
    assert router_restarted(None, 5, 10.0)


@pytest.mark.parametrize("value", [0, -1, True, False, 1.5, "100", None])
def test_known_uptime_rejects_non_uptimes(value: Any) -> None:
    assert known_uptime(value) is None


def test_known_uptime_accepts_positive_int() -> None:
    assert known_uptime(1) == 1


# --- area 5: interface restart -------------------------------------------------------------


def test_interface_restart_resets_only_that_point() -> None:
    book = BaselineBook()
    lan = MeasurementPoint(RID, Scope.INTERFACE, device="lan1")
    process_samples(
        book,
        [sample(0.0, 5_000, 5_000), sample(0.0, 800, 800, point=lan)],
        now_mono=0.0,
    )
    # eth0 went down/up (counters back near 0), lan1 kept counting
    rates = process_samples(
        book,
        [sample(10.0, 3, 4, uptime=10_010), sample(10.0, 900, 900, point=lan)],
        now_mono=10.0,
    )
    by_device = {r.point.device: r for r in rates}
    assert by_device["eth0"].quality is Quality.COUNTER_RESET
    assert by_device["lan1"].quality is Quality.OK
    rates = process_samples(book, [sample(20.0, 13, 14, uptime=10_020)], now_mono=20.0)
    assert rates[0].quality is Quality.OK and rates[0].rx_delta == 10


def test_interface_back_after_long_absence_is_a_gap() -> None:
    result = step(sample(0.0, 100, 100), sample(MAX_INTERVAL_S + 60.0, 200, 200))
    assert_no_rate(result.rate, Quality.GAP)


# --- area 6: measurement gaps --------------------------------------------------------------


def test_interval_over_900_s_is_a_gap() -> None:
    result = step(sample(0.0, 1, 1), sample(MAX_INTERVAL_S + 0.5, 2, 2))
    assert_no_rate(result.rate, Quality.GAP)
    assert result.baseline.mono_s == MAX_INTERVAL_S + 0.5


def test_interval_of_exactly_900_s_counts() -> None:
    rate = step(sample(0.0, 1, 1), sample(float(MAX_INTERVAL_S), 2, 2)).rate
    assert rate.quality is Quality.OK


def test_stale_poll_is_a_gap() -> None:
    result = step(sample(0.0, 1, 1), sample(30.0, 2, 2), stale=True)
    assert_no_rate(result.rate, Quality.GAP)


def test_interval_under_5_s_is_skipped_and_keeps_the_baseline() -> None:
    base = first(sample(0.0, 100, 100))
    result = delta(base, sample(MIN_INTERVAL_S - 0.1, 200, 200))
    assert result.skipped
    assert result.rate is None
    assert result.baseline is base
    # the next sample is measured against the original baseline
    rate = delta(result.baseline, sample(10.0, 1_100, 1_100)).rate
    assert rate.interval_s == 10.0
    assert rate.rx_delta == 1_000


def test_interval_of_exactly_5_s_counts() -> None:
    rate = step(sample(0.0, 1, 1), sample(float(MIN_INTERVAL_S), 2, 2)).rate
    assert rate.quality is Quality.OK


def test_skipped_sample_yields_nothing_in_process_samples() -> None:
    book = BaselineBook()
    process_samples(book, [sample(0.0, 1, 1)], now_mono=0.0)
    assert process_samples(book, [sample(2.0, 2, 2)], now_mono=2.0) == []
    assert book.get(ETH.point_id).mono_s == 0.0


# --- area 7: wrong or missing timestamps --------------------------------------------------


@pytest.mark.parametrize("mono", [None, math.nan, math.inf, -math.inf, True, "10"])
def test_unusable_time_keeps_the_previous_baseline(mono: Any) -> None:
    base = first(sample(0.0, 1, 1))
    result = delta(base, sample(mono, 2, 2, wall=1_800_000_010.0))
    assert_no_rate(result.rate, Quality.TIME_NOT_ADVANCING)
    assert result.baseline is base


@pytest.mark.parametrize("mono", [0.0, -5.0])
def test_time_not_advancing(mono: float) -> None:
    base = first(sample(0.0, 1, 1))
    result = delta(base, sample(mono, 2, 2))
    assert_no_rate(result.rate, Quality.TIME_NOT_ADVANCING)
    assert result.baseline is base


def test_baseline_without_mono_time_is_a_gap() -> None:
    base = Baseline(ETH.point_id, Source.NETDEV, None, None, 10, (1,) * 8)
    result = delta(base, sample(10.0, 2, 2))
    assert_no_rate(result.rate, Quality.GAP)


def test_first_sample_without_time_holds_no_baseline() -> None:
    result = delta(None, sample(None, 1, 1))
    assert_no_rate(result.rate, Quality.TIME_NOT_ADVANCING)
    assert result.baseline is None


@pytest.mark.parametrize("value", [None, math.nan, math.inf, True, "1"])
def test_finite_time_rejects(value: Any) -> None:
    assert finite_time(value) is None


# --- area 8a: counter validity (bool is not a counter) --------------------------------------


@pytest.mark.parametrize("value", [True, False, -1, 1.0, "5", None, [1]])
def test_as_counter_rejects(value: Any) -> None:
    assert as_counter(value) is None


def test_as_counter_accepts_zero_and_big_values() -> None:
    assert as_counter(0) == 0
    assert as_counter(2**63) == 2**63


def test_bool_counters_are_source_missing() -> None:
    base = first(sample(0.0, 1, 1))
    result = delta(base, sample(10.0, True, False))
    assert_no_rate(result.rate, Quality.SOURCE_MISSING)
    assert result.baseline is base


def test_missing_counters_are_source_missing_not_zero() -> None:
    result = delta(None, sample(0.0, None, None))
    assert_no_rate(result.rate, Quality.SOURCE_MISSING)
    assert result.baseline is None


# --- rule 6: plausibility -----------------------------------------------------------------


def test_over_link_speed_is_implausible() -> None:
    # 1000 Mbit/s full: 131 250 000 B/s per direction
    prev = sample(0.0, 0, 0, link=1000, duplex="full")
    cur = sample(10.0, 1_400_000_000, 0, link=1000, duplex="full")
    assert_no_rate(step(prev, cur).rate, Quality.IMPLAUSIBLE)


def test_half_duplex_adds_both_directions() -> None:
    # 100 Mbit/s: 13 125 000 B/s; each direction 8 MB/s alone is fine
    rx = tx = 80_000_000
    full = step(
        sample(0.0, 0, 0, link=100, duplex="full"),
        sample(10.0, rx, tx, link=100, duplex="full"),
    ).rate
    assert full.quality is Quality.OK
    half = step(
        sample(0.0, 0, 0, link=100, duplex="half"),
        sample(10.0, rx, tx, link=100, duplex="half"),
    ).rate
    assert_no_rate(half, Quality.IMPLAUSIBLE)


def test_default_limits_without_link_speed() -> None:
    assert plausibility_limit(sample(0.0, 0, 0)) == (
        float(DEFAULT_LIMIT_WIRED_BPS),
        False,
    )
    sta = sample(0.0, 0, 0, point=STA, source=Source.HOSTAPD)
    assert plausibility_limit(sta) == (float(DEFAULT_LIMIT_STATION_BPS), False)
    assert plausibility_limit(sample(0.0, 0, 0, link=1000))[0] == pytest.approx(
        131_250_000.0
    )


# --- rule 7: another point or source --------------------------------------------------------


def test_another_source_starts_a_new_baseline() -> None:
    base = first(sample(0.0, 1, 1))
    result = delta(base, sample(10.0, 2, 2, source=Source.SYSFS))
    assert_no_rate(result.rate, Quality.FIRST_SAMPLE)
    assert result.baseline.source is Source.SYSFS


def test_another_point_starts_a_new_baseline() -> None:
    base = first(sample(0.0, 1, 1))
    other = MeasurementPoint(RID2, Scope.INTERFACE, device="eth0")
    assert other.point_id != ETH.point_id
    result = delta(base, sample(10.0, 2, 2, point=other))
    assert_no_rate(result.rate, Quality.FIRST_SAMPLE)


# --- rule 8: HA restart (restored baseline) ---------------------------------------------------


def _restored(prev: Sample) -> Baseline:
    stored = first(prev).to_dict()
    assert "mono_s" not in stored  # monotonic time is never stored
    restored = Baseline.from_dict(stored)
    assert restored is not None and restored.restored and restored.mono_s is None
    return restored


def test_restored_baseline_with_matching_clocks_counts() -> None:
    prev = sample(1_000.0, 100, 100, uptime=5_000, wall=1_800_000_000.0)
    # new HA run: a monotonic clock unrelated to the old one
    cur = sample(3.0, 60_100, 30_100, uptime=5_060, wall=1_800_000_060.0)
    rate = delta(_restored(prev), cur).rate
    assert rate.quality is Quality.OK
    assert rate.interval_s == 60.0
    assert rate.rx_delta == 60_000


def test_restored_baseline_with_uptime_mismatch_is_a_gap() -> None:
    prev = sample(1_000.0, 100, 100, uptime=5_000, wall=1_800_000_000.0)
    cur = sample(3.0, 200, 200, uptime=5_100, wall=1_800_000_060.0)  # 40 s off
    assert_no_rate(delta(_restored(prev), cur).rate, Quality.GAP)


def test_restored_baseline_older_than_900_s_is_a_gap() -> None:
    prev = sample(1_000.0, 100, 100, uptime=5_000, wall=1_800_000_000.0)
    cur = sample(3.0, 200, 200, uptime=6_000, wall=1_800_001_000.0)
    assert_no_rate(delta(_restored(prev), cur).rate, Quality.GAP)


@pytest.mark.parametrize(
    ("cur_uptime", "cur_wall"),
    [(0, 1_800_000_060.0), (5_060, None), (5_060, 1_800_000_000.0)],
)
def test_restored_baseline_needs_both_clocks(cur_uptime: int, cur_wall: Any) -> None:
    prev = sample(1_000.0, 100, 100, uptime=5_000, wall=1_800_000_000.0)
    cur = Sample(
        ETH, 3.0, cur_wall, rx_bytes=200, tx_bytes=200, router_uptime_s=cur_uptime
    )
    restored = _restored(prev)
    assert restored_interval(restored, cur) is None
    assert_no_rate(delta(restored, cur).rate, Quality.GAP)


def test_restored_baseline_after_router_restart() -> None:
    prev = sample(1_000.0, 100, 100, uptime=5_000, wall=1_800_000_000.0)
    cur = sample(3.0, 10, 10, uptime=20, wall=1_800_000_030.0)
    # uptime went back: the clocks disagree, so rule 8 already gives a gap
    assert_no_rate(delta(_restored(prev), cur).rate, Quality.GAP)


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        {"point_id": "x", "source": "netdev", "counters": [0] * 8},
        {"point_id": ETH.point_id, "source": "nope", "counters": [0] * 8},
        {"point_id": ETH.point_id, "source": "netdev", "counters": [0] * 7},
        {"point_id": ETH.point_id, "source": "netdev", "counters": "0"},
    ],
)
def test_broken_stored_baseline_is_ignored(raw: Any) -> None:
    assert Baseline.from_dict(raw) is None


def test_restored_counters_are_validated() -> None:
    raw = {
        "point_id": ETH.point_id,
        "source": "netdev",
        "wall_s": "yesterday",
        "router_uptime_s": True,
        "counters": [True, -1, 3, None, 0, 0, 0, 0],
    }
    base = Baseline.from_dict(raw)
    assert base is not None
    assert base.counters[:4] == (None, None, 3, None)
    assert base.wall_s is None and base.router_uptime_s is None


# --- bounded baseline book (separate quotas) -------------------------------------------------


def _dev(rid: str, name: str) -> MeasurementPoint:
    return MeasurementPoint(rid, Scope.INTERFACE, device=name)


def _sta(ref: str) -> MeasurementPoint:
    return MeasurementPoint(RID, Scope.STATION, radio_id="phy0-ap0", client_ref=ref)


def test_infra_quota_per_router_is_counted_and_separate() -> None:
    book = BaselineBook(infra_per_router=2, infra_total=10, client_max=5)
    for name in ("eth0", "eth1", "eth2"):
        process_samples(book, [sample(0.0, 1, 1, point=_dev(RID, name))], now_mono=0.0)
    assert book.infra_count == 2
    assert book.counters["dropped_points_infra"] == 1
    # another router has its own quota
    process_samples(book, [sample(0.0, 1, 1, point=_dev(RID2, "eth0"))], now_mono=0.0)
    assert book.infra_count == 3
    # a known point is always admitted
    assert book.admit(_dev(RID, "eth0"), 1.0)


def test_infra_total_quota() -> None:
    book = BaselineBook(infra_per_router=5, infra_total=2, client_max=5)
    process_samples(
        book,
        [
            sample(0.0, 1, 1, point=_dev(RID, "eth0")),
            sample(0.0, 1, 1, point=_dev(RID2, "eth0")),
            sample(0.0, 1, 1, point=_dev(RID2, "eth1")),
        ],
        now_mono=0.0,
    )
    assert book.infra_count == 2
    assert book.counters["dropped_points_infra"] == 1


def test_client_quota_never_displaces_an_active_point() -> None:
    book = BaselineBook(client_max=2, client_idle_s=100.0)
    refs = ["cli_" + c * 16 for c in "abc"]
    for ref in refs:
        process_samples(
            book,
            [sample(0.0, 1, 1, point=_sta(ref), source=Source.HOSTAPD)],
            now_mono=0.0,
        )
    assert book.client_count == 2
    assert book.counters["dropped_points_client"] == 1
    assert not book.has(_sta(refs[2]).point_id)


def test_client_quota_replaces_an_idle_point() -> None:
    book = BaselineBook(client_max=2, client_idle_s=100.0)
    a, b, c = (_sta("cli_" + ch * 16) for ch in "abc")
    process_samples(
        book, [sample(0.0, 1, 1, point=a, source=Source.HOSTAPD)], now_mono=0.0
    )
    process_samples(
        book, [sample(150.0, 1, 1, point=b, source=Source.HOSTAPD)], now_mono=150.0
    )
    process_samples(
        book, [sample(200.0, 1, 1, point=c, source=Source.HOSTAPD)], now_mono=200.0
    )
    assert book.counters["replaced_points_client"] == 1
    assert not book.has(a.point_id)
    assert book.has(b.point_id) and book.has(c.point_id)


def test_client_and_infra_quotas_do_not_touch_each_other() -> None:
    book = BaselineBook(infra_per_router=1, infra_total=1, client_max=1)
    process_samples(
        book,
        [
            sample(0.0, 1, 1, point=_dev(RID, "eth0")),
            sample(0.0, 1, 1, point=_sta(CREF), source=Source.HOSTAPD),
            sample(0.0, 1, 1, point=_dev(RID, "eth1")),
            sample(0.0, 1, 1, point=_sta(CREF2), source=Source.HOSTAPD),
        ],
        now_mono=0.0,
    )
    assert (book.infra_count, book.client_count) == (1, 1)
    assert book.counters["dropped_points_infra"] == 1
    assert book.counters["dropped_points_client"] == 1


def test_prune_drop_router_and_clear() -> None:
    book = BaselineBook()
    process_samples(
        book,
        [sample(0.0, 1, 1), sample(0.0, 1, 1, point=_dev(RID2, "eth1"))],
        now_mono=0.0,
    )
    process_samples(book, [sample(10.0, 2, 2)], now_mono=90_000.0)
    assert book.prune(90_000.0) == 1  # RID2/eth1 not seen for 25 h
    assert book.counters["pruned_points"] == 1
    assert book.drop_router(RID) == 1
    assert len(book) == 0
    process_samples(book, [sample(0.0, 1, 1)], now_mono=0.0)
    book.clear()
    assert len(book) == 0
    assert book.counters["pruned_points"] == 1  # counters survive a clear


def test_refused_point_yields_no_rate() -> None:
    book = BaselineBook(infra_per_router=1)
    process_samples(book, [sample(0.0, 1, 1)], now_mono=0.0)
    other = _dev(RID, "eth9")
    process_samples(book, [sample(0.0, 1, 1, point=other)], now_mono=0.0)
    assert process_samples(book, [sample(10.0, 2, 2, point=other)], now_mono=10.0) == []
