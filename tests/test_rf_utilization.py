"""Tests for channel utilization (rf_utilization.py, pure, no HA)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from custom_components.openwrt_router.rf_models import (
    SOURCE_HOSTAPD_STATUS,
    SOURCE_IWINFO_SURVEY,
    CapabilityState,
)
from custom_components.openwrt_router.rf_utilization import (
    DEFAULT_MAX_GAP_S,
    DEFAULT_MIN_ACTIVE_MS,
    SurveySample,
    UnknownReason,
    UtilizationThresholds,
    summarize,
    utilization_from_bss_load,
    utilization_from_delta,
)

R = UnknownReason


def _sample(**overrides):
    base = {
        "radio_key": "radio0",
        "mhz": 2437,
        "taken_at": 1000.0,
        "uptime_s": 5000,
        "active_ms": 1_000_000,
        "busy_ms": 300_000,
        "rx_ms": 100_000,
        "tx_ms": 50_000,
        "noise": -95,
    }
    base.update(overrides)
    return SurveySample(**base)


PREV = _sample()


def _next(**overrides):
    """A sample 60 s later with 60 000 ms active time and the given deltas."""
    base = {
        "taken_at": 1060.0,
        "uptime_s": 5060,
        "active_ms": 1_060_000,
        "busy_ms": 300_000 + 30_000,  # 50 %
        "rx_ms": 100_000 + 12_000,  # 20 %
        "tx_ms": 50_000 + 6_000,  # 10 %
    }
    base.update(overrides)
    return _sample(**base)


def _delta(cur, prev=PREV, **kwargs):
    return utilization_from_delta(prev, cur, **kwargs)


# =====================================================================
# (A) survey counter deltas
# =====================================================================


class TestUtilizationFromDelta:
    def test_case_03_channel_utilization_from_counter_deltas(self):
        result = _delta(_next())
        assert result.known
        assert result.reason is None
        assert result.busy_pct == pytest.approx(50.0)
        assert result.rx_pct == pytest.approx(20.0)
        assert result.tx_pct == pytest.approx(10.0)
        assert result.other_busy_pct == pytest.approx(20.0)
        assert result.interval_s == pytest.approx(60.0)
        assert result.source == SOURCE_IWINFO_SURVEY
        assert result.measured_at == 1060.0
        metric = result.busy_metric()
        assert metric.state is CapabilityState.MEASURED
        assert metric.value == pytest.approx(50.0)
        assert metric.source == SOURCE_IWINFO_SURVEY

    def test_case_04_counter_reset_is_unknown(self):
        cur = _next(busy_ms=10, rx_ms=5, tx_ms=1, active_ms=2_000)
        result = _delta(cur)
        assert not result.known
        assert result.reason is R.COUNTER_RESET
        assert result.busy_pct is None
        assert result.rx_pct is None

    def test_case_04_any_single_decreasing_counter_is_a_reset(self):
        result = _delta(_next(tx_ms=49_000))
        assert result.reason is R.COUNTER_RESET
        assert result.busy_pct is None

    def test_case_04_wrap_is_not_reconstructed(self):
        # Close to 2**32 before, small after: could be a 32-bit wrap, could be
        # a reset. Not provable, so unknown instead of a recomputed value.
        prev = _sample(active_ms=2**32 - 1000, busy_ms=2**32 - 2000)
        cur = _sample(
            taken_at=1060.0,
            uptime_s=5060,
            active_ms=59_000,
            busy_ms=10_000,
        )
        result = _delta(cur, prev)
        assert result.reason is R.COUNTER_RESET
        assert result.busy_pct is None

    def test_case_05_channel_change_is_unknown(self):
        result = _delta(_next(mhz=2462))
        assert result.reason is R.CHANNEL_CHANGED
        assert result.busy_pct is None

    def test_case_23_router_restart_uptime_went_back(self):
        cur = _next(uptime_s=40, active_ms=40_000, busy_ms=4_000, rx_ms=1, tx_ms=1)
        result = _delta(cur)
        assert result.reason is R.ROUTER_RESTART
        assert result.busy_pct is None

    def test_case_23_router_restart_uptime_does_not_match_elapsed_time(self):
        # 600 s passed, uptime only grew by 100 s: a reboot in between, even
        # though uptime is larger than before.
        prev = _sample(uptime_s=50)
        cur = _sample(
            taken_at=1600.0,
            uptime_s=150,
            active_ms=1_100_000,
            busy_ms=310_000,
            rx_ms=101_000,
            tx_ms=51_000,
        )
        result = _delta(cur, prev, max_gap_s=3600)
        assert result.reason is R.UPTIME_MISMATCH
        assert result.busy_pct is None

    def test_case_24_radio_restart_counters_reset_with_same_uptime(self):
        # Router kept running (uptime fits), the radio restarted: counters
        # start again from zero.
        cur = _next(active_ms=20_000, busy_ms=5_000, rx_ms=2_000, tx_ms=1_000)
        result = _delta(cur)
        assert result.reason is R.COUNTER_RESET
        assert result.busy_pct is None

    def test_no_previous_sample(self):
        result = utilization_from_delta(None, _next())
        assert result.reason is R.NO_PREVIOUS
        assert result.busy_pct is None
        assert result.measured_at == 1060.0

    def test_gap_too_large(self):
        cur = _next(taken_at=1000.0 + DEFAULT_MAX_GAP_S + 1)
        result = _delta(cur)
        assert result.reason is R.GAP_TOO_LARGE

    def test_gap_limit_is_a_parameter(self):
        assert _delta(_next(), max_gap_s=30).reason is R.GAP_TOO_LARGE

    def test_time_not_advancing(self):
        assert _delta(_next(taken_at=1000.0)).reason is R.TIME_NOT_ADVANCING
        assert _delta(_next(taken_at=990.0)).reason is R.TIME_NOT_ADVANCING

    def test_active_delta_zero(self):
        cur = _next(active_ms=PREV.active_ms, busy_ms=PREV.busy_ms)
        assert _delta(cur).reason is R.ACTIVE_TOO_SMALL

    def test_active_delta_below_minimum(self):
        cur = _next(
            active_ms=PREV.active_ms + DEFAULT_MIN_ACTIVE_MS - 1,
            busy_ms=PREV.busy_ms,
            rx_ms=PREV.rx_ms,
            tx_ms=PREV.tx_ms,
        )
        assert _delta(cur).reason is R.ACTIVE_TOO_SMALL
        assert _delta(cur, min_active_ms=10).known

    def test_busy_larger_than_active_is_implausible_not_capped(self):
        cur = _next(busy_ms=PREV.busy_ms + 61_000)
        result = _delta(cur)
        assert result.reason is R.IMPLAUSIBLE
        assert result.busy_pct is None  # not 100

    def test_rx_larger_than_active_is_implausible(self):
        result = _delta(_next(rx_ms=PREV.rx_ms + 60_001))
        assert result.reason is R.IMPLAUSIBLE
        assert result.busy_pct is None

    def test_radio_mismatch(self):
        result = _delta(_next(radio_key="radio1"))
        assert result.reason is R.RADIO_MISMATCH

    def test_case_25_missing_active_makes_everything_unknown(self):
        result = _delta(_next(active_ms=None))
        assert result.reason is R.MISSING_FIELD
        assert result.busy_pct is None
        assert result.rx_pct is None

    def test_case_25_missing_field_only_affects_its_share(self):
        result = _delta(_next(tx_ms=None))
        assert result.known
        assert result.busy_pct == pytest.approx(50.0)
        assert result.rx_pct == pytest.approx(20.0)
        assert result.tx_pct is None
        assert result.other_busy_pct is None  # needs all three
        assert result.part_reasons == {
            "tx": R.MISSING_FIELD,
            "other_busy": R.MISSING_FIELD,
        }

    def test_case_25_field_missing_in_previous_sample_only(self):
        prev = replace(PREV, rx_ms=None)
        result = _delta(_next(), prev)
        assert result.rx_pct is None
        assert result.part_reasons["rx"] is R.MISSING_FIELD
        assert result.busy_pct == pytest.approx(50.0)

    def test_case_25_missing_busy_keeps_rx_tx(self):
        result = _delta(_next(busy_ms=None))
        assert result.busy_pct is None
        assert result.rx_pct == pytest.approx(20.0)
        assert not result.known  # "known" means busy is known
        assert result.busy_metric().state is CapabilityState.NO_DATA

    def test_other_busy_negative_is_unknown_not_zero(self):
        # rx + tx > busy: inconsistent counters; other_busy is unknown.
        cur = _next(busy_ms=PREV.busy_ms + 10_000)
        result = _delta(cur)
        assert result.busy_pct == pytest.approx(100 * 10_000 / 60_000)
        assert result.other_busy_pct is None
        assert result.part_reasons["other_busy"] is R.IMPLAUSIBLE

    def test_uptime_unknown_skips_restart_check_but_notes_it(self):
        result = _delta(_next(uptime_s=None))
        assert result.known
        assert "uptime_unavailable" in result.notes

    def test_unknown_result_metric_is_never_zero(self):
        result = utilization_from_delta(None, _next())
        metric = result.busy_metric()
        assert metric.value is None
        assert metric.state is CapabilityState.NO_DATA

    def test_as_dict(self):
        data = _delta(_next(tx_ms=None)).as_dict()
        assert data["source"] == "iwinfo.survey"
        assert data["busy_pct"] == pytest.approx(50.0)
        assert data["tx_pct"] is None
        assert data["reason"] is None
        assert data["part_reasons"] == {
            "tx": "missing_field",
            "other_busy": "missing_field",
        }

    def test_every_unknown_reason_is_covered(self):
        # Guard: a new reason must get a test above.
        assert {r.value for r in R} == {
            "no_previous",
            "radio_mismatch",
            "time_not_advancing",
            "gap_too_large",
            "router_restart",
            "uptime_mismatch",
            "channel_changed",
            "counter_reset",
            "missing_field",
            "active_too_small",
            "implausible",
        }


# =====================================================================
# (B) hostapd BSS load
# =====================================================================


class TestBssLoad:
    def test_scaled_to_percent_with_source(self):
        metric = utilization_from_bss_load(128, measured_at=5.0)
        assert metric.state is CapabilityState.MEASURED
        assert metric.value == pytest.approx(128 * 100 / 255)
        assert metric.source == SOURCE_HOSTAPD_STATUS
        assert metric.measured_at == 5.0

    @pytest.mark.parametrize("raw", [0, 255])
    def test_bounds_are_valid(self, raw):
        assert utilization_from_bss_load(raw).state is CapabilityState.MEASURED

    @pytest.mark.parametrize("raw", [None, -1, 256, "128", True, 12.5])
    def test_case_25_invalid_raw_is_unknown(self, raw):
        metric = utilization_from_bss_load(raw)
        assert metric.state is CapabilityState.NO_DATA
        assert metric.value is None
        assert metric.source == SOURCE_HOSTAPD_STATUS

    def test_zero_without_channel_time_is_unknown_not_zero(self):
        # bss_load_update_period 0: hostapd never computes a load and reports
        # utilization 0 with airtime.time 0.
        metric = utilization_from_bss_load(0, channel_time=0)
        assert metric.state is CapabilityState.NO_DATA
        assert metric.value is None

    def test_channel_time_present_keeps_value(self):
        metric = utilization_from_bss_load(0, channel_time=6100)
        assert metric.state is CapabilityState.MEASURED
        assert metric.value == 0.0


# =====================================================================
# Window summary
# =====================================================================


TH = UtilizationThresholds()


class TestSummarize:
    def test_basic_figures(self):
        samples = [(100.0, 10.0), (160.0, 30.0), (220.0, 20.0)]
        s = summarize(samples, now=220.0, window_s=300, thresholds=TH)
        assert s.current == 20.0
        assert s.mean == pytest.approx(20.0)
        assert s.peak == 30.0
        assert s.valid_count == 3
        assert s.invalid_count == 0
        assert s.coverage == 1.0
        assert s.phases == ()

    def test_unknown_never_becomes_zero_and_lowers_coverage(self):
        samples = [(100.0, 80.0), (160.0, None), (220.0, 80.0), (280.0, None)]
        s = summarize(samples, now=280.0, window_s=300, thresholds=TH)
        assert s.mean == pytest.approx(80.0)  # not 40 (None is no 0 %)
        assert s.current is None  # newest point unknown → no current value
        assert s.valid_count == 2
        assert s.invalid_count == 2
        assert s.coverage == pytest.approx(0.5)

    def test_points_outside_window_are_ignored(self):
        samples = [(0.0, 99.0), (250.0, 10.0)]
        s = summarize(samples, now=300.0, window_s=100, thresholds=TH)
        assert s.valid_count == 1
        assert s.peak == 10.0

    def test_out_of_range_values_are_invalid(self):
        samples = [(10.0, -1.0), (20.0, 101.0), (30.0, float("nan")), (40.0, 5.0)]
        s = summarize(samples, now=40.0, window_s=100, thresholds=TH)
        assert s.valid_count == 1
        assert s.invalid_count == 3

    def test_empty_window(self):
        s = summarize([], now=40.0, window_s=100, thresholds=TH)
        assert s.current is None
        assert s.mean is None
        assert s.peak is None
        assert s.coverage is None
        assert s.sustained_overload is None

    def test_phases_split_by_unknown_and_low_points(self):
        samples = [
            (10.0, 75.0),
            (20.0, 90.0),
            (30.0, None),  # breaks the phase
            (40.0, 80.0),
            (50.0, 20.0),  # below → breaks
            (60.0, 71.0),
        ]
        s = summarize(samples, now=60.0, window_s=100, thresholds=TH)
        assert [(p.start, p.end, p.peak, p.points) for p in s.phases] == [
            (10.0, 20.0, 90.0, 2),
            (40.0, 40.0, 80.0, 1),
            (60.0, 60.0, 71.0, 1),
        ]

    def test_unsorted_input_is_sorted(self):
        samples = [(30.0, 3.0), (10.0, 1.0), (20.0, 2.0)]
        s = summarize(samples, now=30.0, window_s=100, thresholds=TH)
        assert s.current == 3.0

    def test_case_06_high_channel_utilization_sustained_overload(self):
        samples = [(float(t), 85.0) for t in range(0, 600, 60)]
        samples[3] = (180.0, 50.0)  # one dip, 9 of 10 over the threshold
        s = summarize(samples, now=540.0, window_s=600, thresholds=TH)
        assert s.sustained_overload is True
        assert s.peak == 85.0

    def test_case_06_not_sustained_when_share_too_low(self):
        samples = [(float(t), 85.0 if t < 240 else 20.0) for t in range(0, 600, 60)]
        s = summarize(samples, now=540.0, window_s=600, thresholds=TH)
        assert s.sustained_overload is False

    def test_case_06_too_little_coverage_is_none_not_false(self):
        samples = [
            (float(t), 85.0 if t % 120 == 0 else None) for t in range(0, 600, 60)
        ]
        s = summarize(samples, now=540.0, window_s=600, thresholds=TH)
        assert s.coverage == pytest.approx(0.5)
        assert s.sustained_overload is None

    def test_case_06_too_few_points_is_none(self):
        s = summarize([(10.0, 95.0)], now=10.0, window_s=600, thresholds=TH)
        assert s.coverage == 1.0
        assert s.sustained_overload is None

    def test_thresholds_are_overridable(self):
        samples = [(float(t), 50.0) for t in range(0, 300, 60)]
        low = UtilizationThresholds(warn_pct=40.0)
        s = summarize(samples, now=240.0, window_s=300, thresholds=low)
        assert s.sustained_overload is True
        assert len(s.phases) == 1

    def test_as_dict(self):
        s = summarize([(10.0, 80.0)], now=10.0, window_s=60, thresholds=TH)
        data = s.as_dict()
        assert data["phases"] == [
            {"start": 10.0, "end": 10.0, "peak": 80.0, "points": 1}
        ]
        assert data["sustained_overload"] is None
