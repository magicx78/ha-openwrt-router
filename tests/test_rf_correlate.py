"""Tests for multi-AP load correlation (rf_correlate.py, pure)."""

from __future__ import annotations

import math

from custom_components.openwrt_router.rf_conflicts import RadioRef, Severity
from custom_components.openwrt_router.rf_correlate import (
    CorrelateThresholds,
    CorrelationKind,
    correlate_radios,
)
from custom_components.openwrt_router.rf_spectrum import block_for

TH = CorrelateThresholds()
STEP = TH.bucket_s
A = RadioRef("ap1", "radio0")
B = RadioRef("ap2", "radio0")
K = CorrelationKind


def _series(highs, n=24, high=85.0, low=20.0):
    """n points one bucket apart; indexes in ``highs`` are high load."""
    return [(i * STEP, high if i in highs else low) for i in range(n)]


def _blocks(a=6, b=6, band_a="2.4g", band_b="2.4g", width=20):
    return {A: block_for(band_a, a, width), B: block_for(band_b, b, width)}


def _run(series_a, series_b, blocks=None, thresholds=TH):
    series = {A: series_a, B: series_b}
    return correlate_radios(series, blocks or _blocks(), thresholds)


class TestSharedLoad:
    def test_case_26_multi_ap_shared_channel_load(self):
        (f,) = _run(_series(range(10)), _series(range(10)))
        assert f.kind is K.SHARED_CHANNEL_LOAD
        assert f.severity is Severity.WARNING
        assert f.members == (A, B)
        assert f.common_points == 24
        assert (f.joint_high, f.union_high) == (10, 10)
        assert f.share == 1.0
        assert "overlap:co_channel:20MHz" in f.evidence
        assert "joint_high:10/10" in f.evidence

    def test_case_26_adjacent_overlap_counts_as_shared(self):
        (f,) = _run(_series(range(10)), _series(range(10)), _blocks(1, 3))
        assert f.kind is K.SHARED_CHANNEL_LOAD
        assert any(e.startswith("overlap:adjacent_overlap:") for e in f.evidence)

    def test_case_26_load_without_overlap_is_info_only(self):
        (f,) = _run(_series(range(10)), _series(range(10)), _blocks(1, 11))
        assert f.kind is K.SIMULTANEOUS_LOAD_NO_OVERLAP
        assert f.severity is Severity.INFO

    def test_case_26_different_bands_is_info_only(self):
        blocks = _blocks(6, 36, band_b="5g")
        (f,) = _run(_series(range(10)), _series(range(10)), blocks)
        assert f.kind is K.SIMULTANEOUS_LOAD_NO_OVERLAP

    def test_rule_findings_carry_evidence_not_cause(self):
        (f,) = _run(_series(range(10)), _series(range(10)))
        assert f.evidence
        assert not hasattr(f, "cause")
        assert "cause" not in f.as_dict()


class TestNoFinding:
    def test_alternating_high_phases(self):
        evens = range(0, 24, 2)
        odds = range(1, 24, 2)
        assert _run(_series(evens), _series(odds)) == []

    def test_joint_share_below_threshold(self):
        # joint 4 (8..11), union 12 (0..11) -> 0.33 < 0.5
        assert _run(_series(range(12)), _series(range(8, 12))) == []

    def test_too_few_joint_high_buckets(self):
        assert _run(_series(range(2)), _series(range(2))) == []

    def test_both_low(self):
        assert _run(_series(()), _series(())) == []

    def test_case_25_too_few_common_points(self):
        assert _run(_series(range(10), n=10), _series(range(10), n=10)) == []

    def test_case_25_unknown_values_do_not_count_as_common(self):
        b = [(ts, None if i >= 9 else v) for i, (ts, v) in enumerate(_series(range(9)))]
        assert _run(_series(range(9)), b) == []
        b_nan = [(ts, math.nan if i >= 9 else v) for i, (ts, v) in enumerate(b)]
        assert _run(_series(range(9)), b_nan) == []

    def test_case_25_missing_block(self):
        blocks = {A: block_for("2.4g", 6, 20)}
        assert _run(_series(range(10)), _series(range(10)), blocks) == []

    def test_case_25_single_or_no_radio(self):
        assert correlate_radios({A: _series(range(10))}, _blocks(), TH) == []
        assert correlate_radios({}, {}, TH) == []


class TestBucketsAndThresholds:
    def test_points_inside_a_bucket_are_averaged(self):
        def dense(highs):
            out = []
            for i in range(24):
                value = 85.0 if i in highs else 20.0
                out += [(i * STEP, value), (i * STEP + 60, value + 1)]
            return out

        (f,) = _run(dense(range(10)), dense(range(10)))
        assert f.common_points == 24

    def test_thresholds_can_be_overridden(self):
        th = CorrelateThresholds(min_common_points=5)
        (f,) = _run(_series(range(5), n=10), _series(range(5), n=10), thresholds=th)
        assert f.common_points == 10

    def test_three_radios_give_pairwise_findings(self):
        c = RadioRef("ap3", "radio0")
        series = {A: _series(range(10)), B: _series(range(10)), c: _series(range(10))}
        blocks = {**_blocks(), c: block_for("2.4g", 6, 20)}
        found = correlate_radios(series, blocks, TH)
        assert [f.members for f in found] == [(A, B), (A, c), (B, c)]
