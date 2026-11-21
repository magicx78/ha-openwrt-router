"""Tests for historical roll-up and windows (rf_aggregate.py, pure)."""

from __future__ import annotations

import math

import pytest

from custom_components.openwrt_router.rf_aggregate import (
    DAY_S,
    HOUR_S,
    MAX_POINTS,
    RAW_RESOLUTION_S,
    Agg,
    Retention,
    bucket_start,
    merge_buckets,
    prune,
    roll_up,
    series_for_window,
)

NOW = 1_800_000_000  # a fixed clock; the module never reads the time itself


def _agg(*values):
    agg = Agg()
    for value in values:
        agg = agg.add(value)
    return agg


class TestAgg:
    def test_add_is_functional(self):
        empty = Agg()
        one = empty.add(5.0)
        assert empty.count == 0
        assert one.count == 1
        assert one is not empty

    def test_stats(self):
        agg = _agg(10.0, 30.0, 20.0)
        assert agg.count == 3
        assert agg.total == 60.0
        assert agg.minimum == 10.0
        assert agg.maximum == 30.0
        assert agg.mean == 20.0

    def test_case_25_empty_mean_is_none(self):
        assert Agg().mean is None
        assert Agg().minimum is None

    @pytest.mark.parametrize("bad", [None, math.nan, math.inf, True, "x"])
    def test_case_25_unknown_values_go_to_invalid(self, bad):
        agg = _agg(10.0, bad)
        assert agg.count == 1
        assert agg.invalid == 1
        assert agg.mean == 10.0

    def test_only_invalid_has_no_mean(self):
        agg = _agg(None, None)
        assert agg.mean is None
        assert agg.invalid == 2

    def test_merge_equals_adding_all(self):
        merged = _agg(1.0, 2.0, None).merge(_agg(9.0, None))
        assert merged == _agg(1.0, 2.0, None, 9.0, None)

    def test_merge_with_empty(self):
        assert _agg(4.0).merge(Agg()) == _agg(4.0)
        assert Agg().merge(_agg(4.0)) == _agg(4.0)


class TestBuckets:
    def test_bucket_start(self):
        assert bucket_start(125, 60) == 120
        assert bucket_start(3599.9, HOUR_S) == 0
        assert bucket_start(DAY_S + 5, DAY_S) == DAY_S

    def test_bucket_size_must_be_positive(self):
        with pytest.raises(ValueError):
            bucket_start(10, 0)

    def test_case_22_historical_roll_up(self):
        points = [(0, 10.0), (30, 20.0), (60, 50.0), (3600, None), (3610, 70.0)]
        minutes = roll_up(points, 60)
        assert minutes[0].mean == 15.0
        assert minutes[60].mean == 50.0
        assert minutes[3600].invalid == 1
        assert minutes[3600].mean == 70.0
        hours = roll_up(points, HOUR_S)
        assert hours[0].count == 3
        assert hours[3600].count == 1

    def test_case_22_daily_mean_is_weighted_not_mean_of_means(self):
        hourly = {0: _agg(10.0, 10.0, 10.0), HOUR_S: _agg(50.0)}
        daily = merge_buckets(hourly)
        assert list(daily) == [0]
        assert daily[0].mean == 20.0  # not (10 + 50) / 2
        assert daily[0].maximum == 50.0

    def test_roll_up_keys_are_sorted(self):
        minutes = roll_up([(200, 1.0), (10, 2.0), (100, 3.0)], 60)
        assert list(minutes) == [0, 60, 180]


class TestRetention:
    def test_defaults_cover_the_windows(self):
        r = Retention()
        assert r.raw_s >= HOUR_S
        assert r.hourly_s >= 7 * DAY_S
        assert r.daily_s >= 30 * DAY_S

    def test_prune(self):
        buckets = {NOW - 7200: _agg(1.0), NOW - 3600: _agg(2.0), NOW: _agg(3.0)}
        kept = prune(buckets, NOW, 3600)
        assert list(kept) == [NOW - 3600, NOW]
        assert len(buckets) == 3  # input unchanged


class TestSeriesForWindow:
    @pytest.mark.parametrize(
        ("window", "resolution", "count"),
        [
            ("1h", RAW_RESOLUTION_S, 60),
            ("24h", HOUR_S, 24),
            ("7d", HOUR_S, 168),
            ("30d", DAY_S, 30),
        ],
    )
    def test_case_22_window_picks_resolution(self, window, resolution, count):
        s = series_for_window([], {}, {}, now=NOW, window=window)
        assert s.resolution_s == resolution
        assert len(s.points) == count
        assert s.points[-1].ts == bucket_start(NOW, resolution)

    def test_case_22_raw_window_values(self):
        last = bucket_start(NOW, 60)
        raw = [(last, 40.0), (last + 10, 60.0), (last - 60, 10.0)]
        s = series_for_window(raw, {}, {}, now=NOW, window="1h")
        assert s.source == "raw"
        assert s.values[-1] == 50.0
        assert s.values[-2] == 10.0

    def test_case_25_gaps_are_none_never_zero(self):
        last = bucket_start(NOW, HOUR_S)
        hourly = {last: _agg(30.0), last - 2 * HOUR_S: _agg(10.0)}
        s = series_for_window([], hourly, {}, now=NOW, window="24h")
        assert s.values[-1] == 30.0
        assert s.values[-2] is None
        assert s.values[-3] == 10.0
        assert 0.0 not in s.values

    def test_case_25_only_invalid_bucket_is_none_but_counted(self):
        last = bucket_start(NOW, HOUR_S)
        s = series_for_window([], {last: _agg(None, None)}, {}, now=NOW, window="24h")
        assert s.points[-1].mean is None
        assert s.points[-1].invalid == 2

    def test_case_25_no_data_at_all(self):
        s = series_for_window([], {}, {}, now=NOW, window="30d")
        assert all(v is None for v in s.values)
        assert s.coverage == 0.0

    def test_coverage_is_share_of_filled_points(self):
        last = bucket_start(NOW, DAY_S)
        daily = {last: _agg(1.0), last - DAY_S: _agg(2.0), last - 2 * DAY_S: _agg(3.0)}
        s = series_for_window([], {}, daily, now=NOW, window="30d")
        assert s.coverage == pytest.approx(3 / 30)

    def test_rule_hard_point_cap(self):
        window = 1000 * DAY_S
        daily = {bucket_start(NOW, DAY_S) - i * DAY_S: _agg(1.0) for i in range(900)}
        s = series_for_window([], {}, daily, now=NOW, window=window)
        assert len(s.points) <= MAX_POINTS
        assert s.resolution_s % DAY_S == 0
        assert sum(p.count for p in s.points) == 900  # merged, nothing dropped

    def test_integer_window_uses_same_rule(self):
        s = series_for_window([], {}, {}, now=NOW, window=2 * HOUR_S)
        assert s.resolution_s == RAW_RESOLUTION_S  # inside raw retention
        assert len(s.points) == 120
        s = series_for_window([], {}, {}, now=NOW, window=3 * HOUR_S)
        assert s.resolution_s == HOUR_S  # longer than raw retention
        assert len(s.points) == 3

    @pytest.mark.parametrize("window", ["2w", "", 0, -60])
    def test_bad_window_rejected(self, window):
        with pytest.raises(ValueError):
            series_for_window([], {}, {}, now=NOW, window=window)
