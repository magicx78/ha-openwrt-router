"""Tests for the client stability analysis (B3): client_analysis.py."""

from __future__ import annotations

import ast
import math
import re
from datetime import UTC, timedelta, timezone
from pathlib import Path

import pytest

from custom_components.openwrt_router import client_analysis as ca
from custom_components.openwrt_router.client_analysis import (
    CLASS_CRITICAL,
    CLASS_NOTICEABLE,
    CLASS_STABLE,
    CLASS_UNKNOWN,
    CLASS_UNSTABLE,
    CLASS_VERY_STABLE,
    DEFAULT_CLASSES,
    DEFAULT_WEIGHTS,
    PART_A,
    PART_D,
    PART_M,
    PART_R,
    PART_S,
    PART_U,
    PART_W,
    REASON_AP_CHANGED,
    REASON_BAND_CHANGED,
    REASON_BAND_UNKNOWN,
    REASON_FEW_SAMPLES,
    REASON_LOW_COVERAGE,
    REASON_TOO_SHORT,
    STATUS_DEGRADED,
    STATUS_FOUND,
    STATUS_INSUFFICIENT,
    STATUS_NO_TREND,
    STATUS_NOT_COMPARABLE,
    STATUS_NOT_FOUND,
    ScoreSettings,
    SignalTrend,
    TimePatternResult,
    WindowStats,
    active_patterns,
    cap_confidence,
    classify_score,
    collect_window,
    collect_window_days,
    make_settings,
    score_auth,
    score_disconnects,
    score_reconnects,
    score_recurring,
    score_roaming,
    score_signal,
    score_trend,
    score_uptime,
    score_window,
    signal_trend,
    signal_trend_from_days,
    time_pattern,
    time_pattern_from_meta,
    weighted_median,
)
from custom_components.openwrt_router.client_history import (
    DC_INFRA,
    SESSION_BIN_HOURS,
    TR_END,
    TR_MOVE,
    TR_START,
    Bucket,
    ClientEvent,
    ClientHistory,
    ClientObs,
    DayMeta,
    PollInput,
    Transition,
)

DAY = 86400.0
M1 = "AA:BB:CC:00:00:01"
AP1 = "router_a"
AP2 = "router_b"
T0 = 1_800_000_000.0
D0 = 20000  # a made-up UTC day index
FULL_MASK = (1 << 24) - 1


def good_bucket(**kw: int) -> Bucket:
    """One perfect day: always online, mean RSSI -60 dBm."""
    base = {
        "observed_s": 86400,
        "online_s": 86400,
        "rssi_n": 1440,
        "rssi_sum": -60 * 1440,
        "rssi_min": -62,
        "rssi_max": -58,
    }
    base.update(kw)
    return Bucket(**base)


def stats(bucket: Bucket | None = None, **kw) -> WindowStats:
    values = {
        "window_s": DAY,
        "bucket": bucket or good_bucket(),
        "ongoing_h": 24.0,
        "log_coverage": 1.0,
        "patterns": 0,
        "data_days": 10,
    }
    values.update(kw)
    return WindowStats(**values)


# --- purity -------------------------------------------------------------------


def test_module_imports_no_home_assistant() -> None:
    tree = ast.parse(Path(ca.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not any(a.name.startswith("homeassistant") for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                assert node.module == "client_history"
            else:
                assert not (node.module or "").startswith("homeassistant")
    text = Path(ca.__file__).read_text(encoding="utf-8")
    assert not re.search(r"\btime\.time\(|\.now\(|\.utcnow\(|\.today\(", text)


# --- sub-scores ---------------------------------------------------------------


def test_sub_score_formulas() -> None:
    assert score_disconnects(0) == 100
    assert score_disconnects(4) == pytest.approx(100 / math.e)
    assert score_reconnects(3) == pytest.approx(100 / math.e)
    assert score_auth(2) == pytest.approx(100 / math.e)
    assert score_roaming(3) == pytest.approx(100 / math.e)
    assert score_uptime(0) == 0
    assert score_uptime(6) == pytest.approx(100)
    assert score_uptime(48) == 100
    assert score_uptime(1) == pytest.approx(100 * math.log(2) / math.log(7))
    assert score_signal(-60, 0) == 100
    assert score_signal(-85, 0) == 0
    assert score_signal(-72.5, 0) == pytest.approx(50)
    assert score_signal(-60, 1) == pytest.approx(50)
    assert score_signal(-40, 0) == 100  # clamped
    assert [score_recurring(n) for n in (0, 1, 2, 3, 5)] == [100, 65, 30, 0, 0]
    # negative metrics are treated as 0
    assert score_disconnects(-3) == 100


def test_default_weights_and_classes() -> None:
    assert dict(DEFAULT_WEIGHTS) == {
        PART_D: 30,
        PART_R: 15,
        PART_U: 15,
        PART_S: 20,
        PART_A: 10,
        PART_M: 5,
        PART_W: 5,
    }
    assert DEFAULT_CLASSES == (90, 75, 50, 25)


# --- score --------------------------------------------------------------------


def test_perfect_client_scores_100() -> None:
    res = score_window(stats())
    assert res.score == pytest.approx(100)
    assert res.cls == CLASS_VERY_STABLE
    assert res.coverage == pytest.approx(1)
    assert all(p.included for p in res.parts.values())


def test_score_is_weighted_mean_of_parts() -> None:
    # one error disconnect in 24 online hours: D = 100 e^-1/4, rest 100
    res = score_window(stats(good_bucket(dc_error=1)))
    d = 100 * math.exp(-0.25)
    assert res.parts[PART_D].value == pytest.approx(d)
    assert res.parts[PART_D].metric == pytest.approx(1)
    assert res.score == pytest.approx((30 * d + 70 * 100) / 100)


def test_disconnect_rate_is_per_24_online_hours() -> None:
    half = good_bucket(online_s=43200, observed_s=86400, dc_error=1)
    res = score_window(stats(half))
    assert res.parts[PART_D].metric == pytest.approx(2)


def test_disconnect_class_weights() -> None:
    def x(**kw: int) -> float:
        return score_window(stats(good_bucket(**kw))).parts[PART_D].metric

    assert x(dc_error=1) == pytest.approx(1.0)
    assert x(dc_unknown=1) == pytest.approx(0.75)
    assert x(dc_inactivity=1) == pytest.approx(0.5)
    assert x(dc_leave=1) == pytest.approx(0.25)
    assert x(dc_infra=5) == 0  # infra costs nothing


def test_infra_costs_nothing() -> None:
    assert score_window(stats(good_bucket(dc_infra=10))).score == pytest.approx(100)


def test_sleepy_sets_inactivity_weight_to_zero() -> None:
    bucket = good_bucket(dc_inactivity=4)
    normal = score_window(stats(bucket))
    sleepy = score_window(stats(bucket), make_settings(sleepy=True))
    assert normal.parts[PART_D].metric == pytest.approx(2)
    assert sleepy.parts[PART_D].metric == 0
    assert sleepy.score == pytest.approx(100)
    assert normal.score < sleepy.score
    # sleepy keeps the other classes
    other = score_window(stats(good_bucket(dc_error=1)), make_settings(sleepy=True))
    assert other.parts[PART_D].metric == pytest.approx(1)


def test_normal_roam_costs_nothing_and_flap_less_than_error() -> None:
    roams = score_window(stats(good_bucket(roams_in=8, roams_out=8, band_changes=2)))
    assert roams.score == pytest.approx(100)
    flap = score_window(stats(good_bucket(roams_in=2, roams_out=2, roam_flaps=1)))
    error = score_window(stats(good_bucket(dc_error=1)))
    assert 100 > flap.score > error.score


def test_coverage_below_half_is_unknown() -> None:
    # 30 % observed, no log, too few RSSI values, no session: D only
    bucket = Bucket(observed_s=25920, online_s=25920, rssi_n=3, rssi_sum=-180)
    res = score_window(stats(bucket, log_coverage=None, ongoing_h=None, data_days=1))
    assert res.parts[PART_D].included
    assert res.coverage == pytest.approx(0.3 * 30 / 100)
    assert res.score is None and res.cls == CLASS_UNKNOWN


def test_part_with_coverage_below_point_three_is_left_out() -> None:
    bad_log = good_bucket(reconnects=50, auth_fail=50, roam_flaps=50)
    res = score_window(stats(bad_log, log_coverage=0.29))
    for part in (PART_R, PART_A, PART_M):
        assert not res.parts[part].included
    assert res.score == pytest.approx(100)
    assert res.coverage == pytest.approx(70 / 100)
    res = score_window(stats(bad_log, log_coverage=0.3))
    assert res.parts[PART_R].included and res.score < 90


def test_without_log_r_a_m_are_unknown() -> None:
    res = score_window(stats(log_coverage=None))
    for part in (PART_R, PART_A, PART_M):
        assert res.parts[part].value is None and not res.parts[part].included
    assert res.score == pytest.approx(100)
    assert res.coverage == pytest.approx(0.7)


def test_missing_data_is_unknown_never_100() -> None:
    empty = WindowStats(window_s=DAY, bucket=Bucket())
    res = score_window(empty)
    assert res.score is None and res.cls == CLASS_UNKNOWN and res.coverage == 0
    assert empty.availability is None
    assert empty.coverage == 0
    assert WindowStats(window_s=0, bucket=Bucket()).coverage == 0
    # offline the whole time: availability 0, not unknown
    off = WindowStats(window_s=DAY, bucket=Bucket(observed_s=86400))
    assert off.availability == 0


def test_uptime_needs_long_or_running_session() -> None:
    short = stats(sessions_h=(0.2, 0.5), ongoing_h=None)
    assert not score_window(short).parts[PART_U].included
    longer = stats(sessions_h=(0.2, 2.0, 3.0), ongoing_h=None)
    part = score_window(longer).parts[PART_U]
    assert part.included and part.metric == pytest.approx(2.0)
    running = stats(sessions_h=(), ongoing_h=0.5)
    assert score_window(running).parts[PART_U].included


def test_signal_needs_ten_values_and_uses_weak_share() -> None:
    few = good_bucket(rssi_n=9, rssi_sum=-540)
    assert not score_window(stats(few)).parts[PART_S].included
    weak = good_bucket(rssi_sum=-60 * 1440, weak_s=43200)
    assert score_window(stats(weak)).parts[PART_S].value == pytest.approx(75)


def test_recurring_needs_three_days() -> None:
    assert not score_window(stats(patterns=2, data_days=2)).parts[PART_W].included
    part = score_window(stats(patterns=2, data_days=3)).parts[PART_W]
    assert part.included and part.value == 30


def test_custom_weights_apply_and_invalid_fall_back() -> None:
    only_d = make_settings({k: 0 for k in DEFAULT_WEIGHTS} | {PART_D: 1})
    res = score_window(stats(good_bucket(dc_error=4)), only_d)
    assert res.score == pytest.approx(100 / math.e)
    bad = make_settings({PART_D: -1, PART_S: float("nan"), "nope": 5, PART_R: True})
    assert dict(bad.weights) == dict(DEFAULT_WEIGHTS)
    zero = make_settings({k: 0 for k in DEFAULT_WEIGHTS})
    assert dict(zero.weights) == dict(DEFAULT_WEIGHTS)
    assert make_settings(weights="x").weights == DEFAULT_WEIGHTS  # type: ignore[arg-type]


# --- classes ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "cls"),
    [
        (100, CLASS_VERY_STABLE),
        (90, CLASS_VERY_STABLE),
        (89.9, CLASS_STABLE),
        (75, CLASS_STABLE),
        (74, CLASS_NOTICEABLE),
        (50, CLASS_NOTICEABLE),
        (49, CLASS_UNSTABLE),
        (25, CLASS_UNSTABLE),
        (24.9, CLASS_CRITICAL),
        (0, CLASS_CRITICAL),
        (None, CLASS_UNKNOWN),
        (float("nan"), CLASS_UNKNOWN),
    ],
)
def test_default_classes(score, cls) -> None:
    assert classify_score(score) == cls


def test_classes_are_configurable() -> None:
    settings = make_settings(classes=[95, 80, 60, 30])
    assert settings.classes == (95, 80, 60, 30)
    assert classify_score(92, settings.classes) == CLASS_STABLE
    res = score_window(stats(good_bucket(dc_error=1)), settings)
    assert res.cls == CLASS_STABLE  # 93.4 < 95
    assert score_window(stats(good_bucket(dc_error=1))).cls == CLASS_VERY_STABLE


@pytest.mark.parametrize(
    "bad",
    [
        None,
        [90, 75, 50],
        [90, 75, 50, 25, 10],
        [75, 90, 50, 25],
        [90, 90, 50, 25],
        [120, 75, 50, 25],
        [90, 75, 50, 0],
        [90, 75, "x", 25],
        [90, 75, float("nan"), 25],
        "90,75,50,25",
        5,
    ],
)
def test_invalid_classes_fall_back(bad) -> None:
    assert make_settings(classes=bad).classes == DEFAULT_CLASSES


def test_score_trend_arrow() -> None:
    assert score_trend(80, 70) == "up"
    assert score_trend(60, 70) == "down"
    assert score_trend(75, 70) == "flat"
    assert score_trend(None, 70) is None
    assert score_trend(70, None) is None


# --- time pattern -------------------------------------------------------------


def meta_days(n: int, dc: dict[int, dict[int, int]], mask: int = FULL_MASK):
    """n covered days; dc maps day offset -> {utc hour: disconnects}."""
    return {D0 + i: DayMeta(mask, dict(dc.get(i, {}))) for i in range(n)}


def test_time_pattern_found() -> None:
    meta = meta_days(10, {i: {3: 1} for i in (0, 2, 4, 6, 8)} | {5: {14: 1}})
    res = time_pattern_from_meta(meta, UTC)
    assert res.status == STATUS_FOUND
    assert [h.hour for h in res.hours] == [3]
    hit = res.hours[0]
    assert (hit.hit_days, hit.covered_days) == (5, 10)
    assert hit.rate == pytest.approx(0.5)
    assert hit.confidence <= 0.6


def test_time_pattern_uses_local_time() -> None:
    meta = meta_days(10, {i: {3: 1} for i in range(0, 10, 2)})
    tz = timezone(timedelta(hours=2))
    res = time_pattern_from_meta(meta, tz)
    assert [h.hour for h in res.hours] == [5]


def test_time_pattern_not_found_when_spread() -> None:
    dc = {i: {h: 1 for h in range(24)} for i in range(0, 10, 2)}
    res = time_pattern_from_meta(meta_days(10, dc), UTC)
    assert res.status == STATUS_NOT_FOUND and res.hours == ()


def test_time_pattern_not_found_below_hit_rules() -> None:
    # only 3 hit days (< 4)
    res = time_pattern_from_meta(meta_days(10, {i: {3: 1} for i in (0, 1, 2)}), UTC)
    assert res.status == STATUS_NOT_FOUND
    # 4 hit days of 10 covered = 40 % < 50 %
    res = time_pattern_from_meta(meta_days(10, {i: {3: 1} for i in (0, 1, 2, 3)}), UTC)
    assert res.status == STATUS_NOT_FOUND


def test_time_pattern_insufficient_days() -> None:
    res = time_pattern_from_meta(meta_days(6, {i: {3: 1} for i in range(6)}), UTC)
    assert res.status == STATUS_INSUFFICIENT
    assert res.max_covered_days == 6
    assert time_pattern_from_meta({}, UTC).status == STATUS_INSUFFICIENT


def test_time_pattern_ignores_uncovered_hours() -> None:
    mask = FULL_MASK & ~(1 << 3)  # hour 3 never covered
    meta = meta_days(10, {i: {3: 1} for i in range(10)}, mask=mask)
    assert time_pattern_from_meta(meta, UTC).status == STATUS_NOT_FOUND


# --- signal trend -------------------------------------------------------------


def day_bucket(
    mean: int,
    n: int = 1440,
    observed: int = 86400,
    online: int = 86400,
    band: str | None = "5g",
) -> Bucket:
    fields = {"2.4g": "online_2g_s", "5g": "online_5g_s", "6g": "online_6g_s"}
    extra = {fields[band]: online} if band else {}
    return Bucket(
        observed_s=observed, online_s=online, rssi_n=n, rssi_sum=mean * n, **extra
    )


def trend_days(n_days: int, old: int, new: int, **kw) -> dict[int, dict[str, Bucket]]:
    half = n_days // 2
    return {
        D0 + i: {AP1: day_bucket(old if i < half else new, **kw)} for i in range(n_days)
    }


def test_signal_trend_degraded() -> None:
    res = signal_trend_from_days(trend_days(14, -55, -63), D0 + 13)
    assert res.status == STATUS_DEGRADED
    assert res.window_days == 7 and res.ap == AP1
    assert res.delta_db == pytest.approx(-8)
    assert 0 < res.confidence <= 0.6


def test_signal_trend_exactly_minus_six_is_degraded() -> None:
    res = signal_trend_from_days(trend_days(14, -55, -61), D0 + 13)
    assert res.status == STATUS_DEGRADED


def test_signal_trend_no_trend() -> None:
    res = signal_trend_from_days(trend_days(14, -55, -60), D0 + 13)
    assert res.status == STATUS_NO_TREND and res.delta_db == pytest.approx(-5)
    assert res.confidence == 0


def test_signal_trend_short_span_uses_three_days() -> None:
    res = signal_trend_from_days(trend_days(8, -55, -65), D0 + 7)
    assert res.status == STATUS_DEGRADED and res.window_days == 3
    short = signal_trend_from_days(trend_days(5, -55, -65), D0 + 4)
    assert short.status == STATUS_NOT_COMPARABLE and short.reason == REASON_TOO_SHORT
    assert signal_trend_from_days({}, D0).reason == REASON_TOO_SHORT


def test_signal_trend_too_few_samples() -> None:
    res = signal_trend_from_days(trend_days(14, -55, -65, n=10), D0 + 13)
    assert res.status == STATUS_NOT_COMPARABLE and res.reason == REASON_FEW_SAMPLES


def test_signal_trend_low_coverage() -> None:
    res = signal_trend_from_days(
        trend_days(14, -55, -65, observed=30000, online=30000), D0 + 13
    )
    assert res.status == STATUS_NOT_COMPARABLE and res.reason == REASON_LOW_COVERAGE


def test_signal_trend_ap_changed() -> None:
    days = trend_days(14, -55, -65)
    for i in range(7, 14):
        days[D0 + i] = {AP2: day_bucket(-65)}
    res = signal_trend_from_days(days, D0 + 13)
    assert res.status == STATUS_NOT_COMPARABLE and res.reason == REASON_AP_CHANGED


def test_signal_trend_below_seventy_percent_same_ap() -> None:
    days: dict[int, dict[str, Bucket]] = {}
    for i in range(14):
        mean = -55 if i < 7 else -65
        days[D0 + i] = {
            AP1: day_bucket(mean, online=50000, observed=50000),
            AP2: day_bucket(mean, online=36400, observed=36400),
        }
    res = signal_trend_from_days(days, D0 + 13)  # 58 % at AP1
    assert res.status == STATUS_NOT_COMPARABLE and res.reason == REASON_AP_CHANGED


def test_confidence_cap() -> None:
    assert cap_confidence(0.9) == 0.6
    assert cap_confidence(0.4) == 0.4
    assert cap_confidence(-1) == 0
    assert cap_confidence(float("nan")) == 0
    # every hypothesis output respects the cap
    meta = meta_days(20, {i: {3: 2} for i in range(20)})
    assert all(h.confidence <= 0.6 for h in time_pattern_from_meta(meta, UTC).hours)
    big = signal_trend_from_days(trend_days(14, -40, -80), D0 + 13)
    assert big.status == STATUS_DEGRADED and big.confidence == 0.6


def test_active_patterns() -> None:
    found = TimePatternResult(STATUS_FOUND)
    assert active_patterns(found, SignalTrend(STATUS_DEGRADED)) == 2
    assert (
        active_patterns(
            TimePatternResult(STATUS_NOT_FOUND), SignalTrend(STATUS_NO_TREND)
        )
        == 0
    )


# --- with a real B1 history ---------------------------------------------------


def _feed(hist: ClientHistory, polls: int, start: float = T0, rssi: int = -60) -> None:
    for k in range(polls):
        hist.ingest(
            PollInput(
                router=AP1,
                now=start + k * 60,
                interval=60,
                fresh=True,
                clients=(ClientObs(M1, rssi=rssi),),
            )
        )


def test_collect_window_from_history() -> None:
    hist = ClientHistory()
    _feed(hist, 121)  # two hours online, last poll T0+7200
    now = T0 + 7200 + 30
    win = collect_window(hist, M1, now)
    assert win is not None
    assert win.window_s == pytest.approx(7230)  # since first seen
    assert win.coverage == pytest.approx(7200 / 7230)
    assert win.availability == pytest.approx(1)
    assert win.ongoing_h == pytest.approx(7230 / 3600)
    assert win.bucket.rssi_n == 121
    res = score_window(win)
    # no log, one day of data: D, U, S known -> 65 % coverage
    assert res.coverage == pytest.approx((30 * 7200 / 7230 + 35) / 100)
    u = score_uptime(7230 / 3600)  # running session of about 2 h
    c_d = 7200 / 7230
    assert res.score == pytest.approx(
        (30 * c_d * 100 + 15 * u + 20 * 100) / (30 * c_d + 35)
    )
    assert collect_window(hist, "AA:BB:CC:00:00:99", now) is None


def test_collect_window_previous_day_without_data_is_unknown() -> None:
    hist = ClientHistory()
    _feed(hist, 121)
    prev = collect_window(hist, M1, T0 + 7200, end=T0 + 7200 - DAY)
    assert prev is not None and prev.bucket.observed_s == 0
    assert score_window(prev).score is None


def test_collect_window_sessions_from_transitions() -> None:
    hist = ClientHistory()
    _feed(hist, 121)  # online T0..T0+7200
    for k in range(1, 6):  # gone: offline after the grace, ends at T0+7200
        hist.ingest(
            PollInput(router=AP1, now=T0 + 7200 + k * 60, interval=60, fresh=True)
        )
    now = T0 + 7500
    win = collect_window(hist, M1, now)
    assert win.ongoing_h is None
    assert win.sessions_h == ()
    # a 2 h session lands in the 2 h .. 4 h bin (representative sqrt(8) h)
    assert win.session_hist[5] == 1 and sum(win.session_hist) == 1
    assert score_window(win).parts[PART_U].metric == pytest.approx(SESSION_BIN_HOURS[5])


def test_collect_window_days_and_analysis_wrappers() -> None:
    hist = ClientHistory()
    _feed(hist, 200)
    now = T0 + 200 * 60
    win = collect_window_days(hist, M1, now)
    assert win.bucket.online_s == pytest.approx(199 * 60)
    assert time_pattern(hist, M1, UTC).status == STATUS_INSUFFICIENT
    trend = signal_trend(hist, M1, now)
    assert trend.status == STATUS_NOT_COMPARABLE and trend.reason == REASON_TOO_SHORT


def test_default_settings_object() -> None:
    s = ScoreSettings()
    assert dict(s.weights) == dict(DEFAULT_WEIGHTS) and not s.sleepy


# --- follow-up: band rule and session histogram -------------------------------


def test_signal_trend_same_ap_band_changed() -> None:
    days = trend_days(14, -55, -65)
    for i in range(7, 14):
        days[D0 + i] = {AP1: day_bucket(-65, band="2.4g")}
    res = signal_trend_from_days(days, D0 + 13)
    assert res.status == STATUS_NOT_COMPARABLE and res.reason == REASON_BAND_CHANGED
    assert res.ap == AP1


def test_signal_trend_same_ap_same_band_is_comparable() -> None:
    days = trend_days(14, -55, -65, band="2.4g")
    res = signal_trend_from_days(days, D0 + 13)
    assert res.status == STATUS_DEGRADED and res.ap == AP1


def test_signal_trend_band_split_below_seventy_percent() -> None:
    days: dict[int, dict[str, Bucket]] = {}
    for i in range(14):
        b = day_bucket(-55 if i < 7 else -65, band=None)
        # same AP, 60 % on 5 GHz and 40 % on 2.4 GHz
        days[D0 + i] = {AP1: b._replace(online_5g_s=51840, online_2g_s=34560)}
    res = signal_trend_from_days(days, D0 + 13)
    assert res.status == STATUS_NOT_COMPARABLE and res.reason == REASON_BAND_CHANGED


def test_signal_trend_band_not_reported_is_not_comparable() -> None:
    res = signal_trend_from_days(trend_days(14, -55, -65, band=None), D0 + 13)
    assert res.status == STATUS_NOT_COMPARABLE and res.reason == REASON_BAND_UNKNOWN


def test_weighted_median() -> None:
    assert weighted_median([(1, 1), (2, 1), (3, 1)]) == 2
    assert weighted_median([(1, 1), (2, 1), (3, 1), (4, 1)]) == 2.5
    assert weighted_median([(5, 3), (1, 1)]) == 5
    assert weighted_median([(1, 2), (9, 2)]) == 5
    assert weighted_median([(1, 0)]) == 0
    assert weighted_median([]) == 0


def test_uptime_from_histogram_and_exact_lengths() -> None:
    hist = [0] * 10
    hist[0] = 3  # three short sessions
    hist[7] = 2  # two of 6-12 h
    part = score_window(stats(session_hist=tuple(hist), ongoing_h=None)).parts[PART_U]
    assert part.included and part.metric == pytest.approx(SESSION_BIN_HOURS[0])
    only_short = score_window(stats(session_hist=(4,), ongoing_h=None))
    assert not only_short.parts[PART_U].included


def _session_day(hist: ClientHistory, start: float, hours: int) -> None:
    """One session of ``hours`` at AP1 starting at ``start``, then offline."""
    for k in range(hours * 60 + 1):
        hist.ingest(
            PollInput(
                router=AP1,
                now=start + k * 60,
                interval=60,
                fresh=True,
                clients=(ClientObs(M1, rssi=-60, band="5g"),),
            )
        )
    end = start + hours * 3600
    for k in range(1, 6):
        hist.ingest(PollInput(router=AP1, now=end + k * 60, interval=60, fresh=True))


def test_uptime_over_seven_days_sees_sessions_older_than_a_day() -> None:
    hist = ClientHistory()
    _session_day(hist, T0, 8)  # an 8 h session on day one
    # keep the fleet fresh for three days without the client
    t = T0 + 8 * 3600 + 300
    end = T0 + 3 * DAY
    while t < end:
        t += 60
        hist.ingest(PollInput(router=AP1, now=t, interval=60, fresh=True))
    # the 24 h transitions no longer know the session ...
    assert hist.transitions(M1) == ()
    day = collect_window(hist, M1, t, hours=24)
    week = collect_window(hist, M1, t, hours=168)
    month = collect_window_days(hist, M1, t, days=30)
    assert sum(day.session_hist) == 0
    assert not score_window(day).parts[PART_U].included
    # ... but the buckets do
    for win in (week, month):
        assert win.session_hist[7] == 1  # 6 h .. 12 h
        part = score_window(win).parts[PART_U]
        assert part.included and part.metric == pytest.approx(SESSION_BIN_HOURS[7])
        assert part.value == 100


# --- B4: AP-specific pattern (plan 5) ------------------------------------------

H = 3600
AP3 = "router_c"
M2 = "AA:BB:CC:00:00:02"
M3 = "AA:BB:CC:00:00:03"
M4 = "AA:BB:CC:00:00:04"


def online_bucket(hours: float, **kw: int) -> Bucket:
    secs = int(hours * H)
    return Bucket(observed_s=secs, online_s=secs, **kw)


def test_ap_pattern_found() -> None:
    res = ca.ap_pattern_from_buckets(
        {AP1: online_bucket(48, dc_error=4), AP2: online_bucket(48)}
    )
    assert res.status == STATUS_FOUND
    assert (res.worst_ap, res.best_ap) == (AP1, AP2)
    assert res.worst_rate == pytest.approx(2.0)  # per 24 online hours
    assert res.best_rate == 0
    assert res.confidence == pytest.approx(0.42) and res.confidence <= 0.6
    many = ca.ap_pattern_from_buckets(
        {AP1: online_bucket(48, dc_error=40), AP2: online_bucket(48)}
    )
    assert many.confidence == 0.6


def test_ap_pattern_too_few_hours_is_insufficient() -> None:
    res = ca.ap_pattern_from_buckets(
        {AP1: online_bucket(48, dc_error=10), AP2: online_bucket(20)}
    )
    assert res.status == STATUS_INSUFFICIENT
    assert [r.ap for r in res.rates] == [AP1]
    # the offline key "" never counts as an AP
    res = ca.ap_pattern_from_buckets(
        {AP1: online_bucket(48, dc_error=10), "": online_bucket(100)}
    )
    assert res.status == STATUS_INSUFFICIENT


def test_ap_pattern_ratio_too_small() -> None:
    res = ca.ap_pattern_from_buckets(
        {AP1: online_bucket(48, dc_error=4), AP2: online_bucket(48, dc_error=2)}
    )
    assert res.status == STATUS_NOT_FOUND  # 2.0 vs 1.0: only 2x
    assert res.worst_rate == pytest.approx(2.0) and res.best_rate == pytest.approx(1)
    small = ca.ap_pattern_from_buckets(
        {AP1: online_bucket(60, dc_error=1), AP2: online_bucket(48)}
    )
    assert small.status == STATUS_NOT_FOUND  # 0.4 vs 0: below 0.5 absolute
    assert small.confidence == 0


def test_ap_pattern_counts_only_error_disconnects() -> None:
    res = ca.ap_pattern_from_buckets(
        {
            AP1: online_bucket(48, dc_unknown=10, dc_infra=10, dc_leave=10),
            AP2: online_bucket(48),
        }
    )
    assert res.status == STATUS_NOT_FOUND


def test_ap_pattern_feeds_part_w() -> None:
    found = ca.ap_pattern_from_buckets(
        {AP1: online_bucket(48, dc_error=4), AP2: online_bucket(48)}
    )
    none_tp = TimePatternResult(STATUS_NOT_FOUND)
    no_trend = SignalTrend(STATUS_NO_TREND)
    assert active_patterns(none_tp, no_trend) == 0
    assert active_patterns(none_tp, no_trend, found) == 1
    n = active_patterns(TimePatternResult(STATUS_FOUND), no_trend, found)
    assert n == 2
    part = score_window(stats(patterns=n)).parts[PART_W]
    assert part.included and part.value == 30
    not_found = ca.ApPatternResult(STATUS_NOT_FOUND)
    assert active_patterns(none_tp, no_trend, not_found) == 0


def test_ap_pattern_from_history_wrapper() -> None:
    hist = ClientHistory()
    _feed(hist, 200)
    now = T0 + 200 * 60
    assert set(ca.ap_buckets(hist, M1, now)) == {AP1}
    assert ca.ap_pattern(hist, M1, now).status == STATUS_INSUFFICIENT
    assert ca.ap_pattern(hist, "AA:BB:CC:00:00:99", now).status == (STATUS_INSUFFICIENT)


# --- B4: AP comparison (plan 6) --------------------------------------------------


def test_ap_comparison_normalized_per_client_hour() -> None:
    inputs = [
        # big AP: 3 clients, 1000 client hours, 20 disconnects -> 2 / 100 h
        ca.ApClientInput(M1, AP1, online_bucket(400, dc_error=10)),
        ca.ApClientInput(M2, AP1, online_bucket(300, dc_unknown=5)),
        ca.ApClientInput(M3, AP1, online_bucket(300, dc_inactivity=5)),
        # small AP: 20 client hours, 2 disconnects -> 10 / 100 h
        ca.ApClientInput(M4, AP2, online_bucket(20, dc_error=2)),
    ]
    cmp = ca.compare_aps(inputs, ca.WINDOW_7D)
    big, small = cmp.aps[AP1], cmp.aps[AP2]
    assert big.disconnects == 20 and small.disconnects == 2
    assert big.disconnects_per_100h == pytest.approx(2.0)
    assert small.disconnects_per_100h == pytest.approx(10.0)
    # fewer disconnects in absolute numbers, but worse per client hour
    assert cmp.ranking == (AP1, AP2)
    assert (big.rank, small.rank) == (1, 2)
    assert big.clients == 3 and big.client_hours == pytest.approx(1000)
    assert small.low_basis and not big.low_basis
    assert cmp.window == ca.WINDOW_7D


def test_ap_under_minimum_client_hours_is_not_ranked() -> None:
    inputs = [
        ca.ApClientInput(M1, AP1, online_bucket(50, dc_error=1)),
        ca.ApClientInput(M2, AP2, online_bucket(9, dc_error=0)),
    ]
    cmp = ca.compare_aps(inputs)
    low = cmp.aps[AP2]
    assert low.status == ca.AP_STATUS_INSUFFICIENT
    assert low.disconnects_per_100h is None and low.reconnects_per_100h is None
    assert low.rssi_mean is None and low.stability is None
    assert low.rank is None and cmp.ranking == (AP1,)
    assert cmp.aps[AP1].status == ca.AP_STATUS_OK


def test_ap_with_only_infra_disconnects() -> None:
    inputs = [
        ca.ApClientInput(M1, AP1, online_bucket(30, dc_infra=4), None, ("inc-1",)),
        ca.ApClientInput(M2, AP1, online_bucket(30, dc_infra=2), None, ("inc-1",)),
        ca.ApClientInput(M3, AP2, online_bucket(60, dc_error=3)),
    ]
    cmp = ca.compare_aps(inputs)
    infra = cmp.aps[AP1]
    assert infra.disconnects == 0 and infra.disconnects_per_100h == 0
    assert infra.infra_disconnects == 6 and infra.infra_clients == 2
    assert infra.incidents == ("inc-1",)
    assert cmp.ranking == (AP1, AP2)


def test_ap_comparison_roams_and_leaves_do_not_count() -> None:
    inputs = [
        ca.ApClientInput(
            M1,
            AP1,
            online_bucket(
                50, roams_in=40, roams_out=40, roam_flaps=2, dc_leave=5, reconnects=1
            ),
        ),
        ca.ApClientInput(M2, AP2, online_bucket(50, dc_error=1)),
    ]
    cmp = ca.compare_aps(inputs)
    a = cmp.aps[AP1]
    assert a.disconnects == 0 and a.disconnects_per_100h == 0
    assert a.leaves == 5
    assert a.roams_in_per_100h == pytest.approx(80)
    assert a.roams_out_per_100h == pytest.approx(80)
    assert a.flaps_per_100h == pytest.approx(4)
    assert a.reconnects_per_100h == pytest.approx(2)
    assert cmp.ranking == (AP1, AP2)


def test_ap_comparison_weighted_stability_signal_and_bands() -> None:
    b1 = online_bucket(
        10, rssi_n=10, rssi_sum=-600, weak_s=0, online_5g_s=10 * H, auth_fail=1
    )
    b2 = online_bucket(30, rssi_n=30, rssi_sum=-2100, weak_s=15 * H, online_2g_s=30 * H)
    inputs = [
        ca.ApClientInput(M1, AP1, b1, 90.0),
        ca.ApClientInput(M2, AP1, b2, 60.0),
        ca.ApClientInput(M3, AP1, online_bucket(5), None),  # no score: ignored
    ]
    s = ca.compare_aps(inputs).aps[AP1]
    assert s.stability == pytest.approx((90 * 10 + 60 * 30) / 40)
    assert s.rssi_mean == pytest.approx(-2700 / 40)
    assert s.weak_share == pytest.approx(15 / 45)
    assert s.band_hours["5g"] == pytest.approx(10)
    assert s.band_hours["2.4g"] == pytest.approx(30)
    assert s.auth_fail_per_100h == pytest.approx(100 / 45)


def test_ap_comparison_from_history() -> None:
    hist = ClientHistory()
    _feed(hist, 200)  # about 3.3 client hours at AP1
    now = T0 + 200 * 60
    for window in ca.WINDOWS:
        cmp = ca.ap_comparison(hist, now, window, scores={M1: 80.0})
        assert set(cmp.aps) == {AP1}
        assert cmp.aps[AP1].status == ca.AP_STATUS_INSUFFICIENT
        assert cmp.aps[AP1].client_hours == pytest.approx(199 / 60)
        assert cmp.ranking == ()
    inputs = ca.ap_inputs(hist, now, ca.WINDOW_24H)
    assert [(i.mac, i.ap, i.score) for i in inputs] == [(M1, AP1, None)]


# --- B4: correlation with NI roots ----------------------------------------------


def end(cls: str, incident: str | None = None, ap: str = AP1) -> Transition:
    return Transition(T0, TR_END, ap, None, cls, incident)


def test_infra_disconnects_with_confirmed_root_are_confirmed() -> None:
    refs = {"inc-1": ca.IncidentRef("inc-1", ca.CAUSE_CONFIRMED, "system_reboot")}
    res = ca.attribute_disconnects(
        [end(DC_INFRA, "inc-1"), end(DC_INFRA, "inc-1"), end("error")], refs
    )
    assert res.attribution == ca.ATTR_INFRASTRUCTURE
    assert res.kind == ca.KIND_CONFIRMED and res.confidence == 1.0
    assert (res.infra, res.client, res.client_errors) == (2, 1, 1)
    assert res.incidents == ("inc-1",) and res.causes == ("system_reboot",)
    assert res.total == 3


def test_infra_disconnects_with_hypothesis_root_are_capped() -> None:
    refs = {
        "inc-1": ca.IncidentRef("inc-1", ca.CAUSE_HYPOTHESIS, "router_unreachable", 0.9)
    }
    res = ca.attribute_disconnects([end(DC_INFRA, "inc-1")], refs)
    assert res.kind == ca.KIND_HYPOTHESIS and res.confidence == 0.6
    refs = {"inc-1": ca.IncidentRef("inc-1", ca.CAUSE_HYPOTHESIS, None, 0.4)}
    res = ca.attribute_disconnects([end(DC_INFRA, "inc-1")], refs)
    assert res.confidence == pytest.approx(0.4)


def test_one_unconfirmed_root_makes_the_whole_cause_a_hypothesis() -> None:
    refs = {
        "inc-1": ca.IncidentRef("inc-1", ca.CAUSE_CONFIRMED),
        "inc-2": ca.IncidentRef("inc-2", None),
    }
    res = ca.attribute_disconnects(
        [end(DC_INFRA, "inc-1"), end(DC_INFRA, "inc-2")], refs
    )
    assert res.kind == ca.KIND_HYPOTHESIS
    assert res.confidence == ca.INFRA_UNKNOWN_CONFIDENCE


def test_infra_tag_without_ni_data_is_never_confirmed() -> None:
    res = ca.attribute_disconnects([end(DC_INFRA), end(DC_INFRA)], {})
    assert res.attribution == ca.ATTR_INFRASTRUCTURE
    assert res.kind == ca.KIND_HYPOTHESIS
    assert res.confidence == pytest.approx(0.3)
    assert res.incidents == ()


def test_incident_known_to_ni_counts_as_infra_even_without_infra_class() -> None:
    refs = {"inc-9": ca.IncidentRef("inc-9", ca.CAUSE_CONFIRMED)}
    res = ca.attribute_disconnects([end("unknown", "inc-9")], refs)
    assert res.attribution == ca.ATTR_INFRASTRUCTURE and res.infra == 1
    assert res.client == 0 and res.client_errors == 0


def test_mostly_client_disconnects_stay_with_the_client() -> None:
    res = ca.attribute_disconnects(
        [end(DC_INFRA), end("error"), end("error"), end("inactivity"), end("leave")],
        {},
    )
    assert res.attribution == ca.ATTR_CLIENT
    assert res.kind == ca.KIND_OBSERVATION and res.confidence is None
    assert (res.infra, res.client, res.client_errors, res.leaves) == (1, 3, 2, 1)


def test_no_problem_disconnects_is_no_attribution() -> None:
    res = ca.attribute_disconnects([end("leave")], {})
    assert res.attribution == ca.ATTR_NONE and res.kind is None
    assert ca.attribute_disconnects([], {}).attribution == ca.ATTR_NONE
    # other transition kinds are ignored
    res = ca.attribute_disconnects([Transition(T0, TR_START, AP1)], {})
    assert res.total == 0


def test_disconnect_ends_from_history() -> None:
    hist = ClientHistory()
    _feed(hist, 121)
    for k in range(1, 6):
        hist.ingest(
            PollInput(router=AP1, now=T0 + 7200 + k * 60, interval=60, fresh=True)
        )
    ends = ca.disconnect_ends(hist, M1, T0, T0 + DAY)
    assert len(ends) == 1 and ends[0].kind == TR_END and ends[0].ap == AP1
    assert ca.disconnect_ends(hist, M1, T0 + DAY, T0 + 2 * DAY) == ()


# --- B4: roam bursts ----------------------------------------------------------------


def alternating(n: int, step: float, start: float = T0) -> list:
    out = []
    for k in range(n):
        a, b = (AP1, AP2) if k % 2 == 0 else (AP2, AP1)
        out.append(ca.RoamStep(start + k * step, a, b))
    return out


def test_roam_burst_found_both_directions() -> None:
    res = ca.roam_burst(alternating(8, 200))  # 8 roams in 1400 s
    assert res.found and res.roams == 8
    assert (res.ap_a, res.ap_b) == (AP1, AP2)
    assert (res.start, res.end) == (T0, T0 + 1400)


def test_roam_burst_not_found() -> None:
    assert not ca.roam_burst(alternating(7, 200)).found
    spread = ca.roam_burst(alternating(8, 300))  # 2100 s: never 8 in 30 min
    assert not spread.found and spread.roams == 7
    # roams between different pairs are not added up
    mixed = alternating(4, 100) + [
        ca.RoamStep(T0 + 500 + k * 100, AP2, AP3) for k in range(4)
    ]
    assert ca.roam_burst(mixed).roams == 4
    assert ca.roam_burst([]) == ca.RoamBurst(False)


def test_roam_steps_from_transitions() -> None:
    trs = [
        Transition(T0, TR_START, AP1),
        Transition(T0 + 60, TR_MOVE, AP2),
        Transition(T0 + 120, TR_MOVE, AP1),
        Transition(T0 + 180, TR_END, AP1),
        Transition(T0 + 240, TR_MOVE, AP2),  # no session: ignored
    ]
    steps = ca.roam_steps(trs)
    assert steps == (
        ca.RoamStep(T0 + 60, AP1, AP2),
        ca.RoamStep(T0 + 120, AP2, AP1),
    )


# --- B4: recommendations (plan 7) ---------------------------------------------------

ALL_KEYS = {
    ca.REC_CHECK_COVERAGE,
    ca.REC_CHECK_ROAMING,
    ca.REC_INFRA_LIKELY,
    ca.REC_CHECK_SCHEDULE,
    ca.REC_CHECK_AP,
    ca.REC_INFRA_CAUSE,
    ca.REC_INFRA_OBSERVED,
}


def bad_day(**kw: int) -> WindowStats:
    values = {
        "observed_s": 86400,
        "online_s": 86400,
        "dc_error": 6,
        "dc_unknown": 4,
        "rssi_n": 100,
        "rssi_sum": -78 * 100,
        "weak_s": int(0.4 * 86400),
    }
    values.update(kw)
    return stats(Bucket(**values))


def assert_structured(rec: ca.Recommendation) -> None:
    assert rec.key in ALL_KEYS
    assert all(isinstance(v, (str, int, float)) for v in rec.params.values())
    if rec.kind == ca.KIND_HYPOTHESIS:
        assert rec.confidence is not None and 0 < rec.confidence <= 0.6
    elif rec.kind == ca.KIND_OBSERVATION:
        assert rec.confidence is None
    else:
        assert rec.kind == ca.KIND_CONFIRMED


def test_rule_coverage_triggers() -> None:
    rec = ca.rule_coverage(ca.ClientFindings(M1, stats_24h=bad_day()))
    assert rec is not None and rec.key == ca.REC_CHECK_COVERAGE
    assert rec.kind == ca.KIND_HYPOTHESIS and rec.confidence == 0.5
    assert rec.params == {
        "disconnects_24h": 10.0,
        "weak_share": 0.4,
        "rssi_mean": -78.0,
    }
    assert_structured(rec)


def test_rule_coverage_does_not_trigger() -> None:
    for s in (
        bad_day(weak_s=int(0.2 * 86400)),  # signal fine
        bad_day(dc_error=3, dc_unknown=0),  # 3 disconnects (threshold 4)
        bad_day(dc_error=0, dc_unknown=0, dc_infra=10),  # infra does not count
        bad_day(rssi_n=5, rssi_sum=-390),  # too few RSSI values
        stats(bad_day().bucket, window_s=3 * DAY),  # coverage below 0.5
        None,
    ):
        assert ca.rule_coverage(ca.ClientFindings(M1, stats_24h=s)) is None


def test_rule_coverage_threshold_is_four_disconnects_per_day() -> None:
    assert ca.COVERAGE_MIN_DISCONNECTS == 4.0
    rec = ca.rule_coverage(
        ca.ClientFindings(M1, stats_24h=bad_day(dc_unknown=0, dc_error=4))
    )
    assert rec is not None and rec.params["disconnects_24h"] == 4.0
    # half a day observed: 2 disconnects are 4 per 24 observed hours
    half = bad_day(
        dc_error=2,
        dc_unknown=0,
        observed_s=43200,
        online_s=43200,
        weak_s=int(0.4 * 43200),
    )
    assert (
        ca.rule_coverage(
            ca.ClientFindings(M1, stats_24h=stats(half.bucket, window_s=43200))
        )
        is not None
    )


def test_rule_roaming() -> None:
    burst = ca.roam_burst(alternating(8, 200))
    rec = ca.rule_roaming(ca.ClientFindings(M1, roam_burst=burst))
    assert rec is not None and rec.key == ca.REC_CHECK_ROAMING
    assert rec.params == {"roams": 8, "ap_a": AP1, "ap_b": AP2, "minutes": 30}
    assert_structured(rec)
    calm = ca.roam_burst(alternating(7, 200))
    assert ca.rule_roaming(ca.ClientFindings(M1, roam_burst=calm)) is None
    assert ca.rule_roaming(ca.ClientFindings(M1)) is None


def test_rule_time_pattern() -> None:
    meta = meta_days(10, {i: {3: 1} for i in (0, 2, 4, 6, 8)})
    found = time_pattern_from_meta(meta, UTC)
    rec = ca.rule_time_pattern(ca.ClientFindings(M1, time_pattern=found))
    assert rec is not None and rec.key == ca.REC_CHECK_SCHEDULE
    assert rec.params["hour"] == 3 and rec.params["hit_days"] == 5
    assert rec.confidence == found.hours[0].confidence
    assert_structured(rec)
    for tp in (
        TimePatternResult(STATUS_NOT_FOUND),
        TimePatternResult(STATUS_INSUFFICIENT),
        None,
    ):
        assert ca.rule_time_pattern(ca.ClientFindings(M1, time_pattern=tp)) is None


def test_rule_ap_specific() -> None:
    found = ca.ap_pattern_from_buckets(
        {AP1: online_bucket(48, dc_error=4), AP2: online_bucket(48)}
    )
    rec = ca.rule_ap_specific(ca.ClientFindings(M1, ap_pattern=found))
    assert rec is not None and rec.key == ca.REC_CHECK_AP
    assert rec.params == {
        "worst_ap": AP1,
        "best_ap": AP2,
        "worst_rate": 2.0,
        "best_rate": 0.0,
    }
    assert rec.confidence == pytest.approx(0.42)
    assert_structured(rec)
    other = ca.ap_pattern_from_buckets(
        {AP1: online_bucket(48, dc_error=4), AP2: online_bucket(20)}
    )
    assert ca.rule_ap_specific(ca.ClientFindings(M1, ap_pattern=other)) is None
    assert ca.rule_ap_specific(ca.ClientFindings(M1)) is None


def test_rule_infrastructure_cause_kinds() -> None:
    confirmed = ca.attribute_disconnects(
        [end(DC_INFRA, "inc-1")],
        {"inc-1": ca.IncidentRef("inc-1", ca.CAUSE_CONFIRMED, "system_reboot")},
    )
    rec = ca.rule_infrastructure_cause(ca.ClientFindings(M1, attribution=confirmed))
    assert rec.key == ca.REC_INFRA_CAUSE and rec.kind == ca.KIND_CONFIRMED
    assert rec.params["cause"] == "system_reboot"
    assert_structured(rec)

    hyp = ca.attribute_disconnects(
        [end(DC_INFRA, "inc-1")],
        {"inc-1": ca.IncidentRef("inc-1", ca.CAUSE_HYPOTHESIS, None, 0.8)},
    )
    rec = ca.rule_infrastructure_cause(ca.ClientFindings(M1, attribution=hyp))
    assert rec.kind == ca.KIND_HYPOTHESIS and rec.confidence == 0.6
    assert_structured(rec)

    # missing NI data: no cause is claimed, only the coincidence
    blind = ca.attribute_disconnects([end(DC_INFRA)], {})
    rec = ca.rule_infrastructure_cause(ca.ClientFindings(M1, attribution=blind))
    assert rec.key == ca.REC_INFRA_OBSERVED and rec.kind == ca.KIND_OBSERVATION
    assert_structured(rec)


def test_rule_infrastructure_cause_does_not_trigger() -> None:
    client = ca.attribute_disconnects([end("error"), end("error")], {})
    none = ca.attribute_disconnects([], {})
    for a in (client, none, None):
        assert (
            ca.rule_infrastructure_cause(ca.ClientFindings(M1, attribution=a)) is None
        )


def test_rule_infrastructure_likely() -> None:
    group = ca.ApReconnects(AP1, {M1: 3, M2: 4, M3: 5, M4: 1}, root_open=False)
    rec = ca.rule_infrastructure_likely(group)
    assert rec is not None and rec.key == ca.REC_INFRA_LIKELY
    assert rec.subject == AP1 and rec.params == {"clients": 3, "reconnects": 12}
    assert_structured(rec)
    assert ca.recommend_aps([group]) == (rec,)


def test_rule_infrastructure_likely_does_not_trigger() -> None:
    elevated = {M1: 3, M2: 4, M3: 5}
    # NI already has a root: no double alarm
    assert ca.rule_infrastructure_likely(ca.ApReconnects(AP1, elevated, True)) is None
    # unknown whether NI had a root: no statement
    assert ca.rule_infrastructure_likely(ca.ApReconnects(AP1, elevated, None)) is None
    two = ca.ApReconnects(AP1, {M1: 3, M2: 4, M3: 2}, False)
    assert ca.rule_infrastructure_likely(two) is None
    assert ca.recommend_aps([]) == ()


def test_ap_reconnects_from_history() -> None:
    hist = ClientHistory()
    events = tuple(ClientEvent(mac, "reconnect", T0 + 30, AP1) for mac in (M1, M1, M2))
    hist.ingest(
        PollInput(
            router=AP1,
            now=T0 + 60,
            interval=60,
            fresh=True,
            clients=(ClientObs(M1), ClientObs(M2)),
            events=events,
        )
    )
    assert ca.ap_reconnects(hist, T0 + 120) == {AP1: {M1: 2, M2: 1}}
    assert ca.ap_reconnects(hist, T0 + 3 * DAY) == {}


def test_recommend_client_with_missing_data_says_nothing() -> None:
    assert ca.recommend_client(ca.ClientFindings(M1)) == ()
    unknown = ca.ClientFindings(
        M1,
        stats_24h=stats(Bucket()),
        time_pattern=TimePatternResult(STATUS_INSUFFICIENT),
        ap_pattern=ca.ApPatternResult(STATUS_INSUFFICIENT),
        roam_burst=ca.RoamBurst(False),
        attribution=ca.attribute_disconnects([], {}),
    )
    assert ca.recommend_client(unknown) == ()


def test_recommend_client_collects_rules_and_kinds_stay_apart() -> None:
    findings = ca.ClientFindings(
        M1,
        stats_24h=bad_day(),
        time_pattern=time_pattern_from_meta(
            meta_days(10, {i: {3: 1} for i in (0, 2, 4, 6, 8)}), UTC
        ),
        ap_pattern=ca.ap_pattern_from_buckets(
            {AP1: online_bucket(48, dc_error=4), AP2: online_bucket(48)}
        ),
        roam_burst=ca.roam_burst(alternating(8, 200)),
        attribution=ca.attribute_disconnects(
            [end(DC_INFRA, "inc-1")],
            {"inc-1": ca.IncidentRef("inc-1", ca.CAUSE_CONFIRMED)},
        ),
    )
    recs = ca.recommend_client(findings)
    assert [r.key for r in recs] == [
        ca.REC_CHECK_COVERAGE,
        ca.REC_CHECK_ROAMING,
        ca.REC_CHECK_SCHEDULE,
        ca.REC_CHECK_AP,
        ca.REC_INFRA_CAUSE,
    ]
    for rec in recs:
        assert_structured(rec)
        assert rec.subject == M1
    kinds = {r.key: r.kind for r in recs}
    assert kinds[ca.REC_INFRA_CAUSE] == ca.KIND_CONFIRMED
    assert all(
        k == ca.KIND_HYPOTHESIS for key, k in kinds.items() if key != ca.REC_INFRA_CAUSE
    )


# --- 1.43: window edges, trailing hour, timeline start state --------------------


def online_for(hist: ClientHistory, start: float, end: float, **kw) -> None:
    t = start
    while t <= end:
        hist.ingest(PollInput(AP1, t, 60.0, True, (ClientObs(M1, "5g", -50, **kw),)))
        t += 60.0


def test_bucket_windows_are_aligned_to_the_clock_hour() -> None:
    """Documented edge: ``collect_window`` sums whole hour buckets, so ``1 h``
    is only the current clock hour and ``24 h`` is 23 h plus that hour."""
    hist = ClientHistory()
    now = T0 + 600  # T0 is an hour border
    online_for(hist, T0 - 30 * 3600, now)
    hour = collect_window(hist, M1, now, 1)
    assert hour.window_s == 600 and hour.bucket.observed_s == 600
    assert hour.start == T0
    day = collect_window(hist, M1, now, 24)
    assert day.window_s == 23 * 3600 + 600
    assert day.start == T0 - 23 * 3600


def test_trailing_hour_covers_the_last_60_minutes() -> None:
    hist = ClientHistory()
    now = T0 + 600
    online_for(hist, T0 - 30 * 3600, now, ip_visible=True)
    win = ca.collect_trailing_hour(hist, M1, now)
    assert win.start == now - 3600 and win.window_s == 3600
    assert win.bucket.observed_s == win.bucket.online_s == 3600
    assert win.availability == 1.0 and win.coverage == 1.0
    assert win.bucket.rssi_n == 61 and win.bucket.rssi_sum == -50 * 61
    assert win.bucket.ip_visible_n == 61
    assert win.memory_from is None
    assert ca.collect_trailing_hour(hist, "AA:BB:CC:00:00:99", now) is None


def test_trailing_hour_counts_disconnects_and_log_events() -> None:
    hist = ClientHistory()
    online_for(hist, T0 - 7200, T0 - 1800)
    end = T0 - 1800
    ev = (
        ClientEvent(M1, "disconnect", end + 30, AP1, reason="timeout"),
        ClientEvent(M1, "auth_fail", end + 40, AP1, count=2),
    )
    hist.ingest(PollInput(AP1, end + 60, 60.0, True, (), ev))
    t = end + 120
    while t <= T0:  # offline from end + 30 on
        hist.ingest(PollInput(AP1, t, 60.0, True, ()))
        t += 60
    win = ca.collect_trailing_hour(hist, M1, T0)
    b = win.bucket
    assert b.dc_error == 1 and b.auth_fail == 2
    assert b.online_s == pytest.approx(1830, abs=1)
    assert b.observed_s == pytest.approx(3600, abs=1)
    assert win.availability == pytest.approx(1830 / 3600, abs=0.001)
    # the finished session ended in the window: it counts for the mean
    assert b.session_s_sum == pytest.approx(5430, abs=1)
    assert sum(win.session_hist) == 1


def test_trailing_hour_after_a_restart_has_no_samples_before_it() -> None:
    hist = ClientHistory()
    now = T0 + 600
    online_for(hist, T0 - 30 * 3600, now)
    loaded = ClientHistory.from_dict(hist.to_dict())
    later = now + 1200  # HA was down for 20 minutes
    loaded.ingest(PollInput(AP1, later, 60.0, True, (ClientObs(M1, "5g", -50),)))
    win = ca.collect_trailing_hour(loaded, M1, later, memory_from=later)
    assert win.memory_from == later
    assert win.bucket.rssi_n == 1  # only the sample after the restart
    assert win.bucket.gap_s == pytest.approx(1200, abs=1)
    assert win.bucket.online_s == pytest.approx(2400, abs=1)
    # memory older than the window start is no limit
    full = ca.collect_trailing_hour(loaded, M1, later, memory_from=later - 7200)
    assert full.memory_from is None


def test_timeline_of_a_long_session_without_transitions_is_online() -> None:
    hist = ClientHistory()
    now = T0 + 600
    online_for(hist, T0 - 30 * 3600, now)
    hist.prune(now)  # the start transition is older than 24 h
    assert hist.transitions(M1) == ()
    live = hist.live(M1)
    segments = ca.timeline_segments(hist.transitions(M1), now - 3600, now, live)
    assert segments == [(now - 3600, now, "online")]


def test_timeline_before_the_first_sighting_is_unknown() -> None:
    hist = ClientHistory()
    online_for(hist, T0, T0 + 600)
    live = hist.live(M1)
    segments = ca.timeline_segments(hist.transitions(M1), T0 - 600, T0 + 600, live)
    assert segments == [(T0 - 600, T0, "unknown"), (T0, T0 + 600, "online")]


def test_timeline_start_state_is_inferred_from_the_first_transition() -> None:
    live = None
    trs = [Transition(T0 + 100, TR_END, AP1, "timeout", "error")]
    segments = ca.timeline_segments(trs, T0, T0 + 200, live)
    assert segments == [(T0, T0 + 100, "online"), (T0 + 100, T0 + 200, "offline")]
