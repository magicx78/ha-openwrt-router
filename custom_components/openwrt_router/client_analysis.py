"""Client stability analysis: score, time pattern and signal trend (B3).

Pure module, no Home Assistant imports; it only reads the B1 history
(``client_history``). Time is never read from the clock: ``now`` and the time
zone are passed in.

Plan ``docs/plans/2026-11-16-client-stability.md`` section 3 (score) and 5
(time pattern, signal trend). The AP-specific pattern, the AP comparison and
the recommendations are B4 and not part of this module.

Rules carried over from the plan:

* missing data is ``unknown``, never 100 (availability with no observed time
  is None; score with coverage below 0.5 is None / class ``unknown``);
* normal roaming costs nothing (only ping-pong flaps, part M);
* ``infra`` disconnects cost nothing;
* every hypothesis (cause of a pattern or trend) has confidence <= 0.6.

[CS-Entscheidung] Time zone: ``time_pattern`` takes a ``datetime.tzinfo``
(``datetime.timezone`` or ``zoneinfo.ZoneInfo``; B2 passes the HA time zone).
UTC hour cells of ``day_meta`` are converted with ``datetime.fromtimestamp``
(pure arithmetic, no clock read). On a DST fall-back day two UTC hours fall
into the same local hour; they are merged (coverage OR, disconnects summed).
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, tzinfo
from itertools import pairwise

from .client_history import (
    SESSION_BIN_HOURS,
    STATE_OFFLINE,
    TR_END,
    TR_START,
    Bucket,
    ClientHistory,
    DayMeta,
    band_online,
    session_histogram,
    sum_buckets,
)

_LOGGER = logging.getLogger(__name__)

_HOUR = 3600
_DAY = 86400

# --- Settings ----------------------------------------------------------------

PART_D = "disconnects"
PART_R = "reconnects"
PART_U = "uptime"
PART_S = "signal"
PART_A = "auth"
PART_M = "roaming"
PART_W = "recurring"
PARTS: tuple[str, ...] = (PART_D, PART_R, PART_U, PART_S, PART_A, PART_M, PART_W)

DEFAULT_WEIGHTS: Mapping[str, float] = {
    PART_D: 30.0,
    PART_R: 15.0,
    PART_U: 15.0,
    PART_S: 20.0,
    PART_A: 10.0,
    PART_M: 5.0,
    PART_W: 5.0,
}
DEFAULT_CLASSES: tuple[float, float, float, float] = (90.0, 75.0, 50.0, 25.0)

CLASS_VERY_STABLE = "very_stable"
CLASS_STABLE = "stable"
CLASS_NOTICEABLE = "noticeable"
CLASS_UNSTABLE = "unstable"
CLASS_CRITICAL = "critical"
CLASS_UNKNOWN = "unknown"
CLASS_NAMES: tuple[str, ...] = (
    CLASS_VERY_STABLE,
    CLASS_STABLE,
    CLASS_NOTICEABLE,
    CLASS_UNSTABLE,
    CLASS_CRITICAL,
)

# Disconnect weights of part D (plan 3); infra costs nothing.
DC_WEIGHTS: Mapping[str, float] = {
    "dc_error": 1.0,
    "dc_unknown": 0.75,
    "dc_inactivity": 0.5,
    "dc_leave": 0.25,
    "dc_infra": 0.0,
}

PART_MIN_COVERAGE = 0.3  # a part with less coverage is left out
SCORE_MIN_COVERAGE = 0.5  # below this the score is unknown
SIGNAL_MIN_SAMPLES = 10
UPTIME_MIN_SESSION_S = 3600.0
UPTIME_FULL_H = 6.0  # median session of 6 h gives 100
RECURRING_MIN_DAYS = 3
TREND_ARROW_POINTS = 10.0

HYPOTHESIS_MAX_CONFIDENCE = 0.6

# Time pattern (plan 5)
PATTERN_MIN_DAYS = 7
PATTERN_MIN_HIT_DAYS = 4
PATTERN_MIN_HIT_SHARE = 0.5
PATTERN_RATE_FACTOR = 3.0

# Signal trend (plan 5)
TREND_LONG_DAYS = 7
TREND_SHORT_DAYS = 3
TREND_MIN_SAMPLES = 100
TREND_MIN_COVERAGE = 0.5
TREND_MIN_SAME_AP = 0.7
TREND_DEGRADED_DB = -6.0

STATUS_FOUND = "found"
STATUS_NOT_FOUND = "not_found"
STATUS_INSUFFICIENT = "insufficient"
STATUS_DEGRADED = "degraded"
STATUS_NO_TREND = "no_trend"
STATUS_NOT_COMPARABLE = "not_comparable"

REASON_TOO_SHORT = "too_short"
REASON_FEW_SAMPLES = "few_samples"
REASON_LOW_COVERAGE = "low_coverage"
REASON_AP_CHANGED = "ap_changed"
# [CS-Entscheidung] Band problems get their own reasons: the panel can then
# say "band changed" vs. "band not reported" instead of a generic AP change.
REASON_BAND_CHANGED = "band_changed"
REASON_BAND_UNKNOWN = "band_unknown"


def cap_confidence(value: float) -> float:
    """Clamp a hypothesis confidence to ``[0, 0.6]``."""
    if not isinstance(value, (int, float)) or not math.isfinite(value):
        return 0.0
    return max(0.0, min(HYPOTHESIS_MAX_CONFIDENCE, float(value)))


@dataclass(frozen=True, slots=True)
class ScoreSettings:
    """Weights, class thresholds and the per-client ``sleepy`` option."""

    weights: Mapping[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    classes: tuple[float, float, float, float] = DEFAULT_CLASSES
    sleepy: bool = False


def _valid_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def make_settings(
    weights: Mapping[str, object] | None = None,
    classes: Iterable[object] | None = None,
    sleepy: bool = False,
) -> ScoreSettings:
    """Validated settings; invalid parts fall back to the defaults.

    Weights: known parts only, each finite and >= 0; unknown keys are ignored,
    invalid values keep the default; if all weights end up 0 the defaults are
    used. Classes: exactly four finite numbers, strictly descending, inside
    ``(0, 100]``; otherwise the defaults.
    """
    merged = dict(DEFAULT_WEIGHTS)
    if isinstance(weights, Mapping):
        for key, value in weights.items():
            if key in merged and _valid_number(value) and value >= 0:
                merged[key] = float(value)
    if sum(merged.values()) <= 0:
        merged = dict(DEFAULT_WEIGHTS)
    return ScoreSettings(merged, _valid_classes(classes), bool(sleepy))


def _valid_classes(raw: Iterable[object] | None) -> tuple[float, float, float, float]:
    if raw is None or isinstance(raw, (str, bytes)):
        return DEFAULT_CLASSES
    try:
        values = list(raw)
    except TypeError:
        return DEFAULT_CLASSES
    if len(values) != 4 or not all(_valid_number(v) for v in values):
        return DEFAULT_CLASSES
    nums = [float(v) for v in values]
    if not all(0 < v <= 100 for v in nums):
        return DEFAULT_CLASSES
    if any(a <= b for a, b in pairwise(nums)):
        return DEFAULT_CLASSES
    return (nums[0], nums[1], nums[2], nums[3])


def classify_score(
    score: float | None, classes: tuple[float, float, float, float] = DEFAULT_CLASSES
) -> str:
    """Class name of a score; ``unknown`` for None."""
    if score is None or not math.isfinite(score):
        return CLASS_UNKNOWN
    for threshold, name in zip(classes, CLASS_NAMES, strict=False):
        if score >= threshold:
            return name
    return CLASS_CRITICAL


# --- Sub-scores (plan 3) -------------------------------------------------------


def score_disconnects(x: float) -> float:
    """D: ``100 * e^(-x/4)``, x = weighted disconnects per 24 online hours."""
    return 100.0 * math.exp(-max(0.0, x) / 4.0)


def score_reconnects(x: float) -> float:
    """R: ``100 * e^(-x/3)``, x = reconnects per 24 online hours."""
    return 100.0 * math.exp(-max(0.0, x) / 3.0)


def score_uptime(median_h: float) -> float:
    """U: ``100 * min(1, ln(1+x) / ln(1+6))``, x = median session hours."""
    return 100.0 * min(1.0, math.log1p(max(0.0, median_h)) / math.log1p(UPTIME_FULL_H))


def score_signal(mean_dbm: float, weak_share: float) -> float:
    """S: ``100 * clamp((m+85)/25) * (1 - 0.5*q)``."""
    q = max(0.0, min(1.0, weak_share))
    return 100.0 * max(0.0, min(1.0, (mean_dbm + 85.0) / 25.0)) * (1.0 - 0.5 * q)


def score_auth(x: float) -> float:
    """A: ``100 * e^(-x/2)``, x = failed attempts per 24 online hours."""
    return 100.0 * math.exp(-max(0.0, x) / 2.0)


def score_roaming(x: float) -> float:
    """M: ``100 * e^(-x/3)``, x = ping-pong flaps per 24 online hours."""
    return 100.0 * math.exp(-max(0.0, x) / 3.0)


def score_recurring(n: int) -> float:
    """W: ``100 - 35 * min(n, 3)``, never below 0."""
    return max(0.0, 100.0 - 35.0 * min(max(0, n), 3))


# --- Window statistics ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WindowStats:
    """Everything the score needs about one client and one time window.

    ``window_s`` is the window length, cut to the time since the client was
    first seen. ``sessions_h`` are exact finished session lengths and
    ``session_hist`` the counts per duration bin of the B1 buckets
    (``client_history.SESSION_BIN_HOURS``); both describe sessions that ended
    inside the window. ``ongoing_h`` is the running session (a lower bound)
    or None.
    ``log_coverage`` is the log coverage of the client's router (0..1, None =
    no log, parts R/A/M unknown). ``patterns`` is the number of active
    recurring patterns, ``data_days`` the number of days with observed data.
    """

    window_s: float
    bucket: Bucket
    sessions_h: tuple[float, ...] = ()
    ongoing_h: float | None = None
    session_hist: tuple[int, ...] = ()
    log_coverage: float | None = None
    patterns: int = 0
    data_days: int = 0

    @property
    def coverage(self) -> float:
        """Observed share of the window (0..1)."""
        if self.window_s <= 0:
            return 0.0
        return max(0.0, min(1.0, self.bucket.observed_s / self.window_s))

    @property
    def availability(self) -> float | None:
        """``online_s / observed_s``; None (unknown) without observed time."""
        if self.bucket.observed_s <= 0:
            return None
        return min(1.0, self.bucket.online_s / self.bucket.observed_s)


@dataclass(frozen=True, slots=True)
class PartResult:
    """One sub-score: value s (0..100 or None), coverage c, metric x."""

    value: float | None
    coverage: float
    metric: float | None
    included: bool


@dataclass(frozen=True, slots=True)
class ScoreResult:
    """Score (None = unknown), class, overall coverage and the parts."""

    score: float | None
    cls: str
    coverage: float
    parts: Mapping[str, PartResult]


def weighted_median(items: Iterable[tuple[float, int]]) -> float:
    """Median of ``(value, count)`` pairs; the mean of the two middle values
    for an even total, like ``statistics.median``."""
    pairs = sorted((float(v), int(n)) for v, n in items if n > 0)
    total = sum(n for _v, n in pairs)
    if total <= 0:
        return 0.0
    want = ((total - 1) // 2, total // 2)
    picked: list[float] = []
    seen = 0
    for value, n in pairs:
        while len(picked) < 2 and want[len(picked)] < seen + n:
            picked.append(value)
        seen += n
    return (picked[0] + picked[1]) / 2


def _per_day(count: float, online_s: float) -> float:
    return count * _DAY / online_s


def score_window(
    stats: WindowStats, settings: ScoreSettings | None = None
) -> ScoreResult:
    """Score of one window (plan 3)."""
    settings = settings or ScoreSettings()
    b = stats.bucket
    online = float(b.online_s)
    log_c = (
        max(0.0, min(1.0, float(stats.log_coverage)))
        if stats.log_coverage is not None and _valid_number(stats.log_coverage)
        else 0.0
    )
    raw: dict[str, tuple[float | None, float, float | None]] = {}

    # D: disconnects
    if online > 0:
        weights = dict(DC_WEIGHTS)
        if settings.sleepy:
            weights["dc_inactivity"] = 0.0
        weighted = sum(getattr(b, name) * w for name, w in weights.items())
        x = _per_day(weighted, online)
        raw[PART_D] = (score_disconnects(x), stats.coverage, x)
    else:
        raw[PART_D] = (None, 0.0, None)

    # R, A, M: log based, rates per 24 online hours
    for part, count, fn in (
        (PART_R, b.reconnects, score_reconnects),
        (PART_A, b.auth_fail + b.assoc_fail, score_auth),
        (PART_M, b.roam_flaps, score_roaming),
    ):
        if online > 0 and log_c > 0:
            x = _per_day(count, online)
            raw[part] = (fn(x), log_c, x)
        else:
            raw[part] = (None, 0.0, None)

    # U: median stable session (finished plus running, lower bound)
    hist = [
        (SESSION_BIN_HOURS[i], int(n))
        for i, n in enumerate(stats.session_hist[: len(SESSION_BIN_HOURS)])
        if n > 0
    ]
    lengths: list[tuple[float, int]] = [(h, 1) for h in stats.sessions_h if h >= 0]
    lengths += hist
    if stats.ongoing_h is not None and stats.ongoing_h >= 0:
        lengths.append((stats.ongoing_h, 1))
    long_enough = (
        stats.ongoing_h is not None
        or any(h * _HOUR >= UPTIME_MIN_SESSION_S for h in stats.sessions_h)
        or any(h * _HOUR >= UPTIME_MIN_SESSION_S for h, _n in hist)
    )
    if lengths and long_enough:
        med = weighted_median(lengths)
        raw[PART_U] = (score_uptime(med), 1.0, med)
    else:
        raw[PART_U] = (None, 0.0, None)

    # S: signal
    if b.rssi_n >= SIGNAL_MIN_SAMPLES:
        mean = b.rssi_sum / b.rssi_n
        weak = b.weak_s / online if online > 0 else 0.0
        raw[PART_S] = (score_signal(mean, weak), 1.0, mean)
    else:
        raw[PART_S] = (None, 0.0, None)

    # W: recurring patterns
    if stats.data_days >= RECURRING_MIN_DAYS:
        raw[PART_W] = (score_recurring(stats.patterns), 1.0, float(stats.patterns))
    else:
        raw[PART_W] = (None, 0.0, None)

    parts: dict[str, PartResult] = {}
    num = den = 0.0
    total_w = sum(settings.weights.get(p, 0.0) for p in PARTS)
    for part in PARTS:
        value, cov, metric = raw[part]
        weight = settings.weights.get(part, 0.0)
        included = value is not None and cov >= PART_MIN_COVERAGE and weight > 0
        parts[part] = PartResult(
            value, cov if value is not None else 0.0, metric, included
        )
        if included and value is not None:
            num += weight * cov * value
            den += weight * cov
    # [CS-Entscheidung] Parts left out (c < 0.3) add nothing to the coverage.
    coverage = den / total_w if total_w > 0 else 0.0
    if den <= 0 or coverage < SCORE_MIN_COVERAGE:
        return ScoreResult(None, CLASS_UNKNOWN, coverage, parts)
    score = num / den
    return ScoreResult(score, classify_score(score, settings.classes), coverage, parts)


def score_trend(current: float | None, previous: float | None) -> str | None:
    """Table arrow: ``up``/``down`` at >= 10 points, ``flat`` else, None if unknown."""
    if current is None or previous is None:
        return None
    delta = current - previous
    if delta >= TREND_ARROW_POINTS:
        return "up"
    if delta <= -TREND_ARROW_POINTS:
        return "down"
    return "flat"


def collect_window(
    history: ClientHistory,
    mac: str,
    now: float,
    hours: int = 24,
    *,
    end: float | None = None,
    log_coverage: float | None = None,
    patterns: int = 0,
) -> WindowStats | None:
    """Window statistics from the hour buckets (up to 7 days).

    The window ends at ``end`` (default ``now``) and covers the ``hours``
    hour buckets before it (the last one may be partial). [CS-Entscheidung]
    Windows are aligned to whole hour buckets at the start. Finished sessions
    come from the bucket duration histograms. None for an unknown MAC.
    """
    live = history.live(mac)
    if live is None:
        return None
    end = now if end is None else end
    hours = max(1, min(int(hours), 168))
    last = math.ceil(end / _HOUR) - 1
    first = last - hours + 1
    start = first * _HOUR
    bucket = sum_buckets(b.bucket for b in history.hours(mac, first, last))
    return _stats(
        history,
        mac,
        live_first=live.first_seen,
        start=start,
        end=end,
        now=now,
        bucket=bucket,
        log_coverage=log_coverage,
        patterns=patterns,
    )


def collect_window_days(
    history: ClientHistory,
    mac: str,
    now: float,
    days: int = 30,
    *,
    log_coverage: float | None = None,
    patterns: int = 0,
) -> WindowStats | None:
    """Window statistics from the day buckets plus still open hours (30 d)."""
    live = history.live(mac)
    if live is None:
        return None
    days = max(1, int(days))
    first_day = int(now // _DAY) - days + 1
    closed = [b.bucket for b in history.days(mac, first_day)]
    open_hours = [b.bucket for b in history.hours(mac, first_day * 24) if not b.closed]
    bucket = sum_buckets([*closed, *open_hours])
    return _stats(
        history,
        mac,
        live_first=live.first_seen,
        start=first_day * _DAY,
        end=now,
        now=now,
        bucket=bucket,
        log_coverage=log_coverage,
        patterns=patterns,
    )


def _stats(
    history: ClientHistory,
    mac: str,
    *,
    live_first: float | None,
    start: float,
    end: float,
    now: float,
    bucket: Bucket,
    log_coverage: float | None,
    patterns: int,
) -> WindowStats:
    # "Abdeckung = observed / Fensterlänge (seit erstem Sehen)"
    begin = max(start, live_first) if live_first is not None else start
    window_s = max(0.0, end - begin)
    # [CS-Entscheidung] Finished sessions come from the duration histogram of
    # the buckets (any window, also beyond the 24 h of stored transitions);
    # the exact lengths of ``session_lengths`` stay for the detail view.
    _sessions, ongoing = session_lengths(history, mac, start, end, now)
    return WindowStats(
        window_s=window_s,
        bucket=bucket,
        session_hist=session_histogram(bucket),
        ongoing_h=ongoing / _HOUR if ongoing is not None else None,
        log_coverage=log_coverage,
        patterns=patterns,
        data_days=data_days(history, mac),
    )


def session_lengths(
    history: ClientHistory, mac: str, start: float, end: float, now: float
) -> tuple[list[float], float | None]:
    """Finished sessions (seconds) ending in ``[start, end]`` and the running
    session length (only when ``end >= now``)."""
    out: list[float] = []
    begin: float | None = None
    for tr in history.transitions(mac):
        if tr.kind == TR_START:
            begin = tr.ts
        elif tr.kind == TR_END:
            if begin is not None and start <= tr.ts <= end and tr.ts >= begin:
                out.append(tr.ts - begin)
            begin = None
    ongoing: float | None = None
    live = history.live(mac)
    if (
        live is not None
        and end >= now
        and live.state != STATE_OFFLINE
        and live.session_start is not None
    ):
        ongoing = max(0.0, now - live.session_start)
    return out, ongoing


def data_days(history: ClientHistory, mac: str) -> int:
    """Days with observed time (from day buckets and open hours)."""
    days = {d.day for d in history.days(mac) if d.bucket.observed_s > 0}
    days |= {h.hour // 24 for h in history.hours(mac) if h.bucket.observed_s > 0}
    return len(days)


# --- Time pattern (plan 5) -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HourPattern:
    """One local hour with recurring disconnects (observed)."""

    hour: int
    hit_days: int
    covered_days: int
    rate: float
    other_rate: float
    confidence: float  # of the cause hypothesis, <= 0.6


@dataclass(frozen=True, slots=True)
class TimePatternResult:
    """``found`` / ``not_found`` / ``insufficient`` (not enough covered days)."""

    status: str
    hours: tuple[HourPattern, ...] = ()
    max_covered_days: int = 0


def local_cells(
    meta: Mapping[int, DayMeta], tz: tzinfo
) -> dict[tuple[date, int], tuple[bool, int]]:
    """UTC day meta as ``(local date, local hour) -> (covered, disconnects)``."""
    cells: dict[tuple[date, int], tuple[bool, int]] = {}
    for day, dm in meta.items():
        for utc_hour in range(24):
            covered = bool(dm.coverage_mask & (1 << utc_hour))
            dc = int(dm.disconnects.get(utc_hour, 0))
            if not covered and not dc:
                continue
            local = datetime.fromtimestamp((day * 24 + utc_hour) * _HOUR, tz)
            key = (local.date(), local.hour)
            old_cov, old_dc = cells.get(key, (False, 0))
            cells[key] = (old_cov or covered, old_dc + dc)
    return cells


def time_pattern_from_meta(
    meta: Mapping[int, DayMeta], tz: tzinfo
) -> TimePatternResult:
    """Recurring disconnects at a local hour (plan 5).

    Hour h is a pattern when it is covered (>= 80 % observed) on at least 7
    days, has disconnects on at least 4 of them and on at least 50 % of the
    covered days, and its rate (disconnects per covered day) is at least 3x
    the mean rate of the other hours. [CS-Entscheidung] Only disconnects in
    covered cells count; the "mean of the other hours" is the mean over the
    other hours that are covered on at least one day.
    """
    cells = local_cells(meta, tz)
    covered = [0] * 24
    hits = [0] * 24
    counts = [0] * 24
    for (_day, hour), (cov, dc) in cells.items():
        if not cov:
            continue
        covered[hour] += 1
        counts[hour] += dc
        if dc > 0:
            hits[hour] += 1
    rates = [counts[h] / covered[h] if covered[h] else None for h in range(24)]
    best = max(covered)
    if best < PATTERN_MIN_DAYS:
        return TimePatternResult(STATUS_INSUFFICIENT, (), best)
    found: list[HourPattern] = []
    for h in range(24):
        if covered[h] < PATTERN_MIN_DAYS or hits[h] < PATTERN_MIN_HIT_DAYS:
            continue
        share = hits[h] / covered[h]
        if share < PATTERN_MIN_HIT_SHARE:
            continue
        others = [r for i, r in enumerate(rates) if i != h and r is not None]
        other = sum(others) / len(others) if others else 0.0
        rate = rates[h] or 0.0
        if rate < PATTERN_RATE_FACTOR * other:
            continue
        found.append(
            HourPattern(h, hits[h], covered[h], rate, other, cap_confidence(share))
        )
    status = STATUS_FOUND if found else STATUS_NOT_FOUND
    return TimePatternResult(status, tuple(found), best)


def time_pattern(history: ClientHistory, mac: str, tz: tzinfo) -> TimePatternResult:
    """Time pattern of one client (empty history: ``insufficient``)."""
    return time_pattern_from_meta(history.day_meta(mac), tz)


# --- Signal trend (plan 5) ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SignalTrend:
    """Signal trend of the oldest vs. the newest window.

    ``status`` is ``degraded`` (mean <= -6 dB), ``no_trend`` or
    ``not_comparable`` with ``reason``. ``confidence`` belongs to the cause
    hypothesis and is at most 0.6.
    """

    status: str
    reason: str | None = None
    window_days: int = 0
    ap: str | None = None
    mean_a: float | None = None
    mean_b: float | None = None
    delta_db: float | None = None
    confidence: float = 0.0


def daily_by_ap(history: ClientHistory, mac: str) -> dict[int, dict[str, Bucket]]:
    """Day -> AP -> bucket, from day buckets plus still open hours."""
    out: dict[int, dict[str, Bucket]] = {}
    for d in history.days(mac):
        out.setdefault(d.day, {})[d.ap] = d.bucket
    for h in history.hours(mac):
        if h.closed:
            continue
        per_ap = out.setdefault(h.hour // 24, {})
        prev = per_ap.get(h.ap)
        per_ap[h.ap] = h.bucket if prev is None else sum_buckets([prev, h.bucket])
    return out


def signal_trend_from_days(
    per_day: Mapping[int, Mapping[str, Bucket]], today: int
) -> SignalTrend:
    """Compare window A (oldest days) with window B (newest days).

    With at least 14 days of data span: 7 vs 7 days, else with at least 6
    days: 3 vs 3, else not comparable. Each window needs >= 100 RSSI values,
    observed coverage >= 0.5 and >= 70 % of its online time at the same AP and
    band in both windows (first the AP, then the band at that AP).
    [CS-Entscheidung] The means are taken at that common AP only (B1 RSSI
    sums are per AP, not per band).
    """
    days = sorted(
        d for d, aps in per_day.items() if any(b.observed_s for b in aps.values())
    )
    if not days:
        return SignalTrend(STATUS_NOT_COMPARABLE, REASON_TOO_SHORT)
    span = today - days[0] + 1
    if span >= 2 * TREND_LONG_DAYS:
        n = TREND_LONG_DAYS
    elif span >= 2 * TREND_SHORT_DAYS:
        n = TREND_SHORT_DAYS
    else:
        return SignalTrend(STATUS_NOT_COMPARABLE, REASON_TOO_SHORT)
    first = days[0]
    win_a = range(first, first + n)
    win_b = range(today - n + 1, today + 1)
    a = _window_by_ap(per_day, win_a)
    b = _window_by_ap(per_day, win_b)
    for win in (a, b):
        total = sum_buckets(win.values())
        if total.observed_s < TREND_MIN_COVERAGE * n * _DAY:
            return SignalTrend(STATUS_NOT_COMPARABLE, REASON_LOW_COVERAGE, n)
    ap_a, share_a = _dominant(a)
    ap_b, share_b = _dominant(b)
    if (
        ap_a is None
        or ap_a != ap_b
        or share_a < TREND_MIN_SAME_AP
        or share_b < TREND_MIN_SAME_AP
    ):
        return SignalTrend(STATUS_NOT_COMPARABLE, REASON_AP_CHANGED, n, ap_a)
    band_reason = _band_check(a, b, ap_a)
    if band_reason is not None:
        return SignalTrend(STATUS_NOT_COMPARABLE, band_reason, n, ap_a)
    ba, bb = a[ap_a], b[ap_a]
    if ba.rssi_n < TREND_MIN_SAMPLES or bb.rssi_n < TREND_MIN_SAMPLES:
        return SignalTrend(STATUS_NOT_COMPARABLE, REASON_FEW_SAMPLES, n, ap_a)
    mean_a = ba.rssi_sum / ba.rssi_n
    mean_b = bb.rssi_sum / bb.rssi_n
    delta = mean_b - mean_a
    if delta <= TREND_DEGRADED_DB:
        # [CS-Entscheidung] confidence grows with the drop, capped at 0.6
        conf = cap_confidence(0.3 + 0.3 * min(1.0, delta / (2 * TREND_DEGRADED_DB)))
        return SignalTrend(STATUS_DEGRADED, None, n, ap_a, mean_a, mean_b, delta, conf)
    return SignalTrend(STATUS_NO_TREND, None, n, ap_a, mean_a, mean_b, delta, 0.0)


def _window_by_ap(
    per_day: Mapping[int, Mapping[str, Bucket]], window: range
) -> dict[str, Bucket]:
    grouped: dict[str, list[Bucket]] = {}
    for day in window:
        for ap, bucket in per_day.get(day, {}).items():
            grouped.setdefault(ap, []).append(bucket)
    return {ap: sum_buckets(items) for ap, items in grouped.items()}


def _dominant_band(win: Mapping[str, Bucket], ap: str) -> tuple[str | None, float]:
    """Band with the most online time at ``ap`` and its share of all online
    time of the window (all APs); None when no band was reported."""
    total = sum(b.online_s for k, b in win.items() if k)
    per_band = band_online(win[ap])
    if total <= 0 or not any(per_band.values()):
        return None, 0.0
    band = max(sorted(per_band), key=lambda k: per_band[k])
    return band, per_band[band] / total


def _band_check(
    a: Mapping[str, Bucket], b: Mapping[str, Bucket], ap: str
) -> str | None:
    """None when both windows spend >= 70 % at ``ap`` on the same band."""
    band_a, share_a = _dominant_band(a, ap)
    band_b, share_b = _dominant_band(b, ap)
    if band_a is None or band_b is None:
        return REASON_BAND_UNKNOWN
    if band_a != band_b or min(share_a, share_b) < TREND_MIN_SAME_AP:
        return REASON_BAND_CHANGED
    return None


def _dominant(win: Mapping[str, Bucket]) -> tuple[str | None, float]:
    """AP ("" = offline excluded) with the largest share of online time."""
    online = {ap: b.online_s for ap, b in win.items() if ap and b.online_s > 0}
    total = sum(online.values())
    if total <= 0:
        return None, 0.0
    ap = max(sorted(online), key=lambda k: online[k])
    return ap, online[ap] / total


def signal_trend(history: ClientHistory, mac: str, now: float) -> SignalTrend:
    """Signal trend of one client."""
    return signal_trend_from_days(daily_by_ap(history, mac), int(now // _DAY))


def active_patterns(pattern: TimePatternResult, trend: SignalTrend) -> int:
    """Number of active recurring patterns for part W (B4 adds AP-specific)."""
    return int(pattern.status == STATUS_FOUND) + int(trend.status == STATUS_DEGRADED)
