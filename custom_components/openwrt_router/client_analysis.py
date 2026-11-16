"""Client stability analysis: score, patterns, AP comparison, advice (B3, B4).

Pure module, no Home Assistant imports; it only reads the B1 history
(``client_history``). Time is never read from the clock: ``now`` and the time
zone are passed in.

Plan ``docs/plans/2026-11-16-client-stability.md`` section 3 (score), 5
(time pattern, signal trend, AP-specific pattern, shared disconnects), 6 (AP
comparison) and 7 (recommendations). NI data (incident windows and
``cause_status``, open roots per AP, roam events) is not read here: B2 passes
it in through the typed inputs :class:`IncidentRef`, :class:`ApReconnects`
and :class:`RoamStep`.

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
from dataclasses import dataclass, field, replace
from datetime import date, datetime, tzinfo
from itertools import pairwise

from .client_history import (
    DC_ERROR,
    DC_INFRA,
    DC_LEAVE,
    SESSION_BIN_HOURS,
    STATE_OFFLINE,
    TR_END,
    TR_MOVE,
    TR_START,
    Bucket,
    ClientHistory,
    DayMeta,
    Transition,
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


# --- AP-specific pattern (plan 5) ------------------------------------------------

AP_PATTERN_MIN_ONLINE_H = 24.0
AP_PATTERN_FACTOR = 3.0
AP_PATTERN_MIN_DIFF = 0.5  # error disconnects per 24 online hours
AP_PATTERN_DAYS = 30


@dataclass(frozen=True, slots=True)
class ApRate:
    """Observed error disconnects of one client at one AP."""

    ap: str
    online_h: float
    errors: int
    rate: float  # error disconnects per 24 online hours


@dataclass(frozen=True, slots=True)
class ApPatternResult:
    """AP-specific pattern of one client.

    ``found``: the worst AP has >= 3x and >= 0.5 more error disconnects per
    24 online hours than the best one; ``not_found``; ``insufficient``: fewer
    than two APs with >= 24 online hours. The rates are observed, the cause
    (the AP) is a hypothesis with ``confidence`` <= 0.6.
    """

    status: str
    rates: tuple[ApRate, ...] = ()
    worst_ap: str | None = None
    best_ap: str | None = None
    worst_rate: float | None = None
    best_rate: float | None = None
    confidence: float = 0.0


def ap_pattern_from_buckets(per_ap: Mapping[str, Bucket]) -> ApPatternResult:
    """AP-specific pattern from one bucket per AP (``""`` = offline, ignored).

    [CS-Entscheidung] Only ``error`` disconnects count (plan 5); the worst AP
    is compared with the best qualifying AP (plan: "über dem besten"), not
    with the mean of the others.
    """
    rates = tuple(
        ApRate(
            ap, b.online_s / _HOUR, int(b.dc_error), _per_day(b.dc_error, b.online_s)
        )
        for ap, b in sorted(per_ap.items())
        if ap and b.online_s >= AP_PATTERN_MIN_ONLINE_H * _HOUR
    )
    if len(rates) < 2:
        return ApPatternResult(STATUS_INSUFFICIENT, rates)
    worst = max(rates, key=lambda r: (r.rate, r.ap))
    best = min(rates, key=lambda r: (r.rate, r.ap))
    found = (
        worst.rate >= AP_PATTERN_FACTOR * best.rate
        and worst.rate - best.rate >= AP_PATTERN_MIN_DIFF
    )
    if not found:
        return ApPatternResult(
            STATUS_NOT_FOUND, rates, worst.ap, best.ap, worst.rate, best.rate
        )
    # [CS-Entscheidung] confidence grows with the error count at the worst
    # AP (10 errors give the cap of 0.6)
    conf = cap_confidence(0.3 + 0.3 * min(1.0, worst.errors / 10))
    return ApPatternResult(
        STATUS_FOUND, rates, worst.ap, best.ap, worst.rate, best.rate, conf
    )


def ap_buckets(
    history: ClientHistory, mac: str, now: float, days: int = AP_PATTERN_DAYS
) -> dict[str, Bucket]:
    """One bucket per AP over the last ``days`` days (day buckets plus open
    hours, like ``collect_window_days``)."""
    today = int(now // _DAY)
    first_day = today - max(1, int(days)) + 1
    return _window_by_ap(daily_by_ap(history, mac), range(first_day, today + 1))


def ap_pattern(
    history: ClientHistory, mac: str, now: float, days: int = AP_PATTERN_DAYS
) -> ApPatternResult:
    """AP-specific pattern of one client over the last ``days`` days."""
    return ap_pattern_from_buckets(ap_buckets(history, mac, now, days))


def active_patterns(
    pattern: TimePatternResult,
    trend: SignalTrend,
    ap_specific: ApPatternResult | None = None,
) -> int:
    """Number of active recurring patterns for part W."""
    return (
        int(pattern.status == STATUS_FOUND)
        + int(trend.status == STATUS_DEGRADED)
        + int(ap_specific is not None and ap_specific.status == STATUS_FOUND)
    )


# --- Shared disconnects / correlation with NI (plan 5) ---------------------------

CAUSE_CONFIRMED = "confirmed"  # same values as NI ``CauseStatus``
CAUSE_HYPOTHESIS = "hypothesis"

ATTR_INFRASTRUCTURE = "infrastructure"
ATTR_CLIENT = "client"
ATTR_NONE = "none"

KIND_OBSERVATION = "observation"
KIND_HYPOTHESIS = "hypothesis"
KIND_CONFIRMED = "confirmed"

INFRA_SHARE_MIN = 0.5
INFRA_UNKNOWN_CONFIDENCE = 0.3


@dataclass(frozen=True, slots=True)
class IncidentRef:
    """What B2 passes in about one NI root incident (read only).

    ``cause_status`` is NI's ``CauseStatus`` value (``confirmed`` only with
    measured data, else ``hypothesis``; None = unknown). ``confidence`` is
    NI's confidence of a hypothesis.
    """

    incident_id: str
    cause_status: str | None = None
    cause: str | None = None
    confidence: float | None = None


@dataclass(frozen=True, slots=True)
class DisconnectAttribution:
    """Who the disconnects of one client are attributed to.

    ``infra`` are the disconnects tagged with an NI root (class ``infra`` or
    an incident id known to NI); ``client`` the other problem disconnects
    (``error``, ``unknown``, ``inactivity``); ``leaves`` the voluntary ones
    (counted on neither side). ``kind`` is ``confirmed`` only when every
    tagged disconnect belongs to an NI root with ``cause_status=confirmed``;
    else ``hypothesis`` (confidence <= 0.6). The client side is an
    ``observation`` (counts only, no cause).
    """

    attribution: str
    kind: str | None
    confidence: float | None
    infra: int = 0
    client: int = 0
    client_errors: int = 0
    leaves: int = 0
    incidents: tuple[str, ...] = ()
    causes: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        """Problem disconnects (infra plus client side)."""
        return self.infra + self.client


def disconnect_ends(
    history: ClientHistory, mac: str, start: float, end: float
) -> tuple[Transition, ...]:
    """Session ends of one client in ``[start, end]`` (24 h of transitions)."""
    return tuple(
        tr
        for tr in history.transitions(mac)
        if tr.kind == TR_END and start <= tr.ts <= end
    )


def attribute_disconnects(
    ends: Iterable[Transition], incidents: Mapping[str, IncidentRef]
) -> DisconnectAttribution:
    """Attribute session ends to the infrastructure or to the client.

    An end counts for the infrastructure when B1 tagged it ``infra`` or it
    carries an incident id known to NI. [CS-Entscheidung] The client is
    attributed to the infrastructure when at least half of its problem
    disconnects are tagged. Never creates an incident or an event.
    """
    infra = client = errors = leaves = 0
    ids: list[str] = []
    for tr in ends:
        if tr.kind != TR_END:
            continue
        tagged = tr.cls == DC_INFRA or (
            tr.incident_id is not None and tr.incident_id in incidents
        )
        if tagged:
            infra += 1
            ids.append(tr.incident_id or "")
        elif tr.cls == DC_LEAVE:
            leaves += 1
        else:
            client += 1
            errors += int(tr.cls == DC_ERROR)
    known = tuple(sorted({i for i in ids if i}))
    causes = tuple(
        sorted({ref.cause for i in known if (ref := incidents.get(i)) and ref.cause})
    )
    if infra + client == 0:
        return DisconnectAttribution(
            ATTR_NONE, None, None, leaves=leaves, incidents=known
        )
    if infra / (infra + client) < INFRA_SHARE_MIN:
        return DisconnectAttribution(
            ATTR_CLIENT,
            KIND_OBSERVATION,
            None,
            infra,
            client,
            errors,
            leaves,
            known,
            causes,
        )
    refs = [incidents.get(i) if i else None for i in ids]
    if all(r is not None and r.cause_status == CAUSE_CONFIRMED for r in refs):
        kind, conf = KIND_CONFIRMED, 1.0
    else:
        kind = KIND_HYPOTHESIS
        # [CS-Entscheidung] the weakest NI confidence of the involved
        # hypotheses; without NI data 0.3; always capped at 0.6
        values = [
            float(r.confidence)
            for r in refs
            if r is not None
            and r.cause_status != CAUSE_CONFIRMED
            and r.confidence is not None
            and _valid_number(r.confidence)
        ]
        conf = cap_confidence(min(values) if values else INFRA_UNKNOWN_CONFIDENCE)
    return DisconnectAttribution(
        ATTR_INFRASTRUCTURE,
        kind,
        conf,
        infra,
        client,
        errors,
        leaves,
        known,
        causes,
    )


# --- AP comparison (plan 6) ------------------------------------------------------

WINDOW_24H = "24h"
WINDOW_7D = "7d"
WINDOW_30D = "30d"
WINDOWS = (WINDOW_24H, WINDOW_7D, WINDOW_30D)
_WINDOW_S = {WINDOW_24H: _DAY, WINDOW_7D: 7 * _DAY, WINDOW_30D: 30 * _DAY}

AP_MIN_CLIENT_HOURS = 10.0
AP_LOW_BASIS_EVENTS = 5
AP_STATUS_OK = "ok"
AP_STATUS_INSUFFICIENT = "insufficient"

_PROBLEM_DC = ("dc_error", "dc_unknown", "dc_inactivity")


@dataclass(frozen=True, slots=True)
class ApClientInput:
    """One client at one AP in one window (from the buckets).

    ``score`` is the client's score of the same window (for the weighted
    mean stability), ``incident_ids`` the NI roots of its tagged disconnects
    at this AP (only known for the 24 h of stored transitions).
    """

    mac: str
    ap: str
    bucket: Bucket
    score: float | None = None
    incident_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ApStats:
    """One AP of the comparison. Rates are per 100 client hours and None
    below 10 client hours (``insufficient``, not ranked)."""

    ap: str
    status: str
    clients: int
    client_hours: float
    disconnects: int
    leaves: int
    infra_disconnects: int
    infra_clients: int
    incidents: tuple[str, ...]
    disconnects_per_100h: float | None
    reconnects_per_100h: float | None
    auth_fail_per_100h: float | None
    roams_in_per_100h: float | None
    roams_out_per_100h: float | None
    flaps_per_100h: float | None
    rssi_mean: float | None
    weak_share: float | None
    stability: float | None
    band_hours: Mapping[str, float]
    low_basis: bool
    rank: int | None = None


@dataclass(frozen=True, slots=True)
class ApComparison:
    """All APs of one window; ``ranking`` lists the ranked APs, best first."""

    window: str | None
    aps: Mapping[str, ApStats]
    ranking: tuple[str, ...]


def compare_aps(
    inputs: Iterable[ApClientInput], window: str | None = None
) -> ApComparison:
    """Compare APs by rates per client hour (plan 6).

    [CS-Entscheidung] The disconnect rate counts ``error``, ``unknown`` and
    ``inactivity``. ``infra`` is reported apart (``infra_disconnects``,
    ``infra_clients``, ``incidents``), and so is ``leave`` (the client left
    on purpose, typically at the AP next to the door). Normal roams only
    show up as roam rates and never in the disconnect rate or the ranking.
    "Low basis" means fewer than 5 counted events (disconnects, reconnects,
    auth failures). An AP is a router key of the B1 buckets; the band split
    is shown as ``band_hours`` because the counters are not split per band.
    """
    grouped: dict[str, list[ApClientInput]] = {}
    for item in inputs:
        if item.ap:
            grouped.setdefault(item.ap, []).append(item)
    aps = {ap: _ap_stats(ap, items) for ap, items in sorted(grouped.items())}
    ranked = sorted(
        (s for s in aps.values() if s.disconnects_per_100h is not None),
        key=lambda s: (s.disconnects_per_100h, s.ap),
    )
    for rank, s in enumerate(ranked, start=1):
        aps[s.ap] = replace(s, rank=rank)
    return ApComparison(window, aps, tuple(s.ap for s in ranked))


def _ap_stats(ap: str, items: list[ApClientInput]) -> ApStats:
    total = sum_buckets(i.bucket for i in items)
    online = float(total.online_s)
    hours = online / _HOUR
    ok = hours >= AP_MIN_CLIENT_HOURS
    disconnects = int(sum(getattr(total, name) for name in _PROBLEM_DC))
    auth = int(total.auth_fail + total.assoc_fail)
    events = disconnects + int(total.reconnects) + auth
    scored = [
        (float(i.score), float(i.bucket.online_s))
        for i in items
        if i.score is not None and _valid_number(i.score) and i.bucket.online_s > 0
    ]
    weight = sum(w for _s, w in scored)

    def rate(count: float) -> float | None:
        return count * 100.0 * _HOUR / online if ok else None

    return ApStats(
        ap=ap,
        status=AP_STATUS_OK if ok else AP_STATUS_INSUFFICIENT,
        clients=len({i.mac for i in items if i.bucket.online_s > 0}),
        client_hours=hours,
        disconnects=disconnects,
        leaves=int(total.dc_leave),
        infra_disconnects=int(total.dc_infra),
        infra_clients=len({i.mac for i in items if i.bucket.dc_infra > 0}),
        incidents=tuple(sorted({x for i in items for x in i.incident_ids if x})),
        disconnects_per_100h=rate(disconnects),
        reconnects_per_100h=rate(total.reconnects),
        auth_fail_per_100h=rate(auth),
        roams_in_per_100h=rate(total.roams_in),
        roams_out_per_100h=rate(total.roams_out),
        flaps_per_100h=rate(total.roam_flaps),
        rssi_mean=total.rssi_sum / total.rssi_n if ok and total.rssi_n > 0 else None,
        weak_share=min(1.0, total.weak_s / online) if ok else None,
        stability=sum(s * w for s, w in scored) / weight if ok and weight else None,
        band_hours={k: v / _HOUR for k, v in band_online(total).items()},
        low_basis=events < AP_LOW_BASIS_EVENTS,
    )


def window_ap_buckets(
    history: ClientHistory, mac: str, now: float, window: str
) -> dict[str, Bucket]:
    """One bucket per AP of one client for ``24h``/``7d`` (hour buckets) or
    ``30d`` (day buckets plus open hours)."""
    if window == WINDOW_30D:
        return ap_buckets(history, mac, now, 30)
    hours = 24 if window == WINDOW_24H else 168
    last = math.ceil(now / _HOUR) - 1
    grouped: dict[str, list[Bucket]] = {}
    for h in history.hours(mac, last - hours + 1, last):
        grouped.setdefault(h.ap, []).append(h.bucket)
    return {ap: sum_buckets(items) for ap, items in grouped.items()}


def ap_inputs(
    history: ClientHistory,
    now: float,
    window: str,
    *,
    macs: Iterable[str] | None = None,
    scores: Mapping[str, float | None] | None = None,
) -> list[ApClientInput]:
    """Comparison input of all (or the given) clients for one window."""
    span = _WINDOW_S.get(window, _DAY)
    out: list[ApClientInput] = []
    for mac in history.macs() if macs is None else macs:
        ends = disconnect_ends(history, mac, now - span, now)
        score = scores.get(mac) if scores is not None else None
        for ap, bucket in sorted(window_ap_buckets(history, mac, now, window).items()):
            if not ap:
                continue
            ids = {tr.incident_id for tr in ends if tr.ap == ap and tr.incident_id}
            out.append(ApClientInput(mac, ap, bucket, score, tuple(sorted(ids))))
    return out


def ap_comparison(
    history: ClientHistory,
    now: float,
    window: str = WINDOW_24H,
    *,
    macs: Iterable[str] | None = None,
    scores: Mapping[str, float | None] | None = None,
) -> ApComparison:
    """AP comparison of one window from the history."""
    inputs = ap_inputs(history, now, window, macs=macs, scores=scores)
    return compare_aps(inputs, window)


# --- Roam bursts (plan 7) ----------------------------------------------------------

ROAM_BURST_WINDOW_S = 1800.0
ROAM_BURST_MIN = 8


@dataclass(frozen=True, slots=True)
class RoamStep:
    """One roam of one client (NI ``wifi.roam`` or a B1 ``move``)."""

    ts: float
    from_ap: str
    to_ap: str


@dataclass(frozen=True, slots=True)
class RoamBurst:
    """Most roams between one pair of APs inside the window (30 min)."""

    found: bool
    roams: int = 0
    ap_a: str | None = None
    ap_b: str | None = None
    start: float | None = None
    end: float | None = None


def roam_steps(transitions: Iterable[Transition]) -> tuple[RoamStep, ...]:
    """Roams from B1 transitions (``start`` sets the AP, ``move`` changes it).

    Moves have poll resolution; B2 should prefer the NI ``wifi.roam`` events.
    """
    out: list[RoamStep] = []
    current: str | None = None
    for tr in transitions:
        if tr.kind == TR_START:
            current = tr.ap
        elif tr.kind == TR_MOVE:
            if current is not None and current != tr.ap:
                out.append(RoamStep(tr.ts, current, tr.ap))
            current = tr.ap
        elif tr.kind == TR_END:
            current = None
    return tuple(out)


def roam_burst(
    steps: Iterable[RoamStep],
    window_s: float = ROAM_BURST_WINDOW_S,
    min_roams: int = ROAM_BURST_MIN,
) -> RoamBurst:
    """Most roams between the same two APs (both directions) in ``window_s``;
    ``found`` at >= ``min_roams``."""
    pairs: dict[tuple[str, str], list[float]] = {}
    for st in steps:
        if not _valid_number(st.ts) or not st.from_ap or not st.to_ap:
            continue
        if st.from_ap == st.to_ap:
            continue
        a, b = sorted((st.from_ap, st.to_ap))
        pairs.setdefault((a, b), []).append(float(st.ts))
    best = RoamBurst(False)
    for (a, b), times in sorted(pairs.items()):
        times.sort()
        lo = 0
        for hi, t in enumerate(times):
            while t - times[lo] > window_s:
                lo += 1
            n = hi - lo + 1
            if n > best.roams:
                best = RoamBurst(n >= min_roams, n, a, b, times[lo], t)
    return best


# --- Recommendations (plan 7) -------------------------------------------------------

REC_CHECK_COVERAGE = "check_coverage"
REC_CHECK_ROAMING = "check_roaming"
REC_INFRA_LIKELY = "infrastructure_likely"
REC_CHECK_SCHEDULE = "check_device_schedule"
REC_CHECK_AP = "check_ap"
REC_INFRA_CAUSE = "infrastructure_cause"
REC_INFRA_OBSERVED = "infrastructure_disconnects"

COVERAGE_MIN_DISCONNECTS = 10.0  # per 24 observed hours
COVERAGE_MIN_WEAK = 0.3
INFRA_MIN_CLIENTS = 3
INFRA_ELEVATED_RECONNECTS = 3  # same threshold as v1.36 UNSTABLE_RECONNECTS
REC_DEFAULT_CONFIDENCE = 0.5


@dataclass(frozen=True, slots=True)
class Recommendation:
    """One structured recommendation, translated later via ``key``.

    ``kind`` is ``observation`` (no cause, confidence None), ``hypothesis``
    (confidence <= 0.6) or ``confirmed`` (only from confirmed NI roots).
    ``subject`` is the MAC or the AP; ``params`` are the measured numbers
    (plan 7 ``basis``) and double as text parameters.
    """

    key: str
    kind: str
    confidence: float | None
    subject: str
    params: Mapping[str, str | int | float]


@dataclass(frozen=True, slots=True)
class ApReconnects:
    """Reconnects per client at one AP in one window (B1 buckets) and whether
    an NI root covered this AP in that window (None = unknown; from B2)."""

    ap: str
    reconnects: Mapping[str, int]
    root_open: bool | None


@dataclass(frozen=True, slots=True)
class ClientFindings:
    """Analysis results of one client for the client rules. Every field may
    be None (not computed or no data): that rule then says nothing."""

    mac: str
    stats_24h: WindowStats | None = None
    time_pattern: TimePatternResult | None = None
    ap_pattern: ApPatternResult | None = None
    roam_burst: RoamBurst | None = None
    attribution: DisconnectAttribution | None = None


def _hypothesis(
    key: str, subject: str, confidence: float, **params: str | float
) -> Recommendation:
    return Recommendation(
        key, KIND_HYPOTHESIS, cap_confidence(confidence), subject, params
    )


def rule_coverage(f: ClientFindings) -> Recommendation | None:
    """>= 10 problem disconnects per 24 h and weak signal >= 30 %."""
    s = f.stats_24h
    if s is None or s.coverage < SCORE_MIN_COVERAGE:
        return None
    b = s.bucket
    if b.observed_s <= 0 or b.online_s <= 0 or b.rssi_n < SIGNAL_MIN_SAMPLES:
        return None
    count = sum(getattr(b, name) for name in _PROBLEM_DC)
    # [CS-Entscheidung] per 24 observed hours (in a full 24 h window: the count)
    per_day = count * _DAY / b.observed_s
    weak = min(1.0, b.weak_s / b.online_s)
    if per_day < COVERAGE_MIN_DISCONNECTS or weak < COVERAGE_MIN_WEAK:
        return None
    return _hypothesis(
        REC_CHECK_COVERAGE,
        f.mac,
        REC_DEFAULT_CONFIDENCE,
        disconnects_24h=round(per_day, 1),
        weak_share=round(weak, 2),
        rssi_mean=round(b.rssi_sum / b.rssi_n, 1),
    )


def rule_roaming(f: ClientFindings) -> Recommendation | None:
    """>= 8 roams between two APs in 30 minutes."""
    r = f.roam_burst
    if r is None or not r.found or r.ap_a is None or r.ap_b is None:
        return None
    return _hypothesis(
        REC_CHECK_ROAMING,
        f.mac,
        REC_DEFAULT_CONFIDENCE,
        roams=r.roams,
        ap_a=r.ap_a,
        ap_b=r.ap_b,
        minutes=round(ROAM_BURST_WINDOW_S / 60),
    )


def rule_time_pattern(f: ClientFindings) -> Recommendation | None:
    """Time pattern found: check the device schedule or a planned job."""
    p = f.time_pattern
    if p is None or p.status != STATUS_FOUND or not p.hours:
        return None
    top = max(p.hours, key=lambda h: (h.rate, -h.hour))
    return _hypothesis(
        REC_CHECK_SCHEDULE,
        f.mac,
        top.confidence,
        hour=top.hour,
        hours=len(p.hours),
        hit_days=top.hit_days,
        covered_days=top.covered_days,
    )


def rule_ap_specific(f: ClientFindings) -> Recommendation | None:
    """Unstable at AP X, stable at AP Y: check AP X and its channel."""
    p = f.ap_pattern
    if (
        p is None
        or p.status != STATUS_FOUND
        or p.worst_ap is None
        or p.best_ap is None
        or p.worst_rate is None
        or p.best_rate is None
    ):
        return None
    return _hypothesis(
        REC_CHECK_AP,
        f.mac,
        p.confidence,
        worst_ap=p.worst_ap,
        best_ap=p.best_ap,
        worst_rate=round(p.worst_rate, 2),
        best_rate=round(p.best_rate, 2),
    )


def rule_infrastructure_cause(f: ClientFindings) -> Recommendation | None:
    """Disconnects explained by NI roots: ``confirmed`` only when every
    tagged disconnect has a confirmed root, else a hypothesis.

    [CS-Entscheidung] Tagged by B1 but no NI root known: only the
    coincidence is reported (``observation``), no cause.
    """
    a = f.attribution
    if a is None or a.attribution != ATTR_INFRASTRUCTURE or a.kind is None:
        return None
    params: dict[str, str | int | float] = {
        "infra": a.infra,
        "client": a.client,
        "incidents": len(a.incidents),
    }
    if a.causes:
        params["cause"] = ",".join(a.causes)
    if a.kind == KIND_CONFIRMED:
        return Recommendation(REC_INFRA_CAUSE, KIND_CONFIRMED, 1.0, f.mac, params)
    if not a.incidents:
        return Recommendation(REC_INFRA_OBSERVED, KIND_OBSERVATION, None, f.mac, params)
    return Recommendation(
        REC_INFRA_CAUSE,
        KIND_HYPOTHESIS,
        cap_confidence(a.confidence or 0.0),
        f.mac,
        params,
    )


CLIENT_RULES = (
    rule_coverage,
    rule_roaming,
    rule_time_pattern,
    rule_ap_specific,
    rule_infrastructure_cause,
)


def recommend_client(findings: ClientFindings) -> tuple[Recommendation, ...]:
    """All client recommendations (rule table ``CLIENT_RULES``)."""
    return tuple(r for rule in CLIENT_RULES if (r := rule(findings)) is not None)


def ap_reconnects(
    history: ClientHistory,
    now: float,
    hours: int = 24,
    macs: Iterable[str] | None = None,
) -> dict[str, dict[str, int]]:
    """Reconnects per AP and client in the last ``hours`` hour buckets."""
    last = math.ceil(now / _HOUR) - 1
    first = last - max(1, min(int(hours), 168)) + 1
    out: dict[str, dict[str, int]] = {}
    for mac in history.macs() if macs is None else macs:
        for h in history.hours(mac, first, last):
            if h.ap and h.bucket.reconnects > 0:
                per = out.setdefault(h.ap, {})
                per[mac] = per.get(mac, 0) + int(h.bucket.reconnects)
    return out


def rule_infrastructure_likely(group: ApReconnects) -> Recommendation | None:
    """>= 3 clients of one AP with elevated reconnects (>= 3) in the same
    window and no NI root: an infrastructure problem is more likely.

    [CS-Entscheidung] With an open NI root NI already reports it (no double
    alarm); with ``root_open`` unknown (None) nothing is said.
    """
    if group.root_open is not False:
        return None
    elevated = sorted(
        mac for mac, n in group.reconnects.items() if n >= INFRA_ELEVATED_RECONNECTS
    )
    if len(elevated) < INFRA_MIN_CLIENTS:
        return None
    return _hypothesis(
        REC_INFRA_LIKELY,
        group.ap,
        REC_DEFAULT_CONFIDENCE,
        clients=len(elevated),
        reconnects=sum(group.reconnects[m] for m in elevated),
    )


AP_RULES = (rule_infrastructure_likely,)


def recommend_aps(groups: Iterable[ApReconnects]) -> tuple[Recommendation, ...]:
    """AP recommendations (rule table ``AP_RULES``), sorted by AP."""
    out = [r for g in groups for rule in AP_RULES if (r := rule(g)) is not None]
    return tuple(sorted(out, key=lambda r: (r.subject, r.key)))
