"""Active network diagnostics: probe statistics and time buckets.

Pure module: standard library only, no Home Assistant, no I/O, no clock.
Every timestamp (epoch seconds) is passed in by the caller.

Sample model (binding rule 1)
-----------------------------
One probe result is a :class:`Sample` with one of three outcomes:

* ``answered`` -- the probe was sent and answered, ``rtt_ms`` is set;
* ``lost`` -- the probe was sent and no answer came back;
* ``gap`` -- no probe ran (scheduler skipped, maintenance, router rebooting,
  Home Assistant down, the measurement path itself timed out).

``loss % = lost / (answered + lost) * 100``. Gaps never enter that
denominator; they are reported as ``coverage = (answered + lost) / expected``.
With no measured probe every statistic is ``None`` and coverage is 0
(binding rule 2: missing data is never healthy).

Formulas
--------
* ``mean`` -- arithmetic mean of the answered rtts.
* ``jitter`` -- mean absolute difference of consecutive answered rtts in time
  order, ``sum(|rtt[i] - rtt[i-1]|) / (n - 1)`` (an unsmoothed form of the
  RFC 3550 interarrival jitter). Lost probes and gaps between two answers are
  skipped, so with sparse probing a pair may be minutes apart. Needs two
  answers, else ``None``.
* ``current`` -- rtt of the newest measured probe; ``None`` when that probe was
  lost (no stale value is shown).
* outlier -- an answered rtt above ``max(median * OUTLIER_FACTOR, median +
  OUTLIER_FLOOR_MS)`` of the same set, judged only with at least
  ``OUTLIER_MIN_SAMPLES`` answers. Outliers are counted, never removed.

Buckets
-------
A :class:`Bucket` keeps count, sum, min, max, lost, gaps, outliers, the sum
of absolute rtt differences and the first/last answered rtt. That makes mean,
jitter and loss exact after merging: :func:`merge_buckets` adds the
difference across the border of two buckets. Merging orders buckets by time
and rejects overlapping ranges (that would double count), so it is
associative and commutative. Samples fold into hour buckets
(:func:`bucket_samples`), hour buckets into UTC day buckets
(:func:`fold_into_days`). A merged bucket covers ``[start, end)`` of its
parts, so a day bucket filled up to 05:00 ends at 05:00 and the next hour
can still be folded in.

Windows (:data:`WINDOWS`): 1 h, 24 h and 7 d come from hour buckets, 30 d from
day buckets plus the hours not folded yet. A bucket belongs to a window when
it overlaps ``[now - window, now]``; the window start is thereby extended to
the border of the bucket holding ``now - window``. So the 1 h window spans
between 1 and 2 hours of buckets (right after a full hour it still holds the
previous hour instead of a nearly empty one), 24 h up to 25 hours, 30 d up to
31 days. With the probe interval given, ``expected`` is the number of probes
planned in that extended span (``ceil(span / interval) * probes_per_round``,
counted from ``since`` when monitoring started later), so missing rounds
lower coverage.

Retention: :func:`prune_history` keeps hour buckets 7 days and day buckets 30
days by default. Fold an hour before it is pruned.

Series keys (binding rule 3): statistics are kept per :class:`SeriesKey`
(measurement point, target id, probe kind, address family), all opaque
strings. This module never merges data of different keys; callers keep one
bucket list per key.
"""

from __future__ import annotations

import itertools
import logging
import math
import statistics
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

_LOGGER = logging.getLogger(__name__)

# --- Constants ---------------------------------------------------------------

OUTCOME_ANSWERED = "answered"
OUTCOME_LOST = "lost"
OUTCOME_GAP = "gap"
OUTCOMES = frozenset({OUTCOME_ANSWERED, OUTCOME_LOST, OUTCOME_GAP})

DNS_NOERROR = "noerror"  # answer with data
DNS_NXDOMAIN = "nxdomain"  # answer "name does not exist": the resolver works
DNS_SERVFAIL = "servfail"  # resolver failure
DNS_ERROR = "error"  # other failure codes (REFUSED, FORMERR, ...)
DNS_TIMEOUT = "timeout"  # query sent, no answer
DNS_GAP = "gap"  # no query ran
DNS_OUTCOMES = frozenset(
    {DNS_NOERROR, DNS_NXDOMAIN, DNS_SERVFAIL, DNS_ERROR, DNS_TIMEOUT, DNS_GAP}
)
_DNS_ANSWERS = frozenset({DNS_NOERROR, DNS_NXDOMAIN})
_DNS_RTT_OPTIONAL = frozenset({DNS_SERVFAIL, DNS_ERROR})

OUTLIER_FACTOR = 3.0
OUTLIER_FLOOR_MS = 10.0
OUTLIER_MIN_SAMPLES = 5

HOUR_S = 3600.0
DAY_S = 86400.0
HOUR_RETENTION_S = 7 * DAY_S
DAY_RETENTION_S = 30 * DAY_S

_EPS = 1e-9

WINDOWS: Mapping[str, float] = {
    "1h": HOUR_S,
    "24h": DAY_S,
    "7d": 7 * DAY_S,
    "30d": 30 * DAY_S,
}


def _check_ts(ts: Any) -> float:
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        raise TypeError("timestamp must be a number")
    if not math.isfinite(ts):
        raise ValueError("timestamp must be finite")
    return float(ts)


def _check_rtt(rtt: Any) -> float:
    if isinstance(rtt, bool) or not isinstance(rtt, (int, float)):
        raise TypeError("rtt must be a number")
    if not math.isfinite(rtt) or rtt < 0:
        raise ValueError("rtt must be finite and not negative")
    return float(rtt)


# --- Keys and samples --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SeriesKey:
    """Opaque identity of one measurement series (binding rule 3)."""

    point: str
    target: str
    kind: str
    family: str

    def __post_init__(self) -> None:
        for name in ("point", "target", "kind", "family"):
            value = getattr(self, name)
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
            if not value:
                raise ValueError(f"{name} must not be empty")


@dataclass(frozen=True, slots=True)
class Sample:
    """One probe result: answered (with rtt), lost or gap."""

    ts: float
    outcome: str
    rtt_ms: float | None = None

    def __post_init__(self) -> None:
        _check_ts(self.ts)
        if self.outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome {self.outcome!r}")
        if self.outcome == OUTCOME_ANSWERED:
            if self.rtt_ms is None:
                raise ValueError("an answered sample needs an rtt")
            _check_rtt(self.rtt_ms)
        elif self.rtt_ms is not None:
            raise ValueError(f"a {self.outcome} sample has no rtt")

    @classmethod
    def answered(cls, ts: float, rtt_ms: float) -> Sample:
        return cls(ts, OUTCOME_ANSWERED, rtt_ms)

    @classmethod
    def lost(cls, ts: float) -> Sample:
        return cls(ts, OUTCOME_LOST)

    @classmethod
    def gap(cls, ts: float) -> Sample:
        return cls(ts, OUTCOME_GAP)


@dataclass(frozen=True, slots=True)
class DnsSample:
    """One DNS query result. NXDOMAIN is an answer, not a resolver failure."""

    ts: float
    outcome: str
    rtt_ms: float | None = None

    def __post_init__(self) -> None:
        _check_ts(self.ts)
        if self.outcome not in DNS_OUTCOMES:
            raise ValueError(f"unknown DNS outcome {self.outcome!r}")
        if self.outcome in _DNS_ANSWERS:
            if self.rtt_ms is None:
                raise ValueError("a DNS answer needs a response time")
            _check_rtt(self.rtt_ms)
        elif self.outcome in _DNS_RTT_OPTIONAL:
            if self.rtt_ms is not None:
                _check_rtt(self.rtt_ms)
        elif self.rtt_ms is not None:
            raise ValueError(f"a DNS {self.outcome} has no response time")


def mark_restart_gap(
    samples: Iterable[Sample | DnsSample], *, start: float, end: float
) -> tuple[Sample | DnsSample, ...]:
    """Turn unanswered probes in ``[start, end)`` into gaps (binding rule 6).

    The caller signals a router or Home Assistant restart window; probes that
    got no answer in it were not lost on the network. Answered probes stay as
    they are. Returns a new tuple, the input is not changed.
    """
    lo, hi = _check_ts(start), _check_ts(end)
    if hi < lo:
        raise ValueError("restart window ends before it starts")
    out: list[Sample | DnsSample] = []
    for sample in samples:
        inside = lo <= sample.ts < hi
        if inside and isinstance(sample, Sample) and sample.outcome == OUTCOME_LOST:
            out.append(Sample.gap(sample.ts))
        elif inside and isinstance(sample, DnsSample) and sample.outcome == DNS_TIMEOUT:
            out.append(DnsSample(sample.ts, DNS_GAP))
        else:
            out.append(sample)
    return tuple(out)


# --- Summaries ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LatencySummary:
    """Statistics of one series over a set of samples or a bucket."""

    answered: int
    lost: int
    gaps: int
    expected: int
    coverage: float
    current_ms: float | None
    mean_ms: float | None
    min_ms: float | None
    max_ms: float | None
    jitter_ms: float | None
    loss_pct: float | None
    outliers: int


def _coverage(measured: int, expected: int) -> float:
    if expected <= 0 or measured <= 0:
        return 0.0
    return min(1.0, measured / expected)


def _expected(expected: int | None, total: int) -> int:
    if expected is None:
        return total
    if isinstance(expected, bool) or not isinstance(expected, int) or expected < 0:
        raise ValueError("expected must be a non-negative integer")
    return expected


def _loss_pct(answered: int, lost: int) -> float | None:
    measured = answered + lost
    return lost / measured * 100.0 if measured else None


def count_outliers(rtts: Sequence[float]) -> int:
    """Number of rtts above the outlier limit of the set (see module doc)."""
    limit = _outlier_limit(rtts)
    return 0 if limit is None else sum(1 for rtt in rtts if rtt > limit)


def summarize(
    samples: Iterable[Sample], *, expected: int | None = None
) -> LatencySummary:
    """Rolling summary of probe samples (any order; sorted by time here).

    ``expected`` is the number of probes that should have run; by default the
    number of samples including gaps.
    """
    ordered = sorted(samples, key=lambda s: s.ts)
    rtts = [s.rtt_ms for s in ordered if s.outcome == OUTCOME_ANSWERED]
    lost = sum(1 for s in ordered if s.outcome == OUTCOME_LOST)
    gaps = len(ordered) - len(rtts) - lost
    measured = [s for s in ordered if s.outcome != OUTCOME_GAP]
    exp = _expected(expected, len(ordered))
    diffs = [abs(b - a) for a, b in itertools.pairwise(rtts)]
    return LatencySummary(
        answered=len(rtts),
        lost=lost,
        gaps=gaps,
        expected=exp,
        coverage=_coverage(len(measured), exp),
        current_ms=measured[-1].rtt_ms if measured else None,
        mean_ms=sum(rtts) / len(rtts) if rtts else None,
        min_ms=min(rtts) if rtts else None,
        max_ms=max(rtts) if rtts else None,
        jitter_ms=sum(diffs) / len(diffs) if diffs else None,
        loss_pct=_loss_pct(len(rtts), lost),
        outliers=count_outliers(rtts),  # type: ignore[arg-type]
    )


@dataclass(frozen=True, slots=True)
class DnsSummary:
    """DNS response statistics; timeouts, SERVFAIL and NXDOMAIN apart."""

    queries: int  # every query that ran (all outcomes except gap)
    answered: int  # NOERROR + NXDOMAIN
    noerror: int
    nxdomain: int
    servfail: int
    errors: int
    timeouts: int
    gaps: int
    expected: int
    coverage: float
    failure_pct: float | None  # (servfail + errors + timeouts) / queries
    timeout_pct: float | None
    current_ms: float | None
    mean_ms: float | None  # response time of NOERROR and NXDOMAIN only
    min_ms: float | None
    max_ms: float | None


def summarize_dns(
    samples: Iterable[DnsSample], *, expected: int | None = None
) -> DnsSummary:
    """Summary of DNS query results (any order; sorted by time here)."""
    ordered = sorted(samples, key=lambda s: s.ts)
    counts = {outcome: 0 for outcome in DNS_OUTCOMES}
    for sample in ordered:
        counts[sample.outcome] += 1
    queries = len(ordered) - counts[DNS_GAP]
    failures = counts[DNS_SERVFAIL] + counts[DNS_ERROR] + counts[DNS_TIMEOUT]
    rtts = [s.rtt_ms for s in ordered if s.outcome in _DNS_ANSWERS]
    measured = [s for s in ordered if s.outcome != DNS_GAP]
    newest = measured[-1] if measured else None
    exp = _expected(expected, len(ordered))
    return DnsSummary(
        queries=queries,
        answered=len(rtts),
        noerror=counts[DNS_NOERROR],
        nxdomain=counts[DNS_NXDOMAIN],
        servfail=counts[DNS_SERVFAIL],
        errors=counts[DNS_ERROR],
        timeouts=counts[DNS_TIMEOUT],
        gaps=counts[DNS_GAP],
        expected=exp,
        coverage=_coverage(queries, exp),
        failure_pct=failures / queries * 100.0 if queries else None,
        timeout_pct=counts[DNS_TIMEOUT] / queries * 100.0 if queries else None,
        current_ms=(
            newest.rtt_ms if newest and newest.outcome in _DNS_ANSWERS else None
        ),
        mean_ms=sum(rtts) / len(rtts) if rtts else None,  # type: ignore[arg-type]
        min_ms=min(rtts) if rtts else None,  # type: ignore[type-var]
        max_ms=max(rtts) if rtts else None,  # type: ignore[type-var]
    )


# --- Buckets -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Bucket:
    """Mergeable aggregate of one series over ``[start, end)``."""

    start: float
    end: float
    answered: int = 0
    lost: int = 0
    gaps: int = 0
    outliers: int = 0
    rtt_sum: float = 0.0
    rtt_min: float | None = None
    rtt_max: float | None = None
    diff_sum: float = 0.0  # sum of |rtt[i] - rtt[i-1]| of consecutive answers
    first_rtt: float | None = None
    last_rtt: float | None = None
    tail_lost: bool = False  # newest measured probe was lost
    last_ts: float | None = None  # newest sample of any outcome

    def __post_init__(self) -> None:
        _check_ts(self.start)
        _check_ts(self.end)
        if self.end <= self.start:
            raise ValueError("bucket end must be after its start")
        for name in ("answered", "lost", "gaps", "outliers"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        for name in ("rtt_sum", "diff_sum"):
            _check_rtt(getattr(self, name))
        has = self.answered > 0
        for name in ("rtt_min", "rtt_max", "first_rtt", "last_rtt"):
            value = getattr(self, name)
            if (value is None) == has:
                raise ValueError(f"{name} must be set exactly when rtts exist")
            if value is not None:
                _check_rtt(value)
        if not isinstance(self.tail_lost, bool):
            raise TypeError("tail_lost must be a bool")
        if self.last_ts is not None and not (
            self.start <= _check_ts(self.last_ts) < self.end
        ):
            raise ValueError("last_ts outside the bucket")
        self._check_consistency()

    def _check_consistency(self) -> None:
        """Counters and rtt fields must describe one possible sample set."""
        if (self.last_ts is None) != (self.answered + self.lost + self.gaps == 0):
            raise ValueError("last_ts must be set exactly when samples exist")
        if self.outliers > self.answered:
            raise ValueError("more outliers than answers")
        if self.tail_lost and self.lost == 0:
            raise ValueError("newest probe lost, but no probe was lost")
        n = self.answered
        if n == 0:
            if self.rtt_sum != 0 or self.diff_sum != 0:
                raise ValueError("rtt sums without answers")
            return
        lo, hi = self.rtt_min, self.rtt_max
        if not _le(lo, hi):  # type: ignore[arg-type]
            raise ValueError("rtt_min above rtt_max")
        if n == 1 and lo != hi:
            raise ValueError("one answer, but min and max differ")
        for value in (self.first_rtt, self.last_rtt):
            if not (_le(lo, value) and _le(value, hi)):  # type: ignore[arg-type]
                raise ValueError("first/last rtt outside min..max")
        if not (_le(n * lo, self.rtt_sum) and _le(self.rtt_sum, n * hi)):  # type: ignore[operator]
            raise ValueError("rtt_sum outside n * min .. n * max")
        if not _le(self.diff_sum, (n - 1) * (hi - lo)):  # type: ignore[operator]
            raise ValueError("diff_sum above (n - 1) * (max - min)")

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe plain dict."""
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Bucket:
        """Rebuild from :meth:`to_dict`.

        Raises ``TypeError`` when ``data`` is not a mapping and ``ValueError``
        when its content is damaged.
        """
        if not isinstance(data, Mapping):
            raise TypeError("bucket data must be a mapping")
        try:
            return cls(**{name: data[name] for name in cls.__dataclass_fields__})
        except (KeyError, TypeError) as err:
            raise ValueError(f"damaged bucket: {err}") from err


def _le(a: float, b: float) -> bool:
    """``a <= b`` with a relative tolerance for float sums."""
    return a <= b + _EPS * max(1.0, abs(a), abs(b))


def empty_bucket(start: float, span: float) -> Bucket:
    """An empty bucket ``[start, start + span)``."""
    if span <= 0:
        raise ValueError("span must be positive")
    return Bucket(start=start, end=start + span)


def align(ts: float, span: float) -> float:
    """Start of the epoch-aligned (UTC) slot of ``span`` seconds holding ``ts``."""
    return math.floor(ts / span) * span


def add_sample(bucket: Bucket, sample: Sample, *, outlier: bool = False) -> Bucket:
    """New bucket with ``sample`` added. Samples must come in time order."""
    if not bucket.start <= sample.ts < bucket.end:
        raise ValueError("sample outside the bucket")
    if bucket.last_ts is not None and sample.ts < bucket.last_ts:
        raise ValueError("sample older than the newest one in the bucket")
    if sample.outcome == OUTCOME_GAP:
        return replace(bucket, gaps=bucket.gaps + 1, last_ts=sample.ts)
    if sample.outcome == OUTCOME_LOST:
        return replace(bucket, lost=bucket.lost + 1, tail_lost=True, last_ts=sample.ts)
    rtt = float(sample.rtt_ms)  # type: ignore[arg-type]
    step = abs(rtt - bucket.last_rtt) if bucket.last_rtt is not None else 0.0
    return replace(
        bucket,
        answered=bucket.answered + 1,
        outliers=bucket.outliers + int(outlier),
        rtt_sum=bucket.rtt_sum + rtt,
        rtt_min=rtt if bucket.rtt_min is None else min(bucket.rtt_min, rtt),
        rtt_max=rtt if bucket.rtt_max is None else max(bucket.rtt_max, rtt),
        diff_sum=bucket.diff_sum + step,
        first_rtt=rtt if bucket.first_rtt is None else bucket.first_rtt,
        last_rtt=rtt,
        tail_lost=False,
        last_ts=sample.ts,
    )


def bucket_samples(
    samples: Iterable[Sample], *, span: float = HOUR_S
) -> tuple[Bucket, ...]:
    """Fold samples into aligned buckets of ``span`` seconds, oldest first.

    Outliers are judged per bucket with :func:`count_outliers`.
    """
    groups: dict[float, list[Sample]] = {}
    for sample in sorted(samples, key=lambda s: s.ts):
        groups.setdefault(align(sample.ts, span), []).append(sample)
    out = []
    for start in sorted(groups):
        group = groups[start]
        rtts = [s.rtt_ms for s in group if s.outcome == OUTCOME_ANSWERED]
        limit = _outlier_limit(rtts)  # type: ignore[arg-type]
        bucket = empty_bucket(start, span)
        for sample in group:
            flag = (
                limit is not None
                and sample.rtt_ms is not None
                and sample.rtt_ms > limit
            )
            bucket = add_sample(bucket, sample, outlier=flag)
        out.append(bucket)
    return tuple(out)


def _outlier_limit(rtts: Sequence[float]) -> float | None:
    if len(rtts) < OUTLIER_MIN_SAMPLES:
        return None
    median = statistics.median(rtts)
    return max(median * OUTLIER_FACTOR, median + OUTLIER_FLOOR_MS)


def _opt(fn: Any, a: float | None, b: float | None) -> float | None:
    if a is None:
        return b
    if b is None:
        return a
    return fn(a, b)


def merge_buckets(a: Bucket, b: Bucket) -> Bucket:
    """Merge two buckets of one series covering disjoint time ranges.

    The older bucket is put first whatever the argument order; overlapping
    ranges raise ``ValueError`` (they would double count).
    """
    first, second = (a, b) if a.start <= b.start else (b, a)
    if first.end > second.start:
        raise ValueError("buckets overlap")
    border = (
        abs(second.first_rtt - first.last_rtt)
        if first.last_rtt is not None and second.first_rtt is not None
        else 0.0
    )
    second_measured = second.answered + second.lost > 0
    return Bucket(
        start=first.start,
        end=second.end,
        answered=first.answered + second.answered,
        lost=first.lost + second.lost,
        gaps=first.gaps + second.gaps,
        outliers=first.outliers + second.outliers,
        rtt_sum=first.rtt_sum + second.rtt_sum,
        rtt_min=_opt(min, first.rtt_min, second.rtt_min),
        rtt_max=_opt(max, first.rtt_max, second.rtt_max),
        diff_sum=first.diff_sum + second.diff_sum + border,
        first_rtt=_opt(lambda x, _y: x, first.first_rtt, second.first_rtt),
        last_rtt=_opt(lambda _x, y: y, first.last_rtt, second.last_rtt),
        tail_lost=second.tail_lost if second_measured else first.tail_lost,
        last_ts=second.last_ts if second.last_ts is not None else first.last_ts,
    )


def merge_all(buckets: Iterable[Bucket]) -> Bucket | None:
    """Merge any number of disjoint buckets; ``None`` when there are none."""
    result: Bucket | None = None
    for bucket in sorted(buckets, key=lambda b: b.start):
        result = bucket if result is None else merge_buckets(result, bucket)
    return result


def bucket_summary(
    bucket: Bucket | None, *, expected: int | None = None
) -> LatencySummary:
    """:class:`LatencySummary` of a bucket; ``None`` gives the empty summary."""
    if bucket is None:
        return summarize((), expected=expected)
    n = bucket.answered
    exp = _expected(expected, n + bucket.lost + bucket.gaps)
    return LatencySummary(
        answered=n,
        lost=bucket.lost,
        gaps=bucket.gaps,
        expected=exp,
        coverage=_coverage(n + bucket.lost, exp),
        current_ms=None if bucket.tail_lost else bucket.last_rtt,
        mean_ms=bucket.rtt_sum / n if n else None,
        min_ms=bucket.rtt_min,
        max_ms=bucket.rtt_max,
        jitter_ms=bucket.diff_sum / (n - 1) if n > 1 else None,
        loss_pct=_loss_pct(n, bucket.lost),
        outliers=bucket.outliers,
    )


def fold_into_days(
    hours: Iterable[Bucket], days: Iterable[Bucket] = ()
) -> tuple[Bucket, ...]:
    """New day buckets with ``hours`` folded in, oldest first.

    Each hour must lie inside one UTC day. Folding an hour that a day already
    holds raises ``ValueError`` (double count), so fold each hour once.
    """
    by_day = {align(day.start, DAY_S): day for day in days}
    for hour in sorted(hours, key=lambda b: b.start):
        index = align(hour.start, DAY_S)
        if hour.end > index + DAY_S:
            raise ValueError("bucket spans two UTC days")
        current = by_day.get(index)
        by_day[index] = hour if current is None else merge_buckets(current, hour)
    return tuple(by_day[index] for index in sorted(by_day))


def window_bucket(
    buckets: Iterable[Bucket], *, now: float, window_s: float
) -> Bucket | None:
    """Merge of the buckets overlapping ``[now - window_s, now]``."""
    lo = now - window_s
    return merge_all(b for b in buckets if b.end > lo and b.start <= now)


def window_expected(
    *,
    now: float,
    window_s: float,
    span: float,
    interval_s: float,
    probes_per_round: int = 1,
    since: float | None = None,
) -> int:
    """Probes planned in a window extended to its bucket border (module doc)."""
    if not math.isfinite(interval_s) or interval_s <= 0:
        raise ValueError("interval must be positive")
    if isinstance(probes_per_round, bool) or not isinstance(probes_per_round, int):
        raise TypeError("probes_per_round must be an integer")
    if probes_per_round < 1:
        raise ValueError("probes_per_round must be at least 1")
    start = align(now - window_s, span)
    if since is not None:
        start = max(start, _check_ts(since))
    covered = max(0.0, now - start)
    return math.ceil(covered / interval_s) * probes_per_round


def _not_folded(hours: Iterable[Bucket], days: Sequence[Bucket]) -> list[Bucket]:
    return [h for h in hours if not any(d.start <= h.start < d.end for d in days)]


def window_summaries(
    hours: Iterable[Bucket],
    days: Iterable[Bucket],
    *,
    now: float,
    interval_s: float | None = None,
    probes_per_round: int = 1,
    since: float | None = None,
    hour_retention_s: float = HOUR_RETENTION_S,
) -> dict[str, LatencySummary]:
    """Summaries for every window of :data:`WINDOWS`.

    Windows up to ``hour_retention_s`` use hour buckets; longer ones use day
    buckets plus the hours no day holds yet. With ``interval_s`` (seconds
    between probe rounds) coverage is measured against the planned probes of
    the window (:func:`window_expected`); without it against the samples
    recorded, gaps included.
    """
    hour_list = tuple(hours)
    day_list = tuple(days)
    long_parts = (*day_list, *_not_folded(hour_list, day_list))
    out: dict[str, LatencySummary] = {}
    for name, length in WINDOWS.items():
        short = length <= hour_retention_s
        expected = (
            None
            if interval_s is None
            else window_expected(
                now=now,
                window_s=length,
                span=HOUR_S if short else DAY_S,
                interval_s=interval_s,
                probes_per_round=probes_per_round,
                since=since,
            )
        )
        parts = hour_list if short else long_parts
        merged = window_bucket(parts, now=now, window_s=length)
        out[name] = bucket_summary(merged, expected=expected)
    return out


def prune_buckets(
    buckets: Iterable[Bucket], *, now: float, retention_s: float
) -> tuple[Bucket, ...]:
    """Buckets that end after ``now - retention_s``, oldest first."""
    if retention_s <= 0:
        raise ValueError("retention must be positive")
    cutoff = now - retention_s
    return tuple(sorted((b for b in buckets if b.end > cutoff), key=lambda b: b.start))


def prune_history(
    hours: Iterable[Bucket],
    days: Iterable[Bucket],
    *,
    now: float,
    hour_retention_s: float = HOUR_RETENTION_S,
    day_retention_s: float = DAY_RETENTION_S,
) -> tuple[tuple[Bucket, ...], tuple[Bucket, ...]]:
    """Bound the history: hours kept 7 days, days 30 days by default."""
    return (
        prune_buckets(hours, now=now, retention_s=hour_retention_s),
        prune_buckets(days, now=now, retention_s=day_retention_s),
    )
