"""Traffic anomaly candidates (task §10; plan §3.3, §5, §10; Phase F).

**No second incident engine.** This module only produces
:class:`~.traffic_model.AnomalyCandidate` objects, keeps at most 100 of them
and publishes start/end as core events (``traffic_analytics.anomaly_*``)
through the core API's ``emit``. Network Intelligence has no public way to
take candidates into its incidents (wish W1), so every candidate says
``incident_engine: not_connected``. A traffic anomaly is a statistical
deviation, never an attack.

**Not built twice.** Port load, port errors and conntrack jumps are
Network Intelligence rules (``lan_port_load``, ``lan_port_errors``,
``system_conntrack_jump``): ports are not evaluated here, and the
connection rate is ``covered_by_network_intelligence`` when the conntrack
count comes from the count file (else ``unavailable``). Changed
communication patterns and inter-VLAN traffic need a flow source and a flow
history: without the source ``unavailable``/``needs_flow_source``, with it
``learning``/``flow_history_not_built`` (the history store is Phase I).

**Baselines** (:func:`robust_stats`, :class:`Baseline`): per point and
counter, median and MAD (scaled by 1.4826) of the average bucket rate per
slot ``(weekday|weekend, local hour)`` from the last 28 days, the recent
hour excluded. Buckets below half coverage do not count. A slot is ready
with at least 6 values from at least 3 distinct days; below that the point
is ``learning``: no candidate, and no all-clear either.

**Spread** = max(MAD x 1.4826, 100 kbit/s, 10 % of the median), so a very
regular series (camera stream) does not alarm on noise.

**Kinds** (direction = download/upload where the area maps it, else rx/tx):

========================  ================================================
``<dir>_spike``           >= 2 complete buckets above median + 6 spreads
``<dir>_night_activity``  a spike in a night hour (00-05 local)
``<dir>_sustained_high``  >= 6 buckets above median + 3 spreads
``<dir>_drop``            >= 3 buckets at <= 20 % of a median >= 1 Mbit/s
``<dir>_bursts``          >= 4 buckets in the hour whose peak is above the
                          peak baseline + 6 spreads, average normal
``<dir>_volume``          clients: last 24 h above median + 6 spreads of
                          the daily volumes of >= 5 earlier days, and >= 2x
                          the median and >= 50 MB
========================  ================================================

Regular patterns (camera streams, nightly backups, update windows) are part
of their slot's baseline and do not trigger.

**Brakes.** Hysteresis: an open candidate stays open while its value is
above the clear threshold (median + 3 spreads, sustained + 2, drop below
40 % of the median) and ends after that. Debounce: the same point and kind
again within 30 min re-opens the ended candidate (no new one, no new
event). Budgets: 30 new candidates per hour in total, 2 per point and hour,
1 per point and kind per 6 h; a candidate over budget, or matched by a
suppression rule, is kept with ``suppressed_reason`` in its own quota
(20) and never published. Suppression rules only accept traffic kinds and
only act on candidates of this module.
"""

from __future__ import annotations

import hashlib
import logging
import statistics
from collections import Counter, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, tzinfo
from typing import Any, Final

from .traffic_accounting import direction_map
from .traffic_const import (
    ANOMALY_STATE_ACTIVE,
    ANOMALY_STATE_COVERED_BY_NI,
    ANOMALY_STATE_LEARNING,
    ANOMALY_STATE_UNAVAILABLE,
    BASELINE_LOOKBACK_S,
    BASELINE_MIN_DAYS,
    BASELINE_MIN_VALUES,
    BASELINE_RESOLUTION_S,
    BUDGET_PER_HOUR,
    BUDGET_POINT_KIND_S,
    BUDGET_POINT_PER_HOUR,
    BURST_MIN_COUNT,
    CANDIDATE_DEBOUNCE_S,
    CONNTRACK_SOURCE_COUNT_FILE,
    DROP_MIN_BUCKETS,
    DROP_MIN_MEDIAN_BPS,
    DROP_RATIO,
    EVENT_ANOMALY_ENDED,
    EVENT_ANOMALY_STARTED,
    GAPPY_BELOW,
    K_CLEAR,
    K_RAISE,
    K_SUSTAINED,
    K_SUSTAINED_CLEAR,
    MAD_SCALE,
    MAX_CANDIDATES,
    MAX_CANDIDATES_SUPPRESSED,
    MAX_CONFIDENCE,
    MAX_SUPPRESSION_RULES,
    MODULE_NAME,
    NIGHT_HOURS,
    REASON_CONNTRACK_NOT_COUNT_FILE,
    REASON_FLOW_HISTORY_NOT_BUILT,
    REASON_NI_RULE,
    REASON_NO_CANDIDATE_API,
    REASON_NO_DATA_YET,
    REASON_NOT_PUBLISHED,
    RECENT_WINDOW_S,
    SPIKE_MIN_BUCKETS,
    SPREAD_MIN_BPS,
    SPREAD_REL_FLOOR,
    SUPPRESSED_BUDGET_HOUR,
    SUPPRESSED_BUDGET_POINT,
    SUPPRESSED_BUDGET_POINT_KIND,
    SUPPRESSED_RULE,
    SUPPRESSED_STORE_FULL,
    SUSTAINED_MIN_BUCKETS,
    VOLUME_MIN_BYTES,
    VOLUME_MIN_DAYS,
    VOLUME_RATIO,
)
from .traffic_model import (
    AnomalyCandidate,
    Bucket,
    CandidateState,
    Coverage,
    CoverageReason,
    MeasurementPoint,
    Scope,
    valid_point_id,
)
from .traffic_series import BucketSource

_LOGGER = logging.getLogger(__name__)

EVALUATED_SCOPES: Final = frozenset(
    {Scope.WAN, Scope.INTERFACE, Scope.VLAN, Scope.CLIENT}
)
BASE_KINDS: Final = (
    "spike",
    "night_activity",
    "sustained_high",
    "drop",
    "bursts",
    "volume",
)
DIRECTIONS: Final = ("download", "upload", "rx", "tx")
TRAFFIC_KINDS: Final = frozenset(f"{d}_{k}" for d in DIRECTIONS for k in BASE_KINDS)
CANDIDATE_PREFIX: Final = "tac_"
INCIDENT_ENGINE_STATE: Final = "not_connected"

Slot = tuple[str, int]


# --- robust statistics ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RobustStats:
    """Median and scaled MAD of a value set and its data base."""

    median: float
    mad: float
    values: int
    days: int

    @property
    def ready(self) -> bool:
        """Enough data for a decision (else: learning)."""
        return self.values >= BASELINE_MIN_VALUES and self.days >= BASELINE_MIN_DAYS

    @property
    def spread(self) -> float:
        """MAD with its floors (see the module docstring)."""
        return max(self.mad, SPREAD_MIN_BPS, SPREAD_REL_FLOOR * self.median)

    def above(self, k: float) -> float:
        """Threshold ``median + k x spread``."""
        return self.median + k * self.spread


def robust_stats(values: Sequence[float], days: int) -> RobustStats | None:
    """Median and MAD x 1.4826 of ``values`` (None when empty)."""
    if not values:
        return None
    median = statistics.median(values)
    mad = statistics.median([abs(v - median) for v in values]) * MAD_SCALE
    return RobustStats(float(median), float(mad), len(values), days)


def avg_bps(bucket: Bucket, counter: str) -> float | None:
    """Average bit/s of a bucket over its covered time (None: unknown)."""
    value = bucket.rx_bytes if counter == "rx" else bucket.tx_bytes
    if value is None or bucket.covered_s <= 0:
        return None
    return value * 8 / bucket.covered_s


def _peak(bucket: Bucket, counter: str) -> float | None:
    return bucket.rx_peak_bps if counter == "rx" else bucket.tx_peak_bps


class SlotClock:
    """Slot ``(weekday|weekend, local hour)`` and day of a time, cached per hour."""

    def __init__(self, tz: tzinfo = UTC) -> None:
        """Clock in ``tz`` (DST handled by ``datetime``)."""
        self.tz = tz
        self._cache: dict[int, tuple[Slot, str]] = {}

    def slot(self, ts: float) -> tuple[Slot, str]:
        """``((class, hour), date)`` of ``ts``."""
        hour = int(ts // 3600)
        hit = self._cache.get(hour)
        if hit is None:
            local = datetime.fromtimestamp(hour * 3600, self.tz)
            klass = "weekend" if local.weekday() >= 5 else "weekday"
            hit = ((klass, local.hour), local.date().isoformat())
            if len(self._cache) > 4096:
                self._cache.clear()
            self._cache[hour] = hit
        return hit


@dataclass(slots=True)
class Baseline:
    """Slot statistics of one point, per counter (average and peak)."""

    built_hour: int
    avg: dict[tuple[str, Slot], RobustStats] = field(default_factory=dict)
    peak: dict[tuple[str, Slot], RobustStats] = field(default_factory=dict)
    daily: dict[str, RobustStats] = field(default_factory=dict)

    def stats(self, counter: str, slot: Slot) -> RobustStats | None:
        """Ready average stats of a slot (None: learning)."""
        found = self.avg.get((counter, slot))
        return found if found is not None and found.ready else None

    def peak_stats(self, counter: str, slot: Slot) -> RobustStats | None:
        """Ready peak stats of a slot (None: learning)."""
        found = self.peak.get((counter, slot))
        return found if found is not None and found.ready else None


def build_baseline(
    buckets: Iterable[Bucket], clock: SlotClock, built_hour: int
) -> Baseline:
    """Baseline from history buckets; gappy buckets never count."""
    avg_values: dict[tuple[str, Slot], list[float]] = {}
    avg_days: dict[tuple[str, Slot], set[str]] = {}
    peak_values: dict[tuple[str, Slot], list[float]] = {}
    peak_days: dict[tuple[str, Slot], set[str]] = {}
    daily: dict[str, dict[str, list[float]]] = {"rx": {}, "tx": {}}
    for bucket in buckets:
        if bucket.gappy:
            continue
        slot, day = clock.slot(bucket.start)
        for counter in ("rx", "tx"):
            value = avg_bps(bucket, counter)
            if value is not None:
                key = (counter, slot)
                avg_values.setdefault(key, []).append(value)
                avg_days.setdefault(key, set()).add(day)
                raw = bucket.rx_bytes if counter == "rx" else bucket.tx_bytes
                daily[counter].setdefault(day, [0.0, 0.0])
                daily[counter][day][0] += raw or 0
                daily[counter][day][1] += bucket.covered_s
            peak = _peak(bucket, counter)
            if peak is not None:
                key = (counter, slot)
                peak_values.setdefault(key, []).append(peak)
                peak_days.setdefault(key, set()).add(day)
    baseline = Baseline(built_hour)
    for key, values in avg_values.items():
        stats = robust_stats(values, len(avg_days[key]))
        if stats is not None:
            baseline.avg[key] = stats
    for key, values in peak_values.items():
        stats = robust_stats(values, len(peak_days[key]))
        if stats is not None:
            baseline.peak[key] = stats
    for counter, days in daily.items():
        # a day counts with at least half of it covered (plan §3.3 rule)
        volumes = [v[0] for v in days.values() if v[1] >= GAPPY_BELOW * 86400]
        stats = robust_stats(volumes, len(volumes))
        if stats is not None:
            baseline.daily[counter] = stats
    return baseline


# --- findings ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """One rule that holds for a point right now."""

    kind: str
    observed: float
    median: float
    mad: float
    threshold: float
    window_s: int
    days: int
    raised: bool  # True: the raise condition holds; False: only "still elevated"


def direction_label(point: MeasurementPoint, counter: str) -> str:
    """download/upload where the area maps it, else the counter name."""
    mapping = direction_map(point)
    if mapping.download == counter:
        return "download"
    if mapping.upload == counter:
        return "upload"
    return counter


def detect(
    point: MeasurementPoint,
    recent: Sequence[Bucket],
    baseline: Baseline,
    clock: SlotClock,
    *,
    now: float,
) -> tuple[list[Finding], bool, bool]:
    """Findings over the recent complete buckets; (findings, learning, current).

    ``current`` is False when the newest complete bucket is missing or
    gappy: then nothing is decided (no candidate, and no all-clear for an
    open one either).
    """
    done = [b for b in recent if b.start + b.resolution_s <= now]
    findings: list[Finding] = []
    learning = True
    if not done:
        return findings, learning, False
    res = done[-1].resolution_s
    newest = done[-1]
    if newest.gappy or newest.start + 2 * res <= now:
        return findings, learning, False
    complete = [b for b in done if not b.gappy]
    for counter in ("rx", "tx"):
        label = direction_label(point, counter)
        rows = []
        for bucket in complete:
            slot, _day = clock.slot(bucket.start)
            rows.append(
                (
                    bucket,
                    avg_bps(bucket, counter),
                    baseline.stats(counter, slot),
                    baseline.peak_stats(counter, slot),
                )
            )
        _bucket, last_avg, last_stats, _ = rows[-1]
        if last_stats is None or last_avg is None:
            continue
        learning = False
        findings.extend(_high_findings(rows, label, res, clock))
        drop = _drop_finding(rows, label, res)
        if drop is not None:
            findings.append(drop)
        bursts = _burst_finding(rows, label, counter, res)
        if bursts is not None:
            findings.append(bursts)
    return findings, learning, True


def _trailing(rows: list[Any], test: Callable[[Any], bool]) -> int:
    count = 0
    for row in reversed(rows):
        if not test(row):
            break
        count += 1
    return count


def _ready(row: Any) -> bool:
    return row[1] is not None and row[2] is not None


def _high_findings(
    rows: list[Any], label: str, res: int, clock: SlotClock
) -> list[Finding]:
    out: list[Finding] = []
    _bucket, last_avg, stats, _ = rows[-1]
    spike_run = _trailing(rows, lambda r: _ready(r) and r[1] > r[2].above(K_RAISE))
    hour = clock.slot(rows[-1][0].start)[0][1]
    spike_kind = f"{label}_night_activity" if hour in NIGHT_HOURS else f"{label}_spike"
    if spike_run >= SPIKE_MIN_BUCKETS:
        run = rows[-spike_run:]
        out.append(
            Finding(
                spike_kind,
                max(r[1] for r in run),
                stats.median,
                stats.mad,
                stats.above(K_RAISE),
                spike_run * res,
                stats.days,
                True,
            )
        )
    elif last_avg > stats.above(K_CLEAR):
        out.append(
            Finding(
                spike_kind,
                last_avg,
                stats.median,
                stats.mad,
                stats.above(K_CLEAR),
                res,
                stats.days,
                False,
            )
        )
    sustained = _trailing(rows, lambda r: _ready(r) and r[1] > r[2].above(K_SUSTAINED))
    kind = f"{label}_sustained_high"
    if sustained >= SUSTAINED_MIN_BUCKETS:
        run = rows[-sustained:]
        out.append(
            Finding(
                kind,
                statistics.median([r[1] for r in run]),
                stats.median,
                stats.mad,
                stats.above(K_SUSTAINED),
                sustained * res,
                stats.days,
                True,
            )
        )
    elif last_avg > stats.above(K_SUSTAINED_CLEAR):
        out.append(
            Finding(
                kind,
                last_avg,
                stats.median,
                stats.mad,
                stats.above(K_SUSTAINED_CLEAR),
                res,
                stats.days,
                False,
            )
        )
    return out


def _drop_finding(rows: list[Any], label: str, res: int) -> Finding | None:
    _bucket, last_avg, stats, _ = rows[-1]
    if stats.median < DROP_MIN_MEDIAN_BPS:
        return None
    run = _trailing(
        rows,
        lambda r: (
            _ready(r)
            and r[2].median >= DROP_MIN_MEDIAN_BPS
            and r[1] <= DROP_RATIO * r[2].median
        ),
    )
    kind = f"{label}_drop"
    if run >= DROP_MIN_BUCKETS:
        return Finding(
            kind,
            last_avg,
            stats.median,
            stats.mad,
            DROP_RATIO * stats.median,
            run * res,
            stats.days,
            True,
        )
    if last_avg <= 2 * DROP_RATIO * stats.median:
        return Finding(
            kind,
            last_avg,
            stats.median,
            stats.mad,
            2 * DROP_RATIO * stats.median,
            res,
            stats.days,
            False,
        )
    return None


def _burst_finding(
    rows: list[Any], label: str, counter: str, res: int
) -> Finding | None:
    bursts = 0
    highest = 0.0
    ref = None
    for bucket, avg, stats, peak_stats in rows:
        peak = _peak(bucket, counter)
        if avg is None or stats is None or peak_stats is None or peak is None:
            continue
        if peak > peak_stats.above(K_RAISE) and avg <= stats.above(K_RAISE):
            bursts += 1
            highest = max(highest, peak)
            ref = peak_stats
    if ref is None:
        return None
    raised = bursts >= BURST_MIN_COUNT
    if not raised and bursts < max(1, BURST_MIN_COUNT // 2):
        return None
    return Finding(
        f"{label}_bursts",
        highest,
        ref.median,
        ref.mad,
        ref.above(K_RAISE),
        len(rows) * res,
        ref.days,
        raised,
    )


def volume_finding(
    point: MeasurementPoint, last_day: Sequence[Bucket], baseline: Baseline
) -> tuple[list[Finding], bool]:
    """Clients: the last 24 h against earlier daily volumes; (findings, learning)."""
    out: list[Finding] = []
    learning = True
    covered = sum(b.covered_s for b in last_day)
    if covered < GAPPY_BELOW * 86400:
        return out, learning
    for counter in ("rx", "tx"):
        stats = baseline.daily.get(counter)
        if stats is None or stats.values < VOLUME_MIN_DAYS:
            continue
        learning = False
        values = [b.rx_bytes if counter == "rx" else b.tx_bytes for b in last_day]
        observed = float(sum(v for v in values if v is not None))
        spread = max(stats.mad, SPREAD_REL_FLOOR * stats.median, 1.0)
        threshold = max(
            stats.median + K_RAISE * spread,
            VOLUME_RATIO * stats.median,
            float(VOLUME_MIN_BYTES),
        )
        if observed > threshold:
            label = direction_label(point, counter)
            out.append(
                Finding(
                    f"{label}_volume",
                    observed,
                    stats.median,
                    stats.mad,
                    threshold,
                    86400,
                    stats.values,
                    True,
                )
            )
    return out, learning


def confidence_of(finding: Finding, coverage: Coverage) -> float:
    """Confidence from the data base and coverage, never above 0.9."""
    base = 0.3 + 0.1 * min(finding.days, 6)
    if coverage is not Coverage.FULL:
        base *= 0.7
    return round(min(MAX_CONFIDENCE, base), 2)


# --- suppression rules -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SuppressionRule:
    """Silences traffic candidates (never anything else).

    ``point_id``/``kind`` None match any; ``until`` None never expires;
    ``hours`` limits the rule to local hours (None: all).
    """

    rule_id: str
    point_id: str | None = None
    kind: str | None = None
    until: float | None = None
    hours: frozenset[int] | None = None

    def __post_init__(self) -> None:
        """Only traffic kinds and traffic points are accepted."""
        if self.kind is not None and self.kind not in TRAFFIC_KINDS:
            raise ValueError("a suppression rule only acts on traffic kinds")
        if self.point_id is not None and not valid_point_id(self.point_id):
            raise ValueError("point_id must be tpt_<16 hex>")
        if self.point_id is None and self.kind is None and self.hours is None:
            raise ValueError("a rule must name a point, a kind or hours")

    def matches(self, point_id: str, kind: str, now: float, hour: int) -> bool:
        """True if the rule silences this candidate now."""
        if kind not in TRAFFIC_KINDS:
            return False
        if self.until is not None and now >= self.until:
            return False
        if self.point_id is not None and self.point_id != point_id:
            return False
        if self.kind is not None and self.kind != kind:
            return False
        return self.hours is None or hour in self.hours


# --- candidate book --------------------------------------------------------------------------


def candidate_id(point_id: str, kind: str, started: float) -> str:
    """Deterministic id of a candidate."""
    text = f"v1\x1f{point_id}\x1f{kind}\x1f{started:.0f}"
    return CANDIDATE_PREFIX + hashlib.sha256(text.encode()).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class CandidateEvent:
    """A start or end to publish."""

    event_type: str
    candidate: AnomalyCandidate


class CandidateBook:
    """At most 100 candidates: open/ended and suppressed in separate quotas."""

    def __init__(
        self,
        *,
        max_total: int = MAX_CANDIDATES,
        max_suppressed: int = MAX_CANDIDATES_SUPPRESSED,
    ) -> None:
        """Empty book."""
        self._max_main = max_total - max_suppressed
        self._max_suppressed = max_suppressed
        self.open: dict[tuple[str, str], AnomalyCandidate] = {}
        self.ended: deque[AnomalyCandidate] = deque()
        self.suppressed: deque[AnomalyCandidate] = deque()
        self._recent_end: dict[tuple[str, str], float] = {}
        self._opened: deque[float] = deque()
        self._opened_point: dict[str, deque[float]] = {}
        self._opened_kind: dict[tuple[str, str], float] = {}
        self.rules: list[SuppressionRule] = []
        self.counters: Counter[str] = Counter()

    def __len__(self) -> int:
        """Candidates held (open, ended, suppressed)."""
        return len(self.open) + len(self.ended) + len(self.suppressed)

    def add_rule(self, rule: SuppressionRule) -> None:
        """Add a suppression rule (bounded)."""
        if not isinstance(rule, SuppressionRule):
            raise TypeError("rule must be a SuppressionRule")
        if len(self.rules) >= MAX_SUPPRESSION_RULES:
            raise ValueError("too many suppression rules")
        self.rules = [r for r in self.rules if r.rule_id != rule.rule_id] + [rule]

    def _budget_reason(self, point_id: str, kind: str, now: float) -> str | None:
        while self._opened and now - self._opened[0] >= 3600:
            self._opened.popleft()
        per_point = self._opened_point.get(point_id)
        if per_point is not None:
            while per_point and now - per_point[0] >= 3600:
                per_point.popleft()
        last_kind = self._opened_kind.get((point_id, kind))
        if last_kind is not None and now - last_kind < BUDGET_POINT_KIND_S:
            return SUPPRESSED_BUDGET_POINT_KIND
        if per_point is not None and len(per_point) >= BUDGET_POINT_PER_HOUR:
            return SUPPRESSED_BUDGET_POINT
        if len(self._opened) >= BUDGET_PER_HOUR:
            return SUPPRESSED_BUDGET_HOUR
        return None

    def _charge(self, point_id: str, kind: str, now: float) -> None:
        self._opened.append(now)
        self._opened_point.setdefault(point_id, deque()).append(now)
        self._opened_kind[(point_id, kind)] = now

    def raise_candidate(
        self, candidate: AnomalyCandidate, *, now: float, hour: int
    ) -> CandidateEvent | None:
        """Open (or re-open, or suppress) a candidate; the event to publish."""
        key = (candidate.point_id, candidate.kind)
        current = self.open.get(key)
        if current is not None:
            self.open[key] = replace(
                current,
                last_seen=now,
                observed=max(current.observed, candidate.observed)
                if not candidate.kind.endswith("_drop")
                else min(current.observed, candidate.observed),
            )
            return None
        ended_at = self._recent_end.get(key)
        if ended_at is not None and now - ended_at < CANDIDATE_DEBOUNCE_S:
            for old in reversed(self.ended):
                if (old.point_id, old.kind) == key:
                    self.ended.remove(old)
                    self.open[key] = replace(
                        old, state=CandidateState.OPEN, last_seen=now
                    )
                    self.counters["reopened_debounce"] += 1
                    return None
        reason: str | None = None
        if any(r.matches(*key, now, hour) for r in self.rules):
            reason = SUPPRESSED_RULE
        if reason is None:
            reason = self._budget_reason(*key, now)
        if reason is None and len(self.open) >= self._max_main:
            reason = SUPPRESSED_STORE_FULL
        if reason is not None:
            self._suppress(replace(candidate, suppressed_reason=reason), key, now)
            return None
        self._charge(*key, now)
        while len(self.open) + len(self.ended) >= self._max_main and self.ended:
            self.ended.popleft()
            self.counters["dropped_ended"] += 1
        self.open[key] = candidate
        self.counters["opened"] += 1
        return CandidateEvent(EVENT_ANOMALY_STARTED, candidate)

    def _suppress(
        self, candidate: AnomalyCandidate, key: tuple[str, str], now: float
    ) -> None:
        self.counters[f"suppressed_{candidate.suppressed_reason}"] += 1
        for old in self.suppressed:
            if (old.point_id, old.kind) == key and old.suppressed_reason == (
                candidate.suppressed_reason
            ):
                self.suppressed.remove(old)
                candidate = replace(old, last_seen=now)
                break
        else:
            if len(self.suppressed) >= self._max_suppressed:
                self.suppressed.popleft()
                self.counters["dropped_suppressed"] += 1
        self.suppressed.append(replace(candidate, state=CandidateState.ENDED))

    def end(self, key: tuple[str, str], now: float) -> CandidateEvent | None:
        """End an open candidate; the end event."""
        current = self.open.pop(key, None)
        if current is None:
            return None
        ended = replace(current, state=CandidateState.ENDED, last_seen=now)
        self.ended.append(ended)
        self._recent_end[key] = now
        if len(self._recent_end) > 4 * MAX_CANDIDATES:
            cutoff = now - CANDIDATE_DEBOUNCE_S
            self._recent_end = {
                k: t for k, t in self._recent_end.items() if t >= cutoff
            }
        self.counters["ended"] += 1
        return CandidateEvent(EVENT_ANOMALY_ENDED, ended)

    def candidates(self, *, state: str | None = None) -> list[AnomalyCandidate]:
        """Candidates, newest first (``open``/``ended``/``suppressed``/None)."""
        groups: list[Iterable[AnomalyCandidate]] = []
        if state in (None, "open"):
            groups.append(self.open.values())
        if state in (None, "ended"):
            groups.append(self.ended)
        if state in (None, "suppressed"):
            groups.append(self.suppressed)
        items = [c for g in groups for c in g]
        items.sort(key=lambda c: (-c.last_seen, c.candidate_id))
        return items

    def drop_router(self, router_id: str | None) -> None:
        """Forget candidates of an unloaded router (no event)."""
        self.open = {k: c for k, c in self.open.items() if c.router_id != router_id}
        self.ended = deque(c for c in self.ended if c.router_id != router_id)
        self.suppressed = deque(c for c in self.suppressed if c.router_id != router_id)

    def clear(self) -> None:
        """Forget every candidate and budget (counters stay)."""
        self.open.clear()
        self.ended.clear()
        self.suppressed.clear()
        self._recent_end.clear()
        self._opened.clear()
        self._opened_point.clear()
        self._opened_kind.clear()


# --- publishing -----------------------------------------------------------------------------


def candidate_dict(candidate: AnomalyCandidate) -> dict[str, Any]:
    """JSON-safe form (pseudonyms and numbers only)."""
    return {
        "candidate_id": candidate.candidate_id,
        "point_id": candidate.point_id,
        "router_id": candidate.router_id,
        "client_ref": candidate.client_ref,
        "kind": candidate.kind,
        "observed": candidate.observed,
        "baseline_median": candidate.baseline_median,
        "baseline_mad": candidate.baseline_mad,
        "threshold": candidate.threshold,
        "window_s": candidate.window_s,
        "confidence": candidate.confidence,
        "coverage": candidate.coverage.value,
        "started": candidate.started,
        "last_seen": candidate.last_seen,
        "state": candidate.state.value,
        "suppressed_reason": candidate.suppressed_reason,
        "incident_ref": candidate.incident_ref,
        "incident_engine": INCIDENT_ENGINE_STATE,
        "classification": "traffic_deviation",
    }


class CandidatePublisher:
    """Publishes candidate events through the core API's ``emit``.

    ``emit`` is ``ConfigurationApi.emit`` (None while the core is not bound:
    nothing is published and ``not_published`` counts it).
    """

    def __init__(self, emit: Callable[..., Any] | None = None) -> None:
        """Publisher over ``emit``."""
        self.emit = emit
        self.counters: Counter[str] = Counter()

    def publish(self, event: CandidateEvent) -> bool:
        """Send one event; False when not bound or the core refused it."""
        if self.emit is None:
            self.counters["not_published"] += 1
            return False
        from .net_events import Severity

        candidate = event.candidate
        try:
            self.emit(
                event.event_type,
                source=MODULE_NAME,
                router_id=candidate.router_id,
                severity=Severity.INFO,
                dedup_key=f"{candidate.point_id}:{candidate.kind}:{event.event_type}",
                data={
                    "candidate_id": candidate.candidate_id,
                    "point": candidate.point_id,
                    "kind": candidate.kind,
                    "observed": candidate.observed,
                    "threshold": candidate.threshold,
                    "window_s": candidate.window_s,
                    "coverage": candidate.coverage.value,
                    "incident_engine": INCIDENT_ENGINE_STATE,
                },
                client_ref=candidate.client_ref,
                confidence=candidate.confidence,
                classification=candidate.kind,
            )
        except Exception as err:  # noqa: BLE001 - publishing never breaks traffic
            self.counters["publish_failed"] += 1
            _LOGGER.debug("Traffic candidate event failed (%s)", type(err).__name__)
            return False
        self.counters["published"] += 1
        return True


# --- detector --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Availability:
    """State of one detection family."""

    state: str
    reason: str | None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {"state": self.state, "reason": self.reason}


def family_availability(
    *,
    has_points: bool,
    conntrack_sources: Mapping[str, str | None] | None,
    flow_ready: bool,
) -> dict[str, Availability]:
    """What can be detected now and why not (see the module docstring)."""
    out: dict[str, Availability] = {}
    traffic = (
        Availability(ANOMALY_STATE_ACTIVE, None)
        if has_points
        else Availability(ANOMALY_STATE_UNAVAILABLE, REASON_NO_DATA_YET)
    )
    for name in (
        "spikes",
        "sustained_high",
        "sudden_drop",
        "night_activity",
        "repeated_bursts",
        "client_volume",
    ):
        out[name] = traffic
    sources = set((conntrack_sources or {}).values())
    if CONNTRACK_SOURCE_COUNT_FILE in sources:
        out["connection_rate"] = Availability(
            ANOMALY_STATE_COVERED_BY_NI, f"{REASON_NI_RULE}:system_conntrack_jump"
        )
    else:
        out["connection_rate"] = Availability(
            ANOMALY_STATE_UNAVAILABLE, REASON_CONNTRACK_NOT_COUNT_FILE
        )
    flows = (
        Availability(ANOMALY_STATE_LEARNING, REASON_FLOW_HISTORY_NOT_BUILT)
        if flow_ready
        else Availability(
            ANOMALY_STATE_UNAVAILABLE, CoverageReason.NEEDS_FLOW_SOURCE.value
        )
    )
    out["communication_pattern"] = flows
    out["inter_vlan"] = flows
    out["port_load"] = Availability(
        ANOMALY_STATE_COVERED_BY_NI, f"{REASON_NI_RULE}:lan_port_load"
    )
    out["port_errors"] = Availability(
        ANOMALY_STATE_COVERED_BY_NI, f"{REASON_NI_RULE}:lan_port_errors"
    )
    out["incident_engine"] = Availability(
        INCIDENT_ENGINE_STATE, REASON_NO_CANDIDATE_API
    )
    return out


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """Outcome of one evaluation pass (counts only)."""

    evaluated: int
    learning: int
    events: tuple[CandidateEvent, ...]
    families: Mapping[str, Availability]


class AnomalyDetector:
    """Evaluates the history interface; keeps candidates; publishes events."""

    def __init__(
        self,
        source: BucketSource,
        *,
        tz: tzinfo = UTC,
        publisher: CandidatePublisher | None = None,
    ) -> None:
        """Detector over ``source`` (local hours in ``tz``)."""
        self.source = source
        self.clock = SlotClock(tz)
        self.book = CandidateBook()
        self.publisher = publisher or CandidatePublisher()
        self._baselines: dict[str, Baseline] = {}
        self.counters: Counter[str] = Counter()
        self.last_families: Mapping[str, Availability] = family_availability(
            has_points=False, conntrack_sources=None, flow_ready=False
        )

    def baseline(self, point: MeasurementPoint, now: float) -> Baseline:
        """Baseline of ``point`` (rebuilt at most once per hour)."""
        hour = int(now // 3600)
        cached = self._baselines.get(point.point_id)
        if cached is not None and cached.built_hour == hour:
            return cached
        # Phase I: the hour tier (a 28-day window would pick daily buckets,
        # which have no hour slot); a single-resolution source ignores it.
        window = self.source.window(
            point.point_id,
            BASELINE_LOOKBACK_S,
            end=now - RECENT_WINDOW_S,
            resolution_s=BASELINE_RESOLUTION_S,
        )
        buckets = () if window is None else window.buckets
        baseline = build_baseline(buckets, self.clock, hour)
        self._baselines[point.point_id] = baseline
        self.counters["baselines_built"] += 1
        return baseline

    def evaluate(
        self,
        now: float,
        *,
        conntrack_sources: Mapping[str, str | None] | None = None,
        flow_ready: bool = False,
    ) -> EvaluationResult:
        """One pass over every evaluated point; publishes start/end events."""
        events: list[CandidateEvent] = []
        evaluated = learning = 0
        points = [p for p in self.source.points() if p.scope in EVALUATED_SCOPES]
        live = {p.point_id for p in points}
        for pid in [p for p in self._baselines if p not in live]:
            del self._baselines[pid]
        hour = self.clock.slot(now)[0][1]
        for point in points:
            recent = self.source.window(point.point_id, RECENT_WINDOW_S, end=now)
            if recent is None:
                continue
            baseline = self.baseline(point, now)
            findings, is_learning, current = detect(
                point, recent.buckets, baseline, self.clock, now=now
            )
            if not current:
                self.counters["no_current_data"] += 1
                continue
            if point.scope is Scope.CLIENT:
                day = self.source.window(point.point_id, 86400, end=now)
                if day is not None:
                    more, vol_learning = volume_finding(point, day.buckets, baseline)
                    findings.extend(more)
                    is_learning = is_learning and vol_learning
            if is_learning:
                learning += 1
                self.counters["learning_evaluations"] += 1
            evaluated += 1
            events.extend(
                self._apply(point, findings, recent.coverage, now=now, hour=hour)
            )
        for event in events:
            self.publisher.publish(event)
        families = family_availability(
            has_points=bool(points),
            conntrack_sources=conntrack_sources,
            flow_ready=flow_ready,
        )
        self.last_families = families
        self.counters["evaluations"] += 1
        return EvaluationResult(evaluated, learning, tuple(events), families)

    def _apply(
        self,
        point: MeasurementPoint,
        findings: list[Finding],
        coverage: Coverage,
        *,
        now: float,
        hour: int,
    ) -> list[CandidateEvent]:
        events: list[CandidateEvent] = []
        holding = {f.kind for f in findings}
        for finding in findings:
            if not finding.raised:
                continue
            candidate = AnomalyCandidate(
                candidate_id=candidate_id(point.point_id, finding.kind, now),
                point_id=point.point_id,
                router_id=point.router_id,
                client_ref=point.client_ref,
                kind=finding.kind,
                observed=round(finding.observed, 3),
                baseline_median=round(finding.median, 3),
                baseline_mad=round(finding.mad, 3),
                threshold=round(finding.threshold, 3),
                window_s=finding.window_s,
                confidence=confidence_of(finding, coverage),
                coverage=coverage,
                started=now,
                last_seen=now,
            )
            event = self.book.raise_candidate(candidate, now=now, hour=hour)
            if event is not None:
                events.append(event)
        for key in [k for k in self.book.open if k[0] == point.point_id]:
            if key[1] not in holding:
                event = self.book.end(key, now)
                if event is not None:
                    events.append(event)
        return events

    def drop_router(self, router_id: str | None) -> None:
        """Forget a router's candidates and baselines."""
        self.book.drop_router(router_id)
        for point in self.source.points():
            if point.router_id == router_id:
                self._baselines.pop(point.point_id, None)

    def clear(self) -> None:
        """Forget everything (module switched off)."""
        self.book.clear()
        self._baselines.clear()

    def summary(self) -> dict[str, Any]:
        """Counts only (no ids)."""
        return {
            "open": len(self.book.open),
            "ended": len(self.book.ended),
            "suppressed": len(self.book.suppressed),
            "rules": len(self.book.rules),
            "incident_engine": INCIDENT_ENGINE_STATE,
            "incident_engine_reason": REASON_NO_CANDIDATE_API,
            "published": self.publisher.counters["published"],
            "not_published": self.publisher.counters["not_published"],
            "not_published_reason": (
                REASON_NOT_PUBLISHED if self.publisher.emit is None else None
            ),
            "families": {k: v.to_dict() for k, v in self.last_families.items()},
            **dict(self.book.counters),
            **dict(self.counters),
        }
