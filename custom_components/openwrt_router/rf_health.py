"""RF health score per radio, AP, network and SSID (pure, no HA, not wired up).

A radio's score is the weighted mean of the components that were actually
measured. Unmeasured components (``unsupported``, ``unreachable``,
``no_data``, ``stale``) never count as 100: their weight leaves the mean and
lowers ``coverage`` (the sum of the measured weights). Below
``min_coverage`` there is no score at all; below ``cap_coverage`` the score
is capped so that "little measured" never looks excellent.

Weights (sum 1.00, Startwert, nicht kalibriert):

============== ======
component      weight
============== ======
utilization    0.20
airtime        0.10
retries        0.15
signal         0.15
roaming        0.10
client_quality 0.10
overlap        0.10
stability      0.10
============== ======

Plan-only parts (``basis="plan"``): the overlap part counts as measured
only if at least one involved overlap conflict is ``measured`` or
``acceptable``. Otherwise (no conflicts, or only ``potential`` ones) it is a
plan result: state ``no_data`` with a score. Its weight never enters
``coverage`` and ``min_coverage`` is checked on measured parts only. The
plan score can only pull the mean down: the score is the lower of the
measured mean and the mean that includes the plan parts.

Aggregates (AP, network, SSID) weight each member by its client count
(minimum 1). Members without a score lower the coverage, not the score.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .rf_conflicts import Conflict, ConflictKind, ConflictStatus, RadioRef
from .rf_models import CapabilityState, Metric, RadioCapabilities

_LOGGER = logging.getLogger(__name__)

WEIGHTS: Mapping[str, float] = MappingProxyType(
    {
        "utilization": 0.20,
        "airtime": 0.10,
        "retries": 0.15,
        "signal": 0.15,
        "roaming": 0.10,
        "client_quality": 0.10,
        "overlap": 0.10,
        "stability": 0.10,
    }
)

GRADE_UNKNOWN = "unknown"
BASIS_MEASURED = "measured"
BASIS_PLAN = "plan"
_OVERLAP_KINDS = frozenset({ConflictKind.CO_CHANNEL, ConflictKind.ADJACENT_OVERLAP})
# Rounding of coverage sums so 0.1 + 0.2 style drift does not cross a limit.
_COVERAGE_DIGITS = 6


@dataclass(frozen=True)
class HealthThresholds:
    """Limits for the health score. All values: Startwert, nicht kalibriert."""

    min_coverage: float = 0.5
    cap_coverage: float = 0.8
    score_cap: int = 80
    grade_excellent: int = 90
    grade_good: int = 75
    grade_fair: int = 50
    # Utilization at or below ``util_good_pct`` scores 100, at or above
    # ``util_bad_pct`` 0, linear in between.
    util_good_pct: float = 30.0
    util_bad_pct: float = 90.0
    # Retry rate (retries per packet), same linear scheme.
    retry_good: float = 0.05
    retry_bad: float = 0.5
    # Penalty per conflict that involves the radio.
    overlap_potential_penalty: float = 10.0
    overlap_measured_penalty: float = 30.0


DEFAULT_HEALTH_THRESHOLDS = HealthThresholds()


@dataclass(frozen=True)
class ComponentScore:
    """One component: a 0..100 score when measured or a plan-only result.

    A plan-only component (``basis="plan"``) has state ``no_data`` and a
    score that may lower the radio score but never adds coverage.
    """

    name: str
    score: float | None
    state: CapabilityState
    evidence: tuple[str, ...]
    basis: str = BASIS_MEASURED

    def __post_init__(self) -> None:
        if self.name not in WEIGHTS:
            raise ValueError(f"unknown health component: {self.name}")
        if self.basis not in (BASIS_MEASURED, BASIS_PLAN):
            raise ValueError(f"unknown basis: {self.basis}")
        if self.basis == BASIS_PLAN and self.state is not CapabilityState.NO_DATA:
            raise ValueError(f"plan component {self.name} must be no_data")
        if self.state is CapabilityState.MEASURED or self.basis == BASIS_PLAN:
            if self.score is None or math.isnan(self.score):
                raise ValueError(f"component {self.name} needs a score")
            if not 0.0 <= self.score <= 100.0:
                raise ValueError(f"score out of range: {self.score}")
        elif self.score is not None:
            raise ValueError(f"{self.state} component must not carry a score")

    def as_dict(self) -> dict[str, Any]:
        """Return the component as a plain dict."""
        return {
            "name": self.name,
            "score": self.score,
            "state": self.state.value,
            "basis": self.basis,
            "weight": WEIGHTS[self.name],
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class HealthScore:
    """Health of one radio."""

    score: int | None
    coverage: float
    components: tuple[ComponentScore, ...]
    grade: str
    capped: bool
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the score as a plain dict."""
        return {
            "score": self.score,
            "coverage": self.coverage,
            "grade": self.grade,
            "capped": self.capped,
            "components": [c.as_dict() for c in self.components],
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class HealthItem:
    """One member of an aggregate (a radio of an AP, an AP of the network)."""

    key: str
    score: int | None
    coverage: float
    clients: int | None


@dataclass(frozen=True)
class AggregateHealth:
    """Health of an AP, the network or an SSID."""

    score: int | None
    coverage: float
    grade: str
    capped: bool
    worst_key: str | None
    worst_score: int | None
    items: tuple[HealthItem, ...]
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the aggregate as a plain dict."""
        return {
            "score": self.score,
            "coverage": self.coverage,
            "grade": self.grade,
            "capped": self.capped,
            "worst_key": self.worst_key,
            "worst_score": self.worst_score,
            "items": [
                {
                    "key": i.key,
                    "score": i.score,
                    "coverage": i.coverage,
                    "clients": i.clients,
                }
                for i in self.items
            ],
            "evidence": list(self.evidence),
        }


def grade(
    score: int | None, thresholds: HealthThresholds = DEFAULT_HEALTH_THRESHOLDS
) -> str:
    """Return the grade word for a score; None gives ``unknown``."""
    if score is None:
        return GRADE_UNKNOWN
    if score >= thresholds.grade_excellent:
        return "excellent"
    if score >= thresholds.grade_good:
        return "good"
    if score >= thresholds.grade_fair:
        return "fair"
    return "poor"


def _linear(value: float, good: float, bad: float) -> float:
    """100 at or better than ``good``, 0 at or worse than ``bad``."""
    if value <= good:
        return 100.0
    if value >= bad:
        return 0.0
    return 100.0 * (bad - value) / (bad - good)


def score_utilization(
    pct: float, thresholds: HealthThresholds = DEFAULT_HEALTH_THRESHOLDS
) -> float:
    """Score a channel utilization in percent."""
    return _linear(pct, thresholds.util_good_pct, thresholds.util_bad_pct)


def score_retry_rate(
    rate: float, thresholds: HealthThresholds = DEFAULT_HEALTH_THRESHOLDS
) -> float:
    """Score a retry rate (retries per packet)."""
    return _linear(rate, thresholds.retry_good, thresholds.retry_bad)


def component_from_metric(
    name: str, metric: Metric | None, scorer: Callable[[float], float]
) -> ComponentScore:
    """Build a component from one metric; no value never becomes a score."""
    if metric is None:
        return ComponentScore(name, None, CapabilityState.NO_DATA, (f"{name}:none",))
    if metric.state is not CapabilityState.MEASURED:
        evidence = (f"{name}:{metric.state.value}:{metric.source}",)
        return ComponentScore(name, None, metric.state, evidence)
    value = metric.value
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise TypeError(f"{name}: measured value is not a number: {value!r}")
    evidence = (f"{name}:{value:g}:{metric.source}",)
    return ComponentScore(
        name, scorer(float(value)), CapabilityState.MEASURED, evidence
    )


def overlap_component(
    ref: RadioRef,
    conflicts: Sequence[Conflict] | None,
    thresholds: HealthThresholds = DEFAULT_HEALTH_THRESHOLDS,
) -> ComponentScore:
    """Score the overlap of one radio from the conflict findings.

    ``conflicts=None`` means no conflict check ran (``no_data``). Acceptable
    findings cost nothing but stay in the evidence; findings that are not
    about overlap are listed as hints. Without a ``measured`` or
    ``acceptable`` overlap finding the result is plan basis (see module doc).
    """
    if conflicts is None:
        return ComponentScore(
            "overlap", None, CapabilityState.NO_DATA, ("overlap:not_checked",)
        )
    penalty = 0.0
    backed = False
    evidence: list[str] = []
    for conflict in conflicts:
        if ref not in conflict.members:
            continue
        others = ",".join(str(m) for m in conflict.members if m != ref)
        entry = f"{conflict.kind.value}:{conflict.status.value}:{others}"
        if conflict.kind not in _OVERLAP_KINDS:
            evidence.append(f"hint:{entry}")
            continue
        evidence.append(f"overlap:{entry}")
        if conflict.status is ConflictStatus.POTENTIAL:
            penalty += thresholds.overlap_potential_penalty
        else:
            backed = True
            if conflict.status is ConflictStatus.MEASURED:
                penalty += thresholds.overlap_measured_penalty
    if not evidence:
        evidence.append("overlap:no_conflicts")
    score = max(0.0, 100.0 - penalty)
    if backed:
        return ComponentScore(
            "overlap", score, CapabilityState.MEASURED, tuple(evidence)
        )
    evidence.append("overlap:plan_only")
    return ComponentScore(
        "overlap", score, CapabilityState.NO_DATA, tuple(evidence), BASIS_PLAN
    )


def _complete(components: Sequence[ComponentScore]) -> tuple[ComponentScore, ...]:
    """Return one component per weight, in weight order; gaps are no_data."""
    by_name: dict[str, ComponentScore] = {}
    for component in components:
        if component.name in by_name:
            raise ValueError(f"duplicate health component: {component.name}")
        by_name[component.name] = component
    return tuple(
        by_name.get(name)
        or ComponentScore(name, None, CapabilityState.NO_DATA, (f"{name}:not_given",))
        for name in WEIGHTS
    )


def _limit(
    mean: float | None, coverage: float, thresholds: HealthThresholds
) -> tuple[int | None, bool, tuple[str, ...]]:
    """Apply the minimum-coverage and cap rules to a mean score."""
    if mean is None or coverage < thresholds.min_coverage:
        return None, False, ("coverage_below_minimum",)
    score = round(mean)
    if coverage < thresholds.cap_coverage and score > thresholds.score_cap:
        cap = f"capped:coverage<{thresholds.cap_coverage:.2f}"
        return thresholds.score_cap, True, (cap,)
    return score, False, ()


def radio_health(
    components: Sequence[ComponentScore],
    thresholds: HealthThresholds = DEFAULT_HEALTH_THRESHOLDS,
) -> HealthScore:
    """Return the health of one radio from its component scores."""
    complete = _complete(components)
    measured = [c for c in complete if c.state is CapabilityState.MEASURED]
    plan = [c for c in complete if c.basis == BASIS_PLAN]
    coverage = round(sum(WEIGHTS[c.name] for c in measured), _COVERAGE_DIGITS)
    mean = None
    if measured:
        mean = _weighted_mean(measured)
        if plan:
            mean = min(mean, _weighted_mean([*measured, *plan]))
    score, capped, evidence = _limit(mean, coverage, thresholds)
    unmeasured = tuple(
        f"unmeasured:{c.name}:{c.state.value}"
        for c in complete
        if c.state is not CapabilityState.MEASURED
    )
    plan_notes = tuple(f"plan_basis:{c.name}" for c in plan)
    return HealthScore(
        score=score,
        coverage=coverage,
        components=complete,
        grade=grade(score, thresholds),
        capped=capped,
        evidence=evidence + unmeasured + plan_notes,
    )


def _weighted_mean(components: Sequence[ComponentScore]) -> float:
    total = sum(WEIGHTS[c.name] * (c.score or 0.0) for c in components)
    return total / sum(WEIGHTS[c.name] for c in components)


def item_from(
    key: str, health: HealthScore | AggregateHealth, clients: int | None
) -> HealthItem:
    """Turn a radio or AP result into a member of the next aggregate."""
    return HealthItem(key, health.score, health.coverage, clients)


def aggregate_health(
    items: Sequence[HealthItem],
    thresholds: HealthThresholds = DEFAULT_HEALTH_THRESHOLDS,
) -> AggregateHealth:
    """Client-weighted health of a group; unscored members lower coverage."""
    weights = [max(1, item.clients or 0) for item in items]
    total_weight = sum(weights)
    scored = [
        (w, i) for w, i in zip(weights, items, strict=True) if i.score is not None
    ]
    coverage = 0.0
    mean = None
    if scored:
        coverage = round(
            sum(w * i.coverage for w, i in scored) / total_weight, _COVERAGE_DIGITS
        )
        mean = sum(w * (i.score or 0) for w, i in scored) / sum(w for w, _ in scored)
    score, capped, evidence = _limit(mean, coverage, thresholds)
    worst = min((i for _, i in scored), key=lambda i: i.score or 0, default=None)
    unscored = tuple(f"unscored:{i.key}" for i in items if i.score is None)
    return AggregateHealth(
        score=score,
        coverage=coverage,
        grade=grade(score, thresholds),
        capped=capped,
        worst_key=worst.key if worst else None,
        worst_score=worst.score if worst else None,
        items=tuple(items),
        evidence=evidence + unscored,
    )


def ap_health(
    radio_items: Sequence[HealthItem],
    thresholds: HealthThresholds = DEFAULT_HEALTH_THRESHOLDS,
) -> AggregateHealth:
    """Health of one AP from its radios."""
    return aggregate_health(radio_items, thresholds)


def network_health(
    ap_items: Sequence[HealthItem],
    thresholds: HealthThresholds = DEFAULT_HEALTH_THRESHOLDS,
) -> AggregateHealth:
    """Health of the network from its APs."""
    return aggregate_health(ap_items, thresholds)


def ssid_health(
    radio_items: Sequence[HealthItem],
    thresholds: HealthThresholds = DEFAULT_HEALTH_THRESHOLDS,
) -> AggregateHealth:
    """Health of one SSID from the radios that carry it (any AP)."""
    return aggregate_health(radio_items, thresholds)


def monitoring_coverage(caps: Sequence[RadioCapabilities]) -> float:
    """Mean metric coverage over radios; 0.0 when nothing is assessed."""
    values = [c for c in (cap.coverage() for cap in caps) if c is not None]
    if not values:
        return 0.0
    return sum(values) / len(values)
