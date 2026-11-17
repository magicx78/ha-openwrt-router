"""Active network diagnostics: Network Quality Score 0-100 with coverage.

Pure module: standard library plus :mod:`.diag_stats`, no Home Assistant, no
I/O, no clock.

Components
----------
Each component maps its input piecewise-linearly onto 0-100 points (linear
between the listed points, clamped outside them):

======================= ====== ======================== ==================================
component               weight input                    points (input -> points)
======================= ====== ======================== ==================================
wan_availability        25     WAN up time, %           90 -> 0, 95 -> 40, 99 -> 80,
                                                        99.9 -> 100
packet_loss             20     probe loss, %            0 -> 100, 1 -> 80, 2.5 -> 50,
                                                        5 -> 20, 10 -> 0
latency                 15     mean rtt, ms             20 -> 100, 50 -> 80, 100 -> 50,
                                                        200 -> 20, 400 -> 0
jitter                  10     jitter, ms               5 -> 100, 15 -> 70, 30 -> 40,
                                                        60 -> 0
dns                     15     failures, %              0 -> 100, 1 -> 80, 5 -> 40, 10 -> 0
                               response time, ms        30 -> 100, 100 -> 80, 300 -> 40,
                                                        1000 -> 0 (component = lower one)
gateway_reachability    10     gateway answered, %      90 -> 0, 95 -> 40, 99 -> 80,
                                                        99.9 -> 100
router_stability        5      unplanned restarts       0 -> 100, 1 -> 70, 3 -> 30, 5 -> 0
======================= ====== ======================== ==================================

Rules
-----
* A component has data when its :class:`Reading` has a value and coverage
  above 0 (DNS: the failure reading). Components without data are
  ``unknown``: left out of the weighted mean, they add 0 to coverage. They
  never count as perfect.
* ``score`` = weighted mean (weights above) of the components with data,
  rounded to 0.1. ``None`` when no component has data.
* ``coverage`` = ``sum(weight * component coverage) / sum(weight)`` over the
  applicable components; a component's coverage is its reading's coverage
  (share of expected probes that ran).
* Components the caller marks ``not_applicable`` (an AP has no WAN) leave
  score and coverage alone.
* ``low_confidence`` when ``coverage < MIN_COVERAGE`` (0.5) or the
  observation is shorter than ``MIN_OBSERVATION_S`` (1 h), or there is no
  score at all. The score is still shown.

Aggregation
-----------
Per router, per WAN connection and per segment use the same
:func:`compute_score` with the inputs of that scope. The whole network uses
:func:`combine_scores` over the router (or WAN) results:

* score = weighted mean (router weight, default 1) of the measured members,
  capped at ``NETWORK_WORST_MARGIN`` (25) points above the worst member that
  is not low-confidence -- one bad router cannot hide behind good ones, and a
  barely measured one cannot drag the network down;
* coverage = ``sum(weight * member coverage) / sum(weight)`` over all members;
  an unmeasured member (``None``) adds 0, so it lowers coverage, not score;
* observation = the shortest observation among measured members.
"""

from __future__ import annotations

import itertools
import logging
import math
from collections.abc import Mapping
from dataclasses import dataclass, field

from .diag_stats import DnsSummary, LatencySummary

_LOGGER = logging.getLogger(__name__)

# --- Constants ---------------------------------------------------------------

COMP_WAN = "wan_availability"
COMP_LOSS = "packet_loss"
COMP_LATENCY = "latency"
COMP_JITTER = "jitter"
COMP_DNS = "dns"
COMP_GATEWAY = "gateway_reachability"
COMP_STABILITY = "router_stability"

COMPONENT_WEIGHTS: Mapping[str, int] = {
    COMP_WAN: 25,
    COMP_LOSS: 20,
    COMP_LATENCY: 15,
    COMP_JITTER: 10,
    COMP_DNS: 15,
    COMP_GATEWAY: 10,
    COMP_STABILITY: 5,
}

Points = tuple[tuple[float, float], ...]

AVAILABILITY_POINTS: Points = ((90.0, 0.0), (95.0, 40.0), (99.0, 80.0), (99.9, 100.0))
LOSS_POINTS: Points = ((0.0, 100.0), (1.0, 80.0), (2.5, 50.0), (5.0, 20.0), (10.0, 0.0))
LATENCY_POINTS: Points = (
    (20.0, 100.0),
    (50.0, 80.0),
    (100.0, 50.0),
    (200.0, 20.0),
    (400.0, 0.0),
)
JITTER_POINTS: Points = ((5.0, 100.0), (15.0, 70.0), (30.0, 40.0), (60.0, 0.0))
DNS_FAILURE_POINTS: Points = ((0.0, 100.0), (1.0, 80.0), (5.0, 40.0), (10.0, 0.0))
DNS_RESPONSE_POINTS: Points = (
    (30.0, 100.0),
    (100.0, 80.0),
    (300.0, 40.0),
    (1000.0, 0.0),
)
RESTART_POINTS: Points = ((0.0, 100.0), (1.0, 70.0), (3.0, 30.0), (5.0, 0.0))

MIN_COVERAGE = 0.5
MIN_OBSERVATION_S = 3600.0
NETWORK_WORST_MARGIN = 25.0

STATUS_OK = "ok"
STATUS_UNKNOWN = "unknown"
STATUS_NOT_APPLICABLE = "not_applicable"


def piecewise(x: float, points: Points) -> float:
    """Piecewise-linear map through ``points`` (x ascending), clamped."""
    if len(points) < 2:
        raise ValueError("need at least two points")
    xs = [p[0] for p in points]
    if any(b <= a for a, b in itertools.pairwise(xs)):
        raise ValueError("points must have strictly ascending x")
    if x <= xs[0]:
        return points[0][1]
    for (x0, y0), (x1, y1) in itertools.pairwise(points):
        if x <= x1:
            return y0 + (y1 - y0) * (x - x0) / (x1 - x0)
    return points[-1][1]


# --- Inputs and results ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Reading:
    """One input value and the share (0-1) of expected measurements behind it."""

    value: float | None
    coverage: float = 1.0

    def __post_init__(self) -> None:
        if self.value is not None and not math.isfinite(self.value):
            raise ValueError("value must be finite")
        if not 0.0 <= self.coverage <= 1.0:
            raise ValueError("coverage must be in [0, 1]")

    @property
    def has_data(self) -> bool:
        return self.value is not None and self.coverage > 0.0


@dataclass(frozen=True, slots=True)
class ScoreInputs:
    """Inputs of one scope (router, WAN connection, segment)."""

    wan_availability: Reading | None = None  # %
    packet_loss: Reading | None = None  # %
    latency: Reading | None = None  # ms
    jitter: Reading | None = None  # ms
    dns_failure: Reading | None = None  # %
    dns_response: Reading | None = None  # ms
    gateway_reachability: Reading | None = None  # %
    router_restarts: Reading | None = None  # count in the window
    observation_seconds: float = 0.0
    not_applicable: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        unknown = set(self.not_applicable) - set(COMPONENT_WEIGHTS)
        if unknown:
            raise ValueError(f"unknown components: {sorted(unknown)}")
        if not math.isfinite(self.observation_seconds) or self.observation_seconds < 0:
            raise ValueError("observation_seconds must be finite and not negative")


@dataclass(frozen=True, slots=True)
class ComponentResult:
    """One line of the score breakdown."""

    name: str
    weight: float
    status: str
    score: float | None
    coverage: float
    inputs: tuple[tuple[str, float | None], ...]


@dataclass(frozen=True, slots=True)
class ScoreResult:
    """A score with its coverage, observation time and breakdown."""

    score: float | None
    coverage: float
    observation_seconds: float
    low_confidence: bool
    components: tuple[ComponentResult, ...]


def _value(reading: Reading | None) -> float | None:
    return reading.value if reading is not None else None


def _single(
    name: str, input_name: str, reading: Reading | None, points: Points
) -> ComponentResult:
    inputs = ((input_name, _value(reading)),)
    weight = COMPONENT_WEIGHTS[name]
    if reading is None or not reading.has_data:
        return ComponentResult(name, weight, STATUS_UNKNOWN, None, 0.0, inputs)
    score = piecewise(reading.value, points)  # type: ignore[arg-type]
    return ComponentResult(name, weight, STATUS_OK, score, reading.coverage, inputs)


def _dns(failure: Reading | None, response: Reading | None) -> ComponentResult:
    inputs = (("failure_pct", _value(failure)), ("response_ms", _value(response)))
    weight = COMPONENT_WEIGHTS[COMP_DNS]
    if failure is None or not failure.has_data:
        return ComponentResult(COMP_DNS, weight, STATUS_UNKNOWN, None, 0.0, inputs)
    score = piecewise(failure.value, DNS_FAILURE_POINTS)  # type: ignore[arg-type]
    if response is not None and response.has_data:
        score = min(score, piecewise(response.value, DNS_RESPONSE_POINTS))  # type: ignore[arg-type]
    return ComponentResult(COMP_DNS, weight, STATUS_OK, score, failure.coverage, inputs)


def _components(inputs: ScoreInputs) -> tuple[ComponentResult, ...]:
    return (
        _single(
            COMP_WAN, "availability_pct", inputs.wan_availability, AVAILABILITY_POINTS
        ),
        _single(COMP_LOSS, "loss_pct", inputs.packet_loss, LOSS_POINTS),
        _single(COMP_LATENCY, "latency_ms", inputs.latency, LATENCY_POINTS),
        _single(COMP_JITTER, "jitter_ms", inputs.jitter, JITTER_POINTS),
        _dns(inputs.dns_failure, inputs.dns_response),
        _single(
            COMP_GATEWAY,
            "reachability_pct",
            inputs.gateway_reachability,
            AVAILABILITY_POINTS,
        ),
        _single(COMP_STABILITY, "restarts", inputs.router_restarts, RESTART_POINTS),
    )


def _not_applicable(result: ComponentResult) -> ComponentResult:
    return ComponentResult(
        result.name, result.weight, STATUS_NOT_APPLICABLE, None, 0.0, result.inputs
    )


def _low_confidence(score: float | None, coverage: float, observed: float) -> bool:
    return score is None or coverage < MIN_COVERAGE or observed < MIN_OBSERVATION_S


def _aggregate(parts: tuple[ComponentResult, ...], observed: float) -> ScoreResult:
    """Weighted mean of parts with data, coverage over applicable parts."""
    applicable = [p for p in parts if p.status != STATUS_NOT_APPLICABLE]
    total = sum(p.weight for p in applicable)
    measured = [p for p in applicable if p.score is not None]
    measured_weight = sum(p.weight for p in measured)
    score = (
        round(sum(p.weight * p.score for p in measured) / measured_weight, 1)  # type: ignore[operator]
        if measured_weight > 0
        else None
    )
    coverage = sum(p.weight * p.coverage for p in applicable) / total if total else 0.0
    return ScoreResult(
        score=score,
        coverage=coverage,
        observation_seconds=observed,
        low_confidence=_low_confidence(score, coverage, observed),
        components=parts,
    )


def compute_score(inputs: ScoreInputs) -> ScoreResult:
    """Network Quality Score of one scope (router, WAN connection, segment)."""
    parts = tuple(
        _not_applicable(p) if p.name in inputs.not_applicable else p
        for p in _components(inputs)
    )
    observed = (
        inputs.observation_seconds if any(p.score is not None for p in parts) else 0.0
    )
    return _aggregate(parts, observed)


def combine_scores(
    members: Mapping[str, ScoreResult | None],
    *,
    weights: Mapping[str, float] | None = None,
) -> ScoreResult:
    """Whole-network score from router (or WAN) results; see module doc.

    ``None`` marks a member that was not measured at all. Member weights
    default to 1.0; the breakdown lists one line per member.
    """
    weights = weights or {}
    parts = []
    for name, result in members.items():
        weight = float(weights.get(name, 1.0))
        if not math.isfinite(weight) or weight <= 0:
            raise ValueError(f"weight of {name!r} must be positive")
        if result is None or result.score is None:
            cov = result.coverage if result is not None else 0.0
            inputs = (("observation_seconds", None),)
            parts.append(
                ComponentResult(name, weight, STATUS_UNKNOWN, None, cov, inputs)
            )
            continue
        inputs = (("observation_seconds", result.observation_seconds),)
        parts.append(
            ComponentResult(
                name, weight, STATUS_OK, result.score, result.coverage, inputs
            )
        )
    measured = [r for r in members.values() if r is not None and r.score is not None]
    observed = min((r.observation_seconds for r in measured), default=0.0)
    base = _aggregate(tuple(parts), observed)
    confident = [r.score for r in measured if not r.low_confidence]
    if base.score is None or not confident:
        return base
    capped = min(base.score, min(confident) + NETWORK_WORST_MARGIN)  # type: ignore[type-var]
    return ScoreResult(
        score=round(capped, 1),
        coverage=base.coverage,
        observation_seconds=base.observation_seconds,
        low_confidence=base.low_confidence,
        components=base.components,
    )


def inputs_from_summaries(
    *,
    path: LatencySummary | None = None,
    gateway: LatencySummary | None = None,
    dns: DnsSummary | None = None,
    wan_availability: Reading | None = None,
    router_restarts: Reading | None = None,
    observation_seconds: float = 0.0,
    not_applicable: frozenset[str] = frozenset(),
) -> ScoreInputs:
    """Build :class:`ScoreInputs` from statistics summaries.

    ``path`` feeds loss, latency and jitter (probes to the external or
    upstream target); ``gateway`` feeds gateway reachability
    (``100 - loss %``); ``dns`` feeds failure % and response time.
    """

    def reading(value: float | None, coverage: float) -> Reading | None:
        return Reading(value, coverage) if value is not None else None

    gateway_pct = (
        100.0 - gateway.loss_pct
        if gateway is not None and gateway.loss_pct is not None
        else None
    )
    return ScoreInputs(
        wan_availability=wan_availability,
        packet_loss=reading(path.loss_pct, path.coverage) if path else None,
        latency=reading(path.mean_ms, path.coverage) if path else None,
        jitter=reading(path.jitter_ms, path.coverage) if path else None,
        dns_failure=reading(dns.failure_pct, dns.coverage) if dns else None,
        dns_response=reading(dns.mean_ms, dns.coverage) if dns else None,
        gateway_reachability=(
            reading(gateway_pct, gateway.coverage) if gateway is not None else None
        ),
        router_restarts=router_restarts,
        observation_seconds=observation_seconds,
        not_applicable=not_applicable,
    )
