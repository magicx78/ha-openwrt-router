"""Security score and monitoring coverage of the Security Center (stage 2, pure).

The score (0-100) starts at 100 and every factor deducts a transparent
amount: each :class:`FactorScore` carries its weight, deduction and an
English reason. Hard rules (plan 2):

* monitoring coverage (0-100) is the share of expected data sources that
  are available; a missing or stale source lowers it;
* below full coverage the score is capped below 100 (:func:`score_cap`):
  "nothing found" by an incomplete monitor is never a perfect value;
* with no usable source at all (or no assessable factor) the score is
  ``None`` (unknown), never 100;
* a factor whose source is missing is *not assessable*: it neither deducts
  0 (which would look "clean") nor anything else, and its weight drops out;
  so does a factor whose value is missing or not finite (NaN, inf). While
  any factor is not assessable the score stays below 100;
* a factor is *partially assessable* (``partial``) when a detector behind it
  reported a limitation (``compute_score(limitations=...)``, e.g.
  ``dest_zone_unknown`` or ``capacity``) or when an "any source" factor
  misses one of its expected sources. Its reason always says so ("none
  (partial: ...)", never a plain "none"), and a limitation lowers the
  coverage by half the factor's share of the weights;
* limitations never make the coverage drop when a source arrives (1.46.2):
  a factor's limitation costs nothing while one of its expected sources is
  not usable (the missing source is already counted in full), and all
  limitations together cost less than one source share
  (``LIMITATION_SHARE_CAP`` of ``100 / len(expected)``).

No clock, no I/O: inputs are counts and :class:`SourceStatus` values.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from .security_model import Availability, DataSource, Severity, SourceStatus

_LOGGER = logging.getLogger(__name__)

FACTOR_INCIDENTS: Final = "active_incidents"
FACTOR_CONFIG: Final = "critical_config_changes"
FACTOR_AUTH: Final = "login_failures"
FACTOR_ACTIVITY: Final = "network_activity"
FACTOR_UNKNOWN: Final = "unknown_devices"
FACTOR_SEGMENTATION: Final = "segmentation"
FACTOR_COVERAGE: Final = "detection_coverage"

PERFECT_SCORE: Final = 100
MAX_PARTIAL_SCORE: Final = 99
# All limitations together cost at most this fraction of one source share
# (1.46.2): a source that arrives with a limitation always raises the
# coverage, so neither coverage nor cap can drop.
LIMITATION_SHARE_CAP: Final = 0.5


@dataclass(frozen=True, kw_only=True, slots=True)
class FactorRule:
    """How one factor is scored.

    ``deduction = min(weight, value * per_unit)``. The factor is assessable
    if its sources are available: all of them, or any one with
    ``require="any"``.
    """

    id: str
    weight: float
    per_unit: float
    sources: frozenset[str]
    require: str = "all"  # "all" | "any"
    description: str = ""

    def assessable(self, statuses: Mapping[str, SourceStatus]) -> bool:
        """True if the rule's sources allow a judgement."""
        if not self.sources:
            return True
        ok = [(st := statuses.get(s)) is not None and st.usable for s in self.sources]
        return any(ok) if self.require == "any" else all(ok)


DEFAULT_RULES: Final[tuple[FactorRule, ...]] = (
    FactorRule(
        id=FACTOR_INCIDENTS,
        weight=30,
        per_unit=10,
        sources=frozenset({DataSource.NI_INCIDENTS}),
        description="Active security incidents (weighted by severity)",
    ),
    FactorRule(
        id=FACTOR_CONFIG,
        weight=15,
        per_unit=7.5,
        sources=frozenset({DataSource.CONFIG_DRIFT}),
        description="Critical configuration changes (drift events)",
    ),
    FactorRule(
        id=FACTOR_AUTH,
        weight=15,
        per_unit=5,
        sources=frozenset({DataSource.WIFI_EVENTS}),
        description="Clients with repeated authentication failures",
    ),
    FactorRule(
        id=FACTOR_ACTIVITY,
        weight=15,
        per_unit=5,
        sources=frozenset(
            {
                DataSource.FIREWALL_LOG,
                DataSource.DNS_QUERY_LOG,
                DataSource.CONNTRACK_STATS,
            }
        ),
        require="any",
        description="Unusual network activity (firewall, DNS, connections)",
    ),
    FactorRule(
        id=FACTOR_UNKNOWN,
        weight=10,
        per_unit=2.5,
        sources=frozenset({DataSource.HOSTAPD_CLIENTS, DataSource.CLIENT_HISTORY}),
        require="any",
        description="Unrecognized or suspicious devices",
    ),
    FactorRule(
        id=FACTOR_SEGMENTATION,
        weight=10,
        per_unit=5,
        sources=frozenset({DataSource.FIREWALL_LOG, DataSource.CONFIG_DRIFT}),
        require="any",
        description="Segmentation findings (inter-VLAN attempts, drift)",
    ),
    FactorRule(
        id=FACTOR_COVERAGE,
        weight=5,
        per_unit=0.05,  # per missing coverage point
        sources=frozenset(),
        description="Gaps in detection coverage",
    ),
)

DEFAULT_EXPECTED_SOURCES: Final = frozenset(
    {
        DataSource.NI_INCIDENTS,
        DataSource.WIFI_EVENTS,
        DataSource.HOSTAPD_CLIENTS,
        DataSource.CLIENT_HISTORY,
        DataSource.CONFIG_DRIFT,
        DataSource.FIREWALL_LOG,
        DataSource.DNS_QUERY_LOG,
    }
)


@dataclass(frozen=True, kw_only=True, slots=True)
class FactorScore:
    """One factor of the score (``deduction`` None = not assessable)."""

    id: str
    weight: float
    deduction: float | None
    assessable: bool
    reason: str
    value: float | None = None
    missing: tuple[str, ...] = ()
    partial: bool = False  # assessable, but with a limitation or a gap
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "id": self.id,
            "weight": self.weight,
            "deduction": self.deduction,
            "assessable": self.assessable,
            "reason": self.reason,
            "value": self.value,
            "missing": list(self.missing),
            "partial": self.partial,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class CoverageResult:
    """Monitoring coverage with the sources that lower it."""

    coverage: int
    available: tuple[str, ...] = ()
    stale: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True, slots=True)
class ScoreResult:
    """Score (None = unknown), coverage, cap and the factor breakdown."""

    score: int | None
    coverage: int
    cap: int
    factors: tuple[FactorScore, ...] = field(default=())
    reason: str = ""

    @property
    def known(self) -> bool:
        """True if a score could be computed."""
        return self.score is not None

    def factor(self, factor_id: str) -> FactorScore | None:
        """Factor by id."""
        return next((f for f in self.factors if f.id == factor_id), None)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (no identities: counts only)."""
        return {
            "score": self.score,
            "coverage": self.coverage,
            "cap": self.cap,
            "reason": self.reason,
            "factors": [f.to_dict() for f in self.factors],
        }


def monitoring_coverage(
    statuses: Mapping[str, SourceStatus],
    expected: Iterable[str] = DEFAULT_EXPECTED_SOURCES,
    *,
    stale_credit: float = 0.0,
) -> CoverageResult:
    """Share (0-100) of ``expected`` sources that are available.

    A source without a status counts as missing. A stale source earns
    ``stale_credit`` (default 0: old data does not cover the present).
    """
    names = sorted(set(expected))
    if not names:
        return CoverageResult(coverage=0)
    credit = min(1.0, max(0.0, float(stale_credit)))
    available, stale, missing = [], [], []
    for name in names:
        status = statuses.get(name)
        if status is None or status.availability is Availability.NOT_AVAILABLE:
            missing.append(name)
        elif status.availability is Availability.STALE:
            stale.append(name)
        else:
            available.append(name)
    share = (len(available) + credit * len(stale)) / len(names)
    coverage = int(share * 100)  # floor: 99.9 % is not full coverage
    return CoverageResult(
        coverage=coverage,
        available=tuple(available),
        stale=tuple(stale),
        missing=tuple(missing),
    )


def score_cap(coverage: int) -> int:
    """Highest score allowed at ``coverage`` (100 only at full coverage)."""
    if coverage >= 100:
        return PERFECT_SCORE
    return min(MAX_PARTIAL_SCORE, round(50 + max(0, coverage) / 2))


def incident_load(severities: Iterable[Severity | str]) -> float:
    """Weighted incident count: critical 3, warning 1, info 0.25."""
    weights = {Severity.CRITICAL: 3.0, Severity.WARNING: 1.0, Severity.INFO: 0.25}
    total = 0.0
    for sev in severities:
        try:
            total += weights[Severity(sev)]
        except ValueError:
            total += 1.0  # unknown severity: count as warning, never as 0
    return total


def _factor(
    rule: FactorRule,
    value: float | None,
    statuses: Mapping[str, SourceStatus],
    *,
    limits: tuple[str, ...] = (),
    expected: frozenset[str] = frozenset(),
) -> FactorScore:
    missing = tuple(
        sorted(s for s in rule.sources if not (statuses.get(s) and statuses[s].usable))
    )
    if not rule.assessable(statuses):
        return FactorScore(
            id=rule.id,
            weight=rule.weight,
            deduction=None,
            assessable=False,
            reason="not assessable: source unavailable",
            missing=missing,
        )
    if not _finite(value):
        return FactorScore(
            id=rule.id,
            weight=rule.weight,
            deduction=None,
            assessable=False,
            reason="not assessable: no value provided"
            if value is None
            else "not assessable: value not finite",
            missing=missing,
        )
    number = float(value)  # type: ignore[arg-type]
    deduction = round(min(rule.weight, max(0.0, number) * rule.per_unit), 2)
    reason = (
        f"{rule.description}: {number:g}" if deduction else f"{rule.description}: none"
    )
    gaps = (*limits, *(f"missing {s}" for s in missing if s in expected))
    if gaps:
        reason = f"{reason} (partial: {', '.join(gaps)})"
    return FactorScore(
        id=rule.id,
        weight=rule.weight,
        deduction=deduction,
        assessable=True,
        reason=reason,
        value=number,
        missing=missing,
        partial=bool(gaps),
        limitations=limits,
    )


def _finite(value: Any) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _limits_of(
    limitations: Mapping[str, Iterable[str]] | None, factor_id: str
) -> tuple[str, ...]:
    raw = (limitations or {}).get(factor_id) or ()
    if isinstance(raw, str):
        raw = (raw,)
    return tuple(dict.fromkeys(str(x)[:64] for x in raw if x))


def compute_score(
    values: Mapping[str, float | None],
    statuses: Mapping[str, SourceStatus],
    *,
    rules: Iterable[FactorRule] = DEFAULT_RULES,
    expected: Iterable[str] = DEFAULT_EXPECTED_SOURCES,
    stale_credit: float = 0.0,
    limitations: Mapping[str, Iterable[str]] | None = None,
) -> ScoreResult:
    """Score from factor ``values`` (factor id → count; None = unknown).

    ``limitations`` maps a factor id to the limitations its detectors
    reported (``DetectorResult.limitation``), e.g. ``{"segmentation":
    ("dest_zone_unknown",)}``: that factor is then partially assessable and
    the coverage drops by half its share of the factor weights. The coverage
    factor's value is filled in here (missing coverage points).
    Not-assessable factors drop out; the remaining deductions are scaled to
    the full 100 points so a missing factor neither helps nor hurts, and the
    result is then capped by :func:`score_cap` (below 100 while a factor is
    not assessable).
    """
    rules = tuple(rules)
    expected = frozenset(expected)
    cov = monitoring_coverage(statuses, expected, stale_credit=stale_credit)
    limits = {r.id: _limits_of(limitations, r.id) for r in rules}
    coverage = _limited_coverage(cov.coverage, rules, limits, statuses, expected)
    cap = score_cap(coverage)
    filled = {**values, FACTOR_COVERAGE: float(100 - coverage)}
    factors = tuple(
        _factor(r, filled.get(r.id), statuses, limits=limits[r.id], expected=expected)
        for r in rules
    )
    judged = [f for f in factors if f.assessable and f.id != FACTOR_COVERAGE]
    if coverage <= 0 or not judged:
        return ScoreResult(
            score=None,
            coverage=coverage,
            cap=cap,
            factors=factors,
            reason="unknown: no usable data source",
        )
    reason = "complete" if coverage >= 100 else f"capped at {cap}: partial coverage"
    if any(not f.assessable for f in factors) and cap > MAX_PARTIAL_SCORE:
        cap = MAX_PARTIAL_SCORE
        reason = f"capped at {cap}: a factor is not assessable"
    assessed = [f for f in factors if f.assessable]
    weight = sum(f.weight for f in assessed)
    lost = sum(f.deduction or 0.0 for f in assessed)
    raw = 100.0 * (1.0 - lost / weight) if weight > 0 else 0.0
    score = max(0, min(cap, round(raw)))
    return ScoreResult(
        score=score,
        coverage=coverage,
        cap=cap,
        factors=factors,
        reason=reason,
    )


def _limited_coverage(
    coverage: int,
    rules: tuple[FactorRule, ...],
    limits: Mapping[str, tuple[str, ...]],
    statuses: Mapping[str, SourceStatus],
    expected: frozenset[str] = DEFAULT_EXPECTED_SOURCES,
) -> int:
    """Coverage minus half the weight share of every limited factor.

    Monotonic (1.46.2): a limited factor costs nothing while one of its
    expected sources is not usable (that gap is already counted as a
    missing source), and the total is capped below one source share, so a
    source that arrives with a limitation never lowers the coverage.
    """
    weights = sum(r.weight for r in rules if r.id != FACTOR_COVERAGE)
    if weights <= 0 or not expected:
        return coverage

    def counts(rule: FactorRule) -> bool:
        if rule.id == FACTOR_COVERAGE or not limits.get(rule.id):
            return False
        if not rule.assessable(statuses):
            return False
        return all(
            (st := statuses.get(s)) is not None and st.usable
            for s in rule.sources & expected
        )

    share = sum(r.weight for r in rules if counts(r))
    deduction = min(
        100.0 * 0.5 * share / weights,
        LIMITATION_SHARE_CAP * 100.0 / len(expected),
    )
    return max(0, math.floor(coverage - deduction))
