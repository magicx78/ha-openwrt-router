"""Self-Healing: risk, confidence score, decision, modes and loop policy (D).

Pure module (no Home Assistant import, no clock read, no router call):
plain data in, plain data out, so the engine (packages C1/I) can call it.
Developer document: ``docs/self-healing.md`` §7, §9, §10.

* :func:`classify_risk` - the risk of a catalog action in its context.
  Context (role, topology, management path, clients, what the service means
  on this router, security findings, maintenance) only ever RAISES the
  catalog's base risk; a missing fact makes the risk HIGH and unassessed,
  never a guess.
* :func:`score` - the Remediation Confidence Score: a rule table of named
  contributions in whole points that add up to the total (0..100).
* :func:`decide` - exactly one of the five outcomes (Unsupported, Not Safe,
  Insufficient Evidence, Requires Approval, Recommended) with every rule
  that fired. A link only by time never yields more than "diagnose".
* :func:`gate` / :func:`gate_for_router` - what may happen given the mode,
  the allowlist, a hold, a fleet pause and maintenance. 1.53.0 executes
  nothing that calls a router (``heal_catalog.EXECUTABLE_IN_RELEASE``).
* :func:`validate_allowlist` - Risk <= 1, ready catalog actions only.
* Loop protection on safety-clock time only: :func:`loop_verdict`,
  :func:`book_attempt`, :func:`record_outcome`, :func:`acknowledge_breaker`,
  :func:`dedupe_verdict`. The data types are ``heal_model``'s; the store
  (``heal_store``) persists them and enforces the same attempt rules at the
  durable step (a test checks both agree).
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, fields, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from . import heal_catalog as hc
from .heal_model import (
    ALLOWLIST_MAX,
    AUTO_HEAL_MAX_RISK,
    BACKOFF_STEP_MAX,
    RECENT_ATTEMPTS_MAX,
    RECENT_FAILURES_MAX,
    ROUTER_COMPONENT,
    TIME_MAX,
    ActionState,
    Actor,
    AllowEntry,
    AttemptRecord,
    BreakerRecord,
    BreakerState,
    CauseLevel,
    CauseStatus,
    Component,
    Decision,
    DecisionOutcome,
    Factor,
    FleetPause,
    HealMode,
    HealModelError,
    HealSettings,
    Impact,
    LoopKey,
    LoopLimits,
    LoopState,
    RemediationAction,
    Risk,
    RiskClass,
    SafetyClock,
    action_dedupe_id,
    component_dedupe_id,
    hold_reason_for,
    incident_dedupe_id,
)

_LOGGER = logging.getLogger(__name__)

O = DecisionOutcome

# The attempt window of the loop protection (the store counts the same).
ATTEMPT_WINDOW_S: Final = 86400
FLEET_WINDOW_S: Final = 86400
# The step a "diagnose first" outcome points at.
DIAGNOSE_STEP: Final = "diag.refresh"
# Booking an attempt needs room for its cooldown before TIME_MAX.
_BOOK_HEADROOM_S: Final = 400 * 86400

SCORE_MIN_DEFAULT: Final = 60
SCORE_MIN_BOUNDS: Final = (60, 100)  # only stricter than the default
MANUAL_FAILURES_DEFAULT: Final = 2
MANUAL_FAILURES_BOUNDS: Final = (1, 2)
AUTO_FAILURES_DEFAULT: Final = 1
AUTO_FAILURES_BOUNDS: Final = (1, 1)

ROLES: Final = ("gateway", "access_point", "unknown")
SEVERITIES: Final = ("info", "warning", "critical")


class PolicyError(ValueError):
    """Bad input to the policy (the message names the field, not the value)."""


def _fail(what: str) -> PolicyError:
    return PolicyError(f"invalid {what}")


def _opt_bool(value: Any, what: str) -> bool | None:
    if value is not None and not isinstance(value, bool):
        raise _fail(what)
    return value


def _opt_count(value: Any, what: str, hi: int = 1_000_000) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= hi:
        raise _fail(what)
    return value


def _safe(value: Any, what: str = "safe_now") -> float:
    """A safety-clock time (never the wall clock)."""
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or not 0 <= value <= TIME_MAX
    ):
        raise _fail(what)
    return float(value)


# ---------------------------------------------------------------------------
# Limits of the policy (configurable only towards stricter)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class PolicyLimits:
    """Score threshold and breaker thresholds within fixed bounds."""

    score_min: int = SCORE_MIN_DEFAULT
    manual_failures_to_open: int = MANUAL_FAILURES_DEFAULT
    auto_failures_to_open: int = AUTO_FAILURES_DEFAULT

    def __post_init__(self) -> None:
        """Validate against the bounds (raises :class:`PolicyError`)."""
        for name, (lo, hi) in (
            ("score_min", SCORE_MIN_BOUNDS),
            ("manual_failures_to_open", MANUAL_FAILURES_BOUNDS),
            ("auto_failures_to_open", AUTO_FAILURES_BOUNDS),
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not lo <= value <= hi
            ):
                raise _fail(f"policy.{name}")


DEFAULT_POLICY_LIMITS: Final = PolicyLimits()


def _limits(value: Any) -> PolicyLimits:
    """Only a real :class:`PolicyLimits` (its bounds were checked)."""
    if type(value) is not PolicyLimits:
        raise _fail("limits")
    return value


# ---------------------------------------------------------------------------
# Inputs: plain data, None means "not known"
# ---------------------------------------------------------------------------


class TargetFact(StrEnum):
    """What shows the fault on the action's target itself."""

    DIRECT = "direct"  # a direct state fact (e.g. the service is not running)
    LOG_ONLY = "log_only"  # only log lines point at it
    NONE = "none"  # nothing on the target


@dataclass(frozen=True, kw_only=True, slots=True)
class RiskContext:
    """What is known about the router and the target (None: unknown).

    ``dependants``: routers whose uplink runs through this router.
    ``target_on_mgmt_path``: the target (radio, interface) carries Home
    Assistant's management path to this router. ``target_is_wireless_uplink``:
    the radio has a STA or mesh interface. ``target_carries_dependants``: the
    target carries the uplink of other routers. ``service_enabled``: the
    target service is enabled in ``rc list`` (False: disabled on purpose).
    ``service_dependant_routers`` / ``service_dependant_clients``: other
    routers and clients that use this router's target service (DNS/DHCP).
    ``service_config_unapplied``: the saved configuration of the target
    service differs from the running one or changed recently, so a restart
    would put a change into effect (review of PR #77).
    """

    role: str | None = None
    identity_confirmed: bool | None = None
    reachable: bool | None = None
    dependants: int | None = None
    target_on_mgmt_path: bool | None = None
    target_is_wireless_uplink: bool | None = None
    target_carries_dependants: bool | None = None
    service_enabled: bool | None = None
    service_dependant_routers: int | None = None
    service_dependant_clients: int | None = None
    service_config_unapplied: bool | None = None
    clients_on_router: int | None = None
    clients_on_target: int | None = None
    open_security_findings: int | None = None
    in_maintenance: bool | None = None
    concurrent_repair: bool | None = None
    breaker_open: bool | None = None
    diag_enabled: bool | None = None

    def __post_init__(self) -> None:
        """Validate."""
        if self.role is not None and self.role not in ROLES:
            raise _fail("context.role")
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name == "role":
                continue
            if f.name in (
                "dependants",
                "service_dependant_routers",
                "service_dependant_clients",
                "clients_on_router",
                "clients_on_target",
                "open_security_findings",
            ):
                _opt_count(value, f"context.{f.name}")
            else:
                _opt_bool(value, f"context.{f.name}")


@dataclass(frozen=True, kw_only=True, slots=True)
class IncidentFacts:
    """The root incident as Network Intelligence reports it (never recomputed).

    ``temporal_only``: the only link to the target is a time window or an
    inferred edge. ``evidence_fresh``: the evidence is younger than two poll
    intervals. ``is_root``: a root incident, not a child it explains.
    ``cause_outside_router``: the cause lies outside this router (WAN down,
    upstream DNS, gateway unreachable); Playbook A (package F) fills it.
    ``severity`` None: unknown, scored like ``info``.
    """

    incident_type: str | None = None
    severity: str | None = None
    cause_level: CauseLevel = CauseLevel.UNKNOWN
    cause_status: CauseStatus = CauseStatus.HYPOTHESIS
    confidence: float | None = None
    source_families: int = 0
    is_root: bool | None = None
    temporal_only: bool | None = None
    evidence_fresh: bool | None = None
    target_fact: TargetFact | None = None
    cause_outside_router: bool | None = None

    def __post_init__(self) -> None:
        """Validate."""
        if self.severity is not None and self.severity not in SEVERITIES:
            raise _fail("incident.severity")
        try:
            object.__setattr__(self, "cause_level", CauseLevel(self.cause_level))
            object.__setattr__(self, "cause_status", CauseStatus(self.cause_status))
            if self.target_fact is not None:
                object.__setattr__(self, "target_fact", TargetFact(self.target_fact))
        except ValueError as err:
            raise _fail("incident") from err
        if self.confidence is not None and (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, int | float)
            or not math.isfinite(self.confidence)
            or not 0.0 <= self.confidence <= 1.0
        ):
            raise _fail("incident.confidence")
        _opt_count(self.source_families, "incident.source_families", 64)
        if self.source_families is None:
            raise _fail("incident.source_families")
        for name in (
            "is_root",
            "temporal_only",
            "evidence_fresh",
            "cause_outside_router",
        ):
            _opt_bool(getattr(self, name), f"incident.{name}")


_NO_INCIDENT: Final = IncidentFacts()


@dataclass(frozen=True, kw_only=True, slots=True)
class DecisionInput:
    """Everything :func:`decide` weighs (no time: a decision reads no clock).

    The only thing :func:`gate` accepts: the gate decides again from it, so
    no caller can hand in a decision of its own (review of PR #77).

    ``prior_failed_attempts``: failed or unknown attempts on the same loop
    key in 24 h (see :func:`prior_failed_attempts`); None (the default):
    unknown, which blocks a write (``history_unknown``).
    ``config_change_24h``: a configuration change or drift in the same area
    in 24 h (None: unknown, counted as a change). ``params`` is kept as a
    read-only copy, each value read once.
    """

    action_type: Any
    params: Any = None
    incident: IncidentFacts | None = None
    context: RiskContext = field(default_factory=RiskContext)
    prior_failed_attempts: int | None = None
    config_change_24h: bool | None = None

    def __post_init__(self) -> None:
        """Validate the typed parts (action and params go to the catalog)."""
        if self.incident is not None and type(self.incident) is not IncidentFacts:
            raise _fail("input.incident")
        if type(self.context) is not RiskContext:
            raise _fail("input.context")
        _opt_count(self.prior_failed_attempts, "input.prior_failed_attempts", 1000)
        _opt_bool(self.config_change_24h, "input.config_change_24h")
        if isinstance(self.params, Mapping):
            # one read per value; later changes of the caller's mapping
            # cannot reach the decision
            snapshot = dict(list(self.params.items()))
            object.__setattr__(self, "params", MappingProxyType(snapshot))


# ---------------------------------------------------------------------------
# Risk classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class RiskAssessment:
    """Risk class with the reasons that raised it above the catalog base."""

    risk_class: RiskClass
    base: RiskClass
    reasons: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()  # needed context facts that were not known
    assessed: bool = True  # False: a fact was missing, the class is HIGH

    def to_model(self) -> Risk:
        """The model's ``Risk`` part."""
        return Risk(risk_class=self.risk_class, reasons=self.reasons[:16])


RISK_CODES: Final = frozenset(
    {
        "role_unknown",
        "identity_not_confirmed",
        "open_security_finding",
        "in_maintenance_window",
        "service_disabled_on_purpose",
        "target_on_management_path",
        "wireless_uplink_radio",
        "uplink_for_other_routers",
        "clients_affected",
        "service_serves_other_routers",
        "service_config_unapplied",
        "context_missing",
        "not_in_catalog",
    }
)


def classify_risk(va: hc.ValidatedAction, context: RiskContext) -> RiskAssessment:
    """Risk of ``va`` on this router: the catalog base, raised by context.

    Rules (each names itself in ``reasons``; none lowers the class):

    * a write on a router whose role is unknown, whose identity is not
      confirmed or that has an open security finding: HIGH;
    * a write during a maintenance window: at least MEDIUM;
    * a service restart of a service disabled on purpose (it would start a
      second DHCP/DNS server; "not running" is the intended state): HIGH;
    * a radio or interface that carries HA's management path, and every
      router reboot (it cuts HA's path to the router): HIGH;
    * a radio with a STA or mesh interface (a wireless uplink): HIGH;
    * a reboot of a router other routers hang behind, or a radio/interface
      carrying their uplink: HIGH;
    * a disruption with clients on the router (radio: on the radio): at
      least MEDIUM;
    * a service restart on a router whose DNS/DHCP other routers use: at
      least MEDIUM, named ``service_serves_other_routers`` (owner of the
      order: the restart stays Risk 2 on a gateway, the approval shows who
      depends on it);
    * a service restart while the saved configuration of the service is
      not applied (the restart would put it into effect): HIGH;
    * a needed fact not known: HIGH and unassessed (``context_missing``).

    Unknown (None) facts never count as harmless: every rule below that
    tests a fact only for a known value relies on the fact being in the
    action's ``needs_facts``, so None ends in ``context_missing``.
    """
    if type(va) is not hc.ValidatedAction:
        raise _fail("validated action")
    if type(context) is not RiskContext:
        raise _fail("context")
    e = va.entry
    level = e.base_risk
    reasons: list[str] = []

    def raise_to(floor: RiskClass, code: str) -> None:
        nonlocal level
        if code not in reasons:
            reasons.append(code)
        level = max(level, floor)

    c = context
    d = e.disruption
    if e.writes:
        if c.role == "unknown":
            raise_to(RiskClass.HIGH, "role_unknown")
        if c.identity_confirmed is False:
            raise_to(RiskClass.HIGH, "identity_not_confirmed")
        if c.open_security_findings is not None and c.open_security_findings > 0:
            raise_to(RiskClass.HIGH, "open_security_finding")
        if c.in_maintenance is True:
            raise_to(RiskClass.MEDIUM, "in_maintenance_window")
    if d is hc.Disruption.SERVICE and c.service_enabled is False:
        raise_to(RiskClass.HIGH, "service_disabled_on_purpose")
    if d is hc.Disruption.SERVICE and c.service_config_unapplied is True:
        raise_to(RiskClass.HIGH, "service_config_unapplied")
    if (
        d is hc.Disruption.SERVICE
        and c.service_dependant_routers is not None
        and c.service_dependant_routers > 0
    ):
        raise_to(RiskClass.MEDIUM, "service_serves_other_routers")
    if d is hc.Disruption.ROUTER or (
        d in (hc.Disruption.RADIO, hc.Disruption.INTERFACE)
        and c.target_on_mgmt_path is True
    ):
        raise_to(RiskClass.HIGH, "target_on_management_path")
    if d is hc.Disruption.RADIO and c.target_is_wireless_uplink is True:
        raise_to(RiskClass.HIGH, "wireless_uplink_radio")
    if (
        d is hc.Disruption.ROUTER and c.dependants is not None and c.dependants > 0
    ) or (
        d in (hc.Disruption.RADIO, hc.Disruption.INTERFACE)
        and c.target_carries_dependants is True
    ):
        raise_to(RiskClass.HIGH, "uplink_for_other_routers")
    clients = c.clients_on_target if d is hc.Disruption.RADIO else c.clients_on_router
    if d is not hc.Disruption.NONE and clients is not None and clients > 0:
        raise_to(RiskClass.MEDIUM, "clients_affected")
    missing = tuple(name for name in e.needs_facts if getattr(c, name) is None)
    if missing:
        raise_to(RiskClass.HIGH, "context_missing")
    return RiskAssessment(
        risk_class=RiskClass(level),
        base=e.base_risk,
        reasons=tuple(reasons),
        missing=missing,
        assessed=not missing,
    )


# ---------------------------------------------------------------------------
# Remediation Confidence Score (rule table in whole points)
# ---------------------------------------------------------------------------

CAUSE_LEVEL_POINTS: Final[Mapping[CauseLevel, int]] = MappingProxyType(
    {
        CauseLevel.CONFIRMED: 40,
        CauseLevel.LIKELY: 30,
        CauseLevel.POSSIBLE: 15,
        CauseLevel.UNKNOWN: 0,
    }
)
CAUSE_STATUS_POINTS: Final[Mapping[CauseStatus, int]] = MappingProxyType(
    {CauseStatus.CONFIRMED: 10, CauseStatus.HYPOTHESIS: 0}
)
CONFIDENCE_POINTS_MAX: Final = 10
SOURCE_FAMILY_POINTS: Final = (0, 5, 10)  # 0, 1, 2 or more families
TARGET_FACT_POINTS: Final[Mapping[TargetFact | None, int]] = MappingProxyType(
    {TargetFact.DIRECT: 30, TargetFact.LOG_ONLY: 10, TargetFact.NONE: 0, None: 0}
)
PRIOR_ATTEMPT_POINTS: Final = -25  # per failed or unknown attempt in 24 h
# unknown history costs at least one unknown attempt (and blocks a write)
PRIOR_UNKNOWN_POINTS: Final = PRIOR_ATTEMPT_POINTS
CONFIG_CHANGE_POINTS: Final = -20  # a change in the same area in 24 h, or unknown
SEVERITY_POINTS: Final[Mapping[str | None, int]] = MappingProxyType(
    {"info": -10, "warning": 0, "critical": 0, None: -10}  # unknown like info
)
SCORE_MAX: Final = 100


@dataclass(frozen=True, kw_only=True, slots=True)
class Contribution:
    """One named line of the score: whole points and the reason code."""

    factor: str
    points: int
    reason: str


@dataclass(frozen=True, kw_only=True, slots=True)
class ScoreBreakdown:
    """The score: its contributions add up to ``total`` (0..100)."""

    contributions: tuple[Contribution, ...]
    total: int

    @property
    def unit(self) -> float:
        """The score as 0..1 (the model's ``Decision.score``)."""
        return self.total / SCORE_MAX


def _half_up(value: float) -> int:
    return math.floor(value + 0.5 + 1e-9)


def score(
    incident: IncidentFacts | None,
    *,
    prior_failed_attempts: int,
    config_change_24h: bool | None,
) -> ScoreBreakdown:
    """The Remediation Confidence Score of an incident (docs §9 rule table).

    Evidence adds: cause level 0/15/30/40, cause status confirmed +10,
    NI confidence up to +10 (10 x confidence, half up), source families
    0/+5/+10, a fact on the target itself 0/+10/+30. History subtracts:
    -25 per failed or unknown attempt on the same key in 24 h (unknown
    history: -25 as one unknown attempt), -20 for a configuration change in
    the same area in 24 h (unknown counts), -10 for an info-level or unknown
    severity. A last line ``clamp`` brings the sum into 0..100, so the
    contributions always add up to the total.
    """
    if incident is not None and type(incident) is not IncidentFacts:
        raise _fail("incident")
    inc = _NO_INCIDENT if incident is None else incident
    prior = _opt_count(prior_failed_attempts, "prior_failed_attempts", 1000)
    _opt_bool(config_change_24h, "config_change_24h")
    lines: list[Contribution] = [
        Contribution(
            factor="cause_level",
            points=CAUSE_LEVEL_POINTS[inc.cause_level],
            reason=f"cause_level_{inc.cause_level.value}",
        ),
        Contribution(
            factor="cause_status",
            points=CAUSE_STATUS_POINTS[inc.cause_status],
            reason=f"cause_status_{inc.cause_status.value}",
        ),
        Contribution(
            factor="incident_confidence",
            points=(
                0
                if inc.confidence is None
                else _half_up(CONFIDENCE_POINTS_MAX * inc.confidence)
            ),
            reason=(
                "confidence_missing"
                if inc.confidence is None
                else "incident_confidence_scaled"
            ),
        ),
        Contribution(
            factor="source_families",
            points=SOURCE_FAMILY_POINTS[min(inc.source_families, 2)],
            reason=(
                "no_source_family",
                "one_source_family",
                "two_or_more_source_families",
            )[min(inc.source_families, 2)],
        ),
        Contribution(
            factor="target_fact",
            points=TARGET_FACT_POINTS[inc.target_fact],
            reason=f"target_fact_{(inc.target_fact or TargetFact.NONE).value}",
        ),
        Contribution(
            factor="prior_attempts",
            points=(
                PRIOR_UNKNOWN_POINTS if prior is None else PRIOR_ATTEMPT_POINTS * prior
            ),
            reason=(
                "prior_attempts_unknown"
                if prior is None
                else ("prior_failed_attempts" if prior > 0 else "no_prior_attempts")
            ),
        ),
        Contribution(
            factor="config_change",
            points=0 if config_change_24h is False else CONFIG_CHANGE_POINTS,
            reason={
                False: "no_config_change_24h",
                True: "config_change_24h",
                None: "config_change_unknown",
            }[config_change_24h],
        ),
        Contribution(
            factor="severity",
            points=SEVERITY_POINTS[inc.severity],
            reason=(
                "severity_unknown"
                if inc.severity is None
                else f"severity_{inc.severity}"
            ),
        ),
    ]
    raw = sum(line.points for line in lines)
    total = min(max(raw, 0), SCORE_MAX)
    lines.append(
        Contribution(
            factor="clamp",
            points=total - raw,
            reason="within_range" if total == raw else "clamped_to_range",
        )
    )
    return ScoreBreakdown(contributions=tuple(lines), total=total)


SCORE_CODES: Final = frozenset(
    {
        "cause_level",
        "cause_status",
        "incident_confidence",
        "source_families",
        "target_fact",
        "prior_attempts",
        "config_change",
        "severity",
        "clamp",
        *(f"cause_level_{v.value}" for v in CauseLevel),
        *(f"cause_status_{v.value}" for v in CauseStatus),
        "confidence_missing",
        "incident_confidence_scaled",
        "no_source_family",
        "one_source_family",
        "two_or_more_source_families",
        *(f"target_fact_{v.value}" for v in TargetFact),
        "prior_failed_attempts",
        "prior_attempts_unknown",
        "no_prior_attempts",
        "no_config_change_24h",
        "config_change_24h",
        "config_change_unknown",
        *(f"severity_{v}" for v in SEVERITIES),
        "severity_unknown",
        "within_range",
        "clamped_to_range",
    }
)


# ---------------------------------------------------------------------------
# Decision: the five outcomes with their explanation
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class RuleHit:
    """One rule that fired: its code, the outcome it stands for (None: a
    note), whether it blocks, and plain details (codes and counts)."""

    code: str
    outcome: DecisionOutcome | None = None
    blocking: bool = False
    detail: tuple[tuple[str, Any], ...] = ()


@dataclass(frozen=True, kw_only=True, slots=True)
class PolicyDecision:
    """The decision on one action with everything needed to explain it.

    Only for showing and storing: :func:`gate` never takes one (it decides
    again from the :class:`DecisionInput`), so altering a decision changes
    nothing that is allowed. ``impact``: counts only - clients on the router
    and on the target, routers behind it, routers and clients that use its
    DNS/DHCP, the estimated outage.
    """

    action_type: str | None
    params: Mapping[str, str]
    outcome: DecisionOutcome
    risk: RiskAssessment
    score: ScoreBreakdown
    hits: tuple[RuleHit, ...]
    why: str
    why_not: str | None
    next_step: str | None
    writes: bool
    impact: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    catalog_version: int = hc.CATALOG_VERSION

    def to_impact(self) -> Impact:
        """The model's expected-impact part (router ids come from the engine).

        ``clients_on_component``: clients on the radio for a radio action,
        clients that use the service for a service restart.
        """
        imp = self.impact
        component = (
            imp.get("service_dependant_clients")
            if imp.get("disruption") == hc.Disruption.SERVICE.value
            else imp.get("clients_on_target")
        )
        return Impact(
            clients_on_router=imp.get("clients_on_router"),
            clients_on_component=component,
            est_outage_s=imp.get("est_outage_s"),
        )

    def to_model(self) -> Decision:
        """The model's ``Decision`` part (outcome, score, factors, why)."""
        return Decision(
            outcome=self.outcome,
            score=self.score.unit,
            factors=tuple(
                Factor(factor=c.factor, value=c.points / SCORE_MAX, reason=c.reason)
                for c in self.score.contributions
            ),
            why=self.why,
            why_not=self.why_not,
        )

    def explanation(self) -> dict[str, Any]:
        """Plain JSON a later UI renders (German texts: ``REASON_TEXT_DE``)."""
        return {
            "action_type": self.action_type,
            "params": dict(self.params),
            "outcome": self.outcome.value,
            "why": self.why,
            "why_not": self.why_not,
            "next_step": self.next_step,
            "writes": self.writes,
            "catalog_version": self.catalog_version,
            "impact": dict(self.impact),
            "score": {
                "total": self.score.total,
                "unit": self.score.unit,
                "contributions": [
                    {"factor": c.factor, "points": c.points, "reason": c.reason}
                    for c in self.score.contributions
                ],
            },
            "risk": {
                "risk_class": int(self.risk.risk_class),
                "base": int(self.risk.base),
                "reasons": list(self.risk.reasons),
                "missing": list(self.risk.missing),
                "assessed": self.risk.assessed,
            },
            "rules": [
                {
                    "code": h.code,
                    "outcome": h.outcome.value if h.outcome else None,
                    "blocking": h.blocking,
                    "detail": dict(h.detail),
                }
                for h in self.hits
            ],
        }


# Order of the outcomes: the first one with a blocking rule wins.
_BLOCK_ORDER: Final = (O.UNSUPPORTED, O.NOT_SAFE, O.INSUFFICIENT_EVIDENCE)
_WHY_BLOCKED: Final[Mapping[DecisionOutcome, str]] = MappingProxyType(
    {
        O.UNSUPPORTED: "outcome_unsupported",
        O.NOT_SAFE: "outcome_not_safe",
        O.INSUFFICIENT_EVIDENCE: "outcome_insufficient_evidence",
    }
)
# Risk reasons that are hard facts against a write (Not Safe).
_NOT_SAFE_RISK_REASONS: Final = (
    "role_unknown",
    "identity_not_confirmed",
    "open_security_finding",
    "service_disabled_on_purpose",
    "service_config_unapplied",
    "target_on_management_path",
    "wireless_uplink_radio",
    "uplink_for_other_routers",
)

DECISION_CODES: Final = frozenset(
    {
        *hc.REFUSAL_CODES,
        "action_disabled",
        "not_root_incident",
        "diagnostics_off",
        "router_unreachable",
        "breaker_open",
        "concurrent_repair",
        "risk_high_no_recovery",
        *_NOT_SAFE_RISK_REASONS,
        "context_missing",
        "history_unknown",
        "cause_outside_router",
        "cause_location_unknown",
        "no_incident",
        "root_unknown",
        "temporal_correlation_only",
        "evidence_stale",
        "hypothesis_single_source",
        "no_direct_target_fact",
        "score_below_threshold",
        "temporal_link_diagnose_only",
        "impact_summary",
        "recovery_statement",
        "risk_needs_approval",
        "all_rules_passed",
        *_WHY_BLOCKED.values(),
    }
)


def _hit(
    hits: list[RuleHit], code: str, outcome: DecisionOutcome | None, **detail: Any
) -> None:
    hits.append(
        RuleHit(
            code=code,
            outcome=outcome,
            blocking=outcome is not None,
            detail=tuple(sorted(detail.items())),
        )
    )


def _refused(inp: DecisionInput, code: str) -> PolicyDecision:
    hits: list[RuleHit] = []
    _hit(hits, code, O.UNSUPPORTED)
    return PolicyDecision(
        action_type=inp.action_type
        if type(inp.action_type) is str and code != "action_type_invalid"
        else None,
        params=MappingProxyType({}),
        outcome=O.UNSUPPORTED,
        risk=RiskAssessment(
            risk_class=RiskClass.HIGH,
            base=RiskClass.HIGH,
            reasons=("not_in_catalog",),
            assessed=False,
        ),
        score=score(
            inp.incident,
            prior_failed_attempts=inp.prior_failed_attempts,
            config_change_24h=inp.config_change_24h,
        ),
        hits=tuple(hits),
        why=_WHY_BLOCKED[O.UNSUPPORTED],
        why_not=code,
        next_step=None,
        writes=False,
    )


def decide(
    inp: DecisionInput, limits: PolicyLimits = DEFAULT_POLICY_LIMITS
) -> PolicyDecision:
    """Exactly one outcome for the action in ``inp``, with every rule that fired.

    The first outcome with a blocking rule wins, in this order:

    1. **Unsupported**: not in the catalog (unknown id, never-family, bad
       params), disabled in the catalog, a child incident (only the root is
       repaired), or the probes' module is off.
    2. **Not Safe** (writes): router unreachable, identity not confirmed,
       role unknown, open security finding, service disabled on purpose,
       saved service configuration not applied, the cause outside the
       router (service restart), management path, wireless uplink, uplink
       of other routers, an open breaker, a concurrent repair, or HIGH risk
       (no rollback mechanism exists).
    3. **Insufficient Evidence**: a needed fact unknown; for writes also
       unknown attempt history, no incident, root unknown, the cause's
       location unknown (service restart), a link only by time, stale
       evidence, a hypothesis with fewer than two source families, no
       direct fact on the target, or a score below the threshold. Points at
       ``diag.refresh``.
    4. **Requires Approval**: a write of Risk 2 or more.
    5. **Recommended**: everything else (diagnostics, Risk <= 1).
    """
    if type(inp) is not DecisionInput:
        raise _fail("input")
    limits = _limits(limits)
    va, refusal = hc.try_validate(inp.action_type, inp.params)
    if va is None:
        return _refused(inp, "unknown_action" if refusal is None else refusal)
    e = va.entry
    c = inp.context
    risk = classify_risk(va, c)
    s = score(
        inp.incident,
        prior_failed_attempts=inp.prior_failed_attempts,
        config_change_24h=inp.config_change_24h,
    )
    hits: list[RuleHit] = []
    inc = inp.incident

    # 1. Unsupported
    if e.status is hc.CatalogStatus.DISABLED:
        _hit(hits, "action_disabled", O.UNSUPPORTED, status_reason=e.status_reason)
    if e.writes and inc is not None and inc.is_root is False:
        _hit(hits, "not_root_incident", O.UNSUPPORTED)
    if "diag_enabled" in e.needs_facts and c.diag_enabled is False:
        _hit(hits, "diagnostics_off", O.UNSUPPORTED)

    # 2. Not Safe (hard facts against a write)
    if e.writes:
        if c.reachable is False:
            _hit(hits, "router_unreachable", O.NOT_SAFE)
        for code in _NOT_SAFE_RISK_REASONS:
            if code in risk.reasons:
                _hit(hits, code, O.NOT_SAFE)
        if c.breaker_open is True:
            _hit(hits, "breaker_open", O.NOT_SAFE)
        if c.concurrent_repair is True:
            _hit(hits, "concurrent_repair", O.NOT_SAFE)
        if (
            e.disruption is hc.Disruption.SERVICE
            and inc is not None
            and inc.cause_outside_router is True
        ):
            # Playbook A's hard rule: no DNS restart when the cause is outside
            _hit(hits, "cause_outside_router", O.NOT_SAFE)
        if risk.assessed and risk.risk_class >= RiskClass.HIGH:
            _hit(
                hits,
                "risk_high_no_recovery",
                O.NOT_SAFE,
                rollback=e.rollback.value,
            )

    # 3. Insufficient Evidence
    if risk.missing:
        _hit(
            hits,
            "context_missing",
            O.INSUFFICIENT_EVIDENCE,
            facts=",".join(risk.missing),
        )
    if e.writes:
        if inp.prior_failed_attempts is None:
            _hit(hits, "history_unknown", O.INSUFFICIENT_EVIDENCE)
        if inc is None:
            _hit(hits, "no_incident", O.INSUFFICIENT_EVIDENCE)
        else:
            if inc.is_root is None:
                _hit(hits, "root_unknown", O.INSUFFICIENT_EVIDENCE)
            if (
                e.disruption is hc.Disruption.SERVICE
                and inc.cause_outside_router is None
            ):
                _hit(hits, "cause_location_unknown", O.INSUFFICIENT_EVIDENCE)
            if inc.temporal_only is not False:
                _hit(hits, "temporal_correlation_only", O.INSUFFICIENT_EVIDENCE)
            if inc.evidence_fresh is not True:
                _hit(hits, "evidence_stale", O.INSUFFICIENT_EVIDENCE)
            if inc.cause_status is CauseStatus.HYPOTHESIS and inc.source_families < 2:
                _hit(
                    hits,
                    "hypothesis_single_source",
                    O.INSUFFICIENT_EVIDENCE,
                    source_families=inc.source_families,
                )
            if inc.target_fact is not TargetFact.DIRECT:
                _hit(hits, "no_direct_target_fact", O.INSUFFICIENT_EVIDENCE)
        if s.total < limits.score_min:
            _hit(
                hits,
                "score_below_threshold",
                O.INSUFFICIENT_EVIDENCE,
                score=s.total,
                threshold=limits.score_min,
            )
    elif inc is not None and inc.temporal_only is not False:
        _hit(hits, "temporal_link_diagnose_only", None)

    # notes: impact and the recovery statement (never blocking)
    impact: dict[str, Any] = {
        "disruption": e.disruption.value,
        "clients_on_router": c.clients_on_router,
        "clients_on_target": c.clients_on_target,
        "dependants": c.dependants,
        "service_dependant_routers": c.service_dependant_routers,
        "service_dependant_clients": c.service_dependant_clients,
        "est_outage_s": e.est_outage_s,
    }
    _hit(hits, "impact_summary", None, **impact)
    _hit(
        hits,
        "recovery_statement",
        None,
        rollback=e.rollback.value,
        statement=e.rollback_statement,
    )

    outcome: DecisionOutcome | None = None
    why_not: str | None = None
    for candidate in _BLOCK_ORDER:
        first = next((h for h in hits if h.outcome is candidate), None)
        if first is not None:
            outcome, why_not = candidate, first.code
            break
    if outcome is not None:
        why = _WHY_BLOCKED[outcome]
    elif e.writes and risk.risk_class >= RiskClass.MEDIUM:
        outcome, why = O.REQUIRES_APPROVAL, "risk_needs_approval"
    else:
        outcome, why = O.RECOMMENDED, "all_rules_passed"
    return PolicyDecision(
        action_type=e.action_type,
        params=va.params,
        outcome=outcome,
        risk=risk,
        score=s,
        hits=tuple(hits),
        why=why,
        why_not=why_not,
        next_step=DIAGNOSE_STEP if outcome is O.INSUFFICIENT_EVIDENCE else None,
        writes=e.writes,
        impact=MappingProxyType(impact),
    )


# ---------------------------------------------------------------------------
# Modes, allowlist, the gate
# ---------------------------------------------------------------------------


class Permission(StrEnum):
    """What may happen with a decided action."""

    NONE = "none"  # nothing (refused, blocked, or the module is off)
    RECOMMEND = "recommend"  # show it as a recommendation only
    RUN_READ_ONLY = "run_read_only"  # Risk 0: runs without approval
    NEEDS_APPROVAL = "needs_approval"  # only after an explicit approval
    AUTO_RUN = "auto_run"  # Auto-Heal: allowlisted, Risk <= 1, guards green


@dataclass(frozen=True, kw_only=True, slots=True)
class GateVerdict:
    """The gate's answer. ``executable_now``: may run in this release.

    ``decision``: the decision the gate itself made from the input (the one
    to show; never one a caller handed in). None only when the gate refused
    before deciding (``gate_input_invalid``, module off).
    """

    permission: Permission
    effective_mode: HealMode
    reasons: tuple[str, ...] = ()
    allowlisted: bool = False
    in_release: bool = False
    executable_now: bool = False
    decision: PolicyDecision | None = None


GATE_CODES: Final = frozenset(
    {
        "gate_input_invalid",
        "module_disabled",
        "not_in_catalog",
        "action_disabled",
        "risk_below_catalog",
        "risk_high_never_authorised",
        "decision_blocked",
        "router_held",
        "fleet_paused",
        "observe_mode",
        "risk_above_auto_limit",
        "not_allowlisted",
        "in_maintenance",
        "guards_not_green",
        "not_in_release",
    }
)


def effective_mode(
    mode: HealMode,
    *,
    module_enabled: bool,
    held: bool,
    fleet_paused: bool,
    risk: RiskClass,
) -> HealMode:
    """The mode in force for an action of ``risk``.

    Module off: Observe. A held router and a paused fleet count as Observe
    for everything of Risk 1 or more (owner decision); Risk 0 keeps the
    configured mode. Anything but a real bool for the three switches is
    unknown and counts as Observe, whatever the risk.
    """
    if (
        type(module_enabled) is not bool
        or type(held) is not bool
        or type(fleet_paused) is not bool
    ):
        return HealMode.OBSERVE
    if not module_enabled:
        return HealMode.OBSERVE
    if risk >= RiskClass.LOW and (held or fleet_paused):
        return HealMode.OBSERVE
    return HealMode(mode)


def _allow_entry_refusal(entry: AllowEntry) -> str | None:
    """Why an allowlist entry is not acceptable (None: it is)."""
    try:
        found = hc.entry(entry.action_type)
        if found.status is hc.CatalogStatus.DISABLED:
            return "action_disabled"
        hc.validate_params(found, entry.params, subset=True)
    except hc.CatalogError as err:
        return err.code
    if found.base_risk > AUTO_HEAL_MAX_RISK or entry.max_risk > AUTO_HEAL_MAX_RISK:
        return "risk_above_auto_limit"
    if entry.max_risk < found.base_risk:
        return "max_risk_below_action_risk"
    return None


def is_allowlisted(
    allowlist: Iterable[Any],
    action_type: str | None,
    params: Mapping[str, Any],
    risk: RiskClass,
) -> bool:
    """A valid entry covers ``action_type`` with these params at ``risk``.

    An entry matches when its action type is equal, each of its params is
    equal in ``params``, and ``risk`` is within its ``max_risk`` and within
    ``AUTO_HEAL_MAX_RISK``. Entries that would not pass
    :func:`validate_allowlist` never match (e.g. a stored entry for a
    disabled or Risk 3 action).
    """
    if action_type is None or risk > AUTO_HEAL_MAX_RISK:
        return False
    for entry in allowlist:
        if not isinstance(entry, AllowEntry) or _allow_entry_refusal(entry):
            continue
        if entry.action_type != action_type or risk > entry.max_risk:
            continue
        if all(params.get(k) == v for k, v in entry.params.items()):
            return True
    return False


@dataclass(frozen=True, kw_only=True, slots=True)
class AllowlistVerdict:
    """Accepted entries and refusals ``(index or "*", code)``."""

    entries: tuple[AllowEntry, ...]
    refusals: tuple[tuple[int | str, str], ...]

    @property
    def ok(self) -> bool:
        """Nothing was refused (an admin may store ``entries``)."""
        return not self.refusals


ALLOWLIST_CODES: Final = frozenset(
    {
        "allowlist_invalid",
        "too_many_entries",
        "entry_invalid",
        "duplicate_entry",
        "risk_above_auto_limit",
        "max_risk_below_action_risk",
        "action_disabled",
    }
)


def validate_allowlist(proposed: Any) -> AllowlistVerdict:
    """Validate an allowlist an admin wants to store for one router.

    Refused: not a list, more than ``ALLOWLIST_MAX`` entries, an entry the
    model refuses (``entry_invalid``, which includes ``max_risk`` above 1),
    unknown or never-in-catalog actions, disabled actions, params outside
    the closed sets, actions whose base risk is above
    ``AUTO_HEAL_MAX_RISK`` (so Risk 2 and 3 never), a ``max_risk`` below
    the action's risk (it could never match) and duplicates. The verdict is
    all or nothing: ``ok`` only without any refusal.
    """
    if not isinstance(proposed, list | tuple):
        return AllowlistVerdict(entries=(), refusals=(("*", "allowlist_invalid"),))
    if len(proposed) > ALLOWLIST_MAX:
        return AllowlistVerdict(entries=(), refusals=(("*", "too_many_entries"),))
    entries: list[AllowEntry] = []
    refusals: list[tuple[int | str, str]] = []
    seen: set[tuple[str, tuple[tuple[str, Any], ...]]] = set()
    for index, raw in enumerate(proposed):
        try:
            entry = raw if isinstance(raw, AllowEntry) else AllowEntry.from_dict(raw)
        except HealModelError:
            refusals.append((index, "entry_invalid"))
            continue
        code = _allow_entry_refusal(entry)
        if code is not None:
            refusals.append((index, code))
            continue
        ident = (entry.action_type, tuple(sorted(entry.params.items())))
        if ident in seen:
            refusals.append((index, "duplicate_entry"))
            continue
        seen.add(ident)
        entries.append(entry)
    if refusals:
        return AllowlistVerdict(entries=(), refusals=tuple(refusals))
    return AllowlistVerdict(entries=tuple(entries), refusals=())


def gate(
    inp: DecisionInput,
    *,
    mode: HealMode,
    allowlist: Sequence[AllowEntry],
    module_enabled: bool,
    held: bool,
    fleet_paused: bool,
    guards_green: bool | None,
    limits: PolicyLimits = DEFAULT_POLICY_LIMITS,
) -> GateVerdict:
    """What may happen with the action of ``inp`` on a router in ``mode``.

    The gate takes the INPUT, never a decision: it validates action and
    parameters against the catalog and runs :func:`decide` itself, so a
    decision cannot be forged or relabelled (review of PR #77). The decision
    it made is in the verdict.

    * ``module_enabled``, ``held``, ``fleet_paused`` must be real bools;
      anything else refuses everything (``gate_input_invalid``).
    * Observe: a recommendation only (Risk 0 read-only diagnostics run).
    * Approval: an explicit approval for everything of Risk 1 or more.
    * Auto-Heal: only an allowlisted action of Risk <= 1 runs by itself, and
      only with all guards green (``guards_green is True``) and outside
      maintenance (``inp.context.in_maintenance is False``: one source of
      truth, the same fact :func:`decide` reads); everything else falls
      back to an approval.
    * Held router, paused fleet: Observe for Risk 1 or more.
    * Risk 3 is never authorised, whatever the mode or the allowlist.
    * ``executable_now`` is True only for actions the release can run
      (1.53.0: no router call at all).
    """
    if type(inp) is not DecisionInput:
        raise _fail("input")
    limits = _limits(limits)

    def refuse(code: str, **kw: Any) -> GateVerdict:
        return GateVerdict(
            permission=Permission.NONE,
            effective_mode=HealMode.OBSERVE,
            reasons=(code,),
            **kw,
        )

    if (
        type(module_enabled) is not bool
        or type(held) is not bool
        or type(fleet_paused) is not bool
    ):
        return refuse("gate_input_invalid")
    if not module_enabled:
        return refuse("module_disabled")
    va, refusal = hc.try_validate(inp.action_type, inp.params)
    decision = decide(inp, limits)
    if va is None:
        return refuse(
            "not_in_catalog" if refusal is None else refusal, decision=decision
        )
    found = va.entry
    risk = decision.risk.risk_class
    eff = effective_mode(
        mode,
        module_enabled=module_enabled,
        held=held,
        fleet_paused=fleet_paused,
        risk=risk,
    )
    in_release = found.action_type in hc.EXECUTABLE_IN_RELEASE

    def verdict(
        permission: Permission, *reasons: str, allowlisted: bool = False
    ) -> GateVerdict:
        runs = permission in (Permission.RUN_READ_ONLY, Permission.AUTO_RUN)
        out = list(reasons)
        if runs and not in_release:
            out.append("not_in_release")
        return GateVerdict(
            permission=permission,
            effective_mode=eff,
            reasons=tuple(out),
            allowlisted=allowlisted,
            in_release=in_release,
            executable_now=runs and in_release,
            decision=decision,
        )

    if found.status is hc.CatalogStatus.DISABLED:
        return verdict(Permission.NONE, "action_disabled")
    if risk < found.base_risk:
        return verdict(Permission.NONE, "risk_below_catalog")
    if risk >= RiskClass.HIGH:
        return verdict(Permission.NONE, "risk_high_never_authorised")
    if decision.outcome not in (O.RECOMMENDED, O.REQUIRES_APPROVAL):
        return verdict(Permission.NONE, "decision_blocked")
    if risk is RiskClass.READ_ONLY and not found.writes:
        return verdict(Permission.RUN_READ_ONLY)
    context: list[str] = []
    if held:
        context.append("router_held")
    if fleet_paused:
        context.append("fleet_paused")
    if eff is HealMode.OBSERVE:
        if not context:
            context.append("observe_mode")
        return verdict(Permission.RECOMMEND, *context)
    if eff is HealMode.APPROVAL:
        return verdict(Permission.NEEDS_APPROVAL, *context)
    listed = is_allowlisted(allowlist, found.action_type, va.params, risk)
    blockers: list[str] = []
    if risk > AUTO_HEAL_MAX_RISK or decision.outcome is O.REQUIRES_APPROVAL:
        blockers.append("risk_above_auto_limit")
    if not listed:
        blockers.append("not_allowlisted")
    if inp.context.in_maintenance is not False:
        blockers.append("in_maintenance")
    if guards_green is not True:
        blockers.append("guards_not_green")
    if blockers:
        return verdict(Permission.NEEDS_APPROVAL, *blockers, allowlisted=listed)
    return verdict(Permission.AUTO_RUN, allowlisted=True)


def safe_now_of(clock: SafetyClock) -> float:
    """The safety-clock time of ``clock`` (never its wall time)."""
    if not isinstance(clock, SafetyClock) or clock.safe is None:
        raise PolicyError("invalid clock")
    return _safe(clock.safe)


def gate_for_router(
    inp: DecisionInput,
    *,
    settings: HealSettings,
    loop: LoopState,
    router_id: str,
    guards_green: bool | None,
    limits: PolicyLimits = DEFAULT_POLICY_LIMITS,
) -> GateVerdict:
    """:func:`gate` with mode, allowlist, hold and pause read from the
    persisted state, on the safety clock of ``loop``."""
    safe = safe_now_of(loop.clock)
    rs = settings.router(router_id)
    return gate(
        inp,
        mode=rs.mode,
        allowlist=rs.allowlist,
        module_enabled=settings.enabled,
        held=loop.hold_on(router_id, safe) is not None,
        fleet_paused=loop.fleet.paused(safe),
        guards_green=guards_green,
        limits=limits,
    )


# ---------------------------------------------------------------------------
# Loop protection (safety-clock time only)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class LoopVerdict:
    """May an attempt run now; if not, why and from when (None: only an admin)."""

    allowed: bool
    reason: str | None = None
    retry_at: float | None = None


LOOP_CODES: Final = frozenset(
    {"breaker_open", "fleet_paused", "cooling_down", "max_attempts", "min_interval"}
)


def cooldown_after(limits: LoopLimits, attempt_no: int) -> int:
    """Seconds to wait after attempt ``attempt_no`` (1-based) in a window:
    the longer of the cooldown and the backoff ``base * 2^(n-1)`` (capped)."""
    if (
        isinstance(attempt_no, bool)
        or not isinstance(attempt_no, int)
        or attempt_no < 1
    ):
        raise _fail("attempt_no")
    step = min(attempt_no - 1, BACKOFF_STEP_MAX)
    backoff = min(limits.backoff_base_s * 2**step, limits.backoff_cap_s)
    return max(limits.cooldown_s, backoff)


def backoff_schedule(
    limits: LoopLimits, attempts: int | None = None
) -> tuple[int, ...]:
    """The wait after each attempt 1..n (default: the attempts per 24 h)."""
    n = limits.max_attempts_24h if attempts is None else attempts
    return tuple(cooldown_after(limits, i) for i in range(1, n + 1))


def _window_times(att: AttemptRecord, safe: float) -> tuple[float, ...]:
    """Attempt times in the sliding 24 h span that ends at ``safe``."""
    return att.times_in_window(safe, ATTEMPT_WINDOW_S)


def book_attempt(
    record: AttemptRecord | None, limits: LoopLimits, safe_now: float
) -> AttemptRecord:
    """The attempt record after one more attempt at ``safe_now``.

    Attempts count in a sliding 24 h span of safety time; the cooldown is
    :func:`cooldown_after` of the number of attempts in that span, and a
    running cooldown is never shortened. The new attempt's result is
    pending (``last_result`` None) until :func:`record_outcome` notes it.
    The store books exactly the same (review of PR #77).
    """
    safe = _safe(safe_now)
    if safe > TIME_MAX - _BOOK_HEADROOM_S:
        raise PolicyError("invalid clock")
    att = AttemptRecord() if record is None else record
    recent = (*_window_times(att, safe), safe)
    count = min(len(recent), 1000)
    step = min(count - 1, BACKOFF_STEP_MAX)
    backoff = min(limits.backoff_base_s * 2**step, limits.backoff_cap_s)
    until = safe + max(limits.cooldown_s, backoff)
    if att.cooldown_until is not None and att.cooldown_until > until:
        until = att.cooldown_until
    kept = recent[-RECENT_ATTEMPTS_MAX:]
    return AttemptRecord(
        count=count,
        window_start=kept[0],
        last_at=safe,
        cooldown_until=until,
        backoff_step=step,
        last_result=None,
        recent=kept,
    )


def book_attempts(
    keys: Iterable[LoopKey],
    attempts: Mapping[LoopKey, AttemptRecord],
    limits: LoopLimits,
    safe_now: float,
) -> dict[LoopKey, AttemptRecord]:
    """:func:`book_attempt` for every key of one action."""
    return {k: book_attempt(attempts.get(k), limits, safe_now) for k in keys}


def loop_verdict(
    keys: Iterable[LoopKey],
    *,
    attempts: Mapping[LoopKey, AttemptRecord],
    breakers: Mapping[LoopKey, BreakerRecord],
    fleet: FleetPause,
    limits: LoopLimits,
    safe_now: float,
) -> LoopVerdict:
    """May one more attempt of an action with ``keys`` run at ``safe_now``?

    In this order: an open breaker on any key (only an admin closes it), a
    fleet pause, a running cooldown, ``max_attempts_24h`` attempts already
    in the sliding 24 h span (``retry_at``: when the oldest of them that
    must leave has left).
    """
    safe = _safe(safe_now)
    keys = tuple(keys)
    for key in keys:
        br = breakers.get(key)
        if br is not None and br.state is BreakerState.OPEN:
            return LoopVerdict(allowed=False, reason="breaker_open", retry_at=None)
    if fleet.paused(safe):
        return LoopVerdict(
            allowed=False, reason="fleet_paused", retry_at=fleet.paused_until
        )
    cooling = [
        att.cooldown_until
        for key in keys
        if (att := attempts.get(key)) is not None
        and att.cooldown_until is not None
        and safe < att.cooldown_until
    ]
    if cooling:
        return LoopVerdict(allowed=False, reason="cooling_down", retry_at=max(cooling))
    used: list[float] = []
    for key in keys:
        att = attempts.get(key)
        if att is None:
            continue
        times = _window_times(att, safe)
        n = limits.max_attempts_24h
        if len(times) >= n:
            used.append(times[len(times) - n] + ATTEMPT_WINDOW_S)
    if used:
        return LoopVerdict(allowed=False, reason="max_attempts", retry_at=max(used))
    return LoopVerdict(allowed=True)


def loop_verdict_for(
    loop: LoopState, keys: Iterable[LoopKey], limits: LoopLimits
) -> LoopVerdict:
    """:func:`loop_verdict` on the persisted state at its safety-clock time."""
    return loop_verdict(
        keys,
        attempts=loop.attempts,
        breakers=loop.breakers,
        fleet=loop.fleet,
        limits=limits,
        safe_now=safe_now_of(loop.clock),
    )


class OutcomeEvent(StrEnum):
    """How one attempt ended (the engine reports one per finished attempt)."""

    RESOLVED = "resolved"
    NOT_RESOLVED = "not_resolved"
    PARTIAL = "partial"
    NEW_FAULT = "new_fault"
    UNKNOWN = "unknown"  # interrupted or manual recovery required
    ESCALATED = "escalated"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"  # the router refused cleanly before any change
    STUCK_RELEASED = "stuck_released"  # an admin ended a stuck action


# Every end that holds the router (heal_model.hold_reason_for), and a
# rollback, opens the breaker at once (package I note, docs §15).
_OPEN_AT_ONCE: Final = frozenset(
    {
        OutcomeEvent.NOT_RESOLVED,
        OutcomeEvent.PARTIAL,
        OutcomeEvent.NEW_FAULT,
        OutcomeEvent.UNKNOWN,
        OutcomeEvent.ESCALATED,
        OutcomeEvent.ROLLED_BACK,
        OutcomeEvent.STUCK_RELEASED,
    }
)


def opens_at_once(event: OutcomeEvent) -> bool:
    """The event opens the breaker of its keys at once (not by a count)."""
    return event in _OPEN_AT_ONCE


def outcome_event_for(action: RemediationAction) -> OutcomeEvent | None:
    """The event of a finished record (None: open, or never executed).

    Interrupted: UNKNOWN whatever the end. ESCALATED after a clean refusal
    (no hold): REJECTED; otherwise ESCALATED.
    """
    if not action.is_terminal or not action.entered_executing:
        return None
    if action.flags.interrupted:
        return OutcomeEvent.UNKNOWN
    state = action.state
    if state is ActionState.RESOLVED:
        return OutcomeEvent.RESOLVED
    if state is ActionState.ROLLED_BACK:
        return OutcomeEvent.ROLLED_BACK
    if state is ActionState.ESCALATED:
        if hold_reason_for(action) is None:
            return OutcomeEvent.REJECTED
        return OutcomeEvent.ESCALATED
    return OutcomeEvent.UNKNOWN


@dataclass(frozen=True, kw_only=True, slots=True)
class OutcomeUpdate:
    """The loop state after an outcome, and what it changed."""

    attempts: dict[LoopKey, AttemptRecord]
    breakers: dict[LoopKey, BreakerRecord]
    fleet: FleetPause
    opened: tuple[LoopKey, ...]
    fleet_paused_now: bool


def record_outcome(
    keys: Iterable[LoopKey],
    event: OutcomeEvent,
    *,
    automatic: bool,
    attempts: Mapping[LoopKey, AttemptRecord],
    breakers: Mapping[LoopKey, BreakerRecord],
    fleet: FleetPause,
    limits: LoopLimits,
    safe_now: float,
    policy: PolicyLimits = DEFAULT_POLICY_LIMITS,
) -> OutcomeUpdate:
    """Apply the end of one attempt to the loop state (returns new copies).

    * the attempt records of ``keys`` note the result (no new attempt);
    * breakers: :func:`opens_at_once` events open at once; a clean refusal
      counts and opens at ``auto_failures_to_open`` (automatic) or
      ``manual_failures_to_open`` (manual) failures. RESOLVED never closes
      an open breaker and never resets the count (review of PR #77: manual
      refusals between successes must still open it); only an admin's
      :func:`acknowledge_breaker` resets it;
    * fleet: every event but RESOLVED is a failure; ``fleet_failure_threshold``
      failures within 24 h pause Auto-Heal fleet-wide for ``fleet_pause_s``
      (a longer pause in force stays).
    """
    safe = _safe(safe_now)
    policy = _limits(policy)
    if type(automatic) is not bool:
        raise _fail("automatic")
    event = OutcomeEvent(event)
    keys = tuple(dict.fromkeys(keys))
    new_attempts = dict(attempts)
    for key in keys:
        att = attempts.get(key)
        if att is not None:
            new_attempts[key] = replace(att, last_result=event.value)
    new_breakers = dict(breakers)
    opened: list[LoopKey] = []
    threshold = (
        policy.auto_failures_to_open if automatic else policy.manual_failures_to_open
    )
    for key in keys:
        br = breakers.get(key)
        if br is None:
            br = BreakerRecord()  # no record: never failed, closed
        if event is OutcomeEvent.RESOLVED:
            pass  # neither closes nor forgets earlier failures
        else:
            failures = min(br.failures + 1, 1000)
            if br.state is BreakerState.OPEN:
                br = replace(br, failures=failures)
            elif opens_at_once(event) or failures >= threshold:
                br = BreakerRecord(
                    state=BreakerState.OPEN,
                    opened_at=safe,
                    reason=f"outcome_{event.value}",
                    failures=failures,
                    acknowledged_at=br.acknowledged_at,
                )
                opened.append(key)
            else:
                br = replace(br, failures=failures)
        new_breakers[key] = br
    new_fleet = fleet
    paused_now = False
    if event is not OutcomeEvent.RESOLVED:
        recent = tuple(t for t in fleet.recent_failures if safe - t < FLEET_WINDOW_S)
        recent = (*recent, safe)[-RECENT_FAILURES_MAX:]
        new_fleet = replace(fleet, recent_failures=recent)
        if len(recent) >= limits.fleet_failure_threshold:
            until = min(safe + limits.fleet_pause_s, TIME_MAX)
            if fleet.paused_until is None or until > fleet.paused_until:
                new_fleet = FleetPause(
                    paused_until=until,
                    since=safe,
                    reason="fleet_failures",
                    recent_failures=recent,
                )
                paused_now = True
    return OutcomeUpdate(
        attempts=new_attempts,
        breakers=new_breakers,
        fleet=new_fleet,
        opened=tuple(opened),
        fleet_paused_now=paused_now,
    )


def acknowledge_breaker(
    record: BreakerRecord, *, actor: Actor, safe_now: float
) -> BreakerRecord:
    """An admin closes a breaker (the only way it closes)."""
    if actor is not Actor.ADMIN:
        raise PolicyError("admin only")
    safe = _safe(safe_now)
    return BreakerRecord(
        state=BreakerState.CLOSED,
        opened_at=record.opened_at,
        reason=record.reason,
        failures=0,
        acknowledged_at=safe,
    )


def prior_failed_attempts(
    keys: Iterable[LoopKey],
    attempts: Mapping[LoopKey, AttemptRecord],
    safe_now: float,
) -> int:
    """Attempts in the sliding 24 h span that are not known to have resolved.

    The store keeps the attempt times and the result of the LAST attempt
    only (None while pending: booking resets it). So every attempt in the
    span counts, except the last one when it is in the span and its result
    is ``resolved``; the highest over the keys.
    """
    safe = _safe(safe_now)
    worst = 0
    for key in keys:
        att = attempts.get(key)
        if att is None:
            continue
        times = _window_times(att, safe)
        count = len(times)
        if (
            count > 0
            and att.last_at is not None
            and times[-1] == att.last_at
            and att.last_result == OutcomeEvent.RESOLVED.value
        ):
            count -= 1
        worst = max(worst, count)
    return worst


@dataclass(frozen=True, kw_only=True, slots=True)
class DedupeVerdict:
    """An open action already holds one of the dedupe ids (or none does)."""

    duplicate_of: str | None = None
    kind: str | None = None  # "action", "incident" or "component"


def dedupe_verdict(
    loop: LoopState,
    *,
    router_id: str,
    action_type: str,
    params: Mapping[str, Any],
    incident_id: str | None,
) -> DedupeVerdict:
    """The open action a new one would duplicate: same (router, action,
    params), same root incident (fleet-wide), or same (router, component).

    Action, parameters and components come from the catalog validation
    (raises :class:`heal_catalog.CatalogError`), never from the caller.
    """
    va = hc.validate(action_type, params)
    components: tuple[Component, ...] = va.components
    held = loop.action_dedupe.get(
        action_dedupe_id(router_id, va.action_type, dict(va.params))
    )
    if held is not None:
        return DedupeVerdict(duplicate_of=held, kind="action")
    if incident_id is not None:
        held = loop.incident_dedupe.get(incident_dedupe_id(incident_id))
        if held is not None:
            return DedupeVerdict(duplicate_of=held, kind="incident")
    for comp in tuple(components) or (ROUTER_COMPONENT,):
        held = loop.component_dedupe.get(component_dedupe_id(router_id, comp))
        if held is not None:
            return DedupeVerdict(duplicate_of=held, kind="component")
    return DedupeVerdict()


def interval_verdict(
    action_type: str, *, last_run_at: float | None, safe_now: float
) -> LoopVerdict:
    """The catalog's shortest interval between two runs on one router
    (``diag.refresh``: 300 s). ``last_run_at`` None: it never ran on this
    router. Safety-clock times only."""
    found = hc.entry(action_type)
    safe = _safe(safe_now)
    if last_run_at is None or found.min_interval_s == 0:
        return LoopVerdict(allowed=True)
    last = _safe(last_run_at, "last_run_at")
    until = last + found.min_interval_s
    if safe < until:
        return LoopVerdict(allowed=False, reason="min_interval", retry_at=until)
    return LoopVerdict(allowed=True)


# ---------------------------------------------------------------------------
# German texts for every code (a later UI renders them)
# ---------------------------------------------------------------------------

REASON_TEXT_DE: Final[Mapping[str, str]] = MappingProxyType(
    {
        # catalog refusals
        "action_type_invalid": "Die Aktionskennung hat keine gültige Form.",
        "unknown_action": "Diese Aktion steht nicht im Katalog.",
        "params_invalid": "Die Parameter haben keine gültige Form.",
        "param_unknown": "Ein Parameter ist für diese Aktion unbekannt.",
        "param_missing": "Ein nötiger Parameter fehlt.",
        "param_value_invalid": "Ein Parameterwert liegt außerhalb der erlaubten Werte.",
        "never_client_action": "Aktionen an Clients (trennen, sperren, umlenken) gibt es nie.",
        "never_firewall": "Firewall-Änderungen stehen nie im Katalog.",
        "never_vlan": "VLAN-Änderungen stehen nie im Katalog.",
        "never_management_ip": "Änderungen der Management-Adresse stehen nie im Katalog.",
        "never_routing": "Routing-Änderungen stehen nie im Katalog.",
        "never_firmware": "Firmware-Eingriffe stehen nie im Katalog.",
        "never_network_reload": "Ein Neuladen des ganzen Netzwerks steht nicht im Katalog.",
        "never_wpad_restart": "Ein Neustart von wpad (WLAN aller Clients) steht nicht im Katalog.",
        "never_config_write": "Konfiguration schreiben steht nicht im Katalog.",
        "never_shell": "Befehle auf dem Router gibt es nicht.",
        "never_dhcp_lease_delete": "DHCP-Leases werden nie gelöscht.",
        "entry_not_in_catalog": "Der Katalogeintrag ist nicht der des Katalogs.",
        "components_invalid": "Die Bauteile passen nicht zu den Parametern.",
        # catalog status reasons
        "first_write_release_approval_only": "Erste schreibende Aktion: nur mit Freigabe, ab 1.54.0.",
        "call_unverified_on_fleet": "Der Router-Aufruf ist auf dieser Flotte nicht geprüft.",
        "modelled_blocked_no_out_of_band": "Modelliert und gesperrt: kein zweiter Zugangsweg zum Router.",
        "restore_dry_run_only": "Wiederherstellen ist nur ein Probelauf.",
        "recommendation_only_no_acl": "Nur Empfehlung: keine Rechte für Schnittstellen.",
        # risk reasons
        "role_unknown": "Die Rolle des Routers ist unbekannt.",
        "identity_not_confirmed": "Die Identität des Routers ist nicht bestätigt.",
        "open_security_finding": "Am Router gibt es eine offene Sicherheitserkennung.",
        "in_maintenance_window": "Für Router oder Ziel läuft ein Wartungsfenster.",
        "service_disabled_on_purpose": "Der Dienst ist auf diesem Router absichtlich aus; ein Neustart wäre keine Reparatur.",
        "target_on_management_path": "Die Aktion trifft den Management-Weg von Home Assistant.",
        "wireless_uplink_radio": "Das Funkmodul trägt einen drahtlosen Uplink.",
        "uplink_for_other_routers": "Hinter diesem Ziel hängen weitere Router.",
        "clients_affected": "Verbundene Clients wären betroffen.",
        "service_serves_other_routers": "Andere Router und ihre Clients nutzen DNS/DHCP dieses Routers.",
        "service_config_unapplied": "Die gespeicherte Konfiguration des Dienstes ist nicht angewendet; ein Neustart würde sie in Kraft setzen (Drift-Playbook statt Neustart).",
        "context_missing": "Nötige Angaben zum Router fehlen; das Risiko gilt als hoch.",
        "not_in_catalog": "Nicht im Katalog: das Risiko gilt als hoch.",
        # decision rules
        "action_disabled": "Die Aktion ist modelliert, aber gesperrt.",
        "not_root_incident": "Repariert wird nur der Wurzelvorfall, nicht ein Folgevorfall.",
        "diagnostics_off": "Die Netzwerkdiagnose ist aus.",
        "router_unreachable": "Der Router ist nicht erreichbar.",
        "breaker_open": "Der Schutzschalter dieser Aktion ist offen.",
        "concurrent_repair": "Auf dem Router läuft schon eine Reparatur.",
        "risk_high_no_recovery": "Hohes Risiko ohne Wiederherstellungsweg.",
        "no_incident": "Kein Vorfall belegt diese Aktion.",
        "history_unknown": "Die Versuche der letzten 24 h sind unbekannt.",
        "cause_outside_router": "Die Ursache liegt außerhalb des Routers; ein Neustart hilft nicht.",
        "cause_location_unknown": "Unklar, ob die Ursache außerhalb des Routers liegt.",
        "root_unknown": "Unklar, ob es der Wurzelvorfall ist.",
        "temporal_correlation_only": "Nur zeitlicher Zusammenhang: zuerst diagnostizieren.",
        "evidence_stale": "Die Hinweise sind veraltet.",
        "hypothesis_single_source": "Vermutung aus nur einer Quellenfamilie.",
        "no_direct_target_fact": "Kein direkter Befund am Ziel.",
        "score_below_threshold": "Die Konfidenz liegt unter der Schwelle.",
        "temporal_link_diagnose_only": "Nur zeitlicher Zusammenhang: Diagnose ist der richtige Schritt.",
        "impact_summary": "Auswirkung: Clients, abhängige Router, geschätzte Unterbrechung.",
        "recovery_statement": "Aussage zur Wiederherstellung dieser Aktion.",
        "risk_needs_approval": "Risiko 2 oder höher: nur mit ausdrücklicher Freigabe.",
        "all_rules_passed": "Alle Regeln erfüllt.",
        "outcome_unsupported": "Nicht unterstützt.",
        "outcome_not_safe": "Nicht sicher.",
        "outcome_insufficient_evidence": "Zu wenig Belege.",
        # score
        "cause_level": "Ursachenstufe",
        "cause_status": "Ursachenstatus",
        "incident_confidence": "Konfidenz des Vorfalls",
        "source_families": "Quellenfamilien",
        "target_fact": "Befund am Ziel",
        "prior_attempts": "Frühere Versuche",
        "config_change": "Konfigurationsänderung",
        "severity": "Schweregrad",
        "clamp": "Begrenzung auf 0 bis 100",
        "cause_level_confirmed": "Ursache bestätigt.",
        "cause_level_likely": "Ursache wahrscheinlich.",
        "cause_level_possible": "Ursache möglich.",
        "cause_level_unknown": "Ursache unbekannt.",
        "cause_status_confirmed": "Ursache gemessen bestätigt.",
        "cause_status_hypothesis": "Ursache ist eine Vermutung.",
        "confidence_missing": "Keine Konfidenz angegeben.",
        "incident_confidence_scaled": "Konfidenz von Network Intelligence, auf 10 Punkte skaliert.",
        "no_source_family": "Keine Quellenfamilie.",
        "one_source_family": "Eine Quellenfamilie.",
        "two_or_more_source_families": "Zwei oder mehr unabhängige Quellenfamilien.",
        "target_fact_direct": "Direkter Befund am Ziel.",
        "target_fact_log_only": "Nur Log-Hinweise am Ziel.",
        "target_fact_none": "Kein Befund am Ziel.",
        "prior_failed_attempts": "Fehlgeschlagene oder unklare Versuche in 24 h.",
        "no_prior_attempts": "Keine früheren Versuche in 24 h.",
        "prior_attempts_unknown": "Unbekannt, ob es frühere Versuche gab.",
        "no_config_change_24h": "Keine Konfigurationsänderung in 24 h.",
        "config_change_24h": "Konfigurationsänderung im selben Bereich in 24 h.",
        "config_change_unknown": "Unbekannt, ob sich die Konfiguration geändert hat.",
        "severity_info": "Nur ein Hinweis (info).",
        "severity_warning": "Warnung.",
        "severity_critical": "Kritisch.",
        "severity_unknown": "Schweregrad unbekannt (zählt wie ein Hinweis).",
        "within_range": "Summe liegt zwischen 0 und 100.",
        "clamped_to_range": "Summe auf 0 bis 100 begrenzt.",
        # gate
        "gate_input_invalid": "Sperre, Pause oder Modulschalter sind unklar: nichts erlaubt.",
        "module_disabled": "Self-Healing ist ausgeschaltet.",
        "risk_below_catalog": "Risiko unter dem Katalogwert: abgelehnt.",
        "risk_high_never_authorised": "Risiko 3 wird nie freigegeben.",
        "decision_blocked": "Die Entscheidung erlaubt keine Aktion.",
        "router_held": "Der Router ist gesperrt (nur beobachten).",
        "fleet_paused": "Self-Healing ist für die Flotte pausiert.",
        "observe_mode": "Modus Beobachten: nur Empfehlung.",
        "risk_above_auto_limit": "Risiko über 1: nie automatisch.",
        "not_allowlisted": "Nicht auf der Allowlist dieses Routers.",
        "in_maintenance": "Wartung aktiv oder unklar: keine automatische Aktion.",
        "guards_not_green": "Nicht alle Prüfungen bestanden.",
        "not_in_release": "In dieser Version wird nichts ausgeführt.",
        # allowlist
        "allowlist_invalid": "Die Allowlist hat keine gültige Form.",
        "too_many_entries": "Zu viele Einträge in der Allowlist.",
        "entry_invalid": "Ein Eintrag der Allowlist ist ungültig.",
        "duplicate_entry": "Doppelter Eintrag in der Allowlist.",
        "max_risk_below_action_risk": "Das erlaubte Risiko liegt unter dem Risiko der Aktion.",
        # loop
        "cooling_down": "Abklingzeit läuft.",
        "max_attempts": "Versuche in 24 h aufgebraucht.",
        "min_interval": "Mindestabstand zwischen zwei Läufen noch nicht erreicht.",
    }
)

RULE_CODES: Final = frozenset(
    DECISION_CODES
    | RISK_CODES
    | SCORE_CODES
    | GATE_CODES
    | ALLOWLIST_CODES
    | LOOP_CODES
)


__all__ = [
    "DEFAULT_POLICY_LIMITS",
    "REASON_TEXT_DE",
    "RULE_CODES",
    "AllowlistVerdict",
    "Contribution",
    "DecisionInput",
    "DedupeVerdict",
    "GateVerdict",
    "IncidentFacts",
    "LoopVerdict",
    "OutcomeEvent",
    "OutcomeUpdate",
    "Permission",
    "PolicyDecision",
    "PolicyError",
    "PolicyLimits",
    "RiskAssessment",
    "RiskContext",
    "RuleHit",
    "ScoreBreakdown",
    "TargetFact",
    "acknowledge_breaker",
    "backoff_schedule",
    "book_attempt",
    "book_attempts",
    "classify_risk",
    "cooldown_after",
    "decide",
    "dedupe_verdict",
    "effective_mode",
    "gate",
    "gate_for_router",
    "interval_verdict",
    "is_allowlisted",
    "loop_verdict",
    "loop_verdict_for",
    "opens_at_once",
    "outcome_event_for",
    "prior_failed_attempts",
    "record_outcome",
    "safe_now_of",
    "score",
    "validate_allowlist",
]
