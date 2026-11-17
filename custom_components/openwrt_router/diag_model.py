"""Data model for active network diagnostics: probes, evidence, chains, causes.

Pure module: standard library only, no Home Assistant imports, no I/O and no
storage format beyond plain ``to_dict()``. Routers are identified by an
opaque ``str`` key, targets, resolvers, WANs and segments by opaque ids; this
module never sees an address or a hostname.

Vocabulary:

* A ``ProbeResult`` is one measurement taken at a ``MeasurementPoint`` (Home
  Assistant or a router) against a target id, meant to test one ``Stage`` of
  the chain Router -> Gateway -> WAN -> Internet -> DNS.
* ``Evidence`` is what a probe result or a poll fact says about one stage.
  ``direct`` is True only when it was measured at the chain's own point (or
  is a fact from that router's own poll); everything else is labelled
  indirect and can never confirm a cause.
* ``StageResult`` / ``ChainResult`` are the evaluated chain, per address
  family. ``Finding`` is the classification of one chain. ``Cause`` and
  ``CauseLink`` are produced by ``diag_causes.correlate``; links never hide
  or change a finding.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum, StrEnum
from types import MappingProxyType
from typing import Any

_LOGGER = logging.getLogger(__name__)


class Stage(StrEnum):
    """Links of the diagnosis chain, upstream first."""

    ROUTER = "router"
    GATEWAY = "gateway"
    WAN = "wan"
    INTERNET = "internet"
    DNS = "dns"


STAGE_ORDER: tuple[Stage, ...] = tuple(Stage)


class StageState(StrEnum):
    """Health of one stage. Missing evidence is UNKNOWN, never HEALTHY."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


MEASURED_STATES = frozenset(
    {StageState.HEALTHY, StageState.DEGRADED, StageState.FAILED}
)


class ProbeKind(StrEnum):
    """How a piece of evidence was obtained. FACT = router poll data."""

    ICMP = "icmp"
    DNS = "dns"
    TCP = "tcp"
    HTTP = "http"
    FACT = "fact"


class ProbeOutcome(StrEnum):
    """Result of one probe (distinct from ``diag_scheduler.Outcome``)."""

    OK = "ok"
    FAILED = "failed"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    ERROR = "error"
    SKIPPED = "skipped"
    NXDOMAIN = "nxdomain"
    SERVFAIL = "servfail"


DNS_ONLY_OUTCOMES = frozenset({ProbeOutcome.NXDOMAIN, ProbeOutcome.SERVFAIL})
UNUSABLE_OUTCOMES = frozenset({ProbeOutcome.ERROR, ProbeOutcome.SKIPPED})


class AddressFamily(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class PointKind(StrEnum):
    HA = "ha"
    ROUTER = "router"


class Basis(StrEnum):
    """What a stage state rests on."""

    DIRECT = "direct"
    INDIRECT = "indirect"
    NONE = "none"


class CauseClass(StrEnum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"


_CLASS_RANK = {
    CauseClass.UNKNOWN: 0,
    CauseClass.POSSIBLE: 1,
    CauseClass.PROBABLE: 2,
    CauseClass.CONFIRMED: 3,
}


def weaker_class(a: CauseClass, b: CauseClass) -> CauseClass:
    """The weaker of two cause classes (used to cap a class)."""
    return a if _CLASS_RANK[a] <= _CLASS_RANK[b] else b


class Severity(StrEnum):
    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


SEVERITY_RANK = {
    Severity.OK: 0,
    Severity.INFO: 1,
    Severity.WARNING: 2,
    Severity.CRITICAL: 3,
}


class Classification(StrEnum):
    NO_FAULT_DETECTED = "no_fault_detected"
    INSUFFICIENT_DATA = "insufficient_data"
    ROUTER_OFFLINE = "router_offline"
    MANAGEMENT_UNREACHABLE = "management_unreachable"
    LAN_PROBLEM = "lan_problem"
    GATEWAY_PROBLEM = "gateway_problem"
    ROUTING_PROBLEM = "routing_problem"
    WAN_PROBLEM = "wan_problem"
    DNS_PROBLEM = "dns_problem"
    SINGLE_EXTERNAL_SERVICE_UNREACHABLE = "single_external_service_unreachable"
    IPV4_ONLY_DISTURBANCE = "ipv4_only_disturbance"
    IPV6_ONLY_DISTURBANCE = "ipv6_only_disturbance"
    POSSIBLE_FIREWALL_RESTRICTION = "possible_firewall_restriction"
    ICMP_UNANSWERED = "icmp_unanswered"
    GATEWAY_CHANGED = "gateway_changed"
    DNS_SERVER_CHANGED = "dns_server_changed"


NON_PROBLEM_CLASSIFICATIONS = frozenset(
    {Classification.NO_FAULT_DETECTED, Classification.INSUFFICIENT_DATA}
)


class LocationKind(StrEnum):
    """Where a cause sits. Ids are opaque; ROUTER ids are router keys."""

    HA = "ha"
    ROUTER = "router"
    WAN = "wan"
    RESOLVER = "resolver"
    SEGMENT = "segment"


# Names of poll facts used as evidence.
FACT_MANAGEMENT = "management_reachable"
FACT_INTERFACE = "interface_up"
FACT_DEFAULT_ROUTE = "default_route"
FACT_WAN_UP = "wan_up"
FACT_NEXT_HOP = "next_hop"
FACT_DNS_SERVERS = "dns_servers"


def plain(value: Any) -> Any:
    """Turn model values into JSON-friendly plain data."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (frozenset, set)):
        return sorted((plain(v) for v in value), key=str)
    if isinstance(value, (tuple, list)):
        return [plain(v) for v in value]
    return value


@dataclass(frozen=True)
class MeasurementPoint:
    """Where a measurement was taken: Home Assistant or a router (by key)."""

    kind: PointKind
    key: str | None = None

    def __post_init__(self) -> None:
        if self.kind == PointKind.ROUTER and not self.key:
            raise ValueError("a router measurement point needs a router key")
        if self.kind == PointKind.HA and self.key is not None:
            raise ValueError("the Home Assistant measurement point has no key")

    @classmethod
    def ha(cls) -> MeasurementPoint:
        return cls(PointKind.HA)

    @classmethod
    def router(cls, key: str) -> MeasurementPoint:
        return cls(PointKind.ROUTER, key)

    @property
    def label(self) -> str:
        return self.key if self.key is not None else PointKind.HA.value

    def to_dict(self) -> dict[str, Any]:
        return plain(self)


@dataclass(frozen=True)
class ProbeResult:
    """One measurement. ``via``: stages a reply also proves reachable (e.g. a
    DNS answer from the resolver on the gateway proves the gateway hop).
    ``evidence``: raw extra details (never logged)."""

    point: MeasurementPoint
    target_id: str
    kind: ProbeKind
    stage: Stage
    family: AddressFamily | None
    outcome: ProbeOutcome
    timestamp: float
    duration_ms: float | None = None
    rtt_ms: float | None = None
    sent: int | None = None
    received: int | None = None
    via: frozenset[Stage] = frozenset()
    evidence: Mapping[str, Any] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        if self.kind == ProbeKind.FACT:
            raise ValueError("poll facts are passed as ChainFacts, not probes")
        if self.outcome in DNS_ONLY_OUTCOMES and self.kind != ProbeKind.DNS:
            raise ValueError("NXDOMAIN/SERVFAIL only apply to DNS probes")
        if not self.target_id:
            raise ValueError("a probe needs a target id")
        for name in ("sent", "received"):
            count = getattr(self, name)
            if count is not None and count < 0:
                raise ValueError(f"{name} must not be negative")
        if (
            self.sent is not None
            and self.received is not None
            and self.received > self.sent
        ):
            raise ValueError("received must not exceed sent")
        object.__setattr__(self, "via", frozenset(self.via))
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))

    def to_dict(self) -> dict[str, Any]:
        return plain(self)


@dataclass(frozen=True)
class Evidence:
    """What one probe result or poll fact says about one stage.

    ``ok``: True = supports the stage, False = speaks against it, None = not
    usable (error, skipped, ambiguous). ``derived_from`` is set when the item
    comes from a reply to a probe aimed at a downstream stage (its ``via``).
    """

    stage: Stage
    family: AddressFamily | None
    point: MeasurementPoint
    kind: ProbeKind
    outcome: ProbeOutcome
    ok: bool | None
    direct: bool
    target_id: str | None = None
    fact: str | None = None
    via: frozenset[Stage] = frozenset()
    derived_from: Stage | None = None
    timestamp: float | None = None

    @property
    def hard(self) -> bool:
        """Non-ICMP evidence; only hard failures can fail a stage."""
        return self.kind != ProbeKind.ICMP

    def to_dict(self) -> dict[str, Any]:
        return plain(self)


@dataclass(frozen=True)
class StageResult:
    stage: Stage
    family: AddressFamily
    state: StageState
    basis: Basis
    evidence: tuple[Evidence, ...] = ()
    masked: tuple[Evidence, ...] = ()
    reasons: tuple[str, ...] = ()
    failed_targets: tuple[str, ...] = ()

    @property
    def measured(self) -> bool:
        return self.state in MEASURED_STATES

    @property
    def applicable(self) -> bool:
        return self.state != StageState.NOT_APPLICABLE

    def to_dict(self) -> dict[str, Any]:
        return plain(self)


@dataclass(frozen=True)
class Contradiction:
    """A downstream stage measured healthy while an upstream one failed."""

    family: AddressFamily
    upstream: Stage
    downstream: Stage
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return plain(self)


def _ratio(part: int, whole: int) -> float:
    return part / whole if whole else 0.0


@dataclass(frozen=True)
class ChainResult:
    """Evaluated chain for one measurement point. ``excluded``: probes taken
    at another router, never used for this chain."""

    point: MeasurementPoint
    stages: tuple[StageResult, ...]
    contradictions: tuple[Contradiction, ...] = ()
    excluded: tuple[ProbeResult, ...] = ()

    def stage(self, stage: Stage, family: AddressFamily) -> StageResult:
        for result in self.stages:
            if result.stage == stage and result.family == family:
                return result
        raise KeyError((stage, family))

    @property
    def families(self) -> tuple[AddressFamily, ...]:
        """Address families that apply to this chain."""
        return tuple(f for f in AddressFamily if any(s.applicable for s in self._of(f)))

    def _of(self, family: AddressFamily | None) -> list[StageResult]:
        return [s for s in self.stages if family is None or s.family == family]

    def coverage_for(self, family: AddressFamily | None = None) -> float:
        """Measured stages / applicable stages (0.0 if nothing applies)."""
        stages = [s for s in self._of(family) if s.applicable]
        return _ratio(sum(s.measured for s in stages), len(stages))

    @property
    def coverage(self) -> float:
        return self.coverage_for(None)

    @property
    def direct_coverage(self) -> float:
        """Like ``coverage`` but only stages resting on direct evidence."""
        stages = [s for s in self.stages if s.applicable]
        direct = sum(s.measured and s.basis == Basis.DIRECT for s in stages)
        return _ratio(direct, len(stages))

    def to_dict(self) -> dict[str, Any]:
        data = plain(self)
        data["coverage"] = self.coverage
        data["direct_coverage"] = self.direct_coverage
        return data


@dataclass(frozen=True)
class ChangeRecord:
    """Previous and current value of a watched poll value (opaque)."""

    previous: Any
    current: Any

    def to_dict(self) -> dict[str, Any]:
        return plain(self)


@dataclass(frozen=True)
class Finding:
    """Classification of one chain (or one observed change).

    ``cause_class`` rates the local hypothesis ``cause_stage``;
    ``underlying`` holds the stage classification behind an
    IPv4-/IPv6-only disturbance.
    """

    point: MeasurementPoint
    classification: Classification
    severity: Severity
    summary_key: str
    recommendation_key: str
    cause_class: CauseClass
    cause_stage: Stage | None = None
    family: AddressFamily | None = None
    underlying: Classification | None = None
    evidence: tuple[Evidence, ...] = ()
    reasons: tuple[str, ...] = ()
    contradictions: tuple[Contradiction, ...] = ()
    chain: ChainResult | None = None
    change: ChangeRecord | None = None

    @property
    def router_key(self) -> str | None:
        return self.point.key

    @property
    def is_problem(self) -> bool:
        return self.classification not in NON_PROBLEM_CLASSIFICATIONS

    def to_dict(self) -> dict[str, Any]:
        data = plain(self)
        if self.chain is not None:
            data["chain"] = self.chain.to_dict()
        return data


@dataclass(frozen=True)
class Location:
    kind: LocationKind
    id: str

    def to_dict(self) -> dict[str, Any]:
        return plain(self)


@dataclass(frozen=True)
class Cause:
    """A cause with its class, the rule that produced it and its evidence."""

    cause_id: str
    location: Location
    cause_class: CauseClass
    rule: str
    summary_key: str
    reason: str
    family: AddressFamily | None = None
    router_keys: tuple[str, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return plain(self)


@dataclass(frozen=True)
class CauseLink:
    """Finding (by index in the correlated input) -> cause."""

    finding_index: int
    router_key: str | None
    cause_id: str
    cause_class: CauseClass
    rule: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return plain(self)


@dataclass(frozen=True)
class CorrelationResult:
    """Every input finding, unchanged and in order, plus causes and links."""

    findings: tuple[Finding, ...]
    causes: tuple[Cause, ...] = ()
    links: tuple[CauseLink, ...] = ()

    def links_for(self, index: int) -> tuple[CauseLink, ...]:
        return tuple(link for link in self.links if link.finding_index == index)

    def cause(self, cause_id: str) -> Cause:
        for cause in self.causes:
            if cause.cause_id == cause_id:
                return cause
        raise KeyError(cause_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "causes": [c.to_dict() for c in self.causes],
            "links": [link.to_dict() for link in self.links],
        }
