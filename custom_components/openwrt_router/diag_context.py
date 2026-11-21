"""Context of a network diagnosis finding (release 1.47.0, part 2).

Pure module (standard library and the ``diag_model`` types only): no Home
Assistant import, no I/O. The run time collects two read-only sources and
hands them in as :class:`SourceView`:

* configuration changes (drifts) from the Configuration Manager, with the
  configuration areas (``config_diff.Area`` values: vlan, interface,
  routing, firewall, dns, dhcp, ...) once they are known;
* incidents of the Security Center.

Both are CONTEXT for a finding, never its proof:

* A context link is at most PROBABLE, and never stronger than the
  finding's own cause class. CONFIRMED needs a direct measurement; the
  finding's own ``cause_class`` is never raised by a context.
* Only changes on the SAME router inside the window count, and only the
  areas that can technically explain the classification (``AREA_RULES``):
  a missing default route is a routing problem; a VLAN or firewall change
  never makes it a confirmed VLAN or firewall fault.
* A firewall change next to a blocked ICMP/TCP target while everything else
  works adds the hypothesis ``possible_firewall_restriction`` (POSSIBLE);
  the finding stays what it is (no outage).
* A source that is missing, disabled or not ready gives the state
  ``context_unavailable`` with its reason, never "no configuration change".
  A source that started listening after the window began gives
  ``partial``: what it saw is listed, an absence is not claimed.

Output holds router ids, area names, opaque change ids, incident ids and
codes only (no address, host or domain).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from .diag_model import CauseClass, Classification, Finding

_LOGGER = logging.getLogger(__name__)

# A change detected this long before the finding (seconds) is context. A
# drift detected up to the window after the finding may have happened before
# it (drift checks run on a schedule): POSSIBLE at most.
DEFAULT_WINDOW_SECONDS: Final = 1800.0
MAX_LINKS: Final = 16

CONTEXT_AVAILABLE: Final = "available"
CONTEXT_PARTIAL: Final = "partial"
CONTEXT_UNAVAILABLE: Final = "context_unavailable"

SOURCE_CONFIG: Final = "configuration"
SOURCE_SECURITY: Final = "security"

HYP_FIREWALL: Final = "possible_firewall_restriction"
HYP_SECURITY: Final = "security_incident_nearby"


class SourceState(StrEnum):
    """State of one context source."""

    READY = "ready"
    MISSING = "missing"
    DISABLED = "disabled"
    NOT_READY = "not_ready"
    # listening, but items were dropped (bounded memory): what is left is
    # used, the context is "partial" with the source's reason
    PARTIAL = "partial"


@dataclass(frozen=True)
class ConfigChange:
    """One detected configuration change (drift) of a router.

    ``areas`` None: not known (yet); ``at``: when the change was detected.
    """

    router_id: str
    at: float
    ref: str
    areas: tuple[str, ...] | None = None
    critical: bool = False


@dataclass(frozen=True)
class SecurityIncident:
    """One Security Center incident (masked view fields only)."""

    router_id: str | None
    at: float
    incident_id: str
    type: str
    category: str
    severity: str


@dataclass(frozen=True)
class SourceView:
    """What a source knows: its state, since when it listens, its items."""

    state: SourceState
    reason: str | None = None
    since: float | None = None
    items: tuple[Any, ...] = ()

    @classmethod
    def unavailable(cls, state: SourceState, reason: str) -> SourceView:
        """A source that cannot say anything."""
        return cls(state=state, reason=reason)


# (area, strongest class the context may give, hypothesis code)
_Rule = tuple[str, CauseClass, str]

_FW: Final = ("firewall", CauseClass.POSSIBLE, HYP_FIREWALL)

AREA_RULES: Final[Mapping[Classification, tuple[_Rule, ...]]] = {
    Classification.LAN_PROBLEM: (
        ("vlan", CauseClass.PROBABLE, "config_change_vlan"),
        ("interface", CauseClass.PROBABLE, "config_change_interface"),
        ("mgmt_ip", CauseClass.POSSIBLE, "config_change_mgmt_ip"),
        ("dhcp", CauseClass.POSSIBLE, "config_change_dhcp"),
    ),
    # never vlan or firewall: a missing route is a routing problem
    Classification.ROUTING_PROBLEM: (
        ("routing", CauseClass.PROBABLE, "config_change_routing"),
        ("interface", CauseClass.POSSIBLE, "config_change_interface"),
    ),
    Classification.GATEWAY_PROBLEM: (
        ("interface", CauseClass.POSSIBLE, "config_change_interface"),
        ("routing", CauseClass.POSSIBLE, "config_change_routing"),
    ),
    Classification.WAN_PROBLEM: (
        ("interface", CauseClass.POSSIBLE, "config_change_interface"),
        ("routing", CauseClass.POSSIBLE, "config_change_routing"),
    ),
    Classification.DNS_PROBLEM: (
        ("dns", CauseClass.PROBABLE, "config_change_dns"),
        ("dhcp", CauseClass.POSSIBLE, "config_change_dhcp"),
        _FW,
    ),
    Classification.SINGLE_EXTERNAL_SERVICE_UNREACHABLE: (_FW,),
    Classification.POSSIBLE_FIREWALL_RESTRICTION: (_FW,),
    Classification.ICMP_UNANSWERED: (_FW,),
    Classification.MANAGEMENT_UNREACHABLE: (
        ("mgmt_ip", CauseClass.POSSIBLE, "config_change_mgmt_ip"),
        ("interface", CauseClass.POSSIBLE, "config_change_interface"),
        ("firewall", CauseClass.POSSIBLE, "config_change_firewall"),
    ),
    Classification.GATEWAY_CHANGED: (
        ("interface", CauseClass.POSSIBLE, "config_change_interface"),
        ("routing", CauseClass.POSSIBLE, "config_change_routing"),
    ),
    Classification.DNS_SERVER_CHANGED: (
        ("dns", CauseClass.POSSIBLE, "config_change_dns"),
        ("dhcp", CauseClass.POSSIBLE, "config_change_dhcp"),
        ("interface", CauseClass.POSSIBLE, "config_change_interface"),
    ),
}

_ORDER: Final = (
    CauseClass.CONFIRMED,
    CauseClass.PROBABLE,
    CauseClass.POSSIBLE,
    CauseClass.UNKNOWN,
)
# The strongest class a context link may ever have.
CONTEXT_MAX_CLASS: Final = CauseClass.PROBABLE


def _weaker(a: CauseClass, b: CauseClass) -> CauseClass:
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


@dataclass(frozen=True)
class ContextLink:
    """One piece of context next to a finding (never its proof)."""

    source: str
    cause_class: CauseClass
    hypothesis: str
    minutes_before: int
    area: str | None = None
    ref: str | None = None
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Plain dict (codes, ids and numbers only)."""
        return {
            "source": self.source,
            "cause_class": self.cause_class.value,
            "hypothesis": self.hypothesis,
            "minutes_before": self.minutes_before,
            "area": self.area,
            "ref": self.ref,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class FindingContext:
    """Context of one finding: per source a state, plus the links."""

    classification: str
    cause_class: CauseClass
    config_state: str
    config_reason: str | None
    security_state: str
    security_reason: str | None
    links: tuple[ContextLink, ...] = ()

    @property
    def hypotheses(self) -> tuple[str, ...]:
        """The hypothesis codes of the links (sorted, unique)."""
        return tuple(sorted({link.hypothesis for link in self.links}))

    def to_dict(self) -> dict[str, Any]:
        """Plain dict for the routes (no address, host or domain)."""
        config = [link for link in self.links if link.source == SOURCE_CONFIG]
        security = [link for link in self.links if link.source == SOURCE_SECURITY]
        return {
            "classification": self.classification,
            # the finding's own class: a context never raises it
            "cause_class": self.cause_class.value,
            "configuration": {
                "state": self.config_state,
                "reason": self.config_reason,
                # None while unavailable: unknown, not "no change"
                "changes": None
                if self.config_state == CONTEXT_UNAVAILABLE
                else [link.to_dict() for link in config],
            },
            "security": {
                "state": self.security_state,
                "reason": self.security_reason,
                "incidents": None
                if self.security_state == CONTEXT_UNAVAILABLE
                else [link.to_dict() for link in security],
            },
            "hypotheses": list(self.hypotheses),
        }


def _source_state(view: SourceView, start: float) -> tuple[str, str | None]:
    if view.state is SourceState.PARTIAL:
        return CONTEXT_PARTIAL, view.reason or view.state.value
    if view.state is not SourceState.READY:
        return CONTEXT_UNAVAILABLE, view.reason or view.state.value
    if view.since is None or view.since > start:
        return CONTEXT_PARTIAL, "listening_since_after_window_start"
    return CONTEXT_AVAILABLE, None


def _minutes(at: float, ts: float) -> int:
    return int((at - ts) // 60) if at >= ts else -int((ts - at + 59) // 60)


def config_links(
    finding: Finding,
    router_id: str,
    at: float,
    changes: Iterable[ConfigChange],
    *,
    window: float = DEFAULT_WINDOW_SECONDS,
    extra_evidence: Iterable[str] = (),
) -> list[ContextLink]:
    """Context links of the configuration changes for one router finding."""
    rules = AREA_RULES.get(finding.classification, ())
    if not rules or (not finding.is_problem and finding.change is None):
        return []
    own = finding.cause_class
    extra = tuple(extra_evidence)
    links: list[ContextLink] = []
    for change in changes:
        if change.router_id != router_id:
            continue
        before = at - window <= change.at <= at
        after = at < change.at <= at + window
        if not (before or after):
            continue
        evidence = (
            f"config_change:{change.ref}",
            "same_router",
            "detected_before_finding" if before else "detected_after_finding",
        )
        if change.areas is None:
            # areas not known: a change happened, nothing more is claimed
            links.append(
                ContextLink(
                    SOURCE_CONFIG,
                    CauseClass.POSSIBLE,
                    "config_change_area_unknown",
                    _minutes(at, change.at),
                    ref=change.ref,
                    evidence=(*evidence, "areas_unknown"),
                )
            )
            continue
        for area, cap, hypothesis in rules:
            if area not in change.areas:
                continue
            cause = _weaker(_weaker(cap, CONTEXT_MAX_CLASS), own)
            if after:
                cause = _weaker(cause, CauseClass.POSSIBLE)
            links.append(
                ContextLink(
                    SOURCE_CONFIG,
                    cause,
                    hypothesis,
                    _minutes(at, change.at),
                    area=area,
                    ref=change.ref,
                    evidence=(*evidence, f"area:{area}", *extra),
                )
            )
    links.sort(key=lambda link: (_ORDER.index(link.cause_class), link.minutes_before))
    return links[:MAX_LINKS]


def security_links(
    finding: Finding,
    router_id: str | None,
    at: float,
    incidents: Iterable[SecurityIncident],
    *,
    window: float = DEFAULT_WINDOW_SECONDS,
) -> list[ContextLink]:
    """Security incidents of the same router near a problem finding (POSSIBLE)."""
    if not finding.is_problem or router_id is None:
        return []
    links = [
        ContextLink(
            SOURCE_SECURITY,
            CauseClass.POSSIBLE,
            HYP_SECURITY,
            _minutes(at, inc.at),
            ref=inc.incident_id,
            evidence=(
                f"security_incident:{inc.type}",
                f"category:{inc.category}",
                f"severity:{inc.severity}",
                "same_router",
            ),
        )
        for inc in incidents
        if inc.router_id == router_id and at - window <= inc.at <= at + window
    ]
    links.sort(key=lambda link: abs(link.minutes_before))
    return links[:MAX_LINKS]


def context_for(
    finding: Finding,
    router_id: str | None,
    at: float,
    *,
    config: SourceView,
    security: SourceView,
    window: float = DEFAULT_WINDOW_SECONDS,
    extra_evidence: Iterable[str] = (),
) -> FindingContext:
    """The context of ``finding`` (router ``router_id``, None for HA) at ``at``.

    The HA point has no router: configuration changes of a router are not
    its context (``not_applicable``).
    """
    start = at - window
    links: list[ContextLink] = []
    if router_id is None:
        config_state, config_reason = CONTEXT_UNAVAILABLE, "not_applicable"
    else:
        config_state, config_reason = _source_state(config, start)
        if config_state != CONTEXT_UNAVAILABLE:
            links += config_links(
                finding,
                router_id,
                at,
                (c for c in config.items if isinstance(c, ConfigChange)),
                window=window,
                extra_evidence=extra_evidence,
            )
    security_state, security_reason = _source_state(security, start)
    if router_id is None:
        security_state, security_reason = CONTEXT_UNAVAILABLE, "not_applicable"
    elif security_state != CONTEXT_UNAVAILABLE:
        links += security_links(
            finding,
            router_id,
            at,
            (i for i in security.items if isinstance(i, SecurityIncident)),
            window=window,
        )
    return FindingContext(
        classification=finding.classification.value,
        cause_class=finding.cause_class,
        config_state=config_state,
        config_reason=config_reason,
        security_state=security_state,
        security_reason=security_reason,
        links=tuple(links),
    )


__all__ = [
    "AREA_RULES",
    "CONTEXT_AVAILABLE",
    "CONTEXT_MAX_CLASS",
    "CONTEXT_PARTIAL",
    "CONTEXT_UNAVAILABLE",
    "DEFAULT_WINDOW_SECONDS",
    "HYP_FIREWALL",
    "ConfigChange",
    "ContextLink",
    "FindingContext",
    "SecurityIncident",
    "SourceState",
    "SourceView",
    "config_links",
    "context_for",
    "security_links",
]
