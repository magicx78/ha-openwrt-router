"""Cause classification across several routers for active network diagnostics.

Pure module: standard library only, no Home Assistant imports, no I/O.

``correlate(findings, dependencies)`` returns every input finding unchanged
and in order, plus causes and link records (finding index -> cause). Nothing
is filtered, hidden or marked suppressed; a report decides what to show.

Rules:

* Cause classes CONFIRMED / PROBABLE / POSSIBLE / UNKNOWN. CONFIRMED needs a
  direct measurement at the cause's location (the router hosting the WAN
  reports it down; a resolver answered SERVFAIL/REFUSED or timed out while
  the path to it was measured healthy). Correlation alone - the same symptom
  at several routers - gives at most PROBABLE, and a router linked only
  through its dependency gets at most a PROBABLE link.
* A finding is linked to a common cause only if the router depends on the
  cause's location according to ``dependencies`` (a router hosting a
  location counts as depending on it). Missing dependency data = no link.
* Every problem finding that no common cause explains gets its own local
  cause with the finding's own class (rule ``local_finding``).

Common-cause rules (the plan's examples A, C, D):

* ``central_internet_access`` (A): routers that are up and reach their
  gateway but no external target, all depending on one WAN, and no router
  depending on that WAN reaches an external target directly.
* ``segment_path`` (C): routers of a segment lose their gateway while a
  router of another segment reaches it -> POSSIBLE VLAN/routing/firewall
  problem of that segment (never more: there is no configuration data yet).
  ``common_gateway``: all dependents with data lose the gateway -> PROBABLE.
* ``common_resolver`` (D): routers with working IP connectivity fail to
  resolve through the same resolver, and none resolves through it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from .diag_chain import dns_failure_confirmed
from .diag_model import (
    FACT_WAN_UP,
    AddressFamily,
    Basis,
    Cause,
    CauseClass,
    CauseLink,
    CorrelationResult,
    Evidence,
    Finding,
    Location,
    LocationKind,
    PointKind,
    ProbeKind,
    Stage,
    StageResult,
    StageState,
    weaker_class,
)

_LOGGER = logging.getLogger(__name__)

RULE_LOCAL = "local_finding"
RULE_CENTRAL = "central_internet_access"
RULE_SEGMENT = "segment_path"
RULE_GATEWAY = "common_gateway"
RULE_RESOLVER = "common_resolver"

LINK_AT_LOCATION = "measured_at_cause_location"
LINK_DEPENDS = "depends_on_cause_location"


def _id_set(value: Iterable[object], name: str) -> frozenset:
    if isinstance(value, str):
        raise TypeError(f"{name} must be a collection of ids, not a string")
    return frozenset(value)


@dataclass(frozen=True)
class RouterDependencies:
    """What one router technically depends on (all ids opaque).

    ``hosts``: locations that sit on this router (the gateway hosts the WAN
    and usually a resolver); only a hosting router can confirm a cause.
    """

    gateway: str | None = None
    upstream: frozenset[str] = frozenset()
    resolvers: frozenset[str] = frozenset()
    wan: str | None = None
    segments: frozenset[str] = frozenset()
    hosts: frozenset[Location] = frozenset()

    def __post_init__(self) -> None:
        for name in ("upstream", "resolvers", "segments", "hosts"):
            object.__setattr__(self, name, _id_set(getattr(self, name), name))

    def locations(self) -> frozenset[Location]:
        found = {Location(LocationKind.ROUTER, key) for key in self.upstream}
        if self.gateway:
            found.add(Location(LocationKind.ROUTER, self.gateway))
        if self.wan:
            found.add(Location(LocationKind.WAN, self.wan))
        found |= {Location(LocationKind.RESOLVER, r) for r in self.resolvers}
        found |= {Location(LocationKind.SEGMENT, s) for s in self.segments}
        return frozenset(found | self.hosts)

    def depends_on(self, location: Location) -> bool:
        return location in self.locations()


@dataclass(frozen=True)
class _Member:
    index: int
    finding: Finding
    deps: RouterDependencies


_Result = tuple[Cause, tuple[CauseLink, ...]]


# --- chain predicates ---------------------------------------------------------------


def _stages(member: _Member, stage: Stage) -> list[StageResult]:
    chain = member.finding.chain
    if chain is None:
        return []
    return [chain.stage(stage, family) for family in chain.families]


def _stage(member: _Member, stage: Stage, family: AddressFamily) -> StageResult | None:
    chain = member.finding.chain
    if chain is None or family not in chain.families:
        return None
    return chain.stage(stage, family)


def _state(member: _Member, stage: Stage, family: AddressFamily) -> StageState | None:
    result = _stage(member, stage, family)
    return None if result is None else result.state


def _healthy_direct(result: StageResult | None) -> bool:
    return (
        result is not None
        and result.state == StageState.HEALTHY
        and result.basis == Basis.DIRECT
    )


def _no_external(member: _Member, family: AddressFamily) -> bool:
    """Up, gateway not lost, but WAN or internet failed in ``family``."""
    return (
        _state(member, Stage.ROUTER, family) == StageState.HEALTHY
        and _state(member, Stage.GATEWAY, family) != StageState.FAILED
        and StageState.FAILED
        in (_state(member, Stage.WAN, family), _state(member, Stage.INTERNET, family))
    )


def _wan_down_fact(member: _Member, family: AddressFamily) -> bool:
    result = _stage(member, Stage.WAN, family)
    return result is not None and any(
        e.fact == FACT_WAN_UP and e.ok is False and e.direct for e in result.evidence
    )


def _gateway_lost(member: _Member) -> bool:
    chain = member.finding.chain
    return chain is not None and any(
        _state(member, Stage.ROUTER, f) != StageState.FAILED
        and _state(member, Stage.GATEWAY, f) == StageState.FAILED
        for f in chain.families
    )


def _gateway_reached(member: _Member) -> bool:
    return any(_healthy_direct(s) for s in _stages(member, Stage.GATEWAY))


def _dns_items(
    member: _Member, resolver: str, ok: bool, family: AddressFamily | None = None
) -> list[Evidence]:
    return [
        e
        for s in _stages(member, Stage.DNS)
        if family is None or s.family == family
        for e in s.evidence
        if e.kind == ProbeKind.DNS
        and e.direct
        and e.ok is ok
        and e.target_id == resolver
    ]


def _resolver_fails(member: _Member, resolver: str) -> bool:
    """Direct DNS failures through ``resolver`` while IP was not lost."""
    chain = member.finding.chain
    return chain is not None and any(
        _state(member, Stage.ROUTER, f) != StageState.FAILED
        and _state(member, Stage.INTERNET, f) != StageState.FAILED
        and _dns_items(member, resolver, False, f)
        for f in chain.families
    )


def _resolver_confirmed(member: _Member, resolver: str) -> bool:
    chain = member.finding.chain
    return chain is not None and any(
        dns_failure_confirmed(chain, f, resolver) for f in chain.families
    )


# --- building causes and links ----------------------------------------------------------


def _make(
    rule: str,
    location: Location,
    cause_class: CauseClass,
    summary_key: str,
    reason: str,
    members: Iterable[_Member],
    *,
    confirming: Iterable[int] = (),
    family: AddressFamily | None = None,
    evidence: Iterable[Evidence] = (),
) -> _Result:
    members = sorted(members, key=lambda m: m.index)
    at_location = set(confirming)
    suffix = f":{family}" if family is not None else ""
    cause = Cause(
        cause_id=f"{rule}:{location.kind}:{location.id}{suffix}",
        location=location,
        cause_class=cause_class,
        rule=rule,
        summary_key=summary_key,
        reason=reason,
        family=family,
        router_keys=tuple(sorted({m.finding.point.label for m in members})),
        evidence=tuple(dict.fromkeys(evidence)),
    )
    links = tuple(
        CauseLink(
            finding_index=m.index,
            router_key=m.finding.router_key,
            cause_id=cause.cause_id,
            cause_class=cause_class
            if m.index in at_location
            else weaker_class(cause_class, CauseClass.PROBABLE),
            rule=rule,
            reason=LINK_AT_LOCATION if m.index in at_location else LINK_DEPENDS,
        )
        for m in members
    )
    return cause, links


def _evidence(
    members: Iterable[_Member],
    stages: Iterable[Stage],
    keep: Callable[[Evidence], bool],
) -> list[Evidence]:
    wanted = tuple(stages)
    return [
        e
        for m in members
        for stage in wanted
        for s in _stages(m, stage)
        for e in s.evidence
        if keep(e)
    ]


def _failing(item: Evidence) -> bool:
    return item.ok is False


def _any(item: Evidence) -> bool:
    return item.ok is not None


# --- rule A: central internet access -------------------------------------------------


def _central_for(
    wan: Location, dependents: list[_Member], family: AddressFamily
) -> tuple[tuple[_Member, ...], frozenset[int]] | None:
    if any(_healthy_direct(_stage(m, Stage.INTERNET, family)) for m in dependents):
        return None  # someone behind this WAN reaches the internet
    affected = [m for m in dependents if _no_external(m, family)]
    confirm = frozenset(
        m.index for m in affected if wan in m.deps.hosts and _wan_down_fact(m, family)
    )
    if not confirm and len(affected) < 2:
        return None
    return tuple(affected), confirm


def _central_internet(members: list[_Member]) -> list[_Result]:
    results: list[_Result] = []
    wans = {
        loc
        for m in members
        for loc in m.deps.locations()
        if loc.kind == LocationKind.WAN
    }
    for wan in sorted(wans, key=lambda loc: loc.id):
        dependents = [m for m in members if m.deps.depends_on(wan)]
        hits = {
            f: hit
            for f in AddressFamily
            if (hit := _central_for(wan, dependents, f)) is not None
        }
        values = set(hits.values())
        if len(hits) == len(AddressFamily) and len(values) == 1:
            hits = {None: values.pop()}  # same routers, same evidence: one cause
        for family, (affected, confirm) in hits.items():
            cause_class = CauseClass.CONFIRMED if confirm else CauseClass.PROBABLE
            reason = (
                "gateway_reports_wan_down"
                if confirm
                else "no_dependent_router_reaches_external_targets"
            )
            results.append(
                _make(
                    RULE_CENTRAL,
                    wan,
                    cause_class,
                    RULE_CENTRAL,
                    reason,
                    affected,
                    confirming=confirm,
                    family=family,
                    evidence=_evidence(affected, (Stage.WAN, Stage.INTERNET), _failing),
                )
            )
    return results


# --- rule C: gateway reachability per segment ------------------------------------------


def _segment_causes(affected: list[_Member], working: list[_Member]) -> list[_Result]:
    taken = {s for m in working for s in m.deps.segments}
    results: list[_Result] = []
    for segment in sorted({s for m in affected for s in m.deps.segments} - taken):
        hit = [m for m in affected if segment in m.deps.segments]
        evidence = _evidence(hit, (Stage.GATEWAY,), _failing)
        evidence += _evidence(working, (Stage.GATEWAY,), _any)
        results.append(
            _make(
                RULE_SEGMENT,
                Location(LocationKind.SEGMENT, segment),
                CauseClass.POSSIBLE,
                "vlan_routing_or_firewall",
                "segment_cannot_reach_gateway_other_segment_can",
                hit,
                evidence=evidence,
            )
        )
    return results


def _gateway_paths(members: list[_Member]) -> list[_Result]:
    results: list[_Result] = []
    for gateway in sorted({m.deps.gateway for m in members if m.deps.gateway}):
        dependents = [
            m
            for m in members
            if m.deps.gateway == gateway and m.finding.router_key != gateway
        ]
        affected = [m for m in dependents if _gateway_lost(m)]
        working = [m for m in dependents if _gateway_reached(m)]
        if not affected:
            continue
        if working:
            results.extend(_segment_causes(affected, working))
        elif len(affected) >= 2:
            results.append(
                _make(
                    RULE_GATEWAY,
                    Location(LocationKind.ROUTER, gateway),
                    CauseClass.PROBABLE,
                    RULE_GATEWAY,
                    "several_dependents_cannot_reach_gateway",
                    affected,
                    evidence=_evidence(affected, (Stage.GATEWAY,), _failing),
                )
            )
    return results


# --- rule D: common resolver -------------------------------------------------------------


def _common_resolver(members: list[_Member]) -> list[_Result]:
    results: list[_Result] = []
    resolvers = {
        loc
        for m in members
        for loc in m.deps.locations()
        if loc.kind == LocationKind.RESOLVER
    }
    for resolver in sorted(resolvers, key=lambda loc: loc.id):
        dependents = [m for m in members if m.deps.depends_on(resolver)]
        if any(_dns_items(m, resolver.id, True) for m in dependents):
            continue  # the resolver answers for someone
        affected = [m for m in dependents if _resolver_fails(m, resolver.id)]
        confirm = frozenset(
            m.index for m in affected if _resolver_confirmed(m, resolver.id)
        )
        if not confirm and len(affected) < 2:
            continue
        failing = [e for m in affected for e in _dns_items(m, resolver.id, False)]
        families = {e.family for e in failing}
        results.append(
            _make(
                RULE_RESOLVER,
                resolver,
                CauseClass.CONFIRMED if confirm else CauseClass.PROBABLE,
                "common_resolver_or_upstream_dns",
                "resolver_failure_measured"
                if confirm
                else "several_dependents_fail_to_resolve",
                affected,
                confirming=confirm,
                family=families.pop() if len(families) == 1 else None,
                evidence=failing,
            )
        )
    return results


# --- local causes and entry point ---------------------------------------------------------


def _local(index: int, finding: Finding) -> _Result:
    if finding.point.kind == PointKind.HA:
        location = Location(LocationKind.HA, PointKind.HA.value)
    else:
        location = Location(LocationKind.ROUTER, finding.point.label)
    cause = Cause(
        cause_id=f"{RULE_LOCAL}:{location.kind}:{location.id}:{index}",
        location=location,
        cause_class=finding.cause_class,
        rule=RULE_LOCAL,
        summary_key=finding.summary_key,
        reason=finding.classification.value,
        family=finding.family,
        router_keys=(finding.point.label,),
        evidence=finding.evidence,
    )
    link = CauseLink(
        finding_index=index,
        router_key=finding.router_key,
        cause_id=cause.cause_id,
        cause_class=finding.cause_class,
        rule=RULE_LOCAL,
        reason=LINK_AT_LOCATION,
    )
    return cause, (link,)


def _members(
    findings: tuple[Finding, ...], dependencies: Mapping[str, RouterDependencies]
) -> list[_Member]:
    """Router findings with a chain and known dependencies."""
    members = []
    for index, finding in enumerate(findings):
        key = finding.router_key
        if finding.chain is None or finding.point.kind != PointKind.ROUTER:
            continue
        deps = dependencies.get(key) if key is not None else None
        if deps is not None:
            members.append(_Member(index, finding, deps))
    return members


def correlate(
    findings: Iterable[Finding],
    dependencies: Mapping[str, RouterDependencies],
) -> CorrelationResult:
    """Link findings to common or local causes without changing any finding."""
    items = tuple(findings)
    members = _members(items, dependencies)
    causes: list[Cause] = []
    links: list[CauseLink] = []
    for rule in (_central_internet, _gateway_paths, _common_resolver):
        for cause, rule_links in rule(members):
            causes.append(cause)
            links.extend(rule_links)
    explained = {link.finding_index for link in links}
    for index, finding in enumerate(items):
        if finding.is_problem and index not in explained:
            cause, local_links = _local(index, finding)
            causes.append(cause)
            links.extend(local_links)
    links.sort(key=lambda link: (link.finding_index, link.cause_id))
    _LOGGER.debug(
        "diag correlate: %d finding(s), %d cause(s), %d link(s)",
        len(items),
        len(causes),
        len(links),
    )
    return CorrelationResult(items, tuple(causes), tuple(links))
