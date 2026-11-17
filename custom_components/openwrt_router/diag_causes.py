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
  through its dependency gets at most a PROBABLE link. A link is never
  stronger than the finding's own cause class.
* Every common-cause rule works per address family. A cause lists every
  router it affects (``router_keys``), but a finding is linked to it only
  if the router depends on the cause's location according to
  ``dependencies`` (a router hosting a location counts as depending on it)
  AND the finding's own ``cause_stage`` and family are the ones the cause
  explains. Missing dependency data = no link.
* Every problem finding that no common cause explains gets its own local
  cause with the finding's own class (rule ``local_finding``). The main
  problem of another address family that no common cause covers gets a
  local cause as well (link reason ``secondary_problem``), so two distinct
  problems of one router both stay visible.

Common-cause rules (the plan's examples A, C, D):

* ``central_internet_access`` (A), explains WAN/INTERNET: routers that are
  up and reach their gateway (measured directly; the router hosting the WAN
  needs no gateway) but no external target, all depending on one WAN, and
  no router depending on that WAN reaches an external target directly.
* ``segment_path`` (C), explains GATEWAY: routers of a segment that are up
  lose their gateway while a router of another segment reaches it ->
  POSSIBLE VLAN/routing/firewall problem of that segment (never more: there
  is no configuration data yet). ``common_gateway``: all dependents with
  data lose the gateway -> PROBABLE.
* ``common_resolver`` (D), explains DNS: routers with directly measured
  working IP connectivity fail to resolve through the same resolver, and
  none resolves through it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace

from .diag_chain import dns_failure_confirmed, summary_key
from .diag_model import (
    FACT_WAN_UP,
    SEVERITY_RANK,
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
    Severity,
    Stage,
    StageProblem,
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

# The stages of a finding that a common cause of each rule can explain.
EXPLAINS: dict[str, frozenset[Stage]] = {
    RULE_CENTRAL: frozenset({Stage.WAN, Stage.INTERNET}),
    RULE_SEGMENT: frozenset({Stage.GATEWAY}),
    RULE_GATEWAY: frozenset({Stage.GATEWAY}),
    RULE_RESOLVER: frozenset({Stage.DNS}),
}

LINK_AT_LOCATION = "measured_at_cause_location"
LINK_DEPENDS = "depends_on_cause_location"
LINK_SECONDARY = "secondary_problem"


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


@dataclass(frozen=True)
class _Hit:
    """A common cause found for one address family (None = both)."""

    rule: str
    location: Location
    family: AddressFamily | None
    cause_class: CauseClass
    summary_key: str
    reason: str
    members: tuple[_Member, ...]
    confirm: frozenset[int] = frozenset()
    evidence: tuple[Evidence, ...] = ()

    def shape(self) -> tuple[object, ...]:
        indexes = tuple(m.index for m in self.members)
        return (indexes, self.confirm, self.cause_class, self.reason)


_Result = tuple[Cause, tuple[CauseLink, ...]]


# --- chain predicates (always for one family) -------------------------------------------


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


def _up(member: _Member, family: AddressFamily) -> bool:
    return _state(member, Stage.ROUTER, family) == StageState.HEALTHY


def _no_external(member: _Member, family: AddressFamily, wan: Location) -> bool:
    """Up, gateway measured reachable (or hosting the WAN itself), but WAN or
    internet failed in ``family``."""
    gateway = _healthy_direct(_stage(member, Stage.GATEWAY, family))
    return (
        _up(member, family)
        and (gateway or wan in member.deps.hosts)
        and StageState.FAILED
        in (_state(member, Stage.WAN, family), _state(member, Stage.INTERNET, family))
    )


def _wan_down_fact(member: _Member, family: AddressFamily) -> bool:
    result = _stage(member, Stage.WAN, family)
    return result is not None and any(
        e.fact == FACT_WAN_UP and e.ok is False and e.direct for e in result.evidence
    )


def _gateway_lost(member: _Member, family: AddressFamily) -> bool:
    return (
        _up(member, family)
        and _state(member, Stage.GATEWAY, family) == StageState.FAILED
    )


def _gateway_reached(member: _Member, family: AddressFamily) -> bool:
    return _healthy_direct(_stage(member, Stage.GATEWAY, family))


def _dns_items(
    member: _Member, resolver: str, ok: bool, family: AddressFamily
) -> list[Evidence]:
    result = _stage(member, Stage.DNS, family)
    if result is None:
        return []
    return [
        e
        for e in result.evidence
        if e.kind == ProbeKind.DNS
        and e.direct
        and e.ok is ok
        and e.target_id == resolver
    ]


def _resolver_fails(member: _Member, resolver: str, family: AddressFamily) -> bool:
    """Direct DNS failures through ``resolver`` while IP connectivity was
    measured working."""
    return (
        _up(member, family)
        and _healthy_direct(_stage(member, Stage.INTERNET, family))
        and bool(_dns_items(member, resolver, False, family))
    )


def _evidence(
    members: Iterable[_Member],
    stage: Stage,
    family: AddressFamily,
    keep: Callable[[Evidence], bool],
) -> tuple[Evidence, ...]:
    return tuple(
        e
        for m in members
        if (result := _stage(m, stage, family)) is not None
        for e in result.evidence
        if keep(e)
    )


def _failing(item: Evidence) -> bool:
    return item.ok is False


def _any(item: Evidence) -> bool:
    return item.ok is not None


# --- building causes and links ----------------------------------------------------------


def _merge(hits: Sequence[_Hit]) -> list[_Hit]:
    """Both families showing the same routers and verdict: one cause."""
    if len(hits) != len(AddressFamily) or len({h.shape() for h in hits}) != 1:
        return list(hits)
    evidence = tuple(dict.fromkeys(e for h in hits for e in h.evidence))
    return [replace(hits[0], family=None, evidence=evidence)]


def _explains(hit: _Hit, finding: Finding) -> bool:
    """The finding's own main problem is what this cause can explain."""
    return finding.cause_stage in EXPLAINS[hit.rule] and (
        hit.family is None or finding.family == hit.family
    )


def _build(hit: _Hit) -> _Result:
    members = sorted(hit.members, key=lambda m: m.index)
    suffix = f":{hit.family}" if hit.family is not None else ""
    cause = Cause(
        cause_id=f"{hit.rule}:{hit.location.kind}:{hit.location.id}{suffix}",
        location=hit.location,
        cause_class=hit.cause_class,
        rule=hit.rule,
        summary_key=hit.summary_key,
        reason=hit.reason,
        family=hit.family,
        router_keys=tuple(sorted({m.finding.point.label for m in members})),
        evidence=tuple(dict.fromkeys(hit.evidence)),
    )
    links = []
    for m in members:
        if not _explains(hit, m.finding):
            continue
        at_location = m.index in hit.confirm
        cause_class = (
            hit.cause_class
            if at_location
            else weaker_class(hit.cause_class, CauseClass.PROBABLE)
        )
        links.append(
            CauseLink(
                finding_index=m.index,
                router_key=m.finding.router_key,
                cause_id=cause.cause_id,
                cause_class=weaker_class(cause_class, m.finding.cause_class),
                rule=hit.rule,
                reason=LINK_AT_LOCATION if at_location else LINK_DEPENDS,
            )
        )
    return cause, tuple(links)


# --- rule A: central internet access -------------------------------------------------


def _central_for(
    wan: Location, dependents: list[_Member], family: AddressFamily
) -> _Hit | None:
    if any(_healthy_direct(_stage(m, Stage.INTERNET, family)) for m in dependents):
        return None  # someone behind this WAN reaches the internet
    affected = tuple(m for m in dependents if _no_external(m, family, wan))
    confirm = frozenset(
        m.index for m in affected if wan in m.deps.hosts and _wan_down_fact(m, family)
    )
    if not confirm and len(affected) < 2:
        return None
    evidence = _evidence(affected, Stage.WAN, family, _failing)
    evidence += _evidence(affected, Stage.INTERNET, family, _failing)
    return _Hit(
        RULE_CENTRAL,
        wan,
        family,
        CauseClass.CONFIRMED if confirm else CauseClass.PROBABLE,
        RULE_CENTRAL,
        "gateway_reports_wan_down"
        if confirm
        else "no_dependent_router_reaches_external_targets",
        affected,
        confirm,
        evidence,
    )


def _central_internet(members: list[_Member]) -> list[_Hit]:
    hits: list[_Hit] = []
    wans = {
        loc
        for m in members
        for loc in m.deps.locations()
        if loc.kind == LocationKind.WAN
    }
    for wan in sorted(wans, key=lambda loc: loc.id):
        dependents = [m for m in members if m.deps.depends_on(wan)]
        found = [
            hit for f in AddressFamily if (hit := _central_for(wan, dependents, f))
        ]
        hits.extend(_merge(found))
    return hits


# --- rule C: gateway reachability per segment ------------------------------------------


def _segment_hits(
    affected: list[_Member], working: list[_Member], family: AddressFamily
) -> list[_Hit]:
    taken = {s for m in working for s in m.deps.segments}
    hits: list[_Hit] = []
    for segment in sorted({s for m in affected for s in m.deps.segments} - taken):
        hit = tuple(m for m in affected if segment in m.deps.segments)
        evidence = _evidence(hit, Stage.GATEWAY, family, _failing)
        evidence += _evidence(working, Stage.GATEWAY, family, _any)
        hits.append(
            _Hit(
                RULE_SEGMENT,
                Location(LocationKind.SEGMENT, segment),
                family,
                CauseClass.POSSIBLE,
                "vlan_routing_or_firewall",
                "segment_cannot_reach_gateway_other_segment_can",
                hit,
                evidence=evidence,
            )
        )
    return hits


def _gateway_family(
    gateway: str, dependents: list[_Member], family: AddressFamily
) -> list[_Hit]:
    affected = [m for m in dependents if _gateway_lost(m, family)]
    working = [m for m in dependents if _gateway_reached(m, family)]
    if not affected:
        return []
    if working:
        return _segment_hits(affected, working, family)
    if len(affected) < 2:
        return []
    return [
        _Hit(
            RULE_GATEWAY,
            Location(LocationKind.ROUTER, gateway),
            family,
            CauseClass.PROBABLE,
            RULE_GATEWAY,
            "several_dependents_cannot_reach_gateway",
            tuple(affected),
            evidence=_evidence(affected, Stage.GATEWAY, family, _failing),
        )
    ]


def _by_location(hits: Iterable[_Hit]) -> list[_Hit]:
    """Merge the per-family hits of each (rule, location)."""
    groups: dict[tuple[str, Location], list[_Hit]] = {}
    for hit in hits:
        groups.setdefault((hit.rule, hit.location), []).append(hit)
    return [merged for group in groups.values() for merged in _merge(group)]


def _gateway_paths(members: list[_Member]) -> list[_Hit]:
    hits: list[_Hit] = []
    for gateway in sorted({m.deps.gateway for m in members if m.deps.gateway}):
        dependents = [
            m
            for m in members
            if m.deps.gateway == gateway and m.finding.router_key != gateway
        ]
        found = [
            hit
            for family in AddressFamily
            for hit in _gateway_family(gateway, dependents, family)
        ]
        hits.extend(_by_location(found))
    return hits


# --- rule D: common resolver -------------------------------------------------------------


def _resolver_for(
    resolver: Location, dependents: list[_Member], family: AddressFamily
) -> _Hit | None:
    affected = tuple(m for m in dependents if _resolver_fails(m, resolver.id, family))
    confirm = frozenset(
        m.index
        for m in affected
        if m.finding.chain is not None
        and dns_failure_confirmed(m.finding.chain, family, resolver.id)
    )
    if not confirm and len(affected) < 2:
        return None
    return _Hit(
        RULE_RESOLVER,
        resolver,
        family,
        CauseClass.CONFIRMED if confirm else CauseClass.PROBABLE,
        "common_resolver_or_upstream_dns",
        "resolver_failure_measured"
        if confirm
        else "several_dependents_fail_to_resolve",
        affected,
        confirm,
        tuple(e for m in affected for e in _dns_items(m, resolver.id, False, family)),
    )


def _common_resolver(members: list[_Member]) -> list[_Hit]:
    hits: list[_Hit] = []
    resolvers = {
        loc
        for m in members
        for loc in m.deps.locations()
        if loc.kind == LocationKind.RESOLVER
    }
    for resolver in sorted(resolvers, key=lambda loc: loc.id):
        dependents = [m for m in members if m.deps.depends_on(resolver)]
        if any(
            _dns_items(m, resolver.id, True, f)
            for m in dependents
            for f in AddressFamily
        ):
            continue  # the resolver answers for someone, in any family
        found = [
            hit
            for f in AddressFamily
            if (hit := _resolver_for(resolver, dependents, f))
        ]
        hits.extend(_merge(found))
    return hits


# --- local causes and entry point ---------------------------------------------------------


def _location(finding: Finding) -> Location:
    if finding.point.kind == PointKind.HA:
        return Location(LocationKind.HA, PointKind.HA.value)
    return Location(LocationKind.ROUTER, finding.point.label)


def _local(index: int, finding: Finding) -> _Result:
    location = _location(finding)
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


def _other_family_heads(finding: Finding) -> list[StageProblem]:
    """Main (most upstream serious) problem of every family other than the
    finding's own; a family-free finding has none."""
    if finding.family is None:
        return []
    heads: dict[AddressFamily, StageProblem] = {}
    for problem in finding.also:
        if (
            problem.family != finding.family
            and SEVERITY_RANK[problem.severity] >= SEVERITY_RANK[Severity.WARNING]
        ):
            heads.setdefault(problem.family, problem)
    return list(heads.values())


def _covered(problem: StageProblem, router: str, causes: Iterable[Cause]) -> bool:
    return any(
        router in cause.router_keys
        and problem.stage in EXPLAINS[cause.rule]
        and cause.family in (None, problem.family)
        for cause in causes
    )


def _secondary(index: int, finding: Finding, problem: StageProblem) -> _Result:
    location = _location(finding)
    chain = finding.chain
    evidence = (
        () if chain is None else chain.stage(problem.stage, problem.family).evidence
    )
    cause = Cause(
        cause_id=(
            f"{RULE_LOCAL}:{location.kind}:{location.id}:{index}"
            f":{problem.family}:{problem.stage}"
        ),
        location=location,
        cause_class=problem.cause_class,
        rule=RULE_LOCAL,
        summary_key=summary_key(problem.classification),
        reason=problem.classification.value,
        family=problem.family,
        router_keys=(finding.point.label,),
        evidence=evidence,
    )
    link = CauseLink(
        finding_index=index,
        router_key=finding.router_key,
        cause_id=cause.cause_id,
        cause_class=problem.cause_class,
        rule=RULE_LOCAL,
        reason=LINK_SECONDARY,
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


def _local_causes(
    items: tuple[Finding, ...], common: list[Cause], explained: set[int]
) -> list[_Result]:
    results: list[_Result] = []
    for index, finding in enumerate(items):
        if not finding.is_problem:
            continue
        if index not in explained:
            results.append(_local(index, finding))
        for problem in _other_family_heads(finding):
            if not _covered(problem, finding.point.label, common):
                results.append(_secondary(index, finding, problem))
    return results


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
        for cause, rule_links in map(_build, rule(members)):
            causes.append(cause)
            links.extend(rule_links)
    explained = {link.finding_index for link in links}
    for cause, local_links in _local_causes(items, list(causes), explained):
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
