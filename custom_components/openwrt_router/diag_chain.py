"""Diagnosis chain Router -> Gateway -> WAN -> Internet -> DNS: evaluation and
classification for one measurement point.

Pure module: standard library only, no Home Assistant imports, no I/O.

Rules implemented here (numbers from the plan's acceptance list):

1. A stage without usable evidence is UNKNOWN and lowers coverage. "No
   fault detected" needs every applicable stage measured directly; otherwise
   the result is PARTIALLY_MEASURED with the unmeasured stages listed.
2. Only a non-ICMP ("hard") failure can fail a stage; any success for the
   same stage (TCP, a DNS reply through that hop, a poll fact, an indirect
   success) keeps it from FAILED. ICMP-only failure is DEGRADED with reason
   ``icmp_unanswered``.
3. The internet stage FAILS only when at least two distinct reference
   targets all fail hard in the same round. One failing target among working
   ones is HEALTHY with reason ``single_external_service``; a single
   configured target failing is DEGRADED at most.
4. Probes taken at another router are excluded. A probe taken at Home
   Assistant is indirect evidence for a router's chain only when its
   ``subject`` is that router; Home Assistant probes without a subject
   belong to the Home Assistant chain only. Indirect evidence is used only
   when no direct evidence exists for that stage, caps it at DEGRADED, never
   yields a CONFIRMED cause and never counts as coverage.
5. Below a FAILED stage, probe failures are masked (stage UNKNOWN unless
   other evidence remains); a downstream stage measured HEALTHY directly is
   reported as a ``Contradiction``.
6. IPv4 and IPv6 are evaluated separately; a family configured as absent is
   NOT_APPLICABLE and does not count for coverage.

The caller passes one measurement round: every ``ProbeResult`` handed in is
treated as the same round, and every distinct target id at the internet
stage as an independent, user-confirmed reference target.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace

from .diag_model import (
    FACT_DEFAULT_ROUTE,
    FACT_DNS_SERVERS,
    FACT_INTERFACE,
    FACT_MANAGEMENT,
    FACT_NEXT_HOP,
    FACT_WAN_UP,
    SEVERITY_RANK,
    STAGE_ORDER,
    UNUSABLE_OUTCOMES,
    AddressFamily,
    Basis,
    CauseClass,
    ChainResult,
    ChangeRecord,
    Classification,
    Contradiction,
    Evidence,
    Finding,
    MeasurementPoint,
    PointKind,
    ProbeKind,
    ProbeOutcome,
    ProbeResult,
    Severity,
    Stage,
    StageProblem,
    StageResult,
    StageState,
    weaker_class,
)

_LOGGER = logging.getLogger(__name__)

# A resolver that answered SERVFAIL/REFUSED or timed out while the path to it
# was measured healthy is a confirmed DNS fault (rule 7).
CONFIRMING_DNS_OUTCOMES = frozenset(
    {ProbeOutcome.SERVFAIL, ProbeOutcome.TIMEOUT, ProbeOutcome.REFUSED}
)
# A refused TCP/HTTP connect proves the host is up only for local hops; beyond
# the gateway a firewall REJECT answers the same way.
_LOCAL_STAGES = frozenset({Stage.ROUTER, Stage.GATEWAY})

R_NO_EVIDENCE = "no_usable_evidence"
R_ICMP = "icmp_unanswered"
R_MIXED = "mixed_evidence"
R_INDIRECT_ONLY = "indirect_evidence_only"
R_INDIRECT_CONTRADICTS = "indirect_evidence_contradicts"
R_SINGLE_SERVICE = "single_external_service"
R_SEVERAL_SERVICES = "several_external_services"
R_ONE_TARGET = "only_one_reference_target"
R_ONE_HARD = "one_hard_failure_only"
R_ALL_TARGETS = "all_reference_targets_failed"
R_NOT_CONFIGURED = "family_not_configured"
R_UPSTREAM = "upstream_failed"
R_CONTRADICTED = "contradicted_by_downstream"

_RECOMMENDATION = {
    Classification.NO_FAULT_DETECTED: "none",
    Classification.INSUFFICIENT_DATA: "enable_more_measurements",
    Classification.PARTIALLY_MEASURED: "enable_more_measurements",
    Classification.ROUTER_OFFLINE: "check_router_power_and_uplink",
    Classification.MANAGEMENT_UNREACHABLE: "check_rpcd_and_uhttpd",
    Classification.LAN_PROBLEM: "check_lan_interface_and_cabling",
    Classification.GATEWAY_PROBLEM: "check_gateway_and_uplink",
    Classification.ROUTING_PROBLEM: "check_default_route",
    Classification.WAN_PROBLEM: "check_wan_connection_and_provider",
    Classification.DNS_PROBLEM: "check_dns_resolver_and_upstream_dns",
    Classification.SINGLE_EXTERNAL_SERVICE_UNREACHABLE: "check_reference_target",
    Classification.IPV4_ONLY_DISTURBANCE: "check_ipv4_configuration",
    Classification.IPV6_ONLY_DISTURBANCE: "check_ipv6_configuration",
    Classification.POSSIBLE_FIREWALL_RESTRICTION: "check_firewall_icmp_rules",
    Classification.ICMP_UNANSWERED: "add_tcp_or_dns_check",
    Classification.GATEWAY_CHANGED: "review_gateway_change",
    Classification.DNS_SERVER_CHANGED: "review_dns_server_change",
}
_SUMMARY = {Classification.DNS_PROBLEM: "internet_access_restricted"}


def summary_key(classification: Classification) -> str:
    """Summary text key for a classification."""
    return _SUMMARY.get(classification, classification.value)


@dataclass(frozen=True)
class ChainFacts:
    """Facts from the measured router's own poll; None = not known."""

    management_reachable: bool | None = None
    interface_up: bool | None = None
    default_route_v4: bool | None = None
    default_route_v6: bool | None = None
    wan_up_v4: bool | None = None
    wan_up_v6: bool | None = None
    ipv4_configured: bool | None = None
    ipv6_configured: bool | None = None

    def configured(self, family: AddressFamily) -> bool | None:
        if family == AddressFamily.IPV4:
            return self.ipv4_configured
        return self.ipv6_configured

    def default_route(self, family: AddressFamily) -> bool | None:
        if family == AddressFamily.IPV4:
            return self.default_route_v4
        return self.default_route_v6

    def wan_up(self, family: AddressFamily) -> bool | None:
        if family == AddressFamily.IPV4:
            return self.wan_up_v4
        return self.wan_up_v6


@dataclass(frozen=True)
class _Verdict:
    state: StageState
    basis: Basis
    reasons: tuple[str, ...] = ()
    failed_targets: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Problem:
    classification: Classification
    severity: Severity
    stage: Stage
    family: AddressFamily
    cause_class: CauseClass
    evidence: tuple[Evidence, ...]
    reasons: tuple[str, ...] = ()


# --- evidence -------------------------------------------------------------------


def _reaches(kind: ProbeKind, outcome: ProbeOutcome, stage: Stage) -> bool | None:
    """Does this result show that the probed host answered at IP level?"""
    if outcome in UNUSABLE_OUTCOMES:
        return None
    if outcome == ProbeOutcome.OK:
        return True
    if outcome in (ProbeOutcome.TIMEOUT, ProbeOutcome.FAILED):
        return False
    if kind == ProbeKind.DNS:
        return True  # NXDOMAIN / SERVFAIL / REFUSED are replies
    if kind in (ProbeKind.TCP, ProbeKind.HTTP) and stage in _LOCAL_STAGES:
        return True  # connection refused: the host itself answered
    return None


def _verdict(probe: ProbeResult) -> bool | None:
    if probe.stage == Stage.DNS:
        if probe.kind != ProbeKind.DNS or probe.outcome in UNUSABLE_OUTCOMES:
            return None
        return probe.outcome == ProbeOutcome.OK
    return _reaches(probe.kind, probe.outcome, probe.stage)


def _probe_evidence(point: MeasurementPoint, probe: ProbeResult) -> list[Evidence]:
    base = {
        "family": probe.family,
        "point": probe.point,
        "kind": probe.kind,
        "outcome": probe.outcome,
        "direct": probe.point == point,
        "target_id": probe.target_id,
        "via": probe.via,
        "timestamp": probe.timestamp,
    }
    items = [Evidence(stage=probe.stage, ok=_verdict(probe), **base)]
    for stage in sorted(probe.via - {probe.stage}, key=STAGE_ORDER.index):
        if _reaches(probe.kind, probe.outcome, stage):
            items.append(
                Evidence(stage=stage, ok=True, derived_from=probe.stage, **base)
            )
    return items


def _fact(
    point: MeasurementPoint,
    stage: Stage,
    name: str,
    value: bool | None,
    family: AddressFamily | None = None,
) -> list[Evidence]:
    if value is None:
        return []
    outcome = ProbeOutcome.OK if value else ProbeOutcome.FAILED
    return [
        Evidence(
            stage=stage,
            family=family,
            point=point,
            kind=ProbeKind.FACT,
            outcome=outcome,
            ok=bool(value),
            direct=True,
            fact=name,
        )
    ]


def _fact_evidence(point: MeasurementPoint, facts: ChainFacts) -> list[Evidence]:
    items = _fact(point, Stage.ROUTER, FACT_MANAGEMENT, facts.management_reachable)
    items += _fact(point, Stage.ROUTER, FACT_INTERFACE, facts.interface_up)
    for family in AddressFamily:
        items += _fact(point, Stage.WAN, FACT_WAN_UP, facts.wan_up(family), family)
        items += _fact(
            point, Stage.WAN, FACT_DEFAULT_ROUTE, facts.default_route(family), family
        )
    return items


def _about(point: MeasurementPoint, probe: ProbeResult) -> bool:
    """Is ``probe`` about the chain of ``point``? A router uses its own probes
    and Home Assistant probes naming it as subject; Home Assistant uses its
    own probes without a subject."""
    if probe.point.kind == PointKind.HA:
        return probe.subject == point.key
    return probe.point == point


def _split(
    point: MeasurementPoint, probes: Iterable[ProbeResult]
) -> tuple[list[ProbeResult], list[ProbeResult]]:
    used: list[ProbeResult] = []
    excluded: list[ProbeResult] = []
    for probe in probes:
        (used if _about(point, probe) else excluded).append(probe)
    return used, excluded


# --- stage verdicts -------------------------------------------------------------


def _ids(items: Iterable[Evidence]) -> tuple[str, ...]:
    return tuple(sorted({e.target_id for e in items if e.target_id}))


def _pool(items: Sequence[Evidence]) -> tuple[list[Evidence], list[Evidence], Basis]:
    usable = [e for e in items if e.ok is not None]
    direct = [e for e in usable if e.direct]
    basis = Basis.DIRECT if direct else Basis.INDIRECT
    return usable, direct or usable, basis


def _without_success(
    usable: list[Evidence], hard: bool, basis: Basis, reason: str
) -> tuple[StageState, str]:
    """State when the pool holds failures only."""
    if not hard:
        return StageState.DEGRADED, R_ICMP
    if basis == Basis.INDIRECT:
        return StageState.DEGRADED, R_INDIRECT_ONLY
    if any(e.ok for e in usable):
        return StageState.DEGRADED, R_INDIRECT_CONTRADICTS
    return StageState.FAILED, reason


def _judge(items: Sequence[Evidence]) -> _Verdict:
    usable, pool, basis = _pool(items)
    if not usable:
        return _Verdict(StageState.UNKNOWN, Basis.NONE, (R_NO_EVIDENCE,))
    fails = [e for e in pool if not e.ok]
    targets = _ids(fails)
    if not fails:
        return _Verdict(StageState.HEALTHY, basis)
    if any(e.ok for e in pool):
        if not any(e.hard for e in fails):
            return _Verdict(StageState.HEALTHY, basis, (R_ICMP,), targets)
        return _Verdict(StageState.DEGRADED, basis, (R_MIXED,), targets)
    hard = any(e.hard for e in fails)
    state, reason = _without_success(usable, hard, basis, R_MIXED)
    reasons = () if state == StageState.FAILED else (reason,)
    return _Verdict(state, basis, reasons, targets)


def _judge_internet(items: Sequence[Evidence]) -> _Verdict:
    usable, pool, basis = _pool(items)
    if not usable:
        return _Verdict(StageState.UNKNOWN, Basis.NONE, (R_NO_EVIDENCE,))
    groups: dict[str, list[Evidence]] = {}
    for item in pool:
        groups.setdefault(item.target_id or item.fact or "", []).append(item)
    ok = [k for k, g in groups.items() if any(e.ok for e in g)]
    hard = sorted(
        k for k, g in groups.items() if k not in ok and any(e.hard for e in g)
    )
    icmp = sorted(k for k in groups if k not in ok and k not in hard)
    failed = tuple(sorted(hard + icmp))
    notes = (R_ICMP,) if icmp else ()
    if ok:
        if not hard:
            return _Verdict(StageState.HEALTHY, basis, notes, failed)
        if len(hard) == 1:
            return _Verdict(
                StageState.HEALTHY, basis, (*notes, R_SINGLE_SERVICE), failed
            )
        return _Verdict(
            StageState.DEGRADED, basis, (*notes, R_SEVERAL_SERVICES), failed
        )
    if len(hard) == 1:
        reason = R_ONE_TARGET if len(groups) == 1 else R_ONE_HARD
        return _Verdict(StageState.DEGRADED, basis, (reason,), failed)
    state, reason = _without_success(usable, bool(hard), basis, R_ALL_TARGETS)
    return _Verdict(state, basis, (reason,), failed)


def _evaluate_family(
    family: AddressFamily, items: Sequence[Evidence], configured: bool | None
) -> list[StageResult]:
    results: list[StageResult] = []
    failed_upstream: Stage | None = None
    for stage in STAGE_ORDER:
        mine = [e for e in items if e.stage == stage and e.family in (None, family)]
        if configured is False:
            results.append(
                StageResult(
                    stage,
                    family,
                    StageState.NOT_APPLICABLE,
                    Basis.NONE,
                    tuple(mine),
                    reasons=(R_NOT_CONFIGURED,),
                )
            )
            continue
        masked: list[Evidence] = []
        if failed_upstream is not None:
            masked = [e for e in mine if e.kind != ProbeKind.FACT and e.ok is False]
            mine = [e for e in mine if not (e.kind != ProbeKind.FACT and e.ok is False)]
        judge = _judge_internet if stage == Stage.INTERNET else _judge
        verdict = judge(mine)
        reasons = verdict.reasons
        if masked:
            reasons = (*reasons, f"{R_UPSTREAM}:{failed_upstream}")
        results.append(
            StageResult(
                stage,
                family,
                verdict.state,
                verdict.basis,
                tuple(mine),
                tuple(masked),
                reasons,
                verdict.failed_targets,
            )
        )
        if verdict.state == StageState.FAILED and failed_upstream is None:
            failed_upstream = stage
    return results


def _contradictions(stages: Sequence[StageResult]) -> list[Contradiction]:
    found: list[Contradiction] = []
    for index, upstream in enumerate(stages):
        if upstream.state != StageState.FAILED:
            continue
        for downstream in stages[index + 1 :]:
            if _healthy_direct(downstream):
                found.append(
                    Contradiction(
                        upstream.family,
                        upstream.stage,
                        downstream.stage,
                        "downstream_healthy_while_upstream_failed",
                    )
                )
    return found


def _healthy_direct(stage: StageResult) -> bool:
    return stage.state == StageState.HEALTHY and stage.basis == Basis.DIRECT


def evaluate_chain(
    point: MeasurementPoint,
    probes: Iterable[ProbeResult] = (),
    facts: ChainFacts | None = None,
) -> ChainResult:
    """Evaluate the chain for ``point`` from one round of probes and facts."""
    facts = facts if facts is not None else ChainFacts()
    used, excluded = _split(point, probes)
    items = _fact_evidence(point, facts)
    for probe in used:
        items.extend(_probe_evidence(point, probe))
    stages: list[StageResult] = []
    contradictions: list[Contradiction] = []
    for family in AddressFamily:
        evaluated = _evaluate_family(family, items, facts.configured(family))
        stages.extend(evaluated)
        contradictions.extend(_contradictions(evaluated))
    chain = ChainResult(point, tuple(stages), tuple(contradictions), tuple(excluded))
    _LOGGER.debug(
        "diag chain %s: coverage %.2f, %d excluded probe(s), %d contradiction(s)",
        point.label,
        chain.coverage,
        len(excluded),
        len(contradictions),
    )
    return chain


# --- classification ---------------------------------------------------------------


def dns_failure_confirmed(
    chain: ChainResult, family: AddressFamily, target_id: str | None = None
) -> bool:
    """True if a resolver (optionally ``target_id``) answered SERVFAIL/REFUSED
    or timed out, measured directly, while every hop on its declared path
    (``via``) was measured healthy directly."""
    for item in chain.stage(Stage.DNS, family).evidence:
        if not (
            item.direct
            and item.kind == ProbeKind.DNS
            and item.ok is False
            and item.outcome in CONFIRMING_DNS_OUTCOMES
            and item.via
        ):
            continue
        if target_id is not None and item.target_id != target_id:
            continue
        if all(_healthy_direct(chain.stage(s, family)) for s in item.via):
            return True
    return False


def _failed_facts(stage: StageResult) -> set[str]:
    return {
        e.fact
        for e in stage.evidence
        if e.kind == ProbeKind.FACT and e.ok is False and e.direct and e.fact
    }


def _codes(stage: StageResult) -> set[str]:
    return {r for r in stage.reasons if not r.startswith(R_UPSTREAM)}


def _by_state(
    failed: bool,
    on_fail: tuple[Severity, CauseClass],
    on_degrade: tuple[Severity, CauseClass],
) -> tuple[Severity, CauseClass]:
    return on_fail if failed else on_degrade


def _router_kind(stage: StageResult) -> tuple[Classification, Severity, CauseClass]:
    failed = stage.state == StageState.FAILED
    facts = _failed_facts(stage)
    if FACT_MANAGEMENT in facts:
        if failed:
            return Classification.ROUTER_OFFLINE, Severity.CRITICAL, CauseClass.PROBABLE
        return (
            Classification.MANAGEMENT_UNREACHABLE,
            Severity.WARNING,
            CauseClass.PROBABLE,
        )
    if FACT_INTERFACE in facts:
        severity = Severity.CRITICAL if failed else Severity.WARNING
        return Classification.LAN_PROBLEM, severity, CauseClass.CONFIRMED
    severity, cause = _by_state(
        failed,
        (Severity.CRITICAL, CauseClass.PROBABLE),
        (Severity.WARNING, CauseClass.POSSIBLE),
    )
    return Classification.ROUTER_OFFLINE, severity, cause


def _wan_kind(stage: StageResult) -> tuple[Classification, Severity, CauseClass]:
    failed = stage.state == StageState.FAILED
    facts = _failed_facts(stage)
    if FACT_WAN_UP in facts or FACT_DEFAULT_ROUTE in facts:
        kind = (
            Classification.WAN_PROBLEM
            if FACT_WAN_UP in facts
            else Classification.ROUTING_PROBLEM
        )
        severity, cause = _by_state(
            failed,
            (Severity.CRITICAL, CauseClass.CONFIRMED),
            (Severity.WARNING, CauseClass.PROBABLE),
        )
        return kind, severity, cause
    severity, cause = _by_state(
        failed,
        (Severity.CRITICAL, CauseClass.PROBABLE),
        (Severity.WARNING, CauseClass.POSSIBLE),
    )
    return Classification.WAN_PROBLEM, severity, cause


def _internet_kind(stage: StageResult) -> tuple[Classification, Severity, CauseClass]:
    if stage.state == StageState.FAILED:
        return Classification.WAN_PROBLEM, Severity.CRITICAL, CauseClass.PROBABLE
    if R_ONE_TARGET in stage.reasons:
        return (
            Classification.SINGLE_EXTERNAL_SERVICE_UNREACHABLE,
            Severity.WARNING,
            CauseClass.POSSIBLE,
        )
    return Classification.WAN_PROBLEM, Severity.WARNING, CauseClass.POSSIBLE


def _dns_kind(
    chain: ChainResult, stage: StageResult
) -> tuple[Classification, Severity, CauseClass]:
    severity = Severity.WARNING if stage.state == StageState.FAILED else Severity.INFO
    if dns_failure_confirmed(chain, stage.family):
        cause = CauseClass.CONFIRMED
    elif _healthy_direct(chain.stage(Stage.INTERNET, stage.family)):
        cause = CauseClass.PROBABLE
    else:
        cause = CauseClass.POSSIBLE
    return Classification.DNS_PROBLEM, severity, cause


def _stage_kind(
    chain: ChainResult, stage: StageResult
) -> tuple[Classification, Severity, CauseClass]:
    if stage.stage == Stage.ROUTER:
        return _router_kind(stage)
    if stage.stage == Stage.GATEWAY:
        severity, cause = _by_state(
            stage.state == StageState.FAILED,
            (Severity.CRITICAL, CauseClass.PROBABLE),
            (Severity.WARNING, CauseClass.POSSIBLE),
        )
        return Classification.GATEWAY_PROBLEM, severity, cause
    if stage.stage == Stage.WAN:
        return _wan_kind(stage)
    if stage.stage == Stage.INTERNET:
        return _internet_kind(stage)
    return _dns_kind(chain, stage)


def _note(stage: StageResult) -> tuple[Classification, Severity, CauseClass] | None:
    """Informational notes on a HEALTHY stage."""
    if R_SINGLE_SERVICE in stage.reasons:
        return (
            Classification.SINGLE_EXTERNAL_SERVICE_UNREACHABLE,
            Severity.INFO,
            CauseClass.PROBABLE,
        )
    if R_ICMP in stage.reasons:
        return (
            Classification.POSSIBLE_FIREWALL_RESTRICTION,
            Severity.INFO,
            CauseClass.POSSIBLE,
        )
    return None


def _stage_problem(
    chain: ChainResult, stage: StageResult, downstream: Sequence[StageResult]
) -> _Problem | None:
    if stage.state == StageState.HEALTHY:
        kind = _note(stage)
    elif stage.state in (StageState.DEGRADED, StageState.FAILED):
        if stage.state == StageState.DEGRADED and _codes(stage) == {R_ICMP}:
            fine = any(_healthy_direct(d) for d in downstream)
            kind = (
                Classification.POSSIBLE_FIREWALL_RESTRICTION
                if fine
                else Classification.ICMP_UNANSWERED,
                Severity.INFO,
                CauseClass.POSSIBLE,
            )
        else:
            kind = _stage_kind(chain, stage)
    else:
        kind = None
    if kind is None:
        return None
    classification, severity, cause = kind
    reasons: tuple[str, ...] = tuple(_codes(stage))
    if stage.basis == Basis.INDIRECT:
        cause = weaker_class(cause, CauseClass.PROBABLE)
    if any(
        c.upstream == stage.stage and c.family == stage.family
        for c in chain.contradictions
    ):
        cause = weaker_class(cause, CauseClass.POSSIBLE)
        reasons = (*reasons, R_CONTRADICTED)
    return _Problem(
        classification,
        severity,
        stage.stage,
        stage.family,
        cause,
        stage.evidence,
        tuple(sorted(reasons)),
    )


def _family_problems(chain: ChainResult, family: AddressFamily) -> list[_Problem]:
    stages = [chain.stage(s, family) for s in STAGE_ORDER]
    problems: list[_Problem] = []
    for index, stage in enumerate(stages):
        problem = _stage_problem(chain, stage, stages[index + 1 :])
        if problem is not None:
            problems.append(problem)
    return problems


def _rank(problem: _Problem) -> tuple[int, int]:
    return (-SEVERITY_RANK[problem.severity], STAGE_ORDER.index(problem.stage))


def _key(problem: _Problem) -> tuple[Stage, AddressFamily]:
    return problem.stage, problem.family


def _serious(problem: _Problem) -> bool:
    return SEVERITY_RANK[problem.severity] >= SEVERITY_RANK[Severity.WARNING]


def _primary(problems: Sequence[_Problem]) -> _Problem:
    """Main problem of one family (``problems`` in stage order): the most
    upstream one at warning level or above - later stages depend on it -
    carrying the family's worst severity. Notes only: the most severe one."""
    serious = [p for p in problems if _serious(p)]
    if not serious:
        return min(problems, key=_rank)
    worst = max((p.severity for p in serious), key=SEVERITY_RANK.__getitem__)
    return replace(serious[0], severity=worst)


def _stage_problems(problems: Iterable[_Problem]) -> tuple[StageProblem, ...]:
    return tuple(
        StageProblem(p.stage, p.family, p.classification, p.severity, p.cause_class)
        for p in problems
    )


def _also(problems: Iterable[_Problem], chosen: _Problem) -> tuple[str, ...]:
    out = []
    for p in problems:
        prefix = "also:" if p.family == chosen.family else f"also:{p.family}:"
        out.append(f"{prefix}{p.stage}:{p.classification}")
    return tuple(out)


def _finding(
    chain: ChainResult,
    problem: _Problem,
    family: AddressFamily | None,
    *,
    others: Iterable[_Problem] = (),
    only: bool = False,
    extra: tuple[Evidence, ...] = (),
) -> Finding:
    classification = problem.classification
    underlying = None
    if only:
        underlying = classification
        classification = (
            Classification.IPV4_ONLY_DISTURBANCE
            if family == AddressFamily.IPV4
            else Classification.IPV6_ONLY_DISTURBANCE
        )
    return Finding(
        point=chain.point,
        classification=classification,
        severity=problem.severity,
        summary_key=summary_key(classification),
        recommendation_key=_RECOMMENDATION[classification],
        cause_class=problem.cause_class,
        cause_stage=problem.stage,
        family=family,
        underlying=underlying,
        evidence=tuple(dict.fromkeys((*problem.evidence, *extra))),
        reasons=(*problem.reasons, *_also(others, problem)),
        contradictions=chain.contradictions,
        also=_stage_problems(others),
        unmeasured=chain.unmeasured(),
        chain=chain,
    )


def _no_problem(chain: ChainResult) -> Finding:
    unmeasured = chain.unmeasured()
    if chain.coverage == 0.0:
        classification, severity = Classification.INSUFFICIENT_DATA, Severity.INFO
    elif unmeasured:
        classification, severity = Classification.PARTIALLY_MEASURED, Severity.INFO
    else:
        classification, severity = Classification.NO_FAULT_DETECTED, Severity.OK
    return Finding(
        point=chain.point,
        classification=classification,
        severity=severity,
        summary_key=classification.value,
        recommendation_key=_RECOMMENDATION[classification],
        cause_class=CauseClass.UNKNOWN,
        contradictions=chain.contradictions,
        unmeasured=unmeasured,
        chain=chain,
    )


def classify(chain: ChainResult) -> Finding:
    """Classify a chain into one finding: per family the most upstream
    serious problem, across families the most severe, most upstream one.
    Every other stage problem is kept in ``also`` (and in ``reasons`` as
    ``also:...``)."""
    by_family = [
        problems
        for family in chain.families
        if (problems := _family_problems(chain, family))
    ]
    finding = _pick(chain, by_family) if by_family else _no_problem(chain)
    _LOGGER.debug(
        "diag classify %s: %s (%s)",
        chain.point.label,
        finding.classification,
        finding.cause_class,
    )
    return finding


def _pick(chain: ChainResult, by_family: list[list[_Problem]]) -> Finding:
    heads = [_primary(problems) for problems in by_family]
    chosen = min(heads, key=_rank)
    problems = [p for problems in by_family for p in problems]
    twin = next(
        (
            h
            for h in heads
            if h.family != chosen.family
            and (h.stage, h.classification) == (chosen.stage, chosen.classification)
        ),
        None,
    )
    if twin is not None:
        merged = _Problem(
            chosen.classification,
            max(chosen.severity, twin.severity, key=SEVERITY_RANK.__getitem__),
            chosen.stage,
            chosen.family,
            weaker_class(chosen.cause_class, twin.cause_class),
            tuple(dict.fromkeys((*chosen.evidence, *twin.evidence))),
            tuple(sorted({*chosen.reasons, *twin.reasons})),
        )
        used = {_key(chosen), _key(twin)}
        rest = [p for p in problems if _key(p) not in used]
        return _finding(chain, merged, None, others=rest)
    others = [p for p in problems if _key(p) != _key(chosen)]
    other = next((f for f in chain.families if f != chosen.family), None)
    if other is not None and _only_in_family(chain, chosen, other, others):
        same = chain.stage(chosen.stage, other)
        return _finding(
            chain, chosen, chosen.family, others=others, only=True, extra=same.evidence
        )
    return _finding(chain, chosen, chosen.family, others=others)


def _only_in_family(
    chain: ChainResult,
    chosen: _Problem,
    other: AddressFamily,
    others: Iterable[_Problem],
) -> bool:
    """The other family is measured healthy where this one breaks and has no
    problem of its own at warning level or above."""
    if not _serious(chosen):
        return False
    if chain.stage(chosen.stage, other).state != StageState.HEALTHY:
        return False
    return not any(p.family == other and _serious(p) for p in others)


# --- change findings ----------------------------------------------------------------


def _change(
    point: MeasurementPoint,
    classification: Classification,
    stage: Stage,
    fact: str,
    previous: object,
    current: object,
    family: AddressFamily | None,
) -> Finding | None:
    if previous is None or current is None or previous == current:
        return None
    evidence = Evidence(
        stage=stage,
        family=family,
        point=point,
        kind=ProbeKind.FACT,
        outcome=ProbeOutcome.OK,
        ok=None,
        direct=True,
        fact=fact,
    )
    _LOGGER.debug("diag change at %s: %s", point.label, classification)
    return Finding(
        point=point,
        classification=classification,
        severity=Severity.INFO,
        summary_key=classification.value,
        recommendation_key=_RECOMMENDATION[classification],
        cause_class=CauseClass.CONFIRMED,
        cause_stage=stage,
        family=family,
        evidence=(evidence,),
        reasons=("observed_in_poll",),
        change=ChangeRecord(previous, current),
    )


def gateway_change(
    point: MeasurementPoint,
    previous: str | None,
    current: str | None,
    *,
    family: AddressFamily | None = None,
) -> Finding | None:
    """Finding when the router's next hop changed; None if either is unknown."""
    return _change(
        point,
        Classification.GATEWAY_CHANGED,
        Stage.GATEWAY,
        FACT_NEXT_HOP,
        previous,
        current,
        family,
    )


def _server_set(servers: Iterable[str] | None) -> tuple[str, ...] | None:
    if isinstance(servers, str):
        # a bare string would be compared character by character
        raise TypeError("DNS servers must be a collection of ids, not a string")
    return None if servers is None else tuple(sorted(set(servers)))


def dns_server_change(
    point: MeasurementPoint,
    previous: Iterable[str] | None,
    current: Iterable[str] | None,
    *,
    family: AddressFamily | None = None,
) -> Finding | None:
    """Finding when the set of DNS servers changed (order is ignored); None
    if either side is unknown."""
    return _change(
        point,
        Classification.DNS_SERVER_CHANGED,
        Stage.DNS,
        FACT_DNS_SERVERS,
        _server_set(previous),
        _server_set(current),
        family,
    )
