"""Tests for diag_chain.py / diag_model.py: chain evaluation and classification.

Pure logic: no network I/O, no Home Assistant instance. The autouse fixture
below makes any socket use fail loudly.
"""

from __future__ import annotations

import ast
import json
import logging
import socket
from pathlib import Path
from typing import Any

import pytest

from custom_components.openwrt_router.diag_chain import (
    ChainFacts,
    classify,
    dns_failure_confirmed,
    dns_server_change,
    evaluate_chain,
    gateway_change,
)
from custom_components.openwrt_router.diag_model import (
    AddressFamily,
    Basis,
    CauseClass,
    Classification,
    MeasurementPoint,
    ProbeKind,
    ProbeOutcome,
    ProbeResult,
    Severity,
    Stage,
    StageState,
)

PKG = Path(__file__).resolve().parent.parent / "custom_components" / "openwrt_router"

V4 = AddressFamily.IPV4
V6 = AddressFamily.IPV6
OK = ProbeOutcome.OK
TIMEOUT = ProbeOutcome.TIMEOUT
FAILED = ProbeOutcome.FAILED
ICMP = ProbeKind.ICMP
TCP = ProbeKind.TCP
DNS = ProbeKind.DNS
AP = MeasurementPoint.router("ap1")
GW = MeasurementPoint.router("gw")
HA = MeasurementPoint.ha()
V4_ONLY = {"ipv4_configured": True, "ipv6_configured": False}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("network I/O attempted")

    for name in ("getaddrinfo", "gethostbyname", "create_connection"):
        monkeypatch.setattr(socket, name, _boom)


def probe(
    stage: Stage,
    outcome: ProbeOutcome = OK,
    kind: ProbeKind = TCP,
    target: str = "t",
    family: AddressFamily | None = V4,
    point: MeasurementPoint = AP,
    **kw: Any,
) -> ProbeResult:
    return ProbeResult(
        point=point,
        target_id=target,
        kind=kind,
        stage=stage,
        family=family,
        outcome=outcome,
        timestamp=kw.pop("timestamp", 1000.0),
        **kw,
    )


def facts(**kw: Any) -> ChainFacts:
    base: dict[str, Any] = {"management_reachable": True, **V4_ONLY}
    base.update(kw)
    return ChainFacts(**base)


def ext(outcome: ProbeOutcome, *targets: str, **kw: Any) -> list[ProbeResult]:
    kind = kw.pop("kind", TCP)
    return [probe(Stage.INTERNET, outcome, kind, t, **kw) for t in targets]


def state(chain: Any, stage: Stage, family: AddressFamily = V4) -> StageState:
    return chain.stage(stage, family).state


# --- customer acceptance cases -----------------------------------------------


def test_case_01_gateway_reachable() -> None:
    chain = evaluate_chain(
        AP,
        [
            probe(Stage.GATEWAY, OK, ICMP, "gw"),
            probe(Stage.GATEWAY, OK, TCP, "gw-tcp"),
            *ext(OK, "ext-a", "ext-b"),
            probe(Stage.DNS, OK, DNS, "dns-gw"),
        ],
        facts(),
    )
    assert state(chain, Stage.GATEWAY) is StageState.HEALTHY
    assert chain.stage(Stage.GATEWAY, V4).basis is Basis.DIRECT
    finding = classify(chain)
    assert finding.classification is Classification.NO_FAULT_DETECTED
    assert finding.severity is Severity.OK
    assert not finding.is_problem


def test_case_02_gateway_failure() -> None:
    chain = evaluate_chain(
        AP,
        [
            probe(Stage.GATEWAY, TIMEOUT, ICMP, "gw"),
            probe(Stage.GATEWAY, TIMEOUT, TCP, "gw-tcp"),
            *ext(TIMEOUT, "ext-a", "ext-b"),
            probe(Stage.DNS, TIMEOUT, DNS, "dns-gw"),
        ],
        facts(),
    )
    assert state(chain, Stage.GATEWAY) is StageState.FAILED
    # rule 5: downstream failures that depend on the gateway are not guessed
    assert state(chain, Stage.INTERNET) is StageState.UNKNOWN
    assert state(chain, Stage.DNS) is StageState.UNKNOWN
    assert chain.stage(Stage.INTERNET, V4).masked
    finding = classify(chain)
    assert finding.classification is Classification.GATEWAY_PROBLEM
    assert finding.severity is Severity.CRITICAL
    assert finding.cause_stage is Stage.GATEWAY
    assert finding.cause_class is CauseClass.PROBABLE
    assert {e.target_id for e in finding.evidence} == {"gw", "gw-tcp"}


def test_case_03_dns_failure_with_working_ip_connectivity() -> None:
    chain = evaluate_chain(
        AP,
        [
            probe(Stage.GATEWAY, OK, ICMP, "gw"),
            *ext(OK, "ext-a", "ext-b", kind=ICMP),
            probe(Stage.DNS, TIMEOUT, DNS, "dns-gw"),
        ],
        facts(),
    )
    assert state(chain, Stage.GATEWAY) is StageState.HEALTHY
    assert state(chain, Stage.INTERNET) is StageState.HEALTHY
    assert state(chain, Stage.DNS) is StageState.FAILED
    finding = classify(chain)
    assert finding.classification is Classification.DNS_PROBLEM
    assert finding.severity is Severity.WARNING
    assert finding.summary_key == "internet_access_restricted"
    assert finding.recommendation_key == "check_dns_resolver_and_upstream_dns"
    assert finding.cause_stage is Stage.DNS
    assert finding.cause_class is CauseClass.PROBABLE
    assert [e.target_id for e in finding.evidence] == ["dns-gw"]


def test_case_04_wan_failure() -> None:
    chain = evaluate_chain(
        GW,
        [*ext(TIMEOUT, "ext-a", "ext-b", point=GW)],
        facts(wan_up_v4=False, default_route_v4=False),
    )
    assert state(chain, Stage.WAN) is StageState.FAILED
    assert state(chain, Stage.INTERNET) is StageState.UNKNOWN
    finding = classify(chain)
    assert finding.classification is Classification.WAN_PROBLEM
    assert finding.severity is Severity.CRITICAL
    # the gateway's own poll shows its WAN down: measured at the location
    assert finding.cause_class is CauseClass.CONFIRMED
    assert any(e.fact == "wan_up" and e.ok is False for e in finding.evidence)


def _dual_stack(v4: ProbeOutcome, v6: ProbeOutcome) -> Any:
    return evaluate_chain(
        AP,
        [
            probe(Stage.GATEWAY, OK, TCP, "gw4"),
            probe(Stage.GATEWAY, OK, TCP, "gw6", family=V6),
            *ext(v4, "ext-a4", "ext-b4"),
            *ext(v6, "ext-a6", "ext-b6", family=V6),
        ],
        facts(ipv6_configured=True),
    )


def test_case_05_ipv4_failure() -> None:
    chain = _dual_stack(TIMEOUT, OK)
    assert state(chain, Stage.INTERNET, V4) is StageState.FAILED
    assert state(chain, Stage.INTERNET, V6) is StageState.HEALTHY
    finding = classify(chain)
    assert finding.classification is Classification.IPV4_ONLY_DISTURBANCE
    assert finding.family is V4
    assert finding.underlying is Classification.WAN_PROBLEM
    assert finding.cause_stage is Stage.INTERNET


def test_case_06_ipv6_failure() -> None:
    chain = _dual_stack(OK, TIMEOUT)
    assert state(chain, Stage.INTERNET, V6) is StageState.FAILED
    assert state(chain, Stage.INTERNET, V4) is StageState.HEALTHY
    finding = classify(chain)
    assert finding.classification is Classification.IPV6_ONLY_DISTURBANCE
    assert finding.family is V6


def test_case_16_false_positive_icmp_failure() -> None:
    # ICMP to the gateway unanswered, but TCP to it works: not an outage
    chain = evaluate_chain(
        AP,
        [
            probe(Stage.GATEWAY, TIMEOUT, ICMP, "gw"),
            probe(Stage.GATEWAY, OK, TCP, "gw-tcp"),
            *ext(OK, "ext-a", "ext-b"),
        ],
        facts(),
    )
    gateway = chain.stage(Stage.GATEWAY, V4)
    assert gateway.state is not StageState.FAILED
    assert "icmp_unanswered" in gateway.reasons
    finding = classify(chain)
    assert finding.classification is Classification.POSSIBLE_FIREWALL_RESTRICTION
    assert finding.severity is Severity.INFO
    assert finding.cause_class is CauseClass.POSSIBLE

    # ICMP-only failure with no other evidence: at most degraded, reason kept
    only_icmp = evaluate_chain(AP, [probe(Stage.GATEWAY, TIMEOUT, ICMP)], facts())
    stage = only_icmp.stage(Stage.GATEWAY, V4)
    assert stage.state is StageState.DEGRADED
    assert "icmp_unanswered" in stage.reasons
    assert classify(only_icmp).classification is Classification.ICMP_UNANSWERED


def test_case_17_missing_measurements_are_unknown() -> None:
    chain = evaluate_chain(AP, [], ChainFacts(ipv6_configured=False))
    assert all(s.state is StageState.UNKNOWN for s in chain.stages if s.family is V4)
    assert chain.coverage == 0.0
    assert classify(chain).classification is Classification.INSUFFICIENT_DATA

    partial = evaluate_chain(AP, [probe(Stage.GATEWAY)], facts())
    assert state(partial, Stage.ROUTER) is StageState.HEALTHY
    assert state(partial, Stage.GATEWAY) is StageState.HEALTHY
    for stage in (Stage.WAN, Stage.INTERNET, Stage.DNS):
        assert state(partial, stage) is StageState.UNKNOWN
    assert partial.coverage == pytest.approx(2 / 5)
    finding = classify(partial)
    assert finding.classification is Classification.NO_FAULT_DETECTED
    assert finding.classification is not Classification.INSUFFICIENT_DATA


# --- rule 1: unknown, coverage ------------------------------------------------


def test_unusable_outcomes_do_not_count_as_measured() -> None:
    chain = evaluate_chain(
        AP,
        [
            probe(Stage.GATEWAY, ProbeOutcome.SKIPPED),
            probe(Stage.WAN, ProbeOutcome.ERROR),
        ],
        ChainFacts(ipv6_configured=False),
    )
    assert state(chain, Stage.GATEWAY) is StageState.UNKNOWN
    assert state(chain, Stage.WAN) is StageState.UNKNOWN
    assert chain.coverage == 0.0


def test_coverage_counts_only_applicable_stages() -> None:
    chain = evaluate_chain(AP, [probe(Stage.GATEWAY)], facts())
    assert chain.coverage_for(V4) == pytest.approx(2 / 5)
    assert all(not s.applicable for s in chain.stages if s.family is V6)
    assert chain.coverage == pytest.approx(2 / 5)
    assert chain.direct_coverage == pytest.approx(2 / 5)


def test_unknown_family_configuration_is_applicable_and_unknown() -> None:
    chain = evaluate_chain(AP, [probe(Stage.GATEWAY)], ChainFacts())
    assert state(chain, Stage.GATEWAY, V6) is StageState.UNKNOWN
    assert chain.coverage == pytest.approx(1 / 10)


# --- rule 2: ICMP alone is never an outage ------------------------------------


@pytest.mark.parametrize(
    "other",
    [
        probe(Stage.GATEWAY, OK, TCP, "gw-tcp"),
        probe(Stage.DNS, ProbeOutcome.SERVFAIL, DNS, "dns-gw", via={Stage.GATEWAY}),
        probe(Stage.GATEWAY, ProbeOutcome.REFUSED, TCP, "gw-tcp"),
    ],
)
def test_independent_success_keeps_stage_from_failing(other: ProbeResult) -> None:
    chain = evaluate_chain(AP, [probe(Stage.GATEWAY, TIMEOUT, ICMP), other], facts())
    assert state(chain, Stage.GATEWAY) is not StageState.FAILED


def test_icmp_failures_to_all_external_targets_are_not_an_outage() -> None:
    chain = evaluate_chain(
        AP, [*ext(TIMEOUT, "ext-a", "ext-b", "ext-c", kind=ICMP)], facts()
    )
    internet = chain.stage(Stage.INTERNET, V4)
    assert internet.state is StageState.DEGRADED
    assert "icmp_unanswered" in internet.reasons


def test_route_fact_counts_as_independent_evidence() -> None:
    chain = evaluate_chain(
        GW,
        [probe(Stage.WAN, TIMEOUT, ICMP, "nexthop", point=GW)],
        facts(wan_up_v4=True, default_route_v4=True),
    )
    assert state(chain, Stage.WAN) is StageState.HEALTHY
    assert "icmp_unanswered" in chain.stage(Stage.WAN, V4).reasons


def test_hard_failure_alone_fails_the_stage() -> None:
    chain = evaluate_chain(AP, [probe(Stage.GATEWAY, TIMEOUT, TCP)], facts())
    assert state(chain, Stage.GATEWAY) is StageState.FAILED


def test_mixed_hard_evidence_is_degraded() -> None:
    chain = evaluate_chain(
        AP,
        [probe(Stage.GATEWAY, TIMEOUT, TCP, "a"), probe(Stage.GATEWAY, OK, TCP, "b")],
        facts(),
    )
    stage = chain.stage(Stage.GATEWAY, V4)
    assert stage.state is StageState.DEGRADED
    assert stage.failed_targets == ("a",)


def test_refused_to_external_target_is_ambiguous() -> None:
    # a local firewall REJECT also answers with a reset
    chain = evaluate_chain(AP, [*ext(ProbeOutcome.REFUSED, "ext-a", "ext-b")], facts())
    assert state(chain, Stage.INTERNET) is StageState.UNKNOWN


# --- rule 3: external reference targets ---------------------------------------


def test_internet_fails_only_when_all_of_two_targets_fail() -> None:
    chain = evaluate_chain(AP, [*ext(TIMEOUT, "ext-a", "ext-b")], facts())
    assert state(chain, Stage.INTERNET) is StageState.FAILED


def test_single_failing_target_among_several_is_not_an_outage() -> None:
    chain = evaluate_chain(
        AP, [*ext(OK, "ext-a", "ext-b"), *ext(TIMEOUT, "ext-c")], facts()
    )
    internet = chain.stage(Stage.INTERNET, V4)
    assert internet.state is StageState.HEALTHY
    assert "single_external_service" in internet.reasons
    assert internet.failed_targets == ("ext-c",)
    finding = classify(chain)
    assert finding.classification is (
        Classification.SINGLE_EXTERNAL_SERVICE_UNREACHABLE
    )
    assert finding.severity is Severity.INFO


def test_several_failing_targets_with_one_working_are_degraded() -> None:
    chain = evaluate_chain(
        AP, [*ext(OK, "ext-a"), *ext(TIMEOUT, "ext-b", "ext-c")], facts()
    )
    assert state(chain, Stage.INTERNET) is StageState.DEGRADED


def test_only_one_configured_target_failing_is_at_most_degraded() -> None:
    chain = evaluate_chain(AP, [*ext(TIMEOUT, "ext-a")], facts())
    internet = chain.stage(Stage.INTERNET, V4)
    assert internet.state is StageState.DEGRADED
    assert "only_one_reference_target" in internet.reasons
    finding = classify(chain)
    assert finding.severity is not Severity.CRITICAL
    assert finding.classification is (
        Classification.SINGLE_EXTERNAL_SERVICE_UNREACHABLE
    )


def test_repeated_probes_to_one_target_count_as_one_target() -> None:
    chain = evaluate_chain(
        AP,
        [*ext(TIMEOUT, "ext-a"), *ext(TIMEOUT, "ext-a", timestamp=1001.0)],
        facts(),
    )
    assert state(chain, Stage.INTERNET) is StageState.DEGRADED


# --- rule 4: measurement point --------------------------------------------------


def test_probes_from_another_router_are_excluded() -> None:
    other = probe(Stage.GATEWAY, OK, point=MeasurementPoint.router("ap2"))
    chain = evaluate_chain(AP, [other], facts())
    assert state(chain, Stage.GATEWAY) is StageState.UNKNOWN
    assert chain.excluded == (other,)


def test_router_probes_never_enter_the_ha_chain() -> None:
    chain = evaluate_chain(HA, [probe(Stage.INTERNET)], ChainFacts())
    assert state(chain, Stage.INTERNET) is StageState.UNKNOWN
    assert len(chain.excluded) == 1


def test_ha_measurements_are_labelled_indirect_for_a_router() -> None:
    chain = evaluate_chain(
        AP, [*ext(OK, "ext-a", "ext-b", point=HA)], ChainFacts(ipv6_configured=False)
    )
    internet = chain.stage(Stage.INTERNET, V4)
    assert internet.state is StageState.HEALTHY
    assert internet.basis is Basis.INDIRECT
    assert all(not e.direct for e in internet.evidence)
    assert chain.coverage == pytest.approx(1 / 5)
    assert chain.direct_coverage == 0.0


def test_ha_measurements_never_fail_or_confirm_for_a_router() -> None:
    chain = evaluate_chain(
        AP,
        [
            *ext(TIMEOUT, "ext-a", "ext-b", point=HA),
            probe(Stage.DNS, ProbeOutcome.SERVFAIL, DNS, "dns", point=HA),
        ],
        facts(),
    )
    assert state(chain, Stage.INTERNET) is StageState.DEGRADED
    assert "indirect_evidence_only" in chain.stage(Stage.INTERNET, V4).reasons
    finding = classify(chain)
    assert finding.cause_class is not CauseClass.CONFIRMED
    assert not dns_failure_confirmed(chain, V4)


def test_ha_chain_uses_its_own_probes_directly() -> None:
    chain = evaluate_chain(HA, [*ext(TIMEOUT, "ext-a", "ext-b", point=HA)])
    assert state(chain, Stage.INTERNET) is StageState.FAILED
    assert chain.stage(Stage.INTERNET, V4).basis is Basis.DIRECT


def test_direct_evidence_wins_over_indirect() -> None:
    chain = evaluate_chain(
        AP,
        [*ext(OK, "ext-a", "ext-b", point=HA), *ext(TIMEOUT, "ext-a", "ext-b")],
        facts(),
    )
    internet = chain.stage(Stage.INTERNET, V4)
    assert internet.basis is Basis.DIRECT
    # an HA success is still independent evidence: no outage claimed
    assert internet.state is StageState.DEGRADED


# --- rule 5: no cascading guesses, contradictions --------------------------------


def test_router_offline_leaves_everything_downstream_unknown() -> None:
    chain = evaluate_chain(
        AP,
        [probe(Stage.ROUTER, TIMEOUT, ICMP, "ap1", point=HA)],
        facts(management_reachable=False),
    )
    assert state(chain, Stage.ROUTER) is StageState.FAILED
    for stage in (Stage.GATEWAY, Stage.WAN, Stage.INTERNET, Stage.DNS):
        assert state(chain, stage) is StageState.UNKNOWN
    finding = classify(chain)
    assert finding.classification is Classification.ROUTER_OFFLINE
    assert finding.severity is Severity.CRITICAL


def test_downstream_success_under_failed_upstream_is_a_contradiction() -> None:
    chain = evaluate_chain(
        AP,
        [probe(Stage.GATEWAY, TIMEOUT, TCP, "gw"), *ext(OK, "ext-a", "ext-b")],
        facts(),
    )
    assert state(chain, Stage.GATEWAY) is StageState.FAILED
    assert state(chain, Stage.INTERNET) is StageState.HEALTHY
    [contradiction] = chain.contradictions
    assert (contradiction.upstream, contradiction.downstream) == (
        Stage.GATEWAY,
        Stage.INTERNET,
    )
    finding = classify(chain)
    assert finding.contradictions == chain.contradictions
    assert finding.cause_class is CauseClass.POSSIBLE
    assert "contradicted_by_downstream" in finding.reasons


def test_facts_downstream_of_a_failure_are_kept() -> None:
    chain = evaluate_chain(
        GW,
        [probe(Stage.GATEWAY, TIMEOUT, TCP, "nexthop", point=GW)],
        facts(wan_up_v4=False),
    )
    assert state(chain, Stage.WAN) is StageState.FAILED


# --- rule 6: address families ---------------------------------------------------


def test_unconfigured_family_is_not_applicable() -> None:
    chain = evaluate_chain(AP, [probe(Stage.GATEWAY)], facts())
    for stage in chain.stages:
        if stage.family is V6:
            assert stage.state is StageState.NOT_APPLICABLE
    assert chain.families == (V4,)


def test_ipv6_only_chain_ignores_ipv4() -> None:
    chain = evaluate_chain(
        AP,
        [*ext(TIMEOUT, "a6", "b6", family=V6)],
        ChainFacts(management_reachable=True, ipv4_configured=False),
    )
    finding = classify(chain)
    assert finding.classification is Classification.WAN_PROBLEM
    assert finding.family is V6


def test_one_family_failing_without_other_family_evidence_is_not_family_only() -> None:
    chain = evaluate_chain(
        AP, [*ext(TIMEOUT, "a", "b")], ChainFacts(management_reachable=True)
    )
    finding = classify(chain)
    assert finding.classification is Classification.WAN_PROBLEM
    assert finding.family is V4


def test_both_families_failing_is_a_plain_problem() -> None:
    chain = _dual_stack(TIMEOUT, TIMEOUT)
    finding = classify(chain)
    assert finding.classification is Classification.WAN_PROBLEM
    assert finding.family is None


def test_family_specific_wan_fact() -> None:
    chain = evaluate_chain(
        GW, [], facts(ipv6_configured=True, wan_up_v4=True, wan_up_v6=False)
    )
    assert state(chain, Stage.WAN, V4) is StageState.HEALTHY
    assert state(chain, Stage.WAN, V6) is StageState.FAILED
    finding = classify(chain)
    assert finding.classification is Classification.IPV6_ONLY_DISTURBANCE
    assert finding.underlying is Classification.WAN_PROBLEM


# --- classification ---------------------------------------------------------------


def test_management_unreachable_when_router_answers_otherwise() -> None:
    chain = evaluate_chain(
        AP,
        [probe(Stage.ROUTER, OK, ICMP, "ap1", point=HA)],
        facts(management_reachable=False),
    )
    assert state(chain, Stage.ROUTER) is StageState.DEGRADED
    finding = classify(chain)
    assert finding.classification is Classification.MANAGEMENT_UNREACHABLE
    assert finding.severity is Severity.WARNING
    assert finding.cause_class is not CauseClass.CONFIRMED


def test_lan_problem_from_interface_fact() -> None:
    chain = evaluate_chain(AP, [], facts(interface_up=False))
    finding = classify(chain)
    assert finding.classification is Classification.LAN_PROBLEM
    assert finding.cause_class is CauseClass.CONFIRMED


def test_routing_problem_from_missing_default_route() -> None:
    chain = evaluate_chain(
        AP, [probe(Stage.GATEWAY, OK)], facts(default_route_v4=False)
    )
    finding = classify(chain)
    assert finding.classification is Classification.ROUTING_PROBLEM
    assert finding.recommendation_key == "check_default_route"
    assert finding.cause_class is CauseClass.CONFIRMED


def test_dns_failure_confirmed_when_resolver_path_is_measured() -> None:
    chain = evaluate_chain(
        AP,
        [
            probe(Stage.GATEWAY, OK, TCP, "gw"),
            probe(Stage.DNS, ProbeOutcome.SERVFAIL, DNS, "dns-gw", via={Stage.GATEWAY}),
        ],
        facts(),
    )
    assert dns_failure_confirmed(chain, V4)
    assert dns_failure_confirmed(chain, V4, "dns-gw")
    assert not dns_failure_confirmed(chain, V4, "dns-other")
    finding = classify(chain)
    assert finding.classification is Classification.DNS_PROBLEM
    assert finding.cause_class is CauseClass.CONFIRMED


def test_dns_failure_without_measured_path_is_not_confirmed() -> None:
    chain = evaluate_chain(
        AP,
        [probe(Stage.DNS, TIMEOUT, DNS, "dns-gw", via={Stage.GATEWAY})],
        facts(),
    )
    assert not dns_failure_confirmed(chain, V4)
    assert classify(chain).cause_class is CauseClass.POSSIBLE


def test_nxdomain_is_a_dns_failure_but_proves_the_hop() -> None:
    chain = evaluate_chain(
        AP,
        [probe(Stage.DNS, ProbeOutcome.NXDOMAIN, DNS, "dns-gw", via={Stage.GATEWAY})],
        facts(),
    )
    assert state(chain, Stage.DNS) is StageState.FAILED
    gateway = chain.stage(Stage.GATEWAY, V4)
    assert gateway.state is StageState.HEALTHY
    assert gateway.evidence[0].derived_from is Stage.DNS


def test_non_dns_probe_at_dns_stage_is_not_usable() -> None:
    chain = evaluate_chain(AP, [probe(Stage.DNS, OK, TCP, "dns-gw")], facts())
    assert state(chain, Stage.DNS) is StageState.UNKNOWN


def test_dns_partially_failing_is_degraded_info() -> None:
    chain = evaluate_chain(
        AP,
        [
            *ext(OK, "ext-a", "ext-b"),
            probe(Stage.DNS, OK, DNS, "dns-a"),
            probe(Stage.DNS, TIMEOUT, DNS, "dns-b"),
        ],
        facts(),
    )
    assert state(chain, Stage.DNS) is StageState.DEGRADED
    finding = classify(chain)
    assert finding.classification is Classification.DNS_PROBLEM
    assert finding.severity is Severity.INFO


def test_icmp_note_upstream_does_not_hide_a_real_failure_downstream() -> None:
    chain = evaluate_chain(
        AP,
        [probe(Stage.GATEWAY, TIMEOUT, ICMP, "gw"), *ext(TIMEOUT, "ext-a", "ext-b")],
        facts(),
    )
    finding = classify(chain)
    assert finding.classification is Classification.WAN_PROBLEM
    assert finding.severity is Severity.CRITICAL
    assert any(r.startswith("also:gateway") for r in finding.reasons)


# --- change findings ----------------------------------------------------------------


def test_gateway_change_finding() -> None:
    finding = gateway_change(AP, "hop-1", "hop-2", family=V4)
    assert finding is not None
    assert finding.classification is Classification.GATEWAY_CHANGED
    assert finding.cause_stage is Stage.GATEWAY
    assert finding.change is not None
    assert (finding.change.previous, finding.change.current) == ("hop-1", "hop-2")
    assert finding.chain is None
    assert finding.is_problem


@pytest.mark.parametrize(
    ("previous", "current"),
    [(None, "hop-1"), ("hop-1", None), (None, None), ("hop-1", "hop-1")],
)
def test_gateway_change_needs_two_known_different_values(
    previous: Any, current: Any
) -> None:
    assert gateway_change(AP, previous, current) is None


def test_dns_server_change_ignores_order() -> None:
    assert dns_server_change(AP, ["r1", "r2"], ["r2", "r1"]) is None
    assert dns_server_change(AP, None, ["r1"]) is None
    finding = dns_server_change(AP, ["r1", "r2"], ["r1", "r3"])
    assert finding is not None
    assert finding.classification is Classification.DNS_SERVER_CHANGED
    assert finding.cause_stage is Stage.DNS
    assert finding.change is not None
    assert finding.change.current == ("r1", "r3")


# --- model --------------------------------------------------------------------------


def test_probe_validation() -> None:
    with pytest.raises(ValueError):
        probe(Stage.GATEWAY, ProbeOutcome.SERVFAIL, TCP)
    with pytest.raises(ValueError):
        probe(Stage.GATEWAY, OK, ProbeKind.FACT)
    with pytest.raises(ValueError):
        probe(Stage.GATEWAY, OK, sent=1, received=2)
    with pytest.raises(ValueError):
        MeasurementPoint.router("")


def test_results_are_immutable_and_serialisable() -> None:
    chain = evaluate_chain(
        AP,
        [probe(Stage.GATEWAY, OK, evidence={"rcode": 0}), *ext(TIMEOUT, "a", "b")],
        facts(),
    )
    finding = classify(chain)
    with pytest.raises(AttributeError):
        finding.severity = Severity.OK  # type: ignore[misc]
    data = json.loads(json.dumps(finding.to_dict()))
    assert data["classification"] == "wan_problem"
    assert data["chain"]["coverage"] == chain.coverage
    assert json.dumps(chain.to_dict())


def test_logging_stays_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    chain = evaluate_chain(
        AP,
        [
            probe(Stage.GATEWAY, TIMEOUT, TCP, "192.0.2.1"),
            probe(Stage.GATEWAY, OK, point=MeasurementPoint.router("ap2")),
        ],
        facts(),
    )
    classify(chain)
    gateway_change(AP, "192.0.2.1", "192.0.2.2")
    assert caplog.records
    assert all(r.levelno <= logging.DEBUG for r in caplog.records)


@pytest.mark.parametrize("module", ["diag_model.py", "diag_chain.py"])
def test_module_is_stdlib_only(module: str) -> None:
    tree = ast.parse((PKG / module).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            imported.add((node.module or "").split(".")[0])
    assert not imported & {"homeassistant", "socket", "aiohttp", "asyncio", "aiodns"}
    assert imported <= {
        "__future__",
        "collections",
        "dataclasses",
        "enum",
        "logging",
        "types",
        "typing",
    }
