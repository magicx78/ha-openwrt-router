"""Tests for diag_causes.py: cause classes and multi-router correlation.

Pure logic: no network I/O, no Home Assistant instance. Findings are built
through ``evaluate_chain`` + ``classify`` so the tests exercise the real
hand-over between the two modules.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import json
import logging
import socket
from pathlib import Path
from typing import Any

import pytest

from custom_components.openwrt_router.diag_causes import (
    RouterDependencies,
    correlate,
)
from custom_components.openwrt_router.diag_chain import (
    ChainFacts,
    classify,
    evaluate_chain,
    gateway_change,
)
from custom_components.openwrt_router.diag_model import (
    AddressFamily,
    CauseClass,
    Classification,
    CorrelationResult,
    Finding,
    Location,
    LocationKind,
    MeasurementPoint,
    ProbeKind,
    ProbeOutcome,
    ProbeResult,
    Severity,
    Stage,
)

PKG = Path(__file__).resolve().parent.parent / "custom_components" / "openwrt_router"

V4 = AddressFamily.IPV4
V6 = AddressFamily.IPV6
OK = ProbeOutcome.OK
TIMEOUT = ProbeOutcome.TIMEOUT
WAN1 = Location(LocationKind.WAN, "wan1")
DNS_GW = Location(LocationKind.RESOLVER, "dns-gw")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("network I/O attempted")

    for name in ("getaddrinfo", "gethostbyname", "create_connection"):
        monkeypatch.setattr(socket, name, _boom)


def ap_deps(segment: str = "lan", **kw: Any) -> RouterDependencies:
    base: dict[str, Any] = {
        "gateway": "gw",
        "upstream": {"gw"},
        "wan": "wan1",
        "resolvers": {"dns-gw"},
        "segments": {segment},
    }
    base.update(kw)
    return RouterDependencies(**base)


FLEET: dict[str, RouterDependencies] = {
    "gw": RouterDependencies(wan="wan1", resolvers={"dns-gw"}, hosts={WAN1, DNS_GW}),
    "ap1": ap_deps(),
    "ap2": ap_deps(),
    "ap3": ap_deps(),
}


def p(
    key: str,
    stage: Stage,
    outcome: ProbeOutcome = OK,
    kind: ProbeKind = ProbeKind.TCP,
    target: str = "t",
    family: AddressFamily = V4,
    **kw: Any,
) -> ProbeResult:
    return ProbeResult(
        point=MeasurementPoint.router(key),
        target_id=target,
        kind=kind,
        stage=stage,
        family=family,
        outcome=outcome,
        timestamp=1000.0,
        **kw,
    )


def finding(key: str, probes: list[ProbeResult], **facts: Any) -> Finding:
    base: dict[str, Any] = {
        "management_reachable": True,
        "ipv4_configured": True,
        "ipv6_configured": False,
    }
    base.update(facts)
    return classify(
        evaluate_chain(MeasurementPoint.router(key), probes, ChainFacts(**base))
    )


def internet(key: str, outcome: ProbeOutcome) -> list[ProbeResult]:
    return [p(key, Stage.INTERNET, outcome, target=t) for t in ("ext-a", "ext-b")]


def healthy(key: str) -> Finding:
    return finding(
        key,
        [
            p(key, Stage.GATEWAY, target="gw"),
            *internet(key, OK),
            p(key, Stage.DNS, OK, ProbeKind.DNS, "dns-gw"),
        ],
    )


def ip_only(key: str) -> Finding:
    return finding(key, [p(key, Stage.GATEWAY, target="gw"), *internet(key, OK)])


def no_internet(key: str) -> Finding:
    return finding(key, [p(key, Stage.GATEWAY, target="gw"), *internet(key, TIMEOUT)])


def gw_wan_down() -> Finding:
    return finding("gw", internet("gw", TIMEOUT), wan_up_v4=False)


def dns_broken(
    key: str, resolver: str = "dns-gw", outcome: ProbeOutcome = TIMEOUT, **kw: Any
) -> Finding:
    return finding(
        key,
        [
            p(key, Stage.GATEWAY, target="gw"),
            *internet(key, OK),
            p(key, Stage.DNS, outcome, ProbeKind.DNS, resolver, **kw),
        ],
    )


def gateway_lost(key: str) -> Finding:
    return finding(
        key,
        [
            p(key, Stage.GATEWAY, TIMEOUT, target="gw"),
            p(key, Stage.GATEWAY, TIMEOUT, ProbeKind.ICMP, "gw"),
        ],
    )


def mgmt_lost(key: str) -> Finding:
    return finding(key, [], management_reachable=False)


def fleet_causes(result: CorrelationResult) -> list[Any]:
    return [c for c in result.causes if c.rule != "local_finding"]


def linked(result: CorrelationResult, cause_id: str) -> set[int]:
    return {link.finding_index for link in result.links if link.cause_id == cause_id}


# --- customer acceptance cases -------------------------------------------------


def test_case_14_single_ap_down() -> None:
    findings = [healthy("gw"), healthy("ap1"), healthy("ap2"), mgmt_lost("ap3")]
    assert findings[3].classification is Classification.ROUTER_OFFLINE
    result = correlate(findings, FLEET)
    assert fleet_causes(result) == []
    [cause] = result.causes
    assert cause.location == Location(LocationKind.ROUTER, "ap3")
    assert cause.rule == "local_finding"
    assert linked(result, cause.cause_id) == {3}
    for index in range(3):
        assert result.links_for(index) == ()


def test_case_15_multiple_routers_common_fault() -> None:
    findings = [
        gw_wan_down(),
        no_internet("ap1"),
        no_internet("ap2"),
        no_internet("ap3"),
    ]
    result = correlate(findings, FLEET)
    [cause] = result.causes
    assert cause.rule == "central_internet_access"
    assert cause.location == WAN1
    assert cause.cause_class is CauseClass.CONFIRMED
    assert cause.reason == "gateway_reports_wan_down"
    assert cause.router_keys == ("ap1", "ap2", "ap3", "gw")
    assert any(e.fact == "wan_up" and e.ok is False for e in cause.evidence)
    assert linked(result, cause.cause_id) == {0, 1, 2, 3}
    classes = {link.finding_index: link.cause_class for link in result.links}
    assert classes[0] is CauseClass.CONFIRMED
    # an AP is linked by dependency (correlation), never confirmed
    assert {classes[i] for i in (1, 2, 3)} == {CauseClass.PROBABLE}


def test_case_15_dns_variant_common_resolver() -> None:
    # gw and ap3 do not test DNS this round: no evidence either way
    findings = [ip_only("gw"), dns_broken("ap1"), dns_broken("ap2"), ip_only("ap3")]
    result = correlate(findings, FLEET)
    [cause] = fleet_causes(result)
    assert cause.rule == "common_resolver"
    assert cause.location == DNS_GW
    assert cause.cause_class is CauseClass.PROBABLE
    assert linked(result, cause.cause_id) == {1, 2}
    assert {e.target_id for e in cause.evidence} == {"dns-gw"}


# --- rules 7-9 -------------------------------------------------------------------


def test_cause_never_explains_router_that_does_not_depend_on_it() -> None:
    deps = {**FLEET, "ap4": ap_deps(wan="wan2", resolvers={"dns-other"})}
    findings = [
        gw_wan_down(),
        no_internet("ap1"),
        no_internet("ap2"),
        no_internet("ap4"),  # other WAN
        no_internet("ap5"),  # no dependency information at all
    ]
    result = correlate(findings, deps)
    [central] = fleet_causes(result)
    assert linked(result, central.cause_id) == {0, 1, 2}
    for index, key in ((3, "ap4"), (4, "ap5")):
        [link] = result.links_for(index)
        assert link.rule == "local_finding"
        assert result.cause(link.cause_id).location == Location(
            LocationKind.ROUTER, key
        )

    dns_findings = [dns_broken("ap1"), dns_broken("ap2"), dns_broken("ap4", "dns-gw")]
    dns_result = correlate(dns_findings, deps)
    [resolver] = fleet_causes(dns_result)
    assert linked(dns_result, resolver.cause_id) == {0, 1}
    assert dns_result.links_for(2)[0].rule == "local_finding"


def test_unknown_dependencies_mean_no_link() -> None:
    findings = [gw_wan_down(), no_internet("ap1"), no_internet("ap2")]
    result = correlate(findings, {})
    assert fleet_causes(result) == []
    assert len(result.causes) == 3
    assert all(link.rule == "local_finding" for link in result.links)


def test_correlation_alone_is_never_confirmed() -> None:
    wan = correlate([no_internet("gw"), no_internet("ap1"), no_internet("ap2")], FLEET)
    [cause] = fleet_causes(wan)
    assert cause.cause_class is CauseClass.PROBABLE
    assert cause.reason == "no_dependent_router_reaches_external_targets"

    dns = correlate([dns_broken("ap1"), dns_broken("ap2"), dns_broken("ap3")], FLEET)
    [cause] = fleet_causes(dns)
    assert cause.cause_class is CauseClass.PROBABLE

    segment = correlate(
        [
            gateway_lost("ap1"),
            gateway_lost("ap2"),
            healthy("ap3"),
        ],
        {**FLEET, "ap1": ap_deps("iot"), "ap2": ap_deps("iot")},
    )
    [cause] = fleet_causes(segment)
    assert cause.cause_class is CauseClass.POSSIBLE

    for result in (wan, dns, segment):
        fleet = {c.cause_id for c in fleet_causes(result)}
        assert all(
            link.cause_class is not CauseClass.CONFIRMED
            for link in result.links
            if link.cause_id in fleet
        )


def test_linking_keeps_every_finding_unchanged() -> None:
    findings = [
        gw_wan_down(),
        no_internet("ap1"),
        no_internet("ap2"),
        mgmt_lost("ap3"),
        dns_broken("ap4"),
        finding("ap5", [], management_reachable=None),
        # IPv4 internet down like the others, plus its own IPv6 gateway loss
        dual(
            "ap6",
            [
                p("ap6", Stage.GATEWAY, target="gw"),
                *internet("ap6", TIMEOUT),
                p("ap6", Stage.GATEWAY, TIMEOUT, target="gw6", family=V6),
            ],
        ),
    ]
    snapshot = copy.deepcopy(findings)
    deps = {**FLEET, "ap4": ap_deps(wan="wan2"), "ap6": ap_deps()}
    result = correlate(findings, deps)
    assert len(result.findings) == len(findings)
    for given, returned, before in zip(
        findings, result.findings, snapshot, strict=True
    ):
        assert returned is given
        assert returned == before
    link_map = {
        index: {
            (link.rule, result.cause(link.cause_id).location)
            for link in result.links_for(index)
        }
        for index in range(len(findings))
    }
    central = {("central_internet_access", WAN1)}
    assert link_map == {
        0: central,
        1: central,
        2: central,
        3: {("local_finding", Location(LocationKind.ROUTER, "ap3"))},
        4: {("local_finding", Location(LocationKind.ROUTER, "ap4"))},
        5: set(),
        6: {("local_finding", Location(LocationKind.ROUTER, "ap6"))},
    }
    assert "ap6" in result.cause("central_internet_access:wan:wan1:ipv4").router_keys
    assert_links_sound(result)
    names = [f.name for f in dataclasses.fields(CorrelationResult)]
    assert not [n for n in names if "suppress" in n or "hidden" in n]


def assert_links_sound(result: CorrelationResult) -> None:
    """Every link: the finding's own stage/family fit the cause, and the link
    is never stronger than the finding's own cause class."""
    rank = list(reversed(CauseClass))  # UNKNOWN < POSSIBLE < PROBABLE < CONFIRMED
    for link in result.links:
        item = result.findings[link.finding_index]
        cause = result.cause(link.cause_id)
        if link.reason == "secondary_problem":
            [other] = [
                o
                for o in item.also
                if (o.stage, o.family) == (cause.evidence[0].stage, cause.family)
            ]
            assert link.cause_class is other.cause_class, link
            continue
        assert rank.index(link.cause_class) <= rank.index(item.cause_class), link
        if cause.rule == "local_finding":
            continue
        assert item.cause_stage in STAGES_OF_RULE[cause.rule], link
        assert cause.family is None or item.family == cause.family, link


STAGES_OF_RULE = {
    "central_internet_access": {Stage.WAN, Stage.INTERNET},
    "segment_path": {Stage.GATEWAY},
    "common_gateway": {Stage.GATEWAY},
    "common_resolver": {Stage.DNS},
}


def dual(key: str, probes: list[ProbeResult]) -> Finding:
    return finding(key, probes, ipv6_configured=True)


# --- review regressions: a common cause must never excuse an unrelated finding --------


def test_ipv4_central_cause_does_not_excuse_ipv6_gateway_loss() -> None:
    ap1 = dual(
        "ap1",
        [
            p("ap1", Stage.GATEWAY, target="gw"),
            *internet("ap1", TIMEOUT),
            p("ap1", Stage.GATEWAY, TIMEOUT, target="gw6", family=V6),
        ],
    )
    assert (ap1.classification, ap1.family) == (Classification.GATEWAY_PROBLEM, V6)
    result = correlate([ap1, no_internet("ap2")], FLEET)
    [central] = fleet_causes(result)
    assert central.family is V4
    # both of ap1's problems stay visible: its IPv4 symptom in the common
    # cause, its IPv6 gateway loss as its own cause
    assert central.router_keys == ("ap1", "ap2")
    assert linked(result, central.cause_id) == {1}
    [link] = result.links_for(0)
    assert link.rule == "local_finding"
    assert result.cause(link.cause_id).summary_key == "gateway_problem"
    assert_links_sound(result)


def test_resolver_cause_does_not_excuse_gateway_degradation() -> None:
    dns = [p(k, Stage.DNS, TIMEOUT, ProbeKind.DNS, "dns-gw") for k in ("ap1", "ap2")]
    ap1 = finding(
        "ap1",
        [
            p("ap1", Stage.GATEWAY, target="gw"),
            p("ap1", Stage.GATEWAY, TIMEOUT, target="gw-http"),
            *internet("ap1", OK),
            dns[0],
        ],
    )
    ap2 = finding(
        "ap2", [p("ap2", Stage.GATEWAY, target="gw"), *internet("ap2", OK), dns[1]]
    )
    assert ap1.classification is Classification.GATEWAY_PROBLEM
    assert ap1.cause_class is CauseClass.POSSIBLE
    result = correlate([ap1, ap2], FLEET)
    [resolver] = fleet_causes(result)
    assert resolver.router_keys == ("ap1", "ap2")
    assert linked(result, resolver.cause_id) == {1}
    [link] = result.links_for(0)
    assert link.rule == "local_finding"
    assert link.cause_class is CauseClass.POSSIBLE
    assert_links_sound(result)


def test_segment_cause_does_not_excuse_own_interface_down() -> None:
    ap1 = finding(
        "ap1", [p("ap1", Stage.GATEWAY, TIMEOUT, target="gw")], interface_up=False
    )
    # the upstream (own LAN) problem is the root; severity reflects the outage
    assert ap1.classification is Classification.LAN_PROBLEM
    assert ap1.severity is Severity.CRITICAL
    ap2 = finding("ap2", [p("ap2", Stage.GATEWAY, target="gw")])
    result = correlate([ap1, ap2], {"ap1": ap_deps("lan"), "ap2": ap_deps("iot")})
    assert fleet_causes(result) == []
    [link] = result.links_for(0)
    assert link.rule == "local_finding"
    assert link.cause_class is CauseClass.CONFIRMED


def test_central_cause_requires_measured_gateway_reachability() -> None:
    a1 = finding("ap1", internet("ap1", TIMEOUT))
    a2 = finding("ap2", internet("ap2", TIMEOUT))
    result = correlate([a1, a2], FLEET)
    assert fleet_causes(result) == []
    assert [link.rule for link in result.links] == ["local_finding"] * 2


def test_segment_rule_compares_same_family_only() -> None:
    a1 = finding(
        "ap1",
        [p("ap1", Stage.GATEWAY, TIMEOUT, target="gw6", family=V6)],
        ipv4_configured=False,
        ipv6_configured=True,
    )
    a2 = finding("ap2", [p("ap2", Stage.GATEWAY, target="gw")])
    result = correlate([a1, a2], {"ap1": ap_deps("lan"), "ap2": ap_deps("iot")})
    assert fleet_causes(result) == []
    assert result.links_for(0)[0].rule == "local_finding"


def test_segment_cause_per_family() -> None:
    lost6 = [
        p(k, Stage.GATEWAY, TIMEOUT, target="gw6", family=V6) for k in ("ap1", "ap2")
    ]
    reached4 = [p(k, Stage.GATEWAY, target="gw") for k in ("ap1", "ap2", "ap3")]
    ap1 = dual("ap1", [reached4[0], lost6[0]])
    ap2 = dual("ap2", [reached4[1], lost6[1]])
    ap3 = dual("ap3", [reached4[2], p("ap3", Stage.GATEWAY, target="gw6", family=V6)])
    deps = {**FLEET, "ap1": ap_deps("iot"), "ap2": ap_deps("iot")}
    result = correlate([ap1, ap2, ap3], deps)
    [cause] = fleet_causes(result)
    assert cause.rule == "segment_path"
    assert cause.family is V6
    assert linked(result, cause.cause_id) == {0, 1}
    assert_links_sound(result)


def test_link_class_never_stronger_than_the_findings_own_class() -> None:
    def contradicted(key: str) -> Finding:
        # internet fails while DNS through an external resolver answers:
        # the finding's own class drops to POSSIBLE
        return finding(
            key,
            [
                p(key, Stage.GATEWAY, target="gw"),
                *internet(key, TIMEOUT),
                p(key, Stage.DNS, OK, ProbeKind.DNS, "dns-ext"),
            ],
        )

    a1, a2 = contradicted("ap1"), contradicted("ap2")
    assert a1.cause_class is CauseClass.POSSIBLE
    result = correlate([a1, a2], FLEET)
    [central] = fleet_causes(result)
    assert central.cause_class is CauseClass.PROBABLE
    assert {link.cause_class for link in result.links} == {CauseClass.POSSIBLE}
    assert_links_sound(result)


def test_linked_finding_keeps_its_secondary_problem_as_a_cause() -> None:
    ap1 = dual(
        "ap1",
        [
            p("ap1", Stage.GATEWAY, target="gw"),
            *internet("ap1", TIMEOUT),
            p("ap1", Stage.GATEWAY, target="gw6", family=V6),
            p("ap1", Stage.GATEWAY, TIMEOUT, target="gw6-b", family=V6),
        ],
    )
    assert (ap1.classification, ap1.family) == (Classification.WAN_PROBLEM, V4)
    result = correlate([ap1, no_internet("ap2")], FLEET)
    rules = sorted(
        (link.rule, result.cause(link.cause_id).summary_key)
        for link in result.links_for(0)
    )
    assert rules == [
        ("central_internet_access", "central_internet_access"),
        ("local_finding", "gateway_problem"),
    ]
    secondary = next(
        result.cause(link.cause_id)
        for link in result.links_for(0)
        if link.rule == "local_finding"
    )
    assert secondary.family is V6
    assert secondary.cause_class is CauseClass.POSSIBLE
    assert_links_sound(result)


def dual_no_internet(key: str, v6_outcome: ProbeOutcome = TIMEOUT) -> Finding:
    return dual(
        key,
        [
            p(key, Stage.GATEWAY, target="gw"),
            p(key, Stage.GATEWAY, target="gw6", family=V6),
            *internet(key, TIMEOUT),
            *[
                p(key, Stage.INTERNET, v6_outcome, target=t, family=V6)
                for t in ("ext-a6", "ext-b6")
            ],
        ],
    )


def test_both_families_down_give_one_family_free_cause() -> None:
    findings = [dual_no_internet("ap1"), dual_no_internet("ap2")]
    assert findings[0].family is None
    result = correlate(findings, FLEET)
    [central] = fleet_causes(result)
    assert central.family is None
    assert {e.family for e in central.evidence} == {V4, V6}
    assert linked(result, central.cause_id) == {0, 1}
    assert_links_sound(result)


def test_cause_of_one_family_does_not_explain_a_both_family_finding() -> None:
    # ap1 is down in both families, ap2 only in IPv4: the IPv4 cause covers
    # only half of ap1's finding, so ap1 keeps a local cause
    findings = [dual_no_internet("ap1"), dual_no_internet("ap2", OK)]
    result = correlate(findings, FLEET)
    [central] = fleet_causes(result)
    assert central.family is V4
    assert central.router_keys == ("ap1", "ap2")
    assert linked(result, central.cause_id) == {1}
    assert [link.rule for link in result.links_for(0)] == ["local_finding"]
    assert_links_sound(result)


def test_resolver_answering_in_one_family_blocks_the_common_cause() -> None:
    def broken_v4(key: str) -> Finding:
        return dual(
            key,
            [
                p(key, Stage.GATEWAY, target="gw"),
                p(key, Stage.GATEWAY, target="gw6", family=V6),
                *internet(key, OK),
                p(key, Stage.DNS, TIMEOUT, ProbeKind.DNS, "dns-gw"),
                p(key, Stage.DNS, OK, ProbeKind.DNS, "dns-gw", family=V6),
            ],
        )

    result = correlate([broken_v4("ap1"), broken_v4("ap2")], FLEET)
    assert fleet_causes(result) == []


def test_correlate_accepts_any_iterable_and_returns_a_tuple() -> None:
    result = correlate((f for f in [healthy("ap1"), mgmt_lost("ap2")]), FLEET)
    assert isinstance(result.findings, tuple)
    assert len(result.findings) == 2


# --- customer example A ------------------------------------------------------------


def test_central_cause_needs_two_routers_or_gateway_evidence() -> None:
    result = correlate([healthy("gw"), no_internet("ap1")], FLEET)
    assert fleet_causes(result) == []
    # the gateway's own evidence alone is enough (and confirmed)
    only_gw = correlate([gw_wan_down()], FLEET)
    [cause] = only_gw.causes
    assert cause.rule == "central_internet_access"
    assert cause.cause_class is CauseClass.CONFIRMED


def test_router_reaching_external_targets_blocks_central_cause() -> None:
    result = correlate([no_internet("ap1"), no_internet("ap2"), healthy("ap3")], FLEET)
    assert fleet_causes(result) == []
    assert len(result.causes) == 2


def test_offline_router_is_not_part_of_central_cause() -> None:
    result = correlate(
        [no_internet("ap1"), no_internet("ap2"), mgmt_lost("ap3")], FLEET
    )
    [central] = fleet_causes(result)
    assert linked(result, central.cause_id) == {0, 1}
    assert result.links_for(2)[0].rule == "local_finding"


# --- customer example C ------------------------------------------------------------


def test_segment_cannot_reach_gateway_while_other_segment_can() -> None:
    deps = {**FLEET, "ap1": ap_deps("iot"), "ap2": ap_deps("iot")}
    result = correlate([gateway_lost("ap1"), gateway_lost("ap2"), healthy("ap3")], deps)
    [cause] = fleet_causes(result)
    assert cause.rule == "segment_path"
    assert cause.location == Location(LocationKind.SEGMENT, "iot")
    assert cause.cause_class is CauseClass.POSSIBLE
    assert cause.summary_key == "vlan_routing_or_firewall"
    assert linked(result, cause.cause_id) == {0, 1}
    assert result.links_for(2) == ()


def test_shared_segment_with_working_router_gives_no_segment_cause() -> None:
    result = correlate([gateway_lost("ap1"), healthy("ap2")], FLEET)
    assert fleet_causes(result) == []


def test_router_without_segment_info_stays_standalone() -> None:
    deps = {**FLEET, "ap1": ap_deps("iot"), "ap2": RouterDependencies(gateway="gw")}
    result = correlate([gateway_lost("ap1"), gateway_lost("ap2"), healthy("ap3")], deps)
    [cause] = fleet_causes(result)
    assert linked(result, cause.cause_id) == {0}
    assert result.links_for(1)[0].rule == "local_finding"


def test_all_dependents_losing_the_gateway_is_a_probable_gateway_cause() -> None:
    result = correlate(
        [gateway_lost("ap1"), gateway_lost("ap2"), gateway_lost("ap3")], FLEET
    )
    [cause] = fleet_causes(result)
    assert cause.rule == "common_gateway"
    assert cause.location == Location(LocationKind.ROUTER, "gw")
    assert cause.cause_class is CauseClass.PROBABLE
    assert linked(result, cause.cause_id) == {0, 1, 2}


# --- customer example D ------------------------------------------------------------


def test_resolver_answering_for_another_router_blocks_common_cause() -> None:
    result = correlate([dns_broken("ap1"), dns_broken("ap2"), healthy("ap3")], FLEET)
    assert fleet_causes(result) == []


def test_resolver_cause_confirmed_by_direct_servfail_with_measured_path() -> None:
    confirmed = dns_broken("ap1", outcome=ProbeOutcome.SERVFAIL, via={Stage.GATEWAY})
    assert confirmed.cause_class is CauseClass.CONFIRMED
    result = correlate([confirmed, dns_broken("ap2")], FLEET)
    [cause] = fleet_causes(result)
    assert cause.cause_class is CauseClass.CONFIRMED
    assert cause.reason == "resolver_failure_measured"
    classes = {link.finding_index: link.cause_class for link in result.links}
    assert classes == {0: CauseClass.CONFIRMED, 1: CauseClass.PROBABLE}


def test_single_router_dns_problem_stays_local() -> None:
    result = correlate([dns_broken("ap1"), healthy("gw")], FLEET)
    assert fleet_causes(result) == []
    [cause] = result.causes
    assert cause.cause_class is CauseClass.PROBABLE  # the finding's own class


# --- other findings ----------------------------------------------------------------


def test_change_findings_stay_standalone() -> None:
    change = gateway_change(MeasurementPoint.router("ap1"), "hop-1", "hop-2")
    assert change is not None
    findings = [gw_wan_down(), no_internet("ap1"), no_internet("ap2"), change]
    result = correlate(findings, FLEET)
    [link] = result.links_for(3)
    assert link.rule == "local_finding"
    assert result.cause(link.cause_id).summary_key == "gateway_changed"


def test_ha_finding_gets_its_own_location() -> None:
    ha = MeasurementPoint.ha()
    probes = [
        ProbeResult(ha, t, ProbeKind.TCP, Stage.INTERNET, V4, TIMEOUT, 1000.0)
        for t in ("ext-a", "ext-b")
    ]
    ha_finding = classify(evaluate_chain(ha, probes))
    result = correlate([ha_finding, no_internet("ap1"), no_internet("ap2")], FLEET)
    [link] = result.links_for(0)
    assert result.cause(link.cause_id).location == Location(LocationKind.HA, "ha")


def test_dependencies_reject_a_bare_string_for_sets() -> None:
    with pytest.raises(TypeError):
        RouterDependencies(resolvers="dns-gw")  # type: ignore[arg-type]


def test_dependency_locations() -> None:
    deps = ap_deps("iot")
    assert deps.locations() == {
        Location(LocationKind.ROUTER, "gw"),
        WAN1,
        DNS_GW,
        Location(LocationKind.SEGMENT, "iot"),
    }
    assert FLEET["gw"].depends_on(WAN1)


def test_result_is_serialisable() -> None:
    result = correlate([gw_wan_down(), no_internet("ap1")], FLEET)
    data = json.loads(json.dumps(result.to_dict()))
    assert data["causes"][0]["cause_class"] == "confirmed"
    assert data["links"][0]["finding_index"] == 0


def test_logging_stays_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    correlate([gw_wan_down(), no_internet("ap1"), dns_broken("ap2")], FLEET)
    assert caplog.records
    assert all(r.levelno <= logging.DEBUG for r in caplog.records)


def test_module_is_stdlib_only() -> None:
    tree = ast.parse((PKG / "diag_causes.py").read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "collections", "dataclasses", "logging", "typing"}
