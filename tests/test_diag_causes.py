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
    Stage,
)

PKG = Path(__file__).resolve().parent.parent / "custom_components" / "openwrt_router"

V4 = AddressFamily.IPV4
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
    **kw: Any,
) -> ProbeResult:
    return ProbeResult(
        point=MeasurementPoint.router(key),
        target_id=target,
        kind=kind,
        stage=stage,
        family=V4,
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
        healthy("ap2"),
        mgmt_lost("ap3"),
        dns_broken("ap4"),
        finding("ap5", [], management_reachable=None),
    ]
    snapshot = copy.deepcopy(findings)
    result = correlate(findings, {**FLEET, "ap4": ap_deps()})
    assert len(result.findings) == len(findings)
    for given, returned, before in zip(
        findings, result.findings, snapshot, strict=True
    ):
        assert returned is given
        assert returned == before
    for index, item in enumerate(findings):
        if item.is_problem:
            assert result.links_for(index), index
        else:
            assert result.links_for(index) == ()
    names = [f.name for f in dataclasses.fields(CorrelationResult)]
    assert not [n for n in names if "suppress" in n or "hidden" in n]


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
