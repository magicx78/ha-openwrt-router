"""Self-Healing package F: the remediation playbooks A-G (heal_playbooks).

Pure logic, no Home Assistant, no router. Order tests 10 (DNS repair plan),
11 (DHCP), 12 (WLAN radio recovery), 13 (WAN recovery), 14 (drift plan
shape), 34 (incident correlation -> playbook, root only); every never-rule
of the owner as its own test; the fleet cases; the matcher; hostile
strings; end to end through ``heal_policy.gate`` (nothing is executable in
1.53.0).
"""

from __future__ import annotations

import dataclasses
import json
import random
from typing import Any

import pytest

from custom_components.openwrt_router import config_const as cc
from custom_components.openwrt_router import diag_model as dm
from custom_components.openwrt_router import heal_catalog as hc
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_playbooks as pb
from custom_components.openwrt_router import heal_policy as hp
from custom_components.openwrt_router import net_events as ne
from custom_components.openwrt_router import net_rules as nr

FS = pb.FindingStatus
MS = pb.MatchStatus
P = hp.Permission
M = hm.HealMode

HOSTILE = (
    "dnsmasq; reboot",
    "dnsmasq\n",
    "<script>alert(1)</script>",
    "$(reboot)",
    "`rm -rf /`",
    "../../etc/passwd",
    "radio0 && wifi down",
    "x" * 5000,
    "dnsmasq\x00",
    "ＤＮＳＭＡＳＱ",
)


class _Str(str):
    """A str subclass that claims to be a catalog value."""


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def incident(**over: Any) -> pb.IncidentInput:
    base: dict[str, Any] = {
        "incident_type": "system_service_restart",
        "scope": "router",
        "service": "dnsmasq",
        "cause": "dns_resolution",
        "cause_status": "confirmed",
        "cause_level": "confirmed",
        "confidence": 0.9,
        "severity": "critical",
        "source_families": ("log", "poll"),
        "is_root": True,
        "temporal_only": False,
        "evidence_fresh": True,
        "affected_clients": 12,
        "occurrences": 3,
    }
    base.update(over)
    return pb.IncidentInput(**base)


def svc(**over: Any) -> pb.ServiceFact:
    base: dict[str, Any] = {
        "running": False,
        "enabled": True,
        "crash_loop": False,
        "restarts_24h": 3,
    }
    base.update(over)
    return pb.ServiceFact(**base)


def healthy_svc() -> pb.ServiceFact:
    return pb.ServiceFact(running=True, enabled=True, crash_loop=False, restarts_24h=0)


def evidence(**over: Any) -> pb.Evidence:
    """A gateway whose dnsmasq is down while WAN and upstream DNS are fine."""
    base: dict[str, Any] = {
        "role": "gateway",
        "reachable": True,
        "capabilities": {
            "data.services": True,
            "data.wireless": True,
            "config.capture": True,
            "config.diff": True,
        },
        "services": {"dnsmasq": svc(), "odhcpd": healthy_svc()},
        "wan_up": True,
        "dns": pb.DnsFact(local_ok=False, upstream_ok=True, log_hint=True),
        "dhcp": pb.DhcpFact(daemons=("dnsmasq",), pool_usage_pct=40),
        "chain": {"router": "healthy", "gateway": "healthy", "wan": "healthy"},
    }
    base.update(over)
    return pb.Evidence(**base)


def ctx(**over: Any) -> hp.RiskContext:
    """A fully known, benign gateway (as in the policy tests)."""
    base: dict[str, Any] = {
        "role": "gateway",
        "identity_confirmed": True,
        "reachable": True,
        "dependants": 0,
        "target_on_mgmt_path": False,
        "target_is_wireless_uplink": False,
        "target_carries_dependants": False,
        "service_enabled": True,
        "service_dependant_routers": 0,
        "service_dependant_clients": 12,
        "service_config_unapplied": False,
        "clients_on_router": 12,
        "clients_on_target": 4,
        "open_security_findings": 0,
        "in_maintenance": False,
        "concurrent_repair": False,
        "breaker_open": False,
        "diag_enabled": True,
    }
    base.update(over)
    return hp.RiskContext(**base)


def gate(
    finding: pb.PlaybookFinding,
    mode: hm.HealMode = M.OBSERVE,
    *,
    context: hp.RiskContext | None = None,
    allowlist: tuple[hm.AllowEntry, ...] = (),
) -> hp.GateVerdict | None:
    inp = pb.to_decision_input(
        finding, context=context or ctx(), prior_failed_attempts=0
    )
    if inp is None:
        return None
    return hp.gate(
        inp,
        mode=mode,
        allowlist=allowlist,
        module_enabled=True,
        held=False,
        fleet_paused=False,
        guards_green=True,
    )


def assess(inc: pb.IncidentInput | None = None, ev: pb.Evidence | None = None):
    return pb.assess(inc or incident(), ev or evidence())


def finding_of(
    inc: pb.IncidentInput | None = None, ev: pb.Evidence | None = None
) -> pb.PlaybookFinding:
    a = assess(inc, ev)
    assert a.finding is not None, a.match
    return a.finding


def step(f: pb.PlaybookFinding, step_id: str) -> pb.StepResult:
    return next(s for s in f.steps if s.step_id == step_id)


def all_text(f: pb.PlaybookFinding) -> str:
    return json.dumps(f.to_dict(), ensure_ascii=False) + "\n".join(f.texts_de())


# ---------------------------------------------------------------------------
# Registry: closed, versioned, checked against catalog, preflight, NI
# ---------------------------------------------------------------------------


def test_registry_has_seven_playbooks_a_to_g_in_order() -> None:
    assert [p.letter for p in pb.PLAYBOOKS.values()] == list("ABCDEFG")
    assert pb.PLAYBOOK_IDS == (
        "dns_recovery",
        "dhcp_recovery",
        "radio_recovery",
        "interface_recovery",
        "wan_recovery",
        "drift_recovery",
        "client_recovery",
    )
    assert pb.REGISTRY_VERSION == 1
    for p in pb.PLAYBOOKS.values():
        assert p.version >= 1


def test_registry_is_read_only() -> None:
    with pytest.raises(TypeError):
        pb.PLAYBOOKS["x"] = pb.PLAYBOOKS["dns_recovery"]  # type: ignore[index]
    with pytest.raises(dataclasses.FrozenInstanceError):
        pb.PLAYBOOKS["dns_recovery"].may_propose = ("router.reboot",)  # type: ignore[misc]


@pytest.mark.parametrize("pid", pb.PLAYBOOK_IDS)
def test_every_playbook_validates_against_the_catalog(pid: str) -> None:
    p = pb.PLAYBOOKS[pid]
    for action in (*p.may_propose, *p.modelled, *p.excluded):
        assert hc.entry(action) is hc.CATALOG[action]
    for name in p.service_choices:
        assert name in hc.SERVICE_NAMES
        # each choice builds a valid catalog action
        hc.validate("service.restart", {"service": name})
    assert not set(p.may_propose) & set(p.excluded)
    # risk class comes from the catalog, never lower than any named action
    for action in (*p.may_propose, *p.modelled):
        assert p.risk_class >= hc.entry(action).base_risk
    assert p.risk_class == max(
        (hc.entry(a).base_risk for a in (*p.may_propose, *p.modelled)),
        default=hm.RiskClass.READ_ONLY,
    )
    # rollback is the catalog's own statement, verbatim
    for action, text in p.rollback.items():
        assert text == hc.entry(action).rollback_statement
    for acl in (acl for a in p.may_propose for acl in hc.entry(a).required_acl):
        assert acl in p.required_permissions


@pytest.mark.parametrize("pid", pb.PLAYBOOK_IDS)
def test_every_playbook_names_only_existing_preflight_ids(pid: str) -> None:
    p = pb.PLAYBOOKS[pid]
    assert p.preflight
    assert set(p.preflight) <= set(pb.PREFLIGHT_CHECK_IDS)
    assert "router_reachable" in p.preflight
    assert "identity_unique" in p.preflight


def test_preflight_ids_are_exactly_the_thirteen_of_package_e() -> None:
    assert pb.PREFLIGHT_CHECK_IDS == (
        "router_reachable",
        "identity_unique",
        "action_supported",
        "permissions_present",
        "no_concurrent_repair",
        "maintenance_window_ok",
        "no_critical_state",
        "management_path_available",
        "components_known",
        "config_captured",
        "backup_present",
        "recovery_path_checked",
        "approval_valid",
    )


def test_only_service_restart_may_ever_be_proposed() -> None:
    proposable = {a for p in pb.PLAYBOOKS.values() for a in p.may_propose}
    assert proposable == {"service.restart"}
    assert pb.PLAYBOOKS["dns_recovery"].service_choices == ("dnsmasq",)
    assert pb.PLAYBOOKS["dhcp_recovery"].service_choices == ("dnsmasq", "odhcpd")
    for pid in ("radio_recovery", "interface_recovery", "wan_recovery"):
        assert pb.PLAYBOOKS[pid].may_propose == ()
    assert pb.PLAYBOOKS["drift_recovery"].may_propose == ()
    assert pb.PLAYBOOKS["client_recovery"].may_propose == ()


def test_known_incident_types_are_the_real_ni_types() -> None:
    real = set(nr.DEFAULT_SETTINGS["thresholds"]) - {"auto_resolve", "ignored"}
    real |= set(nr.DIAG_CHANGE_TYPES)
    assert set(pb.KNOWN_INCIDENT_TYPES) == real
    for p in pb.PLAYBOOKS.values():
        assert set(p.detection.incident_types) <= real


def test_watched_services_causes_scopes_families_match_ni() -> None:
    rule = nr.DEFAULT_SETTINGS["thresholds"]["system_service_restart"]
    assert tuple(rule["services"]) == pb.WATCHED_SERVICES
    assert set(pb.KNOWN_CAUSES) == set(nr.RECOMMENDED_CAUSES)
    assert set(pb.SCOPES) == {s.value for s in ne.Scope}
    families = set(nr._SOURCE_FAMILY.values()) | {
        nr.FAMILY_CORRELATION,
        nr.FAMILY_PEERS,
    }
    assert set(pb.SOURCE_FAMILIES) == families


def test_config_areas_and_chain_states_match_their_modules() -> None:
    assert set(pb.CONFIG_AREAS) == set(cc.AREAS)
    risky = {a for a, r in cc.AREA_DEFAULT_RISK.items() if r in ("high", "critical")}
    assert set(pb.CRITICAL_CONFIG_AREAS) == risky
    assert pb.CHAIN_STAGES == tuple(s.value for s in dm.Stage)
    assert pb.CHAIN_STATES == tuple(s.value for s in dm.StageState)


def test_every_incident_type_maps_to_one_playbook_or_one_reason() -> None:
    mapped: dict[str, list[str]] = {}
    for p in pb.PLAYBOOKS.values():
        for t in p.detection.incident_types:
            mapped.setdefault(t, []).append(p.playbook_id)
    for t in pb.KNOWN_INCIDENT_TYPES:
        if t == "system_service_restart":
            continue
        in_pb = len(mapped.get(t, []))
        in_none = 1 if t in pb.NO_PLAYBOOK_REASONS else 0
        assert in_pb + in_none == 1, t
    services = [s for p in pb.PLAYBOOKS.values() for s in p.detection.services]
    assert len(services) == len(set(services))
    assert "network" not in services


def test_detection_marks_what_is_missing() -> None:
    for p in pb.PLAYBOOKS.values():
        d = p.detection
        if d.availability is pb.Availability.AVAILABLE:
            assert d.missing is None
            assert d.incident_types
        else:
            assert d.missing in pb.TEXT_DE
    f = pb.PLAYBOOKS["drift_recovery"].detection
    assert f.availability is pb.Availability.NOT_AVAILABLE
    assert f.incident_types == ()
    a = pb.PLAYBOOKS["dns_recovery"].detection
    assert a.availability is pb.Availability.PARTIAL
    assert a.missing == "dns_resolution_probe"


def test_steps_are_typed_and_name_their_sources() -> None:
    for p in pb.PLAYBOOKS.values():
        ids = [s.step_id for s in p.steps]
        assert len(ids) == len(set(ids)), p.playbook_id
        kinds = [s.kind for s in p.steps]
        assert pb.StepKind.PROPOSE in kinds
        for s in p.steps:
            if s.kind is pb.StepKind.READ:
                assert s.sources, s.step_id
                assert s.concludes
            if s.kind is pb.StepKind.DEFERRED:
                assert s.deferred_to in {"C2", "G", "H", "K"}
                assert not s.sources
            for code in s.cannot_know:
                assert code in pb.TEXT_DE


def test_every_code_has_a_german_text() -> None:
    for p in pb.PLAYBOOKS.values():
        for code in (
            p.playbook_id,
            *p.never_rules,
            *p.abort_conditions,
            *p.escalation,
        ):
            assert code in pb.TEXT_DE, code
    for reason in pb.NO_PLAYBOOK_REASONS.values():
        assert reason in pb.TEXT_DE


def test_registry_table_is_plain_json() -> None:
    rows = pb.registry_table()
    assert json.loads(json.dumps(rows)) == rows
    assert [r["letter"] for r in rows] == list("ABCDEFG")


def test_a_broken_definition_never_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    good = pb._PLAYBOOKS
    bad = dataclasses.replace(good[0], preflight=("router_reachable", "made_up"))
    monkeypatch.setattr(pb, "_PLAYBOOKS", (bad, *good[1:]))
    with pytest.raises(pb.PlaybookError):
        pb._check_registry()
    bad = dataclasses.replace(good[0], may_propose=("client.deauth",))
    monkeypatch.setattr(pb, "_PLAYBOOKS", (bad, *good[1:]))
    with pytest.raises(hc.CatalogError):
        pb._check_registry()
    bad = dataclasses.replace(good[2], excluded=("wifi.radio_restart",))
    monkeypatch.setattr(pb, "_PLAYBOOKS", (bad, *good[1:]))
    with pytest.raises(pb.PlaybookError):
        pb._check_registry()


# ---------------------------------------------------------------------------
# Order test 10: DNS repair plan (Playbook A)
# ---------------------------------------------------------------------------


def test_order_10_dns_repair_plan_proposes_dnsmasq_restart() -> None:
    a = assess()
    assert a.match.status is MS.MATCHED
    assert a.match.playbook_id == "dns_recovery"
    f = a.finding
    assert f is not None
    assert f.status is FS.PROPOSAL
    assert f.cause_class == "dns_service_down"
    assert f.proposal is not None
    assert f.proposal.action_type == "service.restart"
    assert dict(f.proposal.params) == {"service": "dnsmasq"}
    assert f.incident_facts.cause_outside_router is False
    assert f.incident_facts.target_fact is hp.TargetFact.DIRECT
    assert f.incident_facts.source_families == 2
    assert "rec_restart_dnsmasq_with_approval" in f.recommendations
    assert "wont_execute_in_observe_release" in f.will_not
    # the plan's steps, with the later ones marked for their packages
    assert [s.step_id for s in f.steps] == [
        "dns_service_state",
        "local_resolver",
        "upstream_resolver",
        "config_and_logs",
        "affected_clients",
        "propose",
        "controlled_restart",
        "recheck_dns",
        "document",
    ]
    assert step(f, "dns_service_state").conclusion == "enabled_and_faulty"
    assert step(f, "local_resolver").conclusion == "fails"
    assert step(f, "upstream_resolver").conclusion == "healthy"
    for later in ("controlled_restart", "recheck_dns", "document"):
        assert step(f, later).outcome is pb.StepOutcome.NOT_IN_RELEASE
    # verification probes come from the catalog
    v = pb.PLAYBOOKS["dns_recovery"].verification
    for probe in hc.CATALOG["service.restart"].verification_probes:
        assert probe in v


def test_order_10_dns_plan_goes_through_the_gate_and_never_executes() -> None:
    f = finding_of()
    v = gate(f, M.OBSERVE)
    assert v is not None
    assert v.permission is P.RECOMMEND
    assert v.executable_now is False
    v = gate(f, M.APPROVAL)
    assert v is not None
    assert v.permission is P.NEEDS_APPROVAL
    assert v.executable_now is False
    # Auto-Heal with the action allowlisted still needs an approval (Risk 2)
    allow = (hm.AllowEntry(action_type="service.restart", params={}, max_risk=1),)
    v = gate(f, M.AUTO_HEAL, allowlist=allow)
    assert v is not None
    assert v.permission in (P.NEEDS_APPROVAL, P.NONE, P.RECOMMEND)
    assert v.executable_now is False


def test_dns_local_failure_with_unknown_service_state_is_recommendation_only() -> None:
    f = finding_of(ev=evidence(services={}))
    assert f.proposal is None
    assert f.status is FS.RECOMMENDATION_ONLY
    assert f.cause_class == "local_resolver_failing"


# ---------------------------------------------------------------------------
# Never-rule A: cause outside the router -> never a restart
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "over",
    [
        {"wan_up": False},
        {"chain": {"gateway": "failed"}},
        {"chain": {"internet": "failed"}},
        {"dns": pb.DnsFact(local_ok=True, upstream_ok=False)},
    ],
)
def test_never_restart_when_cause_is_outside_the_router(over: dict[str, Any]) -> None:
    base: dict[str, Any] = {
        "services": {"dnsmasq": healthy_svc()},
        "dns": pb.DnsFact(),
    }
    base.update(over)
    f = finding_of(ev=evidence(**base))
    assert f.incident_facts.cause_outside_router is True
    assert f.proposal is None
    assert f.cause_class == "cause_outside_router"
    assert "wont_restart_cause_outside" in f.will_not
    assert "never_restart_cause_outside" in f.reasons
    assert gate(f) is None


def test_outside_cause_wins_even_with_a_faulty_dnsmasq() -> None:
    # outside and inside signals together: cannot be told -> None, no restart
    f = finding_of(ev=evidence(wan_up=False, chain={"wan": "failed"}))
    assert f.incident_facts.cause_outside_router is None
    assert f.proposal is None


def test_ni_cause_wan_down_counts_as_outside() -> None:
    f = finding_of(
        incident(cause="wan_down"),
        evidence(services={"dnsmasq": healthy_svc()}, dns=pb.DnsFact()),
    )
    assert f.incident_facts.cause_outside_router is True
    assert f.proposal is None


def test_policy_refuses_restart_when_cause_outside_even_if_forced() -> None:
    """Belt and braces: the policy itself says Not Safe for an outside cause."""
    f = finding_of()
    forced = dataclasses.replace(f.incident_facts, cause_outside_router=True)
    inp = hp.DecisionInput(
        action_type="service.restart",
        params={"service": "dnsmasq"},
        incident=forced,
        context=ctx(),
        prior_failed_attempts=0,
    )
    d = hp.decide(inp)
    assert d.outcome is hm.DecisionOutcome.NOT_SAFE


# ---------------------------------------------------------------------------
# Unknown evidence -> cause_outside_router None, recommendation only
# ---------------------------------------------------------------------------


def test_unknown_evidence_gives_none_and_recommendation_only() -> None:
    bare = pb.Evidence(role="gateway")
    for inc in (
        incident(),
        incident(service="odhcpd"),
        incident(incident_type="wifi_mass_disconnect", service=None, cause=None),
        incident(incident_type="lan_port_flap", service=None, cause=None),
        incident(incident_type="wan_down", service=None, cause=None),
        incident(incident_type="wifi_roam_flapping", service=None, cause=None),
    ):
        f = finding_of(inc, bare)
        assert f.incident_facts.cause_outside_router is None, inc.incident_type
        assert f.proposal is None
        assert f.status in (FS.RECOMMENDATION_ONLY, FS.NOTHING_TO_REPAIR)
        assert any(s.outcome is pb.StepOutcome.UNKNOWN for s in f.steps)


def test_dns_inside_signal_without_healthy_outside_is_unknown() -> None:
    ev = evidence(wan_up=None, dns=pb.DnsFact(), chain={})
    f = finding_of(ev=ev)
    assert f.incident_facts.cause_outside_router is None
    assert f.proposal is None
    assert "rec_check_wan_and_upstream_dns" in f.recommendations


# ---------------------------------------------------------------------------
# Order test 11: DHCP (Playbook B)
# ---------------------------------------------------------------------------


def dhcp_ev(**over: Any) -> pb.Evidence:
    base: dict[str, Any] = {
        "services": {"dnsmasq": healthy_svc(), "odhcpd": svc()},
        "dhcp": pb.DhcpFact(daemons=("odhcpd",), pool_usage_pct=30),
    }
    base.update(over)
    return evidence(**base)


def test_order_11_dhcp_restarts_only_the_daemon_that_serves() -> None:
    f = finding_of(incident(service="odhcpd", cause="dhcp_server"), dhcp_ev())
    assert f.playbook_id == "dhcp_recovery"
    assert f.status is FS.PROPOSAL
    assert f.proposal is not None
    assert dict(f.proposal.params) == {"service": "odhcpd"}
    assert f.incident_facts.cause_outside_router is False
    assert "wont_delete_leases" in f.will_not
    v = gate(f, M.APPROVAL)
    assert v is not None and v.permission is P.NEEDS_APPROVAL
    assert v.executable_now is False


def test_order_11_dhcp_no_ip_picks_the_single_serving_daemon() -> None:
    ev = dhcp_ev(
        services={"dnsmasq": svc(), "odhcpd": healthy_svc()},
        dhcp=pb.DhcpFact(daemons=("dnsmasq",), pool_usage_pct=30),
    )
    f = finding_of(
        incident(incident_type="wifi_no_ip", service=None, cause="dhcp_server"), ev
    )
    assert f.proposal is not None
    assert dict(f.proposal.params) == {"service": "dnsmasq"}


def test_order_11_dhcp_restart_of_a_daemon_that_does_not_serve_is_refused() -> None:
    ev = dhcp_ev(dhcp=pb.DhcpFact(daemons=("dnsmasq",)))
    f = finding_of(incident(service="odhcpd"), ev)
    assert f.proposal is None
    assert f.cause_class == "daemon_not_serving_dhcp"
    assert "wont_restart_unknown_daemon" in f.will_not


@pytest.mark.parametrize("daemons", [None, (), ("dnsmasq", "odhcpd")])
def test_dhcp_unknown_daemon_is_recommendation_only(daemons: Any) -> None:
    ev = dhcp_ev(dhcp=pb.DhcpFact(daemons=daemons))
    f = finding_of(
        incident(incident_type="wifi_dhcp_after_connect", service=None, cause=None),
        ev,
    )
    assert f.proposal is None
    assert f.cause_class == "dhcp_daemon_unknown"
    assert "never_restart_unknown_daemon" in f.reasons


def test_never_restart_for_pool_exhaustion() -> None:
    for inc, pool in (
        (incident(incident_type="dhcp_pool_full", service=None, cause=None), 50),
        (incident(service="odhcpd"), 95),
    ):
        f = finding_of(
            inc, dhcp_ev(dhcp=pb.DhcpFact(daemons=("odhcpd",), pool_usage_pct=pool))
        )
        assert f.cause_class == "pool_exhausted"
        assert f.proposal is None
        assert "wont_restart_for_pool" in f.will_not
        assert "rec_enlarge_pool_or_shorten_lease" in f.recommendations


def test_service_fact_disabled_is_never_faulty() -> None:
    assert pb.ServiceFact(running=False, enabled=False).faulty is False
    assert pb.ServiceFact(running=False, enabled=False, crash_loop=True).faulty is False
    assert pb.ServiceFact(running=False, enabled=None).faulty is None
    assert pb.ServiceFact(running=False, enabled=True).faulty is True
    assert pb.ServiceFact(running=True, enabled=True, restarts_24h=2).faulty is True
    assert pb.ServiceFact(running=True, enabled=True, crash_loop=False).faulty is False
    assert pb.ServiceFact(running=True, enabled=True).faulty is None


@pytest.mark.parametrize("cause", ["static_ip", "wrong_network", "client_side"])
def test_dhcp_cause_outside_names_client_side_causes(cause: str) -> None:
    inc = incident(service="odhcpd", cause=cause)
    assert pb.dhcp_cause_outside(inc, dhcp_ev(), "odhcpd") is True
    # also on the pool-full path, where the derivation is passed through
    f = finding_of(
        incident(incident_type="dhcp_pool_full", service=None, cause=cause),
        dhcp_ev(),
    )
    assert f.incident_facts.cause_outside_router is True
    assert (
        pb.dhcp_cause_outside(incident(service="odhcpd"), dhcp_ev(), "odhcpd") is False
    )
    assert pb.dhcp_cause_outside(incident(service="odhcpd"), dhcp_ev(), None) is None


def test_dhcp_conflict_is_outside_and_recommendation_only() -> None:
    f = finding_of(
        incident(incident_type="dhcp_conflict", service=None, cause="ip_conflict"),
        dhcp_ev(),
    )
    assert f.cause_class == "address_conflict"
    assert f.incident_facts.cause_outside_router is True
    assert f.proposal is None


@pytest.mark.parametrize("cause", ["static_ip", "wrong_network", "client_side"])
def test_dhcp_client_side_cause_never_restarts(cause: str) -> None:
    f = finding_of(incident(service="odhcpd", cause=cause), dhcp_ev())
    assert f.incident_facts.cause_outside_router is True
    assert f.proposal is None


def test_never_lease_deletion_and_no_client_action_exists() -> None:
    for key, e in hc.CATALOG.items():
        assert not key.startswith(("dhcp.", "client.", "wpad.", "network."))
        assert "lease" not in key
        assert "deauth" not in key and "block" not in key and "kick" not in key
        assert e.target_kind is None or e.target_kind.value != "client"
    assert hc.refusal_reason("dhcp.lease_delete") == "never_dhcp_lease_delete"
    assert hc.refusal_reason("client.deauth") == "never_client_action"
    for name in ("dhcp.lease_delete", "client.deauth", "client.block", "client.roam"):
        with pytest.raises(hc.CatalogError):
            hc.validate(name, {})
    # and every DHCP finding says it will not delete leases
    for inc in (
        incident(service="odhcpd"),
        incident(incident_type="dhcp_pool_full", service=None),
        incident(incident_type="wifi_no_ip", service=None),
    ):
        f = finding_of(inc, dhcp_ev())
        assert "never_delete_leases" in f.reasons
        assert "wont_delete_leases" in f.will_not


# ---------------------------------------------------------------------------
# Order test 12: WLAN radio recovery (Playbook C)
# ---------------------------------------------------------------------------


def radio_ev(**radio: Any) -> pb.Evidence:
    base: dict[str, Any] = {
        "name": "radio1",
        "up": False,
        "wireless_uplink": False,
        "on_mgmt_path": False,
        "carries_dependants": False,
        "clients": 7,
        "failures_24h": 3,
        "interference": False,
    }
    base.update(radio)
    return evidence(radio=pb.RadioFact(**base))


def radio_inc(**over: Any) -> pb.IncidentInput:
    base: dict[str, Any] = {
        "incident_type": "wifi_mass_disconnect",
        "scope": "router",
        "service": None,
        "cause": "radio_restart",
    }
    base.update(over)
    return incident(**base)


def test_order_12_radio_recovery_is_recommendation_with_reason() -> None:
    f = finding_of(radio_inc(), radio_ev())
    assert f.playbook_id == "radio_recovery"
    assert f.status is FS.RECOMMENDATION_ONLY
    assert f.cause_class == "radio_recurring_failure"
    assert f.proposal is None
    assert [w.action_type for w in f.withheld] == ["wifi.radio_restart"]
    assert f.withheld[0].reason == "action_disabled"
    assert "wont_restart_radio_disabled" in f.will_not
    assert "rec_radio_restart_manual_with_approval" in f.recommendations
    assert f.incident_facts.cause_outside_router is False
    assert gate(f) is None


def test_never_radio_restart_on_a_wireless_uplink() -> None:
    for uplink in (True, None):
        f = finding_of(radio_inc(), radio_ev(wireless_uplink=uplink))
        assert f.proposal is None
        assert "never_restart_wireless_uplink" in f.reasons
        assert "wont_restart_wireless_uplink" in f.will_not
        assert "rec_check_uplink_by_hand" in f.recommendations
        assert not f.withheld  # not even considered


def test_never_radio_restart_on_uplink_even_when_catalog_enables_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The day the catalog enables wifi.radio_restart, the uplink rule holds."""
    enabled = dataclasses.replace(
        hc.CATALOG["wifi.radio_restart"],
        status=hc.CatalogStatus.READY,
        status_reason=None,
    )
    patched = dict(hc.CATALOG)
    patched["wifi.radio_restart"] = enabled
    monkeypatch.setattr(hc, "CATALOG", patched)
    f = finding_of(radio_inc(), radio_ev(wireless_uplink=True))
    assert f.proposal is None
    assert "never_restart_wireless_uplink" in f.reasons
    f = finding_of(radio_inc(), radio_ev(carries_dependants=True))
    assert f.proposal is None
    assert "never_restart_radio_carrying_dependants" in f.reasons
    f = finding_of(radio_inc(), radio_ev(on_mgmt_path=True))
    assert f.proposal is None
    assert "never_restart_radio_on_mgmt_path" in f.reasons


def test_radio_channel_change_is_normal_not_a_fault() -> None:
    f = finding_of(
        radio_inc(incident_type="wifi_radio_change", cause="radio_change"),
        radio_ev(failures_24h=0),
    )
    assert f.status is FS.NOTHING_TO_REPAIR
    assert f.cause_class == "channel_change_normal"


def test_radio_interference_is_outside() -> None:
    f = finding_of(radio_inc(cause="interference"), radio_ev(interference=True))
    assert f.incident_facts.cause_outside_router is True
    assert f.cause_class == "rf_interference"


def test_radio_single_drop_is_observed_only() -> None:
    f = finding_of(radio_inc(), radio_ev(failures_24h=1))
    assert f.cause_class == "single_drop"
    assert "rec_observe_radio" in f.recommendations


def test_hostapd_and_wpad_restart_map_to_c_and_never_restart_wpad() -> None:
    for service in ("hostapd", "wpad"):
        a = assess(incident(service=service, cause=None), radio_ev())
        assert a.match.playbook_id == "radio_recovery"
        assert a.finding is not None
        assert "never_restart_wpad" in a.finding.reasons
        assert a.finding.proposal is None


# ---------------------------------------------------------------------------
# Playbook D: never down/up of an uplink or management interface
# ---------------------------------------------------------------------------


def port_inc(**over: Any) -> pb.IncidentInput:
    base: dict[str, Any] = {
        "incident_type": "lan_uplink_down",
        "scope": "port",
        "service": None,
        "cause": "uplink_down",
    }
    base.update(over)
    return incident(**base)


@pytest.mark.parametrize(
    "itf",
    [
        {"role": "uplink"},
        {"role": "management"},
        {"role": "lan", "on_mgmt_path": True},
        {"role": "lan", "carries_dependants": True},
        {"role": "lan"},  # dependants and mgmt path unknown
    ],
)
def test_never_cycle_uplink_or_management_interface(itf: dict[str, Any]) -> None:
    f = finding_of(
        port_inc(), evidence(interface=pb.InterfaceFact(link_up=False, **itf))
    )
    assert f.proposal is None
    assert f.status is FS.RECOMMENDATION_ONLY
    assert "never_cycle_uplink_or_mgmt" in f.reasons
    assert "wont_cycle_uplink_or_mgmt" in f.will_not
    assert "rec_check_uplink_by_hand" in f.recommendations


@pytest.mark.parametrize(
    "itf",
    [
        {"role": "uplink", "on_mgmt_path": False, "carries_dependants": False},
        {"role": "management", "on_mgmt_path": False, "carries_dependants": False},
        {"role": "lan", "on_mgmt_path": False, "carries_dependants": None},
        {"role": "lan", "on_mgmt_path": None, "carries_dependants": False},
    ],
)
def test_never_cycle_by_role_or_unknown_dependants_alone(itf: dict[str, Any]) -> None:
    """Each condition on its own makes the interface critical."""
    f = finding_of(
        port_inc(), evidence(interface=pb.InterfaceFact(link_up=False, **itf))
    )
    assert f.proposal is None
    assert "never_cycle_uplink_or_mgmt" in f.reasons
    assert "wont_cycle_uplink_or_mgmt" in f.will_not
    assert step(f, "uplink_dependencies").conclusion == "uplink_or_mgmt"


def test_interface_on_an_edge_port_is_still_recommendation_only() -> None:
    itf = pb.InterfaceFact(
        role="lan",
        link_up=True,
        errors_high=True,
        on_mgmt_path=False,
        carries_dependants=False,
    )
    f = finding_of(port_inc(incident_type="lan_port_errors"), evidence(interface=itf))
    assert f.proposal is None
    assert f.cause_class == "port_errors"
    assert "never_automatic_interface_change" in f.reasons
    assert "never_cycle_uplink_or_mgmt" not in f.reasons
    assert [w.action_type for w in f.withheld] == ["interface.cycle"]


def test_interface_upstream_router_down_is_outside() -> None:
    itf = pb.InterfaceFact(role="uplink", link_up=False, upstream_router_down=True)
    f = finding_of(port_inc(), evidence(interface=itf))
    assert f.incident_facts.cause_outside_router is True
    assert f.cause_class == "upstream_router_down"


# ---------------------------------------------------------------------------
# Order test 13: WAN recovery (Playbook E)
# ---------------------------------------------------------------------------


def wan_inc(**over: Any) -> pb.IncidentInput:
    base: dict[str, Any] = {
        "incident_type": "wan_down",
        "service": None,
        "cause": "wan_down",
    }
    base.update(over)
    return incident(**base)


def test_order_13_isp_outage_means_nothing_to_repair_on_the_router() -> None:
    ev = evidence(
        wan=pb.WanFact(link_up=True, interface_up=True, has_address=True),
        chain={"router": "healthy", "gateway": "healthy", "internet": "failed"},
    )
    f = finding_of(wan_inc(), ev)
    assert f.playbook_id == "wan_recovery"
    assert f.status is FS.NOTHING_TO_REPAIR
    assert f.cause_class == "isp_outage"
    assert f.incident_facts.cause_outside_router is True
    assert "rec_wait_for_provider" in f.recommendations
    assert "wont_reboot" in f.will_not
    assert f.proposal is None


@pytest.mark.parametrize(
    ("wan", "chain", "cause", "rec"),
    [
        ({"link_up": False}, {}, "wan_link_down", "rec_check_modem_and_cable"),
        (
            {"link_up": True, "interface_up": True, "has_address": False},
            {},
            "wan_no_address",
            "rec_check_wan_settings",
        ),
        (
            {"link_up": True, "interface_up": False},
            {},
            "local_wan_fault",
            "rec_check_wan_settings",
        ),
        (
            {"link_up": True, "interface_up": True, "has_address": True},
            {"internet": "healthy", "dns": "failed"},
            "dns_only",
            "rec_follow_dns_playbook",
        ),
        ({}, {}, "cause_unknown", "rec_refresh_and_diagnose"),
    ],
)
def test_order_13_wan_classification(
    wan: dict[str, Any], chain: dict[str, str], cause: str, rec: str
) -> None:
    f = finding_of(wan_inc(), evidence(wan=pb.WanFact(**wan), chain=chain))
    assert f.cause_class == cause
    assert rec in f.recommendations
    assert f.proposal is None
    assert "never_reboot_as_standard" in f.reasons


def test_wan_playbook_is_gateway_only() -> None:
    a = assess(wan_inc(), evidence(role="access_point"))
    assert a.match.status is MS.UNSUPPORTED
    assert a.match.reason == "role_not_supported"
    assert a.finding is not None and a.finding.proposal is None


def test_no_reboot_is_proposed_anywhere() -> None:
    for p in pb.PLAYBOOKS.values():
        assert "router.reboot" not in p.may_propose
        assert "router.reboot" not in p.modelled
    rng = random.Random(1530)
    for _ in range(1500):
        f = _random_assessment(rng).finding
        if f is not None and f.proposal is not None:
            assert f.proposal.action_type == "service.restart"


# ---------------------------------------------------------------------------
# Order test 14: drift plan shape (Playbook F)
# ---------------------------------------------------------------------------

BKP = "bkp_" + "a" * 32


def drift_ev(**cfg: Any) -> pb.Evidence:
    base: dict[str, Any] = {
        "version_known": True,
        "version_id": BKP,
        "diff_proven": True,
        "changed_areas": ("dhcp",),
        "change_risk": "medium",
        "restore_check": "compatible",
        "backup_present": True,
    }
    base.update(cfg)
    return dhcp_ev(config=pb.ConfigFact(**base))


def test_order_14_drift_plan_shape() -> None:
    a = assess(incident(service="odhcpd"), drift_ev())
    assert a.match.playbook_id == "drift_recovery"
    assert a.match.drift_overlay is True
    f = a.finding
    assert f is not None
    assert f.status is FS.RECOMMENDATION_ONLY
    assert f.proposal is None
    assert f.plan is not None
    plan = f.plan
    assert plan.version_id == BKP
    assert plan.relevant_areas == ("dhcp",)
    assert plan.critical_areas == ()
    assert plan.restore_check == "compatible"
    assert plan.manual_steps == pb.DRIFT_MANUAL_STEPS
    assert plan.requires_explicit_approval is True
    assert plan.executes is False
    assert f.incident_facts.cause_outside_router is False
    assert [w.action_type for w in f.withheld] == ["config.restore"]
    assert f.withheld[0].reason == "restore_dry_run_only"
    for later in ("request_approval", "secured_restore", "verify"):
        assert step(f, later).outcome is pb.StepOutcome.NOT_IN_RELEASE
    d = f.to_dict()
    assert json.loads(json.dumps(d)) == d
    assert d["plan"]["executes"] is False


def test_never_automatic_restore() -> None:
    f = finding_of(incident(service="odhcpd"), drift_ev())
    assert "never_automatic_restore" in f.reasons
    assert "wont_restore_automatically" in f.will_not
    assert pb.to_decision_input(f, context=ctx()) is None
    assert hc.CATALOG["config.restore"].status is hc.CatalogStatus.DISABLED
    with pytest.raises(pb.PlaybookError):
        dataclasses.replace(f.plan, executes=True)  # type: ignore[arg-type]
    with pytest.raises(pb.PlaybookError):
        dataclasses.replace(f.plan, requires_explicit_approval=False)  # type: ignore[arg-type]


def test_never_automatic_rollback_of_critical_configuration() -> None:
    inc = port_inc(incident_type="lan_port_flap")
    ev = evidence(
        interface=pb.InterfaceFact(role="lan", link_up=True),
        config=pb.ConfigFact(
            diff_proven=True, changed_areas=("vlan",), change_risk="critical"
        ),
    )
    f = finding_of(inc, ev)
    assert f.playbook_id == "drift_recovery"
    assert f.plan is not None and f.plan.critical_areas == ("vlan",)
    assert "never_automatic_rollback_critical" in f.reasons
    assert "wont_rollback_critical_config" in f.will_not
    assert f.proposal is None


def test_drift_overlay_needs_a_diff_not_only_time() -> None:
    a = assess(incident(service="odhcpd"), drift_ev(diff_proven=False))
    assert a.match.playbook_id == "dhcp_recovery"
    a = assess(incident(service="odhcpd"), drift_ev(diff_proven=None))
    assert a.match.playbook_id == "dhcp_recovery"
    # a change in an unrelated area does not divert either
    a = assess(incident(service="odhcpd"), drift_ev(changed_areas=("firewall",)))
    assert a.match.playbook_id == "dhcp_recovery"


def test_drift_needs_config_capabilities() -> None:
    ev = dataclasses.replace(
        drift_ev(), capabilities={"config.capture": False, "data.services": True}
    )
    a = assess(incident(service="odhcpd"), ev)
    assert a.match.status is MS.UNSUPPORTED
    assert a.match.missing == ("config.capture",)


# ---------------------------------------------------------------------------
# Playbook G: never a client action
# ---------------------------------------------------------------------------


def client_inc(**over: Any) -> pb.IncidentInput:
    base: dict[str, Any] = {
        "incident_type": "wifi_reconnect_storm",
        "scope": "client",
        "service": None,
        "cause": None,
    }
    base.update(over)
    return incident(**base)


@pytest.mark.parametrize(
    ("over", "client", "cause"),
    [
        ({"cause": "psk_wrong"}, {}, "client_side"),
        ({}, {"ap_available": False}, "ap_unavailable"),
        ({}, {"dhcp_dns_anomaly": True}, "dhcp_dns_side"),
        ({"incident_type": "wifi_roam_flapping"}, {}, "roaming_flapping"),
        ({}, {"weak_signal": True}, "weak_signal"),
        ({}, {}, "cause_unknown"),
    ],
)
def test_client_playbook_never_touches_the_client(
    over: dict[str, Any], client: dict[str, Any], cause: str
) -> None:
    f = finding_of(client_inc(**over), evidence(client=pb.ClientFact(**client)))
    assert f.playbook_id == "client_recovery"
    assert f.cause_class == cause
    assert f.proposal is None
    assert not f.withheld
    assert "never_client_action" in f.reasons
    assert "wont_touch_client" in f.will_not


def test_client_playbook_names_no_catalog_action() -> None:
    p = pb.PLAYBOOKS["client_recovery"]
    assert p.may_propose == () and p.modelled == ()
    assert p.risk_class == hm.RiskClass.READ_ONLY


# ---------------------------------------------------------------------------
# Order test 34: incident correlation -> playbook, root only
# ---------------------------------------------------------------------------


def test_order_34_only_root_incidents_get_a_playbook() -> None:
    root = assess(incident(is_root=True))
    assert root.match.playbook_id == "dns_recovery"
    child = assess(incident(is_root=False))
    assert child.match.status is MS.NO_PLAYBOOK
    assert child.match.reason == "not_root_incident"
    assert child.finding is None
    unknown = assess(incident(is_root=None))
    assert unknown.match.reason == "root_unknown"
    assert unknown.finding is None


def test_order_34_root_and_its_children_give_exactly_one_playbook() -> None:
    """A wan_down root with dnsmasq/odhcpd children: one plan, for the root."""
    ev = evidence(
        wan=pb.WanFact(link_up=False),
        chain={"wan": "failed"},
        wan_up=False,
    )
    group = [
        wan_inc(is_root=True),
        incident(is_root=False, cause="wan_down"),
        incident(service="odhcpd", is_root=False),
        client_inc(is_root=False),
    ]
    findings = [a.finding for a in (pb.assess(i, ev) for i in group) if a.finding]
    assert [f.playbook_id for f in findings] == ["wan_recovery"]


def test_temporal_only_correlation_matches_nothing_actionable() -> None:
    for inc in (
        incident(temporal_only=True),
        incident(temporal_only=None, source_families=("correlation",)),
        radio_inc(temporal_only=True),
        port_inc(temporal_only=True),
    ):
        a = assess(inc)
        assert a.match.status is MS.NO_PLAYBOOK
        assert a.match.reason == "temporal_correlation_only"
        assert a.finding is None


def test_correlation_family_does_not_count_as_evidence() -> None:
    f = finding_of(incident(source_families=("log", "correlation")))
    assert f.incident_facts.source_families == 1


def test_temporal_only_unknown_never_proposes() -> None:
    f = finding_of(incident(temporal_only=None))
    assert f.proposal is None


def test_fleet_scope_and_unknown_types_have_no_playbook() -> None:
    assert assess(incident(scope="fleet")).match.reason == "fleet_scope"
    assert assess(incident(incident_type="nope")).match.reason == (
        "unknown_incident_type"
    )
    assert assess(incident(service="network")).match.reason == "service_not_covered"
    assert assess(incident(service=None)).match.reason == "service_not_covered"
    for t, reason in pb.NO_PLAYBOOK_REASONS.items():
        a = assess(incident(incident_type=t, service=None))
        assert a.match.status is MS.NO_PLAYBOOK
        assert a.match.reason == reason
        assert a.finding is None


def test_matcher_is_deterministic_and_returns_at_most_one() -> None:
    rng = random.Random(34)
    for _ in range(400):
        inc, ev = _random_case(rng)
        first = pb.match(inc, ev)
        for _ in range(3):
            assert pb.match(inc, ev) == first
        assert first.playbook_id is None or first.playbook_id in pb.PLAYBOOKS
        if first.status is MS.NO_PLAYBOOK:
            assert first.playbook_id is None


def test_matcher_rejects_foreign_input_types() -> None:
    with pytest.raises(pb.PlaybookError):
        pb.match({"incident_type": "wan_down"}, evidence())  # type: ignore[arg-type]
    with pytest.raises(pb.PlaybookError):
        pb.match(incident(), {})  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Fleet facts
# ---------------------------------------------------------------------------


def smallest_ap() -> pb.Evidence:
    """dnsmasq and odhcpd are switched off on purpose here."""
    off = pb.ServiceFact(running=False, enabled=False)
    return evidence(
        role="access_point",
        services={"dnsmasq": off, "odhcpd": off},
        wan_up=None,
        dhcp=pb.DhcpFact(daemons=()),
        dns=pb.DnsFact(),
        chain={},
    )


def test_fleet_smallest_ap_services_off_on_purpose_is_no_fault() -> None:
    for inc in (incident(), incident(service="odhcpd")):
        f = finding_of(inc, smallest_ap())
        assert f.proposal is None
        assert f.status in (FS.NOTHING_TO_REPAIR, FS.RECOMMENDATION_ONLY)
        assert "rec_restart_dnsmasq_with_approval" not in f.recommendations
        assert gate(f) is None
    f = finding_of(incident(), smallest_ap())
    assert f.status is FS.NOTHING_TO_REPAIR
    assert f.cause_class == "service_disabled_on_purpose"
    assert "wont_restart_disabled_service" in f.will_not


def test_disabled_service_is_never_a_restart_candidate_even_if_daemon_listed() -> None:
    off = pb.ServiceFact(running=False, enabled=False)
    ev = evidence(
        role="access_point",
        services={"odhcpd": off},
        dhcp=pb.DhcpFact(daemons=("odhcpd",)),
    )
    f = finding_of(incident(service="odhcpd"), ev)
    assert f.status is FS.NOTHING_TO_REPAIR
    assert f.proposal is None


def repeater(**over: Any) -> pb.Evidence:
    """A repeater of another vendor: no OpenWrt services, no wireless data."""
    base: dict[str, Any] = {
        "role": "access_point",
        "capabilities": {
            "data.services": False,
            "data.wireless": False,
            "config.capture": False,
            "config.diff": False,
        },
        "services": {},
    }
    base.update(over)
    return evidence(**base)


@pytest.mark.parametrize(
    "inc",
    [
        incident(),
        incident(service="odhcpd"),
        radio_inc(),
        client_inc(),
    ],
)
def test_fleet_repeater_without_capability_is_unsupported(
    inc: pb.IncidentInput,
) -> None:
    a = pb.assess(inc, repeater())
    assert a.match.status is MS.UNSUPPORTED
    assert a.match.reason == "capability_missing"
    assert a.match.missing
    f = a.finding
    assert f is not None
    assert f.status is FS.UNSUPPORTED
    assert f.proposal is None
    assert "capability_missing" in f.reasons
    assert all(s.outcome is pb.StepOutcome.NOT_RUN for s in f.steps)
    assert gate(f) is None


def test_unknown_capability_is_not_missing() -> None:
    ev = evidence(capabilities={})
    a = pb.assess(incident(), ev)
    assert a.match.status is MS.MATCHED


def test_access_point_dns_and_dhcp_playbooks_fit() -> None:
    ev = evidence(role="access_point")
    assert pb.match(incident(), ev).status is MS.MATCHED


# ---------------------------------------------------------------------------
# Hostile strings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", HOSTILE)
def test_hostile_strings_never_reach_a_proposal_or_text(bad: str) -> None:
    inc = incident(
        incident_type=bad,
        scope=bad,
        service=bad,
        cause=bad,
        cause_status=bad,
        cause_level=bad,
        severity=bad,
        source_families=(bad, "log"),
    )
    assert inc.incident_type is None
    assert inc.service is None
    assert inc.cause is None
    assert inc.severity is None
    assert inc.source_families == frozenset({"log"})
    assert pb.assess(inc, evidence()).finding is None
    # hostile values on a real incident type: never in proposal or text
    inc = incident(service="dnsmasq", cause=bad, scope=bad, severity=bad)
    ev = evidence(
        role=bad,
        radio=pb.RadioFact(name=bad),
        config=pb.ConfigFact(version_id=bad, changed_areas=(bad,)),
        dhcp=pb.DhcpFact(daemons=(bad, "dnsmasq")),
        chain={"wan": bad},
        capabilities={bad: True},
    )
    f = finding_of(inc, ev)
    assert bad not in all_text(f)
    if f.proposal is not None:
        assert dict(f.proposal.params) == {"service": "dnsmasq"}


def test_str_subclasses_are_not_catalog_values() -> None:
    inc = incident(service=_Str("dnsmasq"), incident_type=_Str("wan_down"))
    assert inc.service is None and inc.incident_type is None
    f = finding_of(
        incident(service="odhcpd"),
        dhcp_ev(dhcp=pb.DhcpFact(daemons=(_Str("odhcpd"),))),
    )
    assert f.proposal is None
    assert pb.RadioFact(name=_Str("radio0")).name is None


def test_proposal_parameter_is_the_catalogs_own_constant() -> None:
    dynamic = b"dnsmasq".decode()  # a new str object, equal but not the same
    f = finding_of(incident(service=dynamic))
    assert f.proposal is not None
    value = f.proposal.params["service"]
    assert value is pb.PLAYBOOKS["dns_recovery"].service_choices[0]
    assert value is not dynamic


def test_closed_set_members_are_the_modules_constants_not_the_callers() -> None:
    dynamic = b"odhcpd".decode()
    assert dynamic is not pb.WATCHED_SERVICES[1]
    assert incident(service=dynamic).service is pb.WATCHED_SERVICES[1]
    ev = dhcp_ev(dhcp=pb.DhcpFact(daemons=(b"odhcpd".decode(),)))
    assert next(iter(ev.dhcp.daemons)) is hc.SERVICE_NAMES[1]
    f = finding_of(incident(service=dynamic, cause="dhcp_server"), ev)
    assert f.proposal is not None
    value = f.proposal.params["service"]
    assert value == "odhcpd"
    assert value is pb.PLAYBOOKS["dhcp_recovery"].service_choices[1]


def test_texts_are_fixed_and_never_interpolated() -> None:
    for text in pb.TEXT_DE.values():
        assert "{" not in text and "%" not in text
    f = finding_of()
    for t in f.texts_de():
        assert t in pb.TEXT_DE.values()


def test_inputs_never_raise_on_garbage() -> None:
    garbage: list[Any] = [None, 1, 1.5, float("nan"), -1, True, b"x", [], {}, object()]
    for g in garbage:
        inc = pb.IncidentInput(
            incident_type=g,
            confidence=g,
            source_families=g,
            is_root=g,
            affected_clients=g,
        )
        assert inc.incident_type is None
        ev = pb.Evidence(
            role=g, capabilities=g, services=g, chain=g, dns=g, radio=g, config=g
        )
        pb.assess(inc, ev)
        pb.assess(incident(), ev)


# ---------------------------------------------------------------------------
# End to end through heal_policy.gate
# ---------------------------------------------------------------------------


def test_recommendation_only_findings_have_nothing_for_the_policy() -> None:
    f = finding_of(wan_inc(), evidence(wan=pb.WanFact(link_up=False)))
    assert pb.to_decision_input(f, context=ctx()) is None


def test_merge_context_fills_gaps_and_unknowns_conflicts() -> None:
    f = finding_of()
    merged = pb.merge_context(hp.RiskContext(), f.context_facts)
    assert merged.role == "gateway"
    assert merged.service_enabled is True
    merged = pb.merge_context(ctx(role="access_point"), f.context_facts)
    assert merged.role is None
    merged = pb.merge_context(ctx(), {"unknown_field": 1, "role": "gateway"})
    assert merged == ctx()


def test_proposal_on_an_unknown_router_context_is_not_approvable() -> None:
    f = finding_of()
    v = gate(f, M.APPROVAL, context=hp.RiskContext())
    assert v is not None
    assert (
        v.permission is not P.NEEDS_APPROVAL
        or v.decision is None
        or (v.decision.outcome is hm.DecisionOutcome.REQUIRES_APPROVAL)
    )
    assert v.executable_now is False


def _random_case(rng: random.Random) -> tuple[pb.IncidentInput, pb.Evidence]:
    def b() -> bool | None:
        return rng.choice((True, False, None))

    types = sorted(pb.KNOWN_INCIDENT_TYPES) + ["junk"]
    inc = pb.IncidentInput(
        incident_type=rng.choice(types),
        scope=rng.choice(sorted(pb.SCOPES) + [None]),
        service=rng.choice(pb.WATCHED_SERVICES + (None,)),
        cause=rng.choice(sorted(pb.KNOWN_CAUSES) + [None]),
        cause_status=rng.choice(["confirmed", "hypothesis", None]),
        cause_level=rng.choice(["confirmed", "likely", "possible", "unknown"]),
        confidence=rng.choice([0.2, 0.6, 0.9, None]),
        severity=rng.choice(["info", "warning", "critical", None]),
        source_families=rng.sample(sorted(pb.SOURCE_FAMILIES), rng.randint(0, 3)),
        is_root=rng.choice((True, True, False, None)),
        temporal_only=b(),
        evidence_fresh=b(),
        affected_clients=rng.choice([0, 5, None]),
        occurrences=rng.choice([1, 3, None]),
    )

    def s() -> pb.ServiceFact | None:
        return rng.choice(
            [
                None,
                pb.ServiceFact(running=b(), enabled=b(), crash_loop=b()),
                pb.ServiceFact(running=False, enabled=True, restarts_24h=3),
            ]
        )

    services = {k: v for k in ("dnsmasq", "odhcpd") if (v := s()) is not None}
    ev = pb.Evidence(
        role=rng.choice(list(hp.ROLES) + [None]),
        reachable=b(),
        capabilities={
            c: b()
            for c in ("data.services", "data.wireless", "config.capture", "config.diff")
        },
        services=services,
        wan_up=b(),
        dns=pb.DnsFact(local_ok=b(), upstream_ok=b(), log_hint=b()),
        dhcp=pb.DhcpFact(
            daemons=rng.choice([None, (), ("dnsmasq",), ("odhcpd",), hc.SERVICE_NAMES]),
            pool_usage_pct=rng.choice([None, 30, 95]),
        ),
        radio=pb.RadioFact(
            name=rng.choice(["radio0", None]),
            wireless_uplink=b(),
            on_mgmt_path=b(),
            carries_dependants=b(),
            failures_24h=rng.choice([None, 0, 3]),
            interference=b(),
        ),
        interface=pb.InterfaceFact(
            role=rng.choice(list(pb.INTERFACE_ROLES) + [None]),
            link_up=b(),
            errors_high=b(),
            upstream_router_down=b(),
            on_mgmt_path=b(),
            carries_dependants=b(),
        ),
        wan=pb.WanFact(link_up=b(), interface_up=b(), has_address=b()),
        chain={
            st: rng.choice(pb.CHAIN_STATES)
            for st in pb.CHAIN_STAGES
            if rng.random() < 0.5
        },
        config=pb.ConfigFact(
            diff_proven=b(),
            changed_areas=rng.sample(sorted(pb.CONFIG_AREAS), rng.randint(0, 2)),
            change_risk=rng.choice(list(pb.CHANGE_RISKS) + [None]),
            backup_present=b(),
        ),
        client=pb.ClientFact(ap_available=b(), weak_signal=b(), roam_flapping=b()),
    )
    return inc, ev


def _random_assessment(rng: random.Random) -> pb.Assessment:
    inc, ev = _random_case(rng)
    return pb.assess(inc, ev)


def test_invariants_over_random_cases_end_to_end() -> None:
    """No case ever executes; a proposal is at most an approval request, and
    only for service.restart with every fact known and favourable."""
    rng = random.Random(20261127)
    proposals = 0
    for _ in range(3000):
        inc, ev = _random_case(rng)
        a = pb.assess(inc, ev)
        f = a.finding
        if a.match.status is MS.NO_PLAYBOOK:
            assert f is None
            continue
        assert inc.is_root is True and inc.temporal_only is not True
        assert f is not None
        assert "wont_execute_in_observe_release" in f.will_not
        assert all(c in pb.TEXT_DE for c in f.codes())
        if f.proposal is None:
            assert pb.to_decision_input(f, context=ctx()) is None
            continue
        proposals += 1
        p = f.proposal
        assert p.action_type == "service.restart"
        assert f.playbook_id in ("dns_recovery", "dhcp_recovery")
        assert p.params["service"] in pb.PLAYBOOKS[f.playbook_id].service_choices
        facts = f.incident_facts
        assert facts.cause_outside_router is False
        assert facts.temporal_only is False
        assert facts.target_fact is hp.TargetFact.DIRECT
        assert ev.service(p.params["service"]).enabled is True
        if f.playbook_id == "dhcp_recovery":
            assert ev.dhcp.daemons is not None
            assert p.params["service"] in ev.dhcp.daemons
            assert ev.dhcp.pool_usage_pct is None or ev.dhcp.pool_usage_pct < 90
        for mode in (M.OBSERVE, M.APPROVAL, M.AUTO_HEAL):
            for context in (ctx(), hp.RiskContext()):
                v = gate(
                    f,
                    mode,
                    context=context,
                    allowlist=(
                        hm.AllowEntry(
                            action_type="service.restart", params={}, max_risk=1
                        ),
                    ),
                )
                assert v is not None
                assert v.executable_now is False
                assert v.permission in (P.NONE, P.RECOMMEND, P.NEEDS_APPROVAL)
                if v.permission is P.NEEDS_APPROVAL:
                    assert mode is not M.OBSERVE
                    assert v.decision is not None
                    assert v.decision.outcome is hm.DecisionOutcome.REQUIRES_APPROVAL
    assert proposals > 0


def test_approval_only_with_every_fact_known_and_favourable() -> None:
    f = finding_of()
    assert gate(f, M.APPROVAL).permission is P.NEEDS_APPROVAL  # type: ignore[union-attr]
    for over in (
        {"identity_confirmed": None},
        {"concurrent_repair": None},
        {"breaker_open": None},
        {"in_maintenance": None},
        {"open_security_findings": None},
        {"service_config_unapplied": None},
        {"service_dependant_routers": None},
    ):
        v = gate(f, M.APPROVAL, context=ctx(**over))
        assert v is not None
        assert v.permission is not P.NEEDS_APPROVAL, over
        assert v.executable_now is False
    # reachability: unknown in both the context and the playbook's evidence
    f = finding_of(ev=evidence(reachable=None))
    v = gate(f, M.APPROVAL, context=ctx(reachable=None))
    assert v is not None and v.permission is not P.NEEDS_APPROVAL
    # the playbook's evidence and the context disagree: unknown, no approval
    v = gate(f := finding_of(), M.APPROVAL, context=ctx(role="access_point"))
    assert v is not None and v.permission is not P.NEEDS_APPROVAL


def test_module_is_pure() -> None:
    """No HA, no router API, no clock, no I/O in the playbook module."""
    import ast
    import pathlib

    src = pathlib.Path(pb.__file__).read_text(encoding="utf-8")
    names: set[str] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add(("." * node.level) + (node.module or ""))
    assert names <= {
        "__future__",
        "dataclasses",
        "logging",
        "math",
        "collections.abc",
        "enum",
        "types",
        "typing",
        ".",
        ".heal_model",
    }, names
    for banned in ("homeassistant", "api", "coordinator", "heal_store", "time"):
        assert not any(n.split(".")[-1] == banned for n in names)
