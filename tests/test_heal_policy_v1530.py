"""Self-Healing, package D (1.53.0): risk, score, decision, modes, loop policy.

Order tests (Phase 7 order §22) covered here:

* 3  Auto-Heal mode (decision only: what may happen, nothing is executed);
* 4  unauthorised action (unknown id, disabled action, parameters outside
     the closed set, risk 3 through a general switch);
* 7  risk classification (the same action on different roles and
     topologies gets a different risk; context never lowers it);
* 24 repair-loop protection (breaker, fleet pause, the order's dnsmasq
     example);
* 25 cooldown, retry limits and backoff.

Further: the score is reproducible and its contributions sum to the total;
each of the five outcomes is reachable and explained; a link only by time
never yields more than "diagnose"; a held router, a paused fleet, a
maintenance window and an open security finding block as specified;
allowlist validation; an unknown outcome opens the breaker and it stays
open across a restart (round trip through the model types); the policy
runs on safety time only (a wall-clock jump in the inputs changes
nothing); the pure loop rules agree with what the store enforces.

Pure: no Home Assistant instance, no router, no network.
"""

from __future__ import annotations

import dataclasses
import json
import random
from types import MappingProxyType
from typing import Any
from unittest.mock import MagicMock

import pytest

from custom_components.openwrt_router import heal_catalog as hc
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_policy as hp
from custom_components.openwrt_router import heal_store as hs

O = hm.DecisionOutcome
P = hp.Permission
M = hm.HealMode
RC = hm.RiskClass
EV = hp.OutcomeEvent
R1 = "rtr_" + "1" * 32
R2 = "rtr_" + "2" * 32
T0 = 1_790_000_000.0  # a safety-clock time
LIMITS = hm.LoopLimits()

DNSMASQ = {"service": "dnsmasq"}
WRITES = [k for k, e in hc.CATALOG.items() if e.writes]
READS = [k for k, e in hc.CATALOG.items() if not e.writes]


# ---------------------------------------------------------------------------
# Builders: a fully known, benign gateway and a strong, direct incident
# ---------------------------------------------------------------------------


def ctx(**over: Any) -> hp.RiskContext:
    base: dict[str, Any] = {
        "role": "gateway",
        "identity_confirmed": True,
        "reachable": True,
        "dependants": 0,
        "target_on_mgmt_path": False,
        "target_is_wireless_uplink": False,
        "target_carries_dependants": False,
        "service_enabled": True,
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


def inc(**over: Any) -> hp.IncidentFacts:
    base: dict[str, Any] = {
        "incident_type": "system_service_restart",
        "severity": "critical",
        "cause_level": hm.CauseLevel.CONFIRMED,
        "cause_status": hm.CauseStatus.CONFIRMED,
        "confidence": 0.9,
        "source_families": 2,
        "is_root": True,
        "temporal_only": False,
        "evidence_fresh": True,
        "target_fact": hp.TargetFact.DIRECT,
    }
    base.update(over)
    return hp.IncidentFacts(**base)


def dinput(
    action_type: Any = "service.restart",
    params: Any = None,
    *,
    incident: hp.IncidentFacts | None | str = "default",
    context: hp.RiskContext | None = None,
    **over: Any,
) -> hp.DecisionInput:
    if params is None and action_type == "service.restart":
        params = DNSMASQ
    return hp.DecisionInput(
        action_type=action_type,
        params=params,
        incident=inc() if incident == "default" else incident,  # type: ignore[arg-type]
        context=context or ctx(),
        **over,
    )


def decide(*args: Any, **kwargs: Any) -> hp.PolicyDecision:
    return hp.decide(dinput(*args, **kwargs))


def gate(
    decision: hp.PolicyDecision,
    *,
    mode: hm.HealMode = M.OBSERVE,
    allowlist: tuple[hm.AllowEntry, ...] = (),
    **over: Any,
) -> hp.GateVerdict:
    kwargs: dict[str, Any] = {
        "module_enabled": True,
        "held": False,
        "fleet_paused": False,
        "in_maintenance": False,
        "guards_green": True,
    }
    kwargs.update(over)
    return hp.gate(decision, mode=mode, allowlist=allowlist, **kwargs)


def allow(action_type: str, max_risk: int = 1, **params: Any) -> hm.AllowEntry:
    return hm.AllowEntry(action_type=action_type, params=params, max_risk=max_risk)


def all_codes(decision: hp.PolicyDecision) -> set[str]:
    exp = decision.explanation()
    codes = {r["code"] for r in exp["rules"]}
    codes |= {c["reason"] for c in exp["score"]["contributions"]}
    codes |= {c["factor"] for c in exp["score"]["contributions"]}
    codes |= set(exp["risk"]["reasons"])
    codes |= {exp["why"]}
    if exp["why_not"]:
        codes.add(exp["why_not"])
    return codes


# ---------------------------------------------------------------------------
# Risk classification (order test 7)
# ---------------------------------------------------------------------------


def risk(action_type: str, params: Any = None, **over: Any) -> hp.RiskAssessment:
    va = hc.validate(action_type, params)
    return hp.classify_risk(va, ctx(**over))


def test_the_same_service_restart_on_different_roles_has_different_risk() -> None:
    # the gateway: dnsmasq is enabled and serves the network
    gw = risk("service.restart", DNSMASQ, role="gateway", service_enabled=True)
    assert gw.risk_class is RC.MEDIUM and gw.assessed
    # an AP where dnsmasq is disabled on purpose: starting it would put a
    # second DHCP/DNS server on the LAN, and "not running" is no fault
    ap = risk("service.restart", DNSMASQ, role="access_point", service_enabled=False)
    assert ap.risk_class is RC.HIGH
    assert "service_disabled_on_purpose" in ap.reasons


def test_the_same_radio_restart_on_different_topologies_has_different_risk() -> None:
    radio = {"radio": "radio0"}
    wired = risk("wifi.radio_restart", radio, role="access_point")
    assert wired.risk_class is RC.MEDIUM
    uplink = risk(
        "wifi.radio_restart", radio, role="access_point", target_is_wireless_uplink=True
    )
    assert uplink.risk_class is RC.HIGH
    assert "wireless_uplink_radio" in uplink.reasons
    mgmt = risk("wifi.radio_restart", radio, target_on_mgmt_path=True)
    assert mgmt.risk_class is RC.HIGH
    assert "target_on_management_path" in mgmt.reasons
    behind = risk("wifi.radio_restart", radio, target_carries_dependants=True)
    assert "uplink_for_other_routers" in behind.reasons


def test_a_reboot_of_the_upstream_ap_names_the_routers_behind_it() -> None:
    upstream = risk("router.reboot", role="access_point", dependants=3)
    assert upstream.risk_class is RC.HIGH
    assert "uplink_for_other_routers" in upstream.reasons
    leaf = risk("router.reboot", role="access_point", dependants=0)
    assert "uplink_for_other_routers" not in leaf.reasons


def test_each_context_rule_raises_and_names_itself() -> None:
    cases = [
        ("service.restart", DNSMASQ, {"role": "unknown"}, "role_unknown", RC.HIGH),
        (
            "service.restart",
            DNSMASQ,
            {"identity_confirmed": False},
            "identity_not_confirmed",
            RC.HIGH,
        ),
        (
            "service.restart",
            DNSMASQ,
            {"open_security_findings": 1},
            "open_security_finding",
            RC.HIGH,
        ),
        (
            "service.restart",
            DNSMASQ,
            {"in_maintenance": True},
            "in_maintenance_window",
            RC.MEDIUM,
        ),
        (
            "service.restart",
            DNSMASQ,
            {"clients_on_router": 5},
            "clients_affected",
            RC.MEDIUM,
        ),
        (
            "interface.cycle",
            {"interface": "lan"},
            {"target_on_mgmt_path": True},
            "target_on_management_path",
            RC.HIGH,
        ),
    ]
    for action_type, params, over, reason, floor in cases:
        got = risk(action_type, params, **over)
        assert reason in got.reasons, reason
        assert got.risk_class >= floor


def test_missing_context_is_high_and_unassessed_never_a_guess() -> None:
    for name in hc.CATALOG["service.restart"].needs_facts:
        got = risk("service.restart", DNSMASQ, **{name: None})
        assert got.risk_class is RC.HIGH, name
        assert not got.assessed
        assert name in got.missing
        assert "context_missing" in got.reasons


def test_every_needed_fact_is_a_context_field() -> None:
    names = {f.name for f in dataclasses.fields(hp.RiskContext)}
    for entry in hc.CATALOG.values():
        assert set(entry.needs_facts) <= names, entry.action_type


def _random_context(rng: random.Random) -> hp.RiskContext:
    def maybe(values: list[Any]) -> Any:
        return rng.choice([*values, None])

    return hp.RiskContext(
        role=maybe(["gateway", "access_point", "unknown"]),
        identity_confirmed=maybe([True, False]),
        reachable=maybe([True, False]),
        dependants=maybe([0, 1, 3]),
        target_on_mgmt_path=maybe([True, False]),
        target_is_wireless_uplink=maybe([True, False]),
        target_carries_dependants=maybe([True, False]),
        service_enabled=maybe([True, False]),
        clients_on_router=maybe([0, 1, 40]),
        clients_on_target=maybe([0, 2]),
        open_security_findings=maybe([0, 1]),
        in_maintenance=maybe([True, False]),
        concurrent_repair=maybe([True, False]),
        breaker_open=maybe([True, False]),
        diag_enabled=maybe([True, False]),
    )


_VALID = {
    "observe.evaluate": {},
    "diag.refresh": {},
    "diag.ha_probes": {},
    "service.restart": DNSMASQ,
    "wifi.radio_restart": {"radio": "radio1"},
    "router.reboot": {},
    "config.restore": {"version_id": "bkp_" + "c" * 32},
    "interface.cycle": {"interface": "wan"},
}


@pytest.mark.parametrize("seed", range(3))
def test_context_never_lowers_the_risk_below_the_catalog(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(1500):
        action_type = rng.choice(list(hc.CATALOG))
        va = hc.validate(action_type, _VALID[action_type])
        context = _random_context(rng)
        got = hp.classify_risk(va, context)
        assert got.risk_class >= va.entry.base_risk
        assert got.base is va.entry.base_risk
        # worsening any single fact never lowers it either
        for name, worse in (
            ("open_security_findings", 1),
            ("identity_confirmed", False),
            ("in_maintenance", True),
            ("target_on_mgmt_path", True),
            ("service_enabled", False),
            ("role", None),
        ):
            worse_ctx = dataclasses.replace(context, **{name: worse})
            assert hp.classify_risk(va, worse_ctx).risk_class >= got.risk_class


def test_risk_round_trips_into_the_model() -> None:
    got = risk("service.restart", DNSMASQ, service_enabled=False)
    model = got.to_model()
    assert isinstance(model, hm.Risk)
    assert model.risk_class is RC.HIGH
    assert "service_disabled_on_purpose" in model.reasons


# ---------------------------------------------------------------------------
# The score: rule table, reproducible, contributions sum up
# ---------------------------------------------------------------------------


def test_the_score_rule_table() -> None:
    s = hp.score(inc(), prior_failed_attempts=0, config_change_24h=False)
    by = {c.factor: c.points for c in s.contributions}
    assert by == {
        "cause_level": 40,
        "cause_status": 10,
        "incident_confidence": 9,
        "source_families": 10,
        "target_fact": 30,
        "prior_attempts": 0,
        "config_change": 0,
        "severity": 0,
        "clamp": 0,
    }
    assert s.total == 99
    assert s.unit == 0.99

    weak = hp.score(
        inc(
            cause_level=hm.CauseLevel.POSSIBLE,
            cause_status=hm.CauseStatus.HYPOTHESIS,
            confidence=0.45,
            source_families=1,
            target_fact=hp.TargetFact.LOG_ONLY,
            severity="info",
        ),
        prior_failed_attempts=1,
        config_change_24h=None,
    )
    by = {c.factor: c.points for c in weak.contributions}
    assert by["cause_level"] == 15
    assert by["cause_status"] == 0
    assert by["incident_confidence"] == 5  # round(4.5) -> 4 would be banker's
    assert by["source_families"] == 5
    assert by["target_fact"] == 10
    assert by["prior_attempts"] == -25
    assert by["config_change"] == -20  # unknown counts as a change
    assert by["severity"] == -10
    # 15 + 0 + 5 + 5 + 10 - 25 - 20 - 10 = -20 -> clamped to 0
    assert by["clamp"] == 20
    assert weak.total == 0


@pytest.mark.parametrize("seed", range(3))
def test_contributions_always_sum_to_the_total_and_repeat(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(1000):
        facts = inc(
            severity=rng.choice(["info", "warning", "critical"]),
            cause_level=rng.choice(list(hm.CauseLevel)),
            cause_status=rng.choice(list(hm.CauseStatus)),
            confidence=rng.choice([None, 0.0, 0.333, 0.5, 0.75, 1.0]),
            source_families=rng.randint(0, 5),
            target_fact=rng.choice([*hp.TargetFact, None]),
        )
        prior = rng.randint(0, 6)
        change = rng.choice([True, False, None])
        a = hp.score(facts, prior_failed_attempts=prior, config_change_24h=change)
        b = hp.score(facts, prior_failed_attempts=prior, config_change_24h=change)
        assert a == b
        assert sum(c.points for c in a.contributions) == a.total
        assert 0 <= a.total <= 100
        assert a.unit == a.total / 100
        assert len({c.factor for c in a.contributions}) == len(a.contributions)


def test_the_decision_score_and_factors_land_in_the_model() -> None:
    d = decide()
    model = d.to_model()
    assert isinstance(model, hm.Decision)
    assert model.outcome is d.outcome
    assert model.score == d.score.unit
    assert [f.factor for f in model.factors] == [
        c.factor for c in d.score.contributions
    ]
    assert round(sum(f.value for f in model.factors), 4) == model.score
    assert model.why == d.why
    # reproducible: the same input gives the same decision, field by field
    assert hp.decide(dinput()) == hp.decide(dinput())
    assert json.dumps(d.explanation(), sort_keys=True) == json.dumps(
        hp.decide(dinput()).explanation(), sort_keys=True
    )


# ---------------------------------------------------------------------------
# The five outcomes, each reachable, each explained
# ---------------------------------------------------------------------------


def test_each_outcome_is_reachable_and_explained() -> None:
    cases = {
        O.RECOMMENDED: decide("diag.refresh", {}),
        O.REQUIRES_APPROVAL: decide(),
        O.NOT_SAFE: decide(context=ctx(open_security_findings=2)),
        O.INSUFFICIENT_EVIDENCE: decide(incident=inc(temporal_only=True)),
        O.UNSUPPORTED: decide("router.reboot", {}),
    }
    for outcome, d in cases.items():
        assert d.outcome is outcome
        assert d.why
        if outcome not in (O.RECOMMENDED, O.REQUIRES_APPROVAL):
            assert d.why_not
            assert any(h.blocking for h in d.hits)
        for code in all_codes(d):
            assert code in hp.REASON_TEXT_DE, code
            assert hp.REASON_TEXT_DE[code].strip()


def test_every_rule_code_has_a_german_text() -> None:
    for code in hp.RULE_CODES:
        assert code in hp.REASON_TEXT_DE, code
    for code in hc.STATUS_REASONS:
        assert code in hp.REASON_TEXT_DE, code


def test_the_requires_approval_explanation() -> None:
    d = decide()
    assert d.outcome is O.REQUIRES_APPROVAL
    assert d.why == "risk_needs_approval"
    assert d.why_not is None
    assert d.risk.risk_class is RC.MEDIUM
    exp = d.explanation()
    assert exp["outcome"] == "requires_approval"
    assert exp["action_type"] == "service.restart"
    assert exp["risk"]["risk_class"] == 2


# ---------------------------------------------------------------------------
# Unauthorised actions (order test 4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("action_type", "params", "why_not"),
    [
        ("shell.exec", {"cmd": "reboot"}, "never_shell"),
        ("foo.bar", {}, "unknown_action"),
        ("client.deauth", {}, "never_client_action"),
        ("firewall.reload", {}, "never_firewall"),
        ("network.reload", {}, "never_network_reload"),
        ("service.restart", {"service": "wpad"}, "param_value_invalid"),
        ("service.restart", {"service": "dnsmasq; reboot"}, "param_value_invalid"),
        ("service.restart", {"service": "dnsmasq", "x": "y"}, "param_unknown"),
        (None, None, "action_type_invalid"),
        ("wifi.radio_restart", {"radio": "radio0"}, "action_disabled"),
        ("router.reboot", {}, "action_disabled"),
        ("config.restore", {"version_id": "bkp_" + "d" * 32}, "action_disabled"),
        ("interface.cycle", {"interface": "lan"}, "action_disabled"),
    ],
)
def test_unauthorised_actions_are_unsupported(
    action_type: Any, params: Any, why_not: str
) -> None:
    d = decide(action_type, params)
    assert d.outcome is O.UNSUPPORTED
    assert d.why_not == why_not
    for mode in M:
        v = gate(
            d,
            mode=mode,
            allowlist=(allow("diag.refresh"),),
        )
        assert v.permission is P.NONE
        assert not v.executable_now


def test_a_disabled_action_says_why_it_is_disabled() -> None:
    d = decide("wifi.radio_restart", {"radio": "radio0"})
    hit = next(h for h in d.hits if h.code == "action_disabled")
    assert dict(hit.detail)["status_reason"] == "call_unverified_on_fleet"


def test_risk_3_can_never_be_authorised_by_a_general_switch() -> None:
    # the model refuses an allowlist entry above Risk 1
    with pytest.raises(hm.HealModelError):
        allow("router.reboot", max_risk=3)
    with pytest.raises(hm.HealModelError):
        allow("service.restart", max_risk=2, service="dnsmasq")
    # an entry the model accepts (max_risk 1) for a Risk 3 action is refused
    # by the allowlist validation and ignored by the gate
    sneaky = allow("router.reboot", max_risk=1)
    verdict = hp.validate_allowlist([sneaky])
    assert not verdict.entries and verdict.refusals[0][1] == "action_disabled"
    for action_type, params in (
        ("router.reboot", {}),
        ("config.restore", {"version_id": "bkp_" + "e" * 32}),
    ):
        d = decide(action_type, params)
        v = gate(d, mode=M.AUTO_HEAL, allowlist=(sneaky,))
        assert v.permission is P.NONE
    # context-raised Risk 3 of a ready action: Not Safe, nothing may happen
    d = decide(context=ctx(role="access_point", service_enabled=False))
    assert d.risk.risk_class is RC.HIGH and d.outcome is O.NOT_SAFE
    for mode in M:
        assert gate(d, mode=mode).permission is P.NONE


def test_a_spoofed_decision_with_risk_3_is_still_refused_by_the_gate() -> None:
    """Defence in depth: the gate checks the risk itself."""
    d = decide()
    spoofed = dataclasses.replace(
        d,
        outcome=O.RECOMMENDED,
        risk=dataclasses.replace(d.risk, risk_class=RC.HIGH),
    )
    for mode in M:
        v = gate(spoofed, mode=mode, allowlist=(allow("diag.refresh"),))
        assert v.permission is P.NONE
        assert "risk_high_never_authorised" in v.reasons


# ---------------------------------------------------------------------------
# Not Safe and Insufficient Evidence rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"reachable": False}, "router_unreachable"),
        ({"identity_confirmed": False}, "identity_not_confirmed"),
        ({"role": "unknown"}, "role_unknown"),
        ({"open_security_findings": 1}, "open_security_finding"),
        ({"service_enabled": False}, "service_disabled_on_purpose"),
        ({"breaker_open": True}, "breaker_open"),
        ({"concurrent_repair": True}, "concurrent_repair"),
    ],
)
def test_hard_facts_make_a_write_not_safe(over: dict[str, Any], code: str) -> None:
    d = decide(context=ctx(**over))
    assert d.outcome is O.NOT_SAFE
    assert code in {h.code for h in d.hits if h.blocking}


def test_an_open_security_finding_vetoes_writes_not_reads() -> None:
    c = ctx(open_security_findings=3)
    assert decide(context=c).outcome is O.NOT_SAFE
    assert decide("diag.refresh", {}, context=c).outcome is O.RECOMMENDED
    assert decide("observe.evaluate", {}, context=c).outcome is O.RECOMMENDED


@pytest.mark.parametrize(
    ("inc_over", "extra", "code"),
    [
        ({"temporal_only": True}, {}, "temporal_correlation_only"),
        ({"temporal_only": None}, {}, "temporal_correlation_only"),
        ({"evidence_fresh": False}, {}, "evidence_stale"),
        ({"evidence_fresh": None}, {}, "evidence_stale"),
        (
            {
                "cause_status": hm.CauseStatus.HYPOTHESIS,
                "cause_level": hm.CauseLevel.LIKELY,
                "source_families": 1,
            },
            {},
            "hypothesis_single_source",
        ),
        ({"target_fact": hp.TargetFact.LOG_ONLY}, {}, "no_direct_target_fact"),
        ({"target_fact": None}, {}, "no_direct_target_fact"),
        ({}, {"prior_failed_attempts": 2}, "score_below_threshold"),
    ],
)
def test_weak_evidence_is_insufficient_for_a_write(
    inc_over: dict[str, Any], extra: dict[str, Any], code: str
) -> None:
    d = decide(incident=inc(**inc_over), **extra)
    assert d.outcome is O.INSUFFICIENT_EVIDENCE
    assert code in {h.code for h in d.hits if h.blocking}
    assert d.next_step == "diag.refresh"


def test_a_write_without_an_incident_is_insufficient() -> None:
    d = decide(incident=None)
    assert d.outcome is O.INSUFFICIENT_EVIDENCE
    assert d.why_not == "no_incident"


def test_missing_context_is_insufficient_evidence_not_a_guess() -> None:
    d = decide(context=ctx(service_enabled=None))
    assert d.outcome is O.INSUFFICIENT_EVIDENCE
    assert d.why_not == "context_missing"
    assert d.risk.risk_class is RC.HIGH and not d.risk.assessed


def test_a_child_incident_is_not_repaired() -> None:
    d = decide(incident=inc(is_root=False))
    assert d.outcome is O.UNSUPPORTED
    assert d.why_not == "not_root_incident"


def test_probes_need_the_diagnostics_module() -> None:
    assert decide("diag.ha_probes", {}).outcome is O.RECOMMENDED
    d = decide("diag.ha_probes", {}, context=ctx(diag_enabled=False))
    assert d.outcome is O.UNSUPPORTED and d.why_not == "diagnostics_off"
    d = decide("diag.ha_probes", {}, context=ctx(diag_enabled=None))
    assert d.outcome is O.INSUFFICIENT_EVIDENCE


def test_a_stricter_score_threshold_is_configurable_a_looser_one_is_not() -> None:
    strict = hp.PolicyLimits(score_min=100)
    assert hp.decide(dinput(), strict).outcome is O.INSUFFICIENT_EVIDENCE
    for bad in (59, 0, 101, -1, True, 60.5):
        with pytest.raises(hm.HealModelError):
            hp.PolicyLimits(score_min=bad)
    for name, bad in (("manual_failures_to_open", 3), ("auto_failures_to_open", 2)):
        with pytest.raises(hm.HealModelError):
            hp.PolicyLimits(**{name: bad})


# ---------------------------------------------------------------------------
# Temporal correlation alone never yields more than "diagnose"
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(3))
def test_temporal_only_never_yields_more_than_diagnose(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(1500):
        action_type = rng.choice(list(hc.CATALOG))
        facts = inc(
            temporal_only=rng.choice([True, None]),
            cause_level=rng.choice(list(hm.CauseLevel)),
            cause_status=rng.choice(list(hm.CauseStatus)),
            confidence=rng.choice([None, 0.2, 0.6, 1.0]),
            source_families=rng.randint(0, 4),
            target_fact=rng.choice([*hp.TargetFact, None]),
            severity=rng.choice(["info", "warning", "critical"]),
            is_root=rng.choice([True, False, None]),
            evidence_fresh=rng.choice([True, False, None]),
        )
        d = hp.decide(
            hp.DecisionInput(
                action_type=action_type,
                params=_VALID[action_type],
                incident=facts,
                context=_random_context(rng),
                prior_failed_attempts=rng.randint(0, 2),
                config_change_24h=rng.choice([True, False, None]),
            )
        )
        if hc.CATALOG[action_type].writes:
            assert d.outcome not in (O.RECOMMENDED, O.REQUIRES_APPROVAL)
            for mode in M:
                v = gate(
                    d,
                    mode=mode,
                    allowlist=(allow("diag.refresh"),),
                )
                assert v.permission in (P.NONE, P.RECOMMEND)
                assert not v.executable_now
            if d.outcome is O.INSUFFICIENT_EVIDENCE:
                assert d.next_step == "diag.refresh"
        else:
            assert d.outcome in (
                O.RECOMMENDED,
                O.INSUFFICIENT_EVIDENCE,
                O.UNSUPPORTED,
            )


# ---------------------------------------------------------------------------
# Modes and the gate (order test 3: Auto-Heal, decision only)
# ---------------------------------------------------------------------------


def test_observe_mode_only_recommends() -> None:
    assert gate(decide()).permission is P.RECOMMEND
    assert gate(decide("diag.refresh", {})).permission is P.RECOMMEND
    v = gate(decide("observe.evaluate", {}))
    assert v.permission is P.RUN_READ_ONLY and v.executable_now


def test_approval_mode_requires_an_explicit_approval() -> None:
    v = gate(decide(), mode=M.APPROVAL)
    assert v.permission is P.NEEDS_APPROVAL
    assert not v.executable_now  # 1.53.0: no write path
    assert not v.in_release
    v = gate(decide("diag.refresh", {}), mode=M.APPROVAL)
    assert v.permission is P.NEEDS_APPROVAL


def test_auto_heal_runs_only_allowlisted_low_risk_with_all_guards_green() -> None:
    refresh = decide("diag.refresh", {})
    entry = allow("diag.refresh")
    v = gate(refresh, mode=M.AUTO_HEAL, allowlist=(entry,))
    assert v.permission is P.AUTO_RUN
    assert v.allowlisted
    # decision only: 1.53.0 executes nothing that calls a router
    assert not v.executable_now and not v.in_release
    # not on the allowlist -> approval
    v = gate(refresh, mode=M.AUTO_HEAL, allowlist=(allow("diag.ha_probes"),))
    assert v.permission is P.NEEDS_APPROVAL and "not_allowlisted" in v.reasons
    # any guard not green (or unknown) -> approval
    for guards in (False, None):
        v = gate(refresh, mode=M.AUTO_HEAL, allowlist=(entry,), guards_green=guards)
        assert v.permission is P.NEEDS_APPROVAL
        assert "guards_not_green" in v.reasons
    # Risk 2 can never run by itself, even with a (crafted) matching entry
    crafted = dataclasses.replace(entry, action_type="service.restart")
    v = gate(decide(), mode=M.AUTO_HEAL, allowlist=(crafted,))
    assert v.permission is P.NEEDS_APPROVAL
    assert "risk_above_auto_limit" in v.reasons


def test_an_allowlist_entry_with_params_matches_only_those_params() -> None:
    refresh = decide("diag.refresh", {})
    # an entry with a parameter the action does not have never matches
    odd = hm.AllowEntry(action_type="diag.refresh", params={"service": "dnsmasq"})
    v = gate(refresh, mode=M.AUTO_HEAL, allowlist=(odd,))
    assert v.permission is P.NEEDS_APPROVAL


def test_an_entry_whose_max_risk_is_below_the_actions_risk_does_not_match() -> None:
    refresh = decide("diag.refresh", {})
    low = allow("diag.refresh", max_risk=0)
    v = gate(refresh, mode=M.AUTO_HEAL, allowlist=(low,))
    assert v.permission is P.NEEDS_APPROVAL


def test_auto_heal_outcomes_below_recommended_permit_nothing() -> None:
    for d in (
        decide(context=ctx(breaker_open=True)),
        decide(incident=inc(temporal_only=True)),
        decide("router.reboot", {}),
    ):
        v = gate(d, mode=M.AUTO_HEAL, allowlist=(allow("diag.refresh"),))
        assert v.permission in (P.NONE, P.RECOMMEND)
        assert v.permission is not P.AUTO_RUN


def test_a_held_router_counts_as_observe_for_risk_1_and_more() -> None:
    for mode in M:
        v = gate(decide(), mode=mode, held=True)
        assert v.effective_mode is M.OBSERVE
        assert v.permission is P.RECOMMEND
        v = gate(
            decide("diag.refresh", {}),
            mode=mode,
            allowlist=(allow("diag.refresh"),),
            held=True,
        )
        assert v.permission is P.RECOMMEND
        # read-only diagnostics keep running
        v = gate(decide("observe.evaluate", {}), mode=mode, held=True)
        assert v.permission is P.RUN_READ_ONLY


def test_a_paused_fleet_counts_as_observe_for_risk_1_and_more() -> None:
    for mode in (M.APPROVAL, M.AUTO_HEAL):
        v = gate(
            decide("diag.refresh", {}),
            mode=mode,
            allowlist=(allow("diag.refresh"),),
            fleet_paused=True,
        )
        assert v.effective_mode is M.OBSERVE
        assert v.permission is P.RECOMMEND
        assert "fleet_paused" in v.reasons
    v = gate(decide("observe.evaluate", {}), mode=M.AUTO_HEAL, fleet_paused=True)
    assert v.permission is P.RUN_READ_ONLY


def test_maintenance_blocks_auto_heal_but_not_proposals() -> None:
    refresh = decide("diag.refresh", {})
    for maint in (True, None):
        v = gate(
            refresh,
            mode=M.AUTO_HEAL,
            allowlist=(allow("diag.refresh"),),
            in_maintenance=maint,
        )
        assert v.permission is P.NEEDS_APPROVAL
        assert "in_maintenance" in v.reasons
    # a write in maintenance: risk at least Medium, still a proposal
    d = decide(context=ctx(in_maintenance=True))
    assert d.outcome is O.REQUIRES_APPROVAL
    assert "in_maintenance_window" in d.risk.reasons
    assert gate(d, mode=M.APPROVAL, in_maintenance=True).permission is P.NEEDS_APPROVAL


def test_the_module_switched_off_permits_nothing() -> None:
    for name in ("observe.evaluate", "diag.refresh"):
        v = gate(decide(name, {}), mode=M.AUTO_HEAL, module_enabled=False)
        assert v.permission is P.NONE
        assert v.effective_mode is M.OBSERVE


def test_effective_mode() -> None:
    em = hp.effective_mode
    assert (
        em(
            M.AUTO_HEAL,
            module_enabled=True,
            held=False,
            fleet_paused=False,
            risk=RC.LOW,
        )
        is M.AUTO_HEAL
    )
    assert (
        em(
            M.AUTO_HEAL,
            module_enabled=False,
            held=False,
            fleet_paused=False,
            risk=RC.LOW,
        )
        is M.OBSERVE
    )
    assert (
        em(M.APPROVAL, module_enabled=True, held=True, fleet_paused=False, risk=RC.LOW)
        is M.OBSERVE
    )
    assert (
        em(M.AUTO_HEAL, module_enabled=True, held=False, fleet_paused=True, risk=RC.LOW)
        is M.OBSERVE
    )
    # Risk 0 keeps its mode while held or paused (read-only diagnostics run)
    assert (
        em(
            M.APPROVAL,
            module_enabled=True,
            held=True,
            fleet_paused=True,
            risk=RC.READ_ONLY,
        )
        is M.APPROVAL
    )


def test_gate_for_router_reads_settings_holds_and_pause_from_the_state() -> None:
    settings = hm.HealSettings(
        routers={
            R1: hm.RouterSettings(mode=M.AUTO_HEAL, allowlist=(allow("diag.refresh"),))
        }
    )
    loop = hm.LoopState()
    loop.clock = hm.SafetyClock().observe(T0)
    refresh = decide("diag.refresh", {})
    v = hp.gate_for_router(
        refresh,
        settings=settings,
        loop=loop,
        router_id=R1,
        in_maintenance=False,
        guards_green=True,
    )
    assert v.permission is P.AUTO_RUN
    # another router is in Observe by default
    v = hp.gate_for_router(
        refresh,
        settings=settings,
        loop=loop,
        router_id=R2,
        in_maintenance=False,
        guards_green=True,
    )
    assert v.permission is P.RECOMMEND
    # a hold on the router
    loop.place_hold(
        hm.RouterHold(router_id=R1, reason=hm.HoldReason.OUTCOME_UNKNOWN, since=T0)
    )
    v = hp.gate_for_router(
        refresh,
        settings=settings,
        loop=loop,
        router_id=R1,
        in_maintenance=False,
        guards_green=True,
    )
    assert v.permission is P.RECOMMEND and "router_held" in v.reasons
    # a fleet pause (and no hold)
    loop.holds.clear()
    loop.fleet = hm.FleetPause(paused_until=T0 + 60, since=T0, reason="fleet_failures")
    v = hp.gate_for_router(
        refresh,
        settings=settings,
        loop=loop,
        router_id=R1,
        in_maintenance=False,
        guards_green=True,
    )
    assert v.permission is P.RECOMMEND and "fleet_paused" in v.reasons
    # the pause is over on the safety clock
    loop.clock = hm.SafetyClock(wall=T0 + 61, safe=T0 + 61, high=T0 + 61)
    v = hp.gate_for_router(
        refresh,
        settings=settings,
        loop=loop,
        router_id=R1,
        in_maintenance=False,
        guards_green=True,
    )
    assert v.permission is P.AUTO_RUN


# ---------------------------------------------------------------------------
# Allowlist validation
# ---------------------------------------------------------------------------


def test_allowlist_validation_accepts_low_risk_ready_actions() -> None:
    v = hp.validate_allowlist(
        [
            {"action_type": "diag.refresh", "max_risk": 1},
            {"action_type": "diag.ha_probes", "params": {}, "max_risk": 1},
            {"action_type": "observe.evaluate", "max_risk": 0},
        ]
    )
    assert not v.refusals
    assert [e.action_type for e in v.entries] == [
        "diag.refresh",
        "diag.ha_probes",
        "observe.evaluate",
    ]
    assert all(isinstance(e, hm.AllowEntry) for e in v.entries)
    assert v.ok


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (
            {"action_type": "service.restart", "params": DNSMASQ, "max_risk": 1},
            "risk_above_auto_limit",
        ),
        (
            {"action_type": "service.restart", "params": DNSMASQ, "max_risk": 2},
            "entry_invalid",
        ),
        ({"action_type": "router.reboot", "max_risk": 1}, "action_disabled"),
        (
            {
                "action_type": "wifi.radio_restart",
                "params": {"radio": "radio0"},
                "max_risk": 1,
            },
            "action_disabled",
        ),
        ({"action_type": "shell.exec", "max_risk": 1}, "never_shell"),
        ({"action_type": "foo.bar", "max_risk": 1}, "unknown_action"),
        ({"action_type": "client.block", "max_risk": 0}, "never_client_action"),
        (
            {"action_type": "diag.refresh", "params": {"cmd": "x"}, "max_risk": 1},
            "param_unknown",
        ),
        ({"action_type": "diag.refresh", "max_risk": 0}, "max_risk_below_action_risk"),
        ({"action_type": "diag.refresh", "max_risk": 3}, "entry_invalid"),
        ({"action_type": "diag.refresh", "extra": 1}, "entry_invalid"),
        ("diag.refresh", "entry_invalid"),
        ({"action_type": "Diag.Refresh", "max_risk": 1}, "entry_invalid"),
    ],
)
def test_allowlist_validation_refuses(raw: Any, code: str) -> None:
    v = hp.validate_allowlist([raw])
    assert not v.ok
    assert not v.entries
    assert v.refusals == ((0, code),)


def test_allowlist_validation_refuses_more_than_the_model_limit_and_duplicates() -> (
    None
):
    too_many = [{"action_type": "diag.refresh", "max_risk": 1}] * (hm.ALLOWLIST_MAX + 1)
    v = hp.validate_allowlist(too_many)
    assert not v.ok and ("*", "too_many_entries") in v.refusals
    v = hp.validate_allowlist([{"action_type": "diag.refresh", "max_risk": 1}] * 2)
    assert v.refusals == ((1, "duplicate_entry"),)
    v = hp.validate_allowlist("diag.refresh")  # not a list
    assert not v.ok and v.refusals == (("*", "allowlist_invalid"),)


# ---------------------------------------------------------------------------
# Loop protection: cooldown, backoff, attempts (order test 25)
# ---------------------------------------------------------------------------

KEY: hm.LoopKey = (R1, "service.restart", "service:dnsmasq")
KEY2: hm.LoopKey = (R2, "service.restart", "service:odhcpd")


def verdict(
    attempts: dict,
    breakers: dict | None = None,
    fleet: Any = None,
    safe: float = T0,
    limits: hm.LoopLimits = LIMITS,
) -> hp.LoopVerdict:
    return hp.loop_verdict(
        (KEY,),
        attempts=attempts,
        breakers=breakers or {},
        fleet=fleet or hm.FleetPause(),
        limits=limits,
        safe_now=safe,
    )


def test_the_default_backoff_schedule() -> None:
    assert hp.backoff_schedule(LIMITS, 6) == (1800, 3600, 7200, 14400, 28800, 57600)
    assert hp.backoff_schedule(LIMITS, 8)[-2:] == (86400, 86400)  # capped at 24 h
    assert hp.cooldown_after(LIMITS, 1) == 1800
    longer = hm.LoopLimits(cooldown_s=7200)
    assert hp.backoff_schedule(longer, 3) == (7200, 7200, 7200)
    assert hp.cooldown_after(hm.LoopLimits(backoff_cap_s=3600), 5) == 3600


def test_cooldown_then_attempt_limit_then_a_new_window() -> None:
    att: dict = {}
    assert verdict(att).allowed
    att[KEY] = hp.book_attempt(att.get(KEY), LIMITS, T0)
    v = verdict(att, safe=T0 + 1)
    assert not v.allowed and v.reason == "cooling_down" and v.retry_at == T0 + 1800
    assert verdict(att, safe=T0 + 1799.9).reason == "cooling_down"
    assert verdict(att, safe=T0 + 1800).allowed
    att[KEY] = hp.book_attempt(att[KEY], LIMITS, T0 + 1800)
    assert att[KEY].count == 2 and att[KEY].backoff_step == 1
    assert verdict(att, safe=T0 + 1800 + 3599).reason == "cooling_down"
    v = verdict(att, safe=T0 + 1800 + 3600)
    assert not v.allowed and v.reason == "max_attempts"
    assert v.retry_at == T0 + 86400
    assert verdict(att, safe=T0 + 86399).reason == "max_attempts"
    # the 24 h window is over: a fresh count starts
    assert verdict(att, safe=T0 + 86400).allowed
    att[KEY] = hp.book_attempt(att[KEY], LIMITS, T0 + 86400)
    assert att[KEY].count == 1 and att[KEY].window_start == T0 + 86400


def test_limits_are_configurable_within_bounds_only() -> None:
    one = hm.LoopLimits(max_attempts_24h=1)
    att = {KEY: hp.book_attempt(None, one, T0)}
    assert verdict(att, safe=T0 + 1800, limits=one).reason == "max_attempts"
    for name, bad in (
        ("cooldown_s", 599),
        ("cooldown_s", 86401),
        ("max_attempts_24h", 0),
        ("max_attempts_24h", 4),
        ("backoff_cap_s", 86401),
        ("fleet_failure_threshold", 11),
        ("fleet_pause_s", 3599),
        ("fleet_concurrency", 2),
    ):
        with pytest.raises(hm.HealModelError):
            hm.LoopLimits(**{name: bad})


@pytest.mark.parametrize("seed", range(4))
def test_the_pure_rules_agree_with_what_the_store_enforces(seed: int) -> None:
    """One rule set: the store's durable step and the policy agree."""
    rng = random.Random(seed)
    store = hs.SelfHealingStore(MagicMock())
    for _ in range(300):
        limits = hm.LoopLimits(
            cooldown_s=rng.choice([600, 1800, 7200]),
            max_attempts_24h=rng.randint(1, 3),
            backoff_base_s=rng.choice([600, 1800]),
            backoff_cap_s=rng.choice([3600, 86400]),
        )
        store.settings = hm.HealSettings(limits=limits)
        loop = hm.LoopState()
        safe = T0
        action = hm.RemediationAction.new(
            router_id=R1,
            action_type="service.restart",
            ts=T0,
            params=DNSMASQ,
            components=(hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq"),),
        )
        keys = action.loop_keys
        for _step in range(6):
            safe += rng.choice([0, 300, 1800, 3600, 40000, 90000])
            if rng.random() < 0.15:
                loop.breakers[keys[0]] = hm.BreakerRecord(
                    state=hm.BreakerState.OPEN, opened_at=safe
                )
            store.loop = loop
            mine = hp.loop_verdict(
                keys,
                attempts=loop.attempts,
                breakers=loop.breakers,
                fleet=hm.FleetPause(),
                limits=limits,
                safe_now=safe,
            )
            theirs = store._attempt_refusal(action, safe)
            assert mine.reason == theirs
            assert mine.allowed is (theirs is None)
            if mine.allowed:
                booked, _no = store._next_attempts(action, safe)
                pure = hp.book_attempts(keys, loop.attempts, limits, safe)
                assert pure == booked
                loop.attempts.update(pure)


# ---------------------------------------------------------------------------
# Loop protection: breaker and fleet pause (order test 24)
# ---------------------------------------------------------------------------


def outcome(
    event: hp.OutcomeEvent,
    *,
    automatic: bool,
    state: hp.OutcomeUpdate | None = None,
    keys: tuple[hm.LoopKey, ...] = (KEY,),
    safe: float = T0,
    limits: hm.LoopLimits = LIMITS,
) -> hp.OutcomeUpdate:
    return hp.record_outcome(
        keys,
        event,
        automatic=automatic,
        attempts=state.attempts if state else {},
        breakers=state.breakers if state else {},
        fleet=state.fleet if state else hm.FleetPause(),
        limits=limits,
        safe_now=safe,
    )


OPEN_AT_ONCE = [
    EV.UNKNOWN,
    EV.ESCALATED,
    EV.NEW_FAULT,
    EV.ROLLED_BACK,
    EV.STUCK_RELEASED,
    EV.NOT_RESOLVED,
    EV.PARTIAL,
]


@pytest.mark.parametrize("event", OPEN_AT_ONCE)
@pytest.mark.parametrize("automatic", [True, False])
def test_an_unknown_or_escalated_outcome_opens_the_breaker_at_once(
    event: hp.OutcomeEvent, automatic: bool
) -> None:
    up = outcome(event, automatic=automatic)
    assert up.breakers[KEY].state is hm.BreakerState.OPEN
    assert up.breakers[KEY].reason == f"outcome_{event.value}"
    assert up.opened == (KEY,)
    assert not verdict({}, up.breakers).allowed
    assert verdict({}, up.breakers).reason == "breaker_open"


def test_a_clean_refusal_opens_after_one_automatic_or_two_manual() -> None:
    up = outcome(EV.REJECTED, automatic=True)
    assert up.breakers[KEY].state is hm.BreakerState.OPEN
    up = outcome(EV.REJECTED, automatic=False)
    assert up.breakers[KEY].state is hm.BreakerState.CLOSED
    assert up.breakers[KEY].failures == 1
    assert up.opened == ()
    up = outcome(EV.REJECTED, automatic=False, state=up, safe=T0 + 10)
    assert up.breakers[KEY].state is hm.BreakerState.OPEN
    assert up.opened == (KEY,)


def _run_to(end: str) -> hm.RemediationAction:
    """A record that reached EXECUTING and ended as ``end`` (model only)."""
    a = hm.RemediationAction.new(
        router_id=R1, action_type="service.restart", ts=T0, params=DNSMASQ
    )
    E = hm.Actor.ENGINE
    S = hm.ActionState
    for to in (S.ANALYZED, S.PROPOSED, S.PREFLIGHT, S.APPROVED, S.EXECUTING):
        a = hm.transition(a, to, actor=E, ts=T0 + 1, reason="step")
    if end == "rejected":
        ex = dataclasses.replace(a.execution, call_result=hm.CallResult.REJECTED)
        a = hm.transition(
            a, S.FAILED, actor=E, ts=T0 + 2, reason="step", changes={"execution": ex}
        )
        return hm.transition(a, S.ESCALATED, actor=E, ts=T0 + 3, reason="step")
    a = hm.transition(a, S.VERIFYING, actor=E, ts=T0 + 2, reason="step")
    if end in ("resolved", "manual_recovery_required", "escalated"):
        return hm.transition(a, S(end), actor=E, ts=T0 + 3, reason="step")
    a = hm.transition(a, S.FAILED, actor=E, ts=T0 + 3, reason="step")
    if end == "failed_escalated":
        return hm.transition(a, S.ESCALATED, actor=E, ts=T0 + 4, reason="step")
    for to in (S.ROLLBACK_PENDING, S.ROLLING_BACK, S.ROLLED_BACK):
        a = hm.transition(a, to, actor=E, ts=T0 + 4, reason="step")
    return a


@pytest.mark.parametrize(
    ("end", "event"),
    [
        ("resolved", EV.RESOLVED),
        ("manual_recovery_required", EV.UNKNOWN),
        ("escalated", EV.ESCALATED),
        ("failed_escalated", EV.ESCALATED),
        ("rejected", EV.REJECTED),
        ("rolled_back", EV.ROLLED_BACK),
    ],
)
def test_the_event_of_a_finished_record_matches_the_hold_rule(
    end: str, event: hp.OutcomeEvent
) -> None:
    """Every end that holds the router (model's ``hold_reason_for``) opens
    the breaker at once; so does ROLLED_BACK (package I note)."""
    a = _run_to(end)
    assert a.is_terminal
    assert hp.outcome_event_for(a) is event
    held = hm.hold_reason_for(a) is not None
    assert hp.opens_at_once(event) is (held or event is EV.ROLLED_BACK)


def test_a_record_that_never_executed_has_no_outcome_event() -> None:
    a = hm.RemediationAction.new(
        router_id=R1, action_type="service.restart", ts=T0, params=DNSMASQ
    )
    a = hm.transition(
        a, hm.ActionState.CANCELLED, actor=hm.Actor.ENGINE, ts=T0, reason="x"
    )
    assert hp.outcome_event_for(a) is None
    # an open record has none either
    b = hm.RemediationAction.new(
        router_id=R1, action_type="service.restart", ts=T0, params=DNSMASQ
    )
    assert hp.outcome_event_for(b) is None


def test_a_resolved_outcome_never_closes_an_open_breaker() -> None:
    up = outcome(EV.UNKNOWN, automatic=False)
    up = outcome(EV.RESOLVED, automatic=False, state=up, safe=T0 + 5)
    assert up.breakers[KEY].state is hm.BreakerState.OPEN
    # a resolved outcome on a closed breaker resets its failure count
    up = outcome(EV.REJECTED, automatic=False)
    up = outcome(EV.RESOLVED, automatic=False, state=up, safe=T0 + 5)
    assert up.breakers[KEY].state is hm.BreakerState.CLOSED
    assert up.breakers[KEY].failures == 0


def test_the_outcome_is_noted_on_the_attempt_record() -> None:
    att = {KEY: hp.book_attempt(None, LIMITS, T0)}
    up = hp.record_outcome(
        (KEY,),
        EV.NOT_RESOLVED,
        automatic=False,
        attempts=att,
        breakers={},
        fleet=hm.FleetPause(),
        limits=LIMITS,
        safe_now=T0 + 60,
    )
    assert up.attempts[KEY].last_result == "not_resolved"
    assert up.attempts[KEY].count == 1  # an outcome is no new attempt


def test_only_an_admin_closes_a_breaker() -> None:
    up = outcome(EV.UNKNOWN, automatic=True)
    br = up.breakers[KEY]
    for actor in (hm.Actor.ENGINE, hm.Actor.RECOVERY):
        with pytest.raises(hp.PolicyError):
            hp.acknowledge_breaker(br, actor=actor, safe_now=T0 + 99)
    closed = hp.acknowledge_breaker(br, actor=hm.Actor.ADMIN, safe_now=T0 + 99)
    assert closed.state is hm.BreakerState.CLOSED
    assert closed.acknowledged_at == T0 + 99
    assert closed.failures == 0
    assert verdict({}, {KEY: closed}).allowed


def test_repeated_failures_pause_the_whole_fleet() -> None:
    up = outcome(EV.NOT_RESOLVED, automatic=False, keys=(KEY,))
    assert not up.fleet_paused_now
    up = outcome(EV.UNKNOWN, automatic=False, keys=(KEY2,), state=up, safe=T0 + 100)
    assert not up.fleet.paused(T0 + 100)
    up = outcome(EV.PARTIAL, automatic=False, keys=(KEY2,), state=up, safe=T0 + 200)
    assert up.fleet_paused_now
    assert up.fleet.paused_until == T0 + 200 + LIMITS.fleet_pause_s
    assert up.fleet.reason == "fleet_failures"
    other = (R2, "diag.refresh", "router:router")
    v = hp.loop_verdict(
        (other,),
        attempts={},
        breakers={},
        fleet=up.fleet,
        limits=LIMITS,
        safe_now=T0 + 300,
    )
    assert not v.allowed and v.reason == "fleet_paused"
    assert v.retry_at == up.fleet.paused_until


def test_failures_older_than_24h_do_not_count_for_the_fleet_pause() -> None:
    up = outcome(EV.NOT_RESOLVED, automatic=False)
    up = outcome(EV.NOT_RESOLVED, automatic=False, keys=(KEY2,), state=up, safe=T0 + 10)
    # the first failure is now more than 24 h old, the second is not
    up = outcome(
        EV.NOT_RESOLVED, automatic=False, keys=(KEY2,), state=up, safe=T0 + 86400 + 5
    )
    assert not up.fleet_paused_now
    assert up.fleet.recent_failures == (T0 + 10, T0 + 86400 + 5)
    # a resolved outcome adds no failure
    up = outcome(EV.RESOLVED, automatic=False, state=up, safe=T0 + 86400 + 6)
    assert len(up.fleet.recent_failures) == 2


def test_a_longer_fleet_pause_is_never_shortened() -> None:
    long = hm.FleetPause(paused_until=T0 + 10 * 86400, since=T0, reason="store_lost")
    state = hp.OutcomeUpdate(
        attempts={}, breakers={}, fleet=long, opened=(), fleet_paused_now=False
    )
    for i in range(3):
        state = outcome(EV.UNKNOWN, automatic=False, state=state, safe=T0 + i)
    assert state.fleet.paused_until == T0 + 10 * 86400
    assert state.fleet.reason == "store_lost"


def test_the_orders_dnsmasq_example() -> None:
    """dnsmasq restarts again and again: one automatic attempt at most, the
    verification fails, the breaker opens, and nothing more happens until an
    admin acknowledges (order §12)."""
    att: dict = {}
    assert verdict(att).allowed
    att[KEY] = hp.book_attempt(None, LIMITS, T0)
    up = hp.record_outcome(
        (KEY,),
        EV.NOT_RESOLVED,
        automatic=True,
        attempts=att,
        breakers={},
        fleet=hm.FleetPause(),
        limits=LIMITS,
        safe_now=T0 + 300,
    )
    for later in (T0 + 900, T0 + 1800, T0 + 86400, T0 + 30 * 86400):
        v = hp.loop_verdict(
            (KEY,),
            attempts=up.attempts,
            breakers=up.breakers,
            fleet=up.fleet,
            limits=LIMITS,
            safe_now=later,
        )
        assert v.reason == "breaker_open"
        assert v.retry_at is None  # only an admin, never time, closes it
    # the decision engine sees the open breaker as a hard fact
    assert decide(context=ctx(breaker_open=True)).outcome is O.NOT_SAFE


def test_an_open_breaker_survives_a_restart_round_trip() -> None:
    up = outcome(EV.UNKNOWN, automatic=False)
    loop = hm.LoopState()
    loop.breakers.update(up.breakers)
    loop.attempts[KEY] = hp.book_attempt(None, LIMITS, T0)
    loop.fleet = up.fleet
    loop.clock = hm.SafetyClock().observe(T0)
    raw = json.loads(json.dumps(loop.to_dict()))
    back = hm.LoopState.from_dict(raw)
    assert back.breakers[KEY] == up.breakers[KEY]
    # a restart much later (safety clock moved on a year) changes nothing
    back.clock = hm.SafetyClock(wall=T0 + 3e7, safe=T0 + 3e7, high=T0 + 3e7)
    v = hp.loop_verdict_for(back, (KEY,), LIMITS)
    assert v.reason == "breaker_open"


# ---------------------------------------------------------------------------
# Safety time only
# ---------------------------------------------------------------------------


def test_the_policy_runs_on_safety_time_only() -> None:
    """A wall-clock jump in the inputs changes no verdict."""
    att = {KEY: hp.book_attempt(None, LIMITS, T0)}
    fleet = hm.FleetPause(paused_until=None, recent_failures=(T0,))
    verdicts = set()
    for wall in (T0, T0 - 10 * 86400, T0 + 10 * 86400, 0.0, 9e10):
        loop = hm.LoopState(attempts=dict(att), fleet=fleet)
        loop.clock = hm.SafetyClock(wall=wall, safe=T0 + 600, high=max(wall, T0 + 600))
        v = hp.loop_verdict_for(loop, (KEY,), LIMITS)
        verdicts.add((v.allowed, v.reason, v.retry_at))
    assert verdicts == {(False, "cooling_down", T0 + 1800)}


def test_safe_now_of_reads_the_safety_value_not_the_wall() -> None:
    clock = hm.SafetyClock(wall=T0 + 5000, safe=T0, high=T0 + 5000)
    assert hp.safe_now_of(clock) == T0
    with pytest.raises(hp.PolicyError):
        hp.safe_now_of(hm.SafetyClock())


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), -1.0, 2e11, True, "1"])
def test_bad_safety_times_are_refused(bad: Any) -> None:
    with pytest.raises(hp.PolicyError):
        verdict({}, safe=bad)
    with pytest.raises(hp.PolicyError):
        hp.book_attempt(None, LIMITS, bad)


def test_decide_and_gate_read_no_clock() -> None:
    """The decision has no time input at all: the same input, the same
    decision, whenever it is made."""
    names = {f.name for f in dataclasses.fields(hp.DecisionInput)}
    assert not {n for n in names if "time" in n or n.endswith(("_at", "_ts"))}


# ---------------------------------------------------------------------------
# Dedupe verdicts
# ---------------------------------------------------------------------------


def test_dedupe_verdicts_follow_the_model_ids() -> None:
    comp = hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq")
    open_action = hm.RemediationAction.new(
        router_id=R1,
        action_type="service.restart",
        ts=T0,
        params=DNSMASQ,
        incident_id="inc-7",
        components=(comp,),
    )
    loop = hm.LoopState()
    loop.action_dedupe[open_action.action_dedupe] = open_action.action_id
    loop.incident_dedupe[open_action.incident_dedupe] = open_action.action_id
    for d in open_action.component_dedupes:
        loop.component_dedupe[d] = open_action.action_id

    same = hp.dedupe_verdict(
        loop,
        router_id=R1,
        action_type="service.restart",
        params=DNSMASQ,
        incident_id="inc-8",
        components=(comp,),
    )
    assert same.duplicate_of == open_action.action_id and same.kind == "action"
    by_incident = hp.dedupe_verdict(
        loop,
        router_id=R2,
        action_type="diag.refresh",
        params={},
        incident_id="inc-7",
        components=(),
    )
    assert by_incident.kind == "incident"
    by_component = hp.dedupe_verdict(
        loop,
        router_id=R1,
        action_type="service.restart",
        params={"service": "odhcpd"},
        incident_id=None,
        components=(comp,),
    )
    assert by_component.kind == "component"
    fresh = hp.dedupe_verdict(
        loop,
        router_id=R2,
        action_type="service.restart",
        params=DNSMASQ,
        incident_id="inc-9",
        components=(comp,),
    )
    assert fresh.duplicate_of is None and fresh.kind is None


# ---------------------------------------------------------------------------
# Purity
# ---------------------------------------------------------------------------


def test_the_policy_modules_import_nothing_from_home_assistant_or_the_api() -> None:
    import ast
    import pathlib

    root = pathlib.Path(hp.__file__).parent
    for name in ("heal_catalog.py", "heal_policy.py"):
        tree = ast.parse((root / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [("." * node.level) + (node.module or "")]
            else:
                continue
            for mod in mods:
                assert not mod.startswith("homeassistant"), (name, mod)
                assert mod.lstrip(".") not in {"api", "coordinator", "heal_store"}, (
                    name,
                    mod,
                )
                assert "aiohttp" not in mod and "asyncssh" not in mod
                assert not mod.startswith(
                    ("subprocess", "socket", "time", "datetime")
                ), (name, mod)


def test_an_interrupted_record_is_unknown_even_if_it_resolved() -> None:
    a = hm.RemediationAction.new(
        router_id=R1, action_type="service.restart", ts=T0, params=DNSMASQ
    )
    E, S = hm.Actor.ENGINE, hm.ActionState
    for to in (S.ANALYZED, S.PROPOSED, S.PREFLIGHT, S.APPROVED, S.EXECUTING):
        a = hm.transition(a, to, actor=E, ts=T0, reason="step")
    a = hm.apply_restart_recovery(a, ts=T0 + 5)
    assert a.flags.interrupted and a.state is S.VERIFYING
    a = hm.transition(a, S.RESOLVED, actor=E, ts=T0 + 6, reason="step")
    assert hp.outcome_event_for(a) is EV.UNKNOWN
    assert hp.opens_at_once(EV.UNKNOWN)


def test_the_attempt_window_is_the_stores() -> None:
    assert hp.ATTEMPT_WINDOW_S == hs.ATTEMPT_WINDOW_S
    assert hp.FLEET_WINDOW_S == hs.ATTEMPT_WINDOW_S


def test_prior_failed_attempts_from_the_attempt_records() -> None:
    att = {KEY: hp.book_attempt(None, LIMITS, T0)}
    assert hp.prior_failed_attempts((KEY,), att, T0 + 10) == 1
    att[KEY] = hp.book_attempt(att[KEY], LIMITS, T0 + 1800)
    assert hp.prior_failed_attempts((KEY,), att, T0 + 1900) == 2
    att[KEY] = dataclasses.replace(att[KEY], last_result="resolved")
    assert hp.prior_failed_attempts((KEY,), att, T0 + 1900) == 1
    # outside the 24 h window nothing counts
    assert hp.prior_failed_attempts((KEY,), att, T0 + 86400) == 0
    assert hp.prior_failed_attempts((KEY2,), att, T0 + 10) == 0


def test_the_policy_is_never_looser_than_the_stores_effective_mode() -> None:
    """The store lets a paused fleet fall back to Approval; the owner's rule
    (Observe for Risk >= 1) is stricter, and the policy follows it."""
    store = hs.SelfHealingStore(MagicMock(), clock=lambda: T0, monotonic=None)
    store.settings = hm.HealSettings(routers={R1: hm.RouterSettings(mode=M.AUTO_HEAL)})
    store.loop.fleet = hm.FleetPause(
        paused_until=T0 + 3600, since=T0, reason="fleet_failures"
    )
    assert store.effective_mode(R1) is M.APPROVAL
    mine = hp.effective_mode(
        M.AUTO_HEAL, module_enabled=True, held=False, fleet_paused=True, risk=RC.LOW
    )
    assert mine is M.OBSERVE


def test_a_spoofed_risk_below_the_catalog_is_refused_by_the_gate() -> None:
    d = decide()
    spoofed = dataclasses.replace(
        d,
        outcome=O.RECOMMENDED,
        risk=dataclasses.replace(d.risk, risk_class=RC.LOW),
    )
    for mode in M:
        v = gate(spoofed, mode=mode, allowlist=(allow("diag.refresh"),))
        assert v.permission is P.NONE
        assert v.reasons == ("risk_below_catalog",)


def test_stored_allowlist_entries_are_validated_again_before_they_match() -> None:
    """An entry the model accepts but the policy refuses never matches,
    even if the caller claims a low risk."""
    crafted = allow("service.restart", max_risk=1, service="dnsmasq")
    assert not hp.is_allowlisted([crafted], "service.restart", DNSMASQ, RC.LOW)
    assert hp.is_allowlisted([allow("diag.refresh")], "diag.refresh", {}, RC.LOW)
    assert not hp.is_allowlisted(["diag.refresh"], "diag.refresh", {}, RC.LOW)


def test_an_entry_with_params_matches_only_those_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No allowlistable action has parameters today; a test-only entry shows
    that a parameter subset matches only the same values."""
    fake = dataclasses.replace(
        hc.CATALOG["diag.refresh"],
        action_type="test.probe",
        params=(hc.ParamSpec(name="service", choices=("dnsmasq", "odhcpd")),),
    )
    monkeypatch.setattr(
        hc, "CATALOG", MappingProxyType({**hc.CATALOG, "test.probe": fake})
    )
    entry = allow("test.probe", service="dnsmasq")
    assert hp.validate_allowlist([entry]).ok
    assert hp.is_allowlisted([entry], "test.probe", DNSMASQ, RC.LOW)
    assert not hp.is_allowlisted([entry], "test.probe", {"service": "odhcpd"}, RC.LOW)
    assert hp.is_allowlisted(
        [allow("test.probe")], "test.probe", {"service": "odhcpd"}, RC.LOW
    )
