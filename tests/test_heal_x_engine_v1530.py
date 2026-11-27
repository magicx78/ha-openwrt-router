"""Self-Healing, package X (1.53.0): the policy of package D in the engine.

``PolicyDecider`` maps the engine's ``DecisionContext`` to a
``heal_policy.DecisionInput`` and asks ``heal_policy.gate``; the record
carries the gate's own decision. Still Observe only: nothing goes past
PROPOSED, nothing is executable, no router call.

Covered here:

* the default decider of a running engine is the policy; a policy error
  falls back to ``ObserveOnlyDecider`` and is counted;
* the facts: what the engine holds in memory is filled, everything else
  stays unknown; the facts-provider seam for packages E and F, with a
  conservative default and hostile providers that change nothing;
* a root incident (the real Network Intelligence of the P6 tests and a
  stand-in) ends PROPOSED with the policy's decision: a read-only
  Recommended, or Insufficient Evidence naming the unknown facts;
* a favourable provider for ``service.restart`` gives at most Requires
  Approval, never anything executable;
* the mode the engine shows is the policy's: a held router and a paused
  fleet show Observe;
* the C1 clamp keeps writes and Risk 1 out but lets a Risk 0 read-only
  recommendation through;
* the plans route explains the decision (score lines, rules, codes,
  German texts) and persists nothing;
* zero extra router calls;
* review nits a (a resolved or ignored incident never gets a record), b
  (spoofed events do not drive the dedupe counter), c (deferred incidents
  are not rebuilt on every tick; bounded memo), d (an incident id reused
  after an NI reset is a new incident).
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterator, Mapping
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import full_router_kit as kit
import pytest
from core_testkit import FakeDisks
from homeassistant.core import Event
from test_heal_engine_v1530 import (
    E1,
    E2,
    FakeNI,
    Registry,
    World,
    heal_hass,
    incident,
    make_entries,
    patched,
    payload,
    states_of,
    world,
)
from test_heal_store_v1530 import R1, R2, T0, Clock, disks
from test_net_p6 import SETTLE, clock, intel, open_of, step, timers, wan
from test_net_p6 import T0 as NI_T0

from custom_components.openwrt_router import heal_catalog as hc
from custom_components.openwrt_router import heal_engine as he
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_policy as hp
from custom_components.openwrt_router import net_rules
from custom_components.openwrt_router.const import EVENT_INCIDENT
from custom_components.openwrt_router.net_events import IncidentStatus

S = hm.ActionState
O = hm.DecisionOutcome
M = hm.HealMode

__all__ = ["clock", "disks", "intel", "timers", "world"]  # fixtures used here

# Every RiskContext fact service.restart needs, favourable.
GOOD_CONTEXT = hp.RiskContext(
    role="gateway",
    identity_confirmed=True,
    reachable=True,
    dependants=0,
    service_enabled=True,
    service_dependant_routers=0,
    service_dependant_clients=3,
    service_config_unapplied=False,
    clients_on_router=4,
    open_security_findings=0,
    in_maintenance=False,
    concurrent_repair=False,
    breaker_open=False,
)
GOOD_INCIDENT = hp.IncidentFacts(
    is_root=True,
    temporal_only=False,
    evidence_fresh=True,
    target_fact=hp.TargetFact.DIRECT,
    cause_outside_router=False,
)


@pytest.fixture
def measured() -> Iterator[None]:
    """NI reports a measured cause: level confirmed, two source families
    (what its rules give for a confirmed cause with log and state evidence;
    the stand-in NI holds no events)."""
    with (
        patch.object(
            net_rules, "cause_families", lambda inc, events: frozenset({"log", "state"})
        ),
        patch.object(
            net_rules,
            "incident_cause_level",
            lambda inc, events: SimpleNamespace(value="confirmed"),
        ),
    ):
        yield


class Favourable:
    """A provider (package E/F stand-in) that knows everything, favourably."""

    def __init__(self, action: str = "service.restart", **params: Any) -> None:
        self.action = action
        self.params = params or (
            {"service": "dnsmasq"} if action == "service.restart" else {}
        )
        self.contexts: list[he.DecisionContext] = []

    def facts(self, context: he.DecisionContext) -> he.HealFacts:
        self.contexts.append(context)
        return he.HealFacts(
            candidate_action=self.action,
            candidate_params=self.params,
            context=GOOD_CONTEXT,
            incident=GOOD_INCIDENT,
            config_change_24h=False,
            playbook_id="dns_recovery",
            playbook_version=1,
        )


class Candidate:
    """Names a candidate action and nothing else (all facts unknown)."""

    def __init__(self, action: str, **params: Any) -> None:
        self.action = action
        self.params = params

    def facts(self, context: he.DecisionContext) -> he.HealFacts:
        return he.HealFacts(candidate_action=self.action, candidate_params=self.params)


def gate_of(plan: he.Plan) -> dict[str, Any]:
    explanation = plan.to_dict()["explanation"]
    assert explanation is not None
    return explanation["gate"]


# ---------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------


def test_the_policy_decider_is_a_heal_decider() -> None:
    decider = he.PolicyDecider()
    assert isinstance(decider, he.HealDecider)
    assert isinstance(he.UnknownFactsProvider(), he.HealFactsProvider)
    assert isinstance(Favourable(), he.HealFactsProvider)
    assert he.UnknownFactsProvider().facts(MagicMock()) == he.HealFacts()


async def test_the_running_engine_uses_the_policy(world: World) -> None:
    hass = world.hass
    e1, _e2 = hass.entries
    await he.async_setup_self_healing(hass, e1)
    engine = he.async_get_self_healing(hass)
    assert engine is not None
    world.engine = engine
    assert isinstance(engine.decider, he.PolicyDecider)
    assert engine.stats()["decider"] == "PolicyDecider"
    world.open("inc-1")
    [record] = world.records()
    assert record.state is S.PROPOSED
    assert record.decision.why == "all_rules_passed"
    assert record.decision.why_not != "no_decision_policy"


async def test_a_root_incident_ends_proposed_as_a_read_only_recommendation(
    world: World,
) -> None:
    """No provider: the record's own action (``observe.evaluate``, Risk 0,
    no router call) is what the policy rates; no cause is needed for it."""
    engine = await world.start(decider=he.PolicyDecider())
    world.open("inc-1")
    [record] = world.records()
    assert states_of(record) == [S.DETECTED, S.ANALYZED, S.PROPOSED]
    assert record.decision.outcome is O.RECOMMENDED
    assert record.decision.why == "all_rules_passed"
    assert record.risk.risk_class is hm.RiskClass.READ_ONLY
    factors = [f.factor for f in record.decision.factors]
    assert factors == [
        "cause_level",
        "cause_status",
        "incident_confidence",
        "source_families",
        "target_fact",
        "prior_attempts",
        "config_change",
        "severity",
        "clamp",
    ]
    assert record.planned_changes == ()
    assert engine.counters["decision_clamped"] == 0
    plan = engine.plan_for(record)
    assert plan.executable is False and plan.proposal.executable is False
    assert plan.proposal.action_type == "observe.evaluate"
    gate = gate_of(plan)
    # the gate would let a Risk 0 read-only step run; nothing runs here
    assert gate["permission"] == "run_read_only"
    assert gate["executable_now"] is False
    for _ in range(6):
        world.tick()
    assert engine.store.get(record.action_id).state is S.PROPOSED
    world.hass.services.async_call.assert_not_called()
    assert world.hass.fired == []


async def test_unknown_facts_give_insufficient_evidence_and_are_named(
    world: World,
) -> None:
    engine = await world.start(
        decider=he.PolicyDecider(Candidate("service.restart", service="dnsmasq"))
    )
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [record] = world.records()
    assert record.state is S.PROPOSED
    assert record.decision.outcome is O.INSUFFICIENT_EVIDENCE
    assert record.decision.why_not == "context_missing"
    plan = engine.plan_for(record).to_dict()
    explanation = plan["explanation"]
    missing = next(
        r for r in explanation["policy"]["rules"] if r["code"] == "context_missing"
    )
    named = set(missing["detail"]["facts"].split(","))
    assert {"reachable", "service_enabled", "clients_on_router"} <= named
    # what the engine holds is known, never named as missing
    assert not named & {"role", "identity_confirmed", "in_maintenance", "breaker_open"}
    facts = explanation["facts"]
    assert {"role", "identity_confirmed", "in_maintenance", "breaker_open"} <= set(
        facts["known"]
    )
    assert {"reachable", "severity", "config_change_24h"} <= set(facts["unknown"])
    assert "prior_failed_attempts" in facts["known"]
    assert plan["executable"] is False


async def test_the_engine_fills_only_what_it_holds(world: World) -> None:
    seen: list[hp.DecisionInput] = []
    real_gate = hp.gate

    def spy(inp: hp.DecisionInput, **kw: Any) -> hp.GateVerdict:
        seen.append(inp)
        return real_gate(inp, **kw)

    await world.start(decider=he.PolicyDecider())
    with patch.object(hp, "gate", spy):
        world.open(
            "inc-1", cause="dns_upstream", cause_status="confirmed", confidence=0.8
        )
    [inp] = seen
    c = inp.context
    assert c.role == "gateway" and c.identity_confirmed is True
    assert c.in_maintenance is False and c.breaker_open is False
    for name in (
        "reachable",
        "dependants",
        "target_on_mgmt_path",
        "target_is_wireless_uplink",
        "target_carries_dependants",
        "service_enabled",
        "service_dependant_routers",
        "service_dependant_clients",
        "service_config_unapplied",
        "clients_on_router",
        "clients_on_target",
        "open_security_findings",
        "concurrent_repair",
        "diag_enabled",
    ):
        assert getattr(c, name) is None, name
    i = inp.incident
    assert i is not None
    assert i.incident_type == "dns_failure"
    assert i.cause_status is hm.CauseStatus.CONFIRMED
    assert i.confidence == 0.8
    assert i.is_root is True
    assert i.severity is None
    for name in (
        "temporal_only",
        "evidence_fresh",
        "target_fact",
        "cause_outside_router",
    ):
        assert getattr(i, name) is None, name
    assert inp.prior_failed_attempts == 0  # the loop state is in memory
    assert inp.config_change_24h is None
    assert inp.action_type == "observe.evaluate" and dict(inp.params) == {}


async def test_maintenance_is_unknown_without_network_intelligence(
    world: World,
) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    world.open("inc-1")
    [record] = world.records()
    world.ni.loaded = False
    context = engine.context_for(record)
    assert context.maintenance_known is False
    world.ni.loaded = True
    world.ni.maintenance.add(E1)
    context = engine.context_for(record)
    assert context.maintenance_known is True and context.in_maintenance is True


async def test_a_favourable_provider_gives_at_most_requires_approval(
    world: World,
    measured: None,
) -> None:
    provider = Favourable()
    engine = await world.start(decider=he.PolicyDecider(provider))
    store = engine.store
    for mode in (M.OBSERVE, M.APPROVAL, M.AUTO_HEAL):
        store.set_settings(hm.HealSettings(routers={R1: hm.RouterSettings(mode=mode)}))
        iid = f"inc-{mode.value}"
        world.open(iid, cause="dns_upstream", cause_status="confirmed")
        record = world.of(iid)
        assert record.state is S.PROPOSED
        assert record.decision.outcome is O.REQUIRES_APPROVAL
        assert record.decision.why == "risk_needs_approval"
        assert record.risk.risk_class is hm.RiskClass.MEDIUM
        assert record.playbook_id == "dns_recovery"
        assert record.planned_changes == (
            hm.Change(kind="service", target="dnsmasq", effect="service.restart"),
        )
        plan = engine.plan_for(record)
        assert plan.executable is False and plan.proposal.executable is False
        gate = gate_of(plan)
        assert gate["permission"] in ("recommend", "needs_approval")
        assert gate["executable_now"] is False
        for _ in range(3):
            world.tick()
        assert store.get(record.action_id).state is S.PROPOSED
        world.resolve(iid)
    assert {a.state for a in world.records()} == {S.CANCELLED}
    assert all(S.WAITING_APPROVAL not in states_of(a) for a in world.records())
    world.hass.services.async_call.assert_not_called()
    assert world.hass.fired == []
    assert store.loop.locks == {} and store.loop.attempts == {}


async def test_engine_facts_win_over_the_provider(world: World, measured: None) -> None:
    """A provider cannot overwrite what the engine knows (role, identity,
    maintenance, breaker, root, cause, history)."""

    class Liar:
        def facts(self, context: he.DecisionContext) -> he.HealFacts:
            return he.HealFacts(
                candidate_action="service.restart",
                candidate_params={"service": "dnsmasq"},
                context=dataclasses.replace(
                    GOOD_CONTEXT,
                    role="access_point",
                    identity_confirmed=False,
                    in_maintenance=True,
                    breaker_open=True,
                ),
                incident=dataclasses.replace(
                    GOOD_INCIDENT,
                    is_root=False,
                    cause_level=hm.CauseLevel.UNKNOWN,
                    cause_status=hm.CauseStatus.HYPOTHESIS,
                    source_families=0,
                    confidence=0.0,
                ),
                config_change_24h=False,
            )

    engine = await world.start(decider=he.PolicyDecider(Liar()))
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [record] = world.records()
    # the engine's facts: a confirmed gateway root, no maintenance, no breaker
    assert record.decision.outcome is O.REQUIRES_APPROVAL
    rules = {
        r["code"]
        for r in engine.plan_for(record).to_dict()["explanation"]["policy"]["rules"]
    }
    assert not rules & {"not_root_incident", "identity_not_confirmed", "breaker_open"}


async def test_an_open_breaker_and_failed_attempts_come_from_the_loop_state(
    world: World,
) -> None:
    engine = await world.start(decider=he.PolicyDecider(Favourable()))
    store = engine.store
    safe = store.now()
    key = (R1, "service.restart", "service:dnsmasq")
    store.loop.attempts[key] = hm.AttemptRecord(
        count=1,
        window_start=safe - 60,
        last_at=safe - 60,
        cooldown_until=safe - 1,
        recent=(safe - 60,),
        last_result="not_resolved",
    )
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    first = world.of("inc-1")
    plan = engine.plan_for(first).to_dict()["explanation"]
    prior = next(
        c
        for c in plan["policy"]["score"]["contributions"]
        if c["factor"] == "prior_attempts"
    )
    assert prior["points"] == -25
    world.resolve("inc-1")
    store.loop.breakers[key] = hm.BreakerRecord(
        state=hm.BreakerState.OPEN, opened_at=safe
    )
    world.open("inc-2", cause="dns_upstream", cause_status="confirmed")
    second = world.of("inc-2")
    assert second.decision.outcome is O.NOT_SAFE
    assert second.decision.why_not == "breaker_open"


# ---------------------------------------------------------------------------
# Hostile providers: nothing beyond PROPOSED, ever
# ---------------------------------------------------------------------------


class _Raising(Mapping):
    def __getitem__(self, key: str) -> Any:
        raise RuntimeError("boom")

    def __iter__(self) -> Iterator[str]:
        return iter(["service"])

    def __len__(self) -> int:
        return 1


def _mutated(**fields: Any) -> he.HealFacts:
    facts = he.HealFacts(
        candidate_action="service.restart", candidate_params={"service": "dnsmasq"}
    )
    for name, value in fields.items():
        object.__setattr__(facts, name, value)
    return facts


def _sub_facts() -> he.HealFacts:
    class SubFacts(he.HealFacts):  # type: ignore[misc]
        __slots__ = ()

    return SubFacts(
        candidate_action="service.restart", candidate_params={"service": "dnsmasq"}
    )


def _bad_context() -> he.HealFacts:
    c = dataclasses.replace(GOOD_CONTEXT)
    object.__setattr__(c, "reachable", "yes")
    return _mutated(context=c)


def _raise() -> Any:
    raise RuntimeError("provider down")


# (name, the provider's answer; built per test so the module imports alone)
HOSTILE: list[tuple[str, Any]] = [
    ("raises", _raise),
    ("none", lambda: None),
    ("dict", lambda: {"candidate_action": "router.reboot"}),
    ("string", lambda: "service.restart"),
    ("sub", _sub_facts),
    ("context_object", lambda: _mutated(context=object())),
    ("context_bad", _bad_context),
    ("incident_dict", lambda: _mutated(incident={"is_root": True})),
    ("params_raising", lambda: _mutated(candidate_params=_Raising())),
    ("params_list", lambda: _mutated(candidate_params=["service", "dnsmasq"])),
    ("action_int", lambda: _mutated(candidate_action=7)),
    ("config_change_str", lambda: _mutated(config_change_24h="no")),
    ("playbook_version_bool", lambda: _mutated(playbook_version=True)),
]


class Hostile:
    def __init__(self, answer: Any) -> None:
        self.answer = answer  # a factory, called on every request

    def facts(self, context: he.DecisionContext) -> Any:
        return self.answer()


@pytest.mark.parametrize(("name", "answer"), HOSTILE, ids=[h[0] for h in HOSTILE])
async def test_a_hostile_provider_changes_nothing_that_is_allowed(
    world: World, name: str, answer: Any
) -> None:
    decider = he.PolicyDecider(Hostile(answer))
    engine = await world.start(decider=decider)
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [record] = world.records()
    assert record.state is S.PROPOSED
    # the facts fell back to unknown: the record's own read-only action
    assert record.decision.outcome is O.RECOMMENDED
    assert record.planned_changes == ()
    assert decider.counters["facts_failed"] + decider.counters["facts_invalid"] == 1
    assert engine.counters["errors"] == 0
    plan = engine.plan_for(record)
    assert plan.executable is False and plan.proposal.executable is False
    json.dumps(plan.to_dict())
    for _ in range(3):
        world.tick()
    assert engine.store.get(record.action_id).state is S.PROPOSED
    world.hass.services.async_call.assert_not_called()


@pytest.mark.parametrize(
    ("action", "params", "outcome"),
    [
        ("router.reboot", {}, O.UNSUPPORTED),
        ("firewall.open", {}, O.UNSUPPORTED),
        ("service.restart", {"service": "wpad"}, O.UNSUPPORTED),
        ("interface.cycle", {"interface": "lan"}, O.UNSUPPORTED),
        ("service.restart", {"service": "dnsmasq"}, O.REQUIRES_APPROVAL),
        ("diag.refresh", {}, O.RECOMMENDED),
    ],
)
async def test_any_valid_candidate_stops_at_proposed(
    world: World,
    measured: None,
    action: str,
    params: dict[str, Any],
    outcome: hm.DecisionOutcome,
) -> None:
    class Any_:
        def facts(self, context: he.DecisionContext) -> he.HealFacts:
            return he.HealFacts(
                candidate_action=action,
                candidate_params=params,
                context=GOOD_CONTEXT,
                incident=GOOD_INCIDENT,
                config_change_24h=False,
            )

    engine = await world.start(decider=he.PolicyDecider(Any_()))
    store = engine.store
    store.set_settings(
        hm.HealSettings(routers={R1: hm.RouterSettings(mode=M.AUTO_HEAL)})
    )
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [record] = world.records()
    assert record.state is S.PROPOSED
    assert record.decision.outcome is outcome
    plan = engine.plan_for(record)
    assert plan.executable is False and plan.proposal.executable is False
    for _ in range(3):
        world.tick()
    assert store.get(record.action_id).state is S.PROPOSED
    assert store.loop.locks == {} and store.loop.attempts == {}


def test_heal_facts_validate_their_input() -> None:
    he.HealFacts()
    he.HealFacts(candidate_action="diag.refresh", candidate_params={})
    for bad in (
        {"candidate_action": 1},
        {"candidate_action": "x" * 80},
        {"candidate_params": {"service": "dnsmasq"}},  # params without action
        {"candidate_action": "service.restart", "candidate_params": [1]},
        {"candidate_action": "service.restart", "candidate_params": {1: "a"}},
        {"candidate_action": "service.restart", "candidate_params": {"a": object()}},
        {
            "candidate_action": "service.restart",
            "candidate_params": {f"k{i}": 1 for i in range(20)},
        },
        {"context": object()},
        {"incident": hp.RiskContext()},
        {"config_change_24h": 0},
        {"playbook_id": "Not A Code"},
        {"playbook_version": 0},
        {"playbook_version": True},
    ):
        with pytest.raises(he.HealFactsError):
            he.HealFacts(**bad)
    params = {"service": "dnsmasq"}
    facts = he.HealFacts(candidate_action="service.restart", candidate_params=params)
    params["service"] = "wpad"
    assert dict(facts.candidate_params) == {"service": "dnsmasq"}


async def test_the_provider_gets_a_copy_of_the_context(world: World) -> None:
    class Meddler:
        def facts(self, context: he.DecisionContext) -> he.HealFacts:
            object.__setattr__(context, "hold", None)
            object.__setattr__(context, "fleet_paused", False)
            object.__setattr__(context, "effective_mode", M.AUTO_HEAL)
            return he.HealFacts()

    engine = await world.start(decider=he.PolicyDecider(Meddler()))
    store = engine.store
    safe = store.now()
    store.loop.fleet = hm.FleetPause(paused_until=safe + 3600, since=safe)
    world.open("inc-1")
    [record] = world.records()
    plan = engine.plan_for(record)
    assert "fleet_paused" in plan.blockers
    assert gate_of(plan)["effective_mode"] == "observe"


# ---------------------------------------------------------------------------
# A policy error falls back, counted
# ---------------------------------------------------------------------------


async def test_a_policy_error_falls_back_to_observe_only(world: World) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    with patch.object(hp, "gate", MagicMock(side_effect=hp.PolicyError("x"))):
        world.open("inc-1")
    [record] = world.records()
    assert record.state is S.PROPOSED
    assert record.decision.why_not == "no_decision_policy"
    assert engine.counters["decider_failed"] == 1
    assert engine.counters["errors"] == 0


async def test_a_gate_without_a_decision_falls_back(world: World) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    refused = hp.GateVerdict(
        permission=hp.Permission.NONE,
        effective_mode=M.OBSERVE,
        reasons=("module_disabled",),
    )
    with patch.object(hp, "gate", MagicMock(return_value=refused)):
        world.open("inc-1")
    [record] = world.records()
    assert record.decision.why_not == "no_decision_policy"
    plan_gate = engine.plan_for(record).to_dict()["explanation"]["gate"]
    assert plan_gate["permission"] in ("none", "run_read_only")


# ---------------------------------------------------------------------------
# The mode the engine shows: the policy's
# ---------------------------------------------------------------------------


async def test_a_held_router_and_a_paused_fleet_show_observe(
    world: World, measured: None
) -> None:
    from custom_components.openwrt_router.diagnostics import _self_healing_summary
    from custom_components.openwrt_router.heal_views import overview_body

    engine = await world.start(decider=he.PolicyDecider(Favourable()))
    store = engine.store
    store.set_settings(
        hm.HealSettings(
            routers={
                R1: hm.RouterSettings(mode=M.AUTO_HEAL),
                R2: hm.RouterSettings(mode=M.AUTO_HEAL),
            }
        )
    )
    assert engine.effective_mode(R1) is M.AUTO_HEAL
    safe = store.now()
    store.loop.place_hold(
        hm.RouterHold(
            router_id=R1, reason=hm.HoldReason.OUTCOME_UNKNOWN, since=safe, until=None
        )
    )
    assert engine.effective_mode(R1) is M.OBSERVE
    assert engine.effective_mode(R2) is M.AUTO_HEAL
    store.loop.fleet = hm.FleetPause(
        paused_until=safe + 3600, since=safe, reason="store_lost"
    )
    assert engine.effective_mode(R2) is M.OBSERVE
    world.open("inc-1", router=E1, cause="dns_upstream", cause_status="confirmed")
    world.open("inc-2", router=E2, cause="dns_upstream", cause_status="confirmed")
    held, paused = world.of("inc-1"), world.of("inc-2")
    assert held.state is paused.state is S.PROPOSED
    for record, reason in ((held, "router_held"), (paused, "fleet_paused")):
        plan = engine.plan_for(record)
        gate = gate_of(plan)
        assert gate["effective_mode"] == "observe"
        assert gate["permission"] == "recommend"
        assert reason in gate["reasons"]
        assert "mode_observe" in plan.blockers
    body = overview_body(engine, admin=True, now=T0)
    modes = {r["router_id"]: r["effective_mode"] for r in body["routers"]}
    assert modes[R1] == modes[R2] == "observe"
    with patch.object(he, "async_get_self_healing", lambda hass: engine):
        summary = _self_healing_summary(world.hass, E1)
    assert summary["effective_modes"]["observe"] == 2
    assert summary["effective_modes"]["auto_heal"] == 0
    # the pause ends: Auto-Heal is shown again for the router without hold
    store.loop.fleet = hm.FleetPause()
    assert engine.effective_mode(R2) is M.AUTO_HEAL
    assert engine.effective_mode(R1) is M.OBSERVE


async def test_the_module_switch_off_shows_observe(world: World) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    engine.store.set_settings(
        hm.HealSettings(enabled=False, routers={R1: hm.RouterSettings(mode=M.APPROVAL)})
    )
    assert engine.effective_mode(R1) is M.OBSERVE


# ---------------------------------------------------------------------------
# The clamp: writes and Risk 1 stay clamped, Risk 0 read-only passes
# ---------------------------------------------------------------------------


async def test_a_read_only_recommendation_is_not_clamped(world: World) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    world.open("inc-1", cause="dns_upstream", cause_status="hypothesis")
    [record] = world.records()
    assert engine.context_for(record).evidence_sufficient is False
    assert record.decision.outcome is O.RECOMMENDED
    assert engine.counters["decision_clamped"] == 0
    assert "insufficient_evidence_sources" in engine.plan_for(record).blockers


async def test_a_risk_one_recommendation_is_still_clamped(world: World) -> None:
    engine = await world.start(decider=he.PolicyDecider(Candidate("diag.refresh")))
    world.open("inc-1", cause="dns_upstream", cause_status="hypothesis")
    [record] = world.records()
    assert record.decision.outcome is O.INSUFFICIENT_EVIDENCE
    assert record.decision.why_not == "insufficient_evidence_sources"
    assert engine.counters["decision_clamped"] == 1


class Claiming:
    """A decider that says read-only but is not (or names no catalog action)."""

    def __init__(self, **kw: Any) -> None:
        self.kw = kw

    def propose(self, context: he.DecisionContext) -> he.Proposal:
        base: dict[str, Any] = {
            "decision": hm.Decision(
                outcome=O.RECOMMENDED, score=0.9, factors=(), why="x", why_not=None
            ),
            "risk": hm.Risk(risk_class=hm.RiskClass.READ_ONLY),
        }
        base.update(self.kw)
        return he.Proposal(**base)


@pytest.mark.parametrize(
    "kw",
    [
        {"action_type": "service.restart"},
        {"action_type": "diag.refresh"},
        {"action_type": "no.such_action"},
        {
            "action_type": "observe.evaluate",
            "risk": hm.Risk(risk_class=hm.RiskClass.LOW),
        },
        {
            "action_type": "observe.evaluate",
            "planned_changes": (
                hm.Change(kind="service", target="dnsmasq", effect="restart"),
            ),
        },
    ],
)
async def test_a_claimed_read_only_write_is_clamped(
    world: World, kw: dict[str, Any]
) -> None:
    engine = await world.start(decider=Claiming(**kw))
    world.open("inc-1", cause="dns_upstream", cause_status="hypothesis")
    [record] = world.records()
    assert record.decision.outcome is O.INSUFFICIENT_EVIDENCE
    assert engine.counters["decision_clamped"] == 1


async def test_a_real_read_only_claim_passes(world: World) -> None:
    engine = await world.start(decider=Claiming(action_type="observe.evaluate"))
    world.open("inc-1", cause="dns_upstream", cause_status="hypothesis")
    [record] = world.records()
    assert record.decision.outcome is O.RECOMMENDED
    assert engine.counters["decision_clamped"] == 0
    assert engine.plan_for(record).executable is False


# ---------------------------------------------------------------------------
# The plans route explains, persists nothing
# ---------------------------------------------------------------------------


async def test_the_plan_explains_the_policy_decision(
    world: World, measured: None
) -> None:
    engine = await world.start(decider=he.PolicyDecider(Favourable()))
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [record] = world.records()
    before_actions = dict(engine.store.actions)
    before_loop = (
        engine.store.loop.to_dict() if hasattr(engine.store.loop, "to_dict") else None
    )
    delayed = len(world.hass.data)  # nothing new in hass.data either
    body = engine.plan_for(record).to_dict()
    engine.plan_for(record).to_dict()
    assert engine.store.actions == before_actions
    if before_loop is not None:
        assert engine.store.loop.to_dict() == before_loop
    assert len(world.hass.data) == delayed
    assert body["executable"] is False
    explanation = body["explanation"]
    json.dumps(explanation)
    policy = explanation["policy"]
    assert policy["outcome"] == "requires_approval"
    assert policy["action_type"] == "service.restart"
    lines = policy["score"]["contributions"]
    assert sum(c["points"] for c in lines) == policy["score"]["total"]
    assert {r["code"] for r in policy["rules"]} >= {
        "impact_summary",
        "recovery_statement",
    }
    texts = explanation["texts_de"]
    codes = {policy["why"], *(r["code"] for r in policy["rules"])}
    codes |= {c["reason"] for c in lines} | {c["factor"] for c in lines}
    codes |= set(explanation["gate"]["reasons"])
    for code in codes:
        assert texts.get(code) == hp.REASON_TEXT_DE[code], code
    assert body["decision"]["outcome"] == "requires_approval"


async def test_the_plans_route_reads_only(world: World, measured: None) -> None:
    from custom_components.openwrt_router import heal_views

    engine = await world.start(decider=he.PolicyDecider(Favourable()))
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [record] = world.records()
    snapshot = dict(engine.store.actions)
    view = heal_views.SelfHealingPlansView()
    request = MagicMock()
    request.app = {"hass": world.hass}
    request.query = {}
    request.content_length = None
    request.body_exists = False
    request.can_read_body = False
    with (
        patch.object(heal_views, "_admin", lambda req: world.hass),
        patch.object(heal_views, "_engine", lambda hass: engine),
        patch.object(heal_views, "read_body", AsyncMock(return_value={})),
    ):
        response = await view.get(request)
    assert response.status == 200
    data = json.loads(response.body)
    [plan] = data["plans"]
    assert plan["action_id"] == record.action_id
    assert plan["executable"] is False
    assert plan["explanation"]["policy"]["outcome"] == "requires_approval"
    assert plan["explanation"]["texts_de"]
    assert engine.store.actions == snapshot


# ---------------------------------------------------------------------------
# End to end with the real Network Intelligence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("provider", [None, "candidate"])
async def test_real_network_intelligence_with_the_real_policy(
    disks: FakeDisks, intel: Any, provider: str | None
) -> None:
    hass = heal_hass(make_entries("gw", "ap1"))
    w = World(hass, Clock(), intel, Registry({"gw": R1, "ap1": R2}))
    intel.hass.bus.async_fire.side_effect = lambda t, d=None, **kw: w.bus.fire(t, d)
    decider = he.PolicyDecider(
        None if provider is None else Candidate("service.restart", service="dnsmasq")
    )
    with patched(intel, w.registry, w.ticks):
        engine = await w.start(decider=decider)
        step(intel, NI_T0, wan())
        step(intel, NI_T0 + SETTLE, wan())
        step(intel, NI_T0 + SETTLE + 60, wan())
        [record] = w.records()
        [inc] = open_of(intel, "wan_down")
        assert record.incident_id == inc.id and record.state is S.PROPOSED
        assert record.params.get("first_seen") == round(inc.first_seen, 3)
        if provider is None:
            assert record.decision.outcome is O.RECOMMENDED
            assert record.risk.risk_class is hm.RiskClass.READ_ONLY
        else:
            assert record.decision.outcome is O.INSUFFICIENT_EVIDENCE
            assert record.decision.why_not == "context_missing"
        plan = engine.plan_for(record)
        assert plan.executable is False
        for _ in range(3):
            w.tick()
        assert engine.store.get(record.action_id).state is S.PROPOSED
        step(intel, NI_T0 + 400, wan(0.0))
        assert engine.store.get(record.action_id).state is S.CANCELLED
        assert engine.counters["decider_failed"] == 0
        await engine.async_stop()


# ---------------------------------------------------------------------------
# Zero extra router calls with the policy and a favourable provider
# ---------------------------------------------------------------------------


async def test_zero_extra_router_calls_with_the_policy(
    world: World, measured: None
) -> None:
    off_calls: list[Any] = []
    off = kit.make_coordinator(MagicMock(), kit.make_api(off_calls))
    await kit.full_polls(off, on_poll=lambda d, n: None)

    hass = world.hass
    on_calls: list[Any] = []
    coordinator = kit.make_coordinator(hass, kit.make_api(on_calls))
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_refresh = AsyncMock()
    for entry in hass.entries:
        entry.runtime_data = SimpleNamespace(
            coordinator=coordinator, api=coordinator.api
        )
        await he.async_setup_self_healing(hass, entry)
    engine = he.async_get_self_healing(hass)
    assert engine is not None and isinstance(engine.decider, he.PolicyDecider)
    engine.decider = he.PolicyDecider(Favourable())
    world.engine = engine

    def after_poll(result: Any, n: int) -> None:
        coordinator.data = result
        coordinator.async_update_listeners()
        world.open(
            f"inc-{n + 1}",
            router=E1 if n == 0 else E2,
            cause="dns_upstream",
            cause_status="confirmed",
        )
        world.tick()
        for record in world.records():
            engine.plan_for(record)

    await kit.full_polls(coordinator, on_poll=after_poll)
    assert on_calls == off_calls and len(on_calls) > 0
    coordinator.async_request_refresh.assert_not_awaited()
    coordinator.async_refresh.assert_not_awaited()
    assert coordinator._listeners == {}
    assert engine.counters["records_created"] == 2
    assert {r.decision.outcome for r in world.records()} == {O.REQUIRES_APPROVAL}
    hass.services.async_call.assert_not_called()
    await he.async_release_self_healing(hass, E1)
    await he.async_release_self_healing(hass, E2)


# ---------------------------------------------------------------------------
# Nit a: a resolved or ignored incident never gets a record
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [IncidentStatus.RESOLVED, IncidentStatus.IGNORED])
async def test_a_closed_but_announced_incident_gets_no_record(
    world: World, status: IncidentStatus
) -> None:
    world.ni.incidents["inc-1"] = incident("inc-1", [E1], status=status)
    world.ni.announced["inc-1"] = 0  # NI still lists it as announced
    engine = await world.start()
    world.tick()
    assert world.records() == []
    ni = world.ni
    known = {i.id: i for i in ni.machine.peek()}
    outcome = engine._detect(known["inc-1"], ni, known, reason="incident_opened")
    assert outcome == "not_active"
    engine._pending["inc-1"] = None
    engine._retry_pending(ni, known)
    assert world.records() == [] and engine.pending_count() == 0
    world.bus.fire(EVENT_INCIDENT, payload("inc-1"))
    assert world.records() == []


# ---------------------------------------------------------------------------
# Nit b: spoofed events with a recorded id do not drive the counter
# ---------------------------------------------------------------------------


async def test_spoofed_events_do_not_drive_the_dedupe_counter(world: World) -> None:
    engine = await world.start()
    world.open("inc-1")
    for _ in range(500):
        world.bus.fire(EVENT_INCIDENT, payload("inc-1"))
    assert engine.counters["deduplicated"] == 0
    assert len(world.records()) == 1
    # a store-level dedupe (another record holds the incident) counts once
    other = hm.RemediationAction.new(
        router_id=R2,
        action_type="diag.refresh",
        ts=T0,
        incident_id="inc-9",
        actor=hm.Actor.ENGINE,
        reason="x",
    )
    engine.store.add(other)
    world.ni.incidents["inc-9"] = incident("inc-9", [E2])
    world.ni.announced["inc-9"] = 0
    for _ in range(300):
        world.bus.fire(EVENT_INCIDENT, payload("inc-9", entry_ids=[E2]))
    assert engine.counters["deduplicated"] == 1
    assert len(engine._dedupe_seen) <= he.DEDUPE_SEEN_MAX


# ---------------------------------------------------------------------------
# Nit c: deferred incidents are not rebuilt on every tick
# ---------------------------------------------------------------------------


async def test_the_tick_does_not_rebuild_deferred_incidents(world: World) -> None:
    for n in range(1, 501):
        iid = f"inc-{n}"
        world.ni.incidents[iid] = incident(iid, [E1])
        world.ni.announced[iid] = 0
    engine = await world.start()
    first = [a for a in world.records()]
    assert len(first) == 1 and first[0].incident_id == "inc-1"
    calls: list[int] = []
    real_new = hm.RemediationAction.new

    def counting(**kw: Any) -> hm.RemediationAction:
        calls.append(1)
        return real_new(**kw)

    adds: list[int] = []
    real_add = engine.store.add

    def counting_add(action: hm.RemediationAction) -> Any:
        adds.append(1)
        return real_add(action)

    with (
        patch.object(hm.RemediationAction, "new", counting),
        patch.object(engine.store, "add", counting_add),
    ):
        world.tick()
        world.tick()
    assert calls == [] and adds == []
    assert len(engine._skip_memo) <= he.SKIP_MEMO_MAX
    assert len(world.records()) == 1
    # the slot frees: the next incident gets its record
    world.resolve("inc-1")
    records = world.records()
    assert len(records) == 2 and records[1].state is S.PROPOSED
    assert records[1].incident_id != "inc-1"


async def test_the_memo_stays_bounded(world: World) -> None:
    engine = await world.start()
    for n in range(1, 3 * he.SKIP_MEMO_MAX):
        iid = f"inc-{n}"
        world.ni.incidents[iid] = incident(iid, [E1])
        world.ni.announced[iid] = 0
    world.tick()
    world.tick()
    assert len(engine._skip_memo) <= he.SKIP_MEMO_MAX
    assert engine.pending_count() <= he.PENDING_MAX


# ---------------------------------------------------------------------------
# Nit d: an incident id reused after an NI reset is a new incident
# ---------------------------------------------------------------------------


async def test_a_reused_id_after_an_ni_reset_is_a_new_incident(world: World) -> None:
    engine = await world.start()
    world.open("inc-1", first_seen=NI_T0)
    first = world.of("inc-1")
    assert first.params == {"incident": "inc-1", "first_seen": NI_T0}
    world.resolve("inc-1")
    assert world.of("inc-1").state is S.CANCELLED
    # NI's store is reset: inc-1 is a different incident now
    world.ni.incidents.clear()
    world.clock.now += 60
    world.open("inc-1", first_seen=NI_T0 + 5000)
    records = [a for a in world.records() if a.incident_id == "inc-1"]
    assert len(records) == 2
    assert records[1].state is S.PROPOSED
    assert records[1].params["first_seen"] == NI_T0 + 5000
    assert engine.counters["deduplicated"] == 0


async def test_an_open_record_of_a_reused_id_is_closed_as_gone(world: World) -> None:
    engine = await world.start()
    world.open("inc-1", first_seen=NI_T0)
    old = world.of("inc-1")
    # NI reset while the record was open; the new inc-1 is announced
    world.ni.incidents["inc-1"] = incident("inc-1", [E1], first_seen=NI_T0 + 9000)
    world.ni.announced["inc-1"] = 0
    world.tick()
    assert engine.store.get(old.action_id).state is S.CANCELLED
    assert engine.store.get(old.action_id).history[-1].reason == "incident_gone"
    new = world.of("inc-1")
    assert new.action_id != old.action_id and new.state is S.PROPOSED


async def test_an_event_for_a_reused_id_replaces_the_stale_record(world: World) -> None:
    engine = await world.start()
    world.open("inc-1", first_seen=NI_T0)
    old = world.of("inc-1")
    world.ni.incidents.clear()
    world.clock.now += 60
    world.open("inc-1", first_seen=NI_T0 + 9000)
    assert engine.store.get(old.action_id).state is S.CANCELLED
    assert world.of("inc-1").action_id != old.action_id
    # resolving the new one never closes by id alone: only its own period
    world.resolve("inc-1")
    assert world.of("inc-1").state is S.CANCELLED


async def test_a_backward_clock_shift_keeps_the_same_incident(world: World) -> None:
    engine = await world.start()
    world.open("inc-1", first_seen=NI_T0 + 100)
    record = world.of("inc-1")
    # NI shifts its times back after a clock jump (``_shift``): same incident
    world.ni.incidents["inc-1"].first_seen = NI_T0 - 3500
    world.tick()
    world.bus.fire(EVENT_INCIDENT, payload("inc-1"))
    assert engine.store.get(record.action_id).state is S.PROPOSED
    assert len(world.records()) == 1


async def test_a_record_without_first_seen_matches_by_id(world: World) -> None:
    """Records of C1 (no ``first_seen``) still match their incident."""
    engine = await world.start()
    world.open("inc-1")
    record = world.of("inc-1")
    assert "first_seen" not in record.params
    world.ni.incidents["inc-1"].first_seen = NI_T0
    world.tick()
    assert engine.store.get(record.action_id).state is S.PROPOSED
    world.bus.fire(EVENT_INCIDENT, payload("inc-1"))
    assert len(world.records()) == 1


# ---------------------------------------------------------------------------
# Guards behind guards: each one on its own (mutation loop of package X)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("in_maintenance", "known", "expected"),
    [
        (True, True, True),
        (True, False, True),  # the record's own flag, NI not loaded
        (False, True, False),
        (None, True, False),
        (None, False, None),  # unknown stays unknown, never "not in maintenance"
        (False, False, None),
    ],
)
async def test_maintenance_maps_true_known_false_and_unknown(
    world: World, in_maintenance: bool | None, known: bool, expected: bool | None
) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    world.open("inc-1")
    context = dataclasses.replace(
        engine.context_for(world.of("inc-1")),
        in_maintenance=in_maintenance,
        maintenance_known=known,
    )
    inp = he.PolicyDecider().decision_input(context, he.UNKNOWN_FACTS)
    assert inp.context.in_maintenance is expected


def test_bookkeeping_params_of_another_incident_go_to_the_catalog() -> None:
    def record(params: dict[str, Any]) -> hm.RemediationAction:
        return hm.RemediationAction.new(
            router_id=R1,
            action_type="observe.evaluate",
            ts=T0,
            actor=hm.Actor.ENGINE,
            reason="incident_opened",
            params=params,
            incident_id="inc-1",
        )

    assert he._catalog_params(record({"incident": "inc-1", "first_seen": 5.0})) == {}
    foreign = record({"incident": "inc-9"})
    assert dict(he._catalog_params(foreign)) == {"incident": "inc-9"}
    extra = record({"incident": "inc-1", "service": "dnsmasq"})
    assert dict(he._catalog_params(extra)) == {
        "incident": "inc-1",
        "service": "dnsmasq",
    }


@pytest.mark.parametrize(
    ("writes", "base_risk", "risk", "changes", "passes"),
    [
        (False, hm.RiskClass.READ_ONLY, hm.RiskClass.READ_ONLY, (), True),
        (True, hm.RiskClass.READ_ONLY, hm.RiskClass.READ_ONLY, (), False),
        (False, hm.RiskClass.LOW, hm.RiskClass.READ_ONLY, (), False),
        (False, hm.RiskClass.READ_ONLY, hm.RiskClass.LOW, (), False),
        (False, hm.RiskClass.READ_ONLY, hm.RiskClass.READ_ONLY, ("x",), False),
    ],
)
def test_each_condition_of_the_clamp_escape_holds_on_its_own(
    writes: bool,
    base_risk: hm.RiskClass,
    risk: hm.RiskClass,
    changes: tuple[str, ...],
    passes: bool,
) -> None:
    """A stand-in catalog entry: the real catalog has no read-only action
    that writes, so ``not found.writes`` is checked here on its own."""
    entry = SimpleNamespace(writes=writes, base_risk=base_risk)
    proposal = SimpleNamespace(
        action_type="x.stand_in",
        risk=SimpleNamespace(risk_class=risk),
        planned_changes=changes,
    )
    with patch.object(hc, "CATALOG", {"x.stand_in": entry}):
        assert he._read_only(proposal, SimpleNamespace(action=None)) is passes


async def test_a_waiting_incident_is_not_looked_at_again(world: World) -> None:
    """Nit c on its own: the memo alone keeps the tick from detecting a
    deferred incident again (no ``_detect`` call while the holder is the
    same)."""
    world.ni.incidents["inc-1"] = incident("inc-1", [E1])
    world.ni.announced["inc-1"] = 0
    engine = await world.start()
    world.open("inc-2")
    assert engine.pending_count() == 1
    with patch.object(engine, "_detect", wraps=engine._detect) as spy:
        world.tick()
        world.tick()
    spy.assert_not_called()
    assert [a.incident_id for a in world.records()] == ["inc-1"]


async def test_a_deferral_never_builds_a_record(world: World) -> None:
    """Nit c on its own: the slot pre-check defers before a record is built,
    also the first time (the memo is still empty then)."""
    world.ni.incidents["inc-1"] = incident("inc-1", [E1])
    world.ni.announced["inc-1"] = 0
    engine = await world.start()
    assert engine._skip_memo == {}
    real_new = hm.RemediationAction.new
    calls: list[int] = []

    def counting(**kw: Any) -> hm.RemediationAction:
        calls.append(1)
        return real_new(**kw)

    with patch.object(hm.RemediationAction, "new", counting):
        world.open("inc-2")
    assert calls == []
    assert engine.pending_count() == 1 and engine.counters["deferred"] == 1


async def test_a_reused_id_not_announced_still_closes_the_old_record(
    world: World,
) -> None:
    """Nit d in the reconcile on its own: the new incident with the old id
    is not announced (no adoption, no ``_close_stale``), the old record is
    still closed as gone."""
    engine = await world.start()
    world.open("inc-1", first_seen=NI_T0)
    old = world.of("inc-1")
    world.ni.incidents["inc-1"] = incident("inc-1", [E1], first_seen=NI_T0 + 9000)
    world.ni.announced.pop("inc-1", None)
    world.tick()
    closed = engine.store.get(old.action_id)
    assert closed.state is S.CANCELLED
    assert closed.history[-1].reason == "incident_gone"
    assert len(world.records()) == 1


async def test_a_resolve_event_of_a_reused_id_does_not_close_the_old_record(
    world: World,
) -> None:
    """Nit d in the event path on its own: the new incident with the old id
    resolves; the old record is not closed as resolved (it is another
    incident), the reconcile closes it as gone."""
    engine = await world.start()
    world.open("inc-1", first_seen=NI_T0)
    old = world.of("inc-1")
    world.ni.incidents["inc-1"] = incident(
        "inc-1", [E1], first_seen=NI_T0 + 9000, status=IncidentStatus.RESOLVED
    )
    world.ni.announced.pop("inc-1", None)
    world.bus.fire(EVENT_INCIDENT, payload("inc-1", "resolved"))
    assert engine.store.get(old.action_id).state is S.PROPOSED
    world.tick()
    closed = engine.store.get(old.action_id)
    assert closed.state is S.CANCELLED
    assert closed.history[-1].reason == "incident_gone"


async def test_a_blocked_write_plans_no_change(world: World) -> None:
    """Planned changes only for a writing decision that acts: a restart with
    every fact unknown is blocked and plans nothing."""
    engine = await world.start(decider=he.PolicyDecider())
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    context = engine.context_for(world.of("inc-1"))
    proposal = he.PolicyDecider(
        Candidate("service.restart", service="dnsmasq")
    ).propose(context)
    assert proposal.action_type == "service.restart"
    assert proposal.decision.outcome in he._NON_ACTING
    assert proposal.planned_changes == ()
    assert proposal.executable is False


__all__ += ["R2", "Event", "FakeNI", "hc"]
