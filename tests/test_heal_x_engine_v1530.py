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
def quiet_security() -> Iterator[None]:
    """A running, ready Security Center without findings (package K1).

    The open findings are the engine's own fact since K1: a provider's 0
    no longer counts, so a test of favourable facts needs the center to
    say it."""
    from custom_components.openwrt_router import security_center

    center = SimpleNamespace(loaded=True, enabled=True, ready=True, incidents={})
    with patch.object(
        security_center, "async_get_security_center", lambda hass: center
    ):
        yield


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


def candidate_of(plan: he.Plan) -> dict[str, Any]:
    """The provider's candidate as the plan shows it (never the record's)."""
    explanation = plan.to_dict()["explanation"]
    assert explanation is not None
    candidate = explanation["candidate"]
    assert candidate["label"] == "candidate"
    assert candidate["note"] == "not_the_record_decision"
    return candidate


def assert_own_read_only(record: hm.RemediationAction) -> None:
    """The record carries the decision of its own ``observe.evaluate``
    (review of PR #81, P2b): Recommended, Risk 0, nothing planned."""
    assert record.action_type == "observe.evaluate"
    assert record.decision.outcome is O.RECOMMENDED
    assert record.risk.risk_class is hm.RiskClass.READ_ONLY
    assert record.planned_changes == ()
    assert record.expected_impact == hm.Impact()  # the model's empty default
    assert record.playbook_id is None and record.playbook_version is None


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
    assert_own_read_only(record)
    full = engine.plan_for(record)
    plan = full.to_dict()
    explanation = candidate_of(full)
    assert explanation["outcome"] == "insufficient_evidence"
    assert explanation["policy"]["why_not"] == "context_missing"
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
    assert c.concurrent_repair is False  # the store answers it (review of PR #81)
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


@pytest.mark.usefixtures("quiet_security")
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
        assert_own_read_only(record)
        plan = engine.plan_for(record)
        assert plan.executable is False and plan.proposal.executable is False
        assert gate_of(plan)["permission"] == "run_read_only"
        candidate = candidate_of(plan)
        assert candidate["outcome"] == "requires_approval"
        assert candidate["policy"]["why"] == "risk_needs_approval"
        assert candidate["policy"]["risk"]["risk_class"] == int(hm.RiskClass.MEDIUM)
        assert candidate["playbook_id"] == "dns_recovery"
        assert candidate["planned_changes"] == [
            {"kind": "service", "target": "dnsmasq", "effect": "service.restart"}
        ]
        gate = candidate["gate"]
        # exactly one permission per mode (risk 2: never above approval)
        assert (
            gate["permission"]
            == {
                M.OBSERVE: "recommend",
                M.APPROVAL: "needs_approval",
                M.AUTO_HEAL: "needs_approval",
            }[mode]
        )
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


@pytest.mark.usefixtures("quiet_security")
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
    assert_own_read_only(record)
    candidate = candidate_of(engine.plan_for(record))
    assert candidate["outcome"] == "requires_approval"
    rules = {r["code"] for r in candidate["policy"]["rules"]}
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
    plan = candidate_of(engine.plan_for(first))
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
    assert_own_read_only(second)
    candidate = candidate_of(engine.plan_for(second))
    assert candidate["outcome"] == "not_safe"
    assert candidate["policy"]["why_not"] == "breaker_open"


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


@pytest.mark.usefixtures("quiet_security")
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
    assert_own_read_only(record)
    plan = engine.plan_for(record)
    assert candidate_of(plan)["outcome"] == outcome.value
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


LOOP_KEY = (R1, "service.restart", "service:dnsmasq")


def _seed_loop(store: Any) -> tuple[hm.AttemptRecord, hm.BreakerRecord]:
    safe = store.now()
    attempt = hm.AttemptRecord(
        count=1,
        window_start=safe - 60,
        last_at=safe - 60,
        cooldown_until=safe + 1800,
        recent=(safe - 60,),
        last_result="not_resolved",
    )
    breaker = hm.BreakerRecord(state=hm.BreakerState.OPEN, opened_at=safe)
    store.loop.attempts[LOOP_KEY] = attempt
    store.loop.breakers[LOOP_KEY] = breaker
    return attempt, breaker


def _meddle(context: he.DecisionContext) -> None:
    """Everything a hostile provider or decider could try on what it gets."""
    object.__setattr__(context, "hold", None)
    object.__setattr__(context, "fleet_paused", False)
    object.__setattr__(context, "effective_mode", M.AUTO_HEAL)
    object.__setattr__(context.action, "state", hm.ActionState.EXECUTING)
    object.__setattr__(context.action, "incident_type", "provider_was_here")
    for record in context.attempts.values():
        object.__setattr__(record, "cooldown_until", 0.0)
        object.__setattr__(record, "count", 0)
    for record in context.breakers.values():
        object.__setattr__(record, "state", hm.BreakerState.CLOSED)


async def test_the_provider_gets_a_copy_of_the_context(world: World) -> None:
    """A deep copy (review of PR #81, P1): changing what the provider is
    handed leaves the store (state, incident type, cooldowns, breakers) and
    the context the policy reads untouched."""
    seen: list[hp.DecisionInput] = []
    real_gate = hp.gate

    def spy(inp: hp.DecisionInput, **kw: Any) -> hp.GateVerdict:
        seen.append(inp)
        return real_gate(inp, **kw)

    class Meddler:
        def __init__(self) -> None:
            self.handed: list[he.DecisionContext] = []

        def facts(self, context: he.DecisionContext) -> he.HealFacts:
            self.handed.append(context)
            _meddle(context)
            return he.HealFacts()

    meddler = Meddler()
    engine = await world.start(decider=he.PolicyDecider(meddler))
    store = engine.store
    attempt, breaker = _seed_loop(store)
    assert store.loop.breakers[LOOP_KEY] == breaker
    safe = store.now()
    store.loop.fleet = hm.FleetPause(paused_until=safe + 3600, since=safe)
    with patch.object(hp, "gate", spy):
        world.open("inc-1")
    [record] = world.records()
    assert record.state is S.PROPOSED
    assert record.incident_type == "dns_failure"
    assert store.loop.attempts[LOOP_KEY] == attempt
    assert store.loop.attempts[LOOP_KEY].cooldown_until == safe + 1800
    assert store.loop.breakers[LOOP_KEY].state is hm.BreakerState.OPEN
    assert [a.state for a in store.open_actions()] == [S.PROPOSED]
    assert meddler.handed[0].action is not store.get(record.action_id)
    # the policy read the engine's own copy, not the meddled one
    assert seen[0].incident is not None
    assert seen[0].incident.incident_type == "dns_failure"
    assert engine.counters["decision_tampered"] == 0
    plan = engine.plan_for(record)
    assert "fleet_paused" in plan.blockers
    assert gate_of(plan)["effective_mode"] == "observe"
    assert engine.store.get(record.action_id).state is S.PROPOSED
    payload = store.payload()
    assert [a["state"] for a in payload["actions"]] == ["proposed"]


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
        refused_gate = engine.plan_for(record).to_dict()["explanation"]["gate"]
    assert record.decision.why_not == "no_decision_policy"
    assert refused_gate["permission"] == "none"
    assert refused_gate["reasons"] == ["module_disabled"]
    # the real gate again: the record's own Risk 0 step
    plan_gate = engine.plan_for(record).to_dict()["explanation"]["gate"]
    assert plan_gate["permission"] == "run_read_only"


# ---------------------------------------------------------------------------
# The mode the engine shows: the policy's
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("quiet_security")
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
        # the record's own Risk 0 step is not held; the candidate is
        assert gate_of(plan)["permission"] == "run_read_only"
        gate = candidate_of(plan)["gate"]
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


async def test_a_risk_one_candidate_never_becomes_the_record(world: World) -> None:
    """A Risk 1 candidate stays in the explanation; the record keeps its own
    Risk 0 step (the clamp for a decider that puts Risk 1 on the record:
    ``test_a_claimed_read_only_write_is_clamped``)."""
    engine = await world.start(decider=he.PolicyDecider(Candidate("diag.refresh")))
    world.open("inc-1", cause="dns_upstream", cause_status="hypothesis")
    [record] = world.records()
    assert_own_read_only(record)
    assert engine.counters["decision_clamped"] == 0
    candidate = candidate_of(engine.plan_for(record))
    assert candidate["action_type"] == "diag.refresh"
    assert candidate["policy"]["risk"]["risk_class"] == int(hm.RiskClass.LOW)


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


@pytest.mark.usefixtures("quiet_security")
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
    json.dumps(body["explanation"])
    explanation = candidate_of(engine.plan_for(record))
    assert body["explanation"]["policy"]["outcome"] == "recommended"
    assert body["explanation"]["policy"]["action_type"] == "observe.evaluate"
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
    # the record's outcome is its own, never the candidate's
    assert body["decision"]["outcome"] == "recommended"
    assert body["proposed_action_type"] == "observe.evaluate"
    assert body["planned_changes"] == []


@pytest.mark.usefixtures("quiet_security")
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
    assert plan["decision"]["outcome"] == "recommended"
    assert plan["explanation"]["candidate"]["label"] == "candidate"
    assert plan["explanation"]["candidate"]["outcome"] == "requires_approval"
    assert plan["explanation"]["candidate"]["texts_de"]
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
        assert record.decision.outcome is O.RECOMMENDED
        assert record.risk.risk_class is hm.RiskClass.READ_ONLY
        assert record.planned_changes == ()
        plan = engine.plan_for(record)
        if provider is not None:
            candidate = candidate_of(plan)
            assert candidate["outcome"] == "insufficient_evidence"
            assert candidate["policy"]["why_not"] == "context_missing"
        else:
            assert "candidate" not in plan.to_dict()["explanation"]
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


@pytest.mark.usefixtures("quiet_security")
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
    assert {r.decision.outcome for r in world.records()} == {O.RECOMMENDED}
    assert {candidate_of(engine.plan_for(r))["outcome"] for r in world.records()} == {
        "requires_approval"
    }
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
    assert len(engine._dedupe_seen) <= 1000


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
    assert len(engine._skip_memo) <= 1000
    assert len(world.records()) == 1
    # the slot frees: the next incident gets its record
    world.resolve("inc-1")
    records = world.records()
    assert len(records) == 2 and records[1].state is S.PROPOSED
    assert records[1].incident_id != "inc-1"


async def test_the_memo_stays_bounded(world: World) -> None:
    engine = await world.start()
    for n in range(1, 3000):
        iid = f"inc-{n}"
        world.ni.incidents[iid] = incident(iid, [E1])
        world.ni.announced[iid] = 0
    world.tick()
    world.tick()
    assert len(engine._skip_memo) == 1000  # SKIP_MEMO_MAX, the oldest dropped
    assert engine.pending_count() == 200  # PENDING_MAX


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
    assert proposal.action_type == "observe.evaluate"
    assert proposal.planned_changes == ()
    assert proposal.executable is False
    assert proposal.explanation is not None
    candidate = proposal.explanation["candidate"]
    assert candidate["action_type"] == "service.restart"
    assert candidate["outcome"] == "insufficient_evidence"
    assert candidate["planned_changes"] == []


# ---------------------------------------------------------------------------
# Review of PR #81
# ---------------------------------------------------------------------------


def _spy_gate() -> tuple[list[hp.DecisionInput], list[dict[str, Any]], Any]:
    inputs: list[hp.DecisionInput] = []
    kwargs: list[dict[str, Any]] = []
    real = hp.gate

    def spy(inp: hp.DecisionInput, **kw: Any) -> hp.GateVerdict:
        inputs.append(inp)
        kwargs.append(kw)
        return real(inp, **kw)

    return inputs, kwargs, spy


# P1: nothing handed to a provider or decider reaches the store


async def test_a_decider_cannot_change_the_stored_record(world: World) -> None:
    class MeddlingDecider:
        def propose(self, context: he.DecisionContext) -> he.Proposal:
            _meddle(context)
            return he.DEFAULT_DECIDER.propose(context)

    engine = await world.start(decider=MeddlingDecider())
    attempt, _breaker = _seed_loop(engine.store)
    world.open("inc-1")
    [record] = world.records()
    assert record.state is S.PROPOSED
    assert record.incident_type == "dns_failure"
    assert engine.store.loop.attempts[LOOP_KEY] == attempt
    assert engine.store.loop.breakers[LOOP_KEY].state is hm.BreakerState.OPEN
    engine.plan_for(record)
    assert engine.store.get(record.action_id).state is S.PROPOSED
    assert engine.counters["decision_tampered"] == 0


async def test_a_record_changed_during_its_decision_is_not_applied(
    world: World,
) -> None:
    """Defence behind the copy: a decider that reaches the live record some
    other way changes it; nothing is applied, the record is put back and
    the case is counted."""

    class Reaching:
        def propose(self, context: he.DecisionContext) -> he.Proposal:
            assert world.engine is not None
            live = world.engine.store.get(context.action.action_id)
            object.__setattr__(live, "state", hm.ActionState.EXECUTING)
            object.__setattr__(live, "incident_type", "decider_was_here")
            return he.DEFAULT_DECIDER.propose(context)

    engine = await world.start(decider=Reaching())
    world.open("inc-1")
    [record] = world.records()
    assert engine.counters["decision_tampered"] == 1
    assert record.state is S.ANALYZED
    assert record.incident_type == "dns_failure"
    assert states_of(record) == [S.DETECTED, S.ANALYZED]
    assert engine.counters["proposed"] == 0
    assert [a["state"] for a in engine.store.payload()["actions"]] == ["analyzed"]


# P2a: an NI maintenance lookup that fails or answers oddly stays unknown


@pytest.mark.parametrize("answer", ["raise", "yes", None, 1])
async def test_an_unusable_maintenance_answer_stays_unknown(
    world: World, answer: Any
) -> None:
    def lookup(entry_id: str) -> Any:
        if answer == "raise":
            raise RuntimeError("ni broken")
        return answer

    world.ni.in_maintenance = lookup
    engine = await world.start(decider=he.PolicyDecider())
    inputs, _kw, spy = _spy_gate()
    with patch.object(hp, "gate", spy):
        world.open("inc-1")
    [inp] = inputs
    assert inp.context.in_maintenance is None
    [record] = world.records()
    assert record.flags.in_maintenance is False
    context = engine.context_for(record)
    assert context.maintenance_known is False
    assert context.in_maintenance is False  # the plan's blocker flag only


# P2b: the record keeps its own decision; the candidate is only explained


@pytest.mark.usefixtures("quiet_security")
async def test_the_record_keeps_its_own_decision_not_the_candidates(
    world: World, measured: None
) -> None:
    engine = await world.start(decider=he.PolicyDecider(Favourable()))
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [record] = world.records()
    assert_own_read_only(record)
    assert record.target_components == (hm.ROUTER_COMPONENT,)  # observe's own
    assert record.history[-1].reason == "decision_recommended"
    candidate = candidate_of(engine.plan_for(record))
    assert candidate["action_type"] == "service.restart"
    assert "params" not in candidate  # only the catalog's, under policy
    assert candidate["policy"]["params"] == {"service": "dnsmasq"}
    assert candidate["outcome"] == "requires_approval"


# P2c: another type or another router is another incident


async def test_a_reused_id_on_another_router_is_a_new_incident(world: World) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    world.open("inc-1", first_seen=5000.0)
    [old] = world.records()
    # NI's store reset; the new inc-1 is on the other router, first seen
    # earlier (its evidence started before), another type
    world.ni.incidents.clear()
    world.ni.announced.clear()
    world.clock.now += 60
    world.open("inc-1", router=E2, first_seen=4000.0, type="wan_down")
    closed = engine.store.get(old.action_id)
    assert closed.state is S.CANCELLED
    assert closed.history[-1].reason == "incident_gone"
    new = world.of("inc-1")
    assert new.action_id != old.action_id
    assert new.router_id == R2 and new.incident_type == "wan_down"
    assert new.state is S.PROPOSED


@pytest.mark.parametrize(
    "change",
    [{"type": "wan_down"}, {"router": "other"}],
    ids=["type", "router"],
)
async def test_same_id_and_first_seen_but_another_incident(
    world: World, change: dict[str, str]
) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    world.open("inc-1", first_seen=5000.0)
    [old] = world.records()
    world.ni.incidents.clear()
    world.ni.announced.clear()
    world.clock.now += 60
    router = E2 if "router" in change else E1
    fields = {"type": change["type"]} if "type" in change else {}
    world.open("inc-1", router=router, first_seen=5000.0, **fields)
    assert engine.store.get(old.action_id).history[-1].reason == "incident_gone"
    records = [r for r in world.records() if r.incident_id == "inc-1"]
    assert len(records) == 2 and records[1].state is S.PROPOSED


@pytest.mark.parametrize("later", [1.0, 60.0, 3599.0, 3600.0])
async def test_a_first_seen_even_a_second_later_is_another_incident(
    world: World, later: float
) -> None:
    """No slack: NI only ever moves ``first_seen`` back (``_shift`` on a step
    back of its clock), so any later value is another incident."""
    engine = await world.start(decider=he.PolicyDecider())
    world.open("inc-1", first_seen=5000.0)
    [old] = world.records()
    world.ni.incidents["inc-1"] = incident("inc-1", [E1], first_seen=5000.0 + later)
    world.ni.announced["inc-1"] = 0
    world.tick()
    assert engine.store.get(old.action_id).history[-1].reason == "incident_gone"
    assert he._same_incident(old, 5000.0) is True
    assert he._same_incident(old, 4999.0) is True
    assert he._same_incident(old, 5000.0 + later) is False


async def test_root_state_of_another_incident_with_the_id_is_unknown(
    world: World,
) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    world.open("inc-1", first_seen=5000.0)
    [old] = world.records()
    assert engine.context_for(old).incident_is_root is True
    world.ni.incidents["inc-1"] = incident("inc-1", [E1], first_seen=9000.0)
    assert engine.context_for(old).incident_is_root is None
    assert engine.context_for(old).severity is None


# P3: the engine's unknown wins over a provider's claim


class Claimer:
    """Claims every engine-owned fact, favourably."""

    def facts(self, context: he.DecisionContext) -> he.HealFacts:
        return he.HealFacts(
            context=dataclasses.replace(
                GOOD_CONTEXT,
                role="gateway",
                identity_confirmed=True,
                breaker_open=False,
                in_maintenance=False,
                concurrent_repair=False,
            ),
            incident=dataclasses.replace(
                GOOD_INCIDENT,
                is_root=True,
                source_families=5,
                cause_status=hm.CauseStatus.CONFIRMED,
                cause_level=hm.CauseLevel.CONFIRMED,
                confidence=0.99,
                severity="critical",
            ),
            config_change_24h=False,
        )


async def test_the_engines_unknown_wins_over_a_provider_claim(world: World) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    world.open("inc-1")
    [record] = world.records()
    known = engine.context_for(record)
    unknown = dataclasses.replace(
        known,
        role=None,
        identity_status=None,
        safe_now=None,
        incident_is_root=None,
        cause=None,
        source_families=(),
        maintenance_known=False,
        in_maintenance=False,
        severity=None,
        concurrent_repair=None,
    )
    decider = he.PolicyDecider(Claimer())
    inp = decider.decision_input(unknown, decider._facts(unknown))
    c, i = inp.context, inp.incident
    assert i is not None
    assert c.role is None
    assert c.identity_confirmed is None
    assert c.breaker_open is None
    assert c.in_maintenance is None
    assert c.concurrent_repair is None
    assert i.is_root is None
    assert i.source_families == 0
    assert i.cause_status is hm.CauseStatus.HYPOTHESIS
    assert i.cause_level is hm.CauseLevel.UNKNOWN
    assert i.confidence is None
    assert i.severity is None
    assert inp.prior_failed_attempts is None
    # what the provider may fill stays its own
    assert c.reachable is True and i.target_fact is hp.TargetFact.DIRECT


async def test_severity_comes_from_network_intelligence(
    world: World, measured: None
) -> None:
    engine = await world.start(decider=he.PolicyDecider(Claimer()))
    inputs, _kw, spy = _spy_gate()
    with patch.object(hp, "gate", spy):
        world.open(
            "inc-1", cause="dns_upstream", cause_status="confirmed", severity="info"
        )
        world.open(
            "inc-2",
            router=E2,
            cause="dns_upstream",
            cause_status="confirmed",
            severity=SimpleNamespace(value="warning"),
        )
    severities = [inp.incident.severity for inp in inputs if inp.incident]
    assert severities == ["info", "warning"]  # the provider said critical
    record = world.of("inc-1")
    assert engine.context_for(record).severity == "info"
    for odd in ("loud", None, 3):
        world.ni.incidents["inc-1"].severity = odd
        assert engine.context_for(record).severity is None
    del world.ni.incidents["inc-1"].severity
    assert engine.context_for(record).severity is None


async def test_concurrent_repair_comes_from_the_store(world: World) -> None:
    engine = await world.start(decider=he.PolicyDecider(Claimer()))
    world.open("inc-1")
    [record] = world.records()
    assert engine.context_for(record).concurrent_repair is False
    lock = hm.LockRecord.external(R1, "button.reboot", T0)
    engine.store.loop.locks[R1] = lock
    context = engine.context_for(record)
    assert context.concurrent_repair is True
    decider = he.PolicyDecider(Claimer())
    inp = decider.decision_input(context, decider._facts(context))
    assert inp.context.concurrent_repair is True  # the provider said False
    del engine.store.loop.locks[R1]
    busy = SimpleNamespace(action_id="rem_other", state=S.EXECUTING)
    real_open = engine.store.open_actions

    def with_busy(router_id: str | None = None) -> list[Any]:
        return [*real_open(router_id), busy]

    with patch.object(engine.store, "open_actions", with_busy):
        assert engine.context_for(record).concurrent_repair is True
    assert engine.context_for(record).concurrent_repair is False


# P3: a reopened period gets its own record (E23)


async def test_a_reopened_period_gets_its_own_record(world: World) -> None:
    await world.start(decider=he.PolicyDecider())
    world.open("inc-1", first_seen=5000.0)
    world.resolve("inc-1")
    inc = world.ni.incidents["inc-1"]
    inc.status = IncidentStatus.ACTIVE
    inc.reopen_count = 1
    world.ni.announced["inc-1"] = 1
    world.clock.now += 60
    world.bus.fire(EVENT_INCIDENT, payload("inc-1", "reopened"))
    records = world.records()
    assert [(r.incident_reopen, r.state) for r in records] == [
        (0, S.CANCELLED),
        (1, S.PROPOSED),
    ]


# P3: the gate's inputs (E30, E31)


async def test_the_gate_gets_the_module_switch_and_no_green_guards(
    world: World, measured: None
) -> None:
    good = dataclasses.replace(GOOD_CONTEXT, diag_enabled=True)

    class Refresh:
        def facts(self, context: he.DecisionContext) -> he.HealFacts:
            return he.HealFacts(
                candidate_action="diag.refresh",
                candidate_params={},
                context=good,
                incident=GOOD_INCIDENT,
                config_change_24h=False,
            )

    engine = await world.start(decider=he.PolicyDecider(Refresh()))
    engine.store.set_settings(
        hm.HealSettings(
            routers={
                R1: hm.RouterSettings(
                    mode=M.AUTO_HEAL,
                    allowlist=(
                        hm.AllowEntry(
                            action_type="diag.refresh", params={}, max_risk=1
                        ),
                    ),
                )
            }
        )
    )
    _inputs, kwargs, spy = _spy_gate()
    with patch.object(hp, "gate", spy):
        world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    assert {kw["guards_green"] for kw in kwargs} == {None}
    assert {kw["module_enabled"] for kw in kwargs} == {True}
    [record] = world.records()
    candidate = candidate_of(engine.plan_for(record))
    assert candidate["outcome"] == "recommended"
    # Auto-Heal, allowlisted, Risk 1: only the preflight guards are missing
    assert candidate["gate"]["permission"] == "needs_approval"
    assert candidate["gate"]["reasons"] == ["guards_not_green"]
    # the module switch off: the gate refuses before deciding
    engine.store.set_settings(hm.HealSettings(enabled=False))
    plan = engine.plan_for(record).to_dict()["explanation"]
    assert plan["gate"]["permission"] == "none"
    assert plan["gate"]["reasons"] == ["module_disabled"]
    assert plan["candidate"]["gate"]["reasons"] == ["module_disabled"]


# P3: events with unknown ids count once per id


async def test_events_with_unknown_ids_count_once_per_id(world: World) -> None:
    engine = await world.start(decider=he.PolicyDecider())
    before = dict(engine.counters)
    for _ in range(10):
        for n in range(10):
            world.bus.fire(EVENT_INCIDENT, payload(f"inc-{n + 900}"))
    diff = {k: v - before[k] for k, v in engine.counters.items() if v != before[k]}
    assert diff == {"incidents_seen": 10, "skipped_unknown_incident": 10}
    for n in range(1001):
        world.bus.fire(EVENT_INCIDENT, payload(f"x-{n}"))
    assert len(engine._unknown_seen) == 1000  # UNKNOWN_SEEN_MAX
    assert "x-0" not in engine._unknown_seen and "x-1000" in engine._unknown_seen


# P3: size bounds pinned by literal numbers (E34, E40)


def test_the_explanation_bounds_are_literal() -> None:
    nested: Any = "x"
    for _ in range(8):
        nested = [nested]
    assert he._plain(nested) == [[[[[[None]]]]]]  # depth 6
    assert len(he._plain(list(range(100)))) == 64
    assert he._plain({"k": "y" * 300})["k"] == "y" * 256
    assert he._plain({"k" * 300: 1}) == {"k" * 256: 1}


async def test_the_dedupe_memory_holds_1000_periods(world: World) -> None:
    engine = await world.start()
    for n in range(1000):
        engine._dedupe_seen[(f"old-{n}", 0, None)] = None
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
    world.bus.fire(EVENT_INCIDENT, payload("inc-9", entry_ids=[E2]))
    assert engine.counters["deduplicated"] == 1
    assert len(engine._dedupe_seen) == 1000
    assert ("old-0", 0, None) not in engine._dedupe_seen
    assert ("inc-9", 0, None) in engine._dedupe_seen


# Guards behind guards, second round (mutation rerun of the review of PR #81)


async def test_a_resolved_pending_incident_is_dropped_without_a_detect(
    world: World,
) -> None:
    world.ni.incidents["inc-1"] = incident("inc-1", [E1])
    world.ni.announced["inc-1"] = 0
    engine = await world.start()
    world.open("inc-2")
    assert engine.pending_count() == 1
    world.ni.incidents["inc-2"].status = IncidentStatus.RESOLVED
    with patch.object(engine, "_detect", wraps=engine._detect) as spy:
        engine._retry_pending()
    spy.assert_not_called()
    assert engine.pending_count() == 0


async def test_a_reopen_while_the_old_period_is_open_is_not_deferred(
    world: World,
) -> None:
    """The router's slot is held by this incident's own record: that is the
    store's incident dedupe, not a deferral behind another incident."""
    engine = await world.start()
    world.open("inc-1")
    inc = world.ni.incidents["inc-1"]
    inc.reopen_count = 1
    world.ni.announced["inc-1"] = 1
    world.bus.fire(EVENT_INCIDENT, payload("inc-1", "reopened"))
    assert engine.pending_count() == 0
    assert engine.counters["deferred"] == 0
    assert engine.counters["deduplicated"] == 1


async def test_first_seen_is_kept_to_the_millisecond(world: World) -> None:
    await world.start()
    world.open("inc-1", first_seen=5000.123456)
    assert world.of("inc-1").params["first_seen"] == 5000.123


async def test_the_context_holds_only_the_routers_loop_records(
    world: World,
) -> None:
    engine = await world.start()
    _seed_loop(engine.store)
    other = (R2, "service.restart", "service:dnsmasq")
    engine.store.loop.attempts[other] = engine.store.loop.attempts[LOOP_KEY]
    engine.store.loop.breakers[other] = engine.store.loop.breakers[LOOP_KEY]
    world.open("inc-1")
    context = engine.context_for(world.of("inc-1"))
    assert set(context.attempts) == {LOOP_KEY}
    assert set(context.breakers) == {LOOP_KEY}


async def test_a_failing_candidate_leaves_the_record_alone(
    world: World, measured: None
) -> None:
    real = hp.gate

    def gate(inp: hp.DecisionInput, **kw: Any) -> hp.GateVerdict:
        if inp.action_type == "service.restart":
            raise hp.PolicyError("candidate only")
        return real(inp, **kw)

    decider = he.PolicyDecider(Favourable())
    engine = await world.start(decider=decider)
    with patch.object(hp, "gate", gate):
        world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
        [record] = world.records()
        explanation = engine.plan_for(record).to_dict()["explanation"]
    assert_own_read_only(record)
    assert engine.counters["decider_failed"] == 0
    assert decider.counters["candidate_failed"] == 2  # the step and the plan
    assert explanation["candidate"]["error"] == "candidate_failed"
    assert "outcome" not in explanation["candidate"]


# ---------------------------------------------------------------------------
# Second review of PR #81: hold and allowlist, the raw candidate params
# ---------------------------------------------------------------------------


def _hold_and_allowlist(store: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Auto-Heal with a Risk 1 allowlist entry, and the router held for an
    hour; their JSON forms (the objects themselves are what a write hits)."""
    safe = store.now()
    allow = hm.AllowEntry(
        action_type="diag.refresh", params={}, max_risk=hm.RiskClass.LOW
    )
    settings = hm.HealSettings(
        routers={R1: hm.RouterSettings(mode=M.AUTO_HEAL, allowlist=(allow,))}
    )
    store.set_settings(settings)
    hold = hm.RouterHold(
        router_id=R1,
        reason=hm.HoldReason.OUTCOME_UNKNOWN,
        since=safe - 10,
        until=safe + 3600,
    )
    store.loop.place_hold(hold)
    return hold.to_dict(), settings.to_dict()


class Vandal:
    """Writes into the hold, the allowlist and the cause it is handed."""

    def facts(self, context: he.DecisionContext) -> he.HealFacts:
        if context.hold is not None:
            object.__setattr__(context.hold, "until", 1.0)  # end the hold
        for entry in context.allowlist:
            object.__setattr__(entry, "action_type", "service.restart")
            object.__setattr__(entry, "params", {"service": "dnsmasq"})
            object.__setattr__(entry, "max_risk", hm.RiskClass.HIGH)
        if context.cause is not None:
            object.__setattr__(context.cause, "status", hm.CauseStatus.CONFIRMED)
            object.__setattr__(context.cause, "confidence", 1.0)
        return he.UNKNOWN_FACTS


async def test_a_provider_cannot_end_a_hold_or_rewrite_the_allowlist(
    world: World,
) -> None:
    """The reviewer's probe (N04 hold, N05 cause, N06 allowlist): the copies
    take every write, in the step and in the plans route, and the tamper
    check has nothing to put back."""
    engine = await world.start(decider=he.PolicyDecider(Vandal()))
    store = engine.store
    hold, settings = _hold_and_allowlist(store)
    world.open("inc-1", cause="dns_upstream", cause_status="hypothesis")
    [record] = world.records()
    assert record.state is S.PROPOSED
    assert engine.counters["decision_tampered"] == 0
    cause = record.cause.to_dict()
    assert record.cause.status is hm.CauseStatus.HYPOTHESIS
    engine.plan_for(record)
    engine.plan_for(record)
    assert store.loop.holds[R1].to_dict() == hold
    assert store.loop.hold_on(R1, store.now()) is not None
    assert store.settings.to_dict() == settings
    [entry] = store.settings.router(R1).allowlist
    assert entry.action_type == "diag.refresh"
    assert dict(entry.params) == {}
    assert entry.max_risk is hm.RiskClass.LOW
    assert store.get(record.action_id).cause.to_dict() == cause
    assert engine.effective_mode(R1) is M.OBSERVE


def _end_hold(store: Any) -> None:
    object.__setattr__(store.loop.holds[R1], "until", 1.0)


def _release_hold(store: Any) -> None:
    del store.loop.holds[R1]


def _hold_fleet(store: Any) -> None:
    safe = store.now()
    store.loop.place_hold(
        hm.RouterHold(
            router_id=None,
            reason=hm.HoldReason.OUTCOME_UNKNOWN,
            since=safe,
            until=safe + 60,
        )
    )


def _widen_allowlist(store: Any) -> None:
    [entry] = store.settings.router(R1).allowlist
    object.__setattr__(entry, "action_type", "service.restart")
    object.__setattr__(entry, "params", {"service": "dnsmasq"})
    object.__setattr__(entry, "max_risk", hm.RiskClass.HIGH)


def _replace_settings(store: Any) -> None:
    store.set_settings(hm.HealSettings(enabled=False))


@pytest.mark.parametrize(
    "write",
    [_end_hold, _release_hold, _hold_fleet, _widen_allowlist, _replace_settings],
    ids=["end_hold", "release_hold", "hold_fleet", "allowlist", "settings"],
)
async def test_holds_or_settings_changed_during_a_decision_are_put_back(
    world: World, write: Any
) -> None:
    """Defence behind the copies: a decider that reaches the live store some
    other way. Nothing is applied, the holds and the settings are put back
    as they were, and the case is counted. Any store write during a
    decision counts, even one that only makes things stricter (docs §2.1)."""

    class Reaching:
        def propose(self, context: he.DecisionContext) -> he.Proposal:
            assert world.engine is not None
            write(world.engine.store)
            return he.DEFAULT_DECIDER.propose(context)

    engine = await world.start(decider=Reaching())
    store = engine.store
    hold, settings = _hold_and_allowlist(store)
    holds_map = store.loop.holds
    world.open("inc-1")
    [record] = world.records()
    assert engine.counters["decision_tampered"] == 1
    assert engine.counters["proposed"] == 0
    assert record.state is S.ANALYZED
    assert store.loop.holds is holds_map
    assert {k: h.to_dict() for k, h in store.loop.holds.items()} == {R1: hold}
    assert store.loop.hold_on(R1, store.now()) is not None
    assert store.settings.to_dict() == settings
    [entry] = store.settings.router(R1).allowlist
    assert entry.max_risk is hm.RiskClass.LOW
    saved = store.payload()
    assert saved["settings"] == settings
    assert saved["loop"]["holds"] == [hold]


async def test_a_quiet_decision_restores_nothing(world: World) -> None:
    """The check itself writes nothing when nothing changed."""
    engine = await world.start(decider=he.PolicyDecider())
    store = engine.store
    _hold_and_allowlist(store)
    settings, holds = store.settings, dict(store.loop.holds)
    world.open("inc-1")
    assert engine.counters["decision_tampered"] == 0
    assert store.settings is settings
    assert store.loop.holds == holds
    assert all(store.loop.holds[k] is h for k, h in holds.items())


async def test_a_rollback_pending_record_is_a_concurrent_repair(
    world: World,
) -> None:
    """ROLLBACK_PENDING holds the repair lock but is not in flight (N13)."""
    engine = await world.start()
    world.open("inc-1")
    record = world.of("inc-1")
    busy = SimpleNamespace(action_id="rem_other", state=S.ROLLBACK_PENDING)
    real_open = engine.store.open_actions

    def with_busy(router_id: str | None = None) -> list[Any]:
        return [*real_open(router_id), busy]

    with patch.object(engine.store, "open_actions", with_busy):
        assert engine.context_for(record).concurrent_repair is True


@pytest.mark.parametrize(
    ("action", "params", "shown", "hidden"),
    [
        ("service.restart", {"service": "dnsmasq"}, {"service": "dnsmasq"}, ()),
        ("service.restart", {"service": "../etc/shadow"}, {}, ("../etc/shadow",)),
        ("diag.refresh", {"secret_key": "hunter2"}, {}, ("secret_key", "hunter2")),
    ],
)
async def test_the_candidate_shows_only_catalog_validated_params(
    world: World,
    measured: None,
    action: str,
    params: dict[str, Any],
    shown: Any,
    hidden: tuple[str, ...],
) -> None:
    engine = await world.start(decider=he.PolicyDecider(Favourable(action, **params)))
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [record] = world.records()
    assert_own_read_only(record)
    candidate = candidate_of(engine.plan_for(record))
    assert "params" not in candidate
    assert candidate["policy"]["params"] == shown
    text = json.dumps(engine.plan_for(record).to_dict())
    for raw in hidden:
        assert raw not in text


# ---------------------------------------------------------------------------
# Third review of PR #81: every changed record goes back; a failing compare
# ---------------------------------------------------------------------------


class OnceReaching:
    """A decider that reaches the live store on its first call only and
    keeps the record's JSON form from just before."""

    def __init__(self, world: World, write: Any) -> None:
        self.world, self.write, self.calls = world, write, 0
        self.before: dict[str, Any] | None = None

    def propose(self, context: he.DecisionContext) -> he.Proposal:
        self.calls += 1
        if self.calls == 1:
            assert self.world.engine is not None
            store = self.world.engine.store
            action_id = context.action.action_id
            self.before = store.actions[action_id].to_dict()
            self.write(store, action_id)
        return he.DEFAULT_DECIDER.propose(context)


def _replace_record(store: Any, action_id: str) -> None:
    live = store.actions[action_id]
    store.actions[action_id] = dataclasses.replace(live, action_type="service.restart")


def _remove_record(store: Any, action_id: str) -> None:
    del store.actions[action_id]


@pytest.mark.parametrize(
    "write", [_replace_record, _remove_record], ids=["replaced", "removed"]
)
async def test_a_record_replaced_or_removed_during_its_decision_is_put_back(
    world: World, write: Any
) -> None:
    decider = OnceReaching(world, write)
    engine = await world.start(decider=decider)
    store = engine.store
    world.open("inc-1")
    assert engine.counters["decision_tampered"] == 1
    assert engine.counters["proposed"] == 0
    [record] = world.records()
    assert decider.before is not None
    assert record.to_dict() == decider.before
    assert record.state is S.ANALYZED
    assert record.action_type == "observe.evaluate"
    [saved] = store.payload()["actions"]
    assert saved["action_type"] == "observe.evaluate"
    assert saved["state"] == "analyzed"
    assert saved == decider.before
    # the next tick decides the record that was put back, as usual
    world.tick()
    [record] = world.records()
    assert record.state is S.PROPOSED
    assert record.action_type == "observe.evaluate"
    assert engine.counters["decision_tampered"] == 1


async def test_a_failing_compare_of_the_holds_counts_as_a_change(
    world: World,
) -> None:
    """G08: something without a JSON form slipped into the holds; comparing
    raises, which counts as changed, and the holds are put back."""

    def slip(store: Any, action_id: str) -> None:
        store.loop.holds[R2] = object()

    engine = await world.start(decider=OnceReaching(world, slip))
    store = engine.store
    hold, _settings = _hold_and_allowlist(store)
    world.open("inc-1")
    assert engine.counters["decision_tampered"] == 1
    assert engine.counters["proposed"] == 0
    [record] = world.records()
    assert record.state is S.ANALYZED
    assert {k: h.to_dict() for k, h in store.loop.holds.items()} == {R1: hold}
    assert store.payload()["loop"]["holds"] == [hold]


async def test_a_failing_compare_of_the_settings_counts_as_a_change(
    world: World,
) -> None:
    def slip(store: Any, action_id: str) -> None:
        store.settings = object()

    engine = await world.start(decider=OnceReaching(world, slip))
    store = engine.store
    _hold, settings = _hold_and_allowlist(store)
    world.open("inc-1")
    assert engine.counters["decision_tampered"] == 1
    assert world.records()[0].state is S.ANALYZED
    assert isinstance(store.settings, hm.HealSettings)
    assert store.settings.to_dict() == settings


__all__ += ["R2", "Event", "FakeNI", "hc"]
