"""Self-Healing, package C1 (1.53.0): the engine skeleton (Observe only).

Order tests (Phase 7 order §22) covered here: 1 (Observe mode: a record is
made and analysed, nothing is ever written; the record stops at PROPOSED
and no plan is executable, whatever a decider says) and 34 (incident
correlation: one announced root on one router makes one record; a child, a
repeat, a fleet or multi-router incident makes none; a resolved incident
closes its record with the engine's time; correlation by time or a single
indicator alone never becomes an acting outcome). Further:

* zero extra router calls: two polls of the real api and coordinator
  (``full_router_kit``) make the same call list with the engine running,
  an incident and a tick as without it; no refresh, no listener;
* start and stop with the router entries, the routes registered once;
* a restart with records on disk (an interrupted execution stays "needs
  verification" and is never touched; an open observe record is closed
  only when Network Intelligence is loaded and the incident is gone);
* a held router and a paused fleet are respected (Observe) and reported;
* the module off creates nothing: no engine, no store, no listener, no
  tick, no route;
* the 5-minute tick advances the safety clock without any router call;
* the decision interface for package D (Protocol, default, clamp,
  failing decider), the diagnostics block and the options-flow switch.

Network Intelligence is the real engine of the P6 tests where the bus
event matters, a small stand-in elsewhere. Router names are roles; no
address, hostname or client name.
"""

from __future__ import annotations

import contextlib
import inspect
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import full_router_kit as kit
import pytest
from core_testkit import SECRET, FakeDisks, FakeEntry, make_hass
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import Event
from test_heal_store_v1530 import KEY, R1, R2, T0, Clock, disks, execute, new_action
from test_heal_store_v1530 import to_approved as store_to_approved
from test_net_p6 import (
    SETTLE,
    clock,
    intel,
    open_of,
    step,
    timers,
    wan,
)
from test_net_p6 import T0 as NI_T0

from custom_components.openwrt_router import config_api, net_engine, net_rules
from custom_components.openwrt_router import heal_engine as he
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_store as hs
from custom_components.openwrt_router.const import (
    DATA_SELF_HEALING_ENGINE,
    DATA_SELF_HEALING_VIEWS_BOUND,
    EVENT_INCIDENT,
    OPTION_SELF_HEALING_ENABLED,
)
from custom_components.openwrt_router.net_events import IncidentStatus

S = hm.ActionState
E1, E2 = "e1", "e2"

__all__ = ["clock", "disks", "intel", "timers"]  # fixtures used here


# --- stand-ins --------------------------------------------------------------------------


class Bus:
    """``hass.bus.async_listen`` with real removal; ``fire`` delivers."""

    def __init__(self) -> None:
        self.listeners: list[tuple[str, Any]] = []

    def async_listen(self, event_type: str, receiver: Any) -> Any:
        item = (event_type, receiver)
        self.listeners.append(item)

        def remove() -> None:
            self.listeners.remove(item)

        return remove

    def fire(self, event_type: str, data: Any) -> None:
        for kind, receiver in list(self.listeners):
            if kind == event_type:
                receiver(Event(event_type, data))


class Ticks:
    """``async_track_time_interval`` of the engine."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, timedelta]] = []
        self.unsubs: list[MagicMock] = []

    def __call__(self, hass: Any, action: Any, interval: timedelta) -> MagicMock:
        unsub = MagicMock()
        self.calls.append((action, interval))
        self.unsubs.append(unsub)
        return unsub

    def fire(self) -> None:
        for (action, _interval), unsub in zip(self.calls, self.unsubs, strict=True):
            if not unsub.called:
                action(None)


class Registry:
    """The core's Router Registry: entry id -> router id."""

    def __init__(self, routers: dict[str, str]) -> None:
        self.routers = dict(routers)
        self.state: dict[str, str] = {}
        self.flags: dict[str, tuple[Any, ...]] = {}

    def _record(self, entry_id: str) -> Any:
        rid = self.routers.get(entry_id)
        if rid is None:
            return None
        return SimpleNamespace(
            router_id=rid,
            state=self.state.get(entry_id, "active"),
            identity=SimpleNamespace(
                entry_id=entry_id,
                identity_flags=self.flags.get(entry_id, ()),
                role="gateway",
            ),
        )

    def get_by_entry(self, entry_id: str) -> Any:
        return self._record(entry_id)

    def find(self, router_id: str) -> Any:
        for entry_id, rid in self.routers.items():
            if rid == router_id:
                return self._record(entry_id)
        return None


class FakeNI:
    """Network Intelligence as the engine reads it (memory only)."""

    def __init__(self) -> None:
        self.loaded = True
        self.incidents: dict[str, Any] = {}
        self.ring: list[Any] = []
        self.maintenance: set[str] = set()
        # incident id -> the reopen count it was announced with on the bus
        self.announced: dict[str, int] = {}
        self.machine = SimpleNamespace(
            peek=lambda: list(self.incidents.values()), last_now=T0
        )

    def in_maintenance(self, entry_id: str) -> bool:
        return entry_id in self.maintenance

    def announced_reopen_count(self, incident_id: str) -> int | None:
        return self.announced.get(incident_id)


def incident(iid: str, routers: list[str], **fields: Any) -> Any:
    base: dict[str, Any] = {
        "id": iid,
        "type": "dns_failure",
        "routers": routers,
        "parent_id": None,
        "status": IncidentStatus.ACTIVE,
        "cause": None,
        "cause_status": None,
        "confidence": 0.7,
        "evidence": [],
        "reopen_count": 0,
    }
    base.update(fields)
    return SimpleNamespace(**base)


def payload(iid: str, state: str = "opened", **fields: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "state": state,
        "incident_id": iid,
        "type": "dns_failure",
        "severity": "warning",
        "confidence": 0.7,
        "cause": None,
        "cause_status": None,
        "cause_level": "unknown",
        "scope": "router",
        "routers": ["Router"],
        "entry_ids": [E1],
        "device_id": None,
        "reason": None,
    }
    data.update(fields)
    return data


class World:
    """One HA instance with two router entries, the core and NI."""

    def __init__(self, hass: Any, clock: Clock, ni: Any, registry: Registry) -> None:
        self.hass = hass
        self.clock = clock
        self.ni = ni
        self.registry = registry
        self.bus = Bus()
        self.ticks = Ticks()
        hass.bus.async_listen = self.bus.async_listen
        self.engine: he.HealEngine | None = None

    async def start(self, **kwargs: Any) -> he.HealEngine:
        kwargs.setdefault("clock", self.clock)
        kwargs.setdefault("monotonic", self.clock.mono)
        engine = he.HealEngine(self.hass, **kwargs)
        await engine.async_start()
        await engine.async_add_entries(e.entry_id for e in self.hass.entries)
        self.hass.data[DATA_SELF_HEALING_ENGINE] = engine
        self.engine = engine
        return engine

    def open(self, iid: str, router: str = E1, **fields: Any) -> None:
        """NI shows an active root and announces it (like ``_announce``)."""
        inc = self.ni.incidents[iid] = incident(iid, [router], **fields)
        self.ni.announced[iid] = inc.reopen_count
        self.bus.fire(EVENT_INCIDENT, payload(iid, entry_ids=[router]))

    def resolve(self, iid: str, *, reason: str | None = None) -> None:
        """NI resolves (or ignores) an incident and announces that."""
        inc = self.ni.incidents.get(iid)
        if inc is not None:
            inc.status = (
                IncidentStatus.IGNORED
                if reason == "ignored"
                else IncidentStatus.RESOLVED
            )
        self.ni.announced.pop(iid, None)
        self.bus.fire(EVENT_INCIDENT, payload(iid, "resolved", reason=reason))

    def tick(self, seconds: float = he.TICK_S) -> None:
        self.clock.now += seconds
        self.clock.real += seconds
        self.ticks.fire()

    def of(self, iid: str) -> hm.RemediationAction:
        """The newest record of an incident."""
        found = [a for a in self.records() if a.incident_id == iid]
        assert found, iid
        return found[-1]

    def records(self) -> list[hm.RemediationAction]:
        assert self.engine is not None
        return sorted(
            self.engine.store.actions.values(),
            key=lambda a: (a.created_at, a.action_id),
        )


def make_entries(*ids: str, **options: Any) -> list[FakeEntry]:
    """Router entries that finished their setup (LOADED, runtime data)."""
    entries = []
    for entry_id in ids:
        entry = FakeEntry(entry_id, options=dict(options))
        entry.runtime_data = SimpleNamespace(coordinator=object())
        entry.state = ConfigEntryState.LOADED
        entries.append(entry)
    return entries


def heal_hass(entries: list[Any]) -> Any:
    """A mocked hass with a configuration directory (the store itself is
    on FakeDisks: nothing is written there)."""
    hass = make_hass(entries)
    hass.config.config_dir = "/config"
    return hass


@contextlib.contextmanager
def patched(ni: Any, registry: Registry, ticks: Ticks) -> Any:
    api = SimpleNamespace(registry=registry)
    with (
        patch.object(net_engine, "async_get_engine", lambda hass: ni),
        patch.object(
            config_api, "async_get_configuration_api", AsyncMock(return_value=api)
        ),
        patch.object(he, "async_track_time_interval", ticks),
    ):
        yield


@pytest.fixture
async def world(disks: FakeDisks) -> Any:
    hass = heal_hass(make_entries(E1, E2))
    w = World(hass, Clock(), FakeNI(), Registry({E1: R1, E2: R2}))
    with patched(w.ni, w.registry, w.ticks):
        yield w
        if w.engine is not None and not w.engine.closed:
            await w.engine.async_stop()


class ActingDecider:
    """A decider (package D) that would act: the engine must not."""

    def __init__(self, outcome: hm.DecisionOutcome) -> None:
        self.outcome = outcome
        self.contexts: list[he.DecisionContext] = []

    def propose(self, context: he.DecisionContext) -> he.Proposal:
        self.contexts.append(context)
        return he.Proposal(
            decision=hm.Decision(
                outcome=self.outcome,
                score=0.95,
                factors=(hm.Factor(factor="policy", value=0.95, reason="test"),),
                why="test_policy",
                why_not=None,
            ),
            risk=hm.Risk(risk_class=hm.RiskClass.LOW, reasons=("test",)),
            playbook_id="dns_recovery",
            playbook_version=1,
            executable=True,
        )


class BrokenDecider:
    def propose(self, context: he.DecisionContext) -> he.Proposal:
        raise RuntimeError("policy failed")


def states_of(action: hm.RemediationAction) -> list[S]:
    return [h.to_state for h in action.history]


# --- order test 1: Observe, never a write -----------------------------------------------


async def test_observe_mode_records_and_never_writes(world: World) -> None:
    """Order test 1: a root incident becomes a record that stops at PROPOSED."""
    engine = await world.start()
    world.open("inc-1")
    [record] = world.records()
    assert record.router_id == R1
    assert record.action_type == he.OBSERVE_ACTION == "observe.evaluate"
    assert record.params == {"incident": "inc-1"}
    assert record.incident_id == "inc-1" and record.incident_type == "dns_failure"
    assert states_of(record) == [S.DETECTED, S.ANALYZED, S.PROPOSED]
    assert {h.actor for h in record.history} == {hm.Actor.ENGINE}
    assert [h.ts for h in record.history] == [T0, T0, T0]
    assert record.decision is not None
    assert record.decision.outcome is hm.DecisionOutcome.INSUFFICIENT_EVIDENCE
    assert record.decision.why_not == "no_decision_policy"
    assert record.risk.risk_class is hm.RiskClass.HIGH  # unassessed
    assert record.approval == hm.Approval() and record.execution == hm.Execution()
    assert record.preflight == () and record.backup_ref == hm.BackupRef()
    assert engine.store.effective_mode(R1) is hm.HealMode.OBSERVE
    # an hour of ticks: nothing moves on
    for _ in range(12):
        world.tick()
    assert world.records() == [engine.store.get(record.action_id)]
    assert engine.store.get(record.action_id).state is S.PROPOSED
    plan = engine.plan_for(engine.store.get(record.action_id))
    assert plan.executable is False
    assert {"no_write_path", "mode_observe", "nothing_executable"} <= set(plan.blockers)
    # no HA service, no bus event, no router lock
    world.hass.services.async_call.assert_not_called()
    assert world.hass.fired == []
    assert not engine.store.loop.repair_active(R1)
    assert engine.store.loop.locks == {}


@pytest.mark.parametrize(
    "outcome",
    [hm.DecisionOutcome.RECOMMENDED, hm.DecisionOutcome.REQUIRES_APPROVAL],
)
async def test_an_acting_decider_still_writes_nothing(
    world: World, outcome: hm.DecisionOutcome
) -> None:
    """Order test 1: even a confirmed cause and an acting decider stop at
    PROPOSED with no executable plan (no write path in 1.53.0)."""
    decider = ActingDecider(outcome)
    engine = await world.start(decider=decider)
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [record] = world.records()
    assert record.state is S.PROPOSED
    assert record.decision.outcome is outcome  # confirmed: not clamped
    assert record.playbook_id == "dns_recovery"
    assert engine.counters["decision_clamped"] == 0
    [context] = decider.contexts
    assert context.evidence_sufficient is True
    assert context.write_path_available is False
    assert context.effective_mode is hm.HealMode.OBSERVE
    plan = engine.plan_for(record)
    assert plan.executable is False and plan.proposal.executable is True
    assert "no_write_path" in plan.blockers and "mode_observe" in plan.blockers
    for _ in range(3):
        world.tick()
    assert engine.store.get(record.action_id).state is S.PROPOSED
    assert world.hass.fired == []
    world.hass.services.async_call.assert_not_called()


def test_no_write_path_and_no_router_access_in_the_modules() -> None:
    """Order test 1, statically: no router client, no service, no entity."""
    from custom_components.openwrt_router import heal_views

    assert he.WRITE_PATH_AVAILABLE is False
    for module in (he, heal_views):
        source = inspect.getsource(module)
        for needle in (
            "from .api",
            "OpenWrtAPI",
            "async_request_refresh",
            "async_refresh",
            "services.async_register",
            "async_call(",
            "async_fire",
            "Entity",
            "aiohttp.ClientSession",
            "async_get_clientsession",
        ):
            assert needle not in source, (module.__name__, needle)


# --- order test 34: incident correlation ------------------------------------------------


async def test_real_network_intelligence_root_makes_one_record(
    disks: FakeDisks, intel: Any
) -> None:
    """Order test 34 end to end: NI's own bus announcement (root, after the
    settle time) makes one record; its resolution closes it."""
    hass = heal_hass(make_entries("gw", "ap1"))
    w = World(hass, Clock(), intel, Registry({"gw": R1, "ap1": R2}))
    intel.hass.bus.async_fire.side_effect = lambda t, d=None, **kw: w.bus.fire(t, d)
    with patched(intel, w.registry, w.ticks):
        engine = await w.start()
        step(intel, NI_T0, wan())
        assert w.records() == []  # NI waits for a parent first
        step(intel, NI_T0 + SETTLE, wan())
        step(intel, NI_T0 + SETTLE + 60, wan())
        [record] = w.records()
        [inc] = open_of(intel, "wan_down")
        assert record.router_id == R1 and record.incident_id == inc.id
        assert record.incident_type == "wan_down"
        assert record.state is S.PROPOSED
        assert record.cause is None  # NI reports no cause: none is invented
        assert record.history[1].reason == "no_cause_reported"
        assert record.decision.outcome is hm.DecisionOutcome.INSUFFICIENT_EVIDENCE
        assert engine.counters["records_created"] == 1
        # the tick reconciles with NI's incidents: the record stays
        w.tick()
        assert engine.store.get(record.action_id).state is S.PROPOSED
        # NI resolves it and says so on the bus
        w.clock.now = T0 + 777
        step(intel, NI_T0 + 400, wan(0.0))
        closed = engine.store.get(record.action_id)
        assert closed.state is S.CANCELLED
        assert closed.history[-1].reason == "incident_cleared"
        assert closed.history[-1].ts == T0 + 777  # the engine's real time
        assert closed.history[-1].actor is hm.Actor.ENGINE
        step(intel, NI_T0 + 460, wan(0.0))
        assert len(w.records()) == 1
        await engine.async_stop()


async def test_cause_comes_from_network_intelligence(world: World) -> None:
    """The cause is NI's (code, status, confidence), never recomputed."""
    engine = await world.start()
    world.open(
        "inc-1", cause="dns_upstream", cause_status="hypothesis", confidence=0.42
    )
    [record] = world.records()
    assert record.cause is not None
    assert record.cause.code == "dns_upstream"
    assert record.cause.status is hm.CauseStatus.HYPOTHESIS
    assert record.cause.confidence == 0.42
    assert record.history[1].reason == "cause_from_incident"
    assert engine.counters["analyzed"] == engine.counters["proposed"] == 1


async def test_time_alone_is_never_an_acting_outcome(world: World) -> None:
    """Order test 34: a hypothesis on one source family (time or a single
    indicator) is clamped to insufficient evidence, whatever D says."""
    decider = ActingDecider(hm.DecisionOutcome.RECOMMENDED)
    engine = await world.start(decider=decider)
    world.open("inc-1", cause="dns_upstream", cause_status="hypothesis")
    [record] = world.records()
    assert decider.contexts[0].evidence_sufficient is False
    assert record.decision.outcome is hm.DecisionOutcome.INSUFFICIENT_EVIDENCE
    assert record.decision.why_not == "insufficient_evidence_sources"
    assert record.decision.score <= 0.59
    assert engine.counters["decision_clamped"] == 1
    plan = engine.plan_for(record)
    assert "insufficient_evidence_sources" in plan.blockers
    assert plan.executable is False


async def test_repeat_child_and_unclear_router_make_no_record(world: World) -> None:
    """Order test 34: one record per root; repeats, children, fleet and
    multi-router incidents make none (counted, never raised). What counts
    is what Network Intelligence holds, never the event's own fields."""
    engine = await world.start()
    world.open("inc-1")
    world.bus.fire(EVENT_INCIDENT, payload("inc-1"))  # announced again
    world.bus.fire(EVENT_INCIDENT, payload("inc-1", "reopened"))
    assert len(world.records()) == 1
    assert engine.counters["deduplicated"] == 2
    # a child of a known root stays silent
    world.ni.incidents["inc-2"] = incident("inc-2", [E2], parent_id="inc-1")
    world.ni.announced["inc-2"] = 0
    with patch.object(net_rules, "suppressed_child", lambda inc, known, now: True):
        world.bus.fire(EVENT_INCIDENT, payload("inc-2", entry_ids=[E2]))
    assert engine.counters["skipped_child"] == 1
    # the fleet, and two routers at once (NI's routers, whatever the event says)
    world.ni.incidents["inc-3"] = incident("inc-3", ["fleet"])
    world.ni.announced["inc-3"] = 0
    world.bus.fire(EVENT_INCIDENT, payload("inc-3", entry_ids=[E1]))
    world.ni.incidents["inc-4"] = incident("inc-4", [E1, E2])
    world.ni.announced["inc-4"] = 0
    world.bus.fire(EVENT_INCIDENT, payload("inc-4", entry_ids=[E2]))
    assert engine.counters["skipped_no_single_router"] == 2
    # unknown to NI: nothing, whatever router the event names
    world.bus.fire(EVENT_INCIDENT, payload("inc-5", entry_ids=[E2]))
    assert engine.counters["skipped_unknown_incident"] == 1
    # malformed announcements
    for bad in (None, "x", {"state": "opened"}, payload("inc-6", "bogus")):
        world.bus.fire(EVENT_INCIDENT, bad)
    assert engine.counters["skipped_bad_event"] == 4
    assert len(world.records()) == 1
    assert engine.counters["errors"] == 0


async def test_a_second_root_on_the_router_waits_for_the_first(world: World) -> None:
    """One open observe record per router: the next root is deferred and
    gets its record once the first closes."""
    engine = await world.start()
    world.open("inc-1")
    world.open("inc-2")
    assert len(world.records()) == 1
    assert engine.counters["deferred"] == 1 and engine.pending_count() == 1
    world.tick()  # still open: still waiting, counted once
    assert engine.counters["deferred"] == 1 and engine.pending_count() == 1
    world.clock.now += 5
    world.resolve("inc-1")
    first, second = world.records()
    assert first.incident_id == "inc-1" and first.state is S.CANCELLED
    assert second.incident_id == "inc-2" and second.state is S.PROPOSED
    assert second.history[0].reason == "incident_deferred"
    assert engine.pending_count() == 0
    # a deferred incident that resolves meanwhile is dropped
    world.open("inc-3")
    world.open("inc-4")
    assert engine.pending_count() == 2
    world.resolve("inc-4")
    assert engine.pending_count() == 1  # inc-3 still waits for inc-2


async def test_records_close_when_the_incident_goes(world: World) -> None:
    """Ignored, gone or now a child: closed with the right reason; a record
    is never closed while NI is not loaded (unknown is not cleared)."""
    engine = await world.start()
    world.open("inc-1", router=E1)
    world.open("inc-2", router=E2)
    world.resolve("inc-1", reason="ignored")
    first = world.of("inc-1")
    assert first.history[-1].reason == "incident_ignored"
    # NI not loaded: nothing closes on the tick
    del world.ni.incidents["inc-2"]
    world.ni.loaded = False
    world.tick()
    assert world.of("inc-2").state is S.PROPOSED
    world.ni.loaded = True
    world.tick()
    second = world.of("inc-2")
    assert second.state is S.CANCELLED
    assert second.history[-1].reason == "incident_gone"
    # re-parented as a child
    world.open("inc-3", router=E2)
    world.ni.incidents["inc-3"].parent_id = "inc-1"
    with patch.object(net_rules, "suppressed_child", lambda inc, known, now: True):
        world.tick()
    third = world.of("inc-3")
    assert third.history[-1].reason == "incident_now_child"
    assert engine.counters["closed"] == 3


async def test_disabled_unloaded_or_unregistered_routers_are_not_acted_on(
    world: World,
) -> None:
    engine = await world.start()
    world.hass.entries[0].disabled_by = "user"
    world.open("inc-1", router=E1)
    assert engine.counters["skipped_router_disabled"] == 1
    engine.remove_entry(E2)
    world.open("inc-2", router=E2)
    assert engine.counters["skipped_router_not_loaded"] == 1
    engine.add_entry(E2)
    world.registry.state[E2] = "orphaned"
    world.open("inc-3", router=E2)
    assert engine.counters["skipped_no_router_id"] == 1
    assert world.records() == []


async def test_maintenance_is_flagged_and_blocks(world: World) -> None:
    engine = await world.start()
    world.ni.maintenance.add(E1)
    world.open("inc-1")
    [record] = world.records()
    assert record.flags.in_maintenance is True
    assert "in_maintenance" in engine.plan_for(record).blockers


async def test_the_store_module_switch_off_makes_no_record(world: World) -> None:
    engine = await world.start()
    engine.store.set_settings(hm.HealSettings(enabled=False))
    world.open("inc-1")
    assert world.records() == []
    assert engine.counters["skipped_module_disabled"] == 1


async def test_capacity_refusals_are_counted_not_raised(world: World) -> None:
    engine = await world.start()
    with patch.object(
        engine.store, "add", MagicMock(side_effect=hs.CapacityError("full"))
    ):
        world.open("inc-1")
    assert engine.counters["refused_capacity"] == 1
    assert engine.counters["errors"] == 0 and world.records() == []


# --- the decision interface (package D) -------------------------------------------------


def test_the_default_decider_proposes_nothing_executable() -> None:
    assert isinstance(he.DEFAULT_DECIDER, he.HealDecider)
    assert isinstance(ActingDecider(hm.DecisionOutcome.RECOMMENDED), he.HealDecider)
    proposal = he.ObserveOnlyDecider().propose(MagicMock())
    assert proposal.executable is False
    assert proposal.decision.outcome is hm.DecisionOutcome.INSUFFICIENT_EVIDENCE
    assert proposal.decision.score == 0.0
    assert proposal.risk.risk_class is hm.RiskClass.HIGH
    assert proposal.planned_changes == () and proposal.playbook_id is None


async def test_a_failing_decider_falls_back_to_the_default(world: World) -> None:
    engine = await world.start(decider=BrokenDecider())
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [record] = world.records()
    assert record.state is S.PROPOSED
    assert record.decision.why_not == "no_decision_policy"
    assert engine.counters["decider_failed"] == 1
    assert engine.counters["errors"] == 0


async def test_the_context_tells_d_everything_it_may_read(world: World) -> None:
    decider = ActingDecider(hm.DecisionOutcome.NOT_SAFE)
    await world.start(decider=decider)
    world.open("inc-1")
    [context] = decider.contexts
    assert context.router_id == R1
    assert context.configured_mode is hm.HealMode.OBSERVE
    assert context.hold is None and context.fleet_paused is False
    assert context.module_enabled is True and context.in_maintenance is False
    assert context.router_loaded is True
    assert context.identity_status == "confirmed" and context.role == "gateway"
    assert context.action.state is S.ANALYZED


# --- holds and the fleet pause ----------------------------------------------------------


async def test_a_held_router_and_a_paused_fleet_are_respected(world: World) -> None:
    """An unknown state holds the router: its mode stays Observe, the plan
    says so; a fleet pause turns Auto-Heal into Approval."""
    engine = await world.start()
    store = engine.store
    store.set_settings(
        hm.HealSettings(
            routers={
                R1: hm.RouterSettings(mode=hm.HealMode.AUTO_HEAL),
                R2: hm.RouterSettings(mode=hm.HealMode.AUTO_HEAL),
            }
        )
    )
    safe = store.now()
    store.loop.place_hold(
        hm.RouterHold(
            router_id=R1, reason=hm.HoldReason.OUTCOME_UNKNOWN, since=safe, until=None
        )
    )
    store.loop.fleet = hm.FleetPause(
        paused_until=safe + 3600, since=safe, reason="store_lost"
    )
    assert store.effective_mode(R1) is hm.HealMode.OBSERVE
    assert store.effective_mode(R2) is hm.HealMode.APPROVAL
    decider = ActingDecider(hm.DecisionOutcome.RECOMMENDED)
    engine.decider = decider
    world.open("inc-1", router=E1, cause="x_y", cause_status="confirmed")
    world.open("inc-2", router=E2, cause="x_y", cause_status="confirmed")
    held, paused = world.of("inc-1"), world.of("inc-2")
    assert held.state is paused.state is S.PROPOSED
    first, second = decider.contexts
    assert first.hold is not None and first.effective_mode is hm.HealMode.OBSERVE
    assert first.configured_mode is hm.HealMode.AUTO_HEAL
    assert second.fleet_paused is True
    assert second.effective_mode is hm.HealMode.APPROVAL
    plan = engine.plan_for(held)
    assert {"router_held", "fleet_paused", "mode_observe"} <= set(plan.blockers)
    assert plan.executable is False
    assert "router_held" not in engine.plan_for(paused).blockers
    assert "fleet_paused" in engine.plan_for(paused).blockers
    # the hold has no end: hours of ticks keep it and the records
    for _ in range(24):
        world.tick()
    assert store.router_hold(R1) is not None
    assert {a.state for a in world.records()} == {S.PROPOSED}


# --- the safety clock -------------------------------------------------------------------


async def test_the_tick_reads_the_safety_clock_every_five_minutes(
    world: World,
) -> None:
    engine = await world.start()
    [(_action, interval)] = world.ticks.calls
    assert interval == timedelta(seconds=300) and he.TICK_S == 300.0
    before = engine.store.loop.clock.safe
    world.tick()
    assert engine.store.loop.clock.safe == before + 300
    assert engine.counters["ticks"] == 1
    assert engine.stats()["last_tick_s_ago"] == 0.0
    # the wall clock jumps back an hour: the safety clock still moves on
    world.clock.now -= 3600
    world.tick()
    assert engine.store.loop.clock.safe == before + 600
    assert engine.store.loop.clock.jumps_back >= 1
    assert world.hass.fired == []


async def test_the_tick_binds_the_core_later(world: World) -> None:
    """Without the core at start the engine runs on and binds on a tick."""
    with patch.object(
        config_api,
        "async_get_configuration_api",
        AsyncMock(side_effect=RuntimeError("core down")),
    ):
        engine = await world.start()
    assert engine.stats()["core_bound"] is False
    world.open("inc-1")
    assert engine.counters["skipped_no_router_id"] == 1
    world.tick()
    for task in list(world.hass.tasks):
        await task
    assert engine.stats()["core_bound"] is True


# --- life cycle -------------------------------------------------------------------------


async def test_engine_starts_with_the_first_router_and_stops_with_the_last(
    world: World,
) -> None:
    hass = world.hass
    e1, e2 = hass.entries
    await he.async_setup_self_healing(hass, e1)
    engine = he.async_get_self_healing(hass)
    assert engine is not None and engine.loaded
    await he.async_setup_self_healing(hass, e2)
    assert he.async_get_self_healing(hass) is engine
    assert engine.entries == {E1, E2}
    # one listener (a @callback method, never a lambda) and one tick
    [(event_type, receiver)] = world.bus.listeners
    assert event_type == EVENT_INCIDENT
    assert receiver == engine._on_incident
    assert getattr(receiver, "_hass_callback", False) is True
    assert receiver.__name__ != "<lambda>"
    assert len(world.ticks.calls) == 1
    # routes registered once, all of them
    assert hass.http.register_view.call_count == 5
    assert len(hass.data[DATA_SELF_HEALING_VIEWS_BOUND]) == 5
    await he.async_release_self_healing(hass, E1)
    assert he.async_get_self_healing(hass) is engine
    await he.async_release_self_healing(hass, E2)
    assert he.async_get_self_healing(hass) is None
    assert DATA_SELF_HEALING_ENGINE not in hass.data
    assert engine.closed and world.bus.listeners == []
    assert world.ticks.unsubs[0].called
    # a new start (reload) does not register the routes again
    await he.async_setup_self_healing(hass, e1)
    assert he.async_get_self_healing(hass) is not engine
    assert hass.http.register_view.call_count == 5
    await he.async_release_self_healing(hass, E1)
    # a stopped engine ignores late events and ticks
    world.bus.fire(EVENT_INCIDENT, payload("inc-1"))
    engine._on_tick(None)
    engine._on_incident(Event(EVENT_INCIDENT, payload("inc-1")))
    assert engine.counters["ticks"] == 0 and engine.store.actions == {}


async def test_module_off_creates_nothing(disks: FakeDisks) -> None:
    """The fleet switch off: no engine, no store, no listener, no tick, no
    route; an entry that says off wins over one that says on."""
    hass = heal_hass(make_entries(E1))
    hass.entries += make_entries(E2, **{OPTION_SELF_HEALING_ENABLED: False})
    w = World(hass, Clock(), FakeNI(), Registry({E1: R1, E2: R2}))
    with patched(w.ni, w.registry, w.ticks):
        assert he.self_healing_enabled(hass) is False
        for entry in hass.entries:
            await he.async_setup_self_healing(hass, entry)
        await he.async_release_self_healing(hass, E1)
        assert he.async_get_self_healing(hass) is None
        assert DATA_SELF_HEALING_ENGINE not in hass.data
        assert DATA_SELF_HEALING_VIEWS_BOUND not in hass.data
        hass.http.register_view.assert_not_called()
        assert w.bus.listeners == [] and w.ticks.calls == []
        assert KEY not in disks.disks and disks.stores == []
        from custom_components.openwrt_router.diagnostics import (
            _self_healing_summary,
        )

        assert _self_healing_summary(hass, E1) == {"enabled": False, "running": False}


async def test_a_disabled_entry_starts_nothing(disks: FakeDisks) -> None:
    hass = heal_hass(make_entries(E1))
    hass.entries[0].disabled_by = "user"
    w = World(hass, Clock(), FakeNI(), Registry({E1: R1}))
    with patched(w.ni, w.registry, w.ticks):
        await he.async_setup_self_healing(hass, hass.entries[0])
        assert he.async_get_self_healing(hass) is None and disks.stores == []


async def test_the_option_switches_the_running_engine(world: World) -> None:
    hass = world.hass
    for entry in hass.entries:
        await he.async_setup_self_healing(hass, entry)
    engine = he.async_get_self_healing(hass)
    await he.async_apply_self_healing_option(hass, on=False)
    assert he.async_get_self_healing(hass) is None and engine.closed
    await he.async_apply_self_healing_option(hass, on=True)
    again = he.async_get_self_healing(hass)
    assert again is not None and again.entries == {E1, E2}
    assert hass.http.register_view.call_count == 5
    # never raises
    with patch.object(he, "_async_engine", AsyncMock(side_effect=RuntimeError)):
        await he.async_apply_self_healing_option(hass, on=True)
    await he.async_release_self_healing(hass, E1)
    await he.async_release_self_healing(hass, E2)


async def test_a_failing_start_leaves_nothing_behind(world: World) -> None:
    hass = world.hass
    with (
        patch.object(
            hs.SelfHealingStore, "async_load", AsyncMock(side_effect=OSError("disk"))
        ),
        pytest.raises(OSError),
    ):
        await he.async_setup_self_healing(hass, hass.entries[0])
    assert he.async_get_self_healing(hass) is None
    assert DATA_SELF_HEALING_ENGINE not in hass.data
    hass.http.register_view.assert_not_called()


async def test_the_entry_wrapper_never_fails_a_router(world: World) -> None:
    """``__init__`` only wires: a Self-Healing failure never fails a setup."""
    import custom_components.openwrt_router as integration

    entry = world.hass.entries[0]
    with (
        patch.object(
            integration, "_async_setup_entry_tm", AsyncMock(return_value=True)
        ),
        patch.object(
            integration, "_async_unload_entry_tm", AsyncMock(return_value=True)
        ),
        patch.object(
            he, "async_setup_self_healing", AsyncMock(side_effect=RuntimeError)
        ),
        patch.object(
            he, "async_release_self_healing", AsyncMock(side_effect=RuntimeError)
        ),
    ):
        assert await integration.async_setup_entry(world.hass, entry) is True
        assert await integration.async_unload_entry(world.hass, entry) is True
    with (
        patch.object(
            integration, "_async_setup_entry_tm", AsyncMock(return_value=False)
        ),
        patch.object(he, "async_setup_self_healing", AsyncMock()) as setup,
    ):
        assert await integration.async_setup_entry(world.hass, entry) is False
        setup.assert_not_awaited()


# --- restart ----------------------------------------------------------------------------


async def test_restart_keeps_an_interrupted_execution_untouched(
    world: World, disks: FakeDisks
) -> None:
    """A record on disk in EXECUTING (another package's future state) comes
    back as "needs verification"; the engine never moves or runs it."""
    store = hs.SelfHealingStore(
        world.hass, clock=world.clock, monotonic=world.clock.mono
    )
    await store.async_load()
    action_id = store.add(new_action()).action.action_id
    store_to_approved(store, action_id)
    assert (await execute(store, action_id)).ok
    world.clock.now = T0 + 100
    engine = await world.start()
    assert engine.load_result is not None
    assert engine.load_result.recovered == [(action_id, S.EXECUTING, S.VERIFYING)]
    record = engine.store.get(action_id)
    assert record.state is S.VERIFYING and record.flags.interrupted
    world.ni.incidents.clear()
    world.resolve("inc-7")
    for _ in range(3):
        world.tick()
    after = engine.store.get(action_id)
    assert after == record
    assert states_of(after).count(S.EXECUTING) == 1
    assert engine.counters["closed"] == 0


async def test_restart_with_open_observe_records(world: World) -> None:
    engine = await world.start()
    world.open("inc-1", router=E1)
    world.open("inc-2", router=E2)
    first, second = world.of("inc-1").action_id, world.of("inc-2").action_id
    await engine.async_stop()
    # restart: NI still has inc-1, inc-2 is gone
    del world.ni.incidents["inc-2"]
    world.clock.now += 60
    world.clock.real += 60
    again = await world.start()
    assert again.store.get(first).state is S.PROPOSED
    assert again.store.get(second).state is S.CANCELLED
    assert again.store.get(second).history[-1].reason == "incident_gone"
    # NI announces inc-1 again after its own restart: no second record
    world.bus.fire(EVENT_INCIDENT, payload("inc-1"))
    assert len(world.records()) == 2 and again.counters["deduplicated"] == 1


async def test_restart_before_ni_is_loaded_closes_nothing(world: World) -> None:
    engine = await world.start()
    world.open("inc-1")
    [record] = world.records()
    await engine.async_stop()
    world.ni.loaded = False
    world.ni.incidents.clear()
    again = await world.start()
    assert again.store.get(record.action_id).state is S.PROPOSED


async def test_a_restart_between_the_steps_moves_the_record_on(world: World) -> None:
    """A record left in DETECTED (HA stopped between the steps) is
    analysed and proposed by the next start's reconcile."""
    store = hs.SelfHealingStore(
        world.hass, clock=world.clock, monotonic=world.clock.mono
    )
    await store.async_load()
    action = hm.RemediationAction.new(
        router_id=R1,
        action_type=he.OBSERVE_ACTION,
        ts=T0,
        actor=hm.Actor.ENGINE,
        reason="incident_opened",
        params={"incident": "inc-1"},
        incident_id="inc-1",
        incident_type="dns_failure",
    )
    store.add(action)
    await store.async_close()
    world.ni.incidents["inc-1"] = incident("inc-1", [E1])
    engine = await world.start()
    assert engine.store.get(action.action_id).state is S.PROPOSED


# --- zero extra router calls ------------------------------------------------------------


async def test_zero_extra_router_calls(world: World) -> None:
    """Two polls of the real api and coordinator: the same router call list
    with the engine running (an incident, a tick) as without it."""
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
    assert engine is not None
    world.engine = engine

    def after_poll(result: Any, n: int) -> None:
        coordinator.data = result
        coordinator.async_update_listeners()
        world.open(f"inc-{n + 1}", router=E1 if n == 0 else E2)
        world.tick()

    await kit.full_polls(coordinator, on_poll=after_poll)
    assert on_calls == off_calls
    assert len(on_calls) > 0
    coordinator.async_request_refresh.assert_not_awaited()
    coordinator.async_refresh.assert_not_awaited()
    assert coordinator._listeners == {}
    assert engine.counters["records_created"] == 2
    assert engine.counters["ticks"] == 2
    await he.async_release_self_healing(hass, E1)
    await he.async_release_self_healing(hass, E2)


# --- diagnostics ------------------------------------------------------------------------


async def test_diagnostics_block_has_counts_and_no_ids(world: World) -> None:
    from custom_components.openwrt_router.diagnostics import _self_healing_summary

    engine = await world.start()
    world.open("inc-1")
    safe = engine.store.now()
    engine.store.loop.place_hold(
        hm.RouterHold(
            router_id=R1, reason=hm.HoldReason.OUTCOME_UNKNOWN, since=safe, until=None
        )
    )
    block = _self_healing_summary(world.hass, E1)
    assert block["enabled"] is True and block["running"] is True
    assert block["release_mode"] == "observe_only" and block["write_path"] is False
    assert block["this_router_held"] is True
    assert block["records_by_state"]["proposed"] == 1
    assert block["effective_modes"]["observe"] == 2
    assert block["holds"] == [
        {
            "reason": "outcome_unknown",
            "fleet": False,
            "no_end": True,
            "remaining_s": None,
        }
    ]
    assert block["safety_clock"]["tick_s"] == 300.0
    assert block["engine"]["records_created"] == 1
    text = repr(block)
    for needle in (R1, R2, "rtr_", "rem_", "inc-1", E1, SECRET, "Router e1"):
        assert needle not in text
    assert _self_healing_summary(world.hass, E2)["this_router_held"] is False
    with patch.object(engine.store, "now", MagicMock(side_effect=RuntimeError)):
        assert _self_healing_summary(world.hass, E1) == {"loaded": False, "error": True}


# --- the options-flow switch ------------------------------------------------------------


def test_options_switch_is_written_through_to_every_router() -> None:
    from custom_components.openwrt_router import config_flow

    hass = heal_hass(make_entries(E1, E2))
    hass.entries.append(make_entries("e3", **{OPTION_SELF_HEALING_ENABLED: False})[0])
    hass.config_entries.async_update_entry = MagicMock()
    fields = config_flow._self_healing_option_fields(hass, {})
    [(key, _type)] = fields.items()
    assert str(key) == OPTION_SELF_HEALING_ENABLED and key.default() is False
    config_flow._write_self_healing_through(hass, hass.entries[0], True)
    [call] = hass.config_entries.async_update_entry.call_args_list
    assert call.args[0].entry_id == "e3"
    assert call.kwargs["options"] == {OPTION_SELF_HEALING_ENABLED: True}
    hass.config_entries.async_update_entry.reset_mock()
    config_flow._write_self_healing_through(hass, hass.entries[0], False)
    updated = [
        c.args[0].entry_id
        for c in hass.config_entries.async_update_entry.call_args_list
    ]
    assert updated == ["e2"]
    # default on: no option anywhere
    fresh = heal_hass(make_entries(E1))
    [(key, _type)] = config_flow._self_healing_option_fields(fresh, {}).items()
    assert key.default() is True
