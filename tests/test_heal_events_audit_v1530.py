"""Self-Healing package K1: audit entries, the bus event, the security veto.

Order test items 29 (audit of every state change), 30 (one HA event,
bounded, no addresses), 33 (Time Machine: the record's own times) and 35
(an open Security Center finding blocks every write proposal; the center
off is unknown, never "no findings").

The journal (``heal_journal``) is attached only to the running engine of
an HA instance (``_async_engine``); the bare engine of the older tests
journals nothing, so their ``hass.fired == []`` still holds.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from config_manager_kit import cm_env, drain, stop
from core_testkit import FakeDisks, make_hass
from test_heal_engine_v1530 import (
    E1,
    E2,
    World,
    world,
)
from test_heal_store_v1530 import R1, R2, T0, disks
from test_heal_x_engine_v1530 import Favourable, candidate_of, measured

from custom_components.openwrt_router import config_api, security_center
from custom_components.openwrt_router import heal_engine as he
from custom_components.openwrt_router import heal_journal as hj
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_policy as hp

S = hm.ActionState
A = hm.Actor

__all__ = ["disks", "measured", "world"]  # fixtures used here


# ---------------------------------------------------------------------------
# Stand-ins
# ---------------------------------------------------------------------------


class FakeAudit:
    """The core's Configuration API as the journal uses it."""

    def __init__(self, registry: Any) -> None:
        self.registry = registry
        self.prefixes: list[tuple[str, str]] = []
        self.mandatory: list[tuple[tuple[str, ...], str]] = []
        self.emitted: list[tuple[str, dict[str, Any]]] = []
        self.removed: list[str] = []
        self.fail_emit = False

    def register_event_prefix(self, prefix: str, *, module: str) -> Any:
        self.prefixes.append((prefix, module))
        return lambda: self.removed.append("prefix")

    def register_audit_mandatory_types(self, types: Any, *, module: str) -> Any:
        self.mandatory.append((tuple(types), module))
        return lambda: self.removed.append("mandatory")

    def emit(self, event_type: str, **kwargs: Any) -> None:
        if self.fail_emit:
            raise ValueError("refused")
        self.emitted.append((event_type, kwargs))

    def types(self) -> list[str]:
        return [t for t, _kw in self.emitted]


async def journaled(world: World, **kwargs: Any) -> tuple[he.HealEngine, FakeAudit]:
    """The world's engine with a journal and an audit-capable core."""
    audit = FakeAudit(world.registry)
    journal = hj.HealJournal(world.hass, clock=world.clock, monotonic=world.clock.mono)
    with patch.object(
        config_api, "async_get_configuration_api", AsyncMock(return_value=audit)
    ):
        engine = await world.start(journal=journal, **kwargs)
    return engine, audit


def remediation_events(hass: Any) -> list[dict[str, Any]]:
    return [d for t, d in hass.fired if t == hj.EVENT_REMEDIATION]


def record(
    path: list[hm.ActionState],
    *,
    ts0: float = T0,
    step: float = 1.0,
    router_id: str = R1,
    risk: hm.RiskClass = hm.RiskClass.HIGH,
) -> hm.RemediationAction:
    """A record whose history is DETECTED followed by ``path``."""
    base = hm.RemediationAction.new(
        router_id=router_id,
        action_type="observe.evaluate",
        ts=ts0,
        actor=A.ENGINE,
        reason="incident_opened",
        params={"incident": "inc-1"},
        incident_id="inc-1",
        incident_type="dns_failure",
    )
    history = [base.history[0]]
    previous = S.DETECTED
    for i, state in enumerate(path, 1):
        history.append(
            hm.HistoryEntry(
                from_state=previous,
                to_state=state,
                ts=ts0 + i * step,
                actor=A.ENGINE,
                reason="test_step",
            )
        )
        previous = state
    return dataclasses.replace(
        base,
        state=previous,
        history=tuple(history),
        updated_at=history[-1].ts,
        risk=hm.Risk(risk_class=risk),
    )


class Mono:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def unit_journal() -> tuple[hj.HealJournal, Any, Mono, list[float]]:
    hass = make_hass()
    mono = Mono()
    wall = [T0 + 100.0]
    journal = hj.HealJournal(hass, clock=lambda: wall[0], monotonic=mono)
    journal.start({})
    return journal, hass, mono, wall


# ---------------------------------------------------------------------------
# Closed sets, pinned by literal lists
# ---------------------------------------------------------------------------


def test_the_names_and_bounds_are_literal() -> None:
    assert hj.MODULE == "self_healing"
    assert hj.EVENT_PREFIX == "self_healing."
    assert hj.EVENT_REMEDIATION == "openwrt_router_remediation_event"
    assert hj.SIGNAL_SELF_HEALING == "openwrt_router_self_healing_update"
    assert hj.EVENT_RATE_MAX == 30
    assert hj.EVENT_RATE_WINDOW_S == 60.0
    assert hj.AUDIT_QUEUE_MAX == 100
    assert hj.DELAYED_S == 5.0


def test_the_audit_types_are_one_per_state() -> None:
    assert dict(hj.AUDIT_TYPES) == {
        S.DETECTED: "self_healing.action_detected",
        S.ANALYZED: "self_healing.action_analyzed",
        S.PROPOSED: "self_healing.action_proposed",
        S.PREFLIGHT: "self_healing.action_preflight",
        S.WAITING_APPROVAL: "self_healing.action_waiting_approval",
        S.APPROVED: "self_healing.action_approved",
        S.EXECUTING: "self_healing.action_executing",
        S.VERIFYING: "self_healing.action_verifying",
        S.RESOLVED: "self_healing.action_resolved",
        S.REJECTED: "self_healing.action_rejected",
        S.CANCELLED: "self_healing.action_cancelled",
        S.FAILED: "self_healing.action_failed",
        S.ROLLBACK_PENDING: "self_healing.action_rollback_pending",
        S.ROLLING_BACK: "self_healing.action_rolling_back",
        S.ROLLED_BACK: "self_healing.action_rolled_back",
        S.ESCALATED: "self_healing.action_escalated",
        S.MANUAL_RECOVERY_REQUIRED: "self_healing.action_manual_recovery_required",
    }
    assert hj.MANDATORY_TYPES == (
        "self_healing.action_approved",
        "self_healing.action_escalated",
        "self_healing.action_executing",
        "self_healing.action_failed",
        "self_healing.action_manual_recovery_required",
        "self_healing.action_rejected",
        "self_healing.action_resolved",
        "self_healing.action_rollback_pending",
        "self_healing.action_rolled_back",
        "self_healing.action_rolling_back",
        "self_healing.action_verifying",
    )
    assert hj.SECURITY_STATES == frozenset({S.EXECUTING, S.ROLLING_BACK})
    assert dict(hj.AUDIT_LEVEL) == {
        S.DETECTED: ("info", "info"),
        S.ANALYZED: ("info", "info"),
        S.PROPOSED: ("info", "info"),
        S.PREFLIGHT: ("info", "pending"),
        S.WAITING_APPROVAL: ("info", "pending"),
        S.APPROVED: ("info", "success"),
        S.REJECTED: ("info", "denied"),
        S.CANCELLED: ("info", "info"),
        S.EXECUTING: ("info", "pending"),
        S.VERIFYING: ("info", "pending"),
        S.RESOLVED: ("info", "success"),
        S.FAILED: ("warning", "failure"),
        S.ROLLBACK_PENDING: ("warning", "pending"),
        S.ROLLING_BACK: ("warning", "pending"),
        S.ROLLED_BACK: ("warning", "failure"),
        S.ESCALATED: ("warning", "failure"),
        S.MANUAL_RECOVERY_REQUIRED: ("critical", "failure"),
    }
    assert hj.AUDIT_DATA_KEYS == (
        "action_id",
        "action_type",
        "actor",
        "at",
        "delayed",
        "from_state",
        "incident_id",
        "incident_type",
        "outcome",
        "reason",
        "risk_class",
        "to_state",
    )


def test_the_event_states_and_payload_keys_are_literal() -> None:
    assert hj.EVENT_STATES == (
        "proposed",
        "approval_required",
        "started",
        "succeeded",
        "failed",
        "rollback_started",
        "rollback_failed",
        "manual_recovery_required",
        "escalated",
    )
    assert hj.EVENT_PAYLOAD_KEYS == (
        "action_id",
        "action_type",
        "actor",
        "device_id",
        "from_state",
        "incident_id",
        "incident_type",
        "outcome",
        "reason",
        "risk_class",
        "router_id",
        "state",
        "to_state",
        "ts",
    )
    assert hj.JOURNAL_COUNTERS == (
        "transitions",
        "events_fired",
        "events_suppressed",
        "events_failed",
        "audit_written",
        "audit_failed",
        "audit_queued",
        "audit_dropped",
        "audit_unavailable",
        "signals",
    )


# Every edge of the model -> the event state (None: no event); the table
# is the whole of ``heal_model.TRANSITIONS`` plus the first entry.
EXPECTED_EVENT_OF_EDGE = {
    (None, S.DETECTED): None,
    (S.DETECTED, S.ANALYZED): None,
    (S.DETECTED, S.CANCELLED): None,
    (S.ANALYZED, S.PROPOSED): "proposed",
    (S.ANALYZED, S.CANCELLED): None,
    (S.PROPOSED, S.PREFLIGHT): None,
    (S.PROPOSED, S.CANCELLED): None,
    (S.PROPOSED, S.ESCALATED): "escalated",
    (S.PROPOSED, S.REJECTED): None,
    (S.PREFLIGHT, S.WAITING_APPROVAL): "approval_required",
    (S.PREFLIGHT, S.APPROVED): None,
    (S.PREFLIGHT, S.CANCELLED): None,
    (S.WAITING_APPROVAL, S.APPROVED): None,
    (S.WAITING_APPROVAL, S.CANCELLED): None,
    (S.WAITING_APPROVAL, S.ESCALATED): "escalated",
    (S.WAITING_APPROVAL, S.REJECTED): None,
    (S.APPROVED, S.EXECUTING): "started",
    (S.APPROVED, S.CANCELLED): None,
    (S.EXECUTING, S.VERIFYING): None,
    (S.EXECUTING, S.FAILED): "failed",
    (S.VERIFYING, S.RESOLVED): "succeeded",
    (S.VERIFYING, S.FAILED): "failed",
    (S.VERIFYING, S.ESCALATED): "escalated",
    (S.VERIFYING, S.MANUAL_RECOVERY_REQUIRED): "manual_recovery_required",
    (S.VERIFYING, S.VERIFYING): None,
    (S.FAILED, S.ESCALATED): "escalated",
    (S.FAILED, S.ROLLBACK_PENDING): None,
    (S.ROLLBACK_PENDING, S.ROLLING_BACK): "rollback_started",
    (S.ROLLBACK_PENDING, S.MANUAL_RECOVERY_REQUIRED): "manual_recovery_required",
    (S.ROLLING_BACK, S.ROLLED_BACK): None,
    (S.ROLLING_BACK, S.MANUAL_RECOVERY_REQUIRED): "rollback_failed",
    (S.ROLLING_BACK, S.VERIFYING): None,
}


def test_the_edge_table_is_the_whole_model() -> None:
    assert set(EXPECTED_EVENT_OF_EDGE) - {(None, S.DETECTED)} == set(hm.TRANSITIONS)


@pytest.mark.parametrize(("edge", "expected"), list(EXPECTED_EVENT_OF_EDGE.items()))
def test_each_edge_has_its_event_state(edge: Any, expected: str | None) -> None:
    src, dst = edge
    if src is not None:
        assert (src, dst) in hm.TRANSITIONS  # a real edge of the model
    assert hj.event_state(src, dst) == expected


def test_every_event_state_is_reachable_and_only_these() -> None:
    reached = {hj.event_state(src, dst) for (src, dst) in hm.TRANSITIONS} | {
        hj.event_state(None, S.DETECTED)
    }
    assert reached == {None, *hj.EVENT_STATES}


# ---------------------------------------------------------------------------
# Order item 29: one audit entry per state change, none per tick
# ---------------------------------------------------------------------------


async def test_one_audit_entry_per_transition_and_none_per_tick(world: World) -> None:
    engine, audit = await journaled(world)
    assert audit.prefixes == [("self_healing.", "self_healing")]
    assert audit.mandatory == [(hj.MANDATORY_TYPES, "self_healing")]
    world.open("inc-1")
    [rec] = world.records()
    assert audit.types() == [
        "self_healing.action_detected",
        "self_healing.action_analyzed",
        "self_healing.action_proposed",
    ]
    kinds = [kw for _t, kw in audit.emitted]
    for kw in kinds:
        assert set(kw) == {
            "source",
            "router_id",
            "severity",
            "result",
            "actor",
            "correlation_id",
            "data",
            "security_relevant",
            "incident_ref",
        }
        assert kw["source"] == "self_healing" and kw["router_id"] == R1
        assert kw["correlation_id"] == rec.action_id
        assert kw["incident_ref"] == "inc-1"
        assert kw["security_relevant"] is False
        assert kw["severity"].value == "info" and kw["result"].value == "info"
        assert kw["actor"].kind.value == "module"
        assert kw["actor"].module == "self_healing"
        assert set(kw["data"]) == set(hj.AUDIT_DATA_KEYS)
    assert [kw["data"] for kw in kinds] == [
        {
            "action_id": rec.action_id,
            "action_type": "observe.evaluate",
            "actor": "engine",
            "at": T0,
            "delayed": False,
            "from_state": None,
            "incident_id": "inc-1",
            "incident_type": "dns_failure",
            "outcome": None,
            "reason": "incident_opened",
            "risk_class": None,
            "to_state": "detected",
        },
        {
            "action_id": rec.action_id,
            "action_type": "observe.evaluate",
            "actor": "engine",
            "at": T0,
            "delayed": False,
            "from_state": "detected",
            "incident_id": "inc-1",
            "incident_type": "dns_failure",
            "outcome": None,
            "reason": "no_cause_reported",
            "risk_class": None,
            "to_state": "analyzed",
        },
        {
            "action_id": rec.action_id,
            "action_type": "observe.evaluate",
            "actor": "engine",
            "at": T0,
            "delayed": False,
            "from_state": "analyzed",
            "incident_id": "inc-1",
            "incident_type": "dns_failure",
            "outcome": "insufficient_evidence",
            "reason": "decision_insufficient_evidence",
            "risk_class": 3,
            "to_state": "proposed",
        },
    ]
    signals = engine.journal.counters["signals"]
    # an hour of ticks and a repeated announcement: no state changes
    for _ in range(12):
        world.tick()
    world.bus.fire(he.EVENT_INCIDENT, {"state": "opened", "incident_id": "inc-1"})
    assert len(audit.emitted) == 3
    assert engine.journal.counters["transitions"] == 3
    assert engine.journal.counters["audit_written"] == 3
    assert engine.journal.counters["signals"] == signals + 12  # one per tick


async def test_a_close_writes_one_entry_and_fires_no_event(world: World) -> None:
    _engine, audit = await journaled(world)
    world.open("inc-1")
    fired = len(remediation_events(world.hass))
    world.resolve("inc-1")
    assert audit.types()[3:] == ["self_healing.action_cancelled"]
    _t, kw = audit.emitted[3]
    assert kw["data"]["from_state"] == "proposed"
    assert kw["data"]["to_state"] == "cancelled"
    assert kw["data"]["reason"] == "incident_cleared"
    assert kw["severity"].value == "info" and kw["result"].value == "info"
    assert len(remediation_events(world.hass)) == fired == 1


async def test_a_tick_journals_what_it_closed_at_once(world: World) -> None:
    """A record the tick closes (incident gone from NI without an
    announcement) is audited by that tick, not by a later sweep."""
    _engine, audit = await journaled(world)
    world.open("inc-2", router=E2)
    del world.ni.incidents["inc-2"]
    world.tick()
    assert audit.types()[3:] == ["self_healing.action_cancelled"]
    assert audit.emitted[3][1]["data"]["reason"] == "incident_gone"


async def test_a_start_journals_what_its_reconcile_changed(world: World) -> None:
    """The restart's reconcile closes a record whose incident went while
    HA was down; ``async_start`` alone already audits that."""
    engine, _audit = await journaled(world)
    world.open("inc-2", router=E2)
    await engine.async_stop()
    del world.ni.incidents["inc-2"]
    world.clock.now += 60
    world.clock.real += 60
    audit = FakeAudit(world.registry)
    journal = hj.HealJournal(world.hass, clock=world.clock, monotonic=world.clock.mono)
    again = he.HealEngine(
        world.hass, clock=world.clock, monotonic=world.clock.mono, journal=journal
    )
    with patch.object(
        config_api, "async_get_configuration_api", AsyncMock(return_value=audit)
    ):
        await again.async_start()
    assert audit.types() == ["self_healing.action_cancelled"]
    assert audit.emitted[0][1]["data"]["reason"] == "incident_gone"
    await again.async_stop()


async def test_added_routers_are_journaled_by_the_add(world: World) -> None:
    """An incident that waited for its router gets its record when the
    router is added; that call audits it, not a later tick."""
    audit = FakeAudit(world.registry)
    journal = hj.HealJournal(world.hass, clock=world.clock, monotonic=world.clock.mono)
    engine = he.HealEngine(
        world.hass, clock=world.clock, monotonic=world.clock.mono, journal=journal
    )
    with patch.object(
        config_api, "async_get_configuration_api", AsyncMock(return_value=audit)
    ):
        await engine.async_start()
        world.engine = engine
        world.open("inc-1", router=E1)  # E1 is not added yet: it waits
        assert world.records() == [] and audit.emitted == []
        await engine.async_add_entries([E1])
    assert audit.types() == [
        "self_healing.action_detected",
        "self_healing.action_analyzed",
        "self_healing.action_proposed",
    ]
    await engine.async_stop()


async def test_a_stop_journals_what_is_still_unseen(world: World) -> None:
    """The stop sweeps before it closes: a transition no earlier sweep saw
    still gets its entry."""
    engine, audit = await journaled(world)
    rec = record([S.ANALYZED, S.PROPOSED])
    engine.store.actions[rec.action_id] = rec  # changed without a sweep
    await engine.async_stop()
    assert audit.types() == [
        "self_healing.action_detected",
        "self_healing.action_analyzed",
        "self_healing.action_proposed",
    ]
    assert audit.removed == ["mandatory", "prefix"]


async def test_the_engine_without_a_journal_writes_and_fires_nothing(
    world: World,
) -> None:
    audit = FakeAudit(world.registry)
    with patch.object(
        config_api, "async_get_configuration_api", AsyncMock(return_value=audit)
    ):
        engine = await world.start()
    assert engine.journal is None
    world.open("inc-1")
    world.tick()
    world.resolve("inc-1")
    assert audit.prefixes == [] and audit.emitted == []
    assert world.hass.fired == []
    assert "journal" not in engine.stats()


async def test_the_running_engine_has_a_journal(world: World) -> None:
    hass = world.hass
    await he.async_setup_self_healing(hass, hass.entries[0])
    engine = he.async_get_self_healing(hass)
    assert engine is not None and isinstance(engine.journal, hj.HealJournal)
    stats = engine.stats()["journal"]
    # the world's core has a registry but no audit log
    assert stats["audit_bound"] is False and stats["audit_unavailable"] == 1
    await he.async_release_self_healing(hass, E1)
    assert engine.journal.closed is True


async def test_audit_waits_for_the_core_and_marks_the_delay(world: World) -> None:
    audit = FakeAudit(world.registry)
    journal = hj.HealJournal(world.hass, clock=world.clock, monotonic=world.clock.mono)
    down = AsyncMock(side_effect=RuntimeError("core not set up"))
    with patch.object(config_api, "async_get_configuration_api", down):
        engine = await world.start(journal=journal)
        world.open("inc-1")
    assert engine.router_ids() == []  # no core: no router id, no record
    assert world.records() == []
    # the record needs the core's router id; give the journal a record
    # through the store while the core is down
    rec = record([S.ANALYZED, S.PROPOSED], ts0=world.clock.now)
    engine.store.actions[rec.action_id] = rec
    engine._journal_sweep()
    assert journal.counters["audit_queued"] == 3 and audit.emitted == []
    assert len(remediation_events(world.hass)) == 1  # the event does not wait
    world.clock.now += 6.0
    with patch.object(
        config_api, "async_get_configuration_api", AsyncMock(return_value=audit)
    ):
        await engine.async_bind_core()
    assert audit.types() == [
        "self_healing.action_detected",
        "self_healing.action_analyzed",
        "self_healing.action_proposed",
    ]
    # ``at`` keeps the transition's own time
    # written at T0 + 6: 6, 5 and 4 s after the transitions (more than 5 s)
    assert [kw["data"]["delayed"] for _t, kw in audit.emitted] == [True, False, False]
    assert [kw["data"]["at"] for _t, kw in audit.emitted] == [
        rec.history[0].ts,
        rec.history[1].ts,
        rec.history[2].ts,
    ]
    assert journal.stats()["audit_waiting"] == 0


def test_the_queue_is_bounded_and_drops_the_oldest() -> None:
    journal, _hass, _mono, _wall = unit_journal()
    records = {}
    for i in range(51):
        rec = record([S.ANALYZED], ts0=T0 + i, step=0.5)
        records[rec.action_id] = rec
    journal.sweep(records)
    assert journal.counters["audit_queued"] == 102
    assert journal.counters["audit_dropped"] == 2
    assert journal.stats()["audit_waiting"] == 100
    audit = FakeAudit(None)
    journal.bind(audit)
    assert len(audit.emitted) == 100
    # the two oldest (T0 and its analysis at T0 + 0.5) went
    assert [kw["data"]["at"] for _t, kw in audit.emitted[:2]] == [T0 + 1, T0 + 1.5]


def test_a_refused_prefix_means_no_audit_and_nothing_else_breaks() -> None:
    journal, hass, _mono, _wall = unit_journal()
    audit = FakeAudit(None)
    audit.register_audit_mandatory_types = MagicMock(  # type: ignore[method-assign]
        side_effect=ValueError("belongs to another module")
    )
    journal.bind(audit)
    assert journal.audit_bound is False
    assert journal.counters["audit_unavailable"] == 1
    assert audit.removed == ["prefix"]  # the half registration is undone
    rec = record([S.ANALYZED, S.PROPOSED])
    assert journal.sweep({rec.action_id: rec}) == 3
    assert journal.counters["audit_queued"] == 3
    assert len([d for t, d in hass.fired if t == hj.EVENT_REMEDIATION]) == 1


def test_a_failing_emit_is_counted_and_the_rest_goes_on() -> None:
    journal, _hass, _mono, _wall = unit_journal()
    audit = FakeAudit(None)
    journal.bind(audit)
    audit.fail_emit = True
    rec = record([S.ANALYZED, S.PROPOSED])
    assert journal.sweep({rec.action_id: rec}) == 3
    assert journal.counters["audit_failed"] == 3
    assert journal.counters["audit_written"] == 0
    assert journal.counters["events_fired"] == 1


def test_close_removes_the_prefix_and_journals_nothing_more() -> None:
    journal, hass, _mono, _wall = unit_journal()
    audit = FakeAudit(None)
    journal.bind(audit)
    journal.close()
    assert audit.removed == ["mandatory", "prefix"]
    rec = record([S.ANALYZED, S.PROPOSED])
    assert journal.sweep({rec.action_id: rec}) == 0
    assert audit.emitted == [] and hass.fired == []


def test_security_relevant_and_mandatory_states_reach_the_core() -> None:
    journal, _hass, _mono, _wall = unit_journal()
    audit = FakeAudit(None)
    journal.bind(audit)
    path = [
        S.ANALYZED,
        S.PROPOSED,
        S.PREFLIGHT,
        S.WAITING_APPROVAL,
        S.APPROVED,
        S.EXECUTING,
        S.VERIFYING,
        S.FAILED,
        S.ROLLBACK_PENDING,
        S.ROLLING_BACK,
        S.MANUAL_RECOVERY_REQUIRED,
    ]
    rec = record(path)
    journal.sweep({rec.action_id: rec})
    got = [
        (
            t,
            kw["security_relevant"],
            kw["severity"].value,
            kw["result"].value,
        )
        for t, kw in audit.emitted
    ]
    assert got == [
        ("self_healing.action_detected", False, "info", "info"),
        ("self_healing.action_analyzed", False, "info", "info"),
        ("self_healing.action_proposed", False, "info", "info"),
        ("self_healing.action_preflight", False, "info", "pending"),
        ("self_healing.action_waiting_approval", False, "info", "pending"),
        ("self_healing.action_approved", False, "info", "success"),
        ("self_healing.action_executing", True, "info", "pending"),
        ("self_healing.action_verifying", False, "info", "pending"),
        ("self_healing.action_failed", False, "warning", "failure"),
        ("self_healing.action_rollback_pending", False, "warning", "pending"),
        ("self_healing.action_rolling_back", True, "warning", "pending"),
        (
            "self_healing.action_manual_recovery_required",
            False,
            "critical",
            "failure",
        ),
    ]
    # only the newest entry carries the record's decision and risk
    assert [kw["data"]["risk_class"] for _t, kw in audit.emitted] == [None] * 11 + [3]


def test_the_restart_entry_of_a_recovered_record_is_journaled_once() -> None:
    hass = make_hass()
    journal = hj.HealJournal(hass, clock=lambda: T0 + 20, monotonic=Mono())
    rec = record([S.ANALYZED, S.PROPOSED, S.PREFLIGHT])
    other = record([S.ANALYZED, S.PROPOSED])
    actions = {rec.action_id: rec, other.action_id: other}
    journal.start(actions, recovered=[rec.action_id])
    audit = FakeAudit(None)
    journal.bind(audit)
    assert journal.sweep(actions) == 1
    assert audit.types() == ["self_healing.action_preflight"]
    assert journal.sweep(actions) == 0
    assert len(audit.emitted) == 1


def test_a_record_shorter_than_seen_is_taken_as_seen() -> None:
    journal, _hass, _mono, _wall = unit_journal()
    rec = record([S.ANALYZED, S.PROPOSED])
    journal.sweep({rec.action_id: rec})
    short = dataclasses.replace(
        rec, history=rec.history[:1], state=S.DETECTED, risk=hm.Risk()
    )
    assert journal.sweep({rec.action_id: short}) == 0
    # it grows again from its own length: only the new entries count
    assert journal.sweep({rec.action_id: rec}) == 2


def test_forgotten_records_are_dropped_from_memory() -> None:
    journal, _hass, _mono, _wall = unit_journal()
    rec = record([S.ANALYZED])
    journal.sweep({rec.action_id: rec})
    assert journal.stats()["records_seen"] == 1
    journal.sweep({})
    assert journal.stats()["records_seen"] == 0


def test_a_sweep_with_a_change_signals_the_entities_once() -> None:
    journal, hass, _mono, _wall = unit_journal()
    rec = record([S.ANALYZED, S.PROPOSED])
    with patch.object(hj, "async_dispatcher_send") as send:
        assert journal.sweep({rec.action_id: rec}) == 3
        assert send.call_args_list == [call(hass, hj.SIGNAL_SELF_HEALING)]
        assert journal.version == 1
        assert journal.sweep({rec.action_id: rec}) == 0  # nothing new: no signal
        assert send.call_count == 1
        journal.close()
        journal.signal()
        assert send.call_count == 1  # closed: never again
    assert journal.counters["signals"] == 1


def test_an_incident_id_the_core_refuses_is_left_out() -> None:
    """The model takes ``a..b``; the core's reference token does not (it
    would refuse the whole entry), so the entry names no incident."""
    journal, hass, _mono, _wall = unit_journal()
    audit = FakeAudit(None)
    journal.bind(audit)
    rec = dataclasses.replace(record([S.ANALYZED, S.PROPOSED]), incident_id="inc..1")
    assert journal.sweep({rec.action_id: rec}) == 3
    assert [kw["incident_ref"] for _t, kw in audit.emitted] == [None, None, None]
    assert [kw["data"]["incident_id"] for _t, kw in audit.emitted] == [None] * 3
    assert [d["incident_id"] for d in remediation_events(hass)] == [None]
    # an id the core accepts is kept
    good = record([S.ANALYZED])
    journal.sweep({good.action_id: good})
    assert audit.emitted[-1][1]["incident_ref"] == "inc-1"


def test_entries_are_written_in_time_order_across_records() -> None:
    journal, _hass, _mono, _wall = unit_journal()
    audit = FakeAudit(None)
    journal.bind(audit)
    late = record([S.ANALYZED], ts0=T0 + 10)
    early = record([S.ANALYZED], ts0=T0)
    journal.sweep({late.action_id: late, early.action_id: early})
    assert [kw["data"]["at"] for _t, kw in audit.emitted] == [
        T0,
        T0 + 1,
        T0 + 10,
        T0 + 11,
    ]


# ---------------------------------------------------------------------------
# Order item 30: one HA event, bounded, ids and codes only
# ---------------------------------------------------------------------------


async def test_a_proposal_fires_exactly_one_event_with_ids_and_codes(
    world: World,
) -> None:
    world.hass.devices[E1] = "dev-e1"
    _engine, _audit = await journaled(world)
    world.open("inc-1")
    [rec] = world.records()
    [(name, data)] = [(t, d) for t, d in world.hass.fired]
    assert name == "openwrt_router_remediation_event"
    assert data == {
        "state": "proposed",
        "action_id": rec.action_id,
        "router_id": R1,
        "device_id": "dev-e1",
        "incident_id": "inc-1",
        "incident_type": "dns_failure",
        "action_type": "observe.evaluate",
        "from_state": "analyzed",
        "to_state": "proposed",
        "risk_class": 3,
        "outcome": "insufficient_evidence",
        "reason": "decision_insufficient_evidence",
        "actor": "engine",
        "ts": T0,
    }
    assert set(data) == set(hj.EVENT_PAYLOAD_KEYS)
    for _ in range(3):
        world.tick()
    assert len(world.hass.fired) == 1


async def test_the_event_names_no_address_host_or_title(world: World) -> None:
    for entry in world.hass.entries:
        entry.title = "gateway.home.lan"
        entry.data = {"host": "192.168.1.1", "password": "secret-pw"}
    _engine, _audit = await journaled(world)
    world.open("inc-1")
    world.open("inc-2", router=E2)
    assert len(world.hass.fired) == 2
    body = repr(world.hass.fired)
    for forbidden in ("192.168.1.1", "gateway.home.lan", "secret-pw"):
        assert forbidden not in body, forbidden
    for _name, data in world.hass.fired:
        # no entry id either (the device id is HA's own opaque id)
        assert E1 not in data.values() and E2 not in data.values()


async def test_the_event_is_fired_local_and_never_for_a_remote_announcement(
    world: World,
) -> None:
    _engine, _audit = await journaled(world)
    world.ni.incidents["inc-1"] = __import__("test_heal_engine_v1530").incident(
        "inc-1", [E1]
    )
    world.ni.announced["inc-1"] = 0
    from homeassistant.core import Event, EventOrigin

    for kind, receiver in list(world.bus.listeners):
        if kind == he.EVENT_INCIDENT:
            receiver(
                Event(
                    he.EVENT_INCIDENT,
                    {"state": "opened", "incident_id": "inc-1"},
                    origin=EventOrigin.remote,
                )
            )
    assert world.records() == [] and world.hass.fired == []
    world.bus.fire(he.EVENT_INCIDENT, {"state": "opened", "incident_id": "inc-1"})
    assert len(world.hass.fired) == 1
    call = world.hass.bus.async_fire.call_args
    assert call.kwargs == {"origin": EventOrigin.local}


def test_the_event_rate_is_bounded_per_minute() -> None:
    journal, hass, mono, _wall = unit_journal()
    records = {}
    for i in range(31):
        rec = record([S.ANALYZED, S.PROPOSED], ts0=T0 + i)
        records[rec.action_id] = rec
    journal.sweep(records)
    events = [d for t, d in hass.fired if t == hj.EVENT_REMEDIATION]
    assert len(events) == 30
    assert journal.counters["events_suppressed"] == 1
    assert journal.counters["events_fired"] == 30
    # the window slides: 59.9 s later still full, at 60 s room again
    more = {}
    for i in range(2):
        rec = record([S.ANALYZED, S.PROPOSED], ts0=T0 + 100 + i)
        more[rec.action_id] = rec
    mono.t += 59.9
    journal.sweep({**records, **more})
    assert journal.counters["events_suppressed"] == 3
    rec = record([S.ANALYZED, S.PROPOSED], ts0=T0 + 200)
    mono.t += 0.1
    journal.sweep({**records, **more, rec.action_id: rec})
    assert journal.counters["events_fired"] == 31
    assert journal.counters["events_suppressed"] == 3


def test_a_suppressed_event_still_writes_its_audit_entry() -> None:
    journal, _hass, _mono, _wall = unit_journal()
    audit = FakeAudit(None)
    journal.bind(audit)
    records = {}
    for i in range(31):
        rec = record([S.PROPOSED], ts0=T0 + i)
        records[rec.action_id] = rec
    journal.sweep(records)
    assert journal.counters["events_suppressed"] == 1
    assert audit.types().count("self_healing.action_proposed") == 31


def test_a_failing_bus_is_counted() -> None:
    journal, hass, _mono, _wall = unit_journal()
    hass.bus.async_fire.side_effect = RuntimeError("bus down")
    rec = record([S.PROPOSED])
    journal.sweep({rec.action_id: rec})
    assert journal.counters["events_failed"] == 1
    assert journal.counters["events_fired"] == 0


def test_an_unknown_device_is_none_and_a_failing_lookup_too() -> None:
    journal, hass, _mono, _wall = unit_journal()
    a = record([S.PROPOSED], ts0=T0)
    b = record([S.PROPOSED], ts0=T0 + 5)

    def lookup(router_id: str) -> Any:
        raise RuntimeError("registry gone")

    journal.sweep({a.action_id: a}, lambda rid: 42)  # type: ignore[arg-type,return-value]
    journal.sweep({a.action_id: a, b.action_id: b}, lookup)
    devices = [d["device_id"] for t, d in hass.fired]
    assert devices == [None, None]


def test_the_rollback_failure_event() -> None:
    journal, hass, _mono, _wall = unit_journal()
    rec = record(
        [
            S.ANALYZED,
            S.PROPOSED,
            S.PREFLIGHT,
            S.WAITING_APPROVAL,
            S.APPROVED,
            S.EXECUTING,
            S.VERIFYING,
            S.FAILED,
            S.ROLLBACK_PENDING,
            S.ROLLING_BACK,
            S.MANUAL_RECOVERY_REQUIRED,
        ]
    )
    journal.sweep({rec.action_id: rec})
    assert [d["state"] for t, d in hass.fired] == [
        "proposed",
        "approval_required",
        "started",
        "failed",
        "rollback_started",
        "rollback_failed",
    ]
    # the record's risk and outcome only on the newest entry
    assert [d["risk_class"] for t, d in hass.fired] == [None] * 5 + [3]


# ---------------------------------------------------------------------------
# The real core: prefix, ring, masking and the Time Machine (order item 33)
# ---------------------------------------------------------------------------


@pytest.fixture
def core_disks() -> Iterator[FakeDisks]:
    with FakeDisks().patch() as fake:
        yield fake


async def test_the_real_core_keeps_the_entries_and_the_time_machine_shows_them(
    core_disks: FakeDisks, tmp_path: Any
) -> None:
    from custom_components.openwrt_router import core_audit
    from custom_components.openwrt_router import tm_sources as src
    from custom_components.openwrt_router.core_models import AuditRing

    env = await cm_env(core_disks, tmp_path, routers=1, options={})
    now = env.clock.utc().timestamp()
    journal = hj.HealJournal(env.hass, clock=lambda: now)
    journal.start({})
    journal.bind(env.api)
    assert journal.audit_bound is True
    rec = record([S.ANALYZED, S.PROPOSED], ts0=now - 2, router_id=env.rid)
    with patch.object(core_audit, "utcnow", env.clock.utc):
        journal.sweep({rec.action_id: rec})
    stored = env.api.events(ring=AuditRing.GENERAL, limit=1000)
    mine = [e for e in stored if str(e.type).startswith("self_healing.")]
    assert [str(e.type) for e in mine] == [
        "self_healing.action_detected",
        "self_healing.action_analyzed",
        "self_healing.action_proposed",
    ]
    for event in mine:
        assert event.source == "self_healing"
        assert event.router_id == env.rid
        assert event.correlation_id == rec.action_id
        assert event.incident_ref == "inc-1"
        # the masking keeps ids and codes as they are
        assert event.data["action_id"] == rec.action_id
        assert event.data["incident_id"] == "inc-1"
    assert [e.data["at"] for e in mine] == [now - 2, now - 1, now]
    req = src.ReadRequest(now - 3600, now + 1, True, now + 1)
    result = await src.async_read_source(
        env.hass, "core_audit", req, src.build_router_map(env.hass)
    )
    marks = [
        m for m in result.marks if m["title_key"].startswith("core_audit.self_healing")
    ]
    assert sorted(m["title_key"] for m in marks) == [
        "core_audit.self_healing.action_analyzed",
        "core_audit.self_healing.action_detected",
        "core_audit.self_healing.action_proposed",
    ]
    for mark in marks:
        assert mark["kind"] == "audit_event"
        assert mark["router_id"] == env.rid
        # the mark's time is the audit entry's (written now), never made up
        assert mark["ts"] == pytest.approx(now, abs=1.0)
    # not for non-admins (the audit source is admin only)
    plain = await src.async_read_source(
        env.hass,
        "core_audit",
        src.ReadRequest(now - 3600, now + 1, False, now + 1),
        src.build_router_map(env.hass),
    )
    assert plain.marks == []
    journal.close()
    await stop(env)
    await drain(env.hass)


def test_the_ring_fits_seven_module_shares_and_the_core() -> None:
    """With Self-Healing seven modules write to the general ring. The ring
    grew by one module share, so no owner's guaranteed share got smaller
    (before 1.53.0: 1000 entries, six modules, core 400, module 100)."""
    from custom_components.openwrt_router import core_models as cm

    assert cm.AUDIT_MAX_EVENTS == 1100
    assert cm.AUDIT_SHARED_MODULES == 7
    assert cm.AUDIT_MODULE_SHARE == 100
    assert cm.AUDIT_CORE_SHARE == 400
    assert cm.AUDIT_CORE_SHARE + cm.AUDIT_SHARED_MODULES * cm.AUDIT_MODULE_SHARE == (
        cm.AUDIT_MAX_EVENTS
    )
    assert cm.SECURITY_AUDIT_MAX_EVENTS == 500  # the security ring is unchanged
    assert cm.SECURITY_MODULE_QUOTA == 100
    assert cm.SECURITY_MODULE_MAX_EVENTS == 500


# The six modules that wrote to the general ring before 1.53.0, with the
# prefixes they register (``register_event_prefix`` in each module).
OTHER_MODULES = (
    ("config_manager", "config_manager."),
    ("net_diagnostics", "net_diagnostics."),
    ("security_center", "security_center."),
    ("time_machine", "time_machine."),
    ("traffic_analytics", "traffic_analytics."),
    ("wifi_rf", "wifi_rf."),
)


async def test_every_owner_keeps_its_full_share_with_self_healing(
    core_disks: FakeDisks, tmp_path: Any
) -> None:
    """All seven modules and the core at their share fill the ring exactly;
    more Self-Healing entries then cost only Self-Healing's own oldest."""
    from custom_components.openwrt_router import core_audit
    from custom_components.openwrt_router.core_models import (
        AUDIT_MAX_EVENTS,
        AuditRing,
        CoreEventType,
    )

    env = await cm_env(core_disks, tmp_path, routers=1, options={})
    audit = env.core.audit
    with patch.object(core_audit, "utcnow", env.clock.utc):
        baseline = audit.summary()
        free_core = 400 - baseline["general_core_entries"]
        for i in range(free_core):
            audit.emit(
                CoreEventType.ROUTER_REGISTERED, router_id=env.rid, data={"i": i}
            )
        for module, prefix in OTHER_MODULES:
            if module not in baseline["general_module_entries"]:
                audit.register_event_prefix(prefix, module=module)
            have = baseline["general_module_entries"].get(module, 0)
            for i in range(100 - have):
                audit.emit(f"{prefix}sample", source=module, data={"i": i})
        journal = hj.HealJournal(env.hass)
        journal.start({})
        journal.bind(env.api)
        records = {}
        for i in range(50):  # 50 records of two entries: exactly 100
            rec = record([S.ANALYZED], ts0=T0 + i, router_id=env.rid)
            records[rec.action_id] = rec
        journal.sweep(records)
        assert audit.ring_size(AuditRing.GENERAL) == AUDIT_MAX_EVENTS
        assert audit.stats["evicted_general"] == 0  # exactly full: nothing went
        summary = audit.summary()
        assert summary["general_core_entries"] == 400
        assert summary["general_module_entries"] == {
            **{module: 100 for module, _prefix in OTHER_MODULES},
            "self_healing": 100,
        }
        # three more Self-Healing entries: only its own three oldest go
        more = record([S.ANALYZED, S.PROPOSED], ts0=T0 + 100, router_id=env.rid)
        journal.sweep({**records, more.action_id: more})
        summary = audit.summary()
        assert summary["general_evicted"] == {"self_healing": 3}
        assert summary["general_core_entries"] == 400
        assert summary["general_module_entries"]["self_healing"] == 100
        for module, _prefix in OTHER_MODULES:
            assert summary["general_module_entries"][module] == 100
    assert journal.counters["audit_written"] == 103
    journal.close()
    await stop(env)


async def test_k2_manual_actions_share_the_module_and_coexist(
    core_disks: FakeDisks, tmp_path: Any
) -> None:
    """Package K2 (``heal_guard``, not on main yet) registers
    ``self_healing.manual.`` for the same module ``self_healing`` and writes
    ``self_healing.manual.action``. The journal's broader prefix
    ``self_healing.`` coexists with it in either order, neither remover
    takes the other's away, both count as one module, and the Time Machine
    shows both as audit marks at their audit time (administrators only)."""
    from custom_components.openwrt_router import core_audit
    from custom_components.openwrt_router import tm_sources as src
    from custom_components.openwrt_router.core_models import AuditRing

    manual = "self_healing.manual.action"  # literal: heal_guard is not imported
    assert not any(
        t.startswith("self_healing.manual.") for t in hj.AUDIT_TYPES.values()
    )
    assert not any(t.startswith("self_healing.manual.") for t in hj.MANDATORY_TYPES)
    env = await cm_env(core_disks, tmp_path, routers=1, options={})
    now = env.clock.utc().timestamp()
    audit = env.core.audit
    with patch.object(core_audit, "utcnow", env.clock.utc):
        # K2 first (its first manual entry on this core), then the journal
        k2_remove = env.api.register_event_prefix(
            "self_healing.manual.", module="self_healing"
        )
        journal = hj.HealJournal(env.hass, clock=lambda: now)
        journal.start({})
        journal.bind(env.api)
        assert journal.audit_bound is True
        env.api.emit(manual, source="self_healing", router_id=env.rid)
        rec = record([S.ANALYZED], ts0=now - 1, router_id=env.rid)
        journal.sweep({rec.action_id: rec})
        # the journal stops: K2's prefix stays
        journal.close()
        env.api.emit(manual, source="self_healing", router_id=env.rid)
        with pytest.raises(ValueError):
            env.api.emit(
                "self_healing.action_detected", source="self_healing", router_id=env.rid
            )
        # the other order: the journal binds again, K2 goes away first
        again = hj.HealJournal(env.hass, clock=lambda: now)
        again.start({})
        again.bind(env.api)
        k2_remove()
        other = record([S.ANALYZED], ts0=now - 1, router_id=env.rid)
        again.sweep({other.action_id: other})
        assert again.counters["audit_written"] == 2
        assert again.counters["audit_failed"] == 0
        # below the journal's prefix a manual entry is still accepted
        env.api.emit(manual, source="self_healing", router_id=env.rid)
    stored = env.api.events(ring=AuditRing.GENERAL, limit=5000)
    mine = [str(e.type) for e in stored if str(e.type).startswith("self_healing.")]
    assert mine == [
        manual,
        "self_healing.action_detected",
        "self_healing.action_analyzed",
        manual,
        "self_healing.action_detected",
        "self_healing.action_analyzed",
        manual,
    ]
    assert audit.summary()["general_module_entries"]["self_healing"] == 7
    # named on purpose, not by the fallback: a later catch-all keeps it
    assert ("self_healing.", "audit_event") in src._MODULE_KINDS
    assert src.audit_kind(manual) == "audit_event"
    assert src.audit_kind("self_healing.action_proposed") == "audit_event"
    req = src.ReadRequest(now - 3600, now + 1, True, now + 1)
    result = await src.async_read_source(
        env.hass, "core_audit", req, src.build_router_map(env.hass)
    )
    marks = [m for m in result.marks if m["title_key"] == f"core_audit.{manual}"]
    assert len(marks) == 3
    for mark in marks:
        assert mark["kind"] == "audit_event"
        assert mark["router_id"] == env.rid
        assert mark["ts"] == pytest.approx(now, abs=1.0)
    plain = await src.async_read_source(
        env.hass,
        "core_audit",
        src.ReadRequest(now - 3600, now + 1, False, now + 1),
        src.build_router_map(env.hass),
    )
    assert plain.marks == []
    again.close()
    await stop(env)
    await drain(env.hass)


# ---------------------------------------------------------------------------
# Order item 35: the Security Center vetoes write proposals
# ---------------------------------------------------------------------------


def center(**over: Any) -> Any:
    base: dict[str, Any] = {
        "loaded": True,
        "enabled": True,
        "ready": True,
        "incidents": {},
    }
    base.update(over)
    return SimpleNamespace(**base)


def finding(router_id: str | None, status: str = "open", severity: str = "critical"):
    return {"router_id": router_id, "status": status, "severity": severity}


@pytest.fixture
def sc() -> Iterator[list[Any]]:
    """The Security Center the engine sees: ``sc[0]`` (None: not running)."""
    holder: list[Any] = [None]
    with patch.object(
        security_center, "async_get_security_center", lambda hass: holder[0]
    ):
        yield holder


async def test_no_center_is_unknown_and_wins_over_a_provider(
    world: World, measured: None, sc: list[Any]
) -> None:
    engine = await world.start(decider=he.PolicyDecider(Favourable()))
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [rec] = world.records()
    assert engine.open_security_findings(R1) is None
    ctx = engine.context_for(rec)
    assert ctx.open_security_findings is None
    inp = he.PolicyDecider().decision_input(
        ctx, he.HealFacts(context=hp.RiskContext(open_security_findings=0))
    )
    assert inp.context.open_security_findings is None
    cand = candidate_of(engine.plan_for(rec))
    assert cand["outcome"] == "insufficient_evidence"
    assert "open_security_findings" in cand["facts"]["unknown"]


async def test_a_quiet_center_lets_the_favourable_candidate_ask_for_approval(
    world: World, measured: None, sc: list[Any]
) -> None:
    sc[0] = center()
    engine = await world.start(decider=he.PolicyDecider(Favourable()))
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [rec] = world.records()
    assert engine.open_security_findings(R1) == 0
    assert candidate_of(engine.plan_for(rec))["outcome"] == "requires_approval"


async def test_an_open_finding_makes_every_write_not_safe(
    world: World, measured: None, sc: list[Any]
) -> None:
    sc[0] = center(incidents={"sec-1": finding(R1)})
    engine = await world.start(decider=he.PolicyDecider(Favourable()))
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [rec] = world.records()
    assert engine.open_security_findings(R1) == 1
    cand = candidate_of(engine.plan_for(rec))
    assert cand["outcome"] == "not_safe"
    assert "open_security_finding" in repr(cand)
    # the record's own read-only evaluation is no write: not vetoed
    assert rec.decision.outcome is hm.DecisionOutcome.RECOMMENDED
    assert rec.risk.risk_class is hm.RiskClass.READ_ONLY


async def test_a_provider_cannot_hide_or_invent_findings(
    world: World, measured: None, sc: list[Any]
) -> None:
    class Claims(Favourable):
        def __init__(self, n: int) -> None:
            super().__init__()
            self.n = n

        def facts(self, context: he.DecisionContext) -> he.HealFacts:
            facts = super().facts(context)
            assert facts.context is not None
            return dataclasses.replace(
                facts,
                context=dataclasses.replace(
                    facts.context, open_security_findings=self.n
                ),
            )

    sc[0] = center(incidents={"sec-1": finding(R1)})
    engine = await world.start(decider=he.PolicyDecider(Claims(0)))
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    [rec] = world.records()
    assert candidate_of(engine.plan_for(rec))["outcome"] == "not_safe"
    sc[0] = center()
    engine.decider = he.PolicyDecider(Claims(4))
    assert candidate_of(engine.plan_for(rec))["outcome"] == "requires_approval"


@pytest.mark.parametrize(
    ("incidents", "r1", "r2"),
    [
        ({"a": finding(R1)}, 1, 0),
        ({"a": finding(R2)}, 0, 1),
        ({"a": finding(None)}, 1, 1),
        ({"a": finding(R1), "b": finding(None), "c": finding(R2)}, 2, 2),
        ({"a": finding(R1, status="confirmed")}, 1, 0),
        ({"a": finding(R1, status="resolved")}, 0, 0),
        ({"a": finding(R1, severity="info")}, 1, 0),
        ({"a": finding(R1, severity="warning")}, 1, 0),
        ({"a": {"router_id": R1, "severity": "critical"}}, 0, 0),
    ],
    ids=[
        "own",
        "other",
        "fleet",
        "mixed",
        "confirmed",
        "resolved",
        "info",
        "warning",
        "no_status",
    ],
)
async def test_which_findings_count(
    world: World, sc: list[Any], incidents: dict[str, Any], r1: int, r2: int
) -> None:
    sc[0] = center(incidents=incidents)
    engine = await world.start()
    assert (engine.open_security_findings(R1), engine.open_security_findings(R2)) == (
        r1,
        r2,
    )


class Raising:
    loaded = True
    enabled = True
    ready = True

    @property
    def incidents(self) -> Any:
        raise RuntimeError("store damaged")


@pytest.mark.parametrize(
    "value",
    [
        center(loaded=False),
        center(enabled=False),
        center(ready=False),
        center(loaded=1),
        center(enabled="yes"),
        center(incidents=None),
        center(incidents=[finding(R1)]),
        center(incidents={"a": "open"}),
        center(incidents={"a": finding(R1), "b": None}),
        center(incidents={"a": {"router_id": 7, "status": "open"}}),
        Raising(),
    ],
    ids=[
        "not_loaded",
        "off",
        "not_ready",
        "loaded_not_bool",
        "enabled_not_bool",
        "no_incidents",
        "incidents_not_mapping",
        "finding_not_mapping",
        "one_finding_unreadable",
        "router_id_not_str",
        "raising",
    ],
)
async def test_an_unusable_center_is_unknown_never_zero(
    world: World, sc: list[Any], value: Any
) -> None:
    sc[0] = value
    engine = await world.start()
    assert engine.open_security_findings(R1) is None


async def test_an_import_failure_of_the_center_is_unknown(world: World) -> None:
    engine = await world.start()
    with patch.object(
        security_center,
        "async_get_security_center",
        MagicMock(side_effect=ImportError("gone")),
    ):
        assert engine.open_security_findings(R1) is None


async def test_the_context_copy_keeps_the_fact(
    world: World, measured: None, sc: list[Any]
) -> None:
    sc[0] = center(incidents={"a": finding(None), "b": finding(None)})
    seen: list[he.DecisionContext] = []

    class Spy(Favourable):
        def facts(self, context: he.DecisionContext) -> he.HealFacts:
            seen.append(context)
            return super().facts(context)

    await world.start(decider=he.PolicyDecider(Spy()))
    world.open("inc-1", cause="dns_upstream", cause_status="confirmed")
    assert [c.open_security_findings for c in seen] == [2]
    assert (
        he.DecisionContext.__dataclass_fields__["open_security_findings"].default
        is None
    )
