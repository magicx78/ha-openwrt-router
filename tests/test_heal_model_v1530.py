"""Self-Healing, package B (1.53.0): the remediation model and state machine.

Order tests (Phase 7 order §22) covered here: 22 (HA restart during an
execution, model part), 28 (action states survive the serialisation; the
store part is in ``test_heal_store_v1530.py``) and 32 (action and incident
deduplication ids). Further:

* the full state x state x actor matrix against the one transition table
  (every legal move accepted, every other one refused with a typed error);
* an exhaustive walk and seeded random walks: no legal sequence executes
  the same action twice, terminal states stay terminal;
* every transition lands in the history with the caller's timestamp and
  actor (no invented times);
* no key or value of the serialised record looks like a credential
  (judged by ``core_masking``).

Pure: no Home Assistant instance, no router, no network.
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import math
import random
from collections.abc import Iterator
from typing import Any

import pytest

from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router.core_masking import (
    is_secret_key,
    looks_like_key_material,
)
from custom_components.openwrt_router.core_models import (
    REMEDIATION_ID_PREFIX,
    is_sha256,
    is_valid_id,
)

S = hm.ActionState
A = hm.Actor
R1 = "rtr_" + "1" * 32
R2 = "rtr_" + "2" * 32
T0 = 1_790_000_000.0

# The order's state set (§3), by name.
ORDER_STATES = (
    "DETECTED",
    "ANALYZED",
    "PROPOSED",
    "PREFLIGHT",
    "WAITING_APPROVAL",
    "APPROVED",
    "EXECUTING",
    "VERIFYING",
    "RESOLVED",
    "REJECTED",
    "CANCELLED",
    "FAILED",
    "ROLLBACK_PENDING",
    "ROLLING_BACK",
    "ROLLED_BACK",
    "ESCALATED",
    "MANUAL_RECOVERY_REQUIRED",
)


def new_action(**overrides: Any) -> hm.RemediationAction:
    args: dict[str, Any] = {
        "router_id": R1,
        "action_type": "service.restart",
        "params": {"name": "dnsmasq"},
        "ts": T0,
        "incident_id": "inc-7",
        "incident_type": "system_service_restart",
        "components": (hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq"),),
        "playbook_id": "dns_recovery",
        "playbook_version": 1,
    }
    args.update(overrides)
    return hm.RemediationAction.new(**args)


def at(state: hm.ActionState, *, interrupted: bool = False) -> hm.RemediationAction:
    """An action that is in ``state`` (history: one entry into it)."""
    action = new_action()
    return dataclasses.replace(
        action,
        state=state,
        history=(
            hm.HistoryEntry(
                from_state=None, to_state=state, ts=T0, actor=A.ENGINE, reason="test"
            ),
        ),
        flags=hm.Flags(interrupted=interrupted),
    )


def full_action() -> hm.RemediationAction:
    """Every field of the record filled (round trip and masking tests)."""
    action = new_action(
        idempotency_id=hm.idempotency_id("client-request-0001"),
        prerequisites=("router_reachable", "identity_unique", "no_concurrent_repair"),
        planned_changes=(
            hm.Change(kind="service", target="dnsmasq", effect="restart"),
        ),
        expected_impact=hm.Impact(
            clients_on_router=12,
            clients_on_component=12,
            dependants=(R2,),
            est_outage_s=5,
        ),
        cause=hm.Cause(
            code="rec_dns_resolution",
            status=hm.CauseStatus.CONFIRMED,
            level=hm.CauseLevel.LIKELY,
            confidence=0.8,
            source_families=("procd", "log"),
        ),
        incident_reopen=2,
    )
    steps = [
        (S.ANALYZED, A.ENGINE, "context_built", {}),
        (
            S.PROPOSED,
            A.ENGINE,
            "decision_made",
            {
                "decision": hm.Decision(
                    outcome=hm.DecisionOutcome.REQUIRES_APPROVAL,
                    score=0.63,
                    factors=(
                        hm.Factor(factor="base", value=0.9, reason="cause_likely"),
                        hm.Factor(factor="fit", value=0.7, reason="direct_state"),
                    ),
                    why="risk_requires_approval",
                    why_not=None,
                ),
                "risk": hm.Risk(
                    risk_class=hm.RiskClass.MEDIUM,
                    reasons=("service_restart", "gateway_role"),
                ),
                "backup_ref": hm.BackupRef(
                    version_id=None, reason="not_needed_no_config_change"
                ),
                "rollback": hm.Rollback(
                    mechanism=hm.RollbackMechanism.NONE,
                    statement="restart_changes_no_config",
                    status=hm.RollbackStatus.NOT_AVAILABLE,
                ),
                "state_fingerprint": "a" * 64,
            },
        ),
        (S.PREFLIGHT, A.ADMIN, "approval_requested", {}),
        (
            S.WAITING_APPROVAL,
            A.ENGINE,
            "preflight_passed",
            {
                "approval": hm.Approval(
                    status=hm.ApprovalStatus.PENDING,
                    guard_approval_id="apr_" + "3" * 32,
                    binding_hash="b" * 64,
                    requested_by=A.ADMIN,
                    decided_by=None,
                    expires_at=T0 + 900,
                ),
                "preflight": (
                    hm.Check(check="router_reachable", outcome=hm.CheckOutcome.PASS),
                    hm.Check(
                        check="no_concurrent_repair",
                        outcome=hm.CheckOutcome.PASS,
                        reason="no_lock",
                    ),
                ),
            },
        ),
        (
            S.APPROVED,
            A.ADMIN,
            "admin_approved",
            {
                "approval": hm.Approval(
                    status=hm.ApprovalStatus.APPROVED,
                    guard_approval_id="apr_" + "3" * 32,
                    binding_hash="b" * 64,
                    requested_by=A.ADMIN,
                    decided_by=A.ADMIN,
                    expires_at=T0 + 900,
                )
            },
        ),
        # the attempt number is fixed when the intent is written
        (
            S.EXECUTING,
            A.ENGINE,
            "intent_written",
            {"execution": hm.Execution(attempt_no=1)},
        ),
        (
            S.VERIFYING,
            A.ENGINE,
            "call_ok",
            {
                "execution": hm.Execution(
                    attempt_no=1,
                    intent_written_at=T0 + 6,
                    call_started_at=T0 + 6.5,
                    call_finished_at=T0 + 7,
                    call_result=hm.CallResult.OK,
                )
            },
        ),
        (
            S.RESOLVED,
            A.ENGINE,
            "verified_resolved",
            {
                "verification": hm.Verification(
                    result=hm.VerificationResult.RESOLVED,
                    before={"service_running": False, "pid": None, "dns_errors": 14},
                    after={"service_running": True, "pid": 4711, "dns_errors": 0},
                    checks=(
                        hm.Check(
                            check="service_running",
                            outcome=hm.CheckOutcome.PASS,
                            reason="new_pid",
                        ),
                    ),
                ),
                "audit_refs": ("evt_" + "4" * 32, "evt_" + "5" * 32),
            },
        ),
    ]
    for i, (to, actor, reason, changes) in enumerate(steps, start=1):
        action = hm.transition(
            action, to, actor=actor, ts=T0 + i, reason=reason, changes=changes
        )
    return action


# --- the state set and the table ------------------------------------------------------


def test_the_order_state_set_exactly() -> None:
    assert sorted(s.name for s in S) == sorted(ORDER_STATES)
    assert len({s.value for s in S}) == len(ORDER_STATES)


def test_terminal_states() -> None:
    assert {
        S.RESOLVED,
        S.REJECTED,
        S.CANCELLED,
        S.ESCALATED,
        S.MANUAL_RECOVERY_REQUIRED,
        S.ROLLED_BACK,
    } == hm.TERMINAL_STATES
    for src, _dst in hm.TRANSITIONS:
        assert src not in hm.TERMINAL_STATES, src


def test_the_normal_path_of_the_order_is_in_the_table() -> None:
    path = (
        S.DETECTED,
        S.ANALYZED,
        S.PROPOSED,
        S.PREFLIGHT,
        S.APPROVED,
        S.EXECUTING,
        S.VERIFYING,
        S.RESOLVED,
    )
    for src, dst in itertools.pairwise(path):
        assert (src, dst) in hm.TRANSITIONS, (src, dst)
    assert (S.PREFLIGHT, S.WAITING_APPROVAL) in hm.TRANSITIONS
    assert (S.WAITING_APPROVAL, S.APPROVED) in hm.TRANSITIONS


def test_only_the_engine_enters_executing_and_only_from_approved() -> None:
    into = {k: r for k, r in hm.TRANSITIONS.items() if k[1] is S.EXECUTING}
    assert list(into) == [(S.APPROVED, S.EXECUTING)]
    rule = into[(S.APPROVED, S.EXECUTING)]
    assert rule.actors == frozenset({A.ENGINE})
    assert rule.durable and hm.Precondition.FIRST_ENTRY in rule.requires
    # the other write step is durable too
    assert hm.TRANSITIONS[(S.ROLLBACK_PENDING, S.ROLLING_BACK)].durable
    assert {k[1] for k, r in hm.TRANSITIONS.items() if r.durable} == set(
        hm.WRITE_AHEAD_STATES
    )


def test_only_an_admin_approves_or_rejects_a_waiting_action() -> None:
    assert hm.TRANSITIONS[(S.WAITING_APPROVAL, S.APPROVED)].actors == {A.ADMIN}
    assert hm.TRANSITIONS[(S.WAITING_APPROVAL, S.REJECTED)].actors == {A.ADMIN}
    assert hm.TRANSITIONS[(S.PROPOSED, S.REJECTED)].actors == {A.ADMIN}


def test_restart_recovery_never_starts_a_write_or_an_approval() -> None:
    for (_src, dst), rule in hm.TRANSITIONS.items():
        if A.RECOVERY in rule.actors:
            assert dst not in {
                S.APPROVED,
                S.EXECUTING,
                S.PREFLIGHT,
                S.WAITING_APPROVAL,
                S.ROLLBACK_PENDING,
                S.ROLLING_BACK,
            }, dst


def _reach(start: set[hm.ActionState]) -> set[hm.ActionState]:
    seen = set(start)
    todo = list(start)
    while todo:
        cur = todo.pop()
        for src, dst in hm.TRANSITIONS:
            if src is cur and dst not in seen:
                seen.add(dst)
                todo.append(dst)
    return seen


def test_no_edge_leads_back_into_the_approval_or_execution_part() -> None:
    """Graph test, preconditions ignored: after EXECUTING nothing reaches
    APPROVED or EXECUTING again (the table alone, without the once-rule)."""
    after = _reach({dst for (src, dst) in hm.TRANSITIONS if src is S.EXECUTING})
    for state in (S.EXECUTING, S.APPROVED, S.PREFLIGHT, S.WAITING_APPROVAL):
        assert state not in after, state


def test_every_state_can_reach_a_terminal_state() -> None:
    for state in S:
        if state in hm.TERMINAL_STATES:
            continue
        assert _reach({state}) & hm.TERMINAL_STATES, state


def test_every_state_is_reachable_from_detected() -> None:
    assert _reach({S.DETECTED}) == set(S)


# --- the full matrix ------------------------------------------------------------------


def _expected(src: hm.ActionState, dst: hm.ActionState, actor: hm.Actor) -> bool:
    rule = hm.TRANSITIONS.get((src, dst))
    if rule is None or actor not in rule.actors:
        return False
    # ``at(src)`` has entered only ``src`` and is not interrupted
    return not (hm.Precondition.FIRST_ENTRY in rule.requires and dst is src)


@pytest.mark.parametrize("src", list(S), ids=lambda s: s.name)
def test_matrix_state_x_state_x_actor(src: hm.ActionState) -> None:
    accepted = refused = 0
    for dst in S:
        for actor in A:
            action = at(src)
            if _expected(src, dst, actor):
                moved = hm.transition(
                    action, dst, actor=actor, ts=T0 + 1, reason="matrix"
                )
                assert moved.state is dst
                assert moved.history[-1] == hm.HistoryEntry(
                    from_state=src,
                    to_state=dst,
                    ts=T0 + 1,
                    actor=actor,
                    reason="matrix",
                )
                assert len(moved.history) == len(action.history) + 1
                accepted += 1
                continue
            with pytest.raises(hm.TransitionError) as err:
                hm.transition(action, dst, actor=actor, ts=T0 + 1, reason="matrix")
            if src in hm.TERMINAL_STATES:
                assert isinstance(err.value, hm.TerminalStateError)
            elif (src, dst) not in hm.TRANSITIONS:
                assert isinstance(err.value, hm.IllegalTransitionError)
            elif actor not in hm.TRANSITIONS[(src, dst)].actors:
                assert isinstance(err.value, hm.ActorNotAllowedError)
            else:
                assert isinstance(err.value, hm.PreconditionFailedError)
            assert err.value.from_state is src and err.value.to_state is dst
            refused += 1
    assert accepted + refused == len(S) * len(A)
    if src in hm.TERMINAL_STATES:
        assert accepted == 0


def test_matrix_totals_match_the_table() -> None:
    legal = sum(
        1 for src in S for dst in S for actor in A if _expected(src, dst, actor)
    )
    assert legal == sum(
        len(r.actors)
        for (s, d), r in hm.TRANSITIONS.items()
        if not (hm.Precondition.FIRST_ENTRY in r.requires and s is d)
    )


def test_not_interrupted_precondition() -> None:
    action = at(S.VERIFYING, interrupted=True)
    with pytest.raises(hm.PreconditionFailedError):
        hm.transition(action, S.FAILED, actor=A.ENGINE, ts=T0, reason="x")
    with pytest.raises(hm.PreconditionFailedError):
        hm.transition(action, S.VERIFYING, actor=A.RECOVERY, ts=T0, reason="x")
    for dst in (S.RESOLVED, S.ESCALATED, S.MANUAL_RECOVERY_REQUIRED):
        assert (
            hm.transition(action, dst, actor=A.ENGINE, ts=T0, reason="x").state is dst
        )


def test_bad_inputs_are_typed_errors_and_never_echo_the_value() -> None:
    action = at(S.DETECTED)
    secret = "S3cr3t-pa55-in-a-reason"
    for kwargs in (
        {"ts": math.nan},
        {"ts": math.inf},
        {"ts": -1.0},
        {"ts": True},
        {"ts": "now"},
        {"reason": "free text with spaces"},
        {"reason": secret},
        {"reason": ""},
    ):
        args: dict[str, Any] = {"actor": A.ENGINE, "ts": T0, "reason": "ok"}
        args.update(kwargs)
        with pytest.raises(hm.TransitionError) as err:
            hm.transition(action, S.ANALYZED, **args)
        assert secret not in str(err.value)
    with pytest.raises(hm.IllegalTransitionError):
        hm.transition(action, "not_a_state", actor=A.ENGINE, ts=T0, reason="x")
    with pytest.raises(hm.ActorNotAllowedError):
        hm.transition(action, S.ANALYZED, actor="root", ts=T0, reason="x")
    # identity and history cannot be changed through ``changes``
    for field in ("action_id", "router_id", "state", "history", "created_at"):
        with pytest.raises(hm.TransitionError):
            hm.transition(
                action,
                S.ANALYZED,
                actor=A.ENGINE,
                ts=T0,
                reason="x",
                changes={field: None},
            )


def test_a_refused_transition_changes_nothing() -> None:
    action = at(S.APPROVED)
    before = action.to_dict()
    with pytest.raises(hm.TransitionError):
        hm.transition(action, S.EXECUTING, actor=A.ADMIN, ts=T0, reason="x")
    with pytest.raises(hm.TransitionError):
        hm.transition(
            action,
            S.EXECUTING,
            actor=A.ENGINE,
            ts=T0,
            reason="x",
            changes={"components": "not a tuple"},
        )
    assert action.to_dict() == before


# --- no double execution ---------------------------------------------------------------


def _moves(action: hm.RemediationAction) -> Iterator[hm.RemediationAction]:
    """Every legal next action: each (target, actor), plus a restart."""
    for dst in S:
        for actor in A:
            try:
                yield hm.transition(action, dst, actor=actor, ts=T0, reason="walk")
            except hm.TransitionError:
                continue
    recovered = hm.apply_restart_recovery(action, ts=T0)
    if recovered is not action:
        yield recovered


def _count(action: hm.RemediationAction, state: hm.ActionState) -> int:
    return sum(1 for h in action.history if h.to_state is state)


def test_exhaustive_no_sequence_executes_twice() -> None:
    """Depth-first over every legal move and every restart: the walk ends
    (the reachable graph is finite and acyclic) and no history holds two
    entries into EXECUTING or ROLLING_BACK."""
    seen: set[tuple[Any, ...]] = set()
    stack = [new_action()]
    paths_to_terminal = 0
    executed = 0
    while stack:
        action = stack.pop()
        sig = (
            action.state,
            action.flags.interrupted,
            tuple(h.to_state for h in action.history),
        )
        if sig in seen:
            continue
        seen.add(sig)
        assert len(action.history) <= hm.HISTORY_MAX
        assert _count(action, S.EXECUTING) <= 1
        assert _count(action, S.ROLLING_BACK) <= 1
        assert _count(action, S.ROLLBACK_PENDING) <= 1
        executed += _count(action, S.EXECUTING)
        if action.state in hm.TERMINAL_STATES:
            paths_to_terminal += 1
            assert list(_moves(action)) == []
            continue
        nxt = list(_moves(action))
        assert nxt, action.state  # no dead end
        stack.extend(nxt)
    assert paths_to_terminal > 50 and executed > 0
    assert len(seen) < 10_000


@pytest.mark.parametrize("seed", range(200))
def test_random_walks_never_execute_twice(seed: int) -> None:
    rng = random.Random(seed)
    action = new_action()
    ts = T0
    for _ in range(60):
        ts += rng.choice((0.5, 1.0, 30.0, -5.0))  # a clock jump back is recorded as is
        if rng.random() < 0.15:
            action = hm.apply_restart_recovery(action, ts=max(ts, 1.0))
            continue
        dst = rng.choice(list(S))
        actor = rng.choice(list(A))
        was_terminal = action.state in hm.TERMINAL_STATES
        try:
            action = hm.transition(
                action, dst, actor=actor, ts=max(ts, 1.0), reason="walk"
            )
        except hm.TransitionError:
            continue
        assert not was_terminal
    assert _count(action, S.EXECUTING) <= 1
    assert _count(action, S.ROLLING_BACK) <= 1
    hist = action.history
    for prev, cur in itertools.pairwise(hist):
        assert cur.from_state is prev.to_state
    assert hist[-1].to_state is action.state


def test_terminal_states_stay_terminal() -> None:
    for state in hm.TERMINAL_STATES:
        action = at(state)
        assert hm.restart_recovery(action) is None
        assert hm.apply_restart_recovery(action, ts=T0) is action
        assert hm.allowed_targets(state, A.ADMIN) == frozenset()
        for dst in S:
            for actor in A:
                with pytest.raises(hm.TerminalStateError):
                    hm.transition(action, dst, actor=actor, ts=T0, reason="x")


# --- order test 22, model part: HA restart during an execution --------------------------


def test_restart_during_execution_needs_verification_and_never_executes_again() -> None:
    action = at(S.EXECUTING)
    assert hm.restart_recovery(action) == (S.VERIFYING, "interrupted_by_restart")
    after = hm.apply_restart_recovery(action, ts=T0 + 60)
    assert after.state is S.VERIFYING and after.flags.interrupted is True
    assert after.history[-1] == hm.HistoryEntry(
        from_state=S.EXECUTING,
        to_state=S.VERIFYING,
        ts=T0 + 60,
        actor=A.RECOVERY,
        reason="interrupted_by_restart",
    )
    # a second restart while it is still unverified adds nothing
    assert hm.restart_recovery(after) is None
    assert hm.apply_restart_recovery(after, ts=T0 + 120) is after
    # it can never execute again, by anyone
    for actor in A:
        with pytest.raises(hm.TransitionError):
            hm.transition(after, S.EXECUTING, actor=actor, ts=T0, reason="x")
    # unknown outcome: no FAILED (that would allow a rollback write)
    with pytest.raises(hm.PreconditionFailedError):
        hm.transition(after, S.FAILED, actor=A.ENGINE, ts=T0, reason="x")
    resolved = hm.transition(
        after, S.RESOLVED, actor=A.ENGINE, ts=T0 + 200, reason="execution_unconfirmed"
    )
    assert resolved.flags.interrupted and resolved.state is S.RESOLVED
    manual = hm.transition(
        after,
        S.MANUAL_RECOVERY_REQUIRED,
        actor=A.RECOVERY,
        ts=T0 + 200,
        reason="verification_unknown",
    )
    assert manual.state is S.MANUAL_RECOVERY_REQUIRED


@pytest.mark.parametrize(
    ("state", "target", "reason"),
    [
        (S.EXECUTING, S.VERIFYING, "interrupted_by_restart"),
        (S.VERIFYING, S.VERIFYING, "interrupted_by_restart"),
        (S.ROLLING_BACK, S.VERIFYING, "interrupted_by_restart"),
        (S.ROLLBACK_PENDING, S.MANUAL_RECOVERY_REQUIRED, "rollback_lost_on_restart"),
        (S.APPROVED, S.CANCELLED, "approval_lost_on_restart"),
        (S.WAITING_APPROVAL, S.CANCELLED, "approval_lost_on_restart"),
        (S.PREFLIGHT, S.CANCELLED, "preflight_lost_on_restart"),
        (S.FAILED, S.ESCALATED, "failed_before_restart"),
    ],
)
def test_restart_rules(state: Any, target: Any, reason: str) -> None:
    action = at(state)
    assert hm.restart_recovery(action) == (target, reason)
    after = hm.apply_restart_recovery(action, ts=T0 + 5)
    assert after.state is target and after.history[-1].actor is A.RECOVERY
    if target is S.VERIFYING:
        assert after.flags.interrupted
    if state is S.ROLLING_BACK:
        assert after.rollback.status is hm.RollbackStatus.UNKNOWN
    # the recovery move is a row of the one table
    assert A.RECOVERY in hm.TRANSITIONS[(state, target)].actors


def test_states_left_alone_by_a_restart() -> None:
    for state in (S.DETECTED, S.ANALYZED, S.PROPOSED):
        assert hm.restart_recovery(at(state)) is None


def test_in_flight_and_lock_state_sets() -> None:
    assert frozenset({S.EXECUTING, S.VERIFYING, S.ROLLING_BACK}) == hm.IN_FLIGHT_STATES
    assert frozenset({S.EXECUTING, S.ROLLING_BACK}) == hm.WRITE_AHEAD_STATES
    assert hm.IN_FLIGHT_STATES <= hm.LOCKING_STATES
    assert not hm.LOCKING_STATES & hm.TERMINAL_STATES


# --- history ----------------------------------------------------------------------------


def test_history_holds_every_transition_with_the_given_time_and_actor() -> None:
    action = full_action()
    assert [h.to_state for h in action.history] == [
        S.DETECTED,
        S.ANALYZED,
        S.PROPOSED,
        S.PREFLIGHT,
        S.WAITING_APPROVAL,
        S.APPROVED,
        S.EXECUTING,
        S.VERIFYING,
        S.RESOLVED,
    ]
    assert [h.ts for h in action.history] == [T0 + i for i in range(9)]
    assert action.history[0].from_state is None
    assert action.history[0].actor is A.ENGINE
    assert [h.actor for h in action.history[3:6]] == [A.ADMIN, A.ENGINE, A.ADMIN]
    assert action.created_at == T0 and action.updated_at == T0 + 8
    # entering EXECUTING stamps the intent with the transition's own time
    assert action.history[6].ts == T0 + 6
    assert action.execution.intent_written_at == T0 + 6


def test_a_clock_jump_back_is_recorded_not_corrected() -> None:
    action = new_action(ts=T0)
    moved = hm.transition(action, S.ANALYZED, actor=A.ENGINE, ts=T0 - 3600, reason="x")
    assert moved.history[-1].ts == T0 - 3600 and moved.updated_at == T0 - 3600


def test_timestamps_are_kept_to_the_millisecond() -> None:
    action = new_action(ts=T0 + 0.1234567)
    assert action.created_at == pytest.approx(T0 + 0.123, abs=1e-9)
    back = hm.RemediationAction.from_dict(json.loads(json.dumps(action.to_dict())))
    assert back.history[0].ts == action.history[0].ts


# --- order test 28: the record survives serialisation -----------------------------------

ORDER_FIELDS = {
    # order §3 -> serialised key
    "action id": "action_id",
    "router id": "router_id",
    "incident id": "incident_id",
    "affected components": "components",
    "suspected/confirmed cause": "cause",
    "repair type": "action_type",
    "risk class": "risk",
    "prerequisites": "prerequisites",
    "planned changes": "planned_changes",
    "expected impact": "expected_impact",
    "approval status": "approval",
    "backup reference": "backup_ref",
    "execution status": "execution",
    "verification result": "verification",
    "rollback status": "rollback",
    "audit reference": "audit_refs",
    # design additions
    "playbook id": "playbook_id",
    "playbook version": "playbook_version",
    "state fingerprint": "state_fingerprint",
    "idempotency": "idempotency_id",
    "history": "history",
}


def test_every_field_of_the_order_is_in_the_record() -> None:
    data = full_action().to_dict()
    for name, key in ORDER_FIELDS.items():
        assert key in data, name
    assert data["state"] == "resolved"
    assert data["execution"]["attempt_no"] == 1
    assert data["verification"]["before"]["dns_errors"] == 14
    assert data["verification"]["after"]["pid"] == 4711
    assert data["risk"]["risk_class"] == 2


def test_round_trip_keeps_every_field() -> None:
    action = full_action()
    raw = json.loads(json.dumps(action.to_dict()))
    back = hm.RemediationAction.from_dict(raw)
    assert back == action
    assert back.to_dict() == action.to_dict()
    for f in dataclasses.fields(hm.RemediationAction):
        assert getattr(back, f.name) == getattr(action, f.name), f.name


def test_new_action_defaults() -> None:
    action = new_action()
    assert is_valid_id(action.action_id, REMEDIATION_ID_PREFIX)
    assert action.state is S.DETECTED
    assert action.approval.status is hm.ApprovalStatus.NOT_REQUESTED
    assert action.rollback.mechanism is hm.RollbackMechanism.NONE
    assert action.rollback.status is hm.RollbackStatus.NOT_AVAILABLE
    assert action.execution.call_result is None
    assert action.verification.result is None
    # unassessed counts as the highest risk (decided in the review of PR #75)
    assert action.risk.risk_class is hm.RiskClass.HIGH
    assert new_action().action_id != action.action_id


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(state="exploded"),
        lambda d: d.update(action_id="rem_xyz"),
        lambda d: d.update(router_id="10.0.0.1"),
        lambda d: d.update(history=[]),
        lambda d: d["history"][-1].update(to_state="detected"),
        lambda d: d["params"].update(password="x"),
        lambda d: d["params"].update(name="A" * 40),
        lambda d: d.update(components=[{"kind": "service", "name": "dns masq"}]),
        lambda d: d.update(components=[{"kind": "service", "name": "0" * 40}]),
        lambda d: d["verification"].update(before={f"m{i}": i for i in range(40)}),
        lambda d: d["risk"].update(risk_class=4),
        lambda d: d.update(state_fingerprint="not-a-digest"),
        lambda d: d.update(audit_refs=["evt_1"]),
        lambda d: d.update(playbook_version=-1),
        lambda d: d.update(unexpected_field=1),
    ],
)
def test_from_dict_refuses_damaged_records(mutate: Any) -> None:
    data = json.loads(json.dumps(full_action().to_dict()))
    mutate(data)
    with pytest.raises(hm.HealModelError) as err:
        hm.RemediationAction.from_dict(data)
    assert "10.0.0.1" not in str(err.value)
    assert "dns masq" not in str(err.value)


def test_measurements_are_bounded() -> None:
    ok = {f"m{i}": i for i in range(hm.MEASUREMENTS_MAX)}
    hm.Verification(before=ok)
    with pytest.raises(hm.HealModelError):
        hm.Verification(before={**ok, "one_more": 1})
    with pytest.raises(hm.HealModelError):
        hm.Verification(after={"list": list(range(hm.LIST_MAX + 1))})
    hm.Verification(after={"list": list(range(hm.LIST_MAX))})


# --- order test 32: deduplication ids ---------------------------------------------------


def test_action_dedupe_id() -> None:
    a = hm.action_dedupe_id(R1, "service.restart", {"name": "dnsmasq"})
    assert a == hm.action_dedupe_id(R1, "service.restart", {"name": "dnsmasq"})
    assert a.startswith("dda_") and len(a) == 36
    assert a != hm.action_dedupe_id(R2, "service.restart", {"name": "dnsmasq"})
    assert a != hm.action_dedupe_id(R1, "service.restart", {"name": "odhcpd"})
    assert a != hm.action_dedupe_id(R1, "diag.refresh", {"name": "dnsmasq"})
    many = {"b": 1, "a": "x"}
    assert hm.action_dedupe_id(R1, "x.y", many) == hm.action_dedupe_id(
        R1, "x.y", dict(reversed(list(many.items())))
    )
    assert not looks_like_key_material(a)
    # the record carries its own dedupe id
    assert new_action().action_dedupe == a


def test_incident_and_component_dedupe_ids() -> None:
    i = hm.incident_dedupe_id("inc-7")
    assert i == hm.incident_dedupe_id("inc-7")
    assert i.startswith("ddi_") and not looks_like_key_material(i)
    assert i != hm.incident_dedupe_id("inc-8")
    # the root incident is fleet-wide (Network Intelligence numbers it so)
    assert new_action().incident_dedupe == i
    assert new_action(router_id=R2).incident_dedupe == i
    assert new_action(incident_id=None).incident_dedupe is None
    comp = hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq")
    c = hm.component_dedupe_id(R1, comp)
    assert c.startswith("ddc_") and not looks_like_key_material(c)
    assert c != hm.component_dedupe_id(R2, comp)
    assert new_action().component_dedupes == (c,)
    assert new_action().loop_keys == ((R1, "service.restart", "service:dnsmasq"),)
    long_name = hm.Component(
        kind=hm.ComponentKind.INTERFACE, name="-".join(f"vlan{i}" for i in range(10))
    )
    (ref,) = {k[2] for k in new_action(components=(long_name,)).loop_keys}
    assert ref.startswith("cmp_") and len(ref) == 36


def test_idempotency_id_never_keeps_the_raw_value() -> None:
    raw = "client-request-0001"
    idem = hm.idempotency_id(raw)
    assert idem == hm.idempotency_id(raw) and idem.startswith("idm_")
    assert raw not in idem and not looks_like_key_material(idem)
    for bad in ("", " ", "x" * 129, "line\nbreak", "tab\tbad", 7, None):
        with pytest.raises(hm.HealModelError):
            hm.idempotency_id(bad)  # type: ignore[arg-type]


# --- credentials -------------------------------------------------------------------------

DIGEST_FIELDS = {"state_fingerprint", "binding_hash"}


def _walk(value: Any, key: str | None = None) -> Iterator[tuple[str | None, Any]]:
    if isinstance(value, dict):
        for k, v in value.items():
            yield k, None
            yield from _walk(v, k)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item, key)
    else:
        yield key, value


def assert_no_credentials(data: Any) -> None:
    for key, value in _walk(data):
        if value is None and key is not None:
            assert not is_secret_key(key), key
        if isinstance(value, str):
            if key in DIGEST_FIELDS:
                assert is_sha256(value), key
            else:
                assert not looks_like_key_material(value), (key, value)


def test_serialised_record_has_nothing_that_looks_like_a_credential() -> None:
    assert_no_credentials(full_action().to_dict())


@pytest.mark.parametrize(
    "params",
    [
        {"password": "x"},
        {"api_key": "x"},
        {"token": "x"},
        {"psk": "x"},
        {"name": "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0"},
        {"name": "0123456789abcdef0123456789abcdef"},
    ],
)
def test_credential_shaped_params_are_refused(params: dict[str, Any]) -> None:
    with pytest.raises(hm.HealModelError):
        new_action(params=params)


# --- loop protection, settings and maintenance as data ---------------------------------


def test_loop_limits_defaults_and_bounds() -> None:
    lim = hm.LoopLimits()
    assert lim.cooldown_s == 1800 and lim.max_attempts_24h == 2
    assert lim.backoff_base_s == 1800 and lim.backoff_cap_s == 86400
    assert lim.fleet_failure_threshold == 3 and lim.fleet_concurrency == 1
    assert lim.fleet_pause_s == 86400
    for bad in (
        {"cooldown_s": 599},
        {"cooldown_s": 86401},
        {"max_attempts_24h": 0},
        {"max_attempts_24h": 4},
        {"fleet_failure_threshold": 11},
        {"fleet_concurrency": 2},
        {"backoff_cap_s": 86401},
    ):
        with pytest.raises(hm.HealModelError):
            hm.LoopLimits(**bad)
    assert hm.LoopLimits.from_dict(lim.to_dict()) == lim


def test_settings_default_is_on_in_observe_with_an_empty_allowlist() -> None:
    settings = hm.HealSettings()
    assert settings.enabled is True
    router = settings.router(R1)
    assert router.mode is hm.HealMode.OBSERVE and router.allowlist == ()
    assert hm.DEFAULT_MODE is hm.HealMode.OBSERVE
    assert hm.HealSettings.from_dict({}).enabled is True
    assert hm.HealSettings.from_dict({}).router(R2).mode is hm.HealMode.OBSERVE


def test_allowlist_never_holds_a_risky_action() -> None:
    hm.AllowEntry(action_type="diag.refresh", max_risk=hm.RiskClass.LOW)
    for risk in (hm.RiskClass.MEDIUM, hm.RiskClass.HIGH):
        with pytest.raises(hm.HealModelError):
            hm.AllowEntry(action_type="service.restart", max_risk=risk)
    entry = hm.AllowEntry(
        action_type="service.restart",
        params={"name": "dnsmasq"},
        max_risk=hm.RiskClass.LOW,
    )
    rs = hm.RouterSettings(mode=hm.HealMode.AUTO_HEAL, allowlist=(entry,))
    back = hm.RouterSettings.from_dict(json.loads(json.dumps(rs.to_dict())))
    assert back == rs


def _filled_loop() -> hm.LoopState:
    loop = hm.LoopState()
    loop.attempts[(R1, "service.restart", "inc-7")] = hm.AttemptRecord(
        count=2,
        window_start=T0,
        last_at=T0 + 600,
        cooldown_until=T0 + 2400,
        backoff_step=1,
        last_result="not_resolved",
    )
    loop.breakers[(R1, "service.restart", "dnsmasq")] = hm.BreakerRecord(
        state=hm.BreakerState.OPEN,
        opened_at=T0 + 700,
        reason="restart_loop_after_repair",
        failures=1,
    )
    loop.fleet = hm.FleetPause(
        paused_until=T0 + 86400,
        since=T0 + 700,
        reason="store_lost",
        recent_failures=(T0 + 10, T0 + 20),
    )
    action = new_action()
    loop.incident_dedupe[action.incident_dedupe or ""] = action.action_id
    loop.action_dedupe[action.action_dedupe] = action.action_id
    for dedupe in action.component_dedupes:
        loop.component_dedupe[dedupe] = action.action_id
    loop.idempotency[hm.idempotency_id("req-1")] = hm.IdempotencyRecord(
        action_id=action.action_id, created_at=T0
    )
    assert loop.try_lock(hm.LockRecord.engine(action, T0))
    loop.place_hold(
        hm.RouterHold(
            router_id=R2,
            reason=hm.HoldReason.OUTCOME_UNKNOWN,
            since=T0 + 40,
            action_id="rem_" + "8" * 32,
        )
    )
    loop.place_hold(
        hm.RouterHold(
            router_id=None,
            reason=hm.HoldReason.STORE_LOST,
            since=T0,
            until=T0 + 86400,
        )
    )
    loop.clock = (
        hm.SafetyClock().observe(T0).observe(T0 + 50).observe(T0 + 10, elapsed=4.0)
    )
    loop.terminal_at["rem_" + "9" * 32] = T0 + 40
    loop.record_external_write(
        hm.ExternalWrite(
            router_id=R2,
            source="button.service_restart",
            target="dnsmasq",
            ts=T0 + 30,
            audit_ref="evt_" + "6" * 32,
        )
    )
    return loop


def test_loop_state_round_trip() -> None:
    loop = _filled_loop()
    raw = json.loads(json.dumps(loop.to_dict()))
    back = hm.LoopState.from_dict(raw)
    assert back == loop
    assert_no_credentials(raw)


def test_router_lock_is_data_with_one_holder() -> None:
    loop = hm.LoopState()
    engine = hm.LockRecord(
        router_id=R1,
        holder=hm.LockHolder.ENGINE,
        action_id="rem_" + "a" * 32,
        since=T0,
        source="self_healing",
    )
    button = hm.LockRecord.external(R1, "button.reboot", T0)
    assert loop.lock_holder(R1) is None
    assert loop.try_lock(engine)
    assert loop.try_lock(engine)  # the same holder (same lock id) again
    assert not loop.try_lock(button)  # a repair is active: the button must wait
    assert loop.lock_holder(R1) == engine
    assert not loop.release_lock(R1, button.lock_id)  # only the holder releases
    assert loop.release_lock(R1, engine.lock_id)
    assert loop.try_lock(button)
    assert loop.repair_active(R1) is False  # an external write is not a repair
    assert loop.lock_holder(R2) is None


def test_external_writes_are_bounded() -> None:
    loop = hm.LoopState()
    for i in range(hm.EXTERNAL_WRITES_MAX + 25):
        loop.record_external_write(
            hm.ExternalWrite(
                router_id=R1, source="switch.service", target="dnsmasq", ts=T0 + i
            )
        )
    assert len(loop.external_writes) == hm.EXTERNAL_WRITES_MAX
    assert loop.external_writes[0].ts == T0 + 25


def test_maintenance_window_round_trip_and_validation() -> None:
    win = hm.MaintenanceWindow(
        window_id="mtw_" + "7" * 32,
        scope=hm.MaintenanceScope.SERVICE,
        router_id=R1,
        target="dnsmasq",
        start=T0,
        end=T0 + 3600,
        reason="planned_update",
        created_by=A.ADMIN,
    )
    assert hm.MaintenanceWindow.from_dict(json.loads(json.dumps(win.to_dict()))) == win
    assert win.active(T0 + 10) and not win.active(T0 + 3601)
    with pytest.raises(hm.HealModelError):
        dataclasses.replace(win, end=T0 - 1)
    with pytest.raises(hm.HealModelError):
        dataclasses.replace(win, created_by=A.RECOVERY)
