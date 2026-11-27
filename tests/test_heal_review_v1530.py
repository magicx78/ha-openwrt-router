"""Self-Healing, package B: fixes of the independent review of PR #75.

Each test turns one of the reviewer's attack tests around (the attack
asserted the unsafe outcome; here the safe one is asserted) or covers a
point of the review list:

* P1-1 write before act under a concurrent flush/close (fake and real Store);
* P1-2 the dedupe fields are frozen after DETECTED;
* P1-3 one external lock holder per router, released by its token only;
* P2-4 ``flags.interrupted`` and the other safety fields cannot be changed
  outside their transitions;
* P2-5 an idempotency id whose record is gone is refused; after its expiry
  the dedupe and cooldown guards still stop a repeat;
* P2-6 one open action per root incident and per (router, component);
* P2-7 an unreadable record holds its router (or the fleet);
* P2-8 an unknown outcome holds the router until an admin releases it;
* P2-9 the safety clock: wall-clock jumps never shorten a wait;
* P2-10 terminal history is not thrown away for nothing;
* P3 admin ways out, the cheap size estimate, token-like names.

No router, no network; FakeDisks and one test on HA's real Store.
"""

# ruff: noqa: F811  (pytest fixtures imported from test_heal_store_v1530)

from __future__ import annotations

import asyncio
import dataclasses
import json
from collections import deque
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from core_testkit import FakeDisks, make_hass
from test_heal_store_v1530 import (  # noqa: F401 - fixtures
    KEY,
    R1,
    R2,
    T0,
    Clock,
    advance,
    clock,
    disk_record,
    disks,
    execute,
    new_action,
    on_disk,
    open_store,
    svc,
    to_approved,
)

from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_store as hs

S = hm.ActionState
A = hm.Actor
READ_ONLY = hm.Risk(risk_class=hm.RiskClass.READ_ONLY)


async def to_verifying(store: hs.SelfHealingStore, action_id: str, ts: float) -> None:
    to_approved(store, action_id, ts)
    assert (await execute(store, action_id, ts=ts + 10)).ok
    store.apply(
        action_id,
        S.VERIFYING,
        actor=A.ENGINE,
        ts=ts + 11,
        reason="call_inconclusive",
        changes={
            "execution": hm.Execution(
                attempt_no=1,
                intent_written_at=ts + 10,
                call_started_at=ts + 10,
                call_result=hm.CallResult.INCONCLUSIVE,
            )
        },
    )


# --- P1-1 write before act under a concurrent flush / close ---------------------------


async def test_p1_1_concurrent_close_cannot_leave_a_stale_disk(
    disks: FakeDisks, clock: Clock
) -> None:
    hass = make_hass()
    store, _ = await open_store(clock, hass)
    act = store.add(new_action()).action
    to_approved(store, act.action_id)
    await store.async_flush()
    close_task: list[Any] = []

    async def exec_job(func: Any, *args: Any) -> Any:
        result = func(*args)
        if func is hs._read_store_file and not close_task:
            close_task.append(asyncio.ensure_future(store.async_close()))
            await asyncio.sleep(0)
            await asyncio.sleep(0)
        return result

    hass.async_add_executor_job = AsyncMock(side_effect=exec_job)
    res = await execute(store, act.action_id)
    await close_task[0]
    assert res.ok
    assert store.closed
    assert disk_record(disks, act.action_id)["state"] == "executing"
    # after close no durable step is reported as done
    late = await store.async_apply_durable(
        act.action_id, S.VERIFYING, actor=A.ENGINE, ts=T0 + 20, reason="x"
    )
    assert (late.ok, late.reason) == (False, "closed")
    # restart: interrupted, never cancelled, and the twin is deduplicated
    again, _ = await open_store(clock)
    record = again.get(act.action_id)
    assert record.state is S.VERIFYING and record.flags.interrupted
    assert again.loop.repair_active(R1)
    assert not again.add(new_action()).created


async def test_p1_1_a_delayed_write_during_the_durable_one_carries_it(
    disks: FakeDisks, clock: Clock
) -> None:
    hass = make_hass()
    store, _ = await open_store(clock, hass)
    act = store.add(new_action()).action
    to_approved(store, act.action_id)
    await store.async_flush()
    seen: list[dict[str, Any]] = []

    async def exec_job(func: Any, *args: Any) -> Any:
        # HA's delayed write fires while the durable step is in flight
        payload = store.payload()
        seen.append(payload)
        await store._store.async_save(payload)
        return func(*args)

    hass.async_add_executor_job = AsyncMock(side_effect=exec_job)
    res = await execute(store, act.action_id)
    assert res.ok
    record = next(r for r in seen[0]["actions"] if r["action_id"] == act.action_id)
    assert record["state"] == "executing"
    assert disk_record(disks, act.action_id)["state"] == "executing"
    assert on_disk(disks)["write_seq"] == store._seq


async def test_p1_1_real_store_close_during_the_read_back(tmp_path: Any) -> None:
    import threading
    import time as _time

    from homeassistant.core import HomeAssistant

    hass = HomeAssistant(str(tmp_path))
    try:
        store = hs.SelfHealingStore(hass, clock=Clock())
        await store.async_load()
        act = store.add(new_action()).action
        to_approved(store, act.action_id)
        await store.async_flush()
        read_done = threading.Event()
        real_read = hs._read_store_file

        def slow_read(path: Any) -> Any:
            data = real_read(path)
            read_done.set()
            _time.sleep(0.3)
            return data

        with patch.object(hs, "_read_store_file", slow_read):
            task = asyncio.ensure_future(execute(store, act.action_id))
            while not read_done.is_set():
                await asyncio.sleep(0.01)
            await store.async_close()
            res = await task
        assert res.ok
        path = tmp_path / ".storage" / KEY
        rec = next(
            r
            for r in json.loads(path.read_text())["data"]["actions"]
            if r["action_id"] == act.action_id
        )
        assert rec["state"] == "executing"
    finally:
        await hass.async_stop(force=True)


# --- P1-2 dedupe fields are frozen ------------------------------------------------


@pytest.mark.parametrize(
    "change",
    [
        {"params": {"name": "dnsmasq"}},
        {"action_type": "service.reload"},
        {"incident_id": "inc-9"},
        {"components": (hm.Component(kind=hm.ComponentKind.SERVICE, name="x"),)},
        {"idempotency_id": hm.idempotency_id("req-x")},
    ],
)
async def test_p1_2_dedupe_fields_cannot_change(
    disks: FakeDisks, clock: Clock, change: dict[str, Any]
) -> None:
    store, _ = await open_store(clock)
    first = store.add(new_action(params={"name": "other"})).action
    with pytest.raises(hm.HealModelError):
        store.update(first.action_id, **change)
    with pytest.raises(hm.TransitionError):
        store.apply(
            first.action_id,
            S.ANALYZED,
            actor=A.ENGINE,
            ts=T0 + 1,
            reason="x",
            changes=change,
        )
    assert store.get(first.action_id) == first


async def test_p1_2_the_reviewer_twin_is_still_a_duplicate(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    store.add(new_action())
    twin = store.add(new_action(incident_id="inc-8"))
    assert not twin.created
    assert len(store.open_actions(R1)) == 1


# --- P1-3 one external holder, released by its token -------------------------------


async def test_p1_3_external_lock_has_one_holder(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    token = store.try_external_lock(R1, "button.service_restart", T0)
    assert token
    assert store.try_external_lock(R1, "button.service_restart", T0 + 1) is None
    assert not store.release_external_lock(R1, "button.service_restart")
    assert not store.release_external_lock(R1, "lck_" + "0" * 32)
    act = store.add(new_action()).action
    to_approved(store, act.action_id)
    result = await execute(store, act.action_id)
    assert (result.ok, result.reason) == (False, "router_locked")
    assert store.release_external_lock(R1, token)
    assert not store.release_external_lock(R1, token)  # once only
    assert (await execute(store, act.action_id)).ok


def test_p1_3_model_lock_by_token() -> None:
    loop = hm.LoopState()
    first = hm.LockRecord.external(R1, "button.reboot", T0)
    second = hm.LockRecord.external(R1, "button.reboot", T0 + 1)
    assert first.lock_id != second.lock_id
    assert loop.try_lock(first)
    assert loop.try_lock(first)  # the same holder (same lock id)
    assert not loop.try_lock(second)  # same source, other holder
    assert not loop.release_lock(R1, second.lock_id)
    assert loop.release_lock(R1, first.lock_id)
    assert loop.lock_holder(R1) is None


# --- P2-4 safety fields only through their transitions --------------------------------


async def test_p2_4_interrupted_cannot_be_cleared(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = store.add(new_action()).action
    to_approved(store, act.action_id)
    assert (await execute(store, act.action_id)).ok
    await store.async_flush()
    again, _ = await open_store(clock)
    record = again.get(act.action_id)
    assert record.flags.interrupted
    with pytest.raises(hm.HealModelError):
        again.update(act.action_id, flags=hm.Flags(interrupted=False))
    with pytest.raises(hm.HealModelError):
        again.update_flags(act.action_id, interrupted=False)
    with pytest.raises(hm.TransitionError):
        again.apply(
            act.action_id,
            S.ESCALATED,
            actor=A.ENGINE,
            ts=T0 + 50,
            reason="x",
            changes={"flags": hm.Flags()},
        )
    with pytest.raises(hm.PreconditionFailedError):
        again.apply(act.action_id, S.FAILED, actor=A.ENGINE, ts=T0 + 50, reason="x")
    assert again.get(act.action_id).flags.interrupted


def _approved_twice() -> hm.RemediationAction:
    action = new_action()
    for i, (to, actor, changes) in enumerate(
        (
            (S.ANALYZED, A.ENGINE, {}),
            (S.PROPOSED, A.ENGINE, {"state_fingerprint": "a" * 64}),
            (S.PREFLIGHT, A.ADMIN, {}),
            (
                S.WAITING_APPROVAL,
                A.ENGINE,
                {
                    "approval": hm.Approval(
                        status=hm.ApprovalStatus.PENDING,
                        guard_approval_id="apr_" + "3" * 32,
                        binding_hash="b" * 64,
                        requested_by=A.ADMIN,
                    )
                },
            ),
        ),
        start=1,
    ):
        action = hm.transition(
            action, to, actor=actor, ts=T0 + i, reason="x", changes=changes
        )
    return action


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("state_fingerprint", "c" * 64),
        ("risk", hm.Risk(risk_class=hm.RiskClass.READ_ONLY)),
        ("decision", None),
        ("playbook_version", 9),
        ("incident_reopen", 5),
        ("backup_ref", hm.BackupRef(reason="x")),
        ("planned_changes", ()),
        ("expected_impact", hm.Impact()),
        ("rollback", hm.Rollback(status=hm.RollbackStatus.UNKNOWN)),
        ("preflight", ()),
        ("approval", hm.Approval()),
        ("execution", hm.Execution(attempt_no=3)),
        ("verification", hm.Verification(result=hm.VerificationResult.RESOLVED)),
        ("audit_refs", ()),
    ],
)
def test_p2_4_fields_after_the_planning_part_are_frozen(name: str, value: Any) -> None:
    action = _approved_twice()  # WAITING_APPROVAL: planning is over
    if name == "audit_refs":
        action = action.with_changes(audit_refs=("evt_" + "4" * 32,))
    with pytest.raises(hm.HealModelError):
        action.with_changes(**{name: value})


def test_p2_4_the_approval_binding_cannot_change() -> None:
    action = _approved_twice()
    moved = hm.Approval(
        status=hm.ApprovalStatus.APPROVED,
        guard_approval_id="apr_" + "3" * 32,
        binding_hash="e" * 64,  # another binding
        requested_by=A.ADMIN,
        decided_by=A.ADMIN,
    )
    with pytest.raises(hm.BadTransitionInputError):
        hm.transition(
            action,
            S.APPROVED,
            actor=A.ADMIN,
            ts=T0 + 9,
            reason="x",
            changes={"approval": moved},
        )
    ok = dataclasses.replace(moved, binding_hash="b" * 64)
    approved = hm.transition(
        action,
        S.APPROVED,
        actor=A.ADMIN,
        ts=T0 + 9,
        reason="x",
        changes={"approval": ok},
    )
    with pytest.raises(hm.BadTransitionInputError):  # never again after APPROVED
        hm.transition(
            approved,
            S.EXECUTING,
            actor=A.ENGINE,
            ts=T0 + 10,
            reason="x",
            changes={"approval": hm.Approval()},
        )


def test_p2_4_audit_refs_only_grow_and_intent_time_is_the_models() -> None:
    action = new_action().with_changes(audit_refs=("evt_" + "4" * 32,))
    grown = action.with_changes(audit_refs=("evt_" + "4" * 32, "evt_" + "5" * 32))
    assert len(grown.audit_refs) == 2
    with pytest.raises(hm.HealModelError):
        grown.with_changes(audit_refs=("evt_" + "5" * 32,))
    executing = hm.transition(
        hm.transition(
            hm.transition(
                hm.transition(
                    hm.transition(
                        new_action(), S.ANALYZED, actor=A.ENGINE, ts=T0 + 1, reason="x"
                    ),
                    S.PROPOSED,
                    actor=A.ENGINE,
                    ts=T0 + 2,
                    reason="x",
                ),
                S.PREFLIGHT,
                actor=A.ENGINE,
                ts=T0 + 3,
                reason="x",
            ),
            S.APPROVED,
            actor=A.ENGINE,
            ts=T0 + 4,
            reason="x",
        ),
        S.EXECUTING,
        actor=A.ENGINE,
        ts=T0 + 5,
        reason="x",
    )
    with pytest.raises(hm.BadTransitionInputError):
        hm.transition(
            executing,
            S.VERIFYING,
            actor=A.ENGINE,
            ts=T0 + 6,
            reason="x",
            changes={"execution": hm.Execution(intent_written_at=T0 + 99)},
        )


def test_p2_4_a_new_record_starts_blank() -> None:
    for name, value in (
        ("flags", hm.Flags(interrupted=True)),
        ("approval", hm.Approval(status=hm.ApprovalStatus.APPROVED)),
        ("execution", hm.Execution(attempt_no=1)),
        ("verification", hm.Verification(result=hm.VerificationResult.RESOLVED)),
    ):
        with pytest.raises(hm.HealModelError):
            new_action(**{name: value})


def test_p2_4_flags_maintenance_and_acknowledgement() -> None:
    action = new_action()
    marked = action.with_flags(in_maintenance=True, acknowledged_by_admin=True)
    assert marked.flags.in_maintenance and marked.flags.acknowledged_by_admin
    with pytest.raises(hm.HealModelError):
        marked.with_flags(acknowledged_by_admin=False)
    with pytest.raises(hm.HealModelError):
        action.with_flags(interrupted=True)


def test_p2_4_unassessed_risk_counts_as_the_highest() -> None:
    assert new_action().risk.risk_class is hm.RiskClass.HIGH


# --- P2-5 idempotency ------------------------------------------------------------------


async def test_p2_5_a_known_id_without_its_record_is_refused(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    idem = hm.idempotency_id("req-1")
    a = store.add(new_action(idempotency_id=idem)).action
    store.apply(a.action_id, S.CANCELLED, actor=A.ENGINE, ts=T0 + 1, reason="x")
    store._evict_oldest_terminal(1)
    with pytest.raises(hs.IdempotencyExpiredError):
        store.add(new_action(idempotency_id=idem, ts=T0 + 60))
    assert store.actions == {}


async def test_p2_5_after_expiry_dedupe_still_returns_the_open_action(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    idem = hm.idempotency_id("req-2")
    first = store.add(new_action(idempotency_id=idem)).action
    advance(store, clock, hs.IDEMPOTENCY_TTL_S + 600)
    store.prune()
    assert idem in store.loop.idempotency  # kept while its action is open
    store.apply(first.action_id, S.ANALYZED, actor=A.ENGINE, ts=clock.now, reason="x")
    retry = store.add(new_action(idempotency_id=idem, ts=clock.now))
    assert (retry.created, retry.action.action_id) == (False, first.action_id)


async def test_p2_5_after_expiry_the_cooldown_stops_a_repeat(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    idem = hm.idempotency_id("req-3")
    first = store.add(new_action(idempotency_id=idem)).action
    # approval took almost a day, then the action ran and was resolved
    advance(store, clock, hs.IDEMPOTENCY_TTL_S - 1200)
    to_approved(store, first.action_id, clock.now)
    assert (await execute(store, first.action_id, ts=clock.now + 10)).ok
    store.apply(
        first.action_id, S.VERIFYING, actor=A.ENGINE, ts=clock.now + 11, reason="ok"
    )
    store.apply(
        first.action_id, S.RESOLVED, actor=A.ENGINE, ts=clock.now + 12, reason="ok"
    )
    advance(store, clock, 1500)  # past the 24 h of the id, inside the cooldown
    assert store.prune() >= 1
    assert idem not in store.loop.idempotency  # forgotten after 24 h
    retry = store.add(new_action(idempotency_id=idem, ts=clock.now))
    assert retry.created  # a new record may exist ...
    to_approved(store, retry.action.action_id, clock.now)
    result = await execute(store, retry.action.action_id, ts=clock.now + 10)
    assert (result.ok, result.reason) == (False, "cooling_down")  # ... not run


# --- P2-6 incident and component dedupe ------------------------------------------


async def test_p2_6_one_open_action_per_router_and_component(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    first = store.add(new_action()).action
    other = store.add(new_action(action_type="service.reload", incident_id="inc-99"))
    assert (other.created, other.dedupe, other.action) == (False, "component", first)
    # a second component of a multi-component action blocks as well
    multi = store.add(
        new_action(
            action_type="service.reload",
            params={"name": "odhcpd"},
            incident_id="inc-50",
            components=(
                hm.Component(kind=hm.ComponentKind.SERVICE, name="odhcpd"),
                hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq"),
            ),
        )
    )
    assert (multi.created, multi.dedupe) == (False, "component")
    # same component name on another router is another component
    assert store.add(new_action(router_id=R2, incident_id="inc-60")).created


async def test_p2_6_one_open_action_per_root_incident(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    first = store.add(new_action()).action
    elsewhere = store.add(svc(4, router_id=R2, incident_id="inc-7"))
    assert (elsewhere.created, elsewhere.dedupe, elsewhere.action) == (
        False,
        "incident",
        first,
    )


def test_p2_6_dedupe_ids() -> None:
    comp = hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq")
    assert hm.incident_dedupe_id("inc-7") == hm.incident_dedupe_id("inc-7")
    assert hm.incident_dedupe_id("inc-7") != hm.incident_dedupe_id("inc-8")
    c1 = hm.component_dedupe_id(R1, comp)
    assert c1 != hm.component_dedupe_id(R2, comp)
    action = new_action()
    assert action.component_dedupes == (c1,)
    bare = new_action(components=())
    router = hm.Component(kind=hm.ComponentKind.ROUTER, name="router")
    assert bare.component_dedupes == (hm.component_dedupe_id(R1, router),)


# --- P2-7 unreadable record holds its router -------------------------------------------


async def test_p2_7_damaged_in_flight_record_holds_its_router(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    store.set_settings(
        hm.HealSettings(routers={R1: hm.RouterSettings(mode=hm.HealMode.APPROVAL)})
    )
    act = store.add(new_action()).action
    to_approved(store, act.action_id)
    assert (await execute(store, act.action_id)).ok
    await store.async_flush()
    disk_record(disks, act.action_id)["components"] = [
        {"kind": "service", "name": "bad name!"}
    ]
    again, result = await open_store(clock)
    assert result.bad_records == 1
    hold = again.router_hold(R1)
    assert hold is not None and hold.reason is hm.HoldReason.RECORD_UNREADABLE
    # its raw state still says EXECUTING: held until an admin releases it
    assert hold.until is None
    assert again.effective_mode(R1) is hm.HealMode.OBSERVE
    assert again.effective_mode(R2) is hm.HealMode.OBSERVE  # default anyway
    assert again.router_hold(R2) is None
    twin = again.add(new_action()).action
    to_preflight = [S.ANALYZED, S.PROPOSED, S.PREFLIGHT]
    for i, state in enumerate(to_preflight, start=1):
        again.apply(twin.action_id, state, actor=A.ENGINE, ts=T0 + i, reason="x")
    with pytest.raises(hs.RouterHeldError):
        again.apply(twin.action_id, S.APPROVED, actor=A.ENGINE, ts=T0 + 5, reason="x")
    with pytest.raises(hs.RouterHeldError):
        again.apply(
            twin.action_id, S.WAITING_APPROVAL, actor=A.ENGINE, ts=T0 + 5, reason="x"
        )
    # the hold is in the file and survives a restart
    assert on_disk(disks)["loop"]["holds"][0]["reason"] == "record_unreadable"
    third, _ = await open_store(clock)
    assert third.router_hold(R1) is not None
    # it ends after 24 h of plausible time, or by an admin
    with pytest.raises(hs.HealStoreError):
        third.release_hold(R1, actor=A.ENGINE, ts=T0)
    assert third.release_hold(R1, actor=A.ADMIN, ts=T0)
    assert third.router_hold(R1) is None
    advance(again, clock, hs.UNREADABLE_HOLD_S + 600)
    assert again.router_hold(R1) is not None  # no end: time does not free it


async def test_p2_7_damaged_record_never_run_holds_its_router_24h(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = store.add(new_action()).action
    await store.async_flush()
    disk_record(disks, act.action_id)["components"] = [
        {"kind": "service", "name": "bad name!"}
    ]
    again, result = await open_store(clock)
    assert result.bad_records == 1
    hold = again.router_hold(R1)
    assert hold is not None and hold.reason is hm.HoldReason.RECORD_UNREADABLE
    assert hold.until == pytest.approx(again.now() + hs.UNREADABLE_HOLD_S, abs=1)
    advance(again, clock, hs.UNREADABLE_HOLD_S + 600)
    assert again.router_hold(R1) is None


async def test_p2_7_unreadable_router_id_holds_the_fleet(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    store.add(new_action())
    await store.async_flush()
    on_disk(disks)["actions"][0]["router_id"] = "not-a-router"
    again, result = await open_store(clock)
    assert result.bad_records == 1
    hold = again.router_hold(R2)
    assert hold is not None and hold.router_id is None
    assert again.router_hold(R1) is hold


async def test_p2_7_a_lost_store_holds_the_fleet(
    disks: FakeDisks, clock: Clock
) -> None:
    disks[KEY].data = {"version": 9, "minor_version": 1, "key": KEY, "data": {}}
    store, result = await open_store(clock)
    assert result.failed
    hold = store.router_hold(R1)
    assert hold is not None and hold.reason is hm.HoldReason.STORE_LOST


# --- P2-8 an unknown outcome holds the router -------------------------------------


async def test_p2_8_unknown_outcome_holds_the_router_until_an_admin_releases(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = store.add(svc(1)).action
    await to_verifying(store, act.action_id, T0)
    store.apply(
        act.action_id,
        S.MANUAL_RECOVERY_REQUIRED,
        actor=A.ENGINE,
        ts=T0 + 30,
        reason="outcome_unknown",
    )
    assert not store.loop.repair_active(R1)  # the short lock is gone
    hold = store.router_hold(R1)
    assert hold is not None
    assert (hold.reason, hold.action_id, hold.until) == (
        hm.HoldReason.OUTCOME_UNKNOWN,
        act.action_id,
        None,
    )
    advance(store, clock, 7 * 86400)
    assert store.router_hold(R1) is hold  # no expiry
    # no further action of any type on the router ...
    nxt = store.add(svc(2, action_type="service.reload")).action
    for i, state in enumerate((S.ANALYZED, S.PROPOSED, S.PREFLIGHT), start=1):
        store.apply(nxt.action_id, state, actor=A.ENGINE, ts=T0 + 40 + i, reason="x")
    with pytest.raises(hs.RouterHeldError):
        store.apply(nxt.action_id, S.APPROVED, actor=A.ENGINE, ts=T0 + 50, reason="x")
    # ... except read-only diagnostics
    diag = store.add(
        svc(3, action_type="diag.refresh", params={}, risk=READ_ONLY)
    ).action
    to_approved(store, diag.action_id, T0 + 60)
    assert (await execute(store, diag.action_id, ts=T0 + 70)).ok
    # persisted; only an admin releases it
    await store.async_flush()
    again, _ = await open_store(clock)
    assert again.router_hold(R1) is not None
    assert again.get(nxt.action_id).state is S.CANCELLED  # preflight lost
    assert again.release_hold(R1, actor=A.ADMIN, ts=T0 + 80)
    later = again.add(svc(4, action_type="service.reload")).action
    to_approved(again, later.action_id, T0 + 81)


async def test_p2_8_a_clean_rejection_does_not_hold(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = store.add(svc(1)).action
    to_approved(store, act.action_id)
    assert (await execute(store, act.action_id)).ok
    store.apply(
        act.action_id,
        S.FAILED,
        actor=A.ENGINE,
        ts=T0 + 11,
        reason="call_rejected",
        changes={
            "execution": hm.Execution(
                attempt_no=1,
                intent_written_at=T0 + 10,
                call_result=hm.CallResult.REJECTED,
            )
        },
    )
    store.apply(act.action_id, S.ESCALATED, actor=A.ENGINE, ts=T0 + 12, reason="x")
    assert store.router_hold(R1) is None


@pytest.mark.parametrize(
    ("final", "reason"),
    [
        (S.ESCALATED, hm.HoldReason.OUTCOME_ESCALATED),
        (S.MANUAL_RECOVERY_REQUIRED, hm.HoldReason.OUTCOME_UNKNOWN),
    ],
)
async def test_p2_8_hold_reasons(
    disks: FakeDisks, clock: Clock, final: hm.ActionState, reason: hm.HoldReason
) -> None:
    store, _ = await open_store(clock)
    act = store.add(svc(1)).action
    await to_verifying(store, act.action_id, T0)
    store.apply(act.action_id, final, actor=A.ENGINE, ts=T0 + 30, reason="x")
    assert store.router_hold(R1).reason is reason


async def test_p2_8_restart_rule_outcomes_hold_too(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = store.add(svc(1)).action
    to_approved(store, act.action_id)
    assert (await execute(store, act.action_id)).ok
    store.apply(act.action_id, S.FAILED, actor=A.ENGINE, ts=T0 + 11, reason="bad")
    await store.async_flush()
    again, _ = await open_store(clock)  # FAILED -> ESCALATED by recovery
    assert again.get(act.action_id).state is S.ESCALATED
    assert again.router_hold(R1) is not None


# --- P2-9 the safety clock -------------------------------------------------------------


async def test_p2_9_a_forward_jump_does_not_forget_attempts(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    key = (R1, "service.restart", "service:dnsmasq")
    store.loop.attempts[key] = hm.AttemptRecord(
        count=2, window_start=T0, last_at=T0, cooldown_until=T0 + 1800
    )
    clock.now = T0 + 8 * 86400  # wall clock wrongly 8 days ahead
    store.prune()
    assert key in store.loop.attempts
    assert store.loop.clock.jumps_ahead == 1
    assert store.now() <= T0 + hm.CLOCK_STEP_MAX_S


def test_p2_9_safety_clock_rules() -> None:
    c = hm.SafetyClock().observe(T0)
    assert (c.wall, c.safe) == (T0, T0)
    c = c.observe(T0 + 100)
    assert c.safe == T0 + 100
    back = c.observe(T0 - 5000)  # backwards: no time passes
    assert back.safe == T0 + 100 and back.jumps_back == 1
    # wall time only counts beyond the highest wall time seen (review 2)
    resumed = back.observe(T0 - 4900)
    assert resumed.safe == T0 + 100 and resumed.high == T0 + 100
    assert resumed.observe(T0 + 150).safe == T0 + 150
    ahead = c.observe(T0 + 100 + 86400)  # forward: one plausible step only
    assert ahead.safe == T0 + 100 + hm.CLOCK_STEP_MAX_S and ahead.jumps_ahead == 1
    assert hm.SafetyClock.from_dict(json.loads(json.dumps(ahead.to_dict()))) == ahead


async def test_p2_9_a_forward_jump_never_shortens_a_cooldown(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    first = store.add(svc(1)).action
    to_approved(store, first.action_id)
    assert (await execute(store, first.action_id)).ok
    store.apply(first.action_id, S.VERIFYING, actor=A.ENGINE, ts=T0 + 11, reason="ok")
    store.apply(first.action_id, S.RESOLVED, actor=A.ENGINE, ts=T0 + 12, reason="ok")
    clock.now = T0 + 3 * 3600  # jump ahead past the 30 min cooldown
    second = store.add(svc(1, ts=clock.now)).action
    to_approved(store, second.action_id, clock.now)
    result = await execute(store, second.action_id, ts=clock.now + 10)
    assert (result.ok, result.reason) == (False, "cooling_down")
    advance(store, clock, 1800)  # real time passes
    assert (await execute(store, second.action_id, ts=clock.now)).ok


async def test_p2_9_a_backward_jump_never_shortens_a_hold_or_pause(
    disks: FakeDisks, clock: Clock
) -> None:
    disks[KEY].data = {"version": 9, "minor_version": 1, "key": KEY, "data": {}}
    store, _ = await open_store(clock)  # store lost: pause + fleet hold 24 h
    clock.now = T0 - 30 * 86400  # backwards
    assert store.router_hold(R1) is not None
    assert store.loop.fleet.paused(store.now())
    clock.now = T0 + 30 * 86400  # and far ahead
    assert store.router_hold(R1) is not None
    assert store.loop.fleet.paused(store.now())


def test_p2_9_maintenance_counts_on_either_clock() -> None:
    win = hm.MaintenanceWindow(
        window_id="mtw_" + "7" * 32,
        scope=hm.MaintenanceScope.SERVICE,
        router_id=R1,
        target="dnsmasq",
        start=T0,
        end=T0 + 3600,
        reason="planned",
        created_by=A.ADMIN,
    )
    assert win.active(T0 + 10)
    assert win.active(T0 + 7200, safe_now=T0 + 10)  # wall past, safe inside
    assert win.active(T0 - 10, safe_now=T0 + 10)
    assert not win.active(T0 + 7200, safe_now=T0 + 7200)


# --- P2-10 terminal history is not dropped for nothing --------------------------------


async def test_p2_10_over_size_keeps_terminal_records(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock, max_bytes=6000)
    done = store.add(new_action(params={"name": "t"}, incident_id="t")).action
    store.apply(done.action_id, S.CANCELLED, actor=A.ENGINE, ts=T0 + 1, reason="x")
    for i in range(10):
        store.add(svc(10 + i))
    payload = store.payload()
    assert done.action_id in store.actions
    assert done.action_id in {a["action_id"] for a in payload["actions"]}
    assert store.counters["save_over_size"] == 1
    assert store.counters["evicted_terminal"] == 0
    act = min(a.action_id for a in store.open_actions(R1))
    to_approved(store, act)
    result = await execute(store, act)
    assert (result.ok, result.reason) == (False, "over_size")


async def test_p2_10_size_estimate_is_an_upper_bound(
    disks: FakeDisks, clock: Clock
) -> None:
    from test_heal_model_v1530 import full_action

    store, _ = await open_store(clock)
    for i in range(30):
        store.add(svc(i, router_id=(R1, R2)[i % 2]))
    full = full_action()
    store.actions[full.action_id] = full
    payload = store.payload()
    real = hs.store_bytes(payload)
    assert real <= store.last_bytes <= real + 16 * len(payload["actions"]) + 64


# --- P3 admin ways out, token-like names -------------------------------------------


async def test_p3_admin_releases_an_action_stuck_in_executing(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = store.add(svc(1)).action
    to_approved(store, act.action_id)
    assert (await execute(store, act.action_id)).ok
    with pytest.raises(hs.HealStoreError):
        store.admin_release_stuck(act.action_id, actor=A.ENGINE, ts=T0 + 99)
    done = store.admin_release_stuck(act.action_id, actor=A.ADMIN, ts=T0 + 99)
    assert done.state is S.MANUAL_RECOVERY_REQUIRED and done.flags.interrupted
    assert not store.loop.repair_active(R1)
    hold = store.router_hold(R1)
    assert hold.reason is hm.HoldReason.STUCK_RELEASED
    assert [h.to_state for h in done.history].count(S.EXECUTING) == 1


async def test_p3_admin_force_releases_a_stuck_external_lock(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    token = store.try_external_lock(R1, "button.reboot", T0)
    assert token
    with pytest.raises(hs.HealStoreError):
        store.admin_force_release_lock(R1, actor=A.ENGINE, ts=T0 + 5)
    assert store.admin_force_release_lock(R1, actor=A.ADMIN, ts=T0 + 5)
    assert store.loop.lock_holder(R1) is None
    assert store.router_hold(R1).reason is hm.HoldReason.LOCK_FORCED
    assert not store.release_external_lock(R1, token)


@pytest.mark.parametrize(
    "name",
    [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIi.abc",
        "Zm9vYmFy:YmF6cXV4cXV1eA",
        "sk-aB3dE5fG7hI9jK1l",
        "a1b2c3d4e5f6a7b8c9d0",
    ],
)
def test_p3_token_like_names_are_refused(name: str) -> None:
    with pytest.raises(hm.HealModelError):
        hm.Component(kind=hm.ComponentKind.SERVICE, name=name)


@pytest.mark.parametrize(
    "name", ["dnsmasq", "odhcpd", "radio1", "phy0-ap0", "br-lan", "eth0.10", "wlan1-1"]
)
def test_p3_router_names_still_pass(name: str) -> None:
    assert hm.Component(kind=hm.ComponentKind.SERVICE, name=name).name == name


# --- the reviewer's exhaustive search, kept as a regression -------------------------


def _moves(action: hm.RemediationAction) -> list[tuple[str, hm.RemediationAction]]:
    out = []
    for dst in S:
        for actor in A:
            try:
                new = hm.transition(
                    action, dst, actor=actor, ts=action.updated_at + 1, reason="x"
                )
            except hm.TransitionError:
                continue
            out.append((f"{actor.value}:{dst.value}", new))
    out.append(("restart", hm.apply_restart_recovery(action, ts=action.updated_at + 1)))
    return out


def test_reviewer_exhaustive_search_with_restarts() -> None:
    start = hm.RemediationAction.new(router_id=R1, action_type="service.restart", ts=T0)
    seen: set[Any] = set()
    queue = deque([(start, 0)])
    paths = 0
    violations: list[Any] = []
    while queue:
        action, restarts = queue.popleft()
        key = (
            tuple((h.from_state, h.to_state, h.actor) for h in action.history),
            action.flags.interrupted,
            action.rollback.status,
            restarts,
        )
        if key in seen:
            continue
        seen.add(key)
        paths += 1
        hist = [(h.from_state, h.to_state, h.actor) for h in action.history]
        tos = [t for _f, t, _a in hist]
        if tos.count(S.EXECUTING) > 1 or tos.count(S.ROLLING_BACK) > 1:
            violations.append(hist)
        for i, (f, t, a) in enumerate(hist):
            if t is S.EXECUTING and (f is not S.APPROVED or a is not A.ENGINE):
                violations.append(hist)
            if t in (S.EXECUTING, S.ROLLING_BACK) and any(
                a2 is A.RECOVERY for _f2, t2, a2 in hist[:i] if t2 is S.VERIFYING
            ):
                violations.append(hist)
            if f in hm.TERMINAL_STATES:
                violations.append(hist)
        if action.state in hm.TERMINAL_STATES:
            assert all(nxt is action for _l, nxt in _moves(action))
            continue
        for label, nxt in _moves(action):
            if nxt is action:
                continue
            r = restarts + (label == "restart")
            if r <= 3:
                queue.append((nxt, r))
    assert violations == []
    assert paths > 100
