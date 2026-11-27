"""Self-Healing, package B: fixes of the second review of PR #75.

The reviewer's round-2 tests asserted the unsafe outcome; here the safe one
is asserted, plus the guards the review found without a failing test:

* P2-1 the safety clock never runs faster than real time while HA runs
  (monotonic step) and counts wall time only beyond its high-water mark;
* P2-2 a damaged loop section does not turn a hold with no end into 24 h;
* point 3: a damaged record that shows it reached a call holds with no end;
* P2-3 the hold check and the attempt booking of the durable step;
* P2-4 retention runs from the safety time a record became terminal;
* P3 the flush/close lock, the write sequence, the read-back's sequence
  check, idempotency ids of open actions, ``audit_refs``, and ``add()``
  takes only records as ``new()`` makes them.

No router, no network; FakeDisks only.
"""

# ruff: noqa: F811  (pytest fixtures imported from test_heal_store_v1530)

from __future__ import annotations

import asyncio
import json
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
    to_approved,
)

from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_store as hs

S = hm.ActionState
A = hm.Actor
STEP = hm.CLOCK_STEP_MAX_S


def risky(**kw: Any) -> Any:
    return new_action(risk=hm.Risk(risk_class=hm.RiskClass.MEDIUM), **kw)


def other_service(**kw: Any) -> Any:
    return risky(
        action_type="service.reload",
        params={"name": "odhcpd"},
        incident_id="inc-60",
        components=(hm.Component(kind=hm.ComponentKind.SERVICE, name="odhcpd"),),
        **kw,
    )


async def unknown_outcome(store: hs.SelfHealingStore) -> hm.RemediationAction:
    act = store.add(risky()).action
    to_approved(store, act.action_id)
    assert (await execute(store, act.action_id)).ok
    store.apply(act.action_id, S.VERIFYING, actor=A.ENGINE, ts=T0 + 11, reason="x")
    store.apply(
        act.action_id,
        S.MANUAL_RECOVERY_REQUIRED,
        actor=A.ENGINE,
        ts=T0 + 12,
        reason="x",
    )
    hold = store.router_hold(R1)
    assert hold is not None and hold.until is None
    return act


def flap(store: hs.SelfHealingStore, clock: Clock, times: int) -> None:
    """The wall clock flips by one step per observation; no real time."""
    base = clock.now
    for i in range(times):
        clock.now = base + i + (STEP if i % 2 else 0)
        store.now()
    clock.now = base + times


# --- P2-1 the safety clock ---------------------------------------------------------


def test_r2_p2_1_wrong_then_corrected_counts_once() -> None:
    """Reviewer: ahead then back gained a step each time. Now the wall time
    counts only beyond the highest wall time ever seen."""
    c = hm.SafetyClock().observe(T0)
    c = c.observe(T0 + 3600)  # wrong ahead: one step (looks like downtime)
    assert c.safe == T0 + STEP
    c = c.observe(T0 + 1)  # corrected
    c = c.observe(T0 + 3601)  # ahead again: only 1 s beyond the high mark
    c = c.observe(T0 + 2)
    assert c.safe == T0 + STEP + 1
    assert c.high == T0 + 3601


def test_r2_p2_1_oscillation_does_not_run_fast() -> None:
    """Reviewer: a clock flapping by 900 s gave > 22 h in 200 observations."""
    wall_only = hm.SafetyClock().observe(T0)
    mono = hm.SafetyClock().observe(T0)
    for i in range(1, 200):
        wall = T0 + i + (STEP if i % 2 else 0)
        wall_only = wall_only.observe(wall)
        mono = mono.observe(wall, elapsed=1.0)
    assert wall_only.safe - T0 <= STEP + 200  # high mark: one step, then 1 s each
    assert mono.safe - T0 == 199  # monotonic: exactly the real time


def test_r2_p2_1_monotonic_step_ignores_the_wall_clock() -> None:
    c = hm.SafetyClock().observe(T0)
    c = c.observe(T0 + 86400, elapsed=2.0)  # wall jumps a day: 2 s passed
    assert c.safe == T0 + 2 and c.jumps_ahead == 1
    c = c.observe(T0 - 86400, elapsed=3.0)  # wall jumps back: 3 s passed
    assert c.safe == T0 + 5 and c.jumps_back == 1
    c = c.observe(T0, elapsed=10_000.0)  # a long pause in one run: capped
    assert c.safe == T0 + 5 + STEP
    assert c.observe(T0, elapsed=-5.0).safe == c.safe  # never backwards
    for bad in (float("nan"), True, "1"):
        with pytest.raises(hm.HealModelError):
            c.observe(T0, elapsed=bad)


def test_r2_p2_1_high_mark_is_persisted_and_never_below_wall() -> None:
    c = hm.SafetyClock().observe(T0).observe(T0 + 50).observe(T0 + 10)
    assert hm.SafetyClock.from_dict(json.loads(json.dumps(c.to_dict()))) == c
    legacy = hm.SafetyClock.from_dict({"wall": T0, "safe": T0})
    assert legacy.high == T0
    with pytest.raises(hm.HealModelError):
        hm.SafetyClock.from_dict({"wall": T0, "safe": T0, "high": T0 - 1})


async def test_r2_p2_1_cooldown_not_cut_short_by_a_flapping_clock(
    disks: FakeDisks, clock: Clock
) -> None:
    """Reviewer: 30 min cooldown over after ~16 s. The store's default
    monotonic source (``time.monotonic``) is used here."""
    store = hs.SelfHealingStore(make_hass(), clock=clock)
    await store.async_load()
    act = store.add(risky()).action
    to_approved(store, act.action_id)
    assert (await execute(store, act.action_id)).ok
    store.apply(act.action_id, S.VERIFYING, actor=A.ENGINE, ts=T0 + 11, reason="x")
    store.apply(act.action_id, S.RESOLVED, actor=A.ENGINE, ts=T0 + 12, reason="x")
    second = store.add(risky(incident_id="inc-8")).action
    to_approved(store, second.action_id, ts=T0 + 20)
    flap(store, clock, 200)
    res = await execute(store, second.action_id, ts=T0 + 40)
    assert (res.ok, res.reason) == (False, "cooling_down")


async def test_r2_p2_1_attempts_window_not_cut_short_by_a_flapping_clock(
    disks: FakeDisks, clock: Clock
) -> None:
    store = hs.SelfHealingStore(make_hass(), clock=clock)
    await store.async_load()
    act = store.add(risky()).action
    to_approved(store, act.action_id)
    safe = store.now()
    limit = store.settings.limits.max_attempts_24h
    for key in act.loop_keys:
        store.loop.attempts[key] = hm.AttemptRecord(
            count=limit, window_start=safe, last_at=safe
        )
    flap(store, clock, 400)  # old clock: 200 steps of 900 s = 50 h
    res = await execute(store, act.action_id, ts=T0 + 40)
    assert (res.ok, res.reason) == (False, "max_attempts")


async def test_r2_p2_1_restart_counts_wall_time_beyond_the_high_mark_only(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    advance(store, clock, 600)
    assert store.now() == T0 + 600
    clock.now = T0 + 3600  # wrong ahead while HA runs: no real time passed
    assert store.now() == T0 + 600
    await store.async_flush()
    clock.now = T0 + 700  # corrected, then HA restarts
    again, _ = await open_store(clock)
    assert again.now() == T0 + 600  # below the high mark: nothing counts
    await again.async_flush()
    clock.now = T0 + 3700
    third, _ = await open_store(clock)
    assert third.now() == T0 + 700  # 100 s beyond the high mark


# --- P2-2 a damaged loop keeps holds with no end -----------------------------------


async def test_r2_p2_2_damaged_loop_keeps_the_no_end_hold(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = await unknown_outcome(store)
    await store.async_flush()
    on_disk(disks)["loop"]["holds"][0]["reason"] = "bogus"  # damage
    again, result = await open_store(clock)
    assert result.bad_records >= 1
    assert again.get(act.action_id).state is S.MANUAL_RECOVERY_REQUIRED
    hold = again.loop.holds.get(R1)
    assert hold is not None
    assert (hold.reason, hold.until, hold.action_id) == (
        hm.HoldReason.OUTCOME_UNKNOWN,
        None,
        act.action_id,
    )
    assert act.action_id in again.loop.terminal_at  # stamp rebuilt too
    advance(again, clock, 3 * 86400)
    again.prune()
    assert again.router_hold(R1) is hold  # time never frees it


async def test_r2_p2_2_a_released_hold_is_not_placed_again(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = await unknown_outcome(store)
    assert store.release_hold(R1, actor=A.ADMIN, ts=T0 + 20)
    assert store.get(act.action_id).flags.hold_released
    await store.async_flush()
    again, _ = await open_store(clock)
    assert again.router_hold(R1) is None
    await again.async_flush()
    on_disk(disks)["loop"]["holds"] = [{"router_id": "bogus"}]  # damage
    third, _ = await open_store(clock)
    assert R1 not in third.loop.holds  # only the fleet's 24 h damage hold
    fleet = third.router_hold(R1)
    assert fleet is not None and fleet.router_id is None and fleet.until is not None


async def test_r2_p2_2_hold_released_is_only_set_by_release_hold(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = await unknown_outcome(store)
    with pytest.raises(hs.HealStoreError):
        store.update_flags(act.action_id, hold_released=True)
    released = store.get(act.action_id).with_flags(hold_released=True)
    with pytest.raises(hm.HealModelError):
        released.with_flags(hold_released=False)


# --- point 3: a damaged record that reached a call ------------------------------


async def test_r2_damaged_record_with_in_flight_history_holds_with_no_end(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = store.add(risky()).action
    to_approved(store, act.action_id)
    assert (await execute(store, act.action_id)).ok
    await store.async_flush()
    disk_record(disks, act.action_id)["state"] = "bogus"  # only history readable
    again, result = await open_store(clock)
    assert result.bad_records == 1
    hold = again.router_hold(R1)
    assert hold is not None and hold.router_id == R1 and hold.until is None
    assert again.router_hold(R2) is None  # its router only, not the fleet


async def test_r2_damaged_in_flight_record_without_router_holds_the_fleet(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = store.add(risky()).action
    to_approved(store, act.action_id)
    assert (await execute(store, act.action_id)).ok
    await store.async_flush()
    disk_record(disks, act.action_id)["router_id"] = "not-a-router"
    again, _ = await open_store(clock)
    hold = again.router_hold(R2)
    assert hold is not None and hold.router_id is None and hold.until is None


def test_r2_in_flight_evidence_of_raw_records() -> None:
    assert hs._shows_in_flight({"state": "rolling_back"})
    assert hs._shows_in_flight({"state": 3, "history": [{"to_state": "verifying"}]})
    assert not hs._shows_in_flight({"state": ["executing"], "history": "x"})
    assert not hs._shows_in_flight({"state": "approved", "history": [None, {}]})
    assert not hs._shows_in_flight(None)


# --- P2-3 guards of the durable step --------------------------------------------


async def test_r2_p2_3_hold_placed_while_other_action_approved(
    disks: FakeDisks, clock: Clock
) -> None:
    """B waits in APPROVED while A runs; A ends with an unknown outcome:
    the hold must stop B's durable step."""
    store, _ = await open_store(clock)
    a = store.add(risky()).action
    b = store.add(other_service()).action
    to_approved(store, a.action_id)
    to_approved(store, b.action_id)
    assert (await execute(store, a.action_id)).ok
    store.apply(a.action_id, S.VERIFYING, actor=A.ENGINE, ts=T0 + 11, reason="x")
    store.apply(
        a.action_id, S.MANUAL_RECOVERY_REQUIRED, actor=A.ENGINE, ts=T0 + 12, reason="x"
    )
    saves = len(disks[KEY].saves)
    res = await execute(store, b.action_id, ts=T0 + 13)
    assert (res.ok, res.reason) == (False, "router_held")
    assert len(disks[KEY].saves) == saves
    assert store.get(b.action_id).state is S.APPROVED


async def test_r2_p2_3_attempt_is_in_the_durable_write(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    a = store.add(risky()).action
    to_approved(store, a.action_id)
    assert (await execute(store, a.action_id)).ok
    rows = on_disk(disks)["loop"]["attempts"]
    assert rows and all(row["count"] == 1 for row in rows)
    assert len(rows) == len(a.loop_keys)
    assert disk_record(disks, a.action_id)["execution"]["attempt_no"] == 1


# --- P2-4 retention from the safety time a record became terminal ---------------


async def test_r2_p2_4_first_start_with_future_clock_keeps_history(
    disks: FakeDisks, clock: Clock
) -> None:
    clock.now = T0 + 400 * 86400  # wrong clock at the very first start
    store, _ = await open_store(clock)
    clock.now = T0  # NTP corrects
    a = store.add(risky(ts=T0)).action
    store.apply(a.action_id, S.CANCELLED, actor=A.ENGINE, ts=T0 + 1, reason="x")
    store.prune()
    assert a.action_id in store.actions
    advance(store, clock, hs.TERMINAL_RETENTION_S - 3600)
    store.prune()
    assert a.action_id in store.actions
    advance(store, clock, 7200)
    store.prune()
    assert a.action_id not in store.actions
    assert a.action_id not in store.loop.terminal_at


async def test_r2_p2_4_wall_stamps_behind_do_not_age_a_record(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    clock.now = T0 - 100 * 86400  # the wall clock jumps back while HA runs
    a = store.add(risky(ts=clock.now)).action
    store.apply(a.action_id, S.CANCELLED, actor=A.ENGINE, ts=clock.now + 1, reason="x")
    clock.now = T0 + 3600  # corrected
    advance(store, clock, 86400)
    store.prune()
    assert a.action_id in store.actions


async def test_r2_p2_4_maintenance_window_kept_after_a_future_first_start(
    disks: FakeDisks, clock: Clock
) -> None:
    clock.now = T0 + 400 * 86400
    store, _ = await open_store(clock)
    clock.now = T0
    window = hm.MaintenanceWindow(
        window_id="mtw_" + "7" * 32,
        scope=hm.MaintenanceScope.SERVICE,
        router_id=R1,
        target="dnsmasq",
        start=T0,
        end=T0 + 3600,
        reason="planned",
        created_by=A.ADMIN,
    )
    store.add_maintenance(window)
    store.prune()
    assert store.maintenance == [window]


async def test_r2_p2_4_terminal_stamp_is_kept_and_dropped_with_the_record(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    a = store.add(risky()).action
    advance(store, clock, 600)
    store.apply(a.action_id, S.CANCELLED, actor=A.ENGINE, ts=clock.now, reason="x")
    assert store.loop.terminal_at[a.action_id] == T0 + 600
    await store.async_flush()
    again, _ = await open_store(clock)
    assert again.loop.terminal_at == {a.action_id: T0 + 600}
    again._evict_oldest_terminal(1)
    assert again.loop.terminal_at == {}


@pytest.mark.parametrize(
    "terminal_at",
    [["rem_" + "1" * 32], {"not-an-id": T0}, {"rem_" + "1" * 32: "soon"}],
)
def test_r2_p2_4_damaged_terminal_stamps_are_refused(terminal_at: Any) -> None:
    with pytest.raises(hm.HealModelError):
        hm.LoopState.from_dict({"terminal_at": terminal_at})


# --- P3 the flush/close lock, the sequence, the read-back -------------------------


def _gate_first_save(store: hs.SelfHealingStore) -> tuple[asyncio.Event, list[int]]:
    gate = asyncio.Event()
    seqs: list[int] = []
    real_save = store._store.async_save

    async def gated(data: Any) -> None:
        seqs.append(data["write_seq"])
        if len(seqs) == 1:
            await gate.wait()
        await real_save(data)

    store._store.async_save = gated
    return gate, seqs


@pytest.mark.parametrize("op", ["flush", "close"])
async def test_r2_p3_flush_and_close_wait_for_the_durable_step(
    disks: FakeDisks, clock: Clock, op: str
) -> None:
    store, _ = await open_store(clock)
    act = store.add(risky()).action
    to_approved(store, act.action_id)
    await store.async_flush()
    gate, seqs = _gate_first_save(store)
    step = asyncio.create_task(execute(store, act.action_id))
    for _ in range(5):
        await asyncio.sleep(0)
    other = asyncio.create_task(
        store.async_flush() if op == "flush" else store.async_close()
    )
    for _ in range(5):
        await asyncio.sleep(0)
    assert not other.done() and len(seqs) == 1  # waits for the durable step
    gate.set()
    assert (await step).ok
    await other
    assert len(seqs) == 2 and seqs[1] > seqs[0]
    assert disk_record(disks, act.action_id)["state"] == "executing"


async def test_r2_p3_write_sequence_is_reserved(disks: FakeDisks, clock: Clock) -> None:
    store, _ = await open_store(clock)
    act = store.add(risky()).action
    to_approved(store, act.action_id)
    await store.async_flush()
    seqs: list[int] = []
    real_save = store._store.async_save

    async def record(data: Any) -> None:
        seqs.append(data["write_seq"])
        await real_save(data)

    store._store.async_save = record
    assert (await execute(store, act.action_id)).ok
    await store.async_flush()
    assert len(seqs) == 2 and seqs[0] < seqs[1] == store._seq
    assert on_disk(disks)["write_seq"] == seqs[1]


async def test_r2_p3_read_back_needs_this_write_not_an_older_file(
    disks: FakeDisks, clock: Clock
) -> None:
    """The first try lands on disk but its read-back fails; the second
    write is swallowed. The file holds the same record from the first try,
    with an older sequence number: that is not proof of this write."""
    store, _ = await open_store(clock)
    act = store.add(risky()).action
    to_approved(store, act.action_id)
    await store.async_flush()

    def broken_read(path: Any) -> Any:
        raise OSError("read failed")

    with patch.object(hs, "_read_store_file", broken_read):
        first = await execute(store, act.action_id)
    assert (first.ok, first.reason) == (False, "not_durable")
    assert disk_record(disks, act.action_id)["state"] == "executing"  # landed
    store._store.async_save = AsyncMock(return_value=None)  # HA swallows it
    second = await execute(store, act.action_id)
    assert (second.ok, second.reason) == (False, "not_durable")
    assert store.get(act.action_id).state is S.APPROVED


async def test_r2_p3_idempotency_ids_of_open_actions_are_never_capped(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    oldest = hm.idempotency_id("req-open")
    store.add(risky(idempotency_id=oldest))
    for i in range(3):
        advance(store, clock, 60)
        done = store.add(
            risky(
                idempotency_id=hm.idempotency_id(f"req-{i}"),
                params={"name": f"s{i}"},
                incident_id=f"inc-c{i}",
                components=(hm.Component(kind=hm.ComponentKind.SERVICE, name=f"s{i}"),),
                ts=clock.now,
            )
        ).action
        store.apply(
            done.action_id, S.CANCELLED, actor=A.ENGINE, ts=clock.now, reason="x"
        )
    with patch.object(hs, "IDEMPOTENCY_MAX", 2):
        store._cap_idempotency()
    assert oldest in store.loop.idempotency
    assert len(store.loop.idempotency) == 2


def test_r2_p3_audit_refs_only_grow_on_a_transition_too() -> None:
    ref1, ref2 = "evt_" + "4" * 32, "evt_" + "5" * 32
    action = new_action().with_changes(audit_refs=(ref1,))
    grown = hm.transition(
        action,
        S.ANALYZED,
        actor=A.ENGINE,
        ts=T0 + 1,
        reason="x",
        changes={"audit_refs": (ref1, ref2)},
    )
    assert grown.audit_refs == (ref1, ref2)
    for refs in ((ref2,), (ref2, ref1), ()):
        with pytest.raises(hm.HealModelError):
            hm.transition(
                grown,
                S.PROPOSED,
                actor=A.ENGINE,
                ts=T0 + 2,
                reason="x",
                changes={"audit_refs": refs},
            )
        with pytest.raises(hm.HealModelError):
            grown.with_changes(audit_refs=refs)


async def test_r2_p3_add_takes_only_new_records(disks: FakeDisks, clock: Clock) -> None:
    """Reviewer: the constructor / from_dict bypassed new()'s defaults."""
    store, _ = await open_store(clock)
    base = risky()
    forged = [
        {"execution": {"attempt_no": 0, "intent_written_at": T0}},
        {"flags": {"interrupted": True}},
        {"flags": {"hold_released": True}},
        {"approval": {"status": "approved"}},
        {"verification": {"result": "resolved"}},
        {"updated_at": T0 + 5},
        {
            "history": [
                *base.to_dict()["history"],
                {
                    "from_state": "detected",
                    "to_state": "detected",
                    "ts": T0,
                    "actor": "engine",
                    "reason": "x",
                },
            ]
        },
    ]
    for change in forged:
        record = hm.RemediationAction.from_dict({**base.to_dict(), **change})
        assert not record.is_new
        with pytest.raises(hs.HealStoreError):
            store.add(record)
    assert store.actions == {}
    assert base.is_new and store.add(base).created
