"""Self-Healing, package B: fixes of the third review of PR #75.

* Point 1: real time counted in a run (monotonic) must not count again as
  wall time above the high-water mark at the next start;
* point 3: the record behind a hold in force is never evicted or pruned;
* point 4: safety time near ``TIME_MAX`` gives a clean refusal, not an error;
* point 5: ``release_hold`` changes nothing when no hold was in place;
* point 6: guards no test covered (maintenance cutoff on both clocks,
  stale terminal stamps, unstamped terminal records, the monotonic
  reference reset at load, a monotonic clock going backwards).

No router, no network; FakeDisks only.
"""

# ruff: noqa: F811  (pytest fixtures imported from test_heal_store_v1530)

from __future__ import annotations

import pytest
from core_testkit import FakeDisks
from test_heal_review2_v1530 import risky, unknown_outcome
from test_heal_store_v1530 import (  # noqa: F401 - fixtures
    KEY,
    R1,
    R2,
    T0,
    Clock,
    advance,
    clock,
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


# --- point 1: real time counts once ------------------------------------------------


def test_r3_back_during_run_then_corrected_counts_once() -> None:
    """Reviewer: 900 s of real time counted twice."""
    c = hm.SafetyClock().observe(T0)
    c = c.observe(T0 - 900, elapsed=0)  # wall set back 900 s while HA runs
    c = c.observe(T0, elapsed=900)  # 900 s real; wall still 900 s behind
    assert c.high == T0 + 900  # the run time raised the mark
    c = c.observe(T0 + 900)  # HA restarts, wall corrected
    assert c.safe - T0 == 900


def test_r3_back_and_restart_cycles_follow_real_time() -> None:
    """Reviewer: 48 cycles (12 h real) gave 24 h of safety time."""
    c = hm.SafetyClock().observe(T0)
    real = T0
    for _ in range(48):
        c = c.observe(real - 900, elapsed=0)
        c = c.observe(real, elapsed=900)
        real += 900
        c = c.observe(real)
    assert c.safe - T0 == 12 * 3600


def test_r3_mark_follows_run_time_with_caps() -> None:
    c = hm.SafetyClock().observe(T0)
    inf = c.observe(T0, elapsed=float("inf"))  # capped step, finite mark
    assert (inf.safe, inf.high) == (T0 + STEP, T0 + STEP)
    ahead = c.observe(T0 + 5000, elapsed=10)  # wall ahead: the mark is the wall
    assert (ahead.safe, ahead.high) == (T0 + 10, T0 + 5000)
    top = (
        hm.SafetyClock()
        .observe(hm.TIME_MAX - 10)
        .observe(hm.TIME_MAX - 10, elapsed=600)
    )
    assert top.high == hm.TIME_MAX and top.safe == hm.TIME_MAX


async def test_r3_store_cooldown_not_halved_by_a_back_set_and_restart(
    disks: FakeDisks, clock: Clock
) -> None:
    """Reviewer: a second execute succeeded ~900 s after the first against
    an 1800 s cooldown."""
    store, _ = await open_store(clock)
    act = store.add(risky()).action
    to_approved(store, act.action_id)
    assert (await execute(store, act.action_id)).ok
    store.apply(act.action_id, S.VERIFYING, actor=A.ENGINE, ts=T0 + 11, reason="x")
    store.apply(act.action_id, S.RESOLVED, actor=A.ENGINE, ts=T0 + 12, reason="x")
    clock.now = T0 - 900  # wall clock set back while HA runs
    advance(store, clock, 900)  # 900 s of real time; wall still behind
    await store.async_flush()
    clock.now = T0 + 900  # restart with the clock corrected
    again, _ = await open_store(clock)
    second = again.add(risky(incident_id="inc-8")).action
    to_approved(again, second.action_id, ts=T0 + 901)
    res = await execute(again, second.action_id, ts=T0 + 902)
    assert (res.ok, res.reason) == (False, "cooling_down")
    advance(again, clock, 900)  # now 1800 s of real time have passed
    assert (await execute(again, second.action_id, ts=clock.now)).ok


# --- point 3: the record behind a hold stays --------------------------------------


async def test_r3_held_record_is_not_evicted_and_the_hold_survives_damage(
    disks: FakeDisks, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reviewer: the held record was evicted first, then a damaged loop
    section turned the no-end hold into 24 h."""
    monkeypatch.setattr(hs, "MAX_ACTIONS", 4)
    store, _ = await open_store(clock)
    held = await unknown_outcome(store)
    for i in range(4):
        a = store.add(new_action(incident_id=f"inc-x{i}", router_id=R2)).action
        store.apply(a.action_id, S.CANCELLED, actor=A.ADMIN, ts=T0 + 30, reason="x")
    assert held.action_id in store.actions
    await store.async_flush()
    on_disk(disks)["loop"]["holds"] = [{"router_id": "bogus"}]
    again, _ = await open_store(clock)
    hold = again.loop.holds.get(R1)
    assert hold is not None and hold.until is None
    assert hold.action_id == held.action_id


async def test_r3_held_record_is_not_pruned(disks: FakeDisks, clock: Clock) -> None:
    store, _ = await open_store(clock)
    held = await unknown_outcome(store)
    other = store.add(new_action(incident_id="inc-y", router_id=R2)).action
    store.apply(other.action_id, S.CANCELLED, actor=A.ADMIN, ts=T0 + 30, reason="x")
    advance(store, clock, hs.TERMINAL_RETENTION_S + 3600)
    store.prune()
    assert held.action_id in store.actions
    assert other.action_id not in store.actions
    assert store.release_hold(R1, actor=A.ADMIN, ts=clock.now)
    store.prune()  # released: its retention applies again
    assert held.action_id not in store.actions


async def test_r3_held_record_is_not_dropped_for_size(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    held = await unknown_outcome(store)  # ends first: the oldest terminal
    other = store.add(new_action(incident_id="inc-z", router_id=R2)).action
    store.apply(other.action_id, S.CANCELLED, actor=A.ADMIN, ts=T0 + 30, reason="x")
    await store.async_flush()
    store.max_bytes = store.last_bytes - 1  # one record must go
    await store.async_flush()
    assert held.action_id in store.actions
    assert other.action_id not in store.actions


# --- point 4: times near TIME_MAX ----------------------------------------------------


async def test_r3_execute_near_time_max_is_refused_cleanly(
    disks: FakeDisks, clock: Clock
) -> None:
    clock.now = hm.TIME_MAX - 10
    store, _ = await open_store(clock)
    act = store.add(risky(ts=clock.now)).action
    to_approved(store, act.action_id, ts=clock.now)
    res = await execute(store, act.action_id, ts=clock.now)
    assert (res.ok, res.reason) == (False, "clock_invalid")
    assert store.get(act.action_id).state is S.APPROVED


async def test_r3_load_near_time_max_holds_and_pauses_without_error(
    disks: FakeDisks, clock: Clock
) -> None:
    clock.now = hm.TIME_MAX - 10
    disks[KEY].data = {"version": 9, "minor_version": 1, "key": KEY, "data": {}}
    store, result = await open_store(clock)
    assert result.failed and result.paused
    hold = store.router_hold(R1)
    assert hold is not None and hold.until == hm.TIME_MAX
    assert store.loop.fleet.paused_until == hm.TIME_MAX


# --- point 5: release_hold without a hold ------------------------------------------


async def test_r3_release_without_a_hold_changes_nothing(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    act = await unknown_outcome(store)
    await store.async_flush()
    store.loop.holds.pop(R1)  # no hold in place for this router
    delayed = len(disks[KEY].delayed)
    assert not store.release_hold(R1, actor=A.ADMIN, ts=T0 + 20)
    assert not store.get(act.action_id).flags.hold_released
    assert len(disks[KEY].delayed) == delayed
    # the hold is still rebuilt from the record at the next load
    await store.async_flush()
    again, _ = await open_store(clock)
    assert again.loop.holds.get(R1) is not None


# --- point 6: guards without a failing test ------------------------------------------


async def test_r3_maintenance_window_kept_when_only_the_wall_is_far_ahead(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    window = hm.MaintenanceWindow(
        window_id="mtw_" + "8" * 32,
        scope=hm.MaintenanceScope.SERVICE,
        router_id=R1,
        target="dnsmasq",
        start=T0,
        end=T0 + 3600,
        reason="planned",
        created_by=A.ADMIN,
    )
    store.add_maintenance(window)
    clock.now = T0 + 400 * 86400  # the wall clock jumps far ahead
    store.prune()
    assert store.maintenance == [window]


async def test_r3_stale_terminal_stamps_are_dropped_at_load(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    open_one = store.add(new_action()).action
    await store.async_flush()
    stamps = on_disk(disks)["loop"]["terminal_at"]
    stamps["rem_" + "9" * 32] = T0  # no such record
    stamps[open_one.action_id] = T0  # not terminal
    again, _ = await open_store(clock)
    assert again.loop.terminal_at == {}


async def test_r3_unstamped_terminal_record_starts_its_retention_at_prune(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    a = store.add(new_action()).action
    store.apply(a.action_id, S.CANCELLED, actor=A.ADMIN, ts=T0 + 1, reason="x")
    del store.loop.terminal_at[a.action_id]
    advance(store, clock, hs.TERMINAL_RETENTION_S + 3600)
    store.prune()
    assert a.action_id in store.actions
    assert store.loop.terminal_at[a.action_id] == store.now()


async def test_r3_monotonic_reference_is_reset_at_load(
    disks: FakeDisks, clock: Clock
) -> None:
    """Monotonic time only relates observations of the same loaded clock:
    the first observation after a load uses the wall high-water mark."""
    clock.now = T0 + 1000
    first, _ = await open_store(clock)  # the file's clock: high T0 + 1000
    await first.async_flush()
    clock.now = T0  # wall now behind the mark
    store = hs.SelfHealingStore(first.hass, clock=clock, monotonic=clock.mono)
    store.now()  # an observation before the load
    clock.real += 600
    await store.async_load()
    assert store.now() == T0 + 1000  # not +600 from before the load


async def test_r3_monotonic_clock_going_backwards_adds_nothing(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    s0 = store.now()
    clock.real -= 1000
    assert store.now() == s0
    clock.real += 10
    assert store.now() == s0 + 10
