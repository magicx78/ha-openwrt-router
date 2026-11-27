"""Self-Healing, package B (1.53.0): the store of the remediation records.

Order tests (Phase 7 order §22) covered here: 22 (HA restart during an
execution: the record on disk says EXECUTING, the next start makes it
"unknown, needs verification" and never executes it again), 28 (every
action state survives the store) and 32 (action, incident and idempotency
deduplication, also across a restart). Further:

* write before act: the durable transition is on disk (read back) before
  it is reported; a failed, swallowed or skipped write leaves the action
  where it was, and the next write stores the true state;
* a newer-major, unreadable, corrupt or partly damaged file starts empty
  (or without the damaged part), keeps a backup and pauses Auto-Heal;
* limits and eviction never drop a non-terminal action;
* nothing in the file looks like a credential (``core_masking``);
* one test on Home Assistant's real ``Store`` on a temporary disk, where a
  failing disk write is swallowed by HA and caught by the read-back.

``FakeDisks`` of the Time Machine tests stands in for HA's storage.
No router, no network.
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import json
import random
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from core_testkit import SECRET, FakeDisks, make_hass
from homeassistant.core import CoreState
from test_heal_model_v1530 import _filled_loop, assert_no_credentials, at, full_action

from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_store as hs

S = hm.ActionState
A = hm.Actor
R1 = "rtr_" + "1" * 32
R2 = "rtr_" + "2" * 32
T0 = 1_790_000_000.0
KEY = hs.HEAL_STORE_KEY


class Clock:
    """Wall clock the test moves by hand."""

    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def disks() -> Any:
    kit = FakeDisks()

    def read(path: Any) -> Any:
        for disk in kit.disks.values():
            if disk.path == path:
                raw = disk.data
                return copy.deepcopy(raw["data"]) if isinstance(raw, dict) else None
        return None

    with kit.patch(), patch.object(hs, "_read_store_file", read):
        yield kit


@pytest.fixture
def clock() -> Clock:
    return Clock()


async def open_store(
    clock: Clock, hass: Any = None, **kwargs: Any
) -> tuple[hs.SelfHealingStore, hs.LoadResult]:
    store = hs.SelfHealingStore(hass or make_hass(), clock=clock, **kwargs)
    return store, await store.async_load()


def new_action(*, router_id: str = R1, ts: float = T0, **overrides: Any) -> Any:
    args: dict[str, Any] = {
        "router_id": router_id,
        "action_type": "service.restart",
        "params": {"name": "dnsmasq"},
        "ts": ts,
        "incident_id": "inc-7",
        "incident_type": "system_service_restart",
        "components": (hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq"),),
        "playbook_id": "dns_recovery",
        "playbook_version": 1,
    }
    args.update(overrides)
    return hm.RemediationAction.new(**args)


def svc(i: int, **overrides: Any) -> Any:
    """An action on its own service and incident (no dedupe with others)."""
    return new_action(
        params={"name": f"svc{i}"},
        incident_id=f"inc-{i}",
        components=(hm.Component(kind=hm.ComponentKind.SERVICE, name=f"svc{i}"),),
        **overrides,
    )


def on_disk(disks: FakeDisks) -> dict[str, Any]:
    return disks[KEY].data["data"]


def disk_record(disks: FakeDisks, action_id: str) -> dict[str, Any] | None:
    return next(
        (r for r in on_disk(disks)["actions"] if r["action_id"] == action_id), None
    )


def to_approved(store: hs.SelfHealingStore, action_id: str, ts: float = T0) -> None:
    """DETECTED -> ... -> APPROVED on the normal path (engine, Risk 0)."""
    for i, state in enumerate(
        (S.ANALYZED, S.PROPOSED, S.PREFLIGHT, S.APPROVED), start=1
    ):
        store.apply(action_id, state, actor=A.ENGINE, ts=ts + i, reason="step")


async def execute(
    store: hs.SelfHealingStore, action_id: str, ts: float = T0 + 10
) -> hs.DurableResult:
    return await store.async_apply_durable(
        action_id, S.EXECUTING, actor=A.ENGINE, ts=ts, reason="intent_written"
    )


# --- load ------------------------------------------------------------------------------


async def test_first_start_is_on_in_observe_with_nothing_written(
    disks: FakeDisks, clock: Clock
) -> None:
    store, result = await open_store(clock)
    assert result.fresh and not result.failed and not result.paused
    assert result.recovered == [] and result.bad_records == 0
    assert store.settings == hm.HealSettings()
    assert store.settings.enabled is True
    assert store.settings.router(R1) == hm.RouterSettings(
        mode=hm.HealMode.OBSERVE, allowlist=()
    )
    assert disks.options[KEY] == {"private": True, "atomic_writes": True}
    assert disks[KEY].saves == [] and disks[KEY].delayed == []
    assert not store.loop.fleet.paused(T0)


async def test_a_file_without_settings_or_loop_loads_the_defaults(
    disks: FakeDisks, clock: Clock
) -> None:
    disks[KEY].data = {"version": 1, "minor_version": 1, "key": KEY, "data": {}}
    store, result = await open_store(clock)
    assert not result.failed and result.bad_records == 0 and not result.paused
    assert store.settings == hm.HealSettings() and store.actions == {}


async def test_round_trip_keeps_every_field(disks: FakeDisks, clock: Clock) -> None:
    """Order test 28, store part: the record, loop data, settings, windows."""
    store, _ = await open_store(clock)
    full = full_action()
    store.actions[full.action_id] = full
    loop = _filled_loop()
    store.loop = loop
    settings = hm.HealSettings(
        routers={
            R2: hm.RouterSettings(
                mode=hm.HealMode.AUTO_HEAL,
                allowlist=(
                    hm.AllowEntry(
                        action_type="service.restart",
                        params={"name": "dnsmasq"},
                        max_risk=hm.RiskClass.LOW,
                    ),
                ),
            )
        }
    )
    store.set_settings(settings)
    window = hm.MaintenanceWindow(
        window_id="mtw_" + "7" * 32,
        scope=hm.MaintenanceScope.SERVICE,
        router_id=R1,
        target="dnsmasq",
        start=T0,
        end=T0 + 3600,
        reason="planned_update",
        created_by=A.ADMIN,
    )
    store.add_maintenance(window)
    await store.async_flush()

    again, result = await open_store(clock)
    assert not result.failed and result.bad_records == 0 and result.recovered == []
    assert again.actions == {full.action_id: full}
    assert again.settings == settings
    assert again.maintenance == [window]
    assert again.loop.attempts == loop.attempts
    assert again.loop.breakers == loop.breakers
    assert again.loop.fleet == loop.fleet
    assert again.loop.idempotency == loop.idempotency
    assert again.loop.external_writes == loop.external_writes
    # the lock and dedupe ids of _filled_loop name an action that is not in
    # the store: dropped at load, never trusted blindly
    assert again.loop.locks == {} and again.loop.action_dedupe == {}


@pytest.mark.parametrize("state", list(S))
async def test_every_state_survives_the_store(
    disks: FakeDisks, clock: Clock, state: hm.ActionState
) -> None:
    """Order test 28: each of the 17 states is read back; the restart rule
    is the only change, and exactly the one of the model."""
    store, _ = await open_store(clock)
    action = at(state)
    store.actions[action.action_id] = action
    await store.async_flush()
    clock.now = T0 + 50
    again, result = await open_store(clock)
    expected = hm.apply_restart_recovery(action, ts=T0 + 50)
    assert again.get(action.action_id) == expected
    if expected is action:
        assert result.recovered == []
    else:
        assert result.recovered == [(action.action_id, state, expected.state)]
        assert disk_record(disks, action.action_id) == json.loads(
            json.dumps(expected.to_dict())
        )
    assert again.loop.repair_active(R1) is (expected.state in hm.LOCKING_STATES)


async def test_restart_during_execution(disks: FakeDisks, clock: Clock) -> None:
    """Order test 22: HA stops while the router call runs."""
    store, _ = await open_store(clock)
    action_id = store.add(new_action()).action.action_id
    to_approved(store, action_id)
    result = await execute(store, action_id)
    assert result.ok
    assert disk_record(disks, action_id)["state"] == "executing"
    assert store.loop.repair_active(R1)
    # HA is gone here: no flush, no final write
    clock.now = T0 + 100
    again, loaded = await open_store(clock)
    record = again.get(action_id)
    assert record.state is S.VERIFYING and record.flags.interrupted
    assert record.history[-1] == hm.HistoryEntry(
        from_state=S.EXECUTING,
        to_state=S.VERIFYING,
        ts=T0 + 100,
        actor=A.RECOVERY,
        reason="interrupted_by_restart",
    )
    assert loaded.recovered == [(action_id, S.EXECUTING, S.VERIFYING)]
    assert disk_record(disks, action_id)["state"] == "verifying"  # on disk at once
    assert again.loop.repair_active(R1)  # the repair still owns the router
    assert [h.to_state for h in record.history].count(S.EXECUTING) == 1
    with pytest.raises(hm.TransitionError):
        await execute(again, action_id, ts=T0 + 101)
    # a second restart adds nothing
    clock.now = T0 + 200
    third, loaded = await open_store(clock)
    assert loaded.recovered == [] and third.get(action_id) == record


async def test_restart_drops_approvals_and_pending_rollbacks(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    waiting = store.add(svc(1)).action.action_id
    for i, state in enumerate((S.ANALYZED, S.PROPOSED, S.PREFLIGHT), start=1):
        store.apply(waiting, state, actor=A.ENGINE, ts=T0 + i, reason="step")
    store.apply(
        waiting,
        S.WAITING_APPROVAL,
        actor=A.ENGINE,
        ts=T0 + 4,
        reason="needs_approval",
        changes={
            "approval": hm.Approval(
                status=hm.ApprovalStatus.PENDING,
                guard_approval_id="apr_" + "3" * 32,
                binding_hash="b" * 64,
                requested_by=A.ENGINE,
                expires_at=T0 + 900,
            )
        },
    )
    pending = store.add(svc(2)).action.action_id
    to_approved(store, pending)
    assert (await execute(store, pending)).ok
    store.apply(pending, S.FAILED, actor=A.ENGINE, ts=T0 + 11, reason="call_failed")
    store.apply(
        pending, S.ROLLBACK_PENDING, actor=A.ENGINE, ts=T0 + 12, reason="rollback"
    )
    await store.async_flush()
    again, result = await open_store(clock)
    assert again.get(waiting).state is S.CANCELLED
    assert again.get(waiting).approval.status is hm.ApprovalStatus.INVALIDATED
    assert again.get(pending).state is S.MANUAL_RECOVERY_REQUIRED
    assert len(result.recovered) == 2
    assert not again.loop.repair_active(R1)


# --- lost and damaged files ------------------------------------------------------------


def _assert_started_empty_and_paused(
    store: hs.SelfHealingStore, result: hs.LoadResult, reason: str
) -> None:
    assert result.paused
    assert store.loop.fleet.paused(T0)
    assert store.loop.fleet.paused_until == T0 + hm.FLEET_PAUSE_DEFAULT_S
    assert store.loop.fleet.reason == reason
    assert store.settings.router(R1).mode is hm.HealMode.OBSERVE


async def test_a_newer_major_version_starts_empty_with_a_backup(
    disks: FakeDisks, clock: Clock
) -> None:
    disks[KEY].data = {
        "version": 2,
        "minor_version": 1,
        "key": KEY,
        "data": {"actions": [full_action().to_dict()]},
    }
    store, result = await open_store(clock)
    assert result.failed and store.actions == {}
    assert disks[KEY].backups == 1
    _assert_started_empty_and_paused(store, result, hs.REASON_STORE_LOST)
    # the pause itself is on disk, in the current version
    assert disks[KEY].data["version"] == 1
    assert on_disk(disks)["loop"]["fleet"]["reason"] == hs.REASON_STORE_LOST
    assert store.counters["load_failed"] == 1


async def test_a_newer_minor_version_loads(disks: FakeDisks, clock: Clock) -> None:
    full = full_action()
    disks[KEY].data = {
        "version": 1,
        "minor_version": 9,
        "key": KEY,
        "data": {"write_seq": 4, "actions": [full.to_dict()], "future_part": [1]},
    }
    store, result = await open_store(clock)
    assert not result.failed and store.get(full.action_id) == full


@pytest.mark.parametrize("damage", ["load_error", "corrupt", "not_a_dict"])
async def test_an_unreadable_file_starts_empty_and_pauses(
    disks: FakeDisks, clock: Clock, damage: str
) -> None:
    disk = disks[KEY]
    disk.data = {"version": 1, "minor_version": 1, "key": KEY, "data": {}}
    if damage == "load_error":
        disk.load_error = OSError("unreadable")
    elif damage == "corrupt":
        disk.corrupt = True
    else:
        disk.data["data"] = ["not", "a", "store"]
    store, result = await open_store(clock)
    assert result.failed and not result.fresh and store.actions == {}
    _assert_started_empty_and_paused(store, result, hs.REASON_STORE_LOST)


async def test_a_restore_that_raises_starts_empty(
    disks: FakeDisks, clock: Clock
) -> None:
    disks[KEY].data = {"version": 1, "minor_version": 1, "key": KEY, "data": {}}
    with patch.object(hs.LoopState, "from_dict", side_effect=RuntimeError("bug")):
        store, result = await open_store(clock)
    assert result.failed and disks[KEY].backups == 1
    _assert_started_empty_and_paused(store, result, hs.REASON_STORE_LOST)


async def test_damaged_parts_are_skipped_the_rest_loads(
    disks: FakeDisks, clock: Clock
) -> None:
    good = full_action()
    disks[KEY].data = {
        "version": 1,
        "minor_version": 1,
        "key": KEY,
        "data": {
            "settings": {"enabled": "yes"},
            "actions": [
                good.to_dict(),
                {"action_id": "rem_" + "9" * 32, "state": "nonsense"},
                good.to_dict(),  # the same id twice
            ],
            "maintenance": "not a list",
        },
    }
    store, result = await open_store(clock)
    assert not result.failed and result.bad_records == 4
    assert store.actions == {good.action_id: good}
    assert store.settings == hm.HealSettings()  # damaged settings: Observe
    assert disks[KEY].backups == 1
    _assert_started_empty_and_paused(store, result, hs.REASON_STORE_DAMAGED)
    # the cleaned state is written at once
    assert [r["action_id"] for r in on_disk(disks)["actions"]] == [good.action_id]


# --- deduplication (order test 32) ----------------------------------------------------


async def test_action_and_incident_dedupe(disks: FakeDisks, clock: Clock) -> None:
    store, _ = await open_store(clock)
    first = store.add(new_action())
    assert first.created and first.dedupe is None
    same = store.add(new_action(ts=T0 + 1))
    assert (same.created, same.action, same.dedupe) == (False, first.action, "action")
    # other params, same root incident on the same component
    incident = store.add(new_action(ts=T0 + 2, params={"name": "dnsmasq", "x": 1}))
    assert (incident.created, incident.action, incident.dedupe) == (
        False,
        first.action,
        "incident",
    )
    assert store.add(new_action(router_id=R2)).created  # another router
    assert len(store.actions) == 2
    # a terminal action no longer blocks a new one
    store.apply(
        first.action.action_id,
        S.CANCELLED,
        actor=A.ADMIN,
        ts=T0 + 3,
        reason="admin_cancelled",
    )
    later = store.add(new_action(ts=T0 + 4))
    assert later.created
    # the dedupe survives a restart
    await store.async_flush()
    again, _ = await open_store(clock)
    dup = again.add(new_action(ts=T0 + 5))
    assert (dup.created, dup.action.action_id) == (False, later.action.action_id)


async def test_idempotency_returns_the_first_action_even_when_finished(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    idem = hm.idempotency_id("request-0001")
    first = store.add(svc(1, idempotency_id=idem)).action
    store.apply(
        first.action_id, S.CANCELLED, actor=A.ADMIN, ts=T0 + 1, reason="cancelled"
    )
    repeat = store.add(svc(2, idempotency_id=idem, ts=T0 + 2))
    assert (repeat.created, repeat.action.action_id, repeat.dedupe) == (
        False,
        first.action_id,
        "idempotency",
    )
    # after the TTL the id is free again
    assert store.prune(T0 + hs.IDEMPOTENCY_TTL_S + 10) >= 1
    assert store.add(svc(2, idempotency_id=idem, ts=T0 + 2)).created


async def test_add_refuses_a_record_that_is_not_new(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    with pytest.raises(hs.HealStoreError):
        store.add(at(S.APPROVED))
    action = store.add(new_action()).action
    with pytest.raises(hs.HealStoreError):
        store.add(action)


# --- limits and eviction ---------------------------------------------------------------


async def test_open_actions_per_router_are_capped(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    for i in range(hs.MAX_OPEN_PER_ROUTER):
        assert store.add(svc(i)).created
    with pytest.raises(hs.CapacityError):
        store.add(svc(99))
    assert len(store.actions) == hs.MAX_OPEN_PER_ROUTER
    assert store.add(svc(99, router_id=R2)).created


async def test_the_total_cap_evicts_the_oldest_terminal_never_an_open_one(
    disks: FakeDisks, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hs, "MAX_ACTIONS", 5)
    store, _ = await open_store(clock)
    finished = []
    for i in range(3):
        action = store.add(svc(i, ts=T0 + i)).action
        store.apply(
            action.action_id, S.CANCELLED, actor=A.ADMIN, ts=T0 + 10 - i, reason="c"
        )
        finished.append(action.action_id)
    opened = [store.add(svc(10 + i)).action.action_id for i in range(2)]
    store.add(svc(20))  # 6th: the terminal one finished first goes (ts T0 + 8)
    assert finished[2] not in store.actions
    assert set(opened) <= set(store.actions) and len(store.actions) == 5
    store.add(svc(21))
    store.add(svc(22))
    assert not set(finished) & set(store.actions)
    with pytest.raises(hs.CapacityError):
        store.add(svc(23))
    assert len(store.actions) == 5
    assert all(not a.is_terminal for a in store.actions.values())
    assert store.counters["evicted_terminal"] == 3


async def test_the_size_limit_evicts_terminal_records_oldest_first(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    finished = []
    for i in range(3):
        action = store.add(svc(i)).action
        store.apply(
            action.action_id, S.CANCELLED, actor=A.ADMIN, ts=T0 + 1 + i, reason="c"
        )
        finished.append(action.action_id)
    open_id = store.add(svc(9)).action.action_id
    keep = {k: v for k, v in store.actions.items() if k != finished[0]}
    store.max_bytes = hs.store_bytes(store._payload_of(keep, store.loop, 99)) + 20
    payload = store.payload()
    assert {a["action_id"] for a in payload["actions"]} == {
        finished[1],
        finished[2],
        open_id,
    }
    assert hs.store_bytes(payload) <= store.max_bytes
    assert store.last_bytes == hs.store_bytes(payload)
    assert finished[0] not in store.actions
    assert store.counters["evicted_terminal"] == 1


async def test_open_actions_are_written_even_over_the_size_limit(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock, max_bytes=300)
    ids = {store.add(svc(i)).action.action_id for i in range(3)}
    await store.async_flush()
    assert {r["action_id"] for r in on_disk(disks)["actions"]} == ids
    assert store.counters["save_over_size"] == 1
    # a durable step over the limit is refused: the action does not advance
    action_id = min(ids)
    to_approved(store, action_id)
    result = await execute(store, action_id)
    assert (result.ok, result.reason) == (False, "over_size")
    assert store.get(action_id).state is S.APPROVED
    assert not store.loop.repair_active(R1)


async def test_prune_keeps_open_actions_and_open_breakers(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    old_open = store.add(svc(1)).action.action_id
    old_done = store.add(svc(2)).action.action_id
    store.apply(old_done, S.CANCELLED, actor=A.ADMIN, ts=T0 + 1, reason="c")
    store.loop.attempts[(R1, "service.restart", "inc-1")] = hm.AttemptRecord(
        count=1, window_start=T0, last_at=T0
    )
    store.loop.breakers[(R1, "service.restart", "svc1")] = hm.BreakerRecord(
        state=hm.BreakerState.OPEN, opened_at=T0, reason="loop", failures=2
    )
    store.loop.breakers[(R1, "service.restart", "svc2")] = hm.BreakerRecord(
        state=hm.BreakerState.CLOSED, opened_at=T0, acknowledged_at=T0
    )
    store.add_maintenance(
        hm.MaintenanceWindow(
            window_id="mtw_" + "7" * 32,
            scope=hm.MaintenanceScope.INTERFACE,
            router_id=R1,
            target="wan",
            start=T0,
            end=T0 + 60,
            reason="planned",
            created_by=A.ADMIN,
        )
    )
    later = T0 + hs.TERMINAL_RETENTION_S + 100
    assert store.prune(later) == 4
    assert set(store.actions) == {old_open}
    assert list(store.loop.breakers) == [(R1, "service.restart", "svc1")]
    assert store.loop.attempts == {} and store.maintenance == []
    assert store.prune(later) == 0


# --- write before act ------------------------------------------------------------------


async def test_durable_step_is_on_disk_before_it_is_reported(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    action_id = store.add(new_action()).action.action_id
    to_approved(store, action_id)
    saves = len(disks[KEY].saves)
    result = await execute(store, action_id, ts=T0 + 10)
    assert result.ok and result.reason is None
    assert result.action is store.get(action_id)
    assert result.action.state is S.EXECUTING
    assert result.action.execution.intent_written_at == T0 + 10
    assert len(disks[KEY].saves) == saves + 1
    assert disk_record(disks, action_id) == json.loads(
        json.dumps(result.action.to_dict())
    )
    assert store.loop.repair_active(R1)
    assert store.counters["durable_writes"] == 1


async def test_the_normal_path_refuses_durable_steps(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    action_id = store.add(new_action()).action.action_id
    to_approved(store, action_id)
    with pytest.raises(hs.WriteAheadRequiredError):
        store.apply(action_id, S.EXECUTING, actor=A.ENGINE, ts=T0 + 9, reason="x")
    assert store.get(action_id).state is S.APPROVED
    assert (await execute(store, action_id)).ok
    store.apply(action_id, S.FAILED, actor=A.ENGINE, ts=T0 + 11, reason="call_failed")
    store.apply(
        action_id, S.ROLLBACK_PENDING, actor=A.ENGINE, ts=T0 + 12, reason="rollback"
    )
    with pytest.raises(hs.WriteAheadRequiredError):
        store.apply(
            action_id, S.ROLLING_BACK, actor=A.ENGINE, ts=T0 + 13, reason="rollback"
        )
    # illegal moves are typed errors on both paths, nothing written
    with pytest.raises(hm.IllegalTransitionError):
        store.apply(action_id, S.RESOLVED, actor=A.ENGINE, ts=T0 + 14, reason="x")
    with pytest.raises(hm.IllegalTransitionError):
        await execute(store, action_id, ts=T0 + 14)
    with pytest.raises(hs.UnknownActionError):
        store.apply("rem_" + "0" * 32, S.CANCELLED, actor=A.ADMIN, ts=T0, reason="x")
    assert store.get(action_id).state is S.ROLLBACK_PENDING


@pytest.mark.parametrize("failure", ["raises", "swallowed", "read_back"])
async def test_a_failed_durable_write_leaves_the_action_where_it_was(
    disks: FakeDisks, clock: Clock, failure: str
) -> None:
    store, _ = await open_store(clock)
    action_id = store.add(new_action()).action.action_id
    to_approved(store, action_id)
    if failure == "raises":
        store._store.async_save = AsyncMock(side_effect=OSError("disk full"))
        expected = "write_failed"
    elif failure == "swallowed":  # what HA's Store does with a WriteError
        store._store.async_save = AsyncMock(return_value=None)
        expected = "not_durable"
    else:
        expected = "not_durable"
    with (
        patch.object(hs, "_read_store_file", side_effect=OSError("gone"))
        if (failure == "read_back")
        else patch.object(hs, "_LOGGER")
    ):
        result = await execute(store, action_id)
    assert (result.ok, result.reason) == (False, expected)
    assert result.action is store.get(action_id)
    assert store.get(action_id).state is S.APPROVED
    assert not store.loop.repair_active(R1)
    assert store.counters["durable_failed"] == 1
    # the next write is the state really in force, at once
    assert disks[KEY].delayed[-1][1] == 0
    if failure != "read_back":
        del store._store.async_save  # the disk works again
    disks.flush_delayed()
    assert disk_record(disks, action_id)["state"] == "approved"


async def test_no_durable_step_while_home_assistant_stops(
    disks: FakeDisks, clock: Clock
) -> None:
    hass = make_hass()
    store, _ = await open_store(clock, hass)
    action_id = store.add(new_action()).action.action_id
    to_approved(store, action_id)
    saves = len(disks[KEY].saves)
    for state in (CoreState.stopping, CoreState.final_write, CoreState.stopped):
        hass.state = state
        result = await execute(store, action_id)
        assert (result.ok, result.reason) == (False, "stopping")
    assert len(disks[KEY].saves) == saves
    assert store.get(action_id).state is S.APPROVED


async def test_no_durable_step_before_the_load(disks: FakeDisks, clock: Clock) -> None:
    store = hs.SelfHealingStore(make_hass(), clock=clock)
    action = at(S.APPROVED)
    store.actions[action.action_id] = action
    result = await execute(store, action.action_id)
    assert (result.ok, result.reason) == (False, "not_loaded")


async def test_a_durable_write_in_flight_blocks_the_action_and_the_router(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    action_id = store.add(new_action()).action.action_id
    to_approved(store, action_id)
    gate = asyncio.Event()
    real_save = store._store.async_save

    async def slow_save(data: Any) -> None:
        await gate.wait()
        await real_save(data)

    store._store.async_save = slow_save
    task = asyncio.create_task(execute(store, action_id))
    for _ in range(5):
        await asyncio.sleep(0)
    with pytest.raises(hs.BusyError):
        store.apply(action_id, S.CANCELLED, actor=A.ADMIN, ts=T0 + 11, reason="x")
    assert not store.try_external_lock(R1, "button.reboot", T0 + 11)
    gate.set()
    result = await task
    assert result.ok and store.loop.repair_active(R1)


async def test_the_real_store_catches_a_write_home_assistant_swallows(
    tmp_path: Any,
) -> None:
    """HA's own Store logs a WriteError and returns; the read-back sees it."""
    from homeassistant.core import HomeAssistant
    from homeassistant.util.file import WriteError

    def broken_disk(*args: Any, **kwargs: Any) -> None:
        raise WriteError("disk full")

    hass = HomeAssistant(str(tmp_path))
    try:
        store = hs.SelfHealingStore(hass, clock=Clock())
        await store.async_load()
        action_id = store.add(new_action()).action.action_id
        to_approved(store, action_id)
        with patch("homeassistant.helpers.storage.write_utf8_file_atomic", broken_disk):
            result = await execute(store, action_id)
        assert (result.ok, result.reason) == (False, "not_durable")
        assert store.get(action_id).state is S.APPROVED
        result = await execute(store, action_id, ts=T0 + 20)
        assert result.ok
        path = tmp_path / ".storage" / KEY
        data = json.loads(path.read_text())["data"]
        record = next(r for r in data["actions"] if r["action_id"] == action_id)
        assert record["state"] == "executing"
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        assert store.last_bytes == hs.store_bytes(data)
        assert_no_credentials(data)
    finally:
        await hass.async_stop(force=True)


# --- no action executes twice (property, with restarts) -------------------------------


@pytest.mark.parametrize("seed", range(40))
async def test_random_runs_with_restarts_never_execute_twice(
    disks: FakeDisks, clock: Clock, seed: int
) -> None:
    rng = random.Random(seed)
    store, _ = await open_store(clock)
    ids = [
        store.add(svc(i, router_id=rng.choice((R1, R2)))).action.action_id
        for i in range(4)
    ]
    executed: dict[str, int] = dict.fromkeys(ids, 0)
    for step in range(60):
        clock.now = T0 + step + 1
        if rng.random() < 0.1:  # HA restarts, maybe after the delayed write
            if rng.random() < 0.5:
                disks.flush_delayed()
            store, _ = await open_store(clock)
            continue
        action_id = rng.choice(ids)
        action = store.get(action_id)
        if action is None:  # added after the last write, lost by a restart
            continue
        actor = rng.choice(list(A))
        targets = sorted(hm.allowed_targets(action.state, actor))
        if not targets:
            continue
        target = rng.choice(targets)
        if not hm.TRANSITIONS[(action.state, target)].durable:
            try:
                store.apply(action_id, target, actor=actor, ts=clock.now, reason="walk")
            except (hm.TransitionError, hs.RouterLockedError):
                pass
            continue
        result = await store.async_apply_durable(
            action_id, target, actor=actor, ts=clock.now, reason="walk"
        )
        if result.ok and target is S.EXECUTING:
            executed[action_id] += 1
    assert all(count <= 1 for count in executed.values()), executed
    for action in store.actions.values():
        assert [h.to_state for h in action.history].count(S.EXECUTING) <= 1
    # one repair per router at a time
    holders = [a for a in store.actions.values() if a.state in hm.LOCKING_STATES]
    assert len({a.router_id for a in holders}) == len(holders)


# --- locks and writes from outside the engine ------------------------------------------


async def test_external_writes_and_the_router_lock(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    action_id = store.add(new_action()).action.action_id
    to_approved(store, action_id)
    assert store.try_external_lock(R1, "button.reboot", T0 + 5)
    assert store.try_external_lock(R1, "button.reboot", T0 + 5)  # same holder
    assert not store.try_external_lock(R1, "switch.service", T0 + 5)
    result = await execute(store, action_id)
    assert (result.ok, result.reason) == (False, "router_locked")
    assert not store.release_external_lock(R1, "switch.service")
    store.record_external_write(
        hm.ExternalWrite(
            router_id=R1, source="button.reboot", target="system", ts=T0 + 6
        )
    )
    assert store.release_external_lock(R1, "button.reboot")
    assert (await execute(store, action_id)).ok
    assert store.loop.repair_active(R1)
    assert not store.try_external_lock(R1, "button.reboot", T0 + 12)
    assert store.try_external_lock(R2, "button.reboot", T0 + 12)
    await store.async_flush()
    again, _ = await open_store(clock)
    # the external lock on R2 cannot outlive HA; the repair's lock on R1 can
    assert again.loop.lock_holder(R2) is None
    assert again.loop.repair_active(R1)
    assert [w.source for w in again.loop.external_writes] == ["button.reboot"]


async def test_a_second_action_cannot_take_a_locked_router(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    first = store.add(svc(1)).action.action_id
    second = store.add(svc(2)).action.action_id
    to_approved(store, first)
    to_approved(store, second)
    assert (await execute(store, first)).ok
    result = await execute(store, second, ts=T0 + 11)
    assert (result.ok, result.reason) == (False, "router_locked")
    store.apply(first, S.VERIFYING, actor=A.ENGINE, ts=T0 + 12, reason="call_ok")
    store.apply(first, S.RESOLVED, actor=A.ENGINE, ts=T0 + 13, reason="resolved")
    assert not store.loop.repair_active(R1)
    assert (await execute(store, second, ts=T0 + 14)).ok


# --- settings, maintenance, writes, credentials ---------------------------------------


async def test_settings_and_maintenance_windows(
    disks: FakeDisks, clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = await open_store(clock)
    with pytest.raises(hs.HealStoreError):
        store.set_settings({"enabled": False})  # type: ignore[arg-type]
    store.set_settings(hm.HealSettings(enabled=False))
    monkeypatch.setattr(hs, "MAINTENANCE_MAX", 2)

    def window(i: int) -> hm.MaintenanceWindow:
        return hm.MaintenanceWindow(
            window_id="mtw_" + str(i) * 32,
            scope=hm.MaintenanceScope.SERVICE,
            router_id=R1,
            target="dnsmasq",
            start=T0,
            end=None,
            reason="planned",
            created_by=A.ADMIN,
        )

    store.add_maintenance(window(1))
    with pytest.raises(hs.HealStoreError):
        store.add_maintenance(window(1))
    store.add_maintenance(window(2))
    with pytest.raises(hs.CapacityError):
        store.add_maintenance(window(3))
    assert store.remove_maintenance("mtw_" + "1" * 32)
    assert not store.remove_maintenance("mtw_" + "1" * 32)
    await store.async_flush()
    again, _ = await open_store(clock)
    assert again.settings.enabled is False
    assert [w.window_id for w in again.maintenance] == ["mtw_" + "2" * 32]


async def test_one_delayed_write_is_armed_at_a_time(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    action_id = store.add(new_action()).action.action_id
    store.apply(action_id, S.ANALYZED, actor=A.ENGINE, ts=T0 + 1, reason="x")
    store.update(action_id, playbook_version=2)
    assert len(disks[KEY].delayed) == 1
    assert disks[KEY].delayed[0][1] == hs.SAVE_DELAY_S
    disks.flush_delayed()
    assert disk_record(disks, action_id)["playbook_version"] == 2
    store.apply(action_id, S.PROPOSED, actor=A.ENGINE, ts=T0 + 2, reason="x")
    assert len(disks[KEY].delayed) == 1  # armed again after the write
    with pytest.raises(hm.HealModelError):
        store.update(action_id, state=S.RESOLVED)
    await store.async_close()
    store.apply(action_id, S.CANCELLED, actor=A.ADMIN, ts=T0 + 3, reason="x")
    disks[KEY].delayed.clear()
    store.schedule()
    assert disks[KEY].delayed == []  # nothing is armed after close


async def test_nothing_in_the_file_looks_like_a_credential(
    disks: FakeDisks, clock: Clock
) -> None:
    store, _ = await open_store(clock)
    full = full_action()
    store.actions[full.action_id] = full
    store.loop = _filled_loop()
    # R1's lock belongs to the action of _filled_loop: this one runs on R2
    action = store.add(
        svc(1, router_id=R2, idempotency_id=hm.idempotency_id(SECRET))
    ).action
    to_approved(store, action.action_id)
    assert (await execute(store, action.action_id)).ok
    store.record_external_write(
        hm.ExternalWrite(
            router_id=R2, source="switch.service", target="dnsmasq", ts=T0 + 3
        )
    )
    await store.async_flush()
    data = on_disk(disks)
    assert_no_credentials(data)
    text = json.dumps(disks[KEY].data)
    assert SECRET not in text
    for word in ("password", "token", "entry_id", "host", "psk"):
        assert f'"{word}"' not in text
    # a credential-shaped value never reaches the store
    with pytest.raises(hm.HealModelError):
        new_action(params={"name": "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0"})
    stats = json.dumps(store.stats())
    assert "rem_" not in stats and "rtr_" not in stats


async def test_records_of_the_store_are_frozen(disks: FakeDisks, clock: Clock) -> None:
    store, _ = await open_store(clock)
    action = store.add(new_action()).action
    with pytest.raises(dataclasses.FrozenInstanceError):
        action.state = S.EXECUTING  # type: ignore[misc]
