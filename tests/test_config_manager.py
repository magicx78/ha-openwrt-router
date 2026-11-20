"""Configuration manager runtime (plan 2026-11-18, sections 1 and 3-5).

Mocks only: the enterprise core runs on FakeDisks, the provider is the
in-memory FakeConfigProvider, the routers are FakeCoordinators whose api
objects must never be called. No Home Assistant instance, no router.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pytest
from config_manager_kit import (
    ON,
    attach_entry,
    cm_env,
    drain,
    factory_of,
    macs,
    restart,
    stop,
    unload_entry,
)
from core_test_provider import (
    FakeConfigProvider,
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import (
    ADMIN_ID,
    FakeDisks,
    bus_events,
    make_hass,
    router_data,
    user_actor,
)
from homeassistant.util import dt as dt_util

from custom_components.openwrt_router import config_manager as cm
from custom_components.openwrt_router import core_audit
from custom_components.openwrt_router.const import (
    CONFIG_BACKUP_SCHEDULE_OFF,
    CONFIG_STATUS_DISABLED,
    CONFIG_STATUS_FAILED,
    CONFIG_STATUS_NEVER,
    CONFIG_STATUS_OK,
    DATA_CONFIG_MANAGER,
    OPTION_CONFIG_BACKUP_SCHEDULE,
    OPTION_CONFIG_DRIFT_CHECK,
)
from custom_components.openwrt_router.core_errors import (
    OperationInProgressError,
    RouterUnavailableError,
)
from custom_components.openwrt_router.core_models import (
    BackupReason,
    BackupType,
    Capability,
    CapabilityState,
)

ADMIN = user_actor(ADMIN_ID)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


# ---------------------------------------------------------------------------
# Runtime: registration and reference counting (section 1)
# ---------------------------------------------------------------------------


async def test_first_entry_registers_the_provider_once(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2)
    runtime = env.runtime
    assert len(env.factory_calls) == 1
    assert env.api.provider_id == "test_provider"
    assert runtime.provider_registered and not runtime.provider_conflict
    assert set(runtime.entries) == {"e1", "e2"}
    assert set(runtime.routers) == set(env.rids)
    assert env.hass.data[DATA_CONFIG_MANAGER] is runtime
    await stop(env)


async def test_registration_leaves_no_unstarted_probe_task(
    disks, tmp_path, monkeypatch
):
    """Option off: the core's probe tasks finish during setup, no router call.

    An unstarted task cancelled by an early unload would surface as a
    CancelledError in every lifecycle test that awaits the core's tasks.
    ``async_attach`` is stubbed so it never yields: only the setup hook
    itself may hand the loop to the probe tasks.
    """
    env = await cm_env(disks, tmp_path, routers=2, options={}, attach=False)

    async def _attach_without_yield(self, entry, coordinator):
        self.entries[entry.entry_id] = entry
        self.coordinators[entry.entry_id] = coordinator

    monkeypatch.setattr(cm.ConfigManagerRuntime, "async_attach", _attach_without_yield)
    manager = env.core.manager
    skipped = manager.stats["probes_skipped"]
    entry = env.entries[0]
    # Called directly (attach_entry drains the loop afterwards).
    with patch.object(cm, "async_track_time_interval", env.timers, create=True):
        await cm.async_setup_config_manager(
            env.hass, entry, env.coords[env.rids[0]], provider_factory=factory_of(env)
        )
    # Both routers' probes ran (and skipped: option off) before setup returned.
    assert manager.stats["probes_skipped"] == skipped + 2
    assert not any(not task.done() for task in manager._probe_tasks.values())
    assert env.provider.calls == []
    await unload_entry(env, env.entries[0])
    assert env.provider.calls == []


async def test_first_entry_unload_keeps_provider(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2)
    runtime = env.runtime
    await unload_entry(env, env.entries[0])
    assert cm.async_get_runtime(env.hass) is runtime
    assert env.api.provider_id == "test_provider"
    assert set(runtime.routers) == {env.rids[1]}
    assert set(runtime.entries) == {"e2"}
    await unload_entry(env, env.entries[1])


async def test_last_entry_unload_unregisters_provider(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2)
    runtime = env.runtime
    api = env.api
    await unload_entry(env, env.entries[0])
    await unload_entry(env, env.entries[1])
    assert runtime.closed
    assert runtime.provider is None and runtime._unsubscribe is None
    assert DATA_CONFIG_MANAGER not in env.hass.data
    assert cm.async_get_runtime(env.hass) is None
    assert api.provider_id is None


async def test_release_is_idempotent_and_runs_from_on_unload(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    runtime = env.runtime
    entry = env.entries[0]
    assert len(entry.on_unload) >= 1
    cm.async_release_config_manager(env.hass, entry.entry_id)
    assert runtime.closed
    # HA runs the on_unload callbacks afterwards: a second release is a no-op
    runtime.release(entry.entry_id)
    await unload_entry(env, entry)
    assert env.api.provider_id is None


async def test_foreign_provider_stays_passive(disks, tmp_path):
    env = await cm_env(disks, tmp_path, attach=False)
    foreign = FakeConfigProvider("foreign_engine")
    unregister = env.api.register_provider(foreign)
    await drain(env.hass)
    await attach_entry(env, env.entries[0])
    runtime = env.runtime
    assert env.factory_calls == []  # never built, never registered
    assert runtime.provider_conflict and not runtime.provider_registered
    runtime.close()  # our last release must not empty the foreign slot
    assert env.api.provider_id == "foreign_engine"
    unregister()
    await stop(env)


async def test_conflict_on_register_stays_passive(disks, tmp_path):
    env = await cm_env(disks, tmp_path, attach=False)
    foreign = FakeConfigProvider("foreign_engine")

    def racing_factory(hass):
        env.api.register_provider(foreign)  # someone else is faster
        return env.provider

    runtime = await cm.async_setup_config_manager(
        env.hass, env.entries[0], env.coords[env.rid], provider_factory=racing_factory
    )
    assert runtime.provider_conflict
    assert env.api.provider_id == "foreign_engine"
    runtime.close()  # our last release must not empty the foreign slot
    assert env.api.provider_id == "foreign_engine"
    await stop(env)


async def test_setup_without_core_returns_none():
    hass = make_hass()
    entry = type("E", (), {"entry_id": "x", "async_on_unload": lambda s, f: None})()
    assert await cm.async_setup_config_manager(hass, entry, None) is None
    assert DATA_CONFIG_MANAGER not in hass.data


async def test_new_core_replaces_the_stale_runtime(disks, tmp_path):
    env = await cm_env(disks, tmp_path, attach=False)
    stale = cm.ConfigManagerRuntime(env.hass, object(), env.api)
    env.hass.data[DATA_CONFIG_MANAGER] = stale
    await attach_entry(env, env.entries[0])
    assert stale.closed
    assert env.runtime is not stale and env.runtime.core is env.core
    assert env.api.provider_id == "test_provider"
    await stop(env)


async def test_restart_registers_again(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    old = env.runtime
    env = await restart(env)
    assert old.closed and env.runtime is not old
    assert env.api.provider_id == "test_provider"
    assert len(env.factory_calls) == 2  # one registration per core
    await stop(env)


# ---------------------------------------------------------------------------
# Memory rebuilt from the store (section 3)
# ---------------------------------------------------------------------------


async def test_memory_rebuilt_from_the_store(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    made = await env.api.async_create_backup(
        env.rid, reason=BackupReason.MANUAL, actor=ADMIN
    )
    env = await restart(env)
    state = env.runtime.routers[env.rid]
    assert state.version_count == 1
    assert state.last_backup_at == made.record.created_at
    assert state.newest_ok_release == "24.10.2"
    assert env.runtime.status(env.rid) == CONFIG_STATUS_OK
    assert env.router_calls() == []
    await stop(env)


async def test_failure_after_the_last_version_survives_a_restart(disks, tmp_path):
    """H1: a failed attempt newer than the newest version stays "failed"."""
    env = await cm_env(disks, tmp_path)
    with patch.object(core_audit, "utcnow", env.clock.utc):  # audit on test time
        await _failure_then_restart(env)


async def _failure_then_restart(env: Any) -> None:
    await env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN)
    env.clock.advance(hours=1)
    env.provider.fail["collect"] = RouterUnavailableError("offline")
    with pytest.raises(RouterUnavailableError):
        await env.api.async_create_backup(
            env.rid, reason=BackupReason.MANUAL, actor=ADMIN
        )
    env.clock.advance(minutes=5)
    with pytest.raises(RouterUnavailableError):  # deduplicated repeat
        await env.api.async_create_backup(
            env.rid, reason=BackupReason.MANUAL, actor=ADMIN
        )
    del env.provider.fail["collect"]
    assert env.runtime.status(env.rid) == CONFIG_STATUS_FAILED
    env = await restart(env)
    state = env.runtime.routers[env.rid]
    assert env.runtime.status(env.rid) == CONFIG_STATUS_FAILED
    assert env.runtime.error_class(env.rid) == "unreachable"
    assert state.last_failure_at == env.clock.utc()
    assert state.last_attempt_at == env.clock.utc()
    # a newer version ends the failed state again
    env.clock.advance(minutes=5)
    await env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN)
    await drain(env.hass)
    assert env.runtime.status(env.rid) == CONFIG_STATUS_OK
    env = await restart(env)
    assert env.runtime.status(env.rid) == CONFIG_STATUS_OK
    await stop(env)


async def test_status_never_and_disabled(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    assert env.runtime.status(env.rid) == CONFIG_STATUS_NEVER
    await stop(env)
    env = await cm_env(disks, tmp_path, options={})
    assert env.runtime.status(env.rid) == CONFIG_STATUS_DISABLED
    assert env.provider.calls == []  # option off: not even probed
    await stop(env)


async def test_bus_event_refreshes_the_state(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    runtime = env.runtime
    before = runtime.stats["refreshes"]
    await env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN)
    await drain(env.hass)
    assert runtime.stats["refreshes"] > before
    assert runtime.routers[env.rid].version_count == 1
    await stop(env)


# ---------------------------------------------------------------------------
# Schedule, worker and drift trigger (section 3)
# ---------------------------------------------------------------------------

NO_SCHEDULE = {**ON, OPTION_CONFIG_BACKUP_SCHEDULE: CONFIG_BACKUP_SCHEDULE_OFF}


async def _records(env, router_id=None):
    return list(await env.api.async_list_backups(router_id or env.rid, limit=50))


def _collected(env):
    return [rid for _op, rid in env.provider.ops("collect")]


async def _wait_entered(env, op="collect"):
    event = env.provider.entered.setdefault(op, asyncio.Event())
    await asyncio.wait_for(event.wait(), 5)


def _release_hook(version):
    def hook(collected):
        return replace(collected, meta=replace(collected.meta, openwrt_version=version))

    return hook


async def _drifted_poll(env, index):
    """Change the live configuration and let one poll show a new fingerprint."""
    env.provider.live(env.rid)["network"]["lan"]["ipaddr"] = f"10.0.{index}.1"
    env.coords[env.rid].poll(
        data=router_data(
            hostname="r1",
            macs=macs(0),
            wan={"wan_found": True, "interface": "wan", "proto": f"proto{index}"},
        )
    )


async def test_option_off_starts_no_timer(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options={})
    assert env.timers.active == []
    await env.tick()  # even a forced tick plans nothing
    assert env.provider.calls == [] and env.router_calls() == []
    await stop(env)


async def test_option_on_starts_one_tick_timer(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=3)
    assert [interval for _a, interval in env.timers.active] == [timedelta(minutes=5)]
    await stop(env)
    assert env.timers.active == []


async def test_scheduled_run_once_per_day(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    await env.tick()
    assert _collected(env) == [env.rid]
    for _ in range(5):  # the rest of the day: nothing more
        env.clock.advance(minutes=5)
        await env.tick()
    assert _collected(env) == [env.rid]
    env.clock.advance(days=1)
    await env.tick()
    assert _collected(env) == [env.rid, env.rid]
    assert [r.reason for r in await _records(env)] == [BackupReason.SCHEDULED]
    assert env.router_calls() == []
    await stop(env)


async def test_identical_scheduled_run_is_deduplicated(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    await env.tick()
    first = (await _records(env))[0]
    created = bus_events(env.hass, "configuration.backup_created")
    env.clock.advance(days=1)
    await env.tick()
    records = await _records(env)
    assert len(_collected(env)) == 2  # the router was read again ...
    assert len(records) == 1  # ... but the content was the same
    assert records[0].backup_id == first.backup_id
    assert first.last_seen_at is None
    assert records[0].last_seen_at > first.created_at
    assert env.runtime.routers[env.rid].version_count == 1
    assert bus_events(env.hass, "configuration.backup_created") == created
    # the moved last_seen_at marks the day as done (also after a restart)
    env = await restart(env)
    await env.tick()
    assert len(_collected(env)) == 2
    await stop(env)


async def test_retryable_failure_retried_once_after_900s(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    env.provider.fail["collect"] = RouterUnavailableError("offline")
    await env.tick()
    assert len(_collected(env)) == 1
    env.clock.advance(seconds=600)
    await env.tick()
    assert len(_collected(env)) == 1  # retry not due yet
    env.clock.advance(seconds=301)
    await env.tick()
    assert len(_collected(env)) == 2  # the one retry
    env.clock.advance(hours=2)
    await env.tick()
    assert len(_collected(env)) == 2  # no third attempt that day
    del env.provider.fail["collect"]
    env.clock.advance(days=1)
    await env.tick()
    assert len(_collected(env)) == 3
    assert len(await _records(env)) == 1
    await stop(env)


@pytest.mark.parametrize(
    ("reason", "error_class"),
    [("permission_denied", "permission"), ("not_detected", "not_available")],
)
async def test_missing_backup_right_is_a_problem_not_ok(
    disks, tmp_path, caplog, reason, error_class
):
    """H2: a scheduled run without the backup right shows failed, once a day."""
    provider = FakeConfigProvider()
    provider.probe_states[Capability.CONFIG_BACKUP] = (
        CapabilityState.UNAVAILABLE,
        reason,
    )
    env = await cm_env(disks, tmp_path, provider=provider)
    with patch.object(core_audit, "utcnow", env.clock.utc):
        await env.tick()
        assert _collected(env) == []
        assert env.runtime.status(env.rid) == CONFIG_STATUS_FAILED
        assert env.runtime.error_class(env.rid) == error_class
        state = env.runtime.routers[env.rid]
        assert state.last_attempt_at == env.clock.local()
        assert state.last_scheduled_day == env.runtime._today_slot(env.rid)
        blocked = bus_events(env.hass, "config_manager.backup_blocked")
        assert len(blocked) == 1
        assert blocked[0]["data"]["error_class"] == error_class
        logged = [r for r in caplog.records if "backup right" in r.getMessage()]
        assert len(logged) == 1
        env.clock.advance(hours=2)
        await env.tick()  # same day: no second log, no second event
        assert len(bus_events(env.hass, "config_manager.backup_blocked")) == 1
        assert len([r for r in caplog.records if "backup right" in r.getMessage()]) == 1
        env = await restart(env)
        assert env.runtime.status(env.rid) == CONFIG_STATUS_FAILED
        assert env.runtime.error_class(env.rid) == error_class
        assert env.router_calls() == []
    await stop(env)


async def test_release_change_backup_once_per_version(disks, tmp_path):
    options = {**NO_SCHEDULE, OPTION_CONFIG_DRIFT_CHECK: False}
    env = await cm_env(disks, tmp_path, options=options)
    await env.runtime.async_backup_now(env.rid, actor=ADMIN)
    assert env.runtime.routers[env.rid].newest_ok_release == "24.10.2"
    env.coords[env.rid].poll(
        data=router_data(hostname="r1", macs=macs(0), version="25.12.0")
    )
    await drain(env.hass)
    assert env.api.registry.find(env.rid).firmware.version == "25.12.0"
    env.provider.collect_hook = _release_hook("25.12.0")
    await env.tick()
    assert len(_collected(env)) == 1  # first sighting: wait 300 s
    env.clock.advance(seconds=301)
    await env.tick()
    assert len(_collected(env)) == 2
    newest = (await _records(env))[0]
    assert newest.reason is BackupReason.RELEASE_CHANGE
    assert newest.openwrt_version == "25.12.0"
    for _ in range(3):
        env.clock.advance(seconds=301)
        await env.tick()
    assert len(_collected(env)) == 2  # once per (router, release)
    env = await restart(env)
    env.clock.advance(seconds=301)
    await env.tick()
    assert len(_collected(env)) == 2  # survives the restart (store)
    await stop(env)


async def test_first_fingerprint_is_reference_only(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    await env.runtime.async_backup_now(env.rid, actor=ADMIN)
    env.coords[env.rid].poll()  # first value after the start
    env.clock.advance(hours=2)
    await env.tick()
    assert env.provider.ops("detect_drift") == []
    await stop(env)


async def test_drift_check_debounced_and_rate_limited(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    await env.runtime.async_backup_now(env.rid, actor=ADMIN)
    env.coords[env.rid].poll()  # reference value
    await _drifted_poll(env, 1)
    env.clock.advance(seconds=200)
    await env.tick()
    assert env.provider.ops("detect_drift") == []  # 300 s debounce
    env.clock.advance(seconds=101)
    await env.tick()
    assert len(env.provider.ops("detect_drift")) == 1
    await _drifted_poll(env, 2)
    env.clock.advance(seconds=600)
    await env.tick()
    assert len(env.provider.ops("detect_drift")) == 1  # at most one per hour
    env.clock.advance(seconds=3000)
    await env.tick()
    assert len(env.provider.ops("detect_drift")) == 2
    assert env.runtime.routers[env.rid].drift["state"] == "open"
    await stop(env)


async def test_drift_without_baseline_waits_for_the_daily_run(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    env.coords[env.rid].poll()
    await _drifted_poll(env, 1)
    env.clock.advance(hours=2)
    await env.tick()
    assert env.provider.ops("detect_drift") == []
    assert env.provider.ops("collect") == []
    await stop(env)


async def test_drift_version_capped_per_day(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    await env.runtime.async_backup_now(env.rid, actor=ADMIN)
    env.coords[env.rid].poll()  # reference value
    for index in range(1, 7):  # six new drifts, one per hour, same day
        await _drifted_poll(env, index)
        env.clock.advance(seconds=3601)
        await env.tick()
    assert len(env.provider.ops("detect_drift")) == 6

    def drift_created():
        # Counted on the bus: the core's retention keeps only the newest
        # automatic version of a day in the store.
        return [
            e["data"]
            for e in bus_events(env.hass, "configuration.backup_created")
            if e["data"].get("reason") == BackupReason.DRIFT.value
        ]

    created = drift_created()
    assert len(created) == 4  # CONFIG_DRIFT_VERSIONS_PER_DAY
    assert {e["backup_type"] for e in created} == {BackupType.UCI_SNAPSHOT.value}
    assert len(_collected(env)) == 1 + 4  # manual + four drift versions
    assert env.runtime.stats["drift_versions_capped"] == 2
    # the same (already seen) drift again: no further version
    env.runtime.routers[env.rid].fp_changed_at = env.clock.local()
    env.clock.advance(seconds=3601)
    await env.tick()
    assert len(env.provider.ops("detect_drift")) == 7
    assert len(_collected(env)) == 5
    # the next day the cap starts again
    await _drifted_poll(env, 7)
    env.clock.advance(days=1)
    await env.tick()
    assert len(drift_created()) == 5
    await stop(env)


async def test_six_routers_run_one_at_a_time(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=6)
    gate = env.provider.gates["collect"] = asyncio.Event()
    env.runtime.async_tick()
    await _wait_entered(env)
    for _ in range(20):
        await asyncio.sleep(0)
    assert env.provider.active == 1  # the rest waits in our queue
    assert len(env.runtime._queue) == 5
    gate.set()
    await drain(env.hass)
    assert env.provider.max_active == 1
    assert sorted(_collected(env)) == sorted(env.rids)
    assert env.router_calls() == []
    await stop(env)


async def test_stagger_stable_within_hour(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=6)
    offsets = {rid: cm.stagger_offset(rid) for rid in env.rids}
    assert offsets == {rid: cm.stagger_offset(rid) for rid in env.rids}
    assert all(timedelta(0) <= o < timedelta(hours=1) for o in offsets.values())
    assert len(set(offsets.values())) > 1
    order = sorted(env.rids, key=offsets.__getitem__)
    runtime = env.runtime
    day = runtime._today_slot(order[0])
    env.clock.t = dt_util.as_utc(runtime._slot_at(order[0], day))
    await env.tick()
    assert _collected(env) == [order[0]]  # only the earliest offset is due
    env.clock.t = dt_util.as_utc(runtime._slot_at(order[1], day))
    await env.tick()
    assert _collected(env) == order[:2]
    assert runtime.next_run_at(order[0]) == runtime._slot_at(
        order[0], day + timedelta(days=1)
    )
    await stop(env)


async def test_operation_in_progress_retried_next_tick(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    held, release = asyncio.Event(), asyncio.Event()

    async def hold_router_lock():
        async with env.core.manager._locked(env.rid):
            held.set()
            await release.wait()

    holder = asyncio.ensure_future(hold_router_lock())
    await held.wait()
    await env.tick()
    assert _collected(env) == []  # lock held: skipped, no router call
    assert env.runtime.stats["runs_deferred"] == 1
    release.set()
    await holder
    # the core itself reports busy once: not a failure, next tick again
    env.provider.fail["collect"] = OperationInProgressError("busy")
    await env.tick()
    assert len(_collected(env)) == 1
    assert env.runtime.routers[env.rid].last_scheduled_day is None
    del env.provider.fail["collect"]
    await env.tick()
    assert len(_collected(env)) == 2
    assert [r.reason for r in await _records(env)] == [BackupReason.SCHEDULED]
    await stop(env)


async def test_restart_mid_backup_reruns_same_day(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    env.provider.gates["collect"] = asyncio.Event()
    env.runtime.async_tick()
    await _wait_entered(env)
    env = await restart(env)  # HA stops while the router is being read
    assert await _records(env) == []
    env.provider.gates.pop("collect")
    await env.tick()
    assert len(_collected(env)) == 2
    assert [r.reason for r in await _records(env)] == [BackupReason.SCHEDULED]
    await stop(env)


async def test_unload_cancels_timers_and_tasks(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    runtime = env.runtime
    listeners = env.coords[env.rid]._listeners
    count_with_ours = len(listeners)
    assert len(env.timers.active) == 1
    env.provider.gates["collect"] = asyncio.Event()
    runtime.async_tick()
    await _wait_entered(env)
    worker = runtime._worker
    await stop(env)
    assert env.timers.active == [] and env.timers.cancelled == 1
    assert worker is not None and worker.cancelled()
    assert runtime._tasks == set() and runtime._queue == []
    assert env.provider.active == 0
    assert len(listeners) < count_with_ours  # drift listener removed
    env.provider.gates.pop("collect")
    env = await restart(env)
    assert await _records(env) == []  # the cancelled run stored nothing
    await stop(env)


async def test_unloading_one_entry_cancels_only_its_run(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2)
    runtime = env.runtime
    first, second = list(runtime.routers)
    gate = env.provider.gates["collect"] = asyncio.Event()
    runtime.async_tick()
    await _wait_entered(env)
    assert _collected(env) == [first]
    old_worker = runtime._worker
    unload = asyncio.ensure_future(unload_entry(env, env.entry_of(first)))

    async def second_started():
        while _collected(env) != [first, second]:
            await asyncio.sleep(0)

    await asyncio.wait_for(second_started(), 5)  # the other router goes on
    gate.set()
    await unload
    assert old_worker.cancelled()
    assert await _records(env, second) != []
    assert first not in runtime.routers
    await unload_entry(env, env.entry_of(second))


async def test_manual_run_rejected_while_a_run_is_active(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2, options=NO_SCHEDULE)
    env.provider.gates["collect"] = asyncio.Event()
    first = asyncio.ensure_future(env.runtime.async_backup_now(env.rid, actor=ADMIN))
    await _wait_entered(env)
    with pytest.raises(OperationInProgressError):
        await env.runtime.async_backup_now(env.rids[1], actor=ADMIN)
    env.provider.gates["collect"].set()
    result = await first
    assert result.created
    await stop(env)


def test_note_validation():
    assert cm.validate_note(None) is None
    assert cm.validate_note("  ") is None
    assert cm.validate_note(" before VLAN ") == "before VLAN"
    assert cm.validate_note("x" * 200) == "x" * 200
    for bad in ("x" * 201, "a\nb", "a\x00b", "a" + chr(0x202E) + "b"):
        with pytest.raises(ValueError):
            cm.validate_note(bad)
    with pytest.raises(TypeError):
        cm.validate_note(5)
