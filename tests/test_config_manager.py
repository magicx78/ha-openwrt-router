"""Configuration manager runtime (plan 2026-11-18, sections 1 and 3-5).

Mocks only: the enterprise core runs on FakeDisks, the provider is the
in-memory FakeConfigProvider, the routers are FakeCoordinators whose api
objects must never be called. No Home Assistant instance, no router.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from config_manager_kit import (
    attach_entry,
    cm_env,
    drain,
    factory_of,
    restart,
    stop,
    unload_entry,
)
from core_test_provider import (
    FakeConfigProvider,
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import ADMIN_ID, FakeDisks, make_hass, user_actor

from custom_components.openwrt_router import config_manager as cm
from custom_components.openwrt_router.const import (
    CONFIG_STATUS_DISABLED,
    CONFIG_STATUS_NEVER,
    CONFIG_STATUS_OK,
    DATA_CONFIG_MANAGER,
)
from custom_components.openwrt_router.core_models import BackupReason

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
