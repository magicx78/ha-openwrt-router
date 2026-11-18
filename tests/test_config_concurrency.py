"""Cases 12 (router offline) and 13 (parallel access) of part 2.

A failure before or during a collection leaves no half version, no
``.partial`` file, a ``configuration.backup_failed`` event, and releases the
router lock and the fleet slot. Mutations of one router are serialised, the
fleet runs FLEET_BACKUP_CONCURRENCY collections at a time, probes coalesce.
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest
from core_test_provider import (
    restart,
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
)
from core_testkit import ADMIN_ID, FakeDisks, bus_events, drain, user_actor

from custom_components.openwrt_router import version_store as version_store_module
from custom_components.openwrt_router.core_errors import (
    OperationInProgressError,
    OperationTimeoutError,
    ProviderError,
    RouterUnavailableError,
    StorageError,
)
from custom_components.openwrt_router.core_models import (
    FLEET_BACKUP_CONCURRENCY,
    PARTIAL_SUFFIX,
    Actor,
    BackupReason,
    CoreEventType,
    DriftAckState,
)

ADMIN = user_actor(ADMIN_ID)


def _write(path: str, data: bytes) -> None:
    """Plant a file next to the store (tests only)."""
    with open(path, "wb") as handle:
        handle.write(data)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _create(env, router_id=None, reason=BackupReason.MANUAL):
    return env.api.async_create_backup(router_id or env.rid, reason=reason, actor=ADMIN)


def _router_files(env, router_id=None) -> list[str]:
    folder = os.path.join(env.versions._root, router_id or env.rid)
    return sorted(os.listdir(folder)) if os.path.isdir(folder) else []


def _assert_clean_failure(env, failed_events: int = 1) -> None:
    assert env.versions.records(env.rid) == ()
    assert not any(f.endswith(PARTIAL_SUFFIX) for f in _router_files(env))
    assert _router_files(env) == []
    failed = bus_events(env.hass, CoreEventType.BACKUP_FAILED.value)
    assert len(failed) == failed_events
    assert not env.manager.locked(env.rid)
    assert env.manager._fleet._value == FLEET_BACKUP_CONCURRENCY


# -- case 12: router offline ----------------------------------------------------------


async def test_case12_offline_before_start(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.coords[env.rid].poll(success=False)
    with pytest.raises(RouterUnavailableError) as err:
        await _create(env)
    assert err.value.details["reason"] == "router_offline"
    assert env.provider.ops("collect") == []
    _assert_clean_failure(env)
    env.coords[env.rid].poll()
    assert (await _create(env)).created  # back online: works again


async def test_case12_connection_lost_mid_collect(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.provider.fail["collect"] = ConnectionResetError("router went away")
    with pytest.raises(ProviderError) as err:
        await _create(env)
    assert err.value.details["operation"] == "collect"
    _assert_clean_failure(env)
    assert env.manager.stats["provider_errors"] == 1


async def test_case12_collect_timeout(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.manager.collect_timeout = 0.05
    env.provider.gates["collect"] = asyncio.Event()  # never set: hangs
    with pytest.raises(OperationTimeoutError):
        await _create(env)
    _assert_clean_failure(env)
    assert env.manager.stats["provider_timeouts"] == 1


async def test_case12_write_failure_leaves_no_partial(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    real = version_store_module._write_atomic
    calls = 0

    def second_write_fails(router_dir, locator, data):
        nonlocal calls
        calls += 1
        if calls == 2:
            with open(os.path.join(router_dir, locator + PARTIAL_SUFFIX), "wb") as f:
                f.write(data[:3])
            raise OSError("disk full")
        return real(router_dir, locator, data)

    with (
        patch.object(version_store_module, "_write_atomic", second_write_fails),
        pytest.raises(StorageError),
    ):
        await _create(env)
    _assert_clean_failure(env)
    assert env.versions.stats["write_errors"] == 1


async def test_case12_startup_sweep_removes_stray_partials(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    record = (await _create(env)).record
    folder = os.path.join(env.versions._root, env.rid)
    stray = os.path.join(folder, "bkp_" + "e" * 32 + ".uci" + PARTIAL_SUFFIX)
    _write(stray, b"half")

    env = await restart(env)

    assert not os.path.exists(stray)
    assert env.versions.last_sweep.partial_deleted == 1
    assert bus_events(env.hass, CoreEventType.STORAGE_SWEPT.value)
    assert (await env.api.async_get_backup(record.backup_id)).usable


# -- case 13: parallel access ---------------------------------------------------------


async def test_case13_same_router_is_serialised(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    gate = env.provider.gates["collect"] = asyncio.Event()
    first = asyncio.create_task(_create(env))
    await env.provider.entered.setdefault("collect", asyncio.Event()).wait()
    assert env.manager.locked(env.rid)

    env.manager.lock_timeout = env.manager.lock_timeout.__class__(seconds=0.05)
    drift_ack = env.api.async_acknowledge_drift(
        env.rid, "drift_x", state=DriftAckState.ACKNOWLEDGED, actor=ADMIN
    )
    with pytest.raises(OperationInProgressError):
        await drift_ack
    assert env.manager.stats["lock_timeouts"] == 1

    gate.set()
    assert (await first).created
    assert not env.manager.locked(env.rid)
    assert env.provider.max_active == 1


async def test_case13_fleet_slot_limits_parallel_collections(disks, tmp_path):
    env = await start_env(disks, tmp_path, routers=3)
    gate = env.provider.gates["collect"] = asyncio.Event()
    tasks = [asyncio.create_task(_create(env, rid)) for rid in env.rids]
    await asyncio.sleep(0)
    await env.provider.entered.setdefault("collect", asyncio.Event()).wait()
    for _ in range(5):
        await asyncio.sleep(0)
    assert len(env.provider.ops("collect")) == FLEET_BACKUP_CONCURRENCY
    gate.set()
    results = await asyncio.gather(*tasks)
    assert all(r.created for r in results)
    assert env.provider.max_active == FLEET_BACKUP_CONCURRENCY
    assert {r.record.router_id for r in results} == set(env.rids)


async def test_case13_waiting_backup_runs_after_the_first(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    gate = env.provider.gates["collect"] = asyncio.Event()
    first = asyncio.create_task(_create(env))
    second = asyncio.create_task(_create(env, reason=BackupReason.PRE_CHANGE))
    await env.provider.entered.setdefault("collect", asyncio.Event()).wait()
    gate.set()
    a, b = await asyncio.gather(first, second)
    assert a.created and b.created
    assert a.record.backup_id != b.record.backup_id
    assert env.provider.max_active == 1


async def test_case13_probes_coalesce(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    gate = env.provider.gates["probe"] = asyncio.Event()
    probes = len(env.provider.ops("probe"))
    assert env.api.request_probe(env.rid, "one")
    await asyncio.sleep(0)
    assert env.api.request_probe(env.rid, "two")
    assert env.api.request_probe(env.rid, "three")
    gate.set()
    await drain(env.hass)
    # one running + one coalesced follow-up, never one per request
    assert len(env.provider.ops("probe")) == probes + 2
    assert env.manager.stats["probes_coalesced"] == 2


async def test_case13_reads_do_not_wait_for_the_lock(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    record = (await _create(env)).record
    gate = env.provider.gates["collect"] = asyncio.Event()
    env.provider.live(env.rid)["system"]["@system[0]"]["hostname"] = "x"
    running = asyncio.create_task(_create(env, reason=BackupReason.SCHEDULED))
    await env.provider.entered.setdefault("collect", asyncio.Event()).wait()
    assert (await env.api.async_get_backup(record.backup_id)) == record
    assert await env.api.async_list_backups(env.rid)
    gate.set()
    await running
    system = await env.api.async_create_backup(
        env.rid, reason=BackupReason.SCHEDULED, actor=Actor.system()
    )
    assert not system.created  # deduplicated against the one just made
