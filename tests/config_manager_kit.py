"""Test environment of the configuration manager wiring (no router, no HA).

Builds on core_testkit / core_test_provider: a real enterprise core on
FakeDisks, N polled routers (FakeCoordinator), and the runtime of
``config_manager`` with a FakeConfigProvider instead of the real engine.
One controllable clock drives the runtime, the configuration manager of the
core and the version store, so "today" is the same for all three. The
5-minute timer is recorded, not started: tests call ``env.tick()``.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

from core_test_provider import FakeConfigProvider
from core_testkit import (
    FakeCoordinator,
    FakeEntry,
    add_users,
    core_of,
    make_hass,
    router_data,
    setup_router,
)
from homeassistant.util import dt as dt_util

from custom_components.openwrt_router import config_manager as cm
from custom_components.openwrt_router.config_api import async_get_configuration_api
from custom_components.openwrt_router.core_models import OPTION_CONFIG_BACKUP_ENABLED

# 2026-11-18 is a Wednesday; 12:00 UTC is after every daily slot.
DEFAULT_NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
ON = {OPTION_CONFIG_BACKUP_ENABLED: True}


def macs(index: int) -> list[str]:
    """Three universally administered MACs per router (distinct identities)."""
    return [f"94:83:c4:{index + 10:02x}:00:0{j}" for j in range(1, 4)]


class Clock:
    """One time for the runtime, the core manager and the version store."""

    def __init__(self, now: datetime = DEFAULT_NOW) -> None:
        self.t = now

    def utc(self) -> datetime:
        return self.t

    def local(self) -> datetime:
        return dt_util.as_local(self.t)

    def advance(self, **kwargs: float) -> None:
        self.t = self.t + timedelta(**kwargs)


class TimerRecorder:
    """Replacement of ``async_track_time_interval``: records, never fires."""

    def __init__(self) -> None:
        self.active: list[tuple[Any, timedelta]] = []
        self.cancelled = 0

    def __call__(self, hass: Any, action: Any, interval: timedelta, **_: Any) -> Any:
        item = (action, interval)
        self.active.append(item)

        def cancel() -> None:
            self.active.remove(item)
            self.cancelled += 1

        return cancel


@dataclass
class CmEnv:
    """Core, routers, fake provider and the configuration manager runtime."""

    hass: Any
    disks: Any
    api: Any
    provider: FakeConfigProvider
    entries: list[FakeEntry]
    coords: dict[str, FakeCoordinator]
    rids: list[str]
    clock: Clock
    timers: TimerRecorder
    factory_calls: list[Any] = field(default_factory=list)

    @property
    def runtime(self) -> cm.ConfigManagerRuntime:
        runtime = cm.async_get_runtime(self.hass)
        assert runtime is not None
        return runtime

    @property
    def rid(self) -> str:
        return self.rids[0]

    @property
    def core(self) -> Any:
        return core_of(self.hass)

    def router_calls(self) -> list[Any]:
        """Calls made on any coordinator's api object (must stay empty)."""
        return [c for coord in self.coords.values() for c in coord.router_calls()]

    def entry_of(self, router_id: str) -> FakeEntry:
        return self.entries[self.rids.index(router_id)]

    async def tick(self) -> None:
        """One 5-minute tick, then wait for every task it started."""
        runtime = cm.async_get_runtime(self.hass)
        if runtime is not None:
            runtime.async_tick()
        await drain(self.hass)


async def drain(hass: Any) -> None:
    """Wait for every task; tasks cancelled on purpose (unload) are fine."""
    while hass.tasks:
        task = hass.tasks.pop(0)
        try:
            await task
        except asyncio.CancelledError:
            if not task.cancelled():
                raise


def prepare_hass(tmp_path: Any) -> Any:
    hass = make_hass()
    root = str(tmp_path)
    hass.config.path = lambda *parts: os.path.join(root, *parts)
    hass.is_stopping = False
    # background tasks run like normal tasks (and are drained by drain())
    hass.async_create_background_task = hass.async_create_task
    add_users(hass)
    return hass


async def cm_env(
    disks: Any,
    tmp_path: Any,
    *,
    routers: int = 1,
    options: dict[str, Any] | None = None,
    provider: FakeConfigProvider | None = None,
    now: datetime = DEFAULT_NOW,
    attach: bool = True,
) -> CmEnv:
    """``routers`` polled routers, the core, and the runtime attached to all."""
    hass = prepare_hass(tmp_path)
    opts = dict(ON if options is None else options)
    clock = Clock(now)
    entries: list[FakeEntry] = []
    coords: dict[str, FakeCoordinator] = {}
    rids: list[str] = []
    for i in range(routers):
        entry = FakeEntry(f"e{i + 1}", host=f"192.168.1.{i + 1}", options=dict(opts))
        coord = await setup_router(
            hass, entry, router_data(hostname=f"r{i + 1}", macs=macs(i))
        )
        coord.poll()
        entries.append(entry)
        rid = core_of(hass).registry.get_by_entry(entry.entry_id).router_id
        coords[rid] = coord
        rids.append(rid)
    await drain(hass)
    core_of(hass).manager._clock = clock.utc
    core_of(hass).versions._clock = clock.utc
    api = await async_get_configuration_api(hass, 1)
    prov = provider or FakeConfigProvider()
    prov.guard = api.guard
    env = CmEnv(
        hass=hass,
        disks=disks,
        api=api,
        provider=prov,
        entries=entries,
        coords=coords,
        rids=rids,
        clock=clock,
        timers=TimerRecorder(),
    )
    if attach:
        for entry in entries:
            await attach_entry(env, entry)
    return env


def factory_of(env: CmEnv) -> Any:
    def factory(hass: Any) -> FakeConfigProvider:
        env.factory_calls.append(hass)
        return env.provider

    return factory


async def attach_entry(env: CmEnv, entry: FakeEntry) -> Any:
    """``async_setup_config_manager`` like ``__init__`` calls it."""
    rid = env.rids[env.entries.index(entry)]
    with (
        patch.object(cm, "async_track_time_interval", env.timers, create=True),
        patch.object(cm.dt_util, "now", env.clock.local),
    ):
        runtime = await cm.async_setup_config_manager(
            env.hass, entry, env.coords[rid], provider_factory=factory_of(env)
        )
    if runtime is not None:
        runtime.now = env.clock.local
    await drain(env.hass)
    return runtime


async def unload_entry(env: CmEnv, entry: FakeEntry) -> None:
    """What ``async_unload_entry`` does: release, core unload, on_unload."""
    from custom_components.openwrt_router.enterprise_core import (
        async_unload_entry_core,
    )

    cm.async_release_config_manager(env.hass, entry.entry_id)
    await async_unload_entry_core(env.hass, entry)
    await entry.run_on_unload()
    await drain(env.hass)


async def stop(env: CmEnv) -> None:
    """Unload every entry (the last one closes the core and the runtime)."""
    for entry in env.entries:
        await unload_entry(env, entry)


async def restart(env: CmEnv) -> CmEnv:
    """HA restart: stop everything, set the same entries up on the same disks."""
    await stop(env)
    coords: dict[str, FakeCoordinator] = {}
    rids: list[str] = []
    for i, entry in enumerate(env.entries):
        coord = await setup_router(
            env.hass, entry, router_data(hostname=f"r{i + 1}", macs=macs(i))
        )
        coord.poll()
        rid = core_of(env.hass).registry.get_by_entry(entry.entry_id).router_id
        coords[rid] = coord
        rids.append(rid)
    await drain(env.hass)
    core_of(env.hass).manager._clock = env.clock.utc
    core_of(env.hass).versions._clock = env.clock.utc
    api = await async_get_configuration_api(env.hass, 1)
    env.provider.guard = api.guard
    new = CmEnv(
        hass=env.hass,
        disks=env.disks,
        api=api,
        provider=env.provider,
        entries=env.entries,
        coords=coords,
        rids=rids,
        clock=env.clock,
        timers=env.timers,
        factory_calls=env.factory_calls,
    )
    for entry in env.entries:
        await attach_entry(new, entry)
    return new
