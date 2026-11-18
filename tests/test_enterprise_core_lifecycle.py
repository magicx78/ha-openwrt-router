"""Enterprise core part 1: lifecycle (case 15), backward compatibility (case 16)
and the measured load of the poll listener.

Case 15: unload / reload / restart keep the router ids, the last unload flushes
and releases the core, a second setup registers nothing twice and every
coordinator listener is gone after the unload.

Case 16: the core is optional. With the core raising in every hook the real
``async_setup_entry`` / poll / ``async_unload_entry`` / ``async_remove_entry``
still succeed, and HA's devices, entities, identifiers and unique_ids are the
same as with a working core.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from core_testkit import (
    MAC_A,
    MAC_B,
    FakeDisks,
    FakeEntry,
    bus_events,
    core_of,
    drain,
    make_hass,
    router_data,
    setup_router,
)
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from test_net_entities import loaded_registry

from custom_components.openwrt_router import (
    async_remove_entry,
    async_setup_entry,
    async_unload_entry,
)
from custom_components.openwrt_router.const import DOMAIN
from custom_components.openwrt_router.core_models import (
    AUDIT_STORE_KEY,
    DATA_ENTERPRISE_CORE,
    ROUTER_REGISTRY_STORE_KEY,
    CoreEventType,
    RecordState,
)
from custom_components.openwrt_router.enterprise_core import (
    async_get_core,
    async_remove_entry_core,
    async_setup_entry_core,
    async_unload_entry_core,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry
from custom_components.openwrt_router.router_registry import RouterRegistry

REGISTERED = CoreEventType.ROUTER_REGISTERED.value
CORE = "custom_components.openwrt_router.enterprise_core"


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _unload(hass: Any, entry: FakeEntry) -> None:
    """What HA does on unload: async_unload_entry, then the unload hooks."""
    await async_unload_entry_core(hass, entry)
    await entry.run_on_unload()
    await drain(hass)


# --- case 15: unload and restart -----------------------------------------------------------


async def test_case15_reload_keeps_ids_and_registers_nothing_twice(
    disks: FakeDisks,
) -> None:
    entries = [
        FakeEntry("01JA", host="192.168.1.1"),
        FakeEntry("01JB", host="192.168.1.2"),
    ]
    hass = make_hass(entries)
    coords = [
        await setup_router(hass, entries[0], router_data(macs=MAC_A)),
        await setup_router(hass, entries[1], router_data(macs=MAC_B, hostname="ap")),
    ]
    ids = {
        e.entry_id: core_of(hass).registry.router_id_for_entry(e.entry_id)
        for e in entries
    }
    assert ids == {e.entry_id: router_id_for_entry(e.entry_id) for e in entries}
    assert len(bus_events(hass, REGISTERED)) == 2

    for entry in entries:
        await _unload(hass, entry)
    assert all(c.listener_count == 0 for c in coords)

    # reload: the same entries again
    coords = [
        await setup_router(hass, entries[0], router_data(macs=MAC_A)),
        await setup_router(hass, entries[1], router_data(macs=MAC_B, hostname="ap")),
    ]
    registry = core_of(hass).registry
    assert {
        e.entry_id: registry.router_id_for_entry(e.entry_id) for e in entries
    } == ids
    assert len(bus_events(hass, REGISTERED)) == 2  # no second registration
    assert len(registry.list()) == 2
    assert all(c.listener_count == 1 for c in coords)


async def test_case15_last_unload_flushes_and_releases(disks: FakeDisks) -> None:
    entries = [FakeEntry("01JA"), FakeEntry("01JB", host="192.168.1.2")]
    hass = make_hass(entries)
    coords = [
        await setup_router(hass, entries[0], router_data(macs=MAC_A)),
        await setup_router(hass, entries[1], router_data(macs=MAC_B)),
    ]
    core = core_of(hass)
    registry_saves = len(disks[ROUTER_REGISTRY_STORE_KEY].saves)
    audit_saves = len(disks[AUDIT_STORE_KEY].saves)

    await _unload(hass, entries[0])
    # one entry left: the core stays, only that entry's listener is gone
    assert async_get_core(hass) is core
    assert coords[0].listener_count == 0
    assert coords[1].listener_count == 1
    assert core.registry.attached_entry_ids == frozenset({"01JB"})

    await _unload(hass, entries[1])
    slot = hass.data[DATA_ENTERPRISE_CORE]
    assert async_get_core(hass) is None
    assert slot.releases == 1
    assert slot.flush is None
    assert core.closed
    assert coords[1].listener_count == 0
    # both stores were written by the release (not only scheduled)
    assert len(disks[ROUTER_REGISTRY_STORE_KEY].saves) == registry_saves + 1
    assert len(disks[AUDIT_STORE_KEY].saves) == audit_saves + 1
    stored = disks[ROUTER_REGISTRY_STORE_KEY].data["data"]
    assert set(stored["routers"]) == {
        router_id_for_entry("01JA"),
        router_id_for_entry("01JB"),
    }


async def test_case15_restart_with_a_new_hass_keeps_ids(disks: FakeDisks) -> None:
    entries = [FakeEntry("01JA"), FakeEntry("01JB", host="192.168.1.2")]
    hass = make_hass(entries)
    for entry, macs in zip(entries, (MAC_A, MAC_B), strict=True):
        await setup_router(hass, entry, router_data(macs=macs))
    ids = {r.entry_id: r.router_id for r in core_of(hass).registry.list()}
    for entry in entries:
        await _unload(hass, entry)

    hass2 = make_hass(entries)  # HA restart: new instance, same .storage
    for entry, macs in zip(entries, (MAC_A, MAC_B), strict=True):
        await setup_router(hass2, entry, router_data(macs=macs))
    assert {r.entry_id: r.router_id for r in core_of(hass2).registry.list()} == ids
    assert bus_events(hass2, REGISTERED) == []
    # the audit log came back with the old core's events
    assert (
        len(core_of(hass2).audit.events(types=[CoreEventType.ROUTER_REGISTERED])) == 2
    )


async def test_case15_failed_setup_unload_hook_releases(disks: FakeDisks) -> None:
    """setup_retry: only the early hook ran; HA then runs the unload hooks."""
    entry = FakeEntry("01JA")
    hass = make_hass([entry])
    await async_setup_entry_core(hass, entry)  # then ConfigEntryNotReady
    core = core_of(hass)
    await entry.run_on_unload()
    await drain(hass)
    assert async_get_core(hass) is None
    assert core.closed
    assert hass.data[DATA_ENTERPRISE_CORE].releases == 1
    stored = disks[ROUTER_REGISTRY_STORE_KEY].data["data"]
    assert list(stored["routers"]) == [router_id_for_entry("01JA")]

    # the retry later works and keeps the id
    await setup_router(hass, entry, router_data())
    assert core_of(hass).registry.router_id_for_entry("01JA") == router_id_for_entry(
        "01JA"
    )
    assert len(bus_events(hass, REGISTERED)) == 1


async def test_case15_double_unload_and_double_setup_are_safe(disks: FakeDisks) -> None:
    entry = FakeEntry("01JA")
    hass = make_hass([entry])
    coord = await setup_router(hass, entry, router_data())
    # a second attach (setup hook called again) replaces the listener
    await async_setup_entry_core(hass, entry, coord)
    assert coord.listener_count == 1
    # remover registered twice with HA; HA's remover raises KeyError on a 2nd call
    await async_unload_entry_core(hass, entry)
    await async_unload_entry_core(hass, entry)
    await entry.run_on_unload()
    await drain(hass)
    assert coord.listener_count == 0
    assert hass.data[DATA_ENTERPRISE_CORE].releases == 1


async def test_case15_new_core_waits_for_the_released_core_flush(
    disks: FakeDisks,
) -> None:
    entry = FakeEntry("01JA")
    hass = make_hass([entry])
    await setup_router(hass, entry, router_data())
    await _unload(hass, entry)
    slot = hass.data[DATA_ENTERPRISE_CORE]
    pending: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    slot.flush = pending  # a release still writing its stores

    task = asyncio.ensure_future(async_setup_entry_core(hass, entry))
    for _ in range(5):
        await asyncio.sleep(0)
    assert not task.done()  # the new core does not read a half-written store
    pending.set_result(None)
    slot.flush = None
    record = await task
    assert record.router_id == router_id_for_entry("01JA")


async def test_case15_remove_after_unload_orphans_with_a_temporary_core(
    disks: FakeDisks,
) -> None:
    entry = FakeEntry("01JA")
    hass = make_hass([entry])
    await setup_router(hass, entry, router_data())
    await _unload(hass, entry)
    hass.entries.remove(entry)
    await async_remove_entry_core(hass, entry)
    assert async_get_core(hass) is None  # the temporary core is not kept
    assert hass.data[DATA_ENTERPRISE_CORE].flush is None
    (stored,) = disks[ROUTER_REGISTRY_STORE_KEY].data["data"]["routers"].values()
    assert stored["state"] == RecordState.ORPHANED.value


# --- case 16: backward compatibility ---------------------------------------------------------


def _setup_mocks(listeners: list[Any]) -> tuple[Any, Any]:
    """api + coordinator mocks like tests/test_init.py (no router contact)."""
    api = AsyncMock()
    api.login = AsyncMock()
    api.reset_acl_blocked = MagicMock()
    api.uses_ssh_fallback = False
    coordinator = MagicMock()
    coordinator.async_config_entry_first_refresh = AsyncMock()
    coordinator.router_info = {"model": "TestRouter"}
    coordinator.data = router_data()
    coordinator.last_update_success = True
    coordinator.api = api

    def add_listener(callback: Any, *args: Any) -> Any:
        listeners.append(callback)
        return MagicMock()

    coordinator.async_add_listener = MagicMock(side_effect=add_listener)
    return api, coordinator


def _core_listeners(listeners: list[Any]) -> list[Any]:
    return [
        cb
        for cb in listeners
        if "RouterRegistry.attach" in getattr(cb, "__qualname__", "")
    ]


async def _populate(hass: Any, entry: FakeEntry) -> tuple[Any, Any]:
    entity_reg = await loaded_registry(hass)
    device_reg = dr.async_get(hass)
    device = device_reg.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, entry.entry_id)},
        manufacturer="OpenWrt",
        name="Router",
    )
    for key in ("uptime", "wan_status", "client_count"):
        entity_reg.async_get_or_create(
            "sensor",
            DOMAIN,
            f"{entry.entry_id}_{key}",
            config_entry=entry,
            device_id=device.id,
        )
    return entity_reg, device_reg


def _snapshot(entity_reg: Any, device_reg: Any, entry: FakeEntry) -> tuple[Any, ...]:
    devices = sorted(
        (d.id, sorted(d.identifiers), d.name)
        for d in dr.async_entries_for_config_entry(device_reg, entry.entry_id)
    )
    entities = sorted(
        (e.entity_id, e.unique_id, e.device_id, e.config_entry_id)
        for e in er.async_entries_for_config_entry(entity_reg, entry.entry_id)
    )
    return (
        devices,
        entities,
        entry.entry_id,
        entry.unique_id,
        dict(entry.data),
        dict(entry.options),
        entry.version,
        entry.minor_version,
    )


async def _run_entry_lifecycle(
    hass: Any, entry: FakeEntry
) -> tuple[bool, bool, list[Any]]:
    """Real setup -> one poll -> unload -> remove, router and HA mocked."""
    listeners: list[Any] = []
    api, coordinator = _setup_mocks(listeners)
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    with (
        patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ),
        patch("custom_components.openwrt_router.OpenWrtAPI", return_value=api),
        patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=coordinator,
        ),
        patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl",
            AsyncMock(return_value=False),
        ),
    ):
        setup_ok = await async_setup_entry(hass, entry)
        for listener in _core_listeners(listeners):
            listener()  # one finished poll; must never raise
        unload_ok = await async_unload_entry(hass, entry)
        await entry.run_on_unload()
        await async_remove_entry(hass, entry)
        await drain(hass)
    return setup_ok, unload_ok, listeners


async def _lifecycle_snapshot(
    disks: FakeDisks, tmp_path: Path
) -> tuple[tuple[Any, ...], tuple[Any, ...], Any]:
    entry = FakeEntry("01JCOMPAT", unique_id="uid-compat")
    hass = make_hass([entry])
    # The other subsystems use real HA Stores with a dict hass.data: give them
    # a real, empty config dir (a MagicMock path would reach the file system).
    hass.config.config_dir = str(tmp_path)
    hass.config.path = MagicMock(
        side_effect=lambda *parts: str(tmp_path.joinpath(*parts))
    )
    entity_reg, device_reg = await _populate(hass, entry)
    before = _snapshot(entity_reg, device_reg, entry)
    setup_ok, unload_ok, listeners = await _run_entry_lifecycle(hass, entry)
    assert setup_ok is True
    assert unload_ok is True
    return before, _snapshot(entity_reg, device_reg, entry), (hass, listeners)


async def test_case16_working_core_changes_nothing_ha_owns(
    disks: FakeDisks, tmp_path: Path
) -> None:
    before, after, (_hass, listeners) = await _lifecycle_snapshot(disks, tmp_path)
    assert after == before
    assert len(_core_listeners(listeners)) == 1  # the core really ran
    assert disks[ROUTER_REGISTRY_STORE_KEY].data is not None


@pytest.mark.parametrize(
    "broken",
    ["setup", "unload", "remove", "poll", "everything"],
)
async def test_case16_core_raising_never_breaks_the_integration(
    disks: FakeDisks, caplog: pytest.LogCaptureFixture, tmp_path: Path, broken: str
) -> None:
    boom = RuntimeError("core exploded")
    targets = {
        "setup": [f"{CORE}.async_setup_entry_core"],
        "unload": [f"{CORE}.async_unload_entry_core"],
        "remove": [f"{CORE}.async_remove_entry_core"],
        "poll": [],
    }
    names = (
        [n for group in targets.values() for n in group]
        if broken == "everything"
        else targets[broken]
    )
    patches = [patch(name, AsyncMock(side_effect=boom)) for name in names]
    if broken in ("poll", "everything"):
        patches.append(patch.object(RouterRegistry, "_process_poll", side_effect=boom))
    for p in patches:
        p.start()
    try:
        before, after, (hass, listeners) = await _lifecycle_snapshot(disks, tmp_path)
    finally:
        for p in patches:
            p.stop()

    # devices, entities, identifiers, unique_ids and the entry are unchanged
    assert after == before
    # every failure is visible (no silent suppression)
    if broken in ("setup", "everything"):
        assert "router id assignment failed" in caplog.text
        assert "registry listener setup failed" in caplog.text
    if broken in ("unload", "everything"):
        assert "Enterprise core unload raised" in caplog.text
    if broken in ("remove", "everything"):
        assert "could not orphan the router record" in caplog.text
    if broken == "poll":
        # attach runs one poll itself, the test one more: both failed, logged once
        assert len(_core_listeners(listeners)) == 1
        assert caplog.text.count("processing a poll of 01JCOMPAT failed") == 1
        assert async_get_core(hass) is None  # released after the unload all the same


async def test_case16_poll_error_is_counted_not_raised(disks: FakeDisks) -> None:
    entry = FakeEntry("01JA")
    hass = make_hass([entry])
    coord = await setup_router(hass, entry, router_data())
    registry = core_of(hass).registry
    with patch.object(
        RouterRegistry, "_process_poll", side_effect=RuntimeError("boom")
    ):
        for _ in range(3):
            coord.poll()  # never raises into the coordinator
    assert registry.stats["listener_errors"] == 3


# --- measured load -------------------------------------------------------------------------


async def test_load_router_calls_listener_time_and_store_writes(
    disks: FakeDisks, capsys: pytest.CaptureFixture[str]
) -> None:
    """1000 polls of 7 routers: 0 router calls, listener time, store writes."""
    entries = [FakeEntry(f"01JLOAD{i}", host=f"192.168.1.{10 + i}") for i in range(7)]
    hass = make_hass(entries)
    coords = []
    for i, entry in enumerate(entries):
        macs = [f"00:1a:2b:{i:02x}:00:{j:02x}" for j in range(1, 4)]
        coords.append(
            await setup_router(hass, entry, router_data(hostname=f"r{i}", macs=macs))
        )
    await drain(hass)
    disks.flush_delayed()
    registry = core_of(hass).registry
    audit = core_of(hass).audit
    reg_disk = disks[ROUTER_REGISTRY_STORE_KEY]
    audit_disk = disks[AUDIT_STORE_KEY]
    reg_saves0, audit_saves0 = len(reg_disk.saves), len(audit_disk.saves)
    sched0 = registry.stats["store_saves_scheduled"]
    imm0 = registry.stats["store_saves_immediate"]
    timing_runs0 = registry.timing["runs"]

    polls = 1000
    durations: list[float] = []
    for n in range(polls):
        for coord in coords:
            start = time.perf_counter()
            # every 10th poll fails (unreachable), then comes back
            coord.poll(success=(n % 10 != 5))
            durations.append(time.perf_counter() - start)
        if n % 100 == 99:  # HA's delayed save fires now and then
            await drain(hass)
            disks.flush_delayed()
    await drain(hass)
    disks.flush_delayed()

    router_calls = [call for coord in coords for call in coord.router_calls()]
    assert router_calls == []  # target: 0 router calls per poll and per day
    assert registry.timing["runs"] - timing_runs0 == polls * len(coords)
    durations.sort()
    avg_us = sum(durations) / len(durations) * 1e6
    p99_us = durations[int(len(durations) * 0.99)] * 1e6
    max_us = durations[-1] * 1e6
    reg_writes = len(reg_disk.saves) - reg_saves0
    audit_writes = len(audit_disk.saves) - audit_saves0
    scheduled = registry.stats["store_saves_scheduled"] - sched0
    immediate = registry.stats["store_saves_immediate"] - imm0
    with capsys.disabled():
        print(
            f"\n[core load] polls={polls}x{len(coords)} router_calls={len(router_calls)} "
            f"listener avg={avg_us:.1f}us p99={p99_us:.1f}us max={max_us:.1f}us "
            f"registry writes={reg_writes} (scheduled={scheduled}, immediate={immediate}) "
            f"audit writes={audit_writes} audit events={audit.ring_size('general')}"
        )
    # the reachability flips are the only changes: writes stay bounded by the
    # delayed-save batching, never one write per poll
    assert immediate == 0
    assert reg_writes <= polls // 100
    assert audit_writes <= polls // 100
    # ~0.2-0.3 ms on a desktop; the bound only catches a regression by an
    # order of magnitude without being flaky on a slow shared CI runner
    assert avg_us < 5000
