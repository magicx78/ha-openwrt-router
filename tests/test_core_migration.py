"""Enterprise core part 1: migration of existing installs (case 5 + acceptance).

A real install has 7 config entries, one of them unreachable for days. The
migration is the first setup with the core: it must work without router
contact, be idempotent, survive an interrupted run (each entry on its own)
and a missing / corrupt / newer store (kept as .bak, rebuilt; only adoption
links can be lost, and that is logged and audited). Nothing is ever merged
and nothing HA owns (entry, devices, entities) changes.
"""

from __future__ import annotations

import copy
import logging
from typing import Any

import pytest
from core_testkit import (
    MAC_A,
    MAC_B,
    MAC_C,
    FakeDisks,
    FakeEntry,
    bus_events,
    core_of,
    guard_adopt_auth,
    ha_entry_calls,
    make_hass,
    router_data,
    setup_router,
)
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from test_net_entities import loaded_registry

from custom_components.openwrt_router.const import DOMAIN
from custom_components.openwrt_router.core_models import (
    ROUTER_REGISTRY_STORE_KEY,
    CoreEventType,
    IdentityStatus,
    RecordState,
)
from custom_components.openwrt_router.enterprise_core import (
    async_get_core,
    async_remove_entry_core,
    async_setup_entry_core,
    async_unload_entry_core,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry

ENTRY_IDS = [f"01JENTRY{i:02d}" for i in range(7)]
UNREACHABLE = ENTRY_IDS[6]  # setup_retry for days: never a coordinator
STORE_RECOVERED = CoreEventType.STORE_RECOVERED.value


def _macs(i: int) -> list[str]:
    return [f"00:1a:2b:{i:02x}:00:{j:02x}" for j in range(1, 4)]


def _entries() -> list[FakeEntry]:
    return [
        FakeEntry(eid, host=f"192.168.1.{10 + i}") for i, eid in enumerate(ENTRY_IDS)
    ]


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _start(hass: Any, entries: list[FakeEntry]) -> dict[str, Any]:
    """One HA start: every entry's setup; the unreachable one stops early."""
    coordinators: dict[str, Any] = {}
    for i, entry in enumerate(entries):
        if entry.entry_id == UNREACHABLE:
            await async_setup_entry_core(hass, entry)  # then ConfigEntryNotReady
            await entry.run_on_unload()  # HA runs the unload hooks after a failed setup
            continue
        coord = await setup_router(
            hass, entry, router_data(hostname=f"r{i}", macs=_macs(i))
        )
        coordinators[entry.entry_id] = coord
    return coordinators


async def _stop(hass: Any, entries: list[FakeEntry]) -> None:
    for entry in entries:
        await async_unload_entry_core(hass, entry)
        await entry.run_on_unload()


def _ha_owned(entries: list[FakeEntry]) -> list[tuple[Any, ...]]:
    return [
        (e.entry_id, e.unique_id, copy.deepcopy(e.data), e.version, e.minor_version)
        for e in entries
    ]


def _saved_routers(disks: FakeDisks) -> dict[str, Any]:
    return disks[ROUTER_REGISTRY_STORE_KEY].data["data"]["routers"]


async def test_case05_seven_entries_one_never_reachable(disks: FakeDisks) -> None:
    entries = _entries()
    before = _ha_owned(entries)
    hass = make_hass(entries)
    await _start(hass, entries)
    registry = core_of(hass).registry
    records = {r.entry_id: r for r in registry.list()}
    assert set(records) == set(ENTRY_IDS)
    for eid, record in records.items():
        assert record.router_id == router_id_for_entry(eid)
        expected = (
            IdentityStatus.UNVERIFIED
            if eid == UNREACHABLE
            else IdentityStatus.CONFIRMED
        )
        assert record.identity.status is expected
    assert _ha_owned(entries) == before  # entry unique_id/data/version untouched
    # the mocked config_entries never applies a call: assert on the calls
    assert ha_entry_calls(hass) == {}
    assert core_of(hass).entry_ids == frozenset(ENTRY_IDS[:6])


async def test_case05_migration_runs_twice_idempotent(disks: FakeDisks) -> None:
    entries = _entries()
    hass = make_hass(entries)
    await _start(hass, entries)
    await _stop(hass, entries)
    first = copy.deepcopy(_saved_routers(disks))
    registered = len(bus_events(hass, CoreEventType.ROUTER_REGISTERED.value))
    assert registered == 7

    hass2 = make_hass(entries)  # HA restart, same store files
    await _start(hass2, entries)
    await _stop(hass2, entries)
    second = _saved_routers(disks)
    assert set(second) == set(first)
    for rid, record in first.items():
        assert second[rid]["registered_at"] == record["registered_at"]
        assert second[rid]["identity"]["entry_id"] == record["identity"]["entry_id"]
        assert second[rid]["state"] == "active"
    assert bus_events(hass2, CoreEventType.ROUTER_REGISTERED.value) == []  # nothing new


async def test_case05_interrupted_run_each_entry_independent(disks: FakeDisks) -> None:
    entries = _entries()
    hass = make_hass(entries)
    # crash after three entries; their delayed save never ran
    for entry in entries[:3]:
        await setup_router(hass, entry, router_data(macs=_macs(entries.index(entry))))
    assert disks[ROUTER_REGISTRY_STORE_KEY].data is None

    hass2 = make_hass(entries)
    for entry in entries[:2]:  # second run, crashes again after two (saved this time)
        await setup_router(hass2, entry, router_data(macs=_macs(entries.index(entry))))
    await core_of(hass2).async_flush()

    hass3 = make_hass(entries)
    await _start(hass3, entries)
    registry = core_of(hass3).registry
    assert {r.entry_id: r.router_id for r in registry.list()} == {
        eid: router_id_for_entry(eid) for eid in ENTRY_IDS
    }
    assert len(registry.list(include_orphaned=True)) == 7  # no duplicates, no orphans


@pytest.mark.parametrize(
    "stored",
    [
        "not json at all",
        {"version": 1, "minor_version": 1, "data": ["a", "list"]},
        {"version": 9, "minor_version": 0, "data": {"routers": {}}},  # newer major
    ],
    ids=["garbage", "wrong_type", "newer_major"],
)
async def test_case05_corrupt_store_kept_as_bak_and_rebuilt(
    disks: FakeDisks, stored: Any, caplog: pytest.LogCaptureFixture
) -> None:
    entries = _entries()
    disks[ROUTER_REGISTRY_STORE_KEY].data = stored
    hass = make_hass(entries)
    with caplog.at_level(logging.WARNING):
        await _start(hass, entries)
    registry = core_of(hass).registry
    assert registry.load_failed
    assert disks[ROUTER_REGISTRY_STORE_KEY].backups == 1
    assert {r.router_id for r in registry.list()} == {
        router_id_for_entry(e) for e in ENTRY_IDS
    }
    (event,) = bus_events(hass, STORE_RECOVERED)
    assert event["data"]["store"] == ROUTER_REGISTRY_STORE_KEY
    assert event["data"]["adoption_links_lost"] == 0
    assert "Router registry store was rebuilt" in caplog.text


async def test_case05_corrupt_store_loses_only_adoption_links_audited(
    disks: FakeDisks,
) -> None:
    entries = _entries()[:2]
    hass = make_hass(entries)
    await _start(hass, entries)
    registry = core_of(hass).registry
    # entry 1 is removed; a new entry for the same device adopts its record
    gone = entries.pop(1)  # make_hass shares this list, so HA no longer sees it
    await async_remove_entry_core(hass, gone)
    orphan_id = router_id_for_entry(gone.entry_id)
    new = FakeEntry("01JNEW", host="192.168.1.99")
    entries.append(new)
    await setup_router(hass, new, router_data(hostname="r1", macs=_macs(1)))
    auth = await guard_adopt_auth(hass, "01JNEW", orphan_id)
    await registry.async_adopt_authorized("01JNEW", orphan_id, authorization=auth)
    await _stop(hass, entries)

    disks[ROUTER_REGISTRY_STORE_KEY].data = "corrupt"
    hass2 = make_hass(entries)
    await _start(hass2, entries)
    registry2 = core_of(hass2).registry
    # rebuilt: the new entry gets its default id again; the link is lost …
    assert registry2.get_by_entry("01JNEW").router_id == router_id_for_entry("01JNEW")
    # … and reported (log + audit + bus) with the router id to adopt again
    (event,) = bus_events(hass2, STORE_RECOVERED)
    assert event["data"]["adoption_links_lost"] == 1
    assert event["data"]["lost_router_ids"] == [orphan_id]
    audited = core_of(hass2).audit.events(types=[CoreEventType.STORE_RECOVERED])
    assert len(audited) == 1


async def test_case05_missing_store_is_a_first_install(disks: FakeDisks) -> None:
    entries = _entries()
    hass = make_hass(entries)
    await _start(hass, entries)
    assert not core_of(hass).registry.load_failed
    assert bus_events(hass, STORE_RECOVERED) == []
    assert disks[ROUTER_REGISTRY_STORE_KEY].backups == 0


async def test_case05_never_merges_entries_with_the_same_hardware(
    disks: FakeDisks,
) -> None:
    entries = _entries()[:2]
    hass = make_hass(entries)
    for entry in entries:  # both entries point at the same box
        await setup_router(hass, entry, router_data(macs=MAC_A))
    registry = core_of(hass).registry
    assert len(registry.list()) == 2
    assert all(
        r.identity.status is IdentityStatus.DUPLICATE_SUSPECTED for r in registry.list()
    )


async def test_case05_entry_gone_while_ha_was_down_is_orphaned_not_deleted(
    disks: FakeDisks,
) -> None:
    entries = _entries()[:3]
    hass = make_hass(entries)
    await _start(hass, entries)
    await _stop(hass, entries)
    hass2 = make_hass(entries[:2])  # entry 3 deleted outside the integration
    await _start(hass2, entries[:2])
    registry = core_of(hass2).registry
    record = registry.get(router_id_for_entry(entries[2].entry_id))
    assert record.state is RecordState.ORPHANED
    assert registry.stats["orphaned_at_load"] == 1


async def test_case05_no_known_entries_orphans_nothing(disks: FakeDisks) -> None:
    entries = _entries()[:2]
    hass = make_hass(entries)
    await _start(hass, entries)
    await _stop(hass, entries)
    hass2 = make_hass([])  # config entries not readable / not loaded yet
    core = await __import__(
        "custom_components.openwrt_router.enterprise_core", fromlist=["x"]
    ).async_get_enterprise_core(hass2)
    assert all(
        r.state is RecordState.ACTIVE for r in core.registry.list(include_orphaned=True)
    )


# --- acceptance: HA's registries stay byte-identical ---------------------------------------


def _device_entry_ids(device: Any) -> list[str]:
    """The device's config entry ids on every supported HA release.

    HA 2026.8+ has ``config_entry_id`` (``config_entries`` is deprecated and
    warns through the frame helper); HA 2026.2 only has ``config_entries``.
    """
    entry_id = getattr(device, "config_entry_id", None)
    if entry_id is not None:
        return [entry_id]
    return sorted(device.config_entries)


async def test_acceptance_devices_entities_and_entries_unchanged(
    disks: FakeDisks,
) -> None:
    entries = _entries()
    hass = make_hass(entries)
    entity_reg = await loaded_registry(hass)
    device_reg = dr.async_get(hass)
    for i, entry in enumerate(entries):
        device = device_reg.async_get_or_create(
            config_entry_id=entry.entry_id,
            identifiers={(DOMAIN, entry.entry_id)},
            manufacturer="OpenWrt",
            name=f"Router {i}",
        )
        for key in ("uptime", "wan_status", "client_count"):
            entity_reg.async_get_or_create(
                "sensor",
                DOMAIN,
                f"{entry.unique_id}_{key}",
                config_entry=entry,
                device_id=device.id,
            )

    def snapshot() -> tuple[Any, ...]:
        # lookups by config entry: stable on HA 2026.2 and 2026.11+
        # (``registry.devices.values()`` is deprecated since 2026.11)
        devices = sorted(
            (d.id, sorted(d.identifiers), _device_entry_ids(d), d.name)
            for entry in entries
            for d in dr.async_entries_for_config_entry(device_reg, entry.entry_id)
        )
        entities = sorted(
            (e.entity_id, e.unique_id, e.device_id, e.config_entry_id, e.platform)
            for entry in entries
            for e in er.async_entries_for_config_entry(entity_reg, entry.entry_id)
        )
        return devices, entities, _ha_owned(entries)

    before = snapshot()
    assert len(before[0]) == 7 and len(before[1]) == 21

    coordinators = await _start(hass, entries)
    for coord in coordinators.values():
        coord.poll()
    await _stop(hass, entries)
    await _start(hass, entries)  # second run (reload)

    assert snapshot() == before
    registry = async_get_core(hass).registry
    # the real registry lookup works (no deprecated call, no frame-helper error)
    assert registry.stats["device_lookup_errors"] == 0
    for entry in entries:
        record = registry.get_by_entry(entry.entry_id)
        assert record.router_id == router_id_for_entry(entry.entry_id)
        (device,) = dr.async_entries_for_config_entry(device_reg, entry.entry_id)
        assert (DOMAIN, entry.entry_id) in device.identifiers
        if entry.entry_id == UNREACHABLE:
            assert record.identity.device_id is None  # never polled
        else:
            assert record.identity.device_id == device.id


def test_fixture_macs_are_distinct() -> None:
    all_macs = [m for i in range(7) for m in _macs(i)] + MAC_A + MAC_B + MAC_C
    assert len(all_macs) == len(set(all_macs))
