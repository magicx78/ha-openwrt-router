"""Router registry: no runtime after unload, orphaned records are bounded.

Review finding 6 of PR #55:

* an unloaded entry leaves no ``_runtime`` state behind;
* orphaned records do not grow forever: orphans WITHOUT versions are
  forgotten after ``ORPHAN_RETENTION_DAYS``; above ``MAX_ORPHANED_RECORDS``
  the oldest go, those without versions first;
* a record bound to a config entry that still exists is never dropped;
* every drop is counted and audited (``router.forgotten``), never silent;
* without known entries or without a loaded version store nothing is
  dropped (counted as skipped).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pytest
from core_testkit import (
    FakeDisks,
    FakeEntry,
    bus_events,
    core_of,
    make_hass,
    router_data,
    setup_router,
)

from custom_components.openwrt_router.const import (
    ROUTER_REGISTRY_STORE_MINOR_VERSION,
)
from custom_components.openwrt_router.core_models import (
    CORE_STORE_VERSION,
    ROUTER_REGISTRY_STORE_KEY,
    SECURITY_EVENT_TYPES,
    AuditRing,
    CoreEventType,
    RecordState,
    audit_ring_for,
    utcnow,
)
from custom_components.openwrt_router.enterprise_core import (
    async_get_enterprise_core,
    async_unload_entry_core,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry
from custom_components.openwrt_router.router_registry import (
    FORGET_AGED,
    FORGET_CAPPED,
    MAX_ORPHANED_RECORDS,
    ORPHAN_RETENTION_DAYS,
)
from custom_components.openwrt_router.version_store import VersionStore


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _orphan(entry_id: str, age_days: float, **extra: Any) -> dict[str, Any]:
    rid = router_id_for_entry(entry_id)
    return {
        "identity": {"router_id": rid, "entry_id": entry_id},
        "state": "orphaned",
        "orphaned_at": (utcnow() - timedelta(days=age_days)).isoformat(),
        **extra,
    }


def _plant(disks: FakeDisks, records: list[dict[str, Any]]) -> None:
    disks[ROUTER_REGISTRY_STORE_KEY].data = {
        "version": CORE_STORE_VERSION,
        "minor_version": ROUTER_REGISTRY_STORE_MINOR_VERSION,
        "key": ROUTER_REGISTRY_STORE_KEY,
        "data": {"routers": {r["identity"]["router_id"]: r for r in records}},
    }


async def _start(disks: FakeDisks, records, *, versioned=(), entries=("live",)):
    """Plant the store, then start the core through a normal setup."""
    _plant(disks, records)
    hass = make_hass([FakeEntry(e) for e in entries])
    with patch.object(VersionStore, "router_ids", return_value=tuple(versioned)):
        await setup_router(hass, hass.entries[0], router_data())
    return hass, core_of(hass).registry


def _ids(registry) -> set[str]:
    return {r.router_id for r in registry.list(include_orphaned=True)}


# -- runtime ---------------------------------------------------------------------------


async def test_unload_drops_runtime(disks):
    hass = make_hass()
    keep, gone = FakeEntry("keep"), FakeEntry("gone", host="192.168.1.9")
    await setup_router(hass, keep, router_data())
    await setup_router(hass, gone, router_data())
    registry = core_of(hass).registry
    assert "gone" in registry._runtime

    await async_unload_entry_core(hass, gone)
    await gone.run_on_unload()
    assert "gone" not in registry._runtime
    assert "keep" in registry._runtime
    # the record stays active; the option is read from the entry again
    rid = registry.get_by_entry("gone").router_id
    assert registry.config_enabled(rid) is False

    await setup_router(hass, gone, router_data())  # reload: runtime is back
    assert "gone" in registry._runtime


# -- aging -----------------------------------------------------------------------------


async def test_aged_orphan_forgotten(disks):
    old = _orphan("old", ORPHAN_RETENTION_DAYS + 1)
    young = _orphan("young", ORPHAN_RETENTION_DAYS - 1)
    hass, registry = await _start(disks, [old, young])
    old_id = old["identity"]["router_id"]
    young_id = young["identity"]["router_id"]
    assert old_id not in _ids(registry)
    assert young_id in _ids(registry)
    assert registry.stats["orphans_forgotten_aged"] == 1
    assert registry.stats["orphans_forgotten_capped"] == 0
    (event,) = bus_events(hass, CoreEventType.ROUTER_FORGOTTEN.value)
    assert event["router_id"] == old_id
    assert event["data"]["reason"] == FORGET_AGED
    assert event["data"]["has_versions"] is False
    assert event["data"]["last_entry_id"] == "old"
    # saved without it
    await registry.async_flush()
    saved = disks[ROUTER_REGISTRY_STORE_KEY].data["data"]["routers"]
    assert old_id not in saved and young_id in saved


async def test_versioned_orphan_outlives(disks):
    old = _orphan("old", ORPHAN_RETENTION_DAYS * 10)
    old_id = old["identity"]["router_id"]
    hass, registry = await _start(disks, [old], versioned=[old_id])
    assert old_id in _ids(registry)
    assert registry.stats["orphans_forgotten_aged"] == 0
    assert bus_events(hass, CoreEventType.ROUTER_FORGOTTEN.value) == []


async def test_existing_entry_never_dropped(disks):
    # orphaned by adoption / duplicate binding: its entry still exists
    replaced = _orphan("live", ORPHAN_RETENTION_DAYS * 10)
    replaced["identity"]["router_id"] = router_id_for_entry("live-old")
    # an earlier binding of an existing entry also protects it
    earlier = _orphan("x-gone", ORPHAN_RETENTION_DAYS * 10)
    earlier["previous_entry_ids"] = ["other"]
    _hass, registry = await _start(
        disks, [replaced, earlier], entries=("live", "other")
    )
    assert replaced["identity"]["router_id"] in _ids(registry)
    assert earlier["identity"]["router_id"] in _ids(registry)
    assert registry.stats["orphans_forgotten_aged"] == 0


async def test_no_known_entries_no_drop(disks):
    _plant(disks, [_orphan("old", ORPHAN_RETENTION_DAYS * 10)])
    core = await async_get_enterprise_core(make_hass())  # no entries known
    registry = core.registry
    assert len(_ids(registry)) == 1
    assert registry.stats["orphan_prune_skipped"] == 1


async def test_versions_unloaded_no_drop(disks):
    old = _orphan("old", ORPHAN_RETENTION_DAYS * 10)
    _plant(disks, [old])
    hass = make_hass([FakeEntry("live")])
    with patch.object(VersionStore, "async_load", side_effect=OSError("disk")):
        await setup_router(hass, hass.entries[0], router_data())
    registry = core_of(hass).registry
    assert old["identity"]["router_id"] in _ids(registry)
    assert registry.stats["orphan_prune_skipped"] == 1


# -- cap -------------------------------------------------------------------------------


async def test_cap_drops_versionless_first(disks):
    extra = 3
    records = [
        _orphan(f"o{i:03d}", age_days=1 + i / 100)
        for i in range(MAX_ORPHANED_RECORDS + extra)
    ]
    # the OLDEST records have versions: they must still outlive the rest
    versioned = [r["identity"]["router_id"] for r in records[-extra - 2 :]]
    hass, registry = await _start(disks, records, versioned=versioned)
    orphans = [
        r
        for r in registry.list(include_orphaned=True)
        if r.state is RecordState.ORPHANED
    ]
    assert len(orphans) == MAX_ORPHANED_RECORDS
    assert set(versioned) <= _ids(registry)
    assert registry.stats["orphans_forgotten_capped"] == extra
    events = bus_events(hass, CoreEventType.ROUTER_FORGOTTEN.value)
    assert len(events) == extra
    assert {e["data"]["reason"] for e in events} == {FORGET_CAPPED}
    # the oldest versionless ones went
    dropped = {e["router_id"] for e in events}
    oldest_versionless = records[-extra - 2 - extra : -extra - 2]
    assert dropped == {r["identity"]["router_id"] for r in oldest_versionless}


async def test_cap_reaches_versioned_last(disks):
    records = [
        _orphan(f"v{i:03d}", age_days=1 + i / 100)
        for i in range(MAX_ORPHANED_RECORDS + 1)
    ]
    versioned = [r["identity"]["router_id"] for r in records]
    hass, _registry = await _start(disks, records, versioned=versioned)
    (event,) = bus_events(hass, CoreEventType.ROUTER_FORGOTTEN.value)
    assert event["router_id"] == records[-1]["identity"]["router_id"]  # oldest
    assert event["data"]["has_versions"] is True


def test_forgotten_is_audited_in_security_ring():
    assert CoreEventType.ROUTER_FORGOTTEN.value == "router.forgotten"
    assert CoreEventType.ROUTER_FORGOTTEN in SECURITY_EVENT_TYPES
    assert audit_ring_for(CoreEventType.ROUTER_FORGOTTEN) is AuditRing.SECURITY
