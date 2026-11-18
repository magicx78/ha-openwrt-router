"""Follow-up B3: module events on the security ring, module audit-mandatory types.

* ``emit(..., security_relevant=True)`` puts a module's own event on the
  security ring (default: general). The flag is stored and survives a
  restart; the bus payload carries it.
* ``register_audit_mandatory_types(types, *, module)`` makes the module's
  own types (below a prefix it registered) audit-mandatory: never
  deduplicated, every occurrence stored and published. Core types and
  other modules' types are refused.
* Undone by the remover, by unregistering the prefix (``register_event_prefix``
  now returns a remover) and by a core release (the next core starts empty).
* A security-relevant event never bumps a general entry of the same scope.
"""

from __future__ import annotations

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import FakeDisks, bus_events, make_hass

from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_models import (
    AuditRing,
    CoreEvent,
    CoreEventType,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry

R1 = router_id_for_entry("e1")
MOD = "security_center"
PREFIX = "security_center."


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _log(hass) -> AuditLog:
    log = AuditLog(hass)
    await log.async_load()
    return log


def _ring(log: AuditLog, ring: AuditRing) -> list[str]:
    return [e.type for e in log.events(ring=ring)]


async def test_security_relevant_ring(disks):
    hass = make_hass()
    log = await _log(hass)
    log.register_event_prefix(PREFIX, module=MOD)
    plain = log.emit(f"{PREFIX}scan", source=MOD, router_id=R1)
    marked = log.emit(
        f"{PREFIX}intrusion", source=MOD, router_id=R1, security_relevant=True
    )
    assert plain.event.audit_ring is AuditRing.GENERAL
    assert marked.event.audit_ring is AuditRing.SECURITY
    assert marked.event.security_relevant is True
    assert _ring(log, AuditRing.SECURITY) == [f"{PREFIX}intrusion"]
    assert _ring(log, AuditRing.GENERAL) == [f"{PREFIX}scan"]
    payload = bus_events(hass, f"{PREFIX}intrusion")[0]
    assert payload["security_relevant"] is True
    assert bus_events(hass, f"{PREFIX}scan")[0]["security_relevant"] is False


async def test_flag_persists(disks):
    hass = make_hass()
    log = await _log(hass)
    log.register_event_prefix(PREFIX, module=MOD)
    log.emit(f"{PREFIX}intrusion", source=MOD, security_relevant=True)
    await log.async_flush()
    again = await _log(hass)
    (event,) = again.events(ring=AuditRing.SECURITY)
    assert event.security_relevant is True


def test_old_dict_reads():
    """An entry stored before B3 has no flags: defaults."""
    event = CoreEvent.from_dict(
        {
            "event_id": "evt_" + "0" * 32,
            "ts": "2026-11-18T10:00:00+00:00",
            "type": "security_center.scan",
            "source": MOD,
        }
    )
    assert event.security_relevant is False and event.audit_mandatory is False
    assert event.audit_ring is AuditRing.GENERAL
    again = CoreEvent.from_dict(event.to_dict())
    assert again == event


async def test_ring_separates_dedup(disks):
    hass = make_hass()
    log = await _log(hass)
    log.register_event_prefix(PREFIX, module=MOD)
    log.emit(f"{PREFIX}scan", source=MOD, router_id=R1, dedup_key="k")
    second = log.emit(
        f"{PREFIX}scan", source=MOD, router_id=R1, dedup_key="k", security_relevant=True
    )
    assert second.published and not second.deduplicated
    assert _ring(log, AuditRing.SECURITY) == [f"{PREFIX}scan"]
    third = log.emit(
        f"{PREFIX}scan", source=MOD, router_id=R1, dedup_key="k", security_relevant=True
    )
    assert third.deduplicated  # same ring, same scope: a repeat


async def test_mandatory_types(disks):
    hass = make_hass()
    log = await _log(hass)
    log.register_event_prefix(PREFIX, module=MOD)
    log.emit(f"{PREFIX}login", source=MOD, router_id=R1, dedup_key="k")
    remove = log.register_audit_mandatory_types([f"{PREFIX}login"], module=MOD)
    assert log.stats["module_mandatory_types"] == 1
    results = [
        log.emit(f"{PREFIX}login", source=MOD, router_id=R1, dedup_key="k")
        for _ in range(3)
    ]
    assert all(r.published and not r.deduplicated for r in results)
    assert all(r.event.audit_mandatory for r in results)
    assert results[0].event.dedup_scope is None
    remove()
    assert log.stats["module_mandatory_types"] == 0
    first = log.emit(f"{PREFIX}login", source=MOD, router_id=R1, dedup_key="k")
    assert not first.event.audit_mandatory
    assert log.emit(
        f"{PREFIX}login", source=MOD, router_id=R1, dedup_key="k"
    ).deduplicated


async def test_mandatory_refused(disks):
    hass = make_hass()
    log = await _log(hass)
    log.register_event_prefix(PREFIX, module=MOD)
    log.register_event_prefix("net_diagnostics.", module="net_diagnostics")
    for bad in (
        [CoreEventType.BACKUP_CREATED.value],  # a core type
        ["net_diagnostics.ping"],  # another module's type
        ["unregistered.thing"],
        [PREFIX],  # the bare prefix
        ["security.login"],  # reserved namespace
    ):
        with pytest.raises(ValueError):
            log.register_audit_mandatory_types(bad, module=MOD)
    with pytest.raises(ValueError):
        log.register_audit_mandatory_types([f"{PREFIX}x"], module="core")
    assert log.stats["module_mandatory_types"] == 0
    # core types stay as they are
    assert log.emit(CoreEventType.BACKUP_CREATED, router_id=R1).event.audit_ring is (
        AuditRing.GENERAL
    )


async def test_prefix_removal_undoes(disks):
    hass = make_hass()
    log = await _log(hass)
    remove_prefix = log.register_event_prefix(PREFIX, module=MOD)
    log.register_audit_mandatory_types([f"{PREFIX}login"], module=MOD)
    assert MOD in log.registered_modules()
    remove_prefix()
    assert MOD not in log.registered_modules()
    assert log.stats["module_mandatory_types"] == 0
    with pytest.raises(ValueError):
        log.emit(f"{PREFIX}login", source=MOD)
    remove_prefix()  # idempotent
    # registering again starts without the mandatory type
    log.register_event_prefix(PREFIX, module=MOD)
    log.emit(f"{PREFIX}login", source=MOD, dedup_key="k")
    assert log.emit(f"{PREFIX}login", source=MOD, dedup_key="k").deduplicated


async def test_core_release_undoes(disks):
    hass = make_hass()
    first = await _log(hass)
    first.register_event_prefix(PREFIX, module=MOD)
    first.register_audit_mandatory_types([f"{PREFIX}login"], module=MOD)
    await first.async_flush()
    second = await _log(hass)  # the next core's audit log
    assert second.registered_modules() == frozenset()
    assert second.stats["module_mandatory_types"] == 0


async def test_api_surface(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    remove = env.api.register_event_prefix(PREFIX, module=MOD)
    assert callable(remove)
    env.api.register_audit_mandatory_types([f"{PREFIX}login"], module=MOD)
    res = env.api.emit(
        f"{PREFIX}login", source=MOD, router_id=env.rid, security_relevant=True
    )
    assert res.event.audit_ring is AuditRing.SECURITY and res.event.audit_mandatory
    await stop_env(env)
