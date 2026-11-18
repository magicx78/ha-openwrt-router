"""Review M2 of PR #56: module events never push core entries off the security ring.

* Core entries of the security ring (``security.*`` and the other core
  security types) have their own capacity, ``SECURITY_AUDIT_MAX_EVENTS``
  (500); only a core entry evicts a core entry.
* Security-relevant MODULE entries share a separate quota:
  ``SECURITY_MODULE_QUOTA`` (100) per module, ``SECURITY_MODULE_MAX_EVENTS``
  (500) for all modules. A module over its quota evicts its own oldest
  entry; when all modules together are full, the module with the most
  entries loses its oldest one (never a module below the new entry's).
* Every dropped module entry is counted (``module_security_evicted``, per
  module in ``summary()["security_module_evicted"]``) and logged once per
  module and run (warning).
* The stored layout is unchanged (one ``security`` list); a store written
  before M2 loads, and the quotas apply on load.
"""

from __future__ import annotations

import logging

import pytest
from core_testkit import FakeDisks, make_hass

from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_models import (
    SECURITY_AUDIT_MAX_EVENTS,
    SECURITY_MODULE_MAX_EVENTS,
    SECURITY_MODULE_QUOTA,
    AuditRing,
    CoreEvent,
    CoreEventType,
    EventResult,
    Severity,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry

R1 = router_id_for_entry("e1")
A = "security_center"
B = "net_diagnostics"


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _log(hass) -> AuditLog:
    log = AuditLog(hass)
    await log.async_load()
    return log


def _register(log: AuditLog, module: str) -> str:
    log.register_event_prefix(f"{module}.", module=module)
    event_type = f"{module}.login_failed"
    log.register_audit_mandatory_types([event_type], module=module)
    return event_type


def _core_security(log: AuditLog, count: int) -> list[str]:
    ids = []
    for i in range(count):
        res = log.emit(
            CoreEventType.AUTHORIZATION_DENIED,
            router_id=R1,
            result=EventResult.DENIED,
            data={"action": "export", "reason": "not_admin", "n": i},
        )
        ids.append(res.event.event_id)
    return ids


def _security_ids(log: AuditLog, source: str | None = None) -> set[str]:
    return {
        e.event_id
        for e in log.events(ring=AuditRing.SECURITY)
        if source is None or e.source == source
    }


def test_constants():
    assert SECURITY_AUDIT_MAX_EVENTS == 500
    assert SECURITY_MODULE_QUOTA == 100
    assert SECURITY_MODULE_MAX_EVENTS == 500


async def test_module_flood_keeps_every_core_entry(disks, caplog):
    hass = make_hass()
    log = await _log(hass)
    flood_type = _register(log, A)
    core_ids = set(_core_security(log, 50))
    caplog.set_level(logging.WARNING)
    for i in range(600):
        res = log.emit(
            flood_type,
            source=A,
            router_id=R1,
            security_relevant=True,
            severity=Severity.WARNING,
            dedup_key=f"k{i}",  # changing keys; mandatory type anyway
            data={"attempt": i},
        )
        assert res.published and not res.deduplicated
    assert core_ids <= _security_ids(log)
    module_entries = [e for e in log.events(ring=AuditRing.SECURITY) if e.source == A]
    assert len(module_entries) == SECURITY_MODULE_QUOTA
    # the newest are kept, the oldest went
    assert module_entries[-1].data["attempt"] == 599
    assert module_entries[0].data["attempt"] == 600 - SECURITY_MODULE_QUOTA
    assert log.stats["module_security_evicted"] == 600 - SECURITY_MODULE_QUOTA
    assert log.stats["evicted_security"] == 0  # no core entry left
    summary = log.summary()
    assert summary["security_module_evicted"] == {A: 600 - SECURITY_MODULE_QUOTA}
    assert summary["security_module_entries"] == {A: SECURITY_MODULE_QUOTA}
    assert summary["security_core_entries"] == 50
    warnings = [r for r in caplog.records if "security ring" in r.getMessage()]
    assert len(warnings) == 1 and A in warnings[0].getMessage()
    # persisted and loaded again: same entries, same quotas
    await log.async_flush()
    again = await _log(hass)
    assert core_ids <= _security_ids(again)
    assert len(_security_ids(again, A)) == SECURITY_MODULE_QUOTA
    assert again.stats["module_security_evicted"] == 0


async def test_core_entries_evict_only_core_entries(disks):
    log = await _log(make_hass())
    flood_type = _register(log, A)
    for i in range(30):
        log.emit(flood_type, source=A, security_relevant=True, data={"i": i})
    module_ids = _security_ids(log, A)
    core_ids = _core_security(log, SECURITY_AUDIT_MAX_EVENTS + 20)
    assert module_ids <= _security_ids(log)  # untouched by the core
    kept_core = _security_ids(log, "core")
    assert len(kept_core) == SECURITY_AUDIT_MAX_EVENTS
    assert kept_core == set(core_ids[20:])
    assert log.stats["evicted_security"] == 20
    assert log.ring_size(AuditRing.SECURITY) == SECURITY_AUDIT_MAX_EVENTS + 30


async def test_one_flooding_module_does_not_evict_another(disks):
    log = await _log(make_hass())
    type_a = _register(log, A)
    type_b = _register(log, B)
    b_ids = set()
    for i in range(40):
        b_ids.add(
            log.emit(
                type_b, source=B, security_relevant=True, data={"i": i}
            ).event.event_id
        )
    core_ids = set(_core_security(log, 10))
    for i in range(600):
        log.emit(type_a, source=A, security_relevant=True, dedup_key=f"x{i}")
    assert b_ids <= _security_ids(log, B)
    assert core_ids <= _security_ids(log)
    assert len(_security_ids(log, A)) == SECURITY_MODULE_QUOTA
    assert log.summary()["security_module_evicted"] == {A: 600 - SECURITY_MODULE_QUOTA}


async def test_total_module_cap_hits_the_largest_module(disks):
    log = await _log(make_hass())
    modules = ["security_center", "net_diagnostics", "wifi_rf", "mod_d", "mod_e"]
    types = {m: _register(log, m) for m in modules}
    for m in modules:
        for i in range(SECURITY_MODULE_QUOTA):
            log.emit(types[m], source=m, security_relevant=True, data={"i": i})
    assert log.summary()["security_module_total"] == SECURITY_MODULE_MAX_EVENTS
    small = "mod_f"
    small_type = _register(log, small)
    first = log.emit(small_type, source=small, security_relevant=True).event.event_id
    # total full: one entry of a full module (oldest of the largest) goes
    assert first in _security_ids(log, small)
    assert log.summary()["security_module_total"] == SECURITY_MODULE_MAX_EVENTS
    assert sum(log.summary()["security_module_evicted"].values()) == 1
    # the small module never loses entries while it is the smallest
    for _ in range(10):
        log.emit(small_type, source=small, security_relevant=True)
    assert len(_security_ids(log, small)) == 11
    assert log.stats["evicted_security"] == 0


async def test_old_store_loads_and_quota_applies(disks):
    hass = make_hass()
    log = await _log(hass)
    flood_type = _register(log, A)
    core_ids = set(_core_security(log, 5))
    template = log.emit(flood_type, source=A, security_relevant=True).event.to_dict()
    # a pre-M2 store (same layout): more module entries than the quota
    stored = {
        "general": [],
        "security": [
            e.to_dict()
            for e in log.events(ring=AuditRing.SECURITY)
            if e.source == "core"
        ]
        + [
            {**template, "event_id": f"evt_{i:032x}", "data": {"i": i}}
            for i in range(SECURITY_MODULE_QUOTA + 25)
        ],
    }
    assert CoreEvent.from_dict(stored["security"][-1]).source == A
    again = AuditLog(hass)
    again._restore(stored)
    assert core_ids <= _security_ids(again, "core")
    assert len(_security_ids(again, A)) == SECURITY_MODULE_QUOTA
    assert again.stats["module_security_evicted"] == 25
    assert set(again._data_to_save()) == {"general", "security"}


async def test_module_cannot_register_as_core(disks):
    log = await _log(make_hass())
    with pytest.raises(ValueError):
        log.register_event_prefix("mod_core.", module="core")
