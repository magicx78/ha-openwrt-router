"""General audit ring: a guaranteed share per owner (core or module).

Before: the general ring (``AUDIT_MAX_EVENTS`` = 1000) was one FIFO, so a
loud module (traffic, WiFi RF, ...) pushed every older entry of the core and
of the other modules out of it.

Now (pattern of the security ring, review M2): entries are counted per owner
(by type: core types belong to the core). The ring stays hard at 1000; when
it is full, the oldest entry of an owner above its share goes
(``AUDIT_CORE_SHARE`` 400, ``AUDIT_MODULE_SHARE`` 100 per module, six
modules). An owner at or below its share never loses an entry to another.
Dropped entries are counted (``evicted_general``, per owner in
``summary()["general_evicted"]``). The stored layout is unchanged.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from core_testkit import FakeDisks, make_hass

from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_models import (
    AUDIT_CORE_SHARE,
    AUDIT_MAX_EVENTS,
    AUDIT_MODULE_SHARE,
    AUDIT_SHARED_MODULES,
    AuditRing,
    CoreEvent,
    CoreEventType,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry

R1 = router_id_for_entry("e1")
LOUD = "traffic_analytics"
QUIET = "net_diagnostics"


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _log(hass=None) -> AuditLog:
    log = AuditLog(hass or make_hass())
    await log.async_load()
    return log


def _register(log: AuditLog, module: str) -> str:
    log.register_event_prefix(f"{module}.", module=module)
    return f"{module}.sample"


def _module(log: AuditLog, module: str, count: int, start: int = 0) -> list[str]:
    event_type = f"{module}.sample"
    return [
        log.emit(event_type, source=module, router_id=R1, data={"i": i}).event.event_id
        for i in range(start, start + count)
    ]


def _core(log: AuditLog, count: int) -> list[str]:
    return [
        log.emit(
            CoreEventType.ROUTER_REGISTERED, router_id=R1, data={"i": i}
        ).event.event_id
        for i in range(count)
    ]


def _general_ids(log: AuditLog, source: str | None = None) -> set[str]:
    return {
        e.event_id
        for e in log.events(ring=AuditRing.GENERAL)
        if source is None or e.source == source
    }


async def test_loud_module_keeps_other_owners_entries(disks) -> None:
    log = await _log()
    _register(log, LOUD)
    _register(log, QUIET)
    quiet_ids = set(_module(log, QUIET, 10))
    core_ids = {
        log.emit(CoreEventType.ROUTER_REGISTERED, router_id=R1).event.event_id
        for _ in range(20)
    }
    loud_ids = _module(log, LOUD, AUDIT_MAX_EVENTS + 200)
    assert log.ring_size(AuditRing.GENERAL) == AUDIT_MAX_EVENTS
    assert quiet_ids <= _general_ids(log)
    assert core_ids <= _general_ids(log)
    # the loud module lost its own oldest entries, and only those
    kept = AUDIT_MAX_EVENTS - 30
    assert _general_ids(log, LOUD) == set(loud_ids[-kept:])
    assert log.stats["evicted_general"] == 230
    summary = log.summary()
    assert summary["general_evicted"] == {LOUD: 230}
    assert summary["general_core_entries"] == 20
    assert summary["general_module_entries"] == {LOUD: kept, QUIET: 10}
    assert summary["general"] == AUDIT_MAX_EVENTS


def test_shares_add_up_to_the_hard_limit() -> None:
    assert AUDIT_MAX_EVENTS == 1000
    assert AUDIT_MODULE_SHARE == 100
    assert AUDIT_SHARED_MODULES == 6
    assert AUDIT_CORE_SHARE == 400
    assert AUDIT_CORE_SHARE + AUDIT_SHARED_MODULES * AUDIT_MODULE_SHARE == (
        AUDIT_MAX_EVENTS
    )


async def test_core_flood_keeps_module_entries(disks) -> None:
    log = await _log()
    _register(log, QUIET)
    quiet_ids = set(_module(log, QUIET, 50))
    core_ids = _core(log, AUDIT_MAX_EVENTS + 100)
    assert quiet_ids <= _general_ids(log)
    assert _general_ids(log, "core") == set(core_ids[-(AUDIT_MAX_EVENTS - 50) :])
    assert log.ring_size(AuditRing.GENERAL) == AUDIT_MAX_EVENTS
    assert log.summary()["general_evicted"] == {"core": 150}


async def test_module_flood_cuts_the_core_down_to_its_share_only(disks) -> None:
    log = await _log()
    _register(log, LOUD)
    core_ids = _core(log, AUDIT_CORE_SHARE + 50)
    loud_ids = _module(log, LOUD, AUDIT_MAX_EVENTS)
    # the core was above its share: its oldest 50 went first (oldest of all
    # owners above their share), then only the module's own entries
    assert _general_ids(log, "core") == set(core_ids[50:])
    kept = AUDIT_MAX_EVENTS - AUDIT_CORE_SHARE
    assert _general_ids(log, LOUD) == set(loud_ids[-kept:])
    assert log.summary()["general_evicted"] == {
        "core": 50,
        LOUD: AUDIT_MAX_EVENTS - kept,
    }
    assert log.stats["evicted_general"] == 50 + AUDIT_MAX_EVENTS - kept


def _six_modules(log: AuditLog) -> list[str]:
    modules = [
        "config_manager",
        "net_diagnostics",
        "security_center",
        "wifi_rf",
        "traffic_analytics",
        "extra_module",
    ]
    for module in modules:
        _register(log, module)
    return modules


async def test_all_at_share_ring_exactly_full(disks) -> None:
    log = await _log()
    modules = _six_modules(log)
    core_ids = set(_core(log, AUDIT_CORE_SHARE))
    ids = {m: _module(log, m, AUDIT_MODULE_SHARE) for m in modules}
    assert log.ring_size(AuditRing.GENERAL) == AUDIT_MAX_EVENTS
    assert log.stats["evicted_general"] == 0  # exactly full: nothing went
    assert log.summary()["general_evicted"] == {}
    # one more entry of one module: only that module's own oldest entry goes
    _module(log, "wifi_rf", 1, start=AUDIT_MODULE_SHARE)
    assert log.ring_size(AuditRing.GENERAL) == AUDIT_MAX_EVENTS
    assert ids["wifi_rf"][0] not in _general_ids(log)
    assert set(ids["wifi_rf"][1:]) <= _general_ids(log)
    assert core_ids <= _general_ids(log)
    for module in modules:
        if module != "wifi_rf":
            assert _general_ids(log, module) == set(ids[module])
    assert log.summary()["general_evicted"] == {"wifi_rf": 1}
    # one more core entry: the core's own oldest goes, no module entry
    _core(log, 1)
    assert len(_general_ids(log, "core")) == AUDIT_CORE_SHARE
    assert log.summary()["general_evicted"] == {"wifi_rf": 1, "core": 1}


async def test_all_below_share_nobody_loses(disks) -> None:
    log = await _log()
    modules = _six_modules(log)
    core_ids = set(_core(log, 10))
    ids = {m: set(_module(log, m, 20)) for m in modules}
    assert log.stats["evicted_general"] == 0
    assert core_ids <= _general_ids(log)
    for module in modules:
        assert _general_ids(log, module) == ids[module]


async def test_more_modules_than_shares_never_cost_core_entries(disks) -> None:
    log = await _log()
    modules = [*_six_modules(log), "seventh_module"]
    _register(log, "seventh_module")
    core_ids = set(_core(log, AUDIT_CORE_SHARE))
    for module in modules[:-1]:
        _module(log, module, AUDIT_MODULE_SHARE)
    # ring full, nobody above his share: the newcomer takes from the module
    # with the most entries (fallback of the security ring), never the core
    seventh = _module(log, "seventh_module", 3)
    assert set(seventh) <= _general_ids(log)
    assert core_ids <= _general_ids(log)
    assert log.ring_size(AuditRing.GENERAL) == AUDIT_MAX_EVENTS
    entries = log.summary()["general_module_entries"]
    assert entries["seventh_module"] == 3
    assert sorted(entries.values()) == [3, 99, 99, 99, 100, 100, 100]
    assert log.summary()["general_core_entries"] == AUDIT_CORE_SHARE
    assert "core" not in log.summary()["general_evicted"]
    assert log.stats["evicted_general"] == 3


async def test_old_store_over_share_is_not_cut_on_load(disks) -> None:
    hass = make_hass()
    log = await _log(hass)
    _register(log, LOUD)
    _register(log, QUIET)
    loud_template = log.emit(f"{LOUD}.sample", source=LOUD).event.to_dict()
    quiet_template = log.emit(f"{QUIET}.sample", source=QUIET).event.to_dict()
    core_template = log.emit(CoreEventType.ROUTER_REGISTERED).event.to_dict()
    # a store written before the shares: the loud module holds 900 entries
    stored = {
        "general": [{**core_template, "event_id": f"evt_{i:032x}"} for i in range(50)]
        + [{**quiet_template, "event_id": f"evt_{i:032x}"} for i in range(50, 100)]
        + [{**loud_template, "event_id": f"evt_{i:032x}"} for i in range(100, 1000)],
        "security": [],
    }
    again = AuditLog(hass)
    again._restore(stored)
    assert again.ring_size(AuditRing.GENERAL) == AUDIT_MAX_EVENTS
    assert again.stats["evicted_general"] == 0  # nothing dropped on load
    assert again.summary()["general_module_entries"] == {LOUD: 900, QUIET: 50}
    assert again.summary()["general_core_entries"] == 50
    assert set(again._data_to_save()) == {"general", "security"}
    # the next entry (from the quiet module) takes from the loud one only
    again.register_event_prefix(f"{QUIET}.", module=QUIET)
    _module(again, QUIET, 1)
    assert again.summary()["general_module_entries"] == {LOUD: 899, QUIET: 51}
    assert again.summary()["general_evicted"] == {LOUD: 1}
    assert again.summary()["general_core_entries"] == 50


async def test_old_store_over_the_limit_is_cut_by_share(disks) -> None:
    hass = make_hass()
    log = await _log(hass)
    _register(log, LOUD)
    loud_template = log.emit(f"{LOUD}.sample", source=LOUD).event.to_dict()
    core_template = log.emit(CoreEventType.ROUTER_REGISTERED).event.to_dict()
    stored = {
        "general": [{**core_template, "event_id": f"evt_{i:032x}"} for i in range(100)]
        + [{**loud_template, "event_id": f"evt_{i:032x}"} for i in range(100, 1050)],
        "security": [],
    }
    again = AuditLog(hass)
    again._restore(stored)
    assert again.ring_size(AuditRing.GENERAL) == AUDIT_MAX_EVENTS
    assert again.stats["evicted_general"] == 50
    assert again.summary()["general_evicted"] == {LOUD: 50}
    assert again.summary()["general_core_entries"] == 100


async def test_persisted_ring_loads_with_the_same_counts(disks) -> None:
    hass = make_hass()
    log = await _log(hass)
    _register(log, LOUD)
    _register(log, QUIET)
    _module(log, QUIET, 7)
    _core(log, 9)
    _module(log, LOUD, AUDIT_MAX_EVENTS + 10)
    await log.async_flush()
    again = await _log(hass)
    assert again.ring_size(AuditRing.GENERAL) == AUDIT_MAX_EVENTS
    assert (
        again.summary()["general_module_entries"]
        == log.summary()["general_module_entries"]
    )
    assert again.summary()["general_core_entries"] == 9
    assert again.stats["evicted_general"] == 0


async def test_events_stay_oldest_first_after_quota_evictions(disks) -> None:
    log = await _log()
    _register(log, LOUD)
    _register(log, QUIET)
    t0 = datetime.now(UTC) - timedelta(days=1)
    for i in range(AUDIT_MAX_EVENTS + 50):
        if i % 100 == 0:
            source, event_type = QUIET, f"{QUIET}.sample"
        else:
            source, event_type = LOUD, f"{LOUD}.sample"
        log.emit(
            event_type, source=source, data={"i": i}, now=t0 + timedelta(seconds=i)
        )
    events = log.events(ring=AuditRing.GENERAL)
    stamps = [e.ts for e in events]
    assert stamps == sorted(stamps)
    assert [e.ts for e in log._rings[AuditRing.GENERAL]] == stamps
    # every quiet entry survived the evictions from the middle of the ring
    assert [e.data["i"] for e in events if e.source == QUIET] == list(
        range(0, AUDIT_MAX_EVENTS + 50, 100)
    )
    newest = log.events(ring=AuditRing.GENERAL, limit=3)
    assert newest == events[-3:]


async def test_retention_counts_owners_down(disks) -> None:
    log = await _log()
    _register(log, QUIET)
    old = datetime.now(UTC) - timedelta(days=95)
    for i in range(5):
        log.emit(f"{QUIET}.sample", source=QUIET, now=old + timedelta(seconds=i))
    assert log.summary()["general_module_entries"] == {QUIET: 5}
    log.emit(CoreEventType.ROUTER_REGISTERED)
    assert log.summary()["general_module_entries"] == {}
    assert log.summary()["general_core_entries"] == 1
    assert log.stats["expired"] == 5
    assert log.stats["evicted_general"] == 0


async def test_repeat_does_not_change_the_counts(disks) -> None:
    log = await _log()
    first = log.emit(CoreEventType.ROUTER_REGISTERED, router_id=R1, dedup_key="k")
    again = log.emit(CoreEventType.ROUTER_REGISTERED, router_id=R1, dedup_key="k")
    assert again.deduplicated and not again.published
    assert again.event.event_id == first.event.event_id
    assert log.summary()["general_core_entries"] == 1
    assert isinstance(log.events()[0], CoreEvent)
