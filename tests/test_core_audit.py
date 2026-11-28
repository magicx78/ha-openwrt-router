"""Enterprise core part 1: event and audit capture (case 14)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from core_testkit import SECRET, FakeDisks, bus_events, make_hass

from custom_components.openwrt_router.core_audit import AuditLog, migrate_audit_store
from custom_components.openwrt_router.core_masking import MASK, mask_for_output
from custom_components.openwrt_router.core_models import (
    AUDIT_STORE_KEY,
    EVENT_CORE,
    AuditRing,
    CoreEventType,
    Severity,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry

R1 = router_id_for_entry("e1")
R2 = router_id_for_entry("e2")
T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
REGISTERED = CoreEventType.ROUTER_REGISTERED
ADOPTED = CoreEventType.ROUTER_ADOPTED
CAPS = CoreEventType.ROUTER_CAPABILITIES_CHANGED


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _log(hass=None) -> AuditLog:
    log = AuditLog(hass or make_hass())
    await log.async_load()
    return log


async def test_case14_rings_are_separate_and_bounded(disks: FakeDisks) -> None:
    log = await _log()
    for i in range(1105):
        log.emit(REGISTERED, router_id=R1, now=T0 + timedelta(seconds=i))
    for i in range(505):
        log.emit(ADOPTED, router_id=R1, now=T0 + timedelta(seconds=i))
    assert log.ring_size(AuditRing.GENERAL) == 1100  # 1000 before 1.53.0
    assert log.ring_size(AuditRing.SECURITY) == 500
    assert log.stats["evicted_general"] == 5
    assert log.stats["evicted_security"] == 5
    # the flood of general events never pushed out security entries
    assert len(log.events(ring=AuditRing.SECURITY)) == 500


async def test_case14_retention_drops_old_entries(disks: FakeDisks) -> None:
    log = await _log()
    log.emit(REGISTERED, router_id=R1, now=T0)
    log.emit(REGISTERED, router_id=R1, now=T0 + timedelta(days=91))
    assert log.ring_size(AuditRing.GENERAL) == 1
    assert log.stats["expired"] == 1


async def test_case14_retention_applies_on_load(disks: FakeDisks) -> None:
    hass = make_hass()
    log = await _log(hass)
    log.emit(REGISTERED, router_id=R2, now=datetime.now(UTC) - timedelta(days=1))
    log.emit(
        REGISTERED, router_id=R1, now=datetime.now(UTC) - timedelta(days=89, hours=23)
    )
    await log.async_flush()  # both still inside the 90 days when written
    stored = disks[AUDIT_STORE_KEY].data["data"]["general"]
    stored[1]["ts"] = (datetime.now(UTC) - timedelta(days=100)).isoformat()
    again = await _log(hass)
    assert [e.router_id for e in again.events()] == [R2]
    assert again.stats["expired"] == 1


async def test_case14_bus_payload_is_masked(disks: FakeDisks) -> None:
    hass = make_hass()
    log = await _log(hass)
    result = log.emit(
        REGISTERED,
        router_id=R1,
        data={
            "password": SECRET,
            "note": f"url http://root:{SECRET}@10.0.0.1/",
            "count": 3,
        },
    )
    assert result.published
    (payload,) = bus_events(hass)
    assert payload["data"]["password"] == MASK
    assert SECRET not in str(payload)
    assert payload["data"]["count"] == 3
    assert payload["router_id"] == R1
    assert hass.fired[0][0] == EVENT_CORE
    # stored entry: secret keys masked always, free text on output
    stored = log.events()[0].to_dict()
    assert stored["data"]["password"] == MASK
    assert SECRET not in str(mask_for_output(stored))


async def test_case14_dedup_counts_repeats_and_does_not_publish(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    log = await _log(hass)
    first = log.emit(CAPS, router_id=R1, dedup_key="k1", now=T0)
    again = log.emit(CAPS, router_id=R1, dedup_key="k1", now=T0 + timedelta(hours=1))
    assert first.published and not again.published and again.deduplicated
    assert again.event.event_id == first.event.event_id
    assert again.event.repeat_count == 1
    assert again.event.last_repeat_at == T0 + timedelta(hours=1)
    assert log.events()[0].repeat_count == 1  # the stored entry was updated
    assert len(bus_events(hass)) == 1
    assert log.stats["deduplicated"] == 1
    # after the cooldown it is published again
    third = log.emit(CAPS, router_id=R1, dedup_key="k1", now=T0 + timedelta(hours=25))
    assert third.published


async def test_case14_dedup_never_swallows_other_router_or_type(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    log = await _log(hass)
    log.emit(CAPS, router_id=R1, dedup_key="k", now=T0)
    other_router = log.emit(CAPS, router_id=R2, dedup_key="k", now=T0)
    other_type = log.emit(
        CoreEventType.ROUTER_IDENTITY_CHANGED, router_id=R1, dedup_key="k", now=T0
    )
    other_key = log.emit(CAPS, router_id=R1, dedup_key="k2", now=T0)
    assert other_router.published and other_type.published and other_key.published
    assert len(bus_events(hass)) == 4


async def test_case14_mandatory_types_ignore_dedup(disks: FakeDisks) -> None:
    hass = make_hass()
    log = await _log(hass)
    log.emit(ADOPTED, router_id=R1, dedup_key="same", now=T0)
    second = log.emit(ADOPTED, router_id=R1, dedup_key="same", now=T0)
    assert second.published and not second.deduplicated
    assert len(log.events(types=[ADOPTED])) == 2


async def test_case14_reset_dedup_publishes_the_next_one(disks: FakeDisks) -> None:
    hass = make_hass()
    log = await _log(hass)
    log.emit(CAPS, router_id=R1, dedup_key="drift-1", now=T0)
    assert log.reset_dedup(R1, CAPS) == 1
    assert log.emit(CAPS, router_id=R1, dedup_key="drift-1", now=T0).published


async def test_case14_dedup_window_survives_a_restart(disks: FakeDisks) -> None:
    hass = make_hass()
    log = await _log(hass)
    now = datetime.now(UTC)
    log.emit(CAPS, router_id=R1, dedup_key="k", now=now)
    await log.async_flush()
    again = await _log(hass)
    assert again.emit(
        CAPS, router_id=R1, dedup_key="k", now=now + timedelta(minutes=5)
    ).deduplicated


async def test_case14_query_filters(disks: FakeDisks) -> None:
    log = await _log()
    log.emit(REGISTERED, router_id=R1, now=T0, correlation_id="cor_" + "1" * 32)
    log.emit(CAPS, router_id=R1, now=T0 + timedelta(hours=1))
    log.emit(REGISTERED, router_id=R2, now=T0 + timedelta(hours=2))
    log.emit(ADOPTED, router_id=R2, now=T0 + timedelta(hours=3))
    assert len(log.events(router_id=R1)) == 2
    assert [e.type for e in log.events(types=[CAPS])] == [CAPS]
    assert (
        len(log.events(since=T0 + timedelta(minutes=30), until=T0 + timedelta(hours=2)))
        == 2
    )
    assert len(log.events(correlation_id="cor_" + "1" * 32)) == 1
    assert [e.type for e in log.events()] == [
        REGISTERED,
        CAPS,
        REGISTERED,
        ADOPTED,
    ]  # both rings, by time
    assert len(log.events(limit=1)) == 1 and log.events(limit=1)[0].type == ADOPTED


async def test_case14_listeners_subscribe_unsubscribe_and_errors_counted(
    disks: FakeDisks,
) -> None:
    log = await _log()
    seen: list[str] = []
    unsubscribe = log.subscribe(lambda e: seen.append(e.type))

    def broken(event):
        raise RuntimeError("listener bug")

    log.subscribe(broken)
    log.emit(REGISTERED, router_id=R1)
    assert seen == [REGISTERED]
    assert log.stats["listener_errors"] == 1
    unsubscribe()
    log.emit(REGISTERED, router_id=R2)
    assert seen == [REGISTERED]
    assert log.listener_count == 1


async def test_case14_module_events_need_a_registered_prefix(disks: FakeDisks) -> None:
    log = await _log()
    with pytest.raises(ValueError):
        log.emit(REGISTERED, source="security_center")  # core namespace
    with pytest.raises(ValueError):
        log.emit("security_center.port_scan", source="security_center")
    with pytest.raises(ValueError):
        log.register_event_prefix("router.", module="x")
    log.register_event_prefix("security_center.", module="security_center")
    result = log.emit(
        "security_center.port_scan",
        source="security_center",
        router_id=R1,
        severity=Severity.WARNING,
        dedup_key="port_scan",
    )
    assert result.published


async def test_case14_bus_failure_is_counted_not_raised(disks: FakeDisks) -> None:
    hass = make_hass()
    hass.bus.async_fire.side_effect = RuntimeError("bus down")
    log = await _log(hass)
    result = log.emit(REGISTERED, router_id=R1)
    assert not result.published
    assert log.stats["bus_errors"] == 1
    assert len(log.events()) == 1  # still audited


async def test_case14_corrupt_audit_store_is_kept_and_reported(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    disks[AUDIT_STORE_KEY].data = {"version": 1, "minor_version": 1, "data": "garbage"}
    log = await _log(hass)
    assert log.load_failed and log.backed_up
    assert disks[AUDIT_STORE_KEY].backups == 1
    (event,) = log.events(types=[CoreEventType.STORE_RECOVERED])
    assert event.data["store"] == AUDIT_STORE_KEY


async def test_case14_unreadable_entries_are_skipped_and_counted(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    good = (await _log(hass)).emit(REGISTERED, router_id=R1).event.to_dict()
    disks[AUDIT_STORE_KEY].data = {
        "version": 1,
        "minor_version": 1,
        "data": {"general": [good, {"type": ""}, "x"], "security": []},
    }
    log = await _log(hass)
    assert len(log.events()) == 1
    assert log.stats["skipped_on_load"] == 2


def test_audit_store_migration() -> None:
    assert migrate_audit_store(1, 0, {}) == {"general": [], "security": []}
    with pytest.raises(NotImplementedError):
        migrate_audit_store(2, 0, {})
