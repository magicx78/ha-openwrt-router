"""Enterprise core part 1: capability detection (case 10 and the change rules)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from core_testkit import (
    FakeDisks,
    FakeEntry,
    bus_events,
    core_of,
    make_hass,
    repeater_data,
    router_data,
    setup_router,
    ssh_router_data,
)

from custom_components.openwrt_router.capabilities import (
    capability_signature,
    evaluate,
    merge,
)
from custom_components.openwrt_router.core_errors import CapabilityUnavailableError
from custom_components.openwrt_router.core_models import (
    CONFIG_CAPABILITIES,
    OPTION_CONFIG_BACKUP_ENABLED,
    Capability,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    CoreEventType,
    ReachabilityState,
)

CHANGED = CoreEventType.ROUTER_CAPABILITIES_CHANGED.value
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _state(caps, name):
    return caps[str(name)].state


# --- case 10: missing capabilities ---------------------------------------------------


async def test_case10_fritz_repeater_missing_capabilities(disks: FakeDisks) -> None:
    hass = make_hass()
    await setup_router(
        hass, FakeEntry("rep", host="192.168.1.40"), repeater_data("192.168.1.40")
    )
    registry = core_of(hass).registry
    rid = registry.get_by_entry("rep").router_id
    caps = registry.capabilities(rid)

    assert _state(caps, Capability.DATA_SYSTEM_BOARD) is CapabilityState.UNAVAILABLE
    assert caps[Capability.DATA_SYSTEM_BOARD].required_permissions == (
        "ubus:system.board",
    )
    assert _state(caps, Capability.DATA_LLDP) is CapabilityState.UNAVAILABLE
    logs = caps[Capability.DATA_LOGS]
    assert logs.state is CapabilityState.UNAVAILABLE
    assert logs.reason == CapabilityReason.PERMISSION_DENIED
    assert logs.required_permissions == ("ubus:log.read",)
    assert _state(caps, Capability.DATA_UCI) is CapabilityState.UNAVAILABLE
    assert caps[Capability.DATA_UCI].source == "features.uci_available"
    assert _state(caps, Capability.PKG_APK) is CapabilityState.UNKNOWN
    assert _state(caps, Capability.DATA_HOSTAPD_CLIENTS) is CapabilityState.AVAILABLE
    for name in CONFIG_CAPABILITIES:
        assert caps[name].state is CapabilityState.UNAVAILABLE
        assert caps[name].reason == CapabilityReason.NO_PROVIDER

    with pytest.raises(CapabilityUnavailableError) as err:
        registry.require_capability(rid, Capability.DATA_LOGS)
    assert err.value.capability == "data.logs"
    assert err.value.reason == "permission_denied"
    assert err.value.router_id == rid
    with pytest.raises(CapabilityUnavailableError) as err:
        registry.require_capability(rid, Capability.CONFIG_BACKUP)
    assert err.value.reason == "no_provider"
    with pytest.raises(CapabilityUnavailableError) as err:
        registry.require_capability(rid, "security.unknown_thing")
    assert err.value.reason == "not_checked"
    assert not registry.has_capability(rid, Capability.DATA_LOGS)
    registry.require_capability(rid, Capability.DATA_HOSTAPD_CLIENTS)  # no raise


async def test_case10_ssh_fallback_router(disks: FakeDisks) -> None:
    hass = make_hass()
    await setup_router(
        hass, FakeEntry("ssh", host="192.168.1.30"), ssh_router_data(), ssh=True
    )
    registry = core_of(hass).registry
    record = registry.get_by_entry("ssh")
    caps = record.capabilities
    assert record.connection.transport.value == "ssh_fallback"
    assert caps[Capability.TRANSPORT_SSH].state is CapabilityState.AVAILABLE
    assert caps[Capability.TRANSPORT_UBUS].detail == {"ssh_fallback_used": True}
    assert caps[Capability.PKG_OPKG].state is CapabilityState.AVAILABLE
    assert caps[Capability.PKG_APK].state is CapabilityState.UNAVAILABLE
    assert (
        caps[Capability.DATA_DHCP_LEASES].state is CapabilityState.UNKNOWN
    )  # key missing
    assert caps[Capability.DATA_LOGS].reason == CapabilityReason.NO_DATA_YET
    with pytest.raises(CapabilityUnavailableError):
        registry.require_capability(record.router_id, Capability.DATA_UCI)


async def test_case10_capabilities_cost_no_router_call(disks: FakeDisks) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("rep"), repeater_data())
    for _ in range(5):
        coord.poll()
    coord.poll(success=False)
    assert coord.router_calls() == []
    assert core_of(hass).registry.stats["listener_errors"] == 0


# --- change rules -----------------------------------------------------------------------


async def test_first_detection_emits_no_change_event(disks: FakeDisks) -> None:
    hass = make_hass()
    await setup_router(hass, FakeEntry("e1"), router_data())
    assert bus_events(hass, CHANGED) == []
    assert core_of(hass).registry.stats["capability_first_detections"] > 0


async def test_real_change_emits_one_event(disks: FakeDisks) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data())
    coord.poll(data=router_data(log="not_permitted"))
    events = bus_events(hass, CHANGED)
    assert len(events) == 1
    assert events[0]["data"] == {
        "changes": [
            {"capability": "data.logs", "from": "available", "to": "unavailable"}
        ],
        "changed_count": 1,
    }
    coord.poll(data=router_data(log="not_permitted"))  # same data: nothing new
    assert len(bus_events(hass, CHANGED)) == 1


async def test_failed_poll_keeps_capabilities_and_sets_offline(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data())
    registry = core_of(hass).registry
    before = registry.get_by_entry("e1").capabilities
    coord.data = router_data(log="not_permitted", lldp="unavailable")  # stale data
    coord.poll(success=False)
    record = registry.get_by_entry("e1")
    assert record.reachability.state is ReachabilityState.OFFLINE
    assert dict(record.capabilities) == dict(before)
    assert bus_events(hass, CHANGED) == []
    coord.poll(success=True, data=router_data())
    assert registry.get_by_entry("e1").reachability.state is ReachabilityState.ONLINE


async def test_unknown_never_overwrites_known(disks: FakeDisks) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data())
    coord.poll(data=router_data(lldp="error", log="error"))  # hiccups: unknown
    registry = core_of(hass).registry
    caps = registry.get_by_entry("e1").capabilities
    assert caps[Capability.DATA_LLDP].state is CapabilityState.AVAILABLE
    assert caps[Capability.DATA_LOGS].state is CapabilityState.AVAILABLE
    assert registry.stats["capability_kept_stale"] == 2
    assert bus_events(hass, CHANGED) == []


async def test_reevaluated_only_when_the_signature_changes(disks: FakeDisks) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data())
    registry = core_of(hass).registry
    evaluations = registry.stats["capability_evaluations"]
    for _ in range(10):
        data = router_data()
        data.uptime += 60  # volatile data only
        coord.poll(data=data)
    assert registry.stats["capability_evaluations"] == evaluations
    coord.poll(data=router_data(package_manager="opkg"))
    assert registry.stats["capability_evaluations"] == evaluations + 1


async def test_config_capabilities_disabled_by_option(disks: FakeDisks) -> None:
    hass = make_hass()
    entry = FakeEntry("e1", options={OPTION_CONFIG_BACKUP_ENABLED: False})
    await setup_router(hass, entry, router_data())
    caps = core_of(hass).registry.get_by_entry("e1").capabilities
    assert {caps[c].reason for c in CONFIG_CAPABILITIES} == {CapabilityReason.DISABLED}


async def test_config_provider_hook_for_part_two(disks: FakeDisks) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data())
    registry = core_of(hass).registry

    def provider(record):
        return {
            Capability.CONFIG_BACKUP: CapabilityStatus(
                capability=Capability.CONFIG_BACKUP,
                state=CapabilityState.AVAILABLE,
                reason=CapabilityReason.OK,
                source="probe:test",
                detected_at=NOW,
            )
        }

    remove = registry.set_config_capability_provider(provider)
    coord.poll()
    caps = registry.get_by_entry("e1").capabilities
    assert caps[Capability.CONFIG_BACKUP].state is CapabilityState.AVAILABLE
    assert caps[Capability.CONFIG_RESTORE].reason == CapabilityReason.NOT_PROBED
    events = bus_events(hass, CHANGED)
    assert events[-1]["data"]["changes"] == [
        {"capability": "config.backup", "from": "unavailable", "to": "available"}
    ]
    remove()
    coord.poll()
    caps = registry.get_by_entry("e1").capabilities
    assert caps[Capability.CONFIG_BACKUP].reason == CapabilityReason.NO_PROVIDER


def test_merge_keeps_detected_at_of_identical_status() -> None:
    earlier = evaluate(router_data(), uses_ssh_fallback=False, ssh_seen=False, now=NOW)
    later = evaluate(
        router_data(),
        uses_ssh_fallback=False,
        ssh_seen=False,
        now=datetime(2026, 11, 18, tzinfo=UTC),
    )
    result = merge(earlier, later)
    assert not result.stored_changed
    assert result.capabilities[Capability.DATA_LLDP].detected_at == NOW


def test_signature_is_cheap_and_stable() -> None:
    kw = {
        "uses_ssh_fallback": False,
        "ssh_seen": False,
        "config_enabled": True,
        "provider_token": 0,
    }
    assert capability_signature(router_data(), **kw) == capability_signature(
        router_data(), **kw
    )
    assert capability_signature(router_data(), **kw) != capability_signature(
        router_data(lldp="unavailable"), **kw
    )
