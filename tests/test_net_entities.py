"""Tests for the network intelligence entities (P6, plan c9).

The entities read only the engine's view (no coordinator, no router call),
unique_ids never match the legacy dynamic patterns, every translation key
exists in strings.json, en.json and de.json, volatile attributes stay out
of the recorder, the maintenance switch drives the engine, and the fleet
entities move to another entry in the entity registry (A9). Router names
are roles.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.const import STATE_ON
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from test_net_engine import FakeDisk, FakeStore, make_hass

from custom_components.openwrt_router import _LEGACY_DYNAMIC_PATTERNS, net_engine
from custom_components.openwrt_router import net_entities as ne
from custom_components.openwrt_router.const import (
    DOMAIN,
    EVENT_INCIDENT,
    UID_FLEET_NET_HEALTH,
)
from custom_components.openwrt_router.logbook import async_describe_events
from custom_components.openwrt_router.net_engine import (
    FleetView,
    NetIntelligence,
    NetView,
    RouterView,
)
from custom_components.openwrt_router.net_rules import RouterScore

G, A = "01JGWENTRY000000000000000GW", "01JAPENTRY000000000000000AP"
COMPONENT = Path(__file__).parent.parent / "custom_components" / "openwrt_router"


@pytest.fixture(autouse=True)
def no_timers() -> Any:
    with patch.object(net_engine, "async_call_later", MagicMock()):
        yield


@pytest.fixture
async def engine() -> NetIntelligence:
    disk = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        intel = NetIntelligence(make_hass())
        await intel.async_load()
    intel.hass.data[net_engine._DATA_KEY] = intel
    for router in (G, A):
        intel.register(router)
    return intel


def ap_data(*, aps: bool = True) -> SimpleNamespace:
    return SimpleNamespace(ap_interfaces=[{"ifname": "phy0-ap0"}] if aps else [])


def setup_all(engine: NetIntelligence, entry_id: str, **kw: Any) -> list[Any]:
    added: list[Any] = []

    def add(entities: Any) -> None:
        added.extend(entities)

    ne.async_setup_sensors(
        engine.hass, entry_id, kw.get("data", ap_data()), kw.get("wan", True), add
    )
    ne.async_setup_binary_sensors(engine.hass, entry_id, add)
    ne.async_setup_switches(engine.hass, entry_id, add)
    for entity in added:
        entity.hass = engine.hass
    return added


def view(engine: NetIntelligence, **router: Any) -> None:
    score = RouterScore(
        score=router.pop("score", 87),
        coverage=0.9,
        areas={"system": {"score": 87, "coverage": 1.0}},
    )
    engine.view = NetView(
        routers={G: RouterView(score=score, **router)},
        fleet=FleetView(
            score=80, coverage=0.8, routers=2, incidents_active=3, critical=True
        ),
    )


# --- set-up and unique ids ----------------------------------------------------------


async def test_unique_ids_avoid_the_legacy_dynamic_patterns(
    engine: NetIntelligence,
) -> None:
    """Plan c9: no new unique_id contains _rate, _ap_, _port_, _radio_, _iface_."""
    entities = setup_all(engine, G)
    ids = {e.unique_id for e in entities}
    assert ids == {f"{G}_{s}" for s in ne.ROUTER_SUFFIXES} | set(ne.FLEET_UNIQUE_IDS)
    for uid in ids:
        for pattern in _LEGACY_DYNAMIC_PATTERNS:
            assert pattern not in uid, (uid, pattern)
    for pattern in ("_rate", "_ap_", "_port_", "_radio_", "_iface_"):
        assert pattern in _LEGACY_DYNAMIC_PATTERNS
    assert len(ids) == 10  # 7 per router + 3 fleet


async def test_second_router_gets_no_fleet_entities(engine: NetIntelligence) -> None:
    setup_all(engine, G)
    second = {e.unique_id for e in setup_all(engine, A)}
    assert second == {f"{A}_{s}" for s in ne.ROUTER_SUFFIXES}


async def test_wifi_sensors_only_with_ap_interfaces(engine: NetIntelligence) -> None:
    ids = {e.unique_id for e in setup_all(engine, A, data=ap_data(aps=False))}
    assert f"{A}_wifi_reconnects_1h" not in ids
    assert f"{A}_wifi_auth_errors_1h" not in ids
    assert f"{A}_net_health" in ids


async def test_wan_sensor_disabled_by_default_without_wan(
    engine: NetIntelligence,
) -> None:
    def wan_entity(**kw: Any) -> Any:
        return next(
            e
            for e in setup_all(engine, G, **kw)
            if e.unique_id.endswith("_wan_stability")
        )

    assert wan_entity(wan=False).entity_registry_enabled_default is False
    assert wan_entity(wan=True).entity_registry_enabled_default is True


async def test_no_entities_without_engine_or_unregistered_router(
    engine: NetIntelligence,
) -> None:
    assert setup_all(engine, "not-registered") == []
    engine.hass.data.pop(net_engine._DATA_KEY)
    assert setup_all(engine, G) == []


async def test_platforms_set_parallel_updates() -> None:
    from custom_components.openwrt_router import binary_sensor, sensor, switch

    assert sensor.PARALLEL_UPDATES == 0
    assert binary_sensor.PARALLEL_UPDATES == 0
    assert switch.PARALLEL_UPDATES == 1  # router actions one at a time


# --- entities read the engine only --------------------------------------------------


async def test_entities_read_the_engine_view_only(engine: NetIntelligence) -> None:
    entities = {e.unique_id: e for e in setup_all(engine, G)}
    for entity in entities.values():
        assert not isinstance(entity, CoordinatorEntity)
        assert entity.should_poll is False
        assert entity.has_entity_name is True
        assert entity.translation_key
    view(
        engine,
        incidents_active=2,
        critical=True,
        reconnects_1h=4,
        auth_errors_1h=1,
        wan_reconnects_24h=3,
    )
    get = entities.__getitem__
    assert get(f"{G}_net_health").native_value == 87
    assert get(f"{G}_net_health").extra_state_attributes == {
        "areas": {"system": {"score": 87, "coverage": 1.0}},
        "coverage": 0.9,
        "maintenance": False,
    }
    assert get(f"{G}_incidents_active").native_value == 2
    assert get(f"{G}_wifi_reconnects_1h").native_value == 4
    assert get(f"{G}_wifi_auth_errors_1h").native_value == 1
    assert get(f"{G}_wan_stability").native_value == 3
    assert get(f"{G}_incident_critical").is_on is True
    assert get(UID_FLEET_NET_HEALTH).native_value == 80
    assert get(UID_FLEET_NET_HEALTH).extra_state_attributes == {
        "coverage": 0.8,
        "routers": 2,
        "maintenance": 0,
    }
    assert get("openwrt_router_fleet_incidents_active").native_value == 3
    assert get("openwrt_router_fleet_incident_critical").is_on is True
    for entity in entities.values():
        assert entity.available


async def test_unknown_score_is_none_never_100(engine: NetIntelligence) -> None:
    [health] = [e for e in setup_all(engine, G) if e.unique_id == f"{G}_net_health"]
    view(engine, score=None)
    assert health.native_value is None


async def test_entities_unavailable_without_engine_or_view(
    engine: NetIntelligence,
) -> None:
    entities = setup_all(engine, G)
    engine.view = NetView()  # no data yet
    router_entities = [e for e in entities if e.unique_id.startswith(G)]
    for entity in router_entities:
        if not entity.unique_id.endswith("_maintenance_mode"):
            assert not entity.available, entity.unique_id
    engine.hass.data.pop(net_engine._DATA_KEY)
    for entity in entities:
        assert not entity.available, entity.unique_id


async def test_module_has_no_network_access() -> None:
    source = inspect.getsource(ne)
    for forbidden in ("from .api", "aiohttp", "async_get_clientsession", "coordinator"):
        assert forbidden not in source.split('"""', 2)[2], forbidden


async def test_dispatcher_signal_writes_state(engine: NetIntelligence) -> None:
    [health] = [e for e in setup_all(engine, G) if e.unique_id == f"{G}_net_health"]
    with (
        patch.object(ne, "async_dispatcher_connect") as connect,
        patch.object(health, "async_write_ha_state") as write,
    ):
        health.platform = MagicMock()
        await health.async_added_to_hass()
        signal, handler = connect.call_args.args[1:]
        assert signal == "openwrt_router_net_intel_updated"
        handler()
    write.assert_called_once()


async def test_device_and_fleet_without_device(engine: NetIntelligence) -> None:
    entities = setup_all(engine, G)
    for entity in entities:
        info = entity.device_info
        if entity.unique_id.startswith("openwrt_router_fleet_"):
            assert info is None
        else:
            assert info == DeviceInfo(identifiers={(DOMAIN, G)})


# --- maintenance switch -------------------------------------------------------------


async def test_maintenance_switch_drives_the_engine(engine: NetIntelligence) -> None:
    [switch] = [
        e for e in setup_all(engine, G) if e.unique_id.endswith("_maintenance_mode")
    ]
    assert switch.entity_category == "config"
    with patch.object(switch, "async_write_ha_state"):
        await switch.async_turn_on()
        assert switch.is_on is True and engine.router_maintenance(G)
        await switch.async_turn_off()
        assert switch.is_on is False and not engine.router_maintenance(G)


@pytest.mark.parametrize(("last", "expected"), [(STATE_ON, True), ("off", False)])
async def test_maintenance_switch_restores_its_state(
    engine: NetIntelligence, last: str, expected: bool
) -> None:
    [switch] = [
        e for e in setup_all(engine, G) if e.unique_id.endswith("_maintenance_mode")
    ]
    if not expected:
        engine.set_maintenance(G, True)  # store said on, the user set off
    switch.async_get_last_state = AsyncMock(return_value=SimpleNamespace(state=last))
    with (
        patch.object(ne, "async_dispatcher_connect"),
        patch("homeassistant.helpers.restore_state.RestoreEntity.async_added_to_hass"),
    ):
        await switch.async_added_to_hass()
    assert engine.router_maintenance(G) is expected


async def test_maintenance_switch_without_engine(engine: NetIntelligence) -> None:
    [switch] = [
        e for e in setup_all(engine, G) if e.unique_id.endswith("_maintenance_mode")
    ]
    engine.hass.data.pop(net_engine._DATA_KEY)
    assert switch.is_on is None and not switch.available
    with patch.object(switch, "async_write_ha_state"):
        await switch.async_turn_on()  # no error


# --- recorder and translations -------------------------------------------------------


def test_unrecorded_attributes_cover_the_attributes() -> None:
    assert ne.NetHealthSensor._unrecorded_attributes >= {
        "areas",
        "coverage",
        "maintenance",
    }
    assert ne.FleetHealthSensor._unrecorded_attributes >= {
        "coverage",
        "routers",
        "maintenance",
    }


@pytest.mark.parametrize(
    "name", ["strings.json", "translations/en.json", "translations/de.json"]
)
async def test_every_translation_key_exists(engine: NetIntelligence, name: str) -> None:
    data = json.loads((COMPONENT / name).read_text(encoding="utf-8"))
    for entity in setup_all(engine, G):
        if isinstance(entity, ne.SwitchEntity):
            platform = "switch"
        elif isinstance(entity, ne.BinarySensorEntity):
            platform = "binary_sensor"
        else:
            platform = "sensor"
        entry = data["entity"][platform].get(entity.translation_key)
        assert entry and entry["name"], (name, platform, entity.translation_key)


# --- fleet anchor in the entity registry (A9) --------------------------------------


def test_fleet_entity_moves_to_the_new_anchor_entry() -> None:
    """A9: the same unique_id from another config entry takes it over."""
    hass = MagicMock()
    hass.data = {}
    registry = er.EntityRegistry(hass)
    registry.entities = er.EntityRegistryItems()
    registry.deleted_entities = {}
    registry.async_schedule_save = lambda: None

    def entry(entry_id: str) -> MagicMock:
        e = MagicMock()
        e.entry_id = entry_id
        e.domain = DOMAIN
        e.disabled_by = None
        e.pref_disable_new_entities = False
        return e

    old, new = entry(G), entry(A)
    hass.config_entries.async_get_entry.side_effect = {G: old, A: new}.get
    first = registry.async_get_or_create(
        "sensor",
        DOMAIN,
        UID_FLEET_NET_HEALTH,
        config_entry=old,
        suggested_object_id="fleet_network_health",
    )
    moved = registry.async_get_or_create(
        "sensor", DOMAIN, UID_FLEET_NET_HEALTH, config_entry=new
    )
    assert moved.entity_id == first.entity_id
    assert moved.config_entry_id == A
    assert len(registry.entities) == 1


# --- logbook ------------------------------------------------------------------------


def test_logbook_describes_the_incident_event() -> None:
    described: dict[str, Any] = {}
    async_describe_events(
        MagicMock(), lambda domain, name, fn: described.__setitem__(name, fn)
    )
    describe = described[EVENT_INCIDENT]
    event = SimpleNamespace(
        data={
            "state": "opened",
            "type": "router_unreachable",
            "severity": "warning",
            "cause": "router_unreachable",
            "cause_status": "confirmed",
            "routers": ["Router AP"],
        }
    )
    assert describe(event) == {
        "name": "Router AP",
        "message": "incident opened: router unreachable (warning, cause router_unreachable)",
    }
    fleet = SimpleNamespace(
        data={
            "state": "resolved",
            "type": "lan_unreachable",
            "severity": "critical",
            "cause": "lan_unreachable",
            "cause_status": "hypothesis",
            "routers": [],
        }
    )
    result = describe(fleet)
    assert result["name"] == "OpenWrt network"
    assert result["message"].endswith("(suspected))")
