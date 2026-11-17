"""Network intelligence entities (plan 2026-11-16, P6, table c9).

Every entity here reads the engine's view (``NetIntelligence.view``, built
after each machine step) and updates when the engine sends
``SIGNAL_NET_INTEL``. None of them talks to a router or polls: the numbers
come from data the coordinators already fetched.

Per router (``unique_id`` ``f"{entry_id}_{suffix}"``, on the router device):
health score, active incidents, Wi-Fi reconnects and authentication errors
in the last hour (only with AP interfaces), WAN reconnects in 24 h
(disabled by default without WAN), a critical-incident problem sensor and
the maintenance switch.

Fleet (``unique_id`` ``openwrt_router_fleet_*``, no device): health score,
active incidents and a critical-incident problem sensor. One set per HA
instance, created by the anchor entry (``NetIntelligence.claim_fleet``).
The engine is looked up on every read (it is replaced after the last
unload), never kept.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.components.switch import SwitchEntity
from homeassistant.const import STATE_OFF, STATE_ON, EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import (
    DOMAIN,
    SIGNAL_NET_INTEL,
    SUFFIX_INCIDENT_CRITICAL,
    SUFFIX_INCIDENTS_ACTIVE,
    SUFFIX_MAINTENANCE_MODE,
    SUFFIX_NET_HEALTH,
    SUFFIX_WAN_STABILITY,
    SUFFIX_WIFI_AUTH_ERRORS_1H,
    SUFFIX_WIFI_RECONNECTS_1H,
    UID_FLEET_INCIDENT_CRITICAL,
    UID_FLEET_INCIDENTS_ACTIVE,
    UID_FLEET_NET_HEALTH,
)
from .net_engine import FleetView, NetIntelligence, RouterView, async_get_engine

_LOGGER = logging.getLogger(__name__)


def _engine_for(hass: HomeAssistant, entry_id: str) -> NetIntelligence | None:
    """The engine, if it runs and this router feeds it (setup may have failed)."""
    engine = async_get_engine(hass)
    return engine if engine is not None and entry_id in engine.routers else None


def _has_aps(data: Any) -> bool:
    aps = getattr(data, "ap_interfaces", None)
    return isinstance(aps, list) and bool(aps)


@callback
def async_withdraw_fleet(hass: HomeAssistant, entry_id: str) -> None:
    """``entry_id`` starts to unload: if it hosts the fleet entities, move
    their registry entries to the successor at once (P6 review M2).

    Called at the start of ``async_unload_entry``, before the platforms
    unload: the registry entries never point at an unloading entry, and the
    successor creates the entities once the old ones are gone
    (``NetIntelligence.unregister``).
    """
    engine = async_get_engine(hass)
    if engine is None:
        return
    successor = engine.withdraw_fleet(entry_id)
    if successor is None:
        return
    registry = er.async_get(hass)
    for domain, unique_id in _FLEET_REGISTRY:
        entity_id = registry.async_get_entity_id(domain, DOMAIN, unique_id)
        if entity_id is None:
            continue
        entry = registry.async_get(entity_id)
        if entry is not None and entry.config_entry_id != successor:
            registry.async_update_entity(entity_id, config_entry_id=successor)


@callback
def async_setup_sensors(
    hass: HomeAssistant,
    entry_id: str,
    data: Any,
    has_wan: bool,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Add the router's intelligence sensors and claim the fleet sensors."""
    engine = _engine_for(hass, entry_id)
    if engine is None:
        return
    entities: list[SensorEntity] = [
        NetHealthSensor(entry_id),
        IncidentsActiveSensor(entry_id),
        WanStabilitySensor(entry_id, enabled=has_wan),
    ]
    if _has_aps(data):
        entities += [WifiReconnectsSensor(entry_id), WifiAuthErrorsSensor(entry_id)]
    async_add_entities(entities)
    engine.claim_fleet(
        "sensor",
        entry_id,
        lambda: async_add_entities([FleetHealthSensor(), FleetIncidentsSensor()]),
    )


@callback
def async_setup_binary_sensors(
    hass: HomeAssistant, entry_id: str, async_add_entities: AddEntitiesCallback
) -> None:
    """Add the router's critical-incident sensor and claim the fleet one."""
    engine = _engine_for(hass, entry_id)
    if engine is None:
        return
    async_add_entities([IncidentCriticalBinarySensor(entry_id)])
    engine.claim_fleet(
        "binary_sensor",
        entry_id,
        lambda: async_add_entities([FleetIncidentCriticalBinarySensor()]),
    )


@callback
def async_setup_switches(
    hass: HomeAssistant, entry_id: str, async_add_entities: AddEntitiesCallback
) -> None:
    """Add the router's maintenance switch."""
    if _engine_for(hass, entry_id) is not None:
        async_add_entities([MaintenanceModeSwitch(entry_id)])


class _IntelEntity(Entity):
    """Pushed by the engine's dispatcher signal; no polling."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(self.hass, SIGNAL_NET_INTEL, self._handle_update)
        )

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()


class _RouterIntelEntity(_IntelEntity):
    """One router's entity, on its device."""

    def __init__(self, entry_id: str, suffix: str) -> None:
        self._entry_id = entry_id
        self._attr_unique_id = f"{entry_id}_{suffix}"
        self._attr_translation_key = suffix
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry_id)})

    @property
    def _view(self) -> RouterView | None:
        engine = async_get_engine(self.hass)
        return engine.view.routers.get(self._entry_id) if engine else None

    @property
    def available(self) -> bool:
        return self._view is not None


class _FleetIntelEntity(_IntelEntity):
    """A fleet entity: no device, one per HA instance."""

    def __init__(self, unique_id: str, translation_key: str) -> None:
        self._attr_unique_id = unique_id
        self._attr_translation_key = translation_key

    @property
    def _view(self) -> FleetView | None:
        engine = async_get_engine(self.hass)
        return engine.view.fleet if engine else None

    @property
    def available(self) -> bool:
        return self._view is not None


class NetHealthSensor(_RouterIntelEntity, SensorEntity):
    """Health score 0-100, unknown below the minimum coverage (plan c6)."""

    _attr_state_class = SensorStateClass.MEASUREMENT
    _unrecorded_attributes = frozenset({"areas", "coverage", "maintenance"})

    def __init__(self, entry_id: str) -> None:
        super().__init__(entry_id, SUFFIX_NET_HEALTH)

    @property
    def native_value(self) -> int | None:
        view = self._view
        return view.score.score if view else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        view = self._view
        if view is None:
            return {}
        return {
            "areas": view.score.areas,
            "coverage": view.score.coverage,
            "maintenance": view.maintenance,
        }


class IncidentsActiveSensor(_RouterIntelEntity, SensorEntity):
    """Open root incidents of the router (no children, no ignored ones)."""

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, entry_id: str) -> None:
        super().__init__(entry_id, SUFFIX_INCIDENTS_ACTIVE)

    @property
    def native_value(self) -> int | None:
        view = self._view
        return view.incidents_active if view else None


class WifiReconnectsSensor(_RouterIntelEntity, SensorEntity):
    """Wi-Fi reconnects of the router's clients in the last hour."""

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, entry_id: str) -> None:
        super().__init__(entry_id, SUFFIX_WIFI_RECONNECTS_1H)

    @property
    def native_value(self) -> int | None:
        view = self._view
        return view.reconnects_1h if view else None


class WifiAuthErrorsSensor(_RouterIntelEntity, SensorEntity):
    """Failed Wi-Fi authentications at the router in the last hour."""

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, entry_id: str) -> None:
        super().__init__(entry_id, SUFFIX_WIFI_AUTH_ERRORS_1H)

    @property
    def native_value(self) -> int | None:
        view = self._view
        return view.auth_errors_1h if view else None


class WanStabilitySensor(_RouterIntelEntity, SensorEntity):
    """WAN reconnects in the last 24 h (disabled by default without WAN)."""

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, entry_id: str, *, enabled: bool = True) -> None:
        super().__init__(entry_id, SUFFIX_WAN_STABILITY)
        # Only read when HA first registers the entity.
        self._attr_entity_registry_enabled_default = enabled

    @property
    def native_value(self) -> int | None:
        view = self._view
        return view.wan_reconnects_24h if view else None


class IncidentCriticalBinarySensor(_RouterIntelEntity, BinarySensorEntity):
    """On while the router has an open critical root incident."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, entry_id: str) -> None:
        super().__init__(entry_id, SUFFIX_INCIDENT_CRITICAL)

    @property
    def is_on(self) -> bool | None:
        view = self._view
        return view.critical if view else None


class MaintenanceModeSwitch(_RouterIntelEntity, SwitchEntity, RestoreEntity):
    """Maintenance mode of the router (plan c8, AK9).

    The engine keeps the state (also in its store); the restored state of
    the switch wins at start, as it is what the user last set in HA, but
    only when it is ``on`` or ``off`` (P6 review L3).
    """

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, entry_id: str) -> None:
        super().__init__(entry_id, SUFFIX_MAINTENANCE_MODE)

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        last = await self.async_get_last_state()
        engine = _engine_for(self.hass, self._entry_id)
        # only a real on/off wins; unavailable/unknown keep the stored state
        if (
            last is not None
            and engine is not None
            and last.state in (STATE_ON, STATE_OFF)
        ):
            engine.set_maintenance(self._entry_id, last.state == STATE_ON)

    @property
    def available(self) -> bool:
        return _engine_for(self.hass, self._entry_id) is not None

    @property
    def is_on(self) -> bool | None:
        engine = _engine_for(self.hass, self._entry_id)
        return engine.router_maintenance(self._entry_id) if engine else None

    async def async_turn_on(self, **kwargs: Any) -> None:
        self._set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        self._set(False)

    def _set(self, on: bool) -> None:
        engine = _engine_for(self.hass, self._entry_id)
        if engine is not None:
            engine.set_maintenance(self._entry_id, on)
        self.async_write_ha_state()


class FleetHealthSensor(_FleetIntelEntity, SensorEntity):
    """Fleet health score: router scores weighted with their coverage."""

    _attr_state_class = SensorStateClass.MEASUREMENT
    _unrecorded_attributes = frozenset({"coverage", "routers", "maintenance"})

    def __init__(self) -> None:
        super().__init__(UID_FLEET_NET_HEALTH, "fleet_net_health")

    @property
    def native_value(self) -> int | None:
        view = self._view
        return view.score if view else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        view = self._view
        if view is None:
            return {}
        return {
            "coverage": view.coverage,
            "routers": view.routers,
            "maintenance": view.maintenance,
        }


class FleetIncidentsSensor(_FleetIntelEntity, SensorEntity):
    """Open root incidents of the whole fleet."""

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self) -> None:
        super().__init__(UID_FLEET_INCIDENTS_ACTIVE, "fleet_incidents_active")

    @property
    def native_value(self) -> int | None:
        view = self._view
        return view.incidents_active if view else None


class FleetIncidentCriticalBinarySensor(_FleetIntelEntity, BinarySensorEntity):
    """On while any open root incident of the fleet is critical."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self) -> None:
        super().__init__(UID_FLEET_INCIDENT_CRITICAL, "fleet_incident_critical")

    @property
    def is_on(self) -> bool | None:
        view = self._view
        return view.critical if view else None


# The unique_id suffixes of the per-router entities (pattern test, plan c9).
ROUTER_SUFFIXES: tuple[str, ...] = (
    SUFFIX_NET_HEALTH,
    SUFFIX_INCIDENTS_ACTIVE,
    SUFFIX_WIFI_RECONNECTS_1H,
    SUFFIX_WIFI_AUTH_ERRORS_1H,
    SUFFIX_WAN_STABILITY,
    SUFFIX_INCIDENT_CRITICAL,
    SUFFIX_MAINTENANCE_MODE,
)
FLEET_UNIQUE_IDS: tuple[str, ...] = (
    UID_FLEET_NET_HEALTH,
    UID_FLEET_INCIDENTS_ACTIVE,
    UID_FLEET_INCIDENT_CRITICAL,
)
# (platform, unique_id) of the fleet entities in the entity registry
_FLEET_REGISTRY: tuple[tuple[str, str], ...] = (
    ("sensor", UID_FLEET_NET_HEALTH),
    ("sensor", UID_FLEET_INCIDENTS_ACTIVE),
    ("binary_sensor", UID_FLEET_INCIDENT_CRITICAL),
)
