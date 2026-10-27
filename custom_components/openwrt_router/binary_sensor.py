"""Binary sensor platform for the OpenWrt Router integration.

Provides:
    - Router Connectivity  (ON = reachable, OFF = unreachable)
    - WAN Connectivity     (ON = internet up, OFF = WAN down)
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import OpenWrtConfigEntry
from .const import (
    DOMAIN,
    SUFFIX_CONNECTIVITY,
    SUFFIX_STICKY_CLIENTS,
    SUFFIX_WAN_CONNECTIVITY,
    USTEER_STATUS_OK,
)
from .coordinator import OpenWrtCoordinator
from .fleet import collect_radios
from .sensor import router_has_wan

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class OpenWrtBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Entity description with coordinator-aware value and attribute functions."""

    # Receives the full coordinator (not just data) so it can read last_update_success
    value_fn: Callable[[OpenWrtCoordinator], bool] = field(default=lambda c: False)
    attr_fn: Callable[[OpenWrtCoordinator], dict[str, Any]] = field(
        default=lambda c: {}
    )
    # If True the sensor is always available (even when router is down)
    always_available: bool = False
    # If True the sensor is created disabled on a router without WAN (dumb AP)
    requires_wan: bool = False


BINARY_SENSOR_DESCRIPTIONS: tuple[OpenWrtBinarySensorEntityDescription, ...] = (
    OpenWrtBinarySensorEntityDescription(
        key=SUFFIX_CONNECTIVITY,
        translation_key="connectivity",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        icon="mdi:router-network",
        always_available=True,
        value_fn=lambda coord: coord.last_update_success,
        attr_fn=lambda coord: {
            "last_seen": (
                coord.data.last_seen.isoformat()
                if coord.data and coord.data.last_seen
                else None
            ),
            "consecutive_failures": coord.data.consecutive_failures
            if coord.data
            else 0,
            "error_type": coord.data.error_type if coord.data else None,
        },
    ),
    OpenWrtBinarySensorEntityDescription(
        key=SUFFIX_WAN_CONNECTIVITY,
        translation_key="wan_connectivity",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        icon="mdi:web",
        always_available=False,
        requires_wan=True,
        value_fn=lambda coord: bool(coord.data and coord.data.wan_connected),
        attr_fn=lambda coord: {
            "ip_address": (coord.data.wan_status.get("ipv4", "") if coord.data else ""),
            "protocol": (coord.data.wan_status.get("proto", "") if coord.data else ""),
        },
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: OpenWrtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up binary sensors from a config entry."""
    coordinator = entry.runtime_data.coordinator
    entities: list[BinarySensorEntity] = [
        OpenWrtBinarySensorEntity(coordinator, entry, description)
        for description in BINARY_SENSOR_DESCRIPTIONS
    ]
    entities.append(OpenWrtStickyClientsBinarySensor(coordinator, entry))
    async_add_entities(entities)


class OpenWrtBinarySensorEntity(
    CoordinatorEntity[OpenWrtCoordinator], BinarySensorEntity
):
    """Binary sensor entity backed by the OpenWrt coordinator."""

    _attr_has_entity_name = True
    entity_description: OpenWrtBinarySensorEntityDescription

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
        description: OpenWrtBinarySensorEntityDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
        )
        # Only read when HA first registers the entity: existing registry
        # entries keep their enabled state.
        if description.requires_wan and not router_has_wan(coordinator.data):
            self._attr_entity_registry_enabled_default = False

    @property
    def available(self) -> bool:
        if self.entity_description.always_available:
            return True
        return self.coordinator.last_update_success

    @property
    def is_on(self) -> bool:
        return self.entity_description.value_fn(self.coordinator)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return self.entity_description.attr_fn(self.coordinator)


class OpenWrtStickyClientsBinarySensor(
    CoordinatorEntity[OpenWrtCoordinator], BinarySensorEntity
):
    """ON while Wi-Fi clients cling to this router although better APs exist (F4).

    With usteer: another router hears the client at least 8 dB stronger, for
    10 min. Without usteer: the client's signal is weak (<= -75 dBm) for
    10 min and another router offers a radio in the same band.
    """

    _attr_has_entity_name = True
    _attr_translation_key = "sticky_clients"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:wifi-arrow-left-right"

    def __init__(
        self, coordinator: OpenWrtCoordinator, entry: OpenWrtConfigEntry
    ) -> None:
        super().__init__(coordinator)
        self._entry_id = entry.entry_id
        self._attr_unique_id = f"{entry.entry_id}_{SUFFIX_STICKY_CLIENTS}"
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry.entry_id)})

    def _sticky(self) -> tuple[str, list[dict[str, Any]]]:
        data = self.coordinator.data
        stability = (data.client_stability if data else None) or {}
        if stability.get("usteer") == USTEER_STATUS_OK:
            return "usteer", list(stability.get("sticky", []))
        weak = stability.get("weak", [])
        hass = getattr(self, "hass", None)
        if not weak or hass is None:
            return "signal", []
        bands = {
            r.band
            for r in collect_radios(hass)
            if r.entry_id != self._entry_id and not r.backhaul
        }
        return "signal", [c for c in weak if c.get("band") in bands]

    @property
    def is_on(self) -> bool:
        return bool(self._sticky()[1])

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        method, clients = self._sticky()
        return {"method": method, "clients": clients}
