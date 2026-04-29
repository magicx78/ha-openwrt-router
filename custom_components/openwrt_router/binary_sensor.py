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
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import OpenWrtConfigEntry
from .const import DOMAIN, SUFFIX_CONNECTIVITY, SUFFIX_WAN_CONNECTIVITY
from .coordinator import OpenWrtCoordinator

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class OpenWrtBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Entity description with coordinator-aware value and attribute functions."""

    # Receives the full coordinator (not just data) so it can read last_update_success
    value_fn: Callable[[OpenWrtCoordinator], bool] = field(default=lambda c: False)
    attr_fn: Callable[[OpenWrtCoordinator], dict[str, Any]] = field(default=lambda c: {})
    # If True the sensor is always available (even when router is down)
    always_available: bool = False


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
            "consecutive_failures": coord.data.consecutive_failures if coord.data else 0,
            "error_type": coord.data.error_type if coord.data else None,
        },
    ),
    OpenWrtBinarySensorEntityDescription(
        key=SUFFIX_WAN_CONNECTIVITY,
        translation_key="wan_connectivity",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        icon="mdi:web",
        always_available=False,
        value_fn=lambda coord: bool(coord.data and coord.data.wan_connected),
        attr_fn=lambda coord: {
            "ip_address": (
                coord.data.wan_status.get("ipv4", "")
                if coord.data
                else ""
            ),
            "protocol": (
                coord.data.wan_status.get("proto", "")
                if coord.data
                else ""
            ),
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
    async_add_entities(
        OpenWrtBinarySensorEntity(coordinator, entry, description)
        for description in BINARY_SENSOR_DESCRIPTIONS
    )


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
