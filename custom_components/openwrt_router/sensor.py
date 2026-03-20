"""Sensor platform for the OpenWrt Router integration.

Provides:
    - Uptime sensor       (seconds since last boot)
    - WAN status sensor   (connected / disconnected)
    - Client count sensor (number of associated WiFi clients)
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    EntityCategory,
    UnitOfDataRate,
    UnitOfInformation,
    UnitOfTime,
    PERCENTAGE,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import OpenWrtConfigEntry
from .const import (
    DOMAIN,
    SUFFIX_CLIENT_COUNT,
    SUFFIX_CPU_LOAD,
    SUFFIX_FIRMWARE,
    SUFFIX_MEMORY_FREE,
    SUFFIX_MEMORY_USAGE,
    SUFFIX_UPTIME,
    SUFFIX_WAN_IP,
    SUFFIX_WAN_RX,
    SUFFIX_WAN_STATUS,
    SUFFIX_WAN_TX,
)
from .coordinator import OpenWrtCoordinator, OpenWrtCoordinatorData

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class OpenWrtSensorEntityDescription(SensorEntityDescription):
    """Extended entity description with a coordinator data extractor.

    Attributes:
        value_fn: Callable that receives the coordinator data and returns
                  the sensor state value.
        extra_attrs_fn: Optional callable returning a dict of extra state
                        attributes.
    """

    value_fn: Callable[[OpenWrtCoordinatorData], Any]
    extra_attrs_fn: Callable[[OpenWrtCoordinatorData], dict[str, Any]] | None = None


SENSOR_DESCRIPTIONS: tuple[OpenWrtSensorEntityDescription, ...] = (
    OpenWrtSensorEntityDescription(
        key=SUFFIX_UPTIME,
        translation_key="uptime",
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfTime.SECONDS,
        icon="mdi:timer-outline",
        value_fn=lambda data: data.uptime,
        extra_attrs_fn=lambda data: {
            "uptime_formatted": _format_uptime(data.uptime),
        },
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_WAN_STATUS,
        translation_key="wan_status",
        icon="mdi:wan",
        value_fn=lambda data: "connected" if data.wan_connected else "disconnected",
        extra_attrs_fn=lambda data: {
            "interface": data.wan_status.get("interface", ""),
            "ip_address": data.wan_status.get("ipv4", ""),
            "protocol": data.wan_status.get("proto", ""),
            "uptime": data.wan_status.get("uptime", 0),
        },
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_CLIENT_COUNT,
        translation_key="client_count",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:account-multiple",
        native_unit_of_measurement="clients",
        value_fn=lambda data: data.client_count,
        extra_attrs_fn=lambda data: {
            "clients": [
                {
                    "mac": c.get("mac", ""),
                    "ssid": c.get("ssid", ""),
                    "signal": c.get("signal", 0),
                }
                for c in data.clients
            ]
        },
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_CPU_LOAD,
        translation_key="cpu_load",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:cpu-64-bit",
        value_fn=lambda data: data.cpu_load,
        extra_attrs_fn=lambda data: {
            "load_1min": round(data.cpu_load, 1),
        },
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_MEMORY_USAGE,
        translation_key="memory_usage",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:memory",
        value_fn=lambda data: _calc_memory_pct(data.memory),
        extra_attrs_fn=lambda data: {
            "total_mb": round(data.memory.get("total", 0) / 1024 / 1024, 1),
            "free_mb": round(data.memory.get("free", 0) / 1024 / 1024, 1),
            "used_mb": round(
                (data.memory.get("total", 0) - data.memory.get("free", 0)) / 1024 / 1024, 1
            ),
        },
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_MEMORY_FREE,
        translation_key="memory_free",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        value_fn=lambda data: round(data.memory.get("free", 0) / 1024 / 1024, 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_WAN_IP,
        translation_key="wan_ip",
        icon="mdi:ip-network",
        value_fn=lambda data: data.wan_status.get("ipv4") or None,
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_WAN_RX,
        translation_key="wan_rx",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        icon="mdi:download-network",
        value_fn=lambda data: data.wan_status.get("rx_bytes") or None,
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_WAN_TX,
        translation_key="wan_tx",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.TOTAL_INCREASING,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        icon="mdi:upload-network",
        value_fn=lambda data: data.wan_status.get("tx_bytes") or None,
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_FIRMWARE,
        translation_key="firmware",
        icon="mdi:package-up",
        value_fn=lambda data: (
            data.router_info.get("release", {}).get("version", "")
            or data.router_info.get("kernel", "")
        ),
        extra_attrs_fn=lambda data: {
            "distribution": data.router_info.get("release", {}).get("distribution", ""),
            "kernel": data.router_info.get("kernel", ""),
            "board": data.router_info.get("board_name", ""),
        },
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: OpenWrtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up OpenWrt sensor entities from a config entry.

    Args:
        hass: Home Assistant instance.
        entry: Config entry carrying runtime_data.
        async_add_entities: Callback to register new entities with HA.
    """
    coordinator: OpenWrtCoordinator = entry.runtime_data.coordinator

    entities = [
        OpenWrtSensorEntity(
            coordinator=coordinator,
            entry=entry,
            description=description,
        )
        for description in SENSOR_DESCRIPTIONS
    ]

    async_add_entities(entities)
    _LOGGER.debug("Added %d OpenWrt sensor entities", len(entities))


class OpenWrtSensorEntity(CoordinatorEntity[OpenWrtCoordinator], SensorEntity):
    """A single sensor entity backed by the OpenWrt coordinator.

    All state is read from coordinator.data; this entity never calls
    the API directly.
    """

    entity_description: OpenWrtSensorEntityDescription
    _attr_has_entity_name = False

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
        description: OpenWrtSensorEntityDescription,
    ) -> None:
        """Initialise the sensor entity.

        Args:
            coordinator: Shared data coordinator.
            entry: Config entry (provides entry_id and router info for device).
            description: Entity description including value extractor.
        """
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._entry = entry

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information to group entities under one device card."""
        router_info = self.coordinator.router_info
        release = router_info.get("release", {})
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=router_info.get("hostname") or self._entry.title,
            manufacturer="OpenWrt",
            model=router_info.get("model", "OpenWrt Router"),
            sw_version=release.get("version", ""),
            configuration_url=(
                f"http://{self._entry.data['host']}:{self._entry.data['port']}"
            ),
        )

    @property
    def native_value(self) -> Any:
        """Return the current sensor value extracted from coordinator data."""
        if self.coordinator.data is None:
            return None
        try:
            return self.entity_description.value_fn(self.coordinator.data)
        except Exception:  # noqa: BLE001
            _LOGGER.debug(
                "Failed to extract value for sensor %s", self.entity_description.key
            )
            return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional state attributes."""
        if self.coordinator.data is None or self.entity_description.extra_attrs_fn is None:
            return {}
        try:
            return self.entity_description.extra_attrs_fn(self.coordinator.data)
        except Exception:  # noqa: BLE001
            return {}


# ------------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------------

def _calc_memory_pct(memory: dict) -> float | None:
    """Calculate memory usage percentage from memory dict."""
    total = memory.get("total", 0)
    free = memory.get("free", 0)
    if not total:
        return None
    return round((total - free) / total * 100, 1)


def _format_uptime(seconds: int) -> str:
    """Convert uptime seconds into a human-readable string.

    Args:
        seconds: Raw uptime in seconds.

    Returns:
        String like '3d 4h 12m 5s'.

    Examples:
        >>> _format_uptime(90061)
        '1d 1h 1m 1s'
    """
    if not seconds or seconds < 0:
        return "0s"

    td = timedelta(seconds=seconds)
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, secs = divmod(remainder, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")

    return " ".join(parts)

    # TODO: add BandwidthSensor (RX/TX bytes per interface) once API supports it
    # TODO: add TrafficStatsSensor (total transferred data) once API supports it
    # TODO: add LinkQualitySensor (per-radio signal / noise ratio) once API supports it
