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
    SUFFIX_ACTIVE_CONNECTIONS,
    SUFFIX_CLIENT_COUNT,
    SUFFIX_CPU_LOAD,
    SUFFIX_CPU_LOAD_5MIN,
    SUFFIX_CPU_LOAD_15MIN,
    SUFFIX_DISK_FREE,
    SUFFIX_DISK_TOTAL,
    SUFFIX_DISK_USAGE,
    SUFFIX_DISK_USED,
    SUFFIX_FIRMWARE,
    SUFFIX_MEMORY_BUFFERED,
    SUFFIX_MEMORY_CACHED,
    SUFFIX_MEMORY_FREE,
    SUFFIX_MEMORY_SHARED,
    SUFFIX_MEMORY_TOTAL,
    SUFFIX_MEMORY_USAGE,
    SUFFIX_MEMORY_USED,
    SUFFIX_PLATFORM_ARCHITECTURE,
    SUFFIX_TMPFS_FREE,
    SUFFIX_TMPFS_TOTAL,
    SUFFIX_TMPFS_USAGE,
    SUFFIX_TMPFS_USED,
    SUFFIX_UPTIME,
    SUFFIX_UPDATE_STATUS,
    SUFFIX_UPDATES_AVAILABLE,
    SUFFIX_WAN_IP,
    SUFFIX_WAN_RX,
    SUFFIX_WAN_STATUS,
    SUFFIX_WAN_TX,
    CONF_PROTOCOL,
    DEFAULT_PROTOCOL,
    KEY_UPDATES_AVAILABLE,
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
        icon="mdi:timer-outline",
        value_fn=lambda data: _format_uptime(data.uptime),
        extra_attrs_fn=lambda data: {
            "uptime_seconds": data.uptime,
            "uptime_raw": str(timedelta(seconds=data.uptime)),
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
            "uptime_seconds": data.wan_status.get("uptime", 0),
            "uptime_formatted": _format_uptime(data.wan_status.get("uptime", 0)),
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
        key=SUFFIX_MEMORY_TOTAL,
        translation_key="memory_total",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        value_fn=lambda data: round(data.memory.get("total", 0) / 1024 / 1024, 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_MEMORY_USED,
        translation_key="memory_used",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        value_fn=lambda data: round(
            (data.memory.get("total", 0) - data.memory.get("free", 0)) / 1024 / 1024, 1
        ),
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
    OpenWrtSensorEntityDescription(
        key=SUFFIX_UPDATE_STATUS,
        translation_key="update_status",
        icon="mdi:package-search",
        value_fn=lambda data: (
            "available"
            if data.updates_available.get("available")
            else "current"
        ),
        extra_attrs_fn=lambda data: {
            "system_updates_count": len(
                data.updates_available.get("system", [])
            ),
            "addon_updates_count": len(
                data.updates_available.get("addons", [])
            ),
            "system_packages": [
                p.get("name") for p in data.updates_available.get("system", [])
            ],
            "addon_packages": [
                p.get("name") for p in data.updates_available.get("addons", [])
            ],
        },
    ),
    # === Extended Monitoring (v1.1.0+) ===
    OpenWrtSensorEntityDescription(
        key=SUFFIX_PLATFORM_ARCHITECTURE,
        translation_key="platform_architecture",
        icon="mdi:cpu-64-bit",
        value_fn=lambda data: data.router_info.get("platform_architecture", "unknown"),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_CPU_LOAD_5MIN,
        translation_key="cpu_load_5min",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:speedometer",
        value_fn=lambda data: data.cpu_load_5min,
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_CPU_LOAD_15MIN,
        translation_key="cpu_load_15min",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:speedometer",
        value_fn=lambda data: data.cpu_load_15min,
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_MEMORY_CACHED,
        translation_key="memory_cached",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        value_fn=lambda data: round(data.memory.get("cached", 0) / 1024 / 1024, 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_MEMORY_SHARED,
        translation_key="memory_shared",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        value_fn=lambda data: round(data.memory.get("shared", 0) / 1024 / 1024, 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_MEMORY_BUFFERED,
        translation_key="memory_buffered",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        value_fn=lambda data: round(data.memory.get("buffered", 0) / 1024 / 1024, 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_DISK_TOTAL,
        translation_key="disk_total",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.GIGABYTES,
        icon="mdi:harddisk",
        value_fn=lambda data: round(data.disk_space.get("primary", {}).get("total_mb", 0) / 1024, 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_DISK_USED,
        translation_key="disk_used",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.GIGABYTES,
        icon="mdi:harddisk-remove",
        value_fn=lambda data: round(data.disk_space.get("primary", {}).get("used_mb", 0) / 1024, 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_DISK_FREE,
        translation_key="disk_free",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.GIGABYTES,
        icon="mdi:harddisk-plus",
        value_fn=lambda data: round(data.disk_space.get("primary", {}).get("free_mb", 0) / 1024, 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_DISK_USAGE,
        translation_key="disk_usage",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:percent",
        value_fn=lambda data: round(data.disk_space.get("primary", {}).get("usage_percent", 0), 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_TMPFS_TOTAL,
        translation_key="tmpfs_total",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory",
        value_fn=lambda data: round(data.tmpfs.get("total_mb", 0), 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_TMPFS_USED,
        translation_key="tmpfs_used",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory-box-outline",
        value_fn=lambda data: round(data.tmpfs.get("used_mb", 0), 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_TMPFS_FREE,
        translation_key="tmpfs_free",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        icon="mdi:memory-plus",
        value_fn=lambda data: round(data.tmpfs.get("free_mb", 0), 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_TMPFS_USAGE,
        translation_key="tmpfs_usage",
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:percent",
        value_fn=lambda data: round(data.tmpfs.get("usage_percent", 0), 1),
    ),
    OpenWrtSensorEntityDescription(
        key=SUFFIX_ACTIVE_CONNECTIONS,
        translation_key="active_connections",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:lan-connect",
        value_fn=lambda data: data.active_connections,
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
    from homeassistant.core import callback

    coordinator: OpenWrtCoordinator = entry.runtime_data.coordinator

    static_entities: list[SensorEntity] = [
        OpenWrtSensorEntity(
            coordinator=coordinator,
            entry=entry,
            description=description,
        )
        for description in SENSOR_DESCRIPTIONS
    ]
    async_add_entities(static_entities)

    # Track which dynamic entities have already been created
    tracked_interfaces: set[str] = set()
    tracked_radios: set[str] = set()

    @callback
    def _add_dynamic_sensors() -> None:
        """Create per-interface and per-radio sensors when data is available."""
        if not coordinator.data:
            return

        new_entities: list[SensorEntity] = []

        for iface in coordinator.data.network_interfaces:
            ifname = iface.get("interface", "")
            if not ifname or ifname in tracked_interfaces:
                continue
            tracked_interfaces.add(ifname)
            new_entities.append(OpenWrtInterfaceSensor(coordinator, entry, ifname, "rx_bytes"))
            new_entities.append(OpenWrtInterfaceSensor(coordinator, entry, ifname, "tx_bytes"))
            new_entities.append(OpenWrtInterfaceRateSensor(coordinator, entry, ifname, "rx_rate"))
            new_entities.append(OpenWrtInterfaceRateSensor(coordinator, entry, ifname, "tx_rate"))
            _LOGGER.debug("Adding bandwidth sensors for interface %s", ifname)

        for radio in coordinator.data.wifi_radios:
            ifname = radio.get("ifname", "")
            if not ifname or ifname in tracked_radios:
                continue
            if radio.get("noise") is not None:
                tracked_radios.add(ifname)
                new_entities.append(OpenWrtRadioSensor(coordinator, entry, ifname, "noise"))
                new_entities.append(OpenWrtRadioSensor(coordinator, entry, ifname, "signal"))
                _LOGGER.debug("Adding signal/noise sensors for radio %s", ifname)

        if new_entities:
            async_add_entities(new_entities)

    _add_dynamic_sensors()
    entry.async_on_unload(coordinator.async_add_listener(_add_dynamic_sensors))

    _LOGGER.debug("Added %d static OpenWrt sensor entities", len(static_entities))


class OpenWrtSensorEntity(CoordinatorEntity[OpenWrtCoordinator], SensorEntity):
    """A single sensor entity backed by the OpenWrt coordinator.

    All state is read from coordinator.data; this entity never calls
    the API directly.
    """

    entity_description: OpenWrtSensorEntityDescription
    _attr_has_entity_name = True

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
                f"{self._entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)}://"
                f"{self._entry.data['host']}:{self._entry.data['port']}"
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


class OpenWrtInterfaceSensor(CoordinatorEntity[OpenWrtCoordinator], SensorEntity):
    """Bandwidth sensor for a single network interface (RX or TX bytes).

    Created dynamically for each interface found in coordinator.data.network_interfaces.
    """

    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfInformation.BYTES

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
        interface: str,
        metric: str,  # "rx_bytes" or "tx_bytes"
    ) -> None:
        super().__init__(coordinator)
        self._interface = interface
        self._metric = metric
        self._entry = entry
        direction = "rx" if metric == "rx_bytes" else "tx"
        self._attr_unique_id = f"{entry.entry_id}_{interface}_{direction}"
        self._attr_translation_key = f"interface_{direction}"
        self._attr_icon = "mdi:download-network" if direction == "rx" else "mdi:upload-network"

    @property
    def name(self) -> str:
        """Return sensor name including interface name."""
        direction = "RX" if self._metric == "rx_bytes" else "TX"
        return f"{self._interface} {direction}"

    @property
    def native_value(self) -> int | None:
        """Return current byte count for this interface."""
        if not self.coordinator.data:
            return None
        for iface in self.coordinator.data.network_interfaces:
            if iface.get("interface") == self._interface:
                return iface.get(self._metric)
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return interface status."""
        if not self.coordinator.data:
            return {}
        for iface in self.coordinator.data.network_interfaces:
            if iface.get("interface") == self._interface:
                return {"status": iface.get("status", "unknown")}
        return {}

    @property
    def device_info(self) -> DeviceInfo:
        """Group under the router device card."""
        router_info = self.coordinator.router_info
        release = router_info.get("release", {})
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=router_info.get("hostname") or self._entry.title,
            manufacturer="OpenWrt",
            model=router_info.get("model", "OpenWrt Router"),
            sw_version=release.get("version", ""),
            configuration_url=(
                f"{self._entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)}://"
                f"{self._entry.data['host']}:{self._entry.data['port']}"
            ),
        )


class OpenWrtInterfaceRateSensor(CoordinatorEntity[OpenWrtCoordinator], SensorEntity):
    """Bandwidth rate sensor (bytes/s) for a single network interface (RX or TX).

    Created dynamically alongside OpenWrtInterfaceSensor.
    Returns None until the second coordinator poll (rate needs two data points).
    """

    _attr_has_entity_name = True
    _attr_device_class = SensorDeviceClass.DATA_RATE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = UnitOfDataRate.BYTES_PER_SECOND
    _attr_suggested_display_precision = 1

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
        interface: str,
        metric: str,  # "rx_rate" or "tx_rate"
    ) -> None:
        super().__init__(coordinator)
        self._interface = interface
        self._metric = metric
        self._entry = entry
        direction = "rx" if metric == "rx_rate" else "tx"
        self._attr_unique_id = f"{entry.entry_id}_{interface}_{direction}_rate"
        self._attr_icon = "mdi:download-network-outline" if direction == "rx" else "mdi:upload-network-outline"

    @property
    def name(self) -> str:
        """Return sensor name including interface and direction."""
        direction = "RX" if self._metric == "rx_rate" else "TX"
        return f"{self._interface} {direction} Rate"

    @property
    def native_value(self) -> float | None:
        """Return current bytes/s rate for this interface, or None if not yet available."""
        if not self.coordinator.data:
            return None
        for iface in self.coordinator.data.network_interfaces:
            if iface.get("interface") == self._interface:
                return iface.get(self._metric)
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return interface status."""
        if not self.coordinator.data:
            return {}
        for iface in self.coordinator.data.network_interfaces:
            if iface.get("interface") == self._interface:
                return {"status": iface.get("status", "unknown")}
        return {}

    @property
    def device_info(self) -> DeviceInfo:
        """Group under the router device card."""
        router_info = self.coordinator.router_info
        release = router_info.get("release", {})
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=router_info.get("hostname") or self._entry.title,
            manufacturer="OpenWrt",
            model=router_info.get("model", "OpenWrt Router"),
            sw_version=release.get("version", ""),
            configuration_url=(
                f"{self._entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)}://"
                f"{self._entry.data['host']}:{self._entry.data['port']}"
            ),
        )


class OpenWrtRadioSensor(CoordinatorEntity[OpenWrtCoordinator], SensorEntity):
    """Signal quality sensor for a single WiFi radio interface.

    Created dynamically for each radio that exposes noise/signal via iwinfo.
    """

    _attr_has_entity_name = True
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "dBm"

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
        ifname: str,
        metric: str,  # "noise" or "signal"
    ) -> None:
        super().__init__(coordinator)
        self._ifname = ifname
        self._metric = metric
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_radio_{ifname}_{metric}"
        self._attr_translation_key = f"radio_{metric}"
        self._attr_icon = "mdi:wifi-strength-2" if metric == "signal" else "mdi:sine-wave"

    @property
    def name(self) -> str:
        """Return sensor name including interface name."""
        label = "Signal" if self._metric == "signal" else "Noise"
        return f"{self._ifname} {label}"

    @property
    def native_value(self) -> int | None:
        """Return current dBm value."""
        if not self.coordinator.data:
            return None
        for radio in self.coordinator.data.wifi_radios:
            if radio.get("ifname") == self._ifname:
                val = radio.get(self._metric)
                return int(val) if val is not None else None
        return None

    @property
    def device_info(self) -> DeviceInfo:
        """Group under the router device card."""
        router_info = self.coordinator.router_info
        release = router_info.get("release", {})
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=router_info.get("hostname") or self._entry.title,
            manufacturer="OpenWrt",
            model=router_info.get("model", "OpenWrt Router"),
            sw_version=release.get("version", ""),
            configuration_url=(
                f"{self._entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)}://"
                f"{self._entry.data['host']}:{self._entry.data['port']}"
            ),
        )


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
