"""Device tracker platform for the OpenWrt Router integration.

Tracks WiFi clients associated with the router.

Each known client is represented as a tracked device.  When a client
disappears from the association list it is marked as 'not_home'.
New clients discovered on subsequent polls are automatically added.

Architecture note:
    This platform uses ScannerEntity (preferred over the legacy
    async_see approach) which is the current HA best-practice for
    router-based device trackers.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import OpenWrtConfigEntry
from .const import (
    CLIENT_KEY_CONNECTED_SINCE,
    CLIENT_KEY_IP,
    CONF_PROTOCOL,
    DEFAULT_PROTOCOL,
    CLIENT_KEY_MAC,
    CLIENT_KEY_RADIO,
    CLIENT_KEY_SIGNAL,
    CLIENT_KEY_SSID,
    DOMAIN,
)
from .coordinator import OpenWrtCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: OpenWrtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker entities and listen for new clients.

    Registers a coordinator listener so that newly discovered clients
    (MACs not yet seen in this session) are added as entities automatically.

    Args:
        hass: Home Assistant instance.
        entry: Config entry carrying runtime_data.
        async_add_entities: Callback to register new entities with HA.
    """
    coordinator: OpenWrtCoordinator = entry.runtime_data.coordinator
    tracked_macs: set[str] = set()

    @callback
    def _add_new_clients() -> None:
        """Create tracker entities for any MACs not yet tracked."""
        if not coordinator.data:
            return

        new_entities: list[OpenWrtClientTrackerEntity] = []
        for client in coordinator.data.clients:
            mac: str = client.get(CLIENT_KEY_MAC, "").upper()
            if not mac or mac in tracked_macs:
                continue

            tracked_macs.add(mac)
            new_entities.append(
                OpenWrtClientTrackerEntity(
                    coordinator=coordinator,
                    entry=entry,
                    mac=mac,
                )
            )
            _LOGGER.debug("New client tracker entity: %s", mac)

        if new_entities:
            async_add_entities(new_entities)

    # Add entities for clients already present in the first coordinator data
    _add_new_clients()

    # Subscribe to future coordinator updates to catch new clients
    entry.async_on_unload(coordinator.async_add_listener(_add_new_clients))


class OpenWrtClientTrackerEntity(CoordinatorEntity[OpenWrtCoordinator], ScannerEntity):
    """Presence tracker for a single WiFi client.

    The entity is identified by MAC address.  It is marked as 'home'
    (connected) when the MAC appears in coordinator.data.clients and
    'not_home' (not connected) when it disappears.

    The entity persists in the entity registry even after the client
    disconnects so that automations and history are preserved.
    """

    _attr_has_entity_name = False  # entity name IS the device name (MAC / hostname)

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
        mac: str,
    ) -> None:
        """Initialise the tracker entity.

        Args:
            coordinator: Shared data coordinator.
            entry: Config entry (used for device grouping).
            mac: Uppercase MAC address of the tracked client (e.g. 'AA:BB:CC:DD:EE:FF').
        """
        super().__init__(coordinator)
        self._mac = mac
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_tracker_{mac.lower().replace(':', '')}"

    @property
    def name(self) -> str:
        """Return the entity name.

        Uses the client hostname if available, otherwise the MAC address.
        """
        client = self.coordinator.get_client_by_mac(self._mac)
        hostname = (client or {}).get("hostname", "")
        return hostname if hostname else self._mac

    @property
    def source_type(self) -> SourceType:
        """Return the source type (router-based tracking)."""
        return SourceType.ROUTER

    @property
    def is_connected(self) -> bool:
        """Return True if the client is currently associated with the router."""
        return self.coordinator.is_client_connected(self._mac)

    @property
    def ip_address(self) -> str | None:
        """Return the client IP address if known."""
        client = self.coordinator.get_client_by_mac(self._mac)
        if not client:
            return None
        ip = client.get(CLIENT_KEY_IP, "")
        return ip if ip else None

    @property
    def mac_address(self) -> str:
        """Return the client MAC address (required by ScannerEntity)."""
        return self._mac

    @property
    def hostname(self) -> str | None:
        """Return the client hostname if available."""
        client = self.coordinator.get_client_by_mac(self._mac)
        return (client or {}).get("hostname") or None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes for the tracked device."""
        client = self.coordinator.get_client_by_mac(self._mac)
        if not client:
            # Client is currently away; return last known SSID / radio if stored
            return {"mac": self._mac, "connected": False}

        return {
            "mac": self._mac,
            "connected": True,
            "ssid": client.get(CLIENT_KEY_SSID, ""),
            "radio": client.get(CLIENT_KEY_RADIO, ""),
            "signal": client.get(CLIENT_KEY_SIGNAL, 0),
            "ip_address": client.get(CLIENT_KEY_IP, ""),
            "connected_since": client.get(CLIENT_KEY_CONNECTED_SINCE),
        }

    @property
    def device_info(self) -> DeviceInfo:
        """Group this tracker under the router device card."""
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

    # TODO: add parental control support once the parental control API is implemented
