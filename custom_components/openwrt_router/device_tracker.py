"""Device tracker platform for the OpenWrt Router integration.

Tracks WiFi clients associated with the router.

Each known client is represented as a tracked device.  When a client
disappears from the association list it is marked as 'not_home'.
New clients discovered on subsequent polls are automatically added.

Architecture note:
    This platform uses ScannerEntity (preferred over the legacy
    async_see approach) which is the current HA best-practice for
    router-based device trackers.

    HA core's ScannerEntity derives ``unique_id`` from ``mac_address``
    (overriding any ``_attr_unique_id``), so only ONE tracker entity per
    client MAC can exist across ALL config entries of this integration.
    With several routers (mesh APs) seeing the same client, each client is
    therefore claimed by exactly one entry via a hass.data claim registry;
    the resulting entity looks the client up on EVERY loaded router, so it
    stays 'home' while roaming between APs.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import OpenWrtConfigEntry
from .const import (
    CLIENT_KEY_CONNECTED_SINCE,
    CLIENT_KEY_IP,
    CLIENT_KEY_MAC,
    CLIENT_KEY_RADIO,
    CLIENT_KEY_SIGNAL,
    CLIENT_KEY_SSID,
    CONF_PROTOCOL,
    DEFAULT_PROTOCOL,
    DOMAIN,
    url_scheme_for,
)
from .coordinator import OpenWrtCoordinator

_LOGGER = logging.getLogger(__name__)

# hass.data key for the cross-entry claim registry: MAC -> entry_id of the
# config entry whose entity tracks that client. ScannerEntity's unique_id is
# the MAC, so a second entity for the same MAC (client visible on several
# APs) would be rejected by HA with "Platform openwrt_router does not
# generate unique IDs".
_CLAIMED_MACS_KEY = f"{DOMAIN}_tracker_claimed_macs"


async def async_setup_entry(
    hass: HomeAssistant,
    entry: OpenWrtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker entities and listen for new clients.

    Registers a coordinator listener so that newly discovered clients
    (MACs not yet seen in this session) are added as entities automatically.
    Clients already claimed by another config entry (same MAC seen by
    several routers) are skipped; their claim is released again on unload
    so another router can take over.

    Args:
        hass: Home Assistant instance.
        entry: Config entry carrying runtime_data.
        async_add_entities: Callback to register new entities with HA.
    """
    coordinator: OpenWrtCoordinator = entry.runtime_data.coordinator
    tracked_macs: set[str] = set()
    claimed_macs: dict[str, str] = hass.data.setdefault(_CLAIMED_MACS_KEY, {})

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

            owner = claimed_macs.get(mac)
            if owner is not None and owner != entry.entry_id:
                # Another router's entity already tracks this client; that
                # entity reports 'home' for every AP via the mesh-wide
                # lookup, so nothing is lost by skipping it here.
                continue

            claimed_macs[mac] = entry.entry_id
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

    @callback
    def _release_claimed_macs() -> None:
        """Free this entry's MAC claims so other routers can take over."""
        for mac in tracked_macs:
            if claimed_macs.get(mac) == entry.entry_id:
                del claimed_macs[mac]

    # Add entities for clients already present in the first coordinator data
    _add_new_clients()

    # Subscribe to future coordinator updates to catch new clients
    entry.async_on_unload(coordinator.async_add_listener(_add_new_clients))
    entry.async_on_unload(_release_claimed_macs)


class OpenWrtClientTrackerEntity(CoordinatorEntity[OpenWrtCoordinator], ScannerEntity):
    """Presence tracker for a single WiFi client.

    The entity is identified by MAC address (ScannerEntity uses the MAC as
    unique_id).  It is marked as 'home' when the MAC appears in the client
    list of ANY loaded router of this integration and 'not_home' when no
    router sees it — so a client roaming between mesh APs stays 'home'
    even though only one config entry owns the entity.

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
            coordinator: Data coordinator of the claiming config entry.
            entry: Config entry (used for device grouping).
            mac: Uppercase MAC address of the tracked client (e.g. 'AA:BB:CC:DD:EE:FF').
        """
        super().__init__(coordinator)
        self._mac = mac
        self._entry = entry
        # Newer HA cores override ScannerEntity.unique_id with mac_address,
        # which silently discards this value; older cores (≥2026.2 floor)
        # still need it. Cross-entry uniqueness is guaranteed by the MAC
        # claim registry in async_setup_entry either way.
        self._attr_unique_id = (
            f"{entry.entry_id}_tracker_{mac.lower().replace(':', '')}"
        )

    def _find_client(self) -> tuple[dict[str, Any] | None, OpenWrtCoordinator | None]:
        """Locate the client on any loaded router; own router first.

        Returns:
            (client dict, coordinator that currently sees the client),
            or (None, None) if no router sees the MAC.
        """
        client = self.coordinator.get_client_by_mac(self._mac)
        if client is not None:
            return client, self.coordinator

        hass = getattr(self, "hass", None)
        if hass is None:
            return None, None
        for entry in hass.config_entries.async_loaded_entries(DOMAIN):
            runtime = getattr(entry, "runtime_data", None)
            coordinator = getattr(runtime, "coordinator", None)
            if coordinator is None or coordinator is self.coordinator:
                continue
            client = coordinator.get_client_by_mac(self._mac)
            if client is not None:
                return client, coordinator
        return None, None

    @property
    def name(self) -> str:
        """Return the entity name.

        Uses the client hostname if available, otherwise the MAC address.
        """
        client, _ = self._find_client()
        hostname = (client or {}).get("hostname", "")
        return hostname if hostname else self._mac

    @property
    def source_type(self) -> SourceType:
        """Return the source type (router-based tracking)."""
        return SourceType.ROUTER

    @property
    def is_connected(self) -> bool:
        """Return True if the client is associated with any loaded router."""
        return self._find_client()[0] is not None

    @property
    def ip_address(self) -> str | None:
        """Return the client IP address if known."""
        client, _ = self._find_client()
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
        client, _ = self._find_client()
        return (client or {}).get("hostname") or None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes for the tracked device."""
        client, coordinator = self._find_client()
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
            "connected_ap": (
                coordinator.router_info.get("hostname", "") if coordinator else ""
            ),
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
                f"{url_scheme_for(self._entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL))}://"
                f"{self._entry.data['host']}:{self._entry.data['port']}"
            ),
        )

    # TODO: add parental control support once the parental control API is implemented
