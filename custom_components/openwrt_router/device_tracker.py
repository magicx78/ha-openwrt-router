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
    stays 'home' while roaming between APs. For the same reason it stays
    available as long as ANY loaded router answers, not just its owner.

    At setup, clients this entry already has in the entity registry get an
    entity too (subject to the same claim registry), so a client that is
    absent after a restart shows 'not_home' instead of 'unavailable'.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import (
    async_dispatcher_connect,
    async_dispatcher_send,
)
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from . import OpenWrtConfigEntry
from .const import (
    CLIENT_KEY_CONNECTED_SINCE,
    CLIENT_KEY_IP,
    CLIENT_KEY_MAC,
    CLIENT_KEY_RADIO,
    CLIENT_KEY_RANDOM_MAC,
    CLIENT_KEY_SIGNAL,
    CLIENT_KEY_SSID,
    CONF_PROTOCOL,
    DEFAULT_PROTOCOL,
    DOMAIN,
    url_scheme_for,
)
from .coordinator import OpenWrtCoordinator
from .dhcp_health import client_dhcp_status
from .fleet import client_counts, dhcp_context
from .mac_utils import is_locally_administered, is_mac

_LOGGER = logging.getLogger(__name__)

# hass.data key for the cross-entry claim registry: MAC -> entry_id of the
# config entry whose entity tracks that client. ScannerEntity's unique_id is
# the MAC, so a second entity for the same MAC (client visible on several
# APs) would be rejected by HA with "Platform openwrt_router does not
# generate unique IDs".
_CLAIMED_MACS_KEY = f"{DOMAIN}_tracker_claimed_macs"

# Dispatcher signal sent after every poll of any router (payload: entry_id).
# CoordinatorEntity only listens to the owner's coordinator, and a coordinator
# that keeps failing stops notifying its listeners — trackers of a failing
# owner use this signal to follow the routers that still answer.
_SIGNAL_ROUTER_POLLED = f"{DOMAIN}_tracker_router_polled"


def _mac_from_unique_id(unique_id: str | None) -> str | None:
    """Return the uppercase MAC of a tracker registry entry, else None.

    Handles both unique_id forms this platform has produced: the MAC itself
    ('AA:BB:CC:DD:EE:FF', ScannerEntity on current cores) and the legacy
    '<entry_id>_tracker_aabbccddeeff' (older cores).
    """
    if not unique_id:
        return None
    token = unique_id.rsplit("_tracker_", 1)[-1]
    if not is_mac(token):
        return None
    hexonly = "".join(c for c in token.upper() if c in "0123456789ABCDEF")
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))


def _is_stale(coordinator: OpenWrtCoordinator) -> bool:
    """True if the router's client list no longer counts for presence."""
    # Strict 'is True': a missing or non-bool value counts as not stale.
    return getattr(coordinator, "stale_for_presence", False) is True


def _registry_name(entity_entry: er.RegistryEntry) -> str | None:
    """Last name the registry knows for a tracker (MAC-like names ignored)."""
    for name in (entity_entry.original_name, entity_entry.name):
        if name and not is_mac(name):
            return name
    return None


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

    Trackers this entry already has in the entity registry are restored too
    (same claim rules), so clients that are absent right now report
    'not_home' instead of staying 'unavailable' after a restart.

    Args:
        hass: Home Assistant instance.
        entry: Config entry carrying runtime_data.
        async_add_entities: Callback to register new entities with HA.
    """
    coordinator: OpenWrtCoordinator = entry.runtime_data.coordinator
    tracked_macs: set[str] = set()
    claimed_macs: dict[str, str] = hass.data.setdefault(_CLAIMED_MACS_KEY, {})

    # MAC -> last known name of every enabled tracker this entry has in the
    # entity registry (both unique_id forms). Read-only; nothing is written
    # here. Legacy '<entry_id>_tracker_<mac>' entries can exist for the same
    # MAC under several entries (the old form was per entry); each one only
    # feeds its own entry's restore, and the claim registry below still
    # yields one entity per MAC. The orphaned legacy entries stay untouched.
    registry_names: dict[str, str | None] = {}
    for entity_entry in er.async_entries_for_config_entry(
        er.async_get(hass), entry.entry_id
    ):
        if (
            entity_entry.domain != Platform.DEVICE_TRACKER
            # A disabled tracker must not claim the MAC: HA would not add the
            # entity, and no other router could track the client either.
            or entity_entry.disabled_by is not None
        ):
            continue
        mac = _mac_from_unique_id(entity_entry.unique_id)
        if mac is not None and registry_names.get(mac) is None:
            registry_names[mac] = _registry_name(entity_entry)

    @callback
    def _claim(mac: str) -> OpenWrtClientTrackerEntity | None:
        """Claim ``mac`` for this entry and build its entity, if still free."""
        if mac in tracked_macs:
            return None
        owner = claimed_macs.get(mac)
        if owner is not None and owner != entry.entry_id:
            # Another router's entity already tracks this client; that
            # entity reports 'home' for every AP via the mesh-wide
            # lookup, so nothing is lost by skipping it here.
            return None
        claimed_macs[mac] = entry.entry_id
        tracked_macs.add(mac)
        return OpenWrtClientTrackerEntity(
            coordinator=coordinator,
            entry=entry,
            mac=mac,
            last_name=registry_names.get(mac),
        )

    @callback
    def _add_new_clients() -> None:
        """Create tracker entities for any MACs not yet tracked."""
        if not coordinator.data:
            return

        new_entities: list[OpenWrtClientTrackerEntity] = []
        for client in coordinator.data.clients:
            mac: str = client.get(CLIENT_KEY_MAC, "").upper()
            if not mac:
                continue
            entity = _claim(mac)
            if entity is not None:
                new_entities.append(entity)
                _LOGGER.debug("New client tracker entity: %s", mac)

        if new_entities:
            async_add_entities(new_entities)

    @callback
    def _restore_registry_clients() -> None:
        """Create entities for registry-known clients not seen right now."""
        new_entities: list[OpenWrtClientTrackerEntity] = []
        for mac in registry_names:
            entity = _claim(mac)
            if entity is not None:
                new_entities.append(entity)
                _LOGGER.debug("Restored client tracker entity: %s", mac)

        if new_entities:
            async_add_entities(new_entities)

    @callback
    def _on_coordinator_update() -> None:
        """Pick up new clients and tell all trackers this router answered."""
        _add_new_clients()
        async_dispatcher_send(hass, _SIGNAL_ROUTER_POLLED, entry.entry_id)

    @callback
    def _release_claimed_macs() -> None:
        """Free this entry's MAC claims so other routers can take over."""
        for mac in tracked_macs:
            if claimed_macs.get(mac) == entry.entry_id:
                del claimed_macs[mac]

    # Add entities for clients already present in the first coordinator data,
    # then for the registry-known ones that are absent at the moment
    _add_new_clients()
    _restore_registry_clients()

    # Subscribe to future coordinator updates to catch new clients
    entry.async_on_unload(coordinator.async_add_listener(_on_coordinator_update))
    entry.async_on_unload(_release_claimed_macs)


class OpenWrtClientTrackerEntity(CoordinatorEntity[OpenWrtCoordinator], ScannerEntity):
    """Presence tracker for a single WiFi client.

    The entity is identified by MAC address (ScannerEntity uses the MAC as
    unique_id).  It is marked as 'home' when the MAC appears in the client
    list of ANY loaded router of this integration and 'not_home' when no
    router sees it — so a client roaming between mesh APs stays 'home'
    even though only one config entry owns the entity. Likewise it is
    available while ANY loaded router answers, not only the owning one.

    The entity persists in the entity registry even after the client
    disconnects so that automations and history are preserved.
    """

    _attr_has_entity_name = False  # entity name IS the device name (MAC / hostname)
    # Signal changes on nearly every poll; presence attributes stay recorded.
    _unrecorded_attributes = frozenset({"signal"})

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
        mac: str,
        last_name: str | None = None,
    ) -> None:
        """Initialise the tracker entity.

        Args:
            coordinator: Data coordinator of the claiming config entry.
            entry: Config entry (used for device grouping).
            mac: Uppercase MAC address of the tracked client (e.g. 'AA:BB:CC:DD:EE:FF').
            last_name: Last known hostname (e.g. from the entity registry),
                used as name while the client is absent.
        """
        super().__init__(coordinator)
        self._mac = mac
        self._entry = entry
        self._last_name = last_name
        # Newer HA cores override ScannerEntity.unique_id with mac_address,
        # which silently discards this value; older cores (≥2026.2 floor)
        # still need it. Cross-entry uniqueness is guaranteed by the MAC
        # claim registry in async_setup_entry either way.
        self._attr_unique_id = (
            f"{entry.entry_id}_tracker_{mac.lower().replace(':', '')}"
        )

    async def async_added_to_hass(self) -> None:
        """Also follow the polls of the other routers (see _async_router_polled)."""
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, _SIGNAL_ROUTER_POLLED, self._async_router_polled
            )
        )

    @callback
    def _async_router_polled(self, entry_id: str) -> None:
        """Refresh the state after another router's poll while ours fails.

        With a healthy owner the owner's own poll refreshes the state; a
        failing owner stops notifying, so the answering routers take over.
        """
        if entry_id == self._entry.entry_id or self.coordinator.last_update_success:
            return
        self.async_write_ha_state()

    def _other_coordinators(self) -> list[OpenWrtCoordinator]:
        """Coordinators of all other loaded routers usable for presence.

        Routers failing beyond the grace period are left out (see
        :func:`_is_stale`).
        """
        hass = getattr(self, "hass", None)
        if hass is None:
            return []
        coordinators: list[OpenWrtCoordinator] = []
        for entry in hass.config_entries.async_loaded_entries(DOMAIN):
            runtime = getattr(entry, "runtime_data", None)
            coordinator = getattr(runtime, "coordinator", None)
            if (
                coordinator is None
                or coordinator is self.coordinator
                or _is_stale(coordinator)
            ):
                continue
            coordinators.append(coordinator)
        return coordinators

    @property
    def available(self) -> bool:
        """Return True while ANY loaded router answers its polls.

        The client is looked up on every router, so a failed poll of the
        owning router alone must not make it unavailable.
        """
        if self.coordinator.last_update_success:
            return True
        return any(
            getattr(coordinator, "last_update_success", False)
            for coordinator in self._other_coordinators()
        )

    def _find_client(self) -> tuple[dict[str, Any] | None, OpenWrtCoordinator | None]:
        """Locate the client on any loaded router; own router first.

        A router whose polls fail only briefly still counts with its last
        client list (no false 'not_home' on a single timeout); one failing
        beyond the grace period is skipped, so its clients do not stay
        'home' forever while the router is down.

        Returns:
            (client dict, coordinator that currently sees the client),
            or (None, None) if no router sees the MAC.
        """
        if not _is_stale(self.coordinator):
            client = self.coordinator.get_client_by_mac(self._mac)
            if client is not None:
                return client, self.coordinator

        for coordinator in self._other_coordinators():
            client = coordinator.get_client_by_mac(self._mac)
            if client is not None:
                return client, coordinator
        return None, None

    @property
    def name(self) -> str:
        """Return the entity name.

        Uses the client hostname if available, else the last known hostname
        (kept while the client is absent), else the MAC address.
        """
        client, _ = self._find_client()
        hostname = (client or {}).get("hostname", "")
        if hostname:
            self._last_name = hostname
            return hostname
        return self._last_name or self._mac

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
        counts = self._client_counts()
        random_mac = is_locally_administered(self._mac)
        if not client:
            # Client is currently away; return last known SSID / radio if stored
            return {
                "mac": self._mac,
                "connected": False,
                CLIENT_KEY_RANDOM_MAC: random_mac,
                **counts,
            }

        return {
            **counts,
            CLIENT_KEY_RANDOM_MAC: random_mac,
            "mac": self._mac,
            "connected": True,
            "dhcp_status": self._dhcp_status(client),
            "ssid": client.get(CLIENT_KEY_SSID, ""),
            "radio": client.get(CLIENT_KEY_RADIO, ""),
            "signal": client.get(CLIENT_KEY_SIGNAL, 0),
            "ip_address": client.get(CLIENT_KEY_IP, ""),
            "connected_since": client.get(CLIENT_KEY_CONNECTED_SINCE),
            "connected_ap": (
                coordinator.router_info.get("hostname", "") if coordinator else ""
            ),
        }

    def _client_counts(self) -> dict[str, int]:
        """associations_24h / reconnects_24h over all routers (router log)."""
        hass = getattr(self, "hass", None)
        if hass is None:
            return {}
        return client_counts(hass, self._mac) or {}

    def _dhcp_status(self, client: dict[str, Any]) -> str | None:
        """ok / pending / dhcp_missing / static_no_lease, None if unknown."""
        hass = getattr(self, "hass", None)
        if hass is None:
            return None
        context = dhcp_context(hass)
        if context is None:
            return None
        leases, arp, static = context
        return client_dhcp_status(
            self._mac,
            client.get(CLIENT_KEY_CONNECTED_SINCE),
            dt_util.utcnow(),
            leases,
            arp,
            static,
        )

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
