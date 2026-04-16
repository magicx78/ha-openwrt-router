"""Switch platform for the OpenWrt Router integration.

Creates one switch per detected WiFi SSID/interface.
The switch name is the SSID itself (e.g. "HomeNet", "HomeNet-5G", "Guest").
"""

from __future__ import annotations

import logging
import time
from typing import Any

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import OpenWrtConfigEntry
from .api import OpenWrtAPI
from .const import (
    CLIENT_KEY_CONNECTED_SINCE,
    CLIENT_KEY_DHCP_EXPIRES,
    CLIENT_KEY_HOSTNAME,
    CLIENT_KEY_IP,
    CLIENT_KEY_MAC,
    CLIENT_KEY_SIGNAL,
    CLIENT_KEY_SSID,
    CONF_PROTOCOL,
    DEFAULT_PROTOCOL,
    DEFAULT_SERVICES,
    DOMAIN,
    RADIO_KEY_BAND,
    RADIO_KEY_ENABLED,
    RADIO_KEY_IFNAME,
    RADIO_KEY_IS_GUEST,
    RADIO_KEY_SSID,
    RADIO_KEY_UCI_SECTION,
)
from .coordinator import OpenWrtCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: OpenWrtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one WiFi switch per detected SSID.

    Iterates coordinator.data.wifi_radios and creates a switch for each
    radio/interface that has a known UCI section (required for writing).
    """
    coordinator: OpenWrtCoordinator = entry.runtime_data.coordinator
    api: OpenWrtAPI = entry.runtime_data.api

    entities: list[OpenWrtWifiSwitchEntity | OpenWrtServiceSwitch] = []

    if coordinator.data:
        for radio in coordinator.data.wifi_radios:
            uci_section = radio.get(RADIO_KEY_UCI_SECTION, "")
            ifname = radio.get(RADIO_KEY_IFNAME, "")

            if not uci_section and not ifname:
                _LOGGER.debug(
                    "Skipping radio %s – no UCI section or ifname", radio
                )
                continue

            entities.append(
                OpenWrtWifiSwitchEntity(
                    coordinator=coordinator,
                    api=api,
                    entry=entry,
                    radio=radio,
                )
            )

    # --- Service switches (one per detected service) ---
    if coordinator.data:
        detected_names = {s["name"] for s in coordinator.data.services}
        for svc_name in DEFAULT_SERVICES:
            if svc_name in detected_names:
                entities.append(
                    OpenWrtServiceSwitch(
                        coordinator=coordinator,
                        api=api,
                        entry=entry,
                        service_name=svc_name,
                    )
                )

    async_add_entities(entities)
    _LOGGER.debug("Added %d OpenWrt switch entities", len(entities))


class OpenWrtWifiSwitchEntity(CoordinatorEntity[OpenWrtCoordinator], SwitchEntity):
    """Switch entity that enables/disables a single WiFi SSID via UCI.

    Entity name = SSID (e.g. "HomeNet", "HomeNet-5G").
    State is read from coordinator.data.wifi_radios.
    Control is sent via api.set_wifi_state(uci_section, enabled).
    """

    _attr_has_entity_name = False
    _attr_device_class = SwitchDeviceClass.SWITCH

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        api: OpenWrtAPI,
        entry: OpenWrtConfigEntry,
        radio: dict[str, Any],
    ) -> None:
        """Initialise the switch entity.

        Args:
            coordinator: Shared data coordinator.
            api: API client for write operations.
            entry: Config entry.
            radio: Radio descriptor dict from coordinator at setup time.
        """
        super().__init__(coordinator)
        self._api = api
        self._entry = entry

        # Stable identifiers used for lookups and unique_id
        self._uci_section: str = radio.get(RADIO_KEY_UCI_SECTION, "")
        self._ifname: str = radio.get(RADIO_KEY_IFNAME, "")
        self._band: str = radio.get(RADIO_KEY_BAND, "")
        self._is_guest: bool = radio.get(RADIO_KEY_IS_GUEST, False)
        self._ssid: str = radio.get(RADIO_KEY_SSID, "") or self._ifname

        # Stable unique ID: prefer UCI section, fallback to ifname
        uid_key = self._uci_section or self._ifname
        self._attr_unique_id = f"{entry.entry_id}_wifi_ssid_{uid_key}"

        # Entity name is computed dynamically via the name property so that
        # SSIDs fetched after setup (e.g. via luci-rpc fallback) are reflected.

        # Icon: star for guest networks
        self._attr_icon = "mdi:wifi-star" if self._is_guest else "mdi:wifi"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info to group this entity under the router device card."""
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
    def name(self) -> str:
        """Return entity name as 'SSID (Band)', updated whenever coordinator data changes."""
        radio = self._get_current_radio()
        ssid = (radio.get(RADIO_KEY_SSID, "") if radio else "") or self._ssid
        # Read band from current coordinator data; fall back to value captured at init
        band = (radio.get(RADIO_KEY_BAND, "") if radio else "") or self._band
        band_display = self._format_band(band)
        return f"{ssid} ({band_display})" if band_display else ssid

    @property
    def is_on(self) -> bool | None:
        """Return True if the SSID is currently enabled."""
        radio = self._get_current_radio()
        if radio is None:
            return None
        return bool(radio.get(RADIO_KEY_ENABLED, False))

    @property
    def available(self) -> bool:
        """Return True if the coordinator has data and the radio is present."""
        return super().available and self._get_current_radio() is not None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return additional attributes including connected client list."""
        radio = self._get_current_radio()
        if radio is None:
            return {}

        ssid = radio.get(RADIO_KEY_SSID, "")
        clients = self._get_clients_for_ssid(ssid) if ssid else []

        return {
            "ssid": ssid,
            "band": radio.get(RADIO_KEY_BAND, ""),
            "ifname": radio.get(RADIO_KEY_IFNAME, ""),
            "uci_section": radio.get(RADIO_KEY_UCI_SECTION, ""),
            "is_guest": radio.get(RADIO_KEY_IS_GUEST, False),
            "connected_clients": len(clients),
            "clients": clients,
        }

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable the SSID."""
        _LOGGER.debug(
            "Turning ON WiFi SSID %s (section=%s)", self._ssid, self._uci_section
        )
        if not self._uci_section:
            _LOGGER.warning(
                "Cannot enable WiFi: UCI section unknown for %s", self._ifname
            )
            return
        await self._api.set_wifi_state(self._uci_section, enabled=True)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable the SSID."""
        _LOGGER.debug(
            "Turning OFF WiFi SSID %s (section=%s)", self._ssid, self._uci_section
        )
        if not self._uci_section:
            _LOGGER.warning(
                "Cannot disable WiFi: UCI section unknown for %s", self._ifname
            )
            return
        await self._api.set_wifi_state(self._uci_section, enabled=False)
        await self.coordinator.async_request_refresh()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_current_radio(self) -> dict[str, Any] | None:
        """Find the current radio data in coordinator by UCI section or ifname."""
        if not self.coordinator.data:
            return None

        for radio in self.coordinator.data.wifi_radios:
            # Prefer exact UCI section match (most stable)
            if self._uci_section and radio.get(RADIO_KEY_UCI_SECTION) == self._uci_section:
                return radio
            # Fallback: interface name
            if self._ifname and radio.get(RADIO_KEY_IFNAME) == self._ifname:
                return radio

        return None

    def _format_band(self, band: str) -> str:
        """Format band code to human-readable string.

        Args:
            band: Band code (e.g. "2g", "5g", "6g", "60g").

        Returns:
            Formatted band string (e.g. "2.4 GHz", "5 GHz") or empty string if unknown.
        """
        band_map = {
            "2g": "2.4 GHz",
            "2.4g": "2.4 GHz",  # _detect_band() returns "2.4g" for 2.4 GHz radios
            "5g": "5 GHz",
            "6g": "6 GHz",
            "60g": "60 GHz",
        }
        return band_map.get(band, "")

    def _get_clients_for_ssid(self, ssid: str) -> list[dict[str, Any]]:
        """Return enriched client list for this SSID.

        Each entry contains name (hostname or MAC), mac, ip, signal,
        connected_since, and dhcp_expires (as ISO-8601 datetime string or
        empty string when unknown).

        Args:
            ssid: SSID name to match.

        Returns:
            List of dicts, one per connected client.
        """
        if not self.coordinator.data or not ssid:
            return []
        result = []
        for client in self.coordinator.data.clients:
            if client.get(CLIENT_KEY_SSID) != ssid:
                continue
            mac: str = client.get(CLIENT_KEY_MAC, "")
            ip: str = client.get(CLIENT_KEY_IP, "")
            hostname: str = client.get(CLIENT_KEY_HOSTNAME, "")
            signal: int = client.get(CLIENT_KEY_SIGNAL, 0)
            connected_since: str = client.get(CLIENT_KEY_CONNECTED_SINCE, "")
            expires_ts: int = client.get(CLIENT_KEY_DHCP_EXPIRES, 0)
            dhcp_expires = self._format_dhcp_expires(expires_ts)
            result.append(
                {
                    "name": hostname or mac,
                    "mac": mac,
                    "ip": ip,
                    "signal_dbm": signal,
                    "connected_since": connected_since,
                    "dhcp_expires": dhcp_expires,
                }
            )
        return result

    @staticmethod
    def _format_dhcp_expires(expires_ts: int) -> str:
        """Convert a Unix expiry timestamp to a human-readable remaining time.

        Returns strings like "2h 14m", "45m", "<1m", or "" when unknown.
        """
        if not expires_ts:
            return ""
        remaining = int(expires_ts - time.time())
        if remaining <= 0:
            return "expired"
        hours, rem = divmod(remaining, 3600)
        minutes = rem // 60
        if hours > 0:
            return f"{hours}h {minutes}m"
        if minutes > 0:
            return f"{minutes}m"
        return "<1m"


class OpenWrtServiceSwitch(CoordinatorEntity[OpenWrtCoordinator], SwitchEntity):
    """Switch entity to start/stop a procd-managed OpenWrt service.

    State: True = service is running, False = stopped.
    Turn on  → rc/init start
    Turn off → rc/init stop
    """

    _attr_has_entity_name = False
    _attr_device_class = SwitchDeviceClass.SWITCH
    _attr_entity_category = None  # visible by default

    # Icon map for well-known services
    _SERVICE_ICONS: dict[str, str] = {
        "dnsmasq": "mdi:dns",
        "dropbear": "mdi:console-network",
        "firewall": "mdi:wall-fire",
        "network": "mdi:lan",
        "uhttpd": "mdi:web",
        "wpad": "mdi:wifi-lock",
    }

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        api: OpenWrtAPI,
        entry: OpenWrtConfigEntry,
        service_name: str,
    ) -> None:
        super().__init__(coordinator)
        self._api = api
        self._entry = entry
        self._service_name = service_name

        self._attr_unique_id = f"{entry.entry_id}_service_{service_name}"
        self._attr_name = f"Service: {service_name}"
        self._attr_icon = self._SERVICE_ICONS.get(service_name, "mdi:cog")

    @property
    def device_info(self) -> DeviceInfo:
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
    def is_on(self) -> bool | None:
        svc = self._get_service()
        if svc is None:
            return None
        return svc.get("running", False)

    @property
    def available(self) -> bool:
        return super().available and self._get_service() is not None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        svc = self._get_service()
        if svc is None:
            return {}
        return {
            "enabled": svc.get("enabled", False),
            "running": svc.get("running", False),
        }

    async def async_turn_on(self, **kwargs: Any) -> None:
        _LOGGER.debug("Starting service %s", self._service_name)
        await self._api.control_service(self._service_name, "start")
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        _LOGGER.debug("Stopping service %s", self._service_name)
        await self._api.control_service(self._service_name, "stop")
        await self.coordinator.async_request_refresh()

    def _get_service(self) -> dict[str, Any] | None:
        if not self.coordinator.data:
            return None
        for svc in self.coordinator.data.services:
            if svc.get("name") == self._service_name:
                return svc
        return None
