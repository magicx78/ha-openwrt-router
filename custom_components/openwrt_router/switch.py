"""Switch platform for the OpenWrt Router integration.

Creates one switch per detected WiFi SSID/interface.
The switch name is the SSID itself (e.g. "HomeNet", "HomeNet-5G", "Guest").
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import OpenWrtConfigEntry
from .api import OpenWrtAPI
from .const import (
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

    entities: list[OpenWrtWifiSwitchEntity] = []

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

    async_add_entities(entities)
    _LOGGER.debug("Added %d OpenWrt WiFi switch entities", len(entities))


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

        # Entity name = SSID (Band)
        # Format: "secure-IoT (2.4 GHz)" or "Guest-WLAN (5 GHz)"
        band_display = self._format_band(self._band)
        self._attr_name = f"{self._ssid} ({band_display})" if band_display else self._ssid

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
                f"http://{self._entry.data['host']}:{self._entry.data['port']}"
            ),
        )

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
        """Return additional attributes (ssid, band, ifname, uci_section, client_count)."""
        radio = self._get_current_radio()
        if radio is None:
            return {}

        # Count clients connected to this SSID
        ssid = radio.get(RADIO_KEY_SSID, "")
        client_count = self._count_clients_for_ssid(ssid) if ssid else 0

        return {
            "ssid": ssid,
            "band": radio.get(RADIO_KEY_BAND, ""),
            "ifname": radio.get(RADIO_KEY_IFNAME, ""),
            "uci_section": radio.get(RADIO_KEY_UCI_SECTION, ""),
            "is_guest": radio.get(RADIO_KEY_IS_GUEST, False),
            "connected_clients": client_count,
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
            "5g": "5 GHz",
            "6g": "6 GHz",
            "60g": "60 GHz",
        }
        return band_map.get(band, "")

    def _count_clients_for_ssid(self, ssid: str) -> int:
        """Count clients currently connected to this SSID.

        Args:
            ssid: SSID name to match.

        Returns:
            Number of connected clients for this SSID.
        """
        if not self.coordinator.data or not ssid:
            return 0
        return sum(
            1 for client in self.coordinator.data.clients
            if client.get("ssid") == ssid
        )
