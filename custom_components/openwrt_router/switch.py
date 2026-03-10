"""Switch platform for the OpenWrt Router integration.

Provides toggleable switches for:
    - WiFi 2.4 GHz radio
    - WiFi 5 GHz radio  (only created if a 5 GHz radio is detected)
    - WiFi 6 GHz radio  (only created if a 6 GHz radio is detected)
    - Guest WiFi        (only created if a guest SSID is detected)

Each switch reads its state from the coordinator and writes changes
through the API via UCI set + commit + reload.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity, SwitchEntityDescription
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
    RADIO_KEY_IS_GUEST,
    RADIO_KEY_UCI_SECTION,
    SUFFIX_GUEST_WIFI,
    SUFFIX_WIFI_24,
    SUFFIX_WIFI_50,
    SUFFIX_WIFI_60,
)
from .coordinator import OpenWrtCoordinator

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class OpenWrtSwitchEntityDescription(SwitchEntityDescription):
    """Extended switch description with band / role selector.

    Attributes:
        band: WiFi band string ('2.4g', '5g', '6g') or None for guest.
        is_guest: True if this switch targets the guest WiFi.
    """

    band: str | None = None
    is_guest: bool = False


SWITCH_DESCRIPTIONS: tuple[OpenWrtSwitchEntityDescription, ...] = (
    OpenWrtSwitchEntityDescription(
        key=SUFFIX_WIFI_24,
        translation_key="wifi_24ghz",
        device_class=SwitchDeviceClass.SWITCH,
        icon="mdi:wifi",
        band="2.4g",
    ),
    OpenWrtSwitchEntityDescription(
        key=SUFFIX_WIFI_50,
        translation_key="wifi_5ghz",
        device_class=SwitchDeviceClass.SWITCH,
        icon="mdi:wifi",
        band="5g",
    ),
    OpenWrtSwitchEntityDescription(
        key=SUFFIX_WIFI_60,
        translation_key="wifi_6ghz",
        device_class=SwitchDeviceClass.SWITCH,
        icon="mdi:wifi",
        band="6g",
    ),
    OpenWrtSwitchEntityDescription(
        key=SUFFIX_GUEST_WIFI,
        translation_key="guest_wifi",
        device_class=SwitchDeviceClass.SWITCH,
        icon="mdi:wifi-star",
        is_guest=True,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: OpenWrtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up OpenWrt switch entities from a config entry.

    Only creates switches for radios that were actually detected during
    feature detection. Switches for unavailable bands are skipped.

    Args:
        hass: Home Assistant instance.
        entry: Config entry carrying runtime_data.
        async_add_entities: Callback to register new entities with HA.
    """
    coordinator: OpenWrtCoordinator = entry.runtime_data.coordinator
    api: OpenWrtAPI = entry.runtime_data.api

    entities: list[OpenWrtWifiSwitchEntity] = []

    for description in SWITCH_DESCRIPTIONS:
        # Determine if this radio / band exists on the router
        if description.is_guest:
            if not coordinator.has_guest_wifi:
                _LOGGER.debug(
                    "Skipping guest WiFi switch – no guest SSID detected"
                )
                continue
            radio = coordinator.get_guest_radio()
        else:
            if description.band == "5g" and not coordinator.has_5ghz:
                _LOGGER.debug("Skipping 5 GHz switch – no 5 GHz radio detected")
                continue
            if description.band == "6g" and not coordinator.has_6ghz:
                _LOGGER.debug("Skipping 6 GHz switch – no 6 GHz radio detected")
                continue
            radio = coordinator.get_radio_by_band(description.band or "")

        if radio is None:
            _LOGGER.debug(
                "Skipping switch %s – no matching radio in coordinator data",
                description.key,
            )
            continue

        entities.append(
            OpenWrtWifiSwitchEntity(
                coordinator=coordinator,
                api=api,
                entry=entry,
                description=description,
                radio=radio,
            )
        )

    async_add_entities(entities)
    _LOGGER.debug("Added %d OpenWrt switch entities", len(entities))


class OpenWrtWifiSwitchEntity(CoordinatorEntity[OpenWrtCoordinator], SwitchEntity):
    """Switch entity that enables/disables a WiFi radio via UCI.

    State is read from coordinator.data (wifi_radios list).
    Control is sent via api.set_wifi_state(uci_section, enabled).
    """

    entity_description: OpenWrtSwitchEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        api: OpenWrtAPI,
        entry: OpenWrtConfigEntry,
        description: OpenWrtSwitchEntityDescription,
        radio: dict[str, Any],
    ) -> None:
        """Initialise the switch entity.

        Args:
            coordinator: Shared data coordinator.
            api: API client for write operations.
            entry: Config entry.
            description: Entity description (band, is_guest).
            radio: Radio descriptor dict from coordinator at setup time.
        """
        super().__init__(coordinator)
        self.entity_description = description
        self._api = api
        self._entry = entry

        # Store the UCI section and interface name for later write calls
        self._uci_section: str = radio.get(RADIO_KEY_UCI_SECTION, "")
        self._ifname: str = radio.get("ifname", "")
        self._band: str = radio.get(RADIO_KEY_BAND, "")
        self._is_guest: bool = radio.get(RADIO_KEY_IS_GUEST, False)

        self._attr_unique_id = f"{entry.entry_id}_{description.key}"

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
        """Return True if the radio is currently enabled.

        Reads from coordinator.data.wifi_radios; returns None while data
        is not yet available.
        """
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
        """Return additional attributes for the switch."""
        radio = self._get_current_radio()
        if radio is None:
            return {}
        return {
            "ssid": radio.get("ssid", ""),
            "ifname": radio.get("ifname", ""),
            "band": radio.get(RADIO_KEY_BAND, ""),
            "uci_section": radio.get(RADIO_KEY_UCI_SECTION, ""),
        }

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Enable the WiFi radio.

        Sets UCI disabled=0, commits, and reloads network.
        The coordinator will pick up the new state on the next poll.
        """
        _LOGGER.debug("Turning ON WiFi switch %s (section=%s)", self._ifname, self._uci_section)
        if not self._uci_section:
            _LOGGER.warning(
                "Cannot enable WiFi: UCI section unknown for %s", self._ifname
            )
            return
        await self._api.set_wifi_state(self._uci_section, enabled=True)
        await self.coordinator.async_request_refresh()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Disable the WiFi radio.

        Sets UCI disabled=1, commits, and reloads network.
        The coordinator will pick up the new state on the next poll.
        """
        _LOGGER.debug("Turning OFF WiFi switch %s (section=%s)", self._ifname, self._uci_section)
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
        """Find the current radio data in coordinator by interface name.

        Returns:
            Radio dict from coordinator.data.wifi_radios or None.
        """
        if not self.coordinator.data:
            return None

        if self._is_guest:
            return self.coordinator.get_guest_radio()

        if self._ifname:
            # Exact match by interface name
            for radio in self.coordinator.data.wifi_radios:
                if radio.get("ifname") == self._ifname:
                    return radio

        # Fallback: match by band
        if self._band:
            return self.coordinator.get_radio_by_band(self._band)

        return None
