"""Button platform for the OpenWrt Router integration.

Provides:
    - Reload WiFi button  (triggers network.reload on the router)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity, ButtonEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import OpenWrtConfigEntry
from .api import OpenWrtAPI
from .const import DOMAIN, SUFFIX_RELOAD_WIFI
from .coordinator import OpenWrtCoordinator

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class OpenWrtButtonEntityDescription(ButtonEntityDescription):
    """Extended button description (reserved for future per-button config)."""


BUTTON_DESCRIPTIONS: tuple[OpenWrtButtonEntityDescription, ...] = (
    OpenWrtButtonEntityDescription(
        key=SUFFIX_RELOAD_WIFI,
        translation_key="reload_wifi",
        device_class=ButtonDeviceClass.RESTART,
        entity_category=EntityCategory.CONFIG,
        icon="mdi:wifi-sync",
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: OpenWrtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up OpenWrt button entities from a config entry.

    Args:
        hass: Home Assistant instance.
        entry: Config entry carrying runtime_data.
        async_add_entities: Callback to register new entities with HA.
    """
    coordinator: OpenWrtCoordinator = entry.runtime_data.coordinator
    api: OpenWrtAPI = entry.runtime_data.api

    entities = [
        OpenWrtButtonEntity(
            coordinator=coordinator,
            api=api,
            entry=entry,
            description=description,
        )
        for description in BUTTON_DESCRIPTIONS
    ]

    async_add_entities(entities)
    _LOGGER.debug("Added %d OpenWrt button entities", len(entities))


class OpenWrtButtonEntity(ButtonEntity):
    """A button that triggers an action directly on the router.

    Unlike sensors and switches, buttons do not subscribe to the coordinator
    because they have no persistent state to display.  They hold a reference
    to the API client directly.
    """

    entity_description: OpenWrtButtonEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        api: OpenWrtAPI,
        entry: OpenWrtConfigEntry,
        description: OpenWrtButtonEntityDescription,
    ) -> None:
        """Initialise the button entity.

        Args:
            coordinator: Coordinator (used for device_info and refresh after press).
            api: API client for write operations.
            entry: Config entry.
            description: Entity description.
        """
        self.entity_description = description
        self._coordinator = coordinator
        self._api = api
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"

    @property
    def device_info(self) -> DeviceInfo:
        """Return device info to group this entity under the router device card."""
        router_info = self._coordinator.router_info
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

    async def async_press(self) -> None:
        """Handle a button press.

        Sends the reload command to the router, then requests a coordinator
        refresh so that entity states reflect the post-reload configuration.
        """
        _LOGGER.debug(
            "Button pressed: %s – reloading WiFi on %s",
            self.entity_description.key,
            self._entry.data.get("host"),
        )

        success = await self._api.reload_wifi()
        if success:
            _LOGGER.info(
                "WiFi reloaded successfully on %s", self._entry.data.get("host")
            )
        else:
            _LOGGER.warning(
                "WiFi reload command was not confirmed by %s – "
                "network.reload may not be available on this router",
                self._entry.data.get("host"),
            )

        # Refresh coordinator data after reload (config may have changed)
        await self._coordinator.async_request_refresh()
