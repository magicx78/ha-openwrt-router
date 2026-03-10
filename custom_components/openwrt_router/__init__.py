"""OpenWrt Router integration for Home Assistant.

Connects to an OpenWrt router via ubus / rpcd JSON-RPC and exposes
router status, WiFi controls, and connected clients as Home Assistant entities.

Supported platforms:
    - sensor        (uptime, WAN status, client count)
    - switch        (WiFi 2.4 GHz, 5 GHz, guest)
    - device_tracker (associated WiFi clients)
    - button        (reload WiFi)

Architecture:
    Config Entry → runtime_data (OpenWrtRuntimeData)
                       ├── api: OpenWrtAPI
                       └── coordinator: OpenWrtCoordinator
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtTimeoutError,
)
from .coordinator import OpenWrtCoordinator
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# All platforms this integration provides entities on
PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.SWITCH,
    Platform.DEVICE_TRACKER,
    Platform.BUTTON,
]


@dataclass
class OpenWrtRuntimeData:
    """Runtime data stored on the config entry.

    Accessed by platforms via: entry.runtime_data

    Attributes:
        api: Authenticated API client for direct calls (e.g. from buttons).
        coordinator: DataUpdateCoordinator that all entities subscribe to.
    """

    api: OpenWrtAPI
    coordinator: OpenWrtCoordinator


# Type alias for the config entry with our runtime_data type
type OpenWrtConfigEntry = ConfigEntry[OpenWrtRuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> bool:
    """Set up OpenWrt Router from a config entry.

    Called by HA after the user completes the config flow (or on restart
    if a config entry already exists).

    Steps:
        1. Create an aiohttp session and API client.
        2. Authenticate (raises ConfigEntryAuthFailed on bad credentials).
        3. Create the DataUpdateCoordinator and do the first data refresh.
        4. Store runtime_data on the config entry.
        5. Forward setup to all platforms.

    Args:
        hass: Home Assistant instance.
        entry: Config entry with host, port, username, password.

    Returns:
        True on success.

    Raises:
        ConfigEntryAuthFailed: Credentials are invalid.
        ConfigEntryNotReady: Router unreachable or first refresh failed.
    """
    host: str = entry.data[CONF_HOST]
    port: int = entry.data[CONF_PORT]
    username: str = entry.data[CONF_USERNAME]
    password: str = entry.data[CONF_PASSWORD]  # never logged

    _LOGGER.debug("Setting up OpenWrt Router entry for %s:%s", host, port)

    # Shared aiohttp session managed by HA
    session = async_get_clientsession(hass)

    api = OpenWrtAPI(
        host=host,
        port=port,
        username=username,
        password=password,
        session=session,
    )

    # Authenticate before creating the coordinator
    try:
        await api.login()
    except OpenWrtAuthError as err:
        raise ConfigEntryAuthFailed(
            f"Authentication failed for {host}: {err}"
        ) from err
    except (OpenWrtConnectionError, OpenWrtTimeoutError) as err:
        raise ConfigEntryNotReady(
            f"Cannot reach OpenWrt router at {host}:{port}: {err}"
        ) from err

    # Create and populate the coordinator
    coordinator = OpenWrtCoordinator(
        hass=hass,
        api=api,
        entry_title=entry.title,
    )

    # First refresh – raises ConfigEntryNotReady if it fails
    await coordinator.async_config_entry_first_refresh()

    # Store runtime data on the entry (accessed by platforms via entry.runtime_data)
    entry.runtime_data = OpenWrtRuntimeData(api=api, coordinator=coordinator)

    # Forward setup to all platforms (sensor, switch, device_tracker, button)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    _LOGGER.info(
        "OpenWrt Router '%s' set up successfully (model: %s, host: %s:%s)",
        entry.title,
        coordinator.router_info.get("model", "unknown"),
        host,
        port,
    )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> bool:
    """Unload a config entry.

    Called when the user removes the integration or HA is restarting.
    Unloads all platform entities; the coordinator and session are cleaned
    up automatically when no longer referenced.

    Args:
        hass: Home Assistant instance.
        entry: The config entry being removed.

    Returns:
        True if all platforms unloaded successfully.
    """
    _LOGGER.debug("Unloading OpenWrt Router entry for %s", entry.data.get(CONF_HOST))
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_reload_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> None:
    """Reload a config entry (e.g. after options change or re-auth).

    Args:
        hass: Home Assistant instance.
        entry: The config entry to reload.
    """
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
