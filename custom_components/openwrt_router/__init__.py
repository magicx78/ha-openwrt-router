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
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    Platform,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr, entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtTimeoutError,
)
from .coordinator import OpenWrtCoordinator
from .const import CONF_PROTOCOL, DEFAULT_PROTOCOL, DOMAIN as DOMAIN, PROTOCOL_HTTP

_LOGGER = logging.getLogger(__name__)

# All platforms this integration provides entities on
PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.SWITCH,
    Platform.DEVICE_TRACKER,
    Platform.BUTTON,
    Platform.BINARY_SENSOR,
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


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate config entries from older schema versions.

    v1 → v2: CONF_PROTOCOL was added in v1.16.0.  Entries created before that
    have no protocol key and must fall back to HTTP (the old hard-coded default).
    """
    if config_entry.version == 1:
        new_data = {**config_entry.data}
        if CONF_PROTOCOL not in new_data:
            new_data[CONF_PROTOCOL] = PROTOCOL_HTTP
        hass.config_entries.async_update_entry(config_entry, data=new_data, version=2)
        _LOGGER.info(
            "Migrated OpenWrt entry %s to v2 (protocol=%s)",
            config_entry.entry_id,
            new_data[CONF_PROTOCOL],
        )
    return True


def _merge_orphan_mac_devices(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Merge legacy MAC-identified devices into the canonical entry_id device.

    v1.17.0 created a second HA device per router because binary_sensor and
    OpenWrtRouterStatusSensor used `(DOMAIN, mac)` instead of `(DOMAIN, entry_id)`
    as their device identifier. v1.17.1 unified the identifier — but HA does not
    automatically migrate already-registered entity↔device links, so users still
    saw two devices: the canonical one with ~30 sensors and an orphan one with
    just the 3 new entities.

    This routine runs on every setup. For each device tied to *this* config
    entry whose identifier is NOT `(DOMAIN, entry_id)`:
      1. Move all of its entities to the canonical device.
      2. Delete the orphan device.

    Idempotent — does nothing on systems that never had the bug.
    """
    dev_reg = dr.async_get(hass)
    ent_reg = er.async_get(hass)

    devices = dr.async_entries_for_config_entry(dev_reg, entry.entry_id)
    canonical = next(
        (d for d in devices if (DOMAIN, entry.entry_id) in d.identifiers),
        None,
    )
    if canonical is None:
        # No canonical device yet — platforms will create it on first entity
        # registration; the merge happens on the next setup.
        return

    for device in devices:
        if device.id == canonical.id:
            continue
        # Only merge devices that solely belong to our domain (don't touch
        # devices linked to multiple integrations).
        if any(d != DOMAIN for d, _ in device.identifiers):
            continue
        entities = er.async_entries_for_device(
            ent_reg, device.id, include_disabled_entities=True
        )
        for ent in entities:
            ent_reg.async_update_entity(ent.entity_id, device_id=canonical.id)
        _LOGGER.warning(
            "Merged %d entities from orphan device %s (identifiers=%s) into "
            "canonical OpenWrt device %s — leftover from v1.17.0 device_info bug",
            len(entities),
            device.id,
            device.identifiers,
            canonical.id,
        )
        dev_reg.async_remove_device(device.id)


# Unique-ID suffixes that identify dynamic per-port / per-radio / per-AP /
# per-interface sensors.  v1.17.4 marks the *classes* as
# entity_registry_enabled_default = False, which only affects NEW entities.
# Existing installs (e.g. the user reporting the entity explosion in
# v1.17.3) already have these registered as enabled, so we additionally
# disable them once on next setup.  The user can re-enable individually
# via the HA entity settings.
_LEGACY_DYNAMIC_PATTERNS = (
    "_iface_",  # OpenWrtInterfaceSensor   (entry_id_iface_<name>_rx/tx)
    "_rate",  # OpenWrtInterfaceRateSensor  (entry_id_<name>_rx_rate)
    "_radio_",  # OpenWrtRadioSensor       (entry_id_radio_<ifname>_signal/noise)
    "_ap_",  # OpenWrtAPInterfaceSensor (entry_id_ap_<ifname>_<metric>)
    "_port_",  # OpenWrtPortSensor        (entry_id_port_<name>_<metric>)
)


def _disable_legacy_dynamic_sensors(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Disable dynamic sensors that were registered as enabled by older versions.

    Idempotent — entities the user has explicitly re-enabled stay enabled.
    """
    ent_reg = er.async_get(hass)
    entities = er.async_entries_for_config_entry(ent_reg, entry.entry_id)
    disabled_count = 0
    for ent in entities:
        if ent.disabled_by is not None:
            continue
        if not any(pat in ent.unique_id for pat in _LEGACY_DYNAMIC_PATTERNS):
            continue
        ent_reg.async_update_entity(
            ent.entity_id, disabled_by=er.RegistryEntryDisabler.INTEGRATION
        )
        disabled_count += 1
    if disabled_count:
        _LOGGER.warning(
            "Disabled %d dynamic OpenWrt sensors (per-iface/port/radio/AP) for "
            "entry %s — re-enable individually in HA if needed",
            disabled_count,
            entry.entry_id,
        )


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
    protocol: str = entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)

    _LOGGER.debug(
        "Setting up OpenWrt Router entry for %s:%s (%s)", host, port, protocol
    )

    # Shared aiohttp session managed by HA
    session = async_get_clientsession(hass)

    api = OpenWrtAPI(
        host=host,
        port=port,
        username=username,
        password=password,
        session=session,
        protocol=protocol,
    )

    # Authenticate before creating the coordinator
    try:
        await api.login()
    except OpenWrtAuthError as err:
        raise ConfigEntryAuthFailed(f"Authentication failed for {host}: {err}") from err
    except (OpenWrtConnectionError, OpenWrtTimeoutError) as err:
        raise ConfigEntryNotReady(
            f"Cannot reach OpenWrt router at {host}:{port}: {err}"
        ) from err

    # Stagger polling: spread multiple coordinators evenly across the scan interval
    # so they never all poll simultaneously (e.g. 4 routers × 15s = 0/15/30/45s offsets).
    from .const import SCAN_INTERVAL_SECONDS

    loaded_entries = hass.config_entries.async_entries(DOMAIN)
    stagger_index = sum(1 for e in loaded_entries if e.entry_id != entry.entry_id)
    poll_offset = (stagger_index * SCAN_INTERVAL_SECONDS) // 4

    # Create and populate the coordinator
    coordinator = OpenWrtCoordinator(
        hass=hass,
        api=api,
        entry_title=entry.title,
        entry=entry,
        poll_offset_seconds=poll_offset,
    )

    # First refresh – raises ConfigEntryNotReady if it fails
    await coordinator.async_config_entry_first_refresh()

    # Store runtime data on the entry (accessed by platforms via entry.runtime_data)
    entry.runtime_data = OpenWrtRuntimeData(api=api, coordinator=coordinator)

    # Forward setup to all platforms (sensor, switch, device_tracker, button)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # One-shot cleanup of legacy MAC-identified devices left over from v1.17.0
    _merge_orphan_mac_devices(hass, entry)

    # One-shot mass-disable of dynamic sensors that older versions registered
    # as enabled. Idempotent — only touches entries that are still enabled
    # AND match the dynamic-sensor unique-id patterns.
    _disable_legacy_dynamic_sensors(hass, entry)

    # Register topology panel (idempotent — only registers once per HA session)
    from .topology_panel import async_setup_topology_panel

    await async_setup_topology_panel(hass)

    # Auto-provision rpcd ACL on router if missing (best-effort, non-blocking)
    try:
        from .acl_provisioning import check_and_deploy_acl

        deployed = await check_and_deploy_acl(api)
        if deployed:
            _LOGGER.info("Deployed rpcd ACL to %s — refreshing data", host)
            await coordinator.async_request_refresh()
    except Exception:  # noqa: BLE001
        _LOGGER.debug("ACL provisioning skipped (SSH not available)")

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
