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

import asyncio
import logging
from dataclasses import dataclass
from functools import partial
from typing import Any

from homeassistant.config_entries import SOURCE_IGNORE, ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    Platform,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import config_validation as cv  # configuration manager
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType  # configuration manager

from .api import (
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
)
from .client_engine import async_get_client_stability, async_unload_client_stability
from .const import CONF_PROTOCOL, DEFAULT_PROTOCOL, DOMAIN, PROTOCOL_HTTP
from .coordinator import OpenWrtCoordinator
from .fleet import (
    async_get_channel_plan_monitor,
    async_get_outage_tracker,
    usteer_node_info,
)
from .issues import (
    acl_base_rights_issue_id,
    async_clear_issue,
    async_sync_acl_base_rights_issue,
    ram_high_issue_id,
)
from .net_engine import (
    async_get_net_intelligence,
    async_remove_router_data,
    async_unload_net_intelligence,
)
from .ssl_util import ssl_context_for_protocol

# Enterprise core: imported here, not inside the setup functions. HA imports
# the integration package in the executor, so the ~300 ms import of the core
# modules never runs on the event loop ("blocking call to import_module").
# Guarded: a broken core must not break the integration, the routers work
# without it. Every hook below checks for None and stays inside its own
# try/except; the warning is logged once, when the package is imported.
_core_import_error: Exception | None = None
try:
    from . import enterprise_core as _enterprise_core
except Exception as _err:  # noqa: BLE001 - any error raised by the core import
    _enterprise_core = None  # type: ignore[assignment]
    _core_import_error = _err

# --- Configuration manager (plan 2026-11-18, section 1): imported here for
# the same reason as the core; None when the core (or it) cannot be imported.
try:
    from . import config_manager as _config_manager
except Exception:  # noqa: BLE001 - the routers work without it
    _config_manager = None  # type: ignore[assignment]
# --- end configuration manager

_LOGGER = logging.getLogger(__name__)

if _core_import_error is not None:
    _LOGGER.warning(
        "Enterprise core unavailable (import failed: %s) — the routers work "
        "without it; router ids, config versions and the audit log are off",
        type(_core_import_error).__name__,
        exc_info=_core_import_error,
    )

# Grace periods around the ACL-deploy rpcd restart (tests patch these to 0).
_ACL_DEPLOY_GRACE_S: float = 2.0
_ACL_LOGIN_RETRY_DELAY_S: float = 1.5

# All platforms this integration provides entities on
PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.SWITCH,
    Platform.DEVICE_TRACKER,
    Platform.BUTTON,
    Platform.BINARY_SENSOR,
]

# --- Configuration manager (plan 2026-11-18, section 4): the action
# openwrt_router.create_config_backup. Config entries only (no YAML); the
# action is registered once here and stays registered across entry reloads.
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Register the integration's actions (independent of config entries)."""
    if _config_manager is not None:
        try:
            _config_manager.async_register_services(hass)
        except Exception:
            _LOGGER.warning(
                "The configuration backup action could not be registered",
                exc_info=True,
            )
    return True


# --- end configuration manager action


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

    v2.1 → v2.2: the legacy dynamic-sensor mass-disable used to run on every
    setup, so sensors the user re-enabled were disabled again on each reload.
    It now runs exactly once per entry; entries created by the config flow
    start at minor version 2 and never run it.
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
    if config_entry.version == 2 and config_entry.minor_version < 2:
        _disable_legacy_dynamic_sensors(hass, config_entry)
        hass.config_entries.async_update_entry(config_entry, minor_version=2)
        _LOGGER.info(
            "Migrated OpenWrt entry %s to v2.2 (legacy sensor disable done)",
            config_entry.entry_id,
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
# disable them once, via the config-entry migration to minor version 2.
# The user can re-enable individually via the HA entity settings.
_LEGACY_DYNAMIC_PATTERNS = (
    "_iface_",  # OpenWrtInterfaceSensor   (entry_id_iface_<name>_rx/tx)
    "_rate",  # OpenWrtInterfaceRateSensor  (entry_id_<name>_rx_rate)
    "_radio_",  # OpenWrtRadioSensor       (entry_id_radio_<ifname>_signal/noise)
    "_ap_",  # OpenWrtAPInterfaceSensor (entry_id_ap_<ifname>_<metric>)
    "_port_",  # OpenWrtPortSensor        (entry_id_port_<name>_<metric>)
)


def _disable_legacy_dynamic_sensors(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Disable dynamic sensors that were registered as enabled by older versions.

    Called once per entry from :func:`async_migrate_entry`. Until v1.28.2 it
    ran on every setup, so any entry that has already been set up with
    v1.17.4 or later carries at least one dynamic sensor disabled by the
    integration. Such an entry has had the cleanup already; its enabled
    dynamic sensors were turned on by the user and are left alone.
    """
    ent_reg = er.async_get(hass)
    entities = er.async_entries_for_config_entry(ent_reg, entry.entry_id)
    dynamic = [
        ent
        for ent in entities
        if any(pat in ent.unique_id for pat in _LEGACY_DYNAMIC_PATTERNS)
    ]
    if any(ent.disabled_by == er.RegistryEntryDisabler.INTEGRATION for ent in dynamic):
        return
    disabled_count = 0
    for ent in dynamic:
        if ent.disabled_by is not None:
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


def _core_note_acl(hass: HomeAssistant, entry: ConfigEntry, outcome: Any) -> None:
    """Tell the enterprise core what ensure_acl saw (no router call).

    ``outcome`` None = ensure failed or was skipped: the core reports the
    rf.* capabilities as unknown. Never raises (logged).
    """
    if _enterprise_core is None:
        return
    try:
        from .acl_provisioning import observe_deployed_acl

        core = _enterprise_core.async_get_core(hass)
        if core is None:
            return
        core.registry.note_deployed_acl(
            entry.entry_id,
            observe_deployed_acl(outcome, failure="ensure_failed"),
        )
    except Exception:
        _LOGGER.warning(
            "Enterprise core: recording the deployed ACL of '%s' failed",
            entry.title,
            exc_info=True,
        )


def _sync_acl_base_rights_issue(
    hass: HomeAssistant, entry: ConfigEntry, outcome: Any
) -> None:
    """Repair issue for a kept tiered ACL that lacks base read rights.

    Opened when ensure kept such an ACL, cleared when the deployed ACL is
    complete again and on unload; unknown (ensure failed) changes nothing.
    Never raises (logged).
    """
    issue_id = acl_base_rights_issue_id(entry.entry_id)
    entry.async_on_unload(partial(async_clear_issue, hass, issue_id))
    try:
        from .acl_provisioning import ACL_FILE_PATH

        known = outcome is not None and getattr(outcome, "known", False)
        async_sync_acl_base_rights_issue(
            hass,
            entry.entry_id,
            entry.title,
            tuple(outcome.missing_base_rights) if known else None,
            ACL_FILE_PATH,
        )
    except Exception:
        _LOGGER.warning(
            "Repair issue for the ACL of '%s' could not be updated",
            entry.title,
            exc_info=True,
        )


def _stagger_offset(entry_ids: list[str], entry_id: str, interval: int) -> int:
    """Return the poll offset of ``entry_id`` within ``interval`` seconds.

    The index is the position of the entry in the sorted list of entry ids
    (the entry itself is always included), so every entry gets a stable,
    distinct slot no matter in which order the entries are set up.
    """
    ids = sorted(set(entry_ids) | {entry_id})
    return (ids.index(entry_id) * interval) // len(ids)


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

    # --- Enterprise core (part 1): router id BEFORE any router contact, so an
    # entry stuck in setup_retry still has its stable id. Never fails setup.
    try:
        if _enterprise_core is not None:
            await _enterprise_core.async_setup_entry_core(hass, entry)
    except Exception:
        _LOGGER.warning(
            "Enterprise core: router id assignment failed for '%s' — the "
            "router works without it",
            entry.title,
            exc_info=True,
        )
    # --- end enterprise core

    # Shared aiohttp session managed by HA
    session = async_get_clientsession(hass)

    api = OpenWrtAPI(
        host=host,
        port=port,
        username=username,
        password=password,
        session=session,
        protocol=protocol,
        ssl_context=ssl_context_for_protocol(protocol),
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
    except OpenWrtResponseError as err:
        # rpcd restarting, uhttpd answering 5xx, HTML instead of JSON: not a
        # credential problem — retry instead of opening the reauth dialog.
        raise ConfigEntryNotReady(
            f"OpenWrt router at {host}:{port} did not answer as rpcd: {err}"
        ) from err

    # Ensure the rpcd ACL is present AND current BEFORE the first data refresh.
    # Running it afterwards (as in ≤v1.23) meant the first refresh cached every
    # ACL-denied ubus method in the API client's _acl_blocked set; those stayed
    # short-circuited even after the ACL was deployed, so the router came up
    # degraded until the next reload/restart. Deploying first — then re-logging
    # in and clearing the block cache — lets the very first poll use the freshly
    # granted methods. Best-effort: a router that blocks the deploy still works
    # via the SSH fallbacks, so failures here must never abort setup.
    # 1.44.0: the variant that leaves an approved tiered ACL alone (same single
    # file/read, zero extra router calls); its outcome tells the enterprise
    # core which rights the deployed ACL grants (rf.* capabilities).
    acl_outcomes: list[Any] = []
    try:
        from .acl_provisioning import ensure_acl_respecting_offer

        acl_deployed = await ensure_acl_respecting_offer(
            api, observe=acl_outcomes.append
        )
    except Exception:
        acl_deployed = False
        _LOGGER.debug("rpcd ACL provisioning skipped for %s", host, exc_info=True)
    acl_outcome = acl_outcomes[0] if acl_outcomes else None
    _core_note_acl(hass, entry, acl_outcome)
    _sync_acl_base_rights_issue(hass, entry, acl_outcome)

    if acl_deployed:
        _LOGGER.info("rpcd ACL on %s was deployed/updated", host)
        # rpcd restarts after a deploy — wait briefly, then re-login so the new
        # session carries the freshly granted ACL grants.
        await asyncio.sleep(_ACL_DEPLOY_GRACE_S)
        try:
            await api.login()
        except (
            OpenWrtConnectionError,
            OpenWrtTimeoutError,
            OpenWrtAuthError,
            OpenWrtResponseError,  # uhttpd answers 5xx while rpcd restarts
        ):
            await asyncio.sleep(_ACL_LOGIN_RETRY_DELAY_S)
            try:
                await api.login()
            except Exception:
                _LOGGER.debug(
                    "Re-login after ACL deploy on %s failed (non-fatal)",
                    host,
                    exc_info=True,
                )
    # Drop any methods that ensure_acl's own probes cached as ACL-blocked so the
    # first refresh re-probes them against the now-current ACL.
    api.reset_acl_blocked()

    # Stagger polling: spread multiple coordinators evenly across the scan interval
    # so they never all poll simultaneously (e.g. 4 routers × 15s = 0/15/30/45s offsets).
    from .const import SCAN_INTERVAL_SECONDS

    poll_offset = _stagger_offset(
        [
            e.entry_id
            for e in hass.config_entries.async_entries(DOMAIN)
            if e.disabled_by is None and e.source != SOURCE_IGNORE
        ],
        entry.entry_id,
        SCAN_INTERVAL_SECONDS,
    )

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

    # Outages are reported fleet-wide so that all routers failing at once
    # (HA host / LAN problem) raise one Repairs issue instead of N.
    outage_tracker = async_get_outage_tracker(hass)
    outage_tracker.register(
        entry.entry_id, entry.title, lambda: coordinator.update_interval
    )
    coordinator.attach_outage_tracker(outage_tracker)
    coordinator.attach_node_resolver(partial(usteer_node_info, hass))
    entry.async_on_unload(partial(outage_tracker.unregister, entry.entry_id))
    # The RAM pressure issue lives as long as the entry is loaded.
    entry.async_on_unload(
        partial(async_clear_issue, hass, ram_high_issue_id(entry.entry_id))
    )

    # Network intelligence: one fleet-wide engine collects the events of all
    # routers from data the coordinator already has (no extra router calls).
    # Its store is loaded before the first ingest. An add-on like the panel:
    # a failure here must not stop the router from working.
    try:
        engine = await async_get_net_intelligence(hass)
        engine.register(entry.entry_id)
        # Client stability observes the engine's polls (no router calls of
        # its own); a failure here leaves the engine running.
        try:
            await async_get_client_stability(hass, engine)
        except Exception:
            _LOGGER.warning(
                "Client stability setup failed for '%s'", entry.title, exc_info=True
            )
        # Also runs when the setup fails further down (HA calls these then).
        entry.async_on_unload(partial(engine.unregister, entry.entry_id))
        entry.async_on_unload(
            coordinator.async_add_listener(
                partial(engine.async_ingest_coordinator, entry.entry_id, coordinator)
            )
        )
        engine.async_ingest_coordinator(entry.entry_id, coordinator)
    except Exception:
        _LOGGER.warning(
            "Network intelligence setup failed for '%s' — the router works "
            "without event history",
            entry.title,
            exc_info=True,
        )

    # --- Enterprise core (part 1): registry listener on finished polls; reads
    # coordinator data only (no router calls). Never fails setup.
    try:
        if _enterprise_core is not None:
            await _enterprise_core.async_setup_entry_core(hass, entry, coordinator)
    except Exception:
        _LOGGER.warning(
            "Enterprise core: registry listener setup failed for '%s' — the "
            "router works without it",
            entry.title,
            exc_info=True,
        )
    # --- end enterprise core

    # --- Configuration manager (plan 2026-11-18, section 1): provider,
    # schedule and drift trigger on top of the core. Memory only, no router
    # call here; never fails setup.
    try:
        if _enterprise_core is not None and _config_manager is not None:
            await _config_manager.async_setup_config_manager(hass, entry, coordinator)
    except Exception:
        _LOGGER.warning(
            "Configuration manager setup failed for '%s' — the router works "
            "without configuration backups",
            entry.title,
            exc_info=True,
        )
    # --- end configuration manager

    # Channel conflicts are judged across all routers after every poll.
    channel_plan = async_get_channel_plan_monitor(hass)
    entry.async_on_unload(
        coordinator.async_add_listener(
            partial(channel_plan.evaluate, entry.entry_id, coordinator)
        )
    )
    entry.async_on_unload(partial(channel_plan.unregister, entry.entry_id))

    # Forward setup to all platforms (sensor, switch, device_tracker, button)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # One-shot cleanup of legacy MAC-identified devices left over from v1.17.0
    _merge_orphan_mac_devices(hass, entry)

    # Register topology panel (idempotent — only registers once per HA session).
    # Platforms are already forwarded: a failure here must not leave the entry
    # in SETUP_ERROR with loaded platforms — the panel is an add-on, the
    # router entities work without it.
    try:
        from .topology_panel import async_setup_topology_panel

        await async_setup_topology_panel(hass, entry)
    except Exception:
        _LOGGER.warning(
            "Topology panel setup failed for '%s' — the router works, the "
            "Network Topology panel may be unavailable",
            entry.title,
            exc_info=True,
        )

    # Register the openwrt-topology-card Lovelace resource (idempotent).
    # Auto-served so users don't need a manual entry under Dashboards → Resources.
    # Optional: a release may ship without the (WIP) topology_card module — its
    # absence must NOT break integration setup, so import defensively.
    try:
        from .topology_card import async_setup_topology_card

        await async_setup_topology_card(hass)
    except ImportError:
        _LOGGER.debug(
            "topology_card module not present — skipping Lovelace card resource"
        )
    except Exception:
        _LOGGER.warning(
            "Topology card resource setup failed for '%s'",
            entry.title,
            exc_info=True,
        )

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

    Called when the user removes the integration, on reload, or HA restart.

    v1.18.0 — F3 Lifecycle:
      1. Unload platform entities (coordinator listeners drop with them).
      2. Decrement panel refcount; on last-entry unload the sidebar panel is
         removed and the snapshot HTTP view is soft-disabled (410 Gone).
      3. Clear cached client-side API state (token, ifname caches) so a
         fresh setup starts clean.  The shared aiohttp ClientSession is NOT
         closed — it belongs to HA.

    Args:
        hass: Home Assistant instance.
        entry: The config entry being removed.

    Returns:
        True if platform unload succeeded.  Panel teardown and api close
        always run so we don't leak refcount/state on partial failure.
    """
    _LOGGER.debug("Unloading OpenWrt Router entry for %s", entry.data.get(CONF_HOST))

    # Before the platforms go: the fleet entities' registry entries move to
    # the next router now, their entities follow once this entry's are gone.
    try:
        from .net_entities import async_withdraw_fleet

        async_withdraw_fleet(hass, entry.entry_id)
    except Exception:
        _LOGGER.debug("Fleet entity hand-over raised", exc_info=True)

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    # Always run lifecycle cleanup — even if platform unload partially failed
    # we want refcount + API state in a consistent shape for any subsequent
    # reload / setup.
    try:
        from .topology_panel import async_teardown_topology_panel

        await async_teardown_topology_panel(hass, entry)
    except Exception:
        _LOGGER.debug("Topology panel teardown raised", exc_info=True)

    try:
        from .topology_card import async_teardown_topology_card

        await async_teardown_topology_card(hass)
    except Exception:
        _LOGGER.debug("Topology card teardown raised", exc_info=True)

    # Stored events of this router stay; the last unload writes the store
    # (awaited here: coroutines given to async_on_unload are not awaited).
    # Only after a successful unload: otherwise HA keeps the entry and its
    # coordinator listener, and the engine must keep the router.
    if unload_ok:
        try:
            await async_unload_net_intelligence(hass, entry.entry_id)
        except Exception:
            _LOGGER.warning(
                "Network intelligence unload raised for '%s'",
                entry.title,
                exc_info=True,
            )
        # After the last router: write the client history now.
        try:
            await async_unload_client_stability(hass)
        except Exception:
            _LOGGER.warning(
                "Client stability unload raised for '%s'", entry.title, exc_info=True
            )
        # --- Configuration manager: release before the core lets go of the
        # entry; the last release stops its timer and unregisters the provider.
        try:
            if _config_manager is not None:
                _config_manager.async_release_config_manager(hass, entry.entry_id)
        except Exception:
            _LOGGER.warning(
                "Configuration manager release raised for '%s'",
                entry.title,
                exc_info=True,
            )
        # --- end configuration manager
        # --- Enterprise core (part 1): detach; the last entry flushes and
        # releases the core.
        try:
            if _enterprise_core is not None:
                await _enterprise_core.async_unload_entry_core(hass, entry)
        except Exception:
            _LOGGER.warning(
                "Enterprise core unload raised for '%s'", entry.title, exc_info=True
            )
        # --- end enterprise core

    runtime = getattr(entry, "runtime_data", None)
    api = getattr(runtime, "api", None) if runtime is not None else None
    if api is not None and hasattr(api, "async_close"):
        try:
            await api.async_close()
        except Exception:
            _LOGGER.debug("API async_close raised", exc_info=True)

    return unload_ok


async def async_remove_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> None:
    """Delete what the integration stored itself about a removed router.

    HA removes devices, entities and issues on its own; this drops the
    router's events, counters and incidents from the network intelligence
    store. Runs after the unload, so for the last router the engine is
    already gone and the store file is edited directly.
    """
    try:
        await async_remove_router_data(hass, entry.entry_id)
    except Exception:
        _LOGGER.warning(
            "Could not remove the network intelligence data of '%s'",
            entry.title,
            exc_info=True,
        )
    # --- Enterprise core (part 1): the router record is orphaned, not deleted
    # (history stays; it can be adopted by a new entry).
    try:
        if _enterprise_core is not None:
            await _enterprise_core.async_remove_entry_core(hass, entry)
    except Exception:
        _LOGGER.warning(
            "Enterprise core: could not orphan the router record of '%s'",
            entry.title,
            exc_info=True,
        )
    # --- end enterprise core


async def async_reload_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> None:
    """Reload a config entry (e.g. after options change or re-auth).

    Delegates to HA instead of calling unload/setup directly, so the entry's
    on_unload callbacks (outage tracker, channel plan, RAM issue) run too.

    Args:
        hass: Home Assistant instance.
        entry: The config entry to reload.
    """
    await hass.config_entries.async_reload(entry.entry_id)


# --- Security Center (release 1.46.0, part 1; plan 2026-11-17) ---
# One fleet-wide center per HA instance (security_center.py). It is wired
# by wrapping the two entry functions defined above, so none of their code
# changes: the center is set up after the whole base setup (network
# intelligence, client stability, configuration manager) and released after
# the base unload. Off by default: then it only reads its store. Every
# error stays here (logged without the entry title, which can be a host
# name or an address); a setup or an unload never fails because of it.
from functools import wraps

try:
    from . import security_center as _security_center
except Exception:  # noqa: BLE001 - the routers work without it
    _security_center = None  # type: ignore[assignment]

_async_setup_entry_base = async_setup_entry
_async_unload_entry_base = async_unload_entry


# ``wraps``: name, docstring and ``__wrapped__`` of the base functions stay
# visible (``inspect.getsource`` shows the base setup with all its hooks).
@wraps(_async_setup_entry_base)
async def async_setup_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> bool:
    """Set up a config entry, then add it to the Security Center."""
    ok = await _async_setup_entry_base(hass, entry)
    # ``is not False``: a base that returns None (HA 2026.11 style) succeeded
    if ok is not False and _security_center is not None:
        try:
            coordinator = getattr(entry.runtime_data, "coordinator", None)
            await _security_center.async_setup_security_center(hass, entry, coordinator)
        except Exception as err:
            _LOGGER.warning(
                "Security Center setup failed (%s); the router works without it",
                type(err).__name__,
            )
            _LOGGER.debug("Security Center setup error", exc_info=err)
    return ok


@wraps(_async_unload_entry_base)
async def async_unload_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> bool:
    """Unload a config entry, then release it from the Security Center."""
    unload_ok = await _async_unload_entry_base(hass, entry)
    if unload_ok is not False and _security_center is not None:
        try:
            await _security_center.async_release_security_center(hass, entry.entry_id)
        except Exception as err:
            _LOGGER.warning("Security Center release failed (%s)", type(err).__name__)
            _LOGGER.debug("Security Center release error", exc_info=err)
    return unload_ok


# --- end Security Center


# --- Network Diagnostics (release 1.47.0, part 1) ---
# One fleet-wide module per HA instance (diag_runtime.py), wired exactly like
# the Security Center above: the two entry functions are wrapped once more,
# so no existing code changes. Set up after the whole base setup (and after
# the Security Center), released after the base unload. Off by default: then
# it only reads its store (no router call, no packet). Every error stays here
# and is logged with the exception type only; a setup or an unload never
# fails because of it.
try:
    from . import diag_runtime as _diag_runtime
except Exception:  # noqa: BLE001 - the routers work without it
    _diag_runtime = None  # type: ignore[assignment]

_async_setup_entry_sc = async_setup_entry
_async_unload_entry_sc = async_unload_entry


@wraps(_async_setup_entry_sc)
async def async_setup_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> bool:
    """Set up a config entry, then add it to the network diagnostics."""
    ok = await _async_setup_entry_sc(hass, entry)
    if ok is not False and _diag_runtime is not None:
        try:
            coordinator = getattr(entry.runtime_data, "coordinator", None)
            await _diag_runtime.async_setup_net_diagnostics(hass, entry, coordinator)
        except Exception as err:
            _LOGGER.warning(
                "Network diagnostics setup failed (%s); the router works without it",
                type(err).__name__,
            )
            _LOGGER.debug("Network diagnostics setup error", exc_info=err)
    return ok


@wraps(_async_unload_entry_sc)
async def async_unload_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> bool:
    """Unload a config entry, then release it from the network diagnostics."""
    unload_ok = await _async_unload_entry_sc(hass, entry)
    if unload_ok is not False and _diag_runtime is not None:
        try:
            await _diag_runtime.async_release_net_diagnostics(hass, entry.entry_id)
        except Exception as err:
            _LOGGER.warning(
                "Network diagnostics release failed (%s)", type(err).__name__
            )
            _LOGGER.debug("Network diagnostics release error", exc_info=err)
    return unload_ok


# --- end Network Diagnostics


# --- WiFi RF Intelligence (release 1.48.0, part 1) ---
# One fleet-wide center per HA instance (rf_center.py), wired like the
# Security Center above: the setup and unload wrappers run after the base
# (and the Security Center) and never fail them. The center listens to the
# entry's polls; with RF off (the default, per entry) it makes no router
# call at all and only reads its history store.
try:
    from . import rf_center as _rf_center
except Exception:  # noqa: BLE001 - the routers work without it
    _rf_center = None  # type: ignore[assignment]

_async_setup_entry_sec = async_setup_entry
_async_unload_entry_sec = async_unload_entry


@wraps(_async_setup_entry_sec)
async def async_setup_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> bool:
    """Set up a config entry, then add it to the WiFi RF center."""
    ok = await _async_setup_entry_sec(hass, entry)
    if ok is not False and _rf_center is not None:
        try:
            coordinator = getattr(entry.runtime_data, "coordinator", None)
            await _rf_center.async_setup_rf_center(hass, entry, coordinator)
        except Exception as err:
            _LOGGER.warning(
                "WiFi RF setup failed (%s); the router works without it",
                type(err).__name__,
            )
            _LOGGER.debug("WiFi RF setup error", exc_info=err)
        # Part 2: the bounded entity set (created only for routers with RF on)
        try:
            from .wifi_rf_entities import async_sync_rf_entities

            await async_sync_rf_entities(hass)
        except Exception as err:
            _LOGGER.warning(
                "WiFi RF entities not set up (%s); the router works without them",
                type(err).__name__,
            )
            _LOGGER.debug("WiFi RF entities error", exc_info=err)
    return ok


@wraps(_async_unload_entry_sec)
async def async_unload_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> bool:
    """Unload a config entry, then release it from the WiFi RF center."""
    unload_ok = await _async_unload_entry_sec(hass, entry)
    if unload_ok is not False and _rf_center is not None:
        try:
            await _rf_center.async_release_rf_center(hass, entry.entry_id)
        except Exception as err:
            _LOGGER.warning("WiFi RF release failed (%s)", type(err).__name__)
            _LOGGER.debug("WiFi RF release error", exc_info=err)
        try:
            from .wifi_rf_entities import async_entry_released

            last = _rf_center.async_get_rf_center(hass) is None
            await async_entry_released(hass, entry.entry_id, last=last)
        except Exception as err:
            _LOGGER.warning("WiFi RF entities release failed (%s)", type(err).__name__)
            _LOGGER.debug("WiFi RF entities release error", exc_info=err)
    return unload_ok


# --- end WiFi RF Intelligence


# --- Traffic Analytics (Phase 5) ---
# One fleet-wide engine per HA instance (traffic_engine.py), wired like the
# Security Center: by wrapping the two entry functions above (after the
# Network Diagnostics and WiFi RF wrappers), so none of
# their code changes. Set up after everything else, released after the
# base unload. Off by default: then it only reads its settings and adds no
# coordinator listener at all. Every error stays here and is
# logged by type only; a setup or an unload never fails because of it.
try:
    from . import traffic_engine as _traffic_engine
except Exception:  # noqa: BLE001 - the routers work without it
    _traffic_engine = None  # type: ignore[assignment]

_async_setup_entry_rf = async_setup_entry
_async_unload_entry_rf = async_unload_entry


@wraps(_async_setup_entry_rf)
async def async_setup_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> bool:
    """Set up a config entry, then add it to traffic analytics."""
    ok = await _async_setup_entry_rf(hass, entry)
    if ok is not False and _traffic_engine is not None:
        try:
            coordinator = getattr(entry.runtime_data, "coordinator", None)
            if coordinator is not None:
                await _traffic_engine.async_setup_traffic(hass, entry, coordinator)
        except Exception as err:
            _LOGGER.warning(
                "Traffic analytics setup failed (%s); the router works without it",
                type(err).__name__,
            )
            _LOGGER.debug("Traffic analytics setup error", exc_info=err)
    return ok


@wraps(_async_unload_entry_rf)
async def async_unload_entry(hass: HomeAssistant, entry: OpenWrtConfigEntry) -> bool:
    """Unload a config entry, then release it from traffic analytics."""
    unload_ok = await _async_unload_entry_rf(hass, entry)
    if unload_ok is not False and _traffic_engine is not None:
        try:
            await _traffic_engine.async_release_traffic(hass, entry.entry_id)
        except Exception as err:
            _LOGGER.warning("Traffic analytics release failed (%s)", type(err).__name__)
            _LOGGER.debug("Traffic analytics release error", exc_info=err)
    return unload_ok


# --- Ende Traffic Analytics ---
