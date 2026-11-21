"""Config flow for the OpenWrt Router integration."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from typing import Any, ClassVar

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

# Selectors of the configuration manager options (plan 2026-11-18, section 2)
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TimeSelector,
)

from .api import (
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtResponseError,
    OpenWrtRpcdSetupError,
    OpenWrtTimeoutError,
)
from .const import (
    CONF_EXTENDED_WIFI_SENSORS,
    CONF_PROTOCOL,
    CONF_TOPOLOGY_PANEL_ALL_USERS,
    CONF_TOPOLOGY_PORT_DEBUG,
    CONFIG_BACKUP_SCHEDULES,
    DEFAULT_CONFIG_BACKUP_SCHEDULE,
    DEFAULT_CONFIG_BACKUP_TIME,
    DEFAULT_CONFIG_DRIFT_CHECK,
    DEFAULT_EXTENDED_WIFI_SENSORS,
    DEFAULT_PORT,
    DEFAULT_PROTOCOL,
    DEFAULT_TOPOLOGY_PANEL_ALL_USERS,
    DEFAULT_TOPOLOGY_PORT_DEBUG,
    DEFAULT_USERNAME,
    DOMAIN,
    ERROR_ACL_ALREADY_CURRENT,
    ERROR_ACL_CHECK_TRANSIENT,
    ERROR_ACL_DEPLOY_FAILED,
    ERROR_ACL_DEPLOY_NO_CHANGE,
    ERROR_ACL_TIERED_KEPT,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_INVALID_HOST,
    ERROR_RPCD_SETUP,
    ERROR_TIMEOUT,
    ERROR_UNKNOWN,
    OPT_EXTENDED_WIFI_PREEXISTING,
    OPTION_CONFIG_BACKUP_SCHEDULE,
    OPTION_CONFIG_BACKUP_TIME,
    OPTION_CONFIG_DRIFT_CHECK,
    OPTION_TIME_MACHINE_ENABLED,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    PROTOCOL_HTTPS_INSECURE,
)
from .core_models import DEFAULT_CONFIG_BACKUP_ENABLED, OPTION_CONFIG_BACKUP_ENABLED
from .extended_sensors import async_apply_extended_wifi_sensors
from .ssl_util import ssl_context_for_protocol
from .topology_panel import async_update_topology_panel_access

_LOGGER = logging.getLogger(__name__)

# Grace periods around the ACL-deploy rpcd restart (tests patch these to 0).
_ACL_RECHECK_GRACE_S: float = 2.0
_ACL_LOGIN_RETRY_DELAY_S: float = 1.5


def _acl_not_written_error(reason: str | None) -> str:
    """Form error when the ACL repair wrote nothing, by outcome reason.

    ``tiered_kept``: an approved tiered ACL was left alone; ``transient``:
    the ACL could not be read, nothing changed; anything else (``current``,
    or no outcome seen) keeps the 1.40-1.43 message "already up to date".
    """
    if reason == "tiered_kept":
        return ERROR_ACL_TIERED_KEPT
    if reason == "transient":
        return ERROR_ACL_CHECK_TRANSIENT
    return ERROR_ACL_ALREADY_CURRENT


def _validate_host(host: str) -> str | None:
    """Validate host input against SSRF-prone values.

    Rejects loopback, link-local, and unspecified IP addresses, as well as
    hostnames containing characters outside the allowed set.

    Args:
        host: Raw host string from user input.

    Returns:
        An error key string if the host is invalid, or None if it is acceptable.
    """
    host = host.strip()
    if not host:
        return ERROR_INVALID_HOST
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
            return ERROR_INVALID_HOST
        return None
    except ValueError:
        pass
    if not re.match(r"^[a-zA-Z0-9._\-]{1,253}$", host):
        return ERROR_INVALID_HOST
    return None


class OpenWrtOptionsFlow(OptionsFlow):
    """Options flow — extended Wi-Fi sensors, topology debug and panel audience."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        opts = self.config_entry.options
        if user_input is not None:
            # Merge: async_create_entry replaces all options, internal keys too.
            new_opts = {**opts, **user_input}
            was_on = opts.get(CONF_EXTENDED_WIFI_SENSORS, DEFAULT_EXTENDED_WIFI_SENSORS)
            is_on = new_opts.get(
                CONF_EXTENDED_WIFI_SENSORS, DEFAULT_EXTENDED_WIFI_SENSORS
            )
            # Touch the entity registry only on an actual change.
            if is_on != was_on:
                new_opts[OPT_EXTENDED_WIFI_PREEXISTING] = (
                    async_apply_extended_wifi_sensors(
                        self.hass,
                        self.config_entry,
                        is_on,
                        opts.get(OPT_EXTENDED_WIFI_PREEXISTING, []),
                    )
                )
            # Apply the panel audience directly: an update listener would
            # clash with async_update_reload_and_abort in the reauth steps
            # (deprecated since HA 2026.6, an error from 2026.12).
            all_users = bool(
                new_opts.get(
                    CONF_TOPOLOGY_PANEL_ALL_USERS, DEFAULT_TOPOLOGY_PANEL_ALL_USERS
                )
            )
            try:
                await async_update_topology_panel_access(
                    self.hass, self.config_entry, all_users
                )
            except Exception:
                # Options are still saved; the next entry setup applies them.
                _LOGGER.warning(
                    "Could not apply the topology panel access option",
                    exc_info=True,
                )
            # Same pattern for config_backup_enabled (1.44.0): applied to the
            # enterprise core directly, no update listener, no reload.
            if OPTION_CONFIG_BACKUP_ENABLED in user_input:
                _apply_config_backup_option(
                    self.hass,
                    self.config_entry,
                    new_opts.get(OPTION_CONFIG_BACKUP_ENABLED) is True,
                    user_id=self.context.get("user_id"),
                )
            # --- Traffic Analytics (Phase K): applied to the fleet engine
            # directly (no update listener, no reload); never raises.
            if any(key in user_input for key in _TRAFFIC_OPTION_KEYS):
                from .traffic_engine import async_apply_traffic_options

                await async_apply_traffic_options(
                    self.hass, self.config_entry.entry_id, new_opts
                )
            # --- end Traffic Analytics
            # --- Network Time Machine (Phase A): ONE switch for the fleet.
            # The value is written through to every other router entry, so
            # all entries agree; no update listener, no reload, never raises.
            if OPTION_TIME_MACHINE_ENABLED in user_input:
                on = new_opts.get(OPTION_TIME_MACHINE_ENABLED) is True
                new_opts[OPTION_TIME_MACHINE_ENABLED] = on
                _write_time_machine_through(self.hass, self.config_entry, on)
            # --- end Network Time Machine
            return self.async_create_entry(title="", data=new_opts)

        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_EXTENDED_WIFI_SENSORS,
                    default=opts.get(
                        CONF_EXTENDED_WIFI_SENSORS, DEFAULT_EXTENDED_WIFI_SENSORS
                    ),
                ): bool,
                vol.Optional(
                    CONF_TOPOLOGY_PORT_DEBUG,
                    default=opts.get(
                        CONF_TOPOLOGY_PORT_DEBUG, DEFAULT_TOPOLOGY_PORT_DEBUG
                    ),
                ): bool,
                vol.Optional(
                    CONF_TOPOLOGY_PANEL_ALL_USERS,
                    default=opts.get(
                        CONF_TOPOLOGY_PANEL_ALL_USERS, DEFAULT_TOPOLOGY_PANEL_ALL_USERS
                    ),
                ): bool,
            }
        )
        if _offer_config_backup_option(self.hass, opts):
            schema = schema.extend(
                {
                    vol.Optional(
                        OPTION_CONFIG_BACKUP_ENABLED,
                        default=opts.get(
                            OPTION_CONFIG_BACKUP_ENABLED, DEFAULT_CONFIG_BACKUP_ENABLED
                        )
                        is True,
                    ): bool,
                }
            )
            # --- Configuration manager options (plan 2026-11-18, section 2):
            # shown together with config_backup_enabled; read on every
            # schedule tick, so no update listener and no reload.
            schema = schema.extend(_config_manager_option_fields(opts))
            # --- end configuration manager options
        # --- WiFi RF Intelligence (1.48.0): always offered, all off by
        # default; read on every poll, so no update listener and no reload.
        schema = schema.extend(_wifi_rf_option_fields(opts))
        # --- end WiFi RF Intelligence
        # --- Traffic Analytics (Phase K): always offered, off by default.
        schema = schema.extend(_traffic_option_fields(opts))
        # --- end Traffic Analytics
        # --- Network Time Machine (Phase A): always offered, off by default;
        # the form shows the fleet state (on while any router has it on).
        schema = schema.extend(_time_machine_option_fields(self.hass, opts))
        # --- end Network Time Machine
        return self.async_show_form(step_id="init", data_schema=schema)


# --- Network Time Machine (Phase A) ---
def _time_machine_option_fields(hass: Any, opts: Any) -> dict[Any, Any]:
    """The fleet-wide switch; its default is the fleet state."""
    try:
        from .tm_query import time_machine_enabled

        on = time_machine_enabled(hass)
    except Exception:  # noqa: BLE001 - the form never fails because of it
        on = False
    on = on or opts.get(OPTION_TIME_MACHINE_ENABLED) is True
    return {vol.Optional(OPTION_TIME_MACHINE_ENABLED, default=on): bool}


def _write_time_machine_through(hass: Any, entry: Any, on: bool) -> None:
    """Give every other router entry the same switch value (one fleet switch).

    Only entries whose value differs are updated, with all their other
    options kept. Errors are logged by type only and never stop the form.
    """
    try:
        entries = hass.config_entries.async_entries(DOMAIN)
    except Exception:  # noqa: BLE001
        return
    if not isinstance(entries, list):
        return
    for other in entries:
        if other.entry_id == entry.entry_id:
            continue
        options = dict(getattr(other, "options", None) or {})
        if (options.get(OPTION_TIME_MACHINE_ENABLED) is True) == on:
            continue
        options[OPTION_TIME_MACHINE_ENABLED] = on
        try:
            hass.config_entries.async_update_entry(other, options=options)
        except Exception as err:  # noqa: BLE001
            _LOGGER.warning(
                "Time Machine switch not written to another router (%s)",
                type(err).__name__,
            )


# --- end Network Time Machine


# --- Configuration manager options (plan 2026-11-18, section 2)
def _config_manager_option_fields(opts: Any) -> dict[Any, Any]:
    """Schedule, time and drift check of the configuration manager."""
    schedule = opts.get(OPTION_CONFIG_BACKUP_SCHEDULE, DEFAULT_CONFIG_BACKUP_SCHEDULE)
    if schedule not in CONFIG_BACKUP_SCHEDULES:
        schedule = DEFAULT_CONFIG_BACKUP_SCHEDULE
    at = opts.get(OPTION_CONFIG_BACKUP_TIME, DEFAULT_CONFIG_BACKUP_TIME)
    if not isinstance(at, str) or not at:
        at = DEFAULT_CONFIG_BACKUP_TIME
    drift = opts.get(OPTION_CONFIG_DRIFT_CHECK, DEFAULT_CONFIG_DRIFT_CHECK)
    return {
        vol.Optional(OPTION_CONFIG_BACKUP_SCHEDULE, default=schedule): SelectSelector(
            SelectSelectorConfig(
                options=list(CONFIG_BACKUP_SCHEDULES),
                mode=SelectSelectorMode.DROPDOWN,
                translation_key=OPTION_CONFIG_BACKUP_SCHEDULE,
            )
        ),
        vol.Optional(OPTION_CONFIG_BACKUP_TIME, default=at): TimeSelector(),
        vol.Optional(OPTION_CONFIG_DRIFT_CHECK, default=drift is not False): bool,
    }


# --- end configuration manager options


# --- WiFi RF Intelligence (1.48.0) ---
def _wifi_rf_option_fields(opts: Any) -> dict[Any, Any]:
    """Switches and cadence of the WiFi RF module, odd stored values fall back."""
    from .const import (
        DEFAULT_WIFI_RF_EVERY_N_POLLS,
        OPTION_WIFI_RF_EVERY_N_POLLS,
        WIFI_RF_EVERY_N_POLLS_MAX,
        WIFI_RF_EVERY_N_POLLS_MIN,
        WIFI_RF_SWITCH_OPTIONS,
    )

    fields: dict[Any, Any] = {
        vol.Optional(key, default=opts.get(key) is True): bool
        for key in WIFI_RF_SWITCH_OPTIONS
    }
    every = opts.get(OPTION_WIFI_RF_EVERY_N_POLLS, DEFAULT_WIFI_RF_EVERY_N_POLLS)
    if (
        isinstance(every, bool)
        or not isinstance(every, int)
        or not WIFI_RF_EVERY_N_POLLS_MIN <= every <= WIFI_RF_EVERY_N_POLLS_MAX
    ):
        every = DEFAULT_WIFI_RF_EVERY_N_POLLS
    fields[vol.Optional(OPTION_WIFI_RF_EVERY_N_POLLS, default=every)] = vol.All(
        vol.Coerce(int),
        vol.Range(min=WIFI_RF_EVERY_N_POLLS_MIN, max=WIFI_RF_EVERY_N_POLLS_MAX),
    )
    return fields


# --- end WiFi RF Intelligence


# --- Traffic Analytics (Phase K) ---
def _traffic_keys() -> tuple[str, ...]:
    from .const import OPTION_TRAFFIC_HISTORY_PROFILE, TRAFFIC_SWITCH_OPTIONS

    return (*TRAFFIC_SWITCH_OPTIONS, OPTION_TRAFFIC_HISTORY_PROFILE)


_TRAFFIC_OPTION_KEYS = _traffic_keys()


def _traffic_option_fields(opts: Any) -> dict[Any, Any]:
    """Switch, extra-call switches and history profile; odd values fall back."""
    from .const import (
        DEFAULT_TRAFFIC_HISTORY_PROFILE,
        OPTION_TRAFFIC_HISTORY_PROFILE,
        TRAFFIC_HISTORY_PROFILES,
        TRAFFIC_SWITCH_OPTIONS,
    )

    fields: dict[Any, Any] = {
        vol.Optional(key, default=opts.get(key) is True): bool
        for key in TRAFFIC_SWITCH_OPTIONS
    }
    profile = opts.get(OPTION_TRAFFIC_HISTORY_PROFILE, DEFAULT_TRAFFIC_HISTORY_PROFILE)
    if profile not in TRAFFIC_HISTORY_PROFILES:
        profile = DEFAULT_TRAFFIC_HISTORY_PROFILE
    fields[vol.Optional(OPTION_TRAFFIC_HISTORY_PROFILE, default=profile)] = (
        SelectSelector(
            SelectSelectorConfig(
                options=list(TRAFFIC_HISTORY_PROFILES),
                mode=SelectSelectorMode.DROPDOWN,
                translation_key=OPTION_TRAFFIC_HISTORY_PROFILE,
            )
        )
    )
    return fields


# --- end Traffic Analytics


def _offer_config_backup_option(hass: Any, opts: Any) -> bool:
    """Show ``config_backup_enabled`` once a configuration provider exists.

    Without a provider the switch has no effect (every config.* stays
    unavailable/no_provider), so it is only offered then, or while it is
    on (so it can always be turned off).
    """
    if opts.get(OPTION_CONFIG_BACKUP_ENABLED) is True:
        return True
    try:
        from .enterprise_core import async_get_core

        core = async_get_core(hass)
        return core is not None and core.manager.provider_id is not None
    except Exception:
        _LOGGER.debug(
            "Enterprise core not readable for the options form", exc_info=True
        )
        return False


def _apply_config_backup_option(
    hass: Any, entry: ConfigEntry, enabled: bool, *, user_id: str | None = None
) -> None:
    """Hand the option to the running core (logged on failure, never raises).

    A change is audited by the core (security ring) with the submitting
    user when the flow context names one (Home Assistant's options flow
    usually does not; the event then says ``actor_known`` False).
    """
    try:
        from .core_models import Actor, ActorKind
        from .enterprise_core import async_get_core

        core = async_get_core(hass)
        if core is None:
            _LOGGER.info(
                "Configuration backup option for %s is applied at the next setup",
                entry.entry_id,
            )
            return  # applied by ensure_entry at the next setup
        actor = (
            Actor(kind=ActorKind.USER, user_id=user_id)
            if isinstance(user_id, str) and user_id
            else None
        )
        rid = core.registry.router_id_for_entry(entry.entry_id)
        if not core.registry.set_config_enabled(entry.entry_id, enabled):
            return
        if rid:
            core.manager.on_config_option_changed(rid, enabled, actor=actor)
        else:
            core.manager.audit_config_option_changed(None, enabled, actor=actor)
    except Exception:
        _LOGGER.warning(
            "Could not apply the configuration backup option", exc_info=True
        )


class OpenWrtConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the config flow for OpenWrt Router.

    Steps:
        user → checklist → create entry

    The unique_id is derived from the router's host:port (see
    :meth:`_compute_unique_id`). Host-based identity guarantees that routers at
    different (static) IPs are always treated as separate entries — identical
    hardware (e.g. multiple Cudy WR3000) that reports the same or an empty MAC
    in ``system board`` can therefore no longer collide into a false
    ``already_configured`` abort. Re-adding the same host is still rejected as a
    duplicate; a router moved to a new IP counts as a new entry (acceptable for
    the static-IP router setups this integration targets).
    """

    VERSION = 2
    # Minor 2: legacy dynamic-sensor disable is a one-time migration
    # (see async_migrate_entry); new entries skip it.
    MINOR_VERSION = 2

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OpenWrtOptionsFlow:
        """Return the options flow handler."""
        return OpenWrtOptionsFlow()

    _CAPABILITY_LABELS: ClassVar[dict[str, str]] = {
        "system_info": "System-Info (CPU, RAM, Uptime)",
        "network_wireless": "WLAN-Status (Radios/SSIDs via netifd oder iwinfo)",
        "network_dump": "Netzwerk-Interfaces (WAN/LAN)",
        "file_read": "Datei-Lesezugriff (Konfiguration, DHCP)",
        "luci_rpc_dhcp": "DHCP-Leases (Client-IPs)",
        "iwinfo": "Signal-Stärke (iwinfo)",
        "uci_get": "UCI-Konfiguration",
        "hostapd_clients": "WLAN-Clients (hostapd)",
        "lldp_neighbors": "LLDP-Nachbarn (Router-zu-Router-Verkabelung, optional)",
    }

    # LLDP is optional and NOT ACL-related: a miss must not trigger the rpcd/ACL
    # install hint. It gets its own recommendation and never blocks the add flow.
    _LLDP_CAP: str = "lldp_neighbors"

    _REQUIRED_CAPS: frozenset[str] = frozenset(
        {
            "system_info",
            "network_dump",
            "network_wireless",
        }
    )

    def __init__(self) -> None:
        """Initialize the config flow."""
        super().__init__()
        self._board_info: dict[str, Any] = {}
        self._capabilities: dict[str, bool] = {}
        self._user_data: dict[str, Any] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial user-facing setup step.

        Presents a form asking for host, port, protocol, username and password.
        On submission, attempts to login and read the board info.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = user_input[CONF_HOST].strip()
            port: int = user_input[CONF_PORT]
            protocol: str = user_input[CONF_PROTOCOL]
            username: str = user_input[CONF_USERNAME].strip()
            password: str = user_input[CONF_PASSWORD]

            host_error = _validate_host(host)
            if host_error:
                errors["host"] = host_error
            else:
                try:
                    board_info = await self._validate_input(
                        host, port, username, password, protocol
                    )

                except OpenWrtAuthError:
                    _LOGGER.debug("Config flow: authentication failed for %s", host)
                    errors["base"] = ERROR_INVALID_AUTH

                except OpenWrtTimeoutError:
                    _LOGGER.debug("Config flow: timeout connecting to %s", host)
                    errors["base"] = ERROR_TIMEOUT

                except OpenWrtConnectionError:
                    _LOGGER.debug("Config flow: cannot connect to %s", host)
                    errors["base"] = ERROR_CANNOT_CONNECT

                except OpenWrtResponseError:
                    _LOGGER.debug("Config flow: unexpected response from %s", host)
                    errors["base"] = ERROR_CANNOT_CONNECT

                except Exception:
                    _LOGGER.exception("Config flow: unexpected error for %s", host)
                    errors["base"] = ERROR_UNKNOWN

                else:
                    unique_id = self._compute_unique_id(board_info, host, port)

                    await self.async_set_unique_id(unique_id)
                    self._abort_if_unique_id_configured(
                        updates={
                            CONF_HOST: host,
                            CONF_PORT: port,
                        }
                    )

                    title = board_info.get("hostname") or host
                    _LOGGER.info(
                        "Config flow: connected to %s (model: %s, unique_id: %s)",
                        title,
                        board_info.get("model", "unknown"),
                        unique_id,
                    )

                    self._board_info = board_info
                    self._user_data = {
                        CONF_HOST: host,
                        CONF_PORT: port,
                        CONF_PROTOCOL: protocol,
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                    }
                    return await self.async_step_checklist()

        schema = self._build_user_schema(user_input)
        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_checklist(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show capability checklist and let user proceed or retry."""
        host = self._user_data.get(CONF_HOST, "")
        errors: dict[str, str] = {}
        deployed = False
        # LLDP is optional and is NOT provisioned by the ACL deploy, so it must
        # stay out of the before/after comparison below — otherwise a router
        # without lldpd makes every successful deploy look like a no-op.
        missing_before = {
            cap
            for cap in self._CAPABILITY_LABELS
            if cap != self._LLDP_CAP and not self._capabilities.get(cap)
        }

        if user_input is not None:
            if user_input.get("deploy_acl"):
                from .acl_provisioning import (
                    AclDeployError,
                    AclEnsureOutcome,
                    ensure_acl_respecting_offer,
                )

                # why nothing was written (review finding 17): a kept
                # tiered ACL and a failed read get their own message
                outcome_reason: list[str] = []

                def _note_outcome(outcome: AclEnsureOutcome) -> None:
                    outcome_reason.append(outcome.reason)

                session = async_get_clientsession(self.hass)
                protocol = self._user_data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)
                deploy_api = OpenWrtAPI(
                    host=host,
                    port=self._user_data[CONF_PORT],
                    username=self._user_data[CONF_USERNAME],
                    password=self._user_data[CONF_PASSWORD],
                    session=session,
                    protocol=protocol,
                    ssl_context=ssl_context_for_protocol(protocol),
                )
                try:
                    await deploy_api.login()
                    # 1.44.0: never undo an approved tiered ACL (same calls
                    # as before when none is deployed).
                    deployed = await ensure_acl_respecting_offer(
                        deploy_api, observe=_note_outcome
                    )
                except AclDeployError:
                    _LOGGER.warning("ACL deploy to %s failed", host, exc_info=True)
                    errors["base"] = ERROR_ACL_DEPLOY_FAILED
                except Exception:
                    _LOGGER.exception("ACL deploy: unexpected error for %s", host)
                    errors["base"] = ERROR_ACL_DEPLOY_FAILED
                finally:
                    await deploy_api.async_close()
                if deployed:
                    # rpcd restarts after a deploy — give it a moment before
                    # logging in again for the re-check below.
                    await asyncio.sleep(_ACL_RECHECK_GRACE_S)
                elif not errors:
                    errors["base"] = _acl_not_written_error(
                        outcome_reason[-1] if outcome_reason else None
                    )
                # fall through → re-run capability check and re-show form
            elif user_input.get("action") != "retry":
                title = self._board_info.get("hostname") or host
                return self.async_create_entry(title=title, data=self._user_data)

        session = async_get_clientsession(self.hass)
        protocol = self._user_data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)
        api = OpenWrtAPI(
            host=host,
            port=self._user_data[CONF_PORT],
            username=self._user_data[CONF_USERNAME],
            password=self._user_data[CONF_PASSWORD],
            session=session,
            protocol=protocol,
            ssl_context=ssl_context_for_protocol(protocol),
        )
        try:
            try:
                await api.login()
            except Exception:  # noqa: BLE001 — rpcd may still be restarting
                await asyncio.sleep(_ACL_LOGIN_RETRY_DELAY_S)
                await api.login()
            self._capabilities = await api.check_capabilities()
        except Exception:  # noqa: BLE001
            self._capabilities = {}
        finally:
            await api.async_close()

        lines: list[str] = []
        missing_required: list[str] = []
        missing_optional: list[str] = []

        for cap, label in self._CAPABILITY_LABELS.items():
            ok = self._capabilities.get(cap, False)
            icon = "✅" if ok else "ℹ️" if cap == self._LLDP_CAP else "❌"
            lines.append(f"{icon} {label}")
            if not ok and cap != self._LLDP_CAP:
                # LLDP is handled separately — it never counts as a missing
                # ubus/ACL capability, so it can't degrade the checklist status.
                if cap in self._REQUIRED_CAPS:
                    missing_required.append(label)
                else:
                    missing_optional.append(label)

        checklist_text = "\n".join(lines)

        # Dedicated, non-blocking LLDP recommendation (not an error).
        lldp_hint = ""
        if not self._capabilities.get(self._LLDP_CAP, False):
            lldp_hint = (
                "\n\nℹ️ **LLDP nicht erkannt** (optional). Für zuverlässige "
                "Router-zu-Router-Verkabelungserkennung auf allen OpenWrt-Routern "
                "lldpd installieren und starten:\n"
                "```\n"
                "opkg update\n"
                "opkg install lldpd\n"
                "/etc/init.d/lldpd enable\n"
                "/etc/init.d/lldpd start\n"
                "```\n"
                "Ohne LLDP funktioniert alles weiter — nur die Router-zu-Router-"
                "Erkennung ist dann weniger sicher."
            )

        deploy_note = ""
        if deployed:
            missing_after = {
                cap
                for cap in self._CAPABILITY_LABELS
                if cap != self._LLDP_CAP and not self._capabilities.get(cap)
            }
            if not missing_after or missing_after < missing_before:
                deploy_note = (
                    "✅ **ACL erfolgreich deployt** — Berechtigungen wurden "
                    "aktualisiert und erneut geprüft.\n\n"
                )
            else:
                errors["base"] = ERROR_ACL_DEPLOY_NO_CHANGE

        install_hint = ""
        if missing_required or missing_optional:
            # Build a self-contained, always-correct manual deploy command from
            # the actual ACL content (no stale scp of a file the user doesn't have).
            import json

            from .acl_provisioning import ACL_FILE_PATH, RPCD_ACL_CONTENT

            acl_json = json.dumps(RPCD_ACL_CONTENT, indent=2)
            install_hint = (
                f"\n\n**Am einfachsten:** Häkchen unten setzen — die ACL wird "
                f"automatisch via ubus (bzw. SSH-Fallback) auf den Router geschrieben. "
                f"Der SSH-Fallback braucht aktives Passwort-Login (dropbear). Falls aus, "
                f"einmalig auf dem Router:\n"
                f"```\n"
                f"uci set dropbear.@dropbear[0].PasswordAuth='on'\n"
                f"uci commit dropbear && /etc/init.d/dropbear restart\n"
                f"```\n"
                f"**Alternativ manuell** (per SSH direkt auf dem Router — kein scp nötig):\n"
                f"```\n"
                f"cat > {ACL_FILE_PATH} <<'EOF'\n"
                f"{acl_json}\n"
                f"EOF\n"
                f"/etc/init.d/rpcd restart\n"
                f"```"
            )

        if missing_required:
            status = (
                f"⚠️ **Kritische Berechtigungen fehlen** — die Integration kann nicht "
                f"vollständig arbeiten."
                f"{install_hint}"
            )
        elif missing_optional:
            status = (
                f"ℹ️ Optionale Funktionen nicht via ubus verfügbar — Grundfunktionen OK.\n"
                f"Für die fehlenden Calls wird der SSH-Fallback genutzt (etwas höhere "
                f"Router-Last). Empfehlung: rpcd-ACL wie unten aktualisieren."
                f"{install_hint}"
            )
        else:
            status = "✅ Alle Berechtigungen vorhanden — optimale Konfiguration."

        status += lldp_hint

        has_missing = bool(missing_required or missing_optional)
        schema = vol.Schema(
            {vol.Optional("deploy_acl", default=False): bool} if has_missing else {}
        )

        return self.async_show_form(
            step_id="checklist",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "host": host,
                "model": self._board_info.get("model", ""),
                "checklist": checklist_text,
                "status": deploy_note + status,
            },
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """Diagnose why re-auth was triggered, then route to the right sub-step."""
        reauth_entry = self._get_reauth_entry()
        host: str = reauth_entry.data[CONF_HOST]
        port: int = reauth_entry.data[CONF_PORT]
        username: str = reauth_entry.data[CONF_USERNAME]
        password: str = reauth_entry.data[CONF_PASSWORD]
        protocol: str = reauth_entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)

        try:
            await self._validate_input(host, port, username, password, protocol)
        except (OpenWrtResponseError, OpenWrtRpcdSetupError):
            return await self.async_step_reauth_rpcd_setup()
        except (OpenWrtConnectionError, OpenWrtTimeoutError):
            return await self.async_step_reauth_cannot_connect()
        except OpenWrtAuthError:
            return await self.async_step_reauth_confirm()
        except Exception:
            _LOGGER.exception("Re-auth: unexpected error during diagnosis for %s", host)
            return await self.async_step_reauth_confirm()
        else:
            _LOGGER.debug(
                "Re-auth: existing credentials for %s still valid, reloading", host
            )
            return self.async_update_reload_and_abort(reauth_entry)

    async def async_step_reauth_rpcd_setup(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show rpcd setup instructions with a 'I've fixed it — retry' button."""
        reauth_entry = self._get_reauth_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = reauth_entry.data[CONF_HOST]
            port: int = reauth_entry.data[CONF_PORT]
            username: str = reauth_entry.data[CONF_USERNAME]
            password: str = reauth_entry.data[CONF_PASSWORD]
            protocol: str = reauth_entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)

            try:
                await self._validate_input(host, port, username, password, protocol)
            except OpenWrtResponseError:
                errors["base"] = ERROR_RPCD_SETUP
            except (OpenWrtConnectionError, OpenWrtTimeoutError):
                return await self.async_step_reauth_cannot_connect()
            except OpenWrtAuthError:
                return await self.async_step_reauth_confirm()
            except Exception:
                _LOGGER.exception("Re-auth rpcd setup: unexpected error")
                errors["base"] = ERROR_UNKNOWN
            else:
                return self.async_update_reload_and_abort(reauth_entry)

        return self.async_show_form(
            step_id="reauth_rpcd_setup",
            data_schema=vol.Schema({}),
            errors=errors,
            description_placeholders={
                "host": reauth_entry.data.get(CONF_HOST, ""),
            },
        )

    async def async_step_reauth_cannot_connect(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show 'router unreachable' message with a retry button."""
        reauth_entry = self._get_reauth_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = reauth_entry.data[CONF_HOST]
            port: int = reauth_entry.data[CONF_PORT]
            username: str = reauth_entry.data[CONF_USERNAME]
            password: str = reauth_entry.data[CONF_PASSWORD]
            protocol: str = reauth_entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)

            try:
                await self._validate_input(host, port, username, password, protocol)
            except (OpenWrtRpcdSetupError, OpenWrtResponseError):
                return await self.async_step_reauth_rpcd_setup()
            except (OpenWrtConnectionError, OpenWrtTimeoutError):
                errors["base"] = ERROR_CANNOT_CONNECT
            except OpenWrtAuthError:
                return await self.async_step_reauth_confirm()
            except Exception:
                _LOGGER.exception("Re-auth cannot connect: unexpected error")
                errors["base"] = ERROR_UNKNOWN
            else:
                return self.async_update_reload_and_abort(reauth_entry)

        return self.async_show_form(
            step_id="reauth_cannot_connect",
            data_schema=vol.Schema({}),
            errors=errors,
            description_placeholders={
                "host": reauth_entry.data.get(CONF_HOST, ""),
            },
        )

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the re-auth form and validate new credentials."""
        errors: dict[str, str] = {}
        reauth_entry = self._get_reauth_entry()

        if user_input is not None:
            host: str = reauth_entry.data[CONF_HOST]
            port: int = reauth_entry.data[CONF_PORT]
            username: str = reauth_entry.data[CONF_USERNAME]
            password: str = user_input[CONF_PASSWORD]
            protocol: str = reauth_entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)

            try:
                await self._validate_input(host, port, username, password, protocol)

            except OpenWrtRpcdSetupError:
                return await self.async_step_reauth_rpcd_setup()
            except OpenWrtAuthError:
                errors["base"] = ERROR_INVALID_AUTH
            except (
                OpenWrtConnectionError,
                OpenWrtTimeoutError,
                OpenWrtResponseError,  # router answers, but not as rpcd (yet)
            ):
                errors["base"] = ERROR_CANNOT_CONNECT
            except Exception:
                _LOGGER.exception("Re-auth: unexpected error")
                errors["base"] = ERROR_UNKNOWN
            else:
                return self.async_update_reload_and_abort(
                    reauth_entry,
                    data_updates={CONF_PASSWORD: password},
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_PASSWORD): str,
                }
            ),
            errors=errors,
            description_placeholders={
                "host": reauth_entry.data.get(CONF_HOST, ""),
                "username": reauth_entry.data.get(CONF_USERNAME, ""),
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_unique_id(board_info: dict[str, Any], host: str, port: int) -> str:
        """Derive the config-entry unique_id for a router.

        Host-based on purpose: the router MAC returned by ``system board`` is
        unreliable as an identity key — OpenWrt's ``system board`` usually has
        no top-level ``mac`` field (→ empty), and identical hardware can report
        the same placeholder/board MAC. Keying on the MAC therefore risks
        aborting a genuinely different router as ``already_configured``.

        The host (a static IP for these setups) is unique per router, so
        ``host:port`` is the stable, collision-free key. The MAC is kept only in
        ``board_info`` for display/diagnostics, never as the identity.

        Args:
            board_info: Board info from :meth:`_validate_input` (unused for the
                key; accepted so callers pass the full context and future logic
                can incorporate a verified-unique MAC if ever needed).
            host: Router host (already stripped).
            port: Router ubus port.

        Returns:
            A stable per-router unique_id string, e.g. ``10.10.10.2_80``.
        """
        return f"{host.strip().lower()}_{port}"

    async def _validate_input(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        protocol: str = DEFAULT_PROTOCOL,
    ) -> dict[str, Any]:
        """Create a temporary API client, test the connection, release it.

        ``async_close`` destroys the rpcd session the test created; without
        it every validation (user step, reauth, each retry click) left a
        session on the router until its TTL expired.
        """
        session = async_get_clientsession(self.hass)
        api = OpenWrtAPI(
            host=host,
            port=port,
            username=username,
            password=password,
            session=session,
            protocol=protocol,
            ssl_context=ssl_context_for_protocol(protocol),
        )
        try:
            return await api.test_connection()
        finally:
            await api.async_close()

    @staticmethod
    def _build_user_schema(
        user_input: dict[str, Any] | None,
    ) -> vol.Schema:
        """Build the data entry schema for the user step (includes protocol)."""
        defaults = user_input or {}
        return vol.Schema(
            {
                vol.Required(
                    CONF_HOST,
                    default=defaults.get(CONF_HOST, ""),
                ): str,
                vol.Required(
                    CONF_PORT,
                    default=defaults.get(CONF_PORT, DEFAULT_PORT),
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
                vol.Required(
                    CONF_PROTOCOL,
                    default=defaults.get(CONF_PROTOCOL, DEFAULT_PROTOCOL),
                ): vol.In(
                    {
                        PROTOCOL_HTTP: "HTTP (Port 80, unsicher)",
                        PROTOCOL_HTTPS: "HTTPS (Port 443, Zertifikat prüfen)",
                        PROTOCOL_HTTPS_INSECURE: "HTTPS Self-Signed (Port 443, Zertifikat ignorieren)",
                    }
                ),
                vol.Required(
                    CONF_USERNAME,
                    default=defaults.get(CONF_USERNAME, DEFAULT_USERNAME),
                ): str,
                vol.Required(CONF_PASSWORD): str,
            }
        )

    @staticmethod
    def _build_protocol_schema() -> vol.Schema:
        """Kept for backward compatibility — protocol is now part of the user step."""
        return vol.Schema(
            {
                vol.Required(
                    CONF_PROTOCOL,
                    default=DEFAULT_PROTOCOL,
                ): vol.In(
                    {
                        PROTOCOL_HTTP: "HTTP (Port 80, unsecure)",
                        PROTOCOL_HTTPS: "HTTPS (Port 443, verify certificate)",
                        PROTOCOL_HTTPS_INSECURE: "HTTPS Self-Signed (Port 443, ignore certificate errors)",
                    }
                ),
            }
        )
