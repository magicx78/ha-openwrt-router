"""Config flow for the OpenWrt Router integration."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtRpcdSetupError,
    OpenWrtTimeoutError,
    OpenWrtResponseError,
)
from .const import (
    CONF_FRITZBOX_HOST,
    CONF_FRITZBOX_PASSWORD,
    CONF_FRITZBOX_PORT,
    CONF_FRITZBOX_USER,
    CONF_PROTOCOL,
    CONF_SWITCH_HOST,
    CONF_SWITCH_PASSWORD,
    CONF_SWITCH_PORT,
    CONF_SWITCH_PROTOCOL,
    CONF_SWITCH_USERNAME,
    DEFAULT_FRITZBOX_HOST,
    DEFAULT_FRITZBOX_PORT,
    DEFAULT_PORT,
    DEFAULT_PROTOCOL,
    DEFAULT_SWITCH_PORT,
    DEFAULT_USERNAME,
    DOMAIN,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_INVALID_HOST,
    ERROR_RPCD_SETUP,
    ERROR_TIMEOUT,
    ERROR_UNKNOWN,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    PROTOCOL_HTTPS_INSECURE,
)

_LOGGER = logging.getLogger(__name__)


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
    if not re.match(r'^[a-zA-Z0-9._\-]{1,253}$', host):
        return ERROR_INVALID_HOST
    return None


class OpenWrtOptionsFlow(OptionsFlow):
    """Options flow — configure Fritz!Box modem credentials per router entry."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        opts = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Optional(
                    CONF_FRITZBOX_HOST,
                    default=opts.get(CONF_FRITZBOX_HOST, DEFAULT_FRITZBOX_HOST),
                ): str,
                vol.Optional(
                    CONF_FRITZBOX_PORT,
                    default=opts.get(CONF_FRITZBOX_PORT, DEFAULT_FRITZBOX_PORT),
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
                vol.Optional(
                    CONF_FRITZBOX_USER,
                    default=opts.get(CONF_FRITZBOX_USER, ""),
                ): str,
                vol.Optional(
                    CONF_FRITZBOX_PASSWORD,
                    default=opts.get(CONF_FRITZBOX_PASSWORD, ""),
                ): str,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)


class OpenWrtConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the config flow for OpenWrt Router.

    Steps:
        user → devices → [fritzbox] → [switch_dev] → checklist → create entry

    The unique_id is set to the router MAC address retrieved during
    validation so that the same physical router cannot be added twice.
    """

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OpenWrtOptionsFlow:
        """Return the options flow handler."""
        return OpenWrtOptionsFlow()

    _CAPABILITY_LABELS: dict[str, str] = {
        "system_info":      "System-Info (CPU, RAM, Uptime)",
        "network_wireless": "WLAN-Status (Radios, SSIDs)",
        "network_dump":     "Netzwerk-Interfaces (WAN/LAN)",
        "file_read":        "Datei-Lesezugriff (Konfiguration, DHCP)",
        "file_exec":        "Datei-Ausführung (Bridge FDB, ARP)",
        "luci_rpc_dhcp":    "DHCP-Leases (Client-IPs)",
        "iwinfo":           "Signal-Stärke (iwinfo)",
        "uci_get":          "UCI-Konfiguration",
        "hostapd_clients":  "WLAN-Clients (hostapd)",
    }

    _REQUIRED_CAPS: frozenset[str] = frozenset({
        "system_info", "network_dump", "network_wireless",
    })

    def __init__(self) -> None:
        """Initialize the config flow."""
        super().__init__()
        self._board_info: dict[str, Any] = {}
        self._capabilities: dict[str, bool] = {}
        self._user_data: dict[str, Any] = {}
        self._add_fritzbox: bool = False
        self._add_switch: bool = False

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

                except Exception:  # noqa: BLE001
                    _LOGGER.exception("Config flow: unexpected error for %s", host)
                    errors["base"] = ERROR_UNKNOWN

                else:
                    mac: str = board_info.get("mac", "").replace(":", "").lower()
                    unique_id = mac if mac else f"{host}_{port}"

                    await self.async_set_unique_id(unique_id)
                    self._abort_if_unique_id_configured(
                        updates={
                            CONF_HOST: host,
                            CONF_PORT: port,
                        }
                    )

                    title = board_info.get("hostname") or host
                    _LOGGER.info(
                        "Config flow: successfully connected to %s (model: %s)",
                        title,
                        board_info.get("model", "unknown"),
                    )

                    self._board_info = board_info
                    self._user_data = {
                        CONF_HOST: host,
                        CONF_PORT: port,
                        CONF_PROTOCOL: protocol,
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                    }
                    return await self.async_step_devices()

        schema = self._build_user_schema(user_input)
        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_devices(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask which additional devices to configure alongside this router."""
        if user_input is not None:
            self._add_fritzbox = bool(user_input.get("add_fritzbox", False))
            self._add_switch = bool(user_input.get("add_switch", False))

            if self._add_fritzbox:
                return await self.async_step_fritzbox()
            if self._add_switch:
                return await self.async_step_switch_dev()
            return await self.async_step_checklist()

        schema = vol.Schema(
            {
                vol.Optional("add_fritzbox", default=False): bool,
                vol.Optional("add_switch", default=False): bool,
            }
        )
        return self.async_show_form(
            step_id="devices",
            data_schema=schema,
            description_placeholders={
                "host": self._user_data.get(CONF_HOST, ""),
                "model": self._board_info.get("model", ""),
            },
        )

    async def async_step_fritzbox(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect Fritz!Box DSL modem credentials during initial setup."""
        if user_input is not None:
            self._user_data[CONF_FRITZBOX_HOST] = user_input.get(CONF_FRITZBOX_HOST, "")
            self._user_data[CONF_FRITZBOX_PORT] = user_input.get(
                CONF_FRITZBOX_PORT, DEFAULT_FRITZBOX_PORT
            )
            self._user_data[CONF_FRITZBOX_USER] = user_input.get(CONF_FRITZBOX_USER, "")
            self._user_data[CONF_FRITZBOX_PASSWORD] = user_input.get(CONF_FRITZBOX_PASSWORD, "")

            if self._add_switch:
                return await self.async_step_switch_dev()
            return await self.async_step_checklist()

        schema = vol.Schema(
            {
                vol.Optional(CONF_FRITZBOX_HOST, default=DEFAULT_FRITZBOX_HOST): str,
                vol.Optional(
                    CONF_FRITZBOX_PORT, default=DEFAULT_FRITZBOX_PORT
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
                vol.Optional(CONF_FRITZBOX_USER, default=""): str,
                vol.Optional(CONF_FRITZBOX_PASSWORD, default=""): str,
            }
        )
        return self.async_show_form(
            step_id="fritzbox",
            data_schema=schema,
            description_placeholders={
                "host": self._user_data.get(CONF_HOST, ""),
            },
        )

    async def async_step_switch_dev(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect managed switch connection details during initial setup."""
        if user_input is not None:
            self._user_data[CONF_SWITCH_HOST] = user_input.get(CONF_SWITCH_HOST, "")
            self._user_data[CONF_SWITCH_PORT] = user_input.get(
                CONF_SWITCH_PORT, DEFAULT_SWITCH_PORT
            )
            self._user_data[CONF_SWITCH_PROTOCOL] = user_input.get(
                CONF_SWITCH_PROTOCOL, DEFAULT_PROTOCOL
            )
            self._user_data[CONF_SWITCH_USERNAME] = user_input.get(CONF_SWITCH_USERNAME, "root")
            self._user_data[CONF_SWITCH_PASSWORD] = user_input.get(CONF_SWITCH_PASSWORD, "")
            return await self.async_step_checklist()

        schema = vol.Schema(
            {
                vol.Required(CONF_SWITCH_HOST, default=""): str,
                vol.Required(
                    CONF_SWITCH_PORT, default=DEFAULT_SWITCH_PORT
                ): vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
                vol.Required(
                    CONF_SWITCH_PROTOCOL, default=DEFAULT_PROTOCOL
                ): vol.In(
                    {
                        PROTOCOL_HTTP: "HTTP (Port 80, unsicher)",
                        PROTOCOL_HTTPS: "HTTPS (Port 443, Zertifikat prüfen)",
                        PROTOCOL_HTTPS_INSECURE: "HTTPS Self-Signed (Port 443, Zertifikat ignorieren)",
                    }
                ),
                vol.Required(CONF_SWITCH_USERNAME, default="root"): str,
                vol.Required(CONF_SWITCH_PASSWORD, default=""): str,
            }
        )
        return self.async_show_form(
            step_id="switch_dev",
            data_schema=schema,
            description_placeholders={
                "host": self._user_data.get(CONF_HOST, ""),
            },
        )

    async def async_step_checklist(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show capability checklist and let user proceed or retry."""
        host = self._user_data.get(CONF_HOST, "")

        if user_input is not None and user_input.get("action") != "retry":
            title = self._board_info.get("hostname") or host
            return self.async_create_entry(title=title, data=self._user_data)

        session = async_get_clientsession(self.hass)
        api = OpenWrtAPI(
            host=host,
            port=self._user_data[CONF_PORT],
            username=self._user_data[CONF_USERNAME],
            password=self._user_data[CONF_PASSWORD],
            session=session,
            protocol=self._user_data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL),
        )
        try:
            await api.login()
            self._capabilities = await api.check_capabilities()
        except Exception:  # noqa: BLE001
            self._capabilities = {}

        lines: list[str] = []
        missing_required: list[str] = []
        missing_optional: list[str] = []

        for cap, label in self._CAPABILITY_LABELS.items():
            ok = self._capabilities.get(cap, False)
            icon = "✅" if ok else "❌"
            lines.append(f"{icon} {label}")
            if not ok:
                if cap in self._REQUIRED_CAPS:
                    missing_required.append(label)
                else:
                    missing_optional.append(label)

        checklist_text = "\n".join(lines)

        install_hint = ""
        if missing_required or missing_optional:
            install_hint = (
                f"\n\n**Pakete installieren (SSH):**\n"
                f"```\n"
                f"opkg update && opkg install luci-mod-rpc luci-lib-jsonc rpcd-mod-rpcsys\n"
                f"scp ha-openwrt-router.json root@{host}:/usr/share/rpcd/acl.d/ha-openwrt-router.json\n"
                f"/etc/init.d/rpcd restart\n"
                f"```"
            )

        if missing_required:
            status = (
                f"⚠️ **Kritische Berechtigungen fehlen** — die Integration kann nicht "
                f"vollständig arbeiten.\n\n"
                f"Bitte die rpcd-ACL auf dem Router aktualisieren:\n"
                f"```\nscp ha-openwrt-router.json root@{host}:"
                f"/usr/share/rpcd/acl.d/ha-openwrt-router.json\n"
                f"/etc/init.d/rpcd restart\n```"
                f"{install_hint}"
            )
        elif missing_optional:
            status = (
                f"ℹ️ Optionale Funktionen nicht verfügbar — Grundfunktionen OK.\n"
                f"SSH-Fallback wird für fehlende Calls verwendet (erhöht Router-Last).\n"
                f"Empfehlung: rpcd-ACL aktualisieren."
                f"{install_hint}"
            )
        else:
            status = "✅ Alle Berechtigungen vorhanden — optimale Konfiguration."

        return self.async_show_form(
            step_id="checklist",
            data_schema=vol.Schema({}),
            description_placeholders={
                "host": host,
                "model": self._board_info.get("model", ""),
                "checklist": checklist_text,
                "status": status,
            },
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> ConfigFlowResult:
        """Diagnose why re-auth was triggered, then route to the right sub-step."""
        reauth_entry = self._get_reauth_entry()
        host: str = reauth_entry.data[CONF_HOST]
        port: int = reauth_entry.data[CONF_PORT]
        username: str = reauth_entry.data[CONF_USERNAME]
        password: str = reauth_entry.data[CONF_PASSWORD]
        protocol: str = reauth_entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)

        try:
            await self._validate_input(host, port, username, password, protocol)
        except OpenWrtResponseError:
            return await self.async_step_reauth_rpcd_setup()
        except (OpenWrtConnectionError, OpenWrtTimeoutError):
            return await self.async_step_reauth_cannot_connect()
        except OpenWrtAuthError:
            return await self.async_step_reauth_confirm()
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Re-auth: unexpected error during diagnosis for %s", host)
            return await self.async_step_reauth_confirm()
        else:
            _LOGGER.debug("Re-auth: existing credentials for %s still valid, reloading", host)
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
            except Exception:  # noqa: BLE001
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
            except OpenWrtRpcdSetupError:
                return await self.async_step_reauth_rpcd_setup()
            except (OpenWrtConnectionError, OpenWrtTimeoutError):
                errors["base"] = ERROR_CANNOT_CONNECT
            except OpenWrtAuthError:
                return await self.async_step_reauth_confirm()
            except Exception:  # noqa: BLE001
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
            except (OpenWrtConnectionError, OpenWrtTimeoutError):
                errors["base"] = ERROR_CANNOT_CONNECT
            except Exception:  # noqa: BLE001
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

    async def _validate_input(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        protocol: str = DEFAULT_PROTOCOL,
    ) -> dict[str, Any]:
        """Create a temporary API client and test the connection."""
        session = async_get_clientsession(self.hass)
        api = OpenWrtAPI(
            host=host,
            port=port,
            username=username,
            password=password,
            session=session,
            protocol=protocol,
        )
        return await api.test_connection()

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
