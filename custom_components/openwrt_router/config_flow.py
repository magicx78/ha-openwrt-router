"""Config flow for the OpenWrt Router integration."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

import aiohttp
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
    DEFAULT_FRITZBOX_HOST,
    DEFAULT_FRITZBOX_PORT,
    DEFAULT_PORT,
    DEFAULT_PROTOCOL,
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
    # Try to parse as an IP address first
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
            return ERROR_INVALID_HOST
        return None  # valid routable IP
    except ValueError:
        pass
    # Validate as a hostname: only alphanumerics, dots, hyphens, underscores
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
        user → protocol → create entry

    The unique_id is set to the router MAC address retrieved during
    validation so that the same physical router cannot be added twice.
    """

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OpenWrtOptionsFlow:
        """Return the options flow handler."""
        return OpenWrtOptionsFlow()

    def __init__(self) -> None:
        """Initialize the config flow."""
        super().__init__()
        self._board_info: dict[str, Any] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial user-facing setup step.

        Presents a form asking for host, port, username and password.
        On submission, attempts to login and read the board info.

        Args:
            user_input: Form values submitted by the user, or None on first render.

        Returns:
            A ConfigFlowResult that either shows the form again (with errors)
            or creates the config entry.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = user_input[CONF_HOST].strip()
            port: int = user_input[CONF_PORT]
            username: str = user_input[CONF_USERNAME].strip()
            password: str = user_input[CONF_PASSWORD]  # never logged

            host_error = _validate_host(host)
            if host_error:
                errors["host"] = host_error
            else:
                try:
                    board_info = await self._validate_input(host, port, username, password)

                except OpenWrtRpcdSetupError:
                    _LOGGER.debug("Config flow: rpcd not configured on %s", host)
                    errors["base"] = ERROR_RPCD_SETUP

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
                    # Build a unique_id from the router MAC address.
                    # Fall back to host:port if MAC is unavailable.
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

                    # Store validated info and proceed to protocol selection
                    self._board_info = board_info
                    self._user_data = {
                        CONF_HOST: host,
                        CONF_PORT: port,
                        CONF_USERNAME: username,
                        CONF_PASSWORD: password,
                    }
                    return await self.async_step_protocol()

        # Build the user form schema, pre-filling defaults where sensible
        schema = self._build_user_schema(user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_protocol(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle protocol selection (HTTP/HTTPS).

        Args:
            user_input: Protocol choice from user or None on first render.

        Returns:
            A ConfigFlowResult that either shows the form or creates the entry.
        """
        if user_input is not None:
            protocol: str = user_input[CONF_PROTOCOL]

            # Create the config entry with protocol selection
            title = self._board_info.get("hostname") or self._user_data.get(CONF_HOST, "")
            return self.async_create_entry(
                title=title,
                data={
                    **self._user_data,
                    CONF_PROTOCOL: protocol,
                },
            )

        # Show protocol selection form
        schema = self._build_protocol_schema()
        return self.async_show_form(
            step_id="protocol",
            data_schema=schema,
            description_placeholders={
                "host": self._user_data.get(CONF_HOST, ""),
            },
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> ConfigFlowResult:
        """Diagnose why re-auth was triggered, then route to the right sub-step.

        Tries the existing credentials first.  If they still work the entry is
        silently reloaded — the user never sees a dialog.  Only when the
        credentials are genuinely wrong does the password form appear.

        Args:
            entry_data: Current config entry data (host, port, username).

        Returns:
            ConfigFlowResult routed to the appropriate sub-step.
        """
        reauth_entry = self._get_reauth_entry()
        host: str = reauth_entry.data[CONF_HOST]
        port: int = reauth_entry.data[CONF_PORT]
        username: str = reauth_entry.data[CONF_USERNAME]
        password: str = reauth_entry.data[CONF_PASSWORD]

        try:
            await self._validate_input(host, port, username, password)
        except OpenWrtRpcdSetupError:
            return await self.async_step_reauth_rpcd_setup()
        except (OpenWrtConnectionError, OpenWrtTimeoutError, OpenWrtResponseError):
            return await self.async_step_reauth_cannot_connect()
        except OpenWrtAuthError:
            # Credentials genuinely changed — ask for new password
            return await self.async_step_reauth_confirm()
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Re-auth: unexpected error during diagnosis for %s", host)
            return await self.async_step_reauth_confirm()
        else:
            # Existing credentials still work — silent auto-resolve, no user prompt
            _LOGGER.debug("Re-auth: existing credentials for %s still valid, reloading", host)
            return self.async_update_reload_and_abort(reauth_entry)

    async def async_step_reauth_rpcd_setup(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show rpcd setup instructions with a 'I've fixed it — retry' button.

        Displayed when session/login returns permission denied, which means
        rpcd is misconfigured (wrong socket path, missing package, etc.).
        """
        reauth_entry = self._get_reauth_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = reauth_entry.data[CONF_HOST]
            port: int = reauth_entry.data[CONF_PORT]
            username: str = reauth_entry.data[CONF_USERNAME]
            password: str = reauth_entry.data[CONF_PASSWORD]

            try:
                await self._validate_input(host, port, username, password)
            except OpenWrtRpcdSetupError:
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
        """Show 'router unreachable' message with a retry button.

        Displayed when the router cannot be reached during re-auth diagnosis.
        """
        reauth_entry = self._get_reauth_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            host: str = reauth_entry.data[CONF_HOST]
            port: int = reauth_entry.data[CONF_PORT]
            username: str = reauth_entry.data[CONF_USERNAME]
            password: str = reauth_entry.data[CONF_PASSWORD]

            try:
                await self._validate_input(host, port, username, password)
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
        """Show the re-auth form and validate new credentials.

        Only reached when existing credentials are genuinely rejected.
        Host/port/username are preserved; only the password can change.
        """
        errors: dict[str, str] = {}
        reauth_entry = self._get_reauth_entry()

        if user_input is not None:
            host: str = reauth_entry.data[CONF_HOST]
            port: int = reauth_entry.data[CONF_PORT]
            username: str = reauth_entry.data[CONF_USERNAME]
            password: str = user_input[CONF_PASSWORD]

            try:
                await self._validate_input(host, port, username, password)

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
        self, host: str, port: int, username: str, password: str
    ) -> dict[str, Any]:
        """Create a temporary API client and test the connection.

        Args:
            host: Router IP / hostname.
            port: HTTP port.
            username: rpcd username.
            password: rpcd password (never logged).

        Returns:
            Board info dict from the router.

        Raises:
            OpenWrtAuthError: Credentials rejected.
            OpenWrtConnectionError: Router unreachable.
            OpenWrtTimeoutError: Request timed out.
            OpenWrtResponseError: Malformed response.
        """
        session = async_get_clientsession(self.hass)
        api = OpenWrtAPI(
            host=host,
            port=port,
            username=username,
            password=password,
            session=session,
        )
        return await api.test_connection()

    @staticmethod
    def _build_user_schema(
        user_input: dict[str, Any] | None,
    ) -> vol.Schema:
        """Build the data entry schema for the user step.

        Pre-fills submitted values so they survive validation errors.

        Args:
            user_input: Previously submitted values or None.

        Returns:
            voluptuous Schema.
        """
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
                    CONF_USERNAME,
                    default=defaults.get(CONF_USERNAME, DEFAULT_USERNAME),
                ): str,
                vol.Required(CONF_PASSWORD): str,
            }
        )

    @staticmethod
    def _build_protocol_schema() -> vol.Schema:
        """Build the data entry schema for the protocol step.

        Returns:
            voluptuous Schema with protocol dropdown.
        """
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
