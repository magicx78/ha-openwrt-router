"""Config flow for the OpenWrt Router integration."""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

import aiohttp
import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import (
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtTimeoutError,
    OpenWrtResponseError,
)
from .const import (
    DEFAULT_PORT,
    DEFAULT_USERNAME,
    DOMAIN,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_INVALID_HOST,
    ERROR_TIMEOUT,
    ERROR_UNKNOWN,
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


class OpenWrtConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the config flow for OpenWrt Router.

    Steps:
        user → validate credentials → create entry

    The unique_id is set to the router MAC address retrieved during
    validation so that the same physical router cannot be added twice.
    """

    VERSION = 1

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

                    return self.async_create_entry(
                        title=title,
                        data={
                            CONF_HOST: host,
                            CONF_PORT: port,
                            CONF_USERNAME: username,
                            CONF_PASSWORD: password,
                        },
                    )

        # Build the user form schema, pre-filling defaults where sensible
        schema = self._build_user_schema(user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> ConfigFlowResult:
        """Handle re-authentication when the session token has become invalid.

        Triggered automatically by HA when ConfigEntryAuthFailed is raised
        in the coordinator.

        Args:
            entry_data: Current config entry data (host, port, username).

        Returns:
            ConfigFlowResult showing re-auth form or updating entry on success.
        """
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show the re-auth form and validate new credentials.

        Only the password field is shown; host/port/username are preserved
        from the existing config entry.
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
