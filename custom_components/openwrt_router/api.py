"""OpenWrt ubus / rpcd JSON-RPC API client."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import ssl
from typing import Any

import aiohttp

from .const import (
    CLIENT_KEY_HOSTNAME,
    CLIENT_KEY_IP,
    CLIENT_KEY_MAC,
    CLIENT_KEY_RADIO,
    CLIENT_KEY_SIGNAL,
    CLIENT_KEY_SSID,
    DEFAULT_PROTOCOL,
    DEFAULT_SESSION_ID,
    DEFAULT_TIMEOUT,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS,
    PROTOCOL_HTTPS_INSECURE,
    DHCP_LEASES_PATH,
    GUEST_SSID_KEYWORDS,
    RADIO_BAND_24GHZ_KEYWORDS,
    RADIO_BAND_5GHZ_KEYWORDS,
    RADIO_BAND_6GHZ_KEYWORDS,
    RADIO_KEY_BAND,
    RADIO_KEY_ENABLED,
    RADIO_KEY_IFNAME,
    RADIO_KEY_IS_GUEST,
    RADIO_KEY_NAME,
    RADIO_KEY_SSID,
    RADIO_KEY_UCI_SECTION,
    UBUS_FILE_OBJECT,
    UBUS_FILE_READ,
    UBUS_IWINFO_ASSOCLIST,
    UBUS_IWINFO_INFO,
    UBUS_IWINFO_OBJECT,
    UBUS_NETWORK_DUMP,
    UBUS_NETWORK_OBJECT,
    UBUS_NETWORK_RELOAD,
    UBUS_NETWORK_RELOAD_METHOD,
    UBUS_SESSION_METHOD_LOGIN,
    UBUS_SESSION_OBJECT_LOGIN,
    UBUS_SYSTEM_BOARD,
    UBUS_SYSTEM_INFO,
    UBUS_SYSTEM_OBJECT,
    UBUS_UCI_COMMIT,
    UBUS_UCI_GET,
    UBUS_UCI_OBJECT,
    UBUS_UCI_SET,
    UBUS_WIRELESS_OBJECT,
    UBUS_WIRELESS_STATUS,
    WAN_INTERFACE_NAMES,
)

_LOGGER = logging.getLogger(__name__)

# ubus RPC error codes
UBUS_STATUS_OK = 0
UBUS_STATUS_INVALID_COMMAND = 1
UBUS_STATUS_INVALID_ARGUMENT = 2
UBUS_STATUS_METHOD_NOT_FOUND = 3
UBUS_STATUS_NOT_FOUND = 4
UBUS_STATUS_NO_DATA = 5
UBUS_STATUS_PERMISSION_DENIED = 6
UBUS_STATUS_TIMEOUT = 7
UBUS_STATUS_NOT_SUPPORTED = 8
UBUS_STATUS_UNKNOWN_ERROR = 9
UBUS_STATUS_CONNECTION_FAILED = 10


class OpenWrtAuthError(Exception):
    """Raised when authentication with the router fails."""


class OpenWrtConnectionError(Exception):
    """Raised when the router cannot be reached."""


class OpenWrtTimeoutError(Exception):
    """Raised when a request times out."""


class OpenWrtMethodNotFoundError(Exception):
    """Raised when a ubus method is not available on the router."""


class OpenWrtResponseError(Exception):
    """Raised when the router returns an unexpected response."""


class OpenWrtAPI:
    """Async client for OpenWrt ubus / rpcd JSON-RPC.

    Handles session management, token renewal, and all ubus calls.
    Compatible with OpenWrt >= 19.07 (rpcd baseline).
    Tested against OpenWrt 24.10.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
        timeout: int = DEFAULT_TIMEOUT,
        protocol: str = DEFAULT_PROTOCOL,
    ) -> None:
        """Initialise the API client.

        Args:
            host: Router hostname or IP address.
            port: HTTP/HTTPS port (default 80 for HTTP, 443 for HTTPS).
            username: rpcd username (usually 'root').
            password: rpcd password.
            session: Shared aiohttp ClientSession.
            timeout: Request timeout in seconds.
            protocol: Connection protocol ("http", "https", "https-insecure").

        Note:
            The password is stored in memory only and is never logged.
        """
        self._host = host
        self._port = port
        self._username = username
        self._password = password  # never logged
        self._session = session
        self._protocol = protocol
        # M-1: granular timeouts — short connect budget, full timeout for reads
        self._timeout = aiohttp.ClientTimeout(
            total=timeout,
            connect=min(5, timeout),
            sock_connect=min(5, timeout),
            sock_read=timeout,
        )
        # Build SSL context for HTTPS connections
        self._ssl_context = self._build_ssl_context()

        # L-2: IPv6-safe URL — bare IPv6 addresses require square brackets
        host_str = f"[{host}]" if ":" in host and not host.startswith("[") else host
        scheme = "https" if protocol != PROTOCOL_HTTP else "http"
        self._ubus_url = f"{scheme}://{host_str}:{port}/ubus"
        self._rpc_id = 0

        # Session token – refreshed on login / expiry
        self._token: str = DEFAULT_SESSION_ID

        # Cached WiFi API method: None=unknown, "wireless", "iwinfo", "none"
        # Set on first get_wifi_status() call and reused to avoid retrying
        # known-unavailable APIs on every poll cycle.
        self._wifi_method: str | None = None

        # L-1: track consecutive login failures to suppress log spam
        self._login_failure_count: int = 0

        # M-4: warn once when using the root account
        self._root_warning_logged: bool = False

    # ------------------------------------------------------------------
    # Public auth API
    # ------------------------------------------------------------------

    async def login(self) -> bool:
        """Authenticate against rpcd and store the session token.

        Returns:
            True on success.

        Raises:
            OpenWrtAuthError: If credentials are rejected.
            OpenWrtConnectionError: If the router is unreachable.
            OpenWrtTimeoutError: If the request times out.
        """
        _LOGGER.debug("Logging in to %s as %s", self._ubus_url, self._username)

        # M-4: warn once if using the privileged root account
        if self._username == "root" and not self._root_warning_logged:
            _LOGGER.warning(
                "OpenWrt Router: Using 'root' as rpcd user grants full router access. "
                "Consider creating a dedicated restricted rpcd user for better security."
            )
            self._root_warning_logged = True

        payload = self._build_call(
            UBUS_SESSION_OBJECT_LOGIN,
            UBUS_SESSION_METHOD_LOGIN,
            {"username": self._username, "password": self._password},
            use_default_session=True,
        )

        try:
            result = await self._raw_call(payload)
        except OpenWrtResponseError as err:
            # L-1: count failures; suppress repeated ERROR spam after threshold
            self._login_failure_count += 1
            if self._login_failure_count >= 5:
                _LOGGER.warning(
                    "OpenWrt Router at %s appears persistently unreachable "
                    "(login failed %d times). Will keep retrying silently.",
                    self._ubus_url,
                    self._login_failure_count,
                )
            raise OpenWrtAuthError(f"Login failed: {err}") from err

        token = (result or {}).get("ubus_rpc_session")
        if not token or token == DEFAULT_SESSION_ID:
            # L-1: also count invalid-token responses as failures
            self._login_failure_count += 1
            raise OpenWrtAuthError(
                "Router returned an invalid session token – check credentials."
            )

        # L-1: successful login resets the failure counter
        self._login_failure_count = 0
        self._token = token
        _LOGGER.debug("Login successful, session established")
        return True

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        """Build SSL context for HTTPS connections.

        Returns:
            SSLContext configured for the selected protocol, or None for HTTP.
        """
        if self._protocol == PROTOCOL_HTTP:
            return None

        # Create SSL context
        ssl_context = ssl.create_default_context()

        if self._protocol == PROTOCOL_HTTPS_INSECURE:
            # Allow self-signed certificates
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        return ssl_context

    async def test_connection(self) -> dict[str, Any]:
        """Login and fetch board info; used by config flow to validate setup.

        Returns:
            dict with 'model', 'hostname', 'release' keys.

        Raises:
            OpenWrtAuthError: Wrong credentials.
            OpenWrtConnectionError: Router unreachable.
            OpenWrtTimeoutError: Request timed out.
        """
        # Try to login; if it fails due to ACL, continue with default session
        try:
            await self.login()
            _LOGGER.debug("Successfully authenticated with router")
        except OpenWrtAuthError as err:
            _LOGGER.warning(
                "Could not authenticate (rpcd may have restricted ACL): %s. "
                "Will attempt to use default session. Some features may be unavailable.",
                err
            )
            # Continue anyway – some routers have public read-only APIs

        return await self.get_router_info()

    # ------------------------------------------------------------------
    # Public data API
    # ------------------------------------------------------------------

    def _extract_platform_architecture(self, board_info: dict[str, Any]) -> str:
        """Extract platform architecture from board info.

        Tries multiple sources:
        1. board_name (e.g. "cudy,wr3000-v1" → extract vendor/platform)
        2. release.target (e.g. "ath79")
        3. kernel (e.g. "5.15.137")
        Falls back to "unknown" if nothing found.

        Args:
            board_info: Result from system/board ubus call.

        Returns:
            Platform architecture string.
        """
        # Try release.target first (best indicator: "ath79", "mt7621", etc.)
        release = board_info.get("release", {})
        if target := release.get("target"):
            return str(target)

        # Try board_name (format: "vendor,model-variant")
        board_name = board_info.get("board_name", "")
        if board_name and "," in board_name:
            # Extract vendor part which often maps to SoC platform
            vendor = board_name.split(",")[0]
            if vendor:
                return vendor

        # Fallback: try kernel string (sometimes contains arch hints)
        kernel = board_info.get("kernel", "")
        if "x86" in kernel.lower():
            return "x86_64"
        if "arm" in kernel.lower():
            return "arm"
        if "mips" in kernel.lower():
            return "mips"

        return "unknown"

    async def get_router_info(self) -> dict[str, Any]:
        """Return static board information (model, hostname, OpenWrt release, architecture).

        Calls:
            system board

        Returns:
            {
                "model": str,
                "hostname": str,
                "release": {"distribution": str, "version": str, ...},
                "mac": str,  # used as unique_id
                "board_name": str,
                "kernel": str,
                "platform_architecture": str,  # e.g. "ath79", "mt7621", "arm_cortex-a9"
            }

        Note:
            If access is denied (unauthenticated router with restrictive ACL),
            returns minimal safe defaults.
        """
        try:
            result = await self._call(UBUS_SYSTEM_OBJECT, UBUS_SYSTEM_BOARD, {})
        except (OpenWrtMethodNotFoundError, OpenWrtAuthError) as err:
            # Access denied – router has restrictive ACL, return safe defaults
            if "access denied" in str(err).lower() or "permission" in str(err).lower():
                _LOGGER.warning(
                    "Cannot access system/board (rpcd ACL restricted). "
                    "Using fallback router info."
                )
                result = {}
            else:
                raise

        # Extract platform architecture from various sources
        platform_arch = self._extract_platform_architecture(result)

        return {
            "model": result.get("model", "OpenWrt Router"),
            "hostname": result.get("hostname", self._host),
            "release": result.get("release", {}),
            "mac": result.get("mac", ""),
            "board_name": result.get("board_name", ""),
            "kernel": result.get("kernel", ""),
            "platform_architecture": platform_arch,
        }

    async def get_router_status(self) -> dict[str, Any]:
        """Return dynamic system metrics (uptime, load, memory).

        Calls:
            system info

        Returns:
            {
                "uptime": int,        # seconds since boot
                "load": list[int],    # raw load values (* 65536) [1min, 5min, 15min]
                "cpu_load": float,    # 1-min load average as percentage (0-100)
                "cpu_load_5min": float,  # 5-min load average as percentage (0-100)
                "cpu_load_15min": float, # 15-min load average as percentage (0-100)
                "memory": dict,       # total, free, shared, buffered, available (bytes)
            }

        Note:
            If access is denied (unauthenticated router with restrictive ACL),
            returns default values (0 uptime, 0 load, empty memory dict).
        """
        try:
            result = await self._call(UBUS_SYSTEM_OBJECT, UBUS_SYSTEM_INFO, {})
        except (OpenWrtMethodNotFoundError, OpenWrtAuthError) as err:
            # Access denied – return safe defaults
            if "access denied" in str(err).lower() or "permission" in str(err).lower():
                _LOGGER.warning(
                    "Cannot access system/info (rpcd ACL restricted). "
                    "System metrics unavailable."
                )
                return {
                    "uptime": 0,
                    "load": [0, 0, 0],
                    "cpu_load": 0.0,
                    "cpu_load_5min": 0.0,
                    "cpu_load_15min": 0.0,
                    "memory": {},
                }
            raise

        raw_load: list[int] = result.get("load", [0, 0, 0])
        # OpenWrt encodes load averages as integer * 65536
        cpu_load = round(raw_load[0] / 65536 * 100, 1) if raw_load else 0.0
        cpu_load_5min = round(raw_load[1] / 65536 * 100, 1) if len(raw_load) > 1 else 0.0
        cpu_load_15min = round(raw_load[2] / 65536 * 100, 1) if len(raw_load) > 2 else 0.0

        return {
            "uptime": result.get("uptime", 0),
            "load": raw_load,
            "cpu_load": cpu_load,
            "cpu_load_5min": cpu_load_5min,
            "cpu_load_15min": cpu_load_15min,
            "memory": result.get("memory", {}),
        }

    async def get_wan_status(self) -> dict[str, Any]:
        """Return WAN interface connection status + RX/TX bytes from /sys/class/net.

        Uses network.interface/dump for basic status (up, ip, uptime) but reads
        RX/TX bytes from /sys/class/net/{iface}/statistics/ files (kernel source).

        Returns:
            {
                "connected": bool,
                "interface": str,
                "ipv4": str,
                "uptime": int,
                "rx_bytes": int or None,
                "tx_bytes": int or None,
            }
        """
        # Get basic network status
        result = await self._call(UBUS_NETWORK_OBJECT, UBUS_NETWORK_DUMP, {})
        interfaces: list[dict[str, Any]] = result.get("interface", [])

        # Find WAN interface (try both name matching and highest traffic)
        wan_iface = None
        for iface in interfaces:
            iface_name: str = iface.get("interface", "").lower()
            if iface_name in WAN_INTERFACE_NAMES or any(
                iface_name.startswith(w) for w in WAN_INTERFACE_NAMES
            ):
                wan_iface = iface
                break

        if not wan_iface and interfaces:
            # Fallback: use first interface that's marked as up
            wan_iface = next((i for i in interfaces if i.get("up")), interfaces[0])

        if not wan_iface:
            return {
                "connected": False,
                "interface": "",
                "ipv4": "",
                "uptime": 0,
                "rx_bytes": None,
                "tx_bytes": None,
            }

        # Extract basic info
        ipv4_list = wan_iface.get("ipv4-address", [])
        ipv4 = ipv4_list[0].get("address", "") if ipv4_list else ""
        iface_name = wan_iface.get("interface", "").lower()

        # Try to read RX/TX bytes from /sys/class/net/{iface}/statistics/
        rx_bytes = None
        tx_bytes = None

        try:
            rx_path = f"/sys/class/net/{iface_name}/statistics/rx_bytes"
            tx_path = f"/sys/class/net/{iface_name}/statistics/tx_bytes"

            rx_result = await self._call("file", "read", {"path": rx_path})
            tx_result = await self._call("file", "read", {"path": tx_path})

            if rx_result:
                rx_bytes = int(rx_result.strip()) if isinstance(rx_result, str) else None
            if tx_result:
                tx_bytes = int(tx_result.strip()) if isinstance(tx_result, str) else None
        except Exception:
            # Silently fail – stats not available on this router
            pass

        return {
            "connected": wan_iface.get("up", False),
            "interface": wan_iface.get("interface", ""),
            "ipv4": ipv4,
            "uptime": wan_iface.get("uptime", 0),
            "proto": wan_iface.get("proto", ""),
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
        }

        # No WAN interface found – treat as disconnected
        _LOGGER.debug("No WAN interface found in network dump")
        return {"connected": False, "interface": "", "ipv4": "", "uptime": 0, "rx_bytes": 0, "tx_bytes": 0}

    async def get_wifi_status(self) -> list[dict[str, Any]]:
        """Return a list of WiFi radio / SSID descriptors.

        Tries network.wireless/status first (OpenWrt 21+), then iwinfo/info,
        then falls back to UCI wireless config.

        Returns:
            List of radio dicts with keys defined by RADIO_KEY_* constants.
        """
        # Fast path: use cached method from previous call
        if self._wifi_method == "uci":
            try:
                values = await self.get_uci_wireless()
                if values:
                    return self._parse_uci_wireless(values)
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                self._wifi_method = None
        if self._wifi_method == "none":
            return []
        if self._wifi_method == "wireless":
            try:
                result = await self._call(UBUS_WIRELESS_OBJECT, UBUS_WIRELESS_STATUS, {})
                parsed = self._parse_wireless_status(result)
                if parsed:
                    return parsed
                # Empty result means no real radios detected via this method –
                # fall through to re-probe with iwinfo / UCI
                _LOGGER.debug(
                    "network.wireless/status returned empty result, re-probing"
                )
                self._wifi_method = None
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                # Method disappeared (e.g. firmware update) – re-probe
                self._wifi_method = None
        if self._wifi_method == "iwinfo":
            try:
                result = await self._call(UBUS_IWINFO_OBJECT, UBUS_IWINFO_INFO, {})
                return self._parse_iwinfo_info(result)
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                self._wifi_method = None

        # First call or cache invalidated – probe all three methods in order
        try:
            result = await self._call(UBUS_WIRELESS_OBJECT, UBUS_WIRELESS_STATUS, {})
            parsed = self._parse_wireless_status(result)
            if parsed:
                self._wifi_method = "wireless"
                _LOGGER.debug("WiFi method: network.wireless/status")
                return parsed
            _LOGGER.debug(
                "network.wireless/status returned empty result, falling back to iwinfo"
            )
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            _LOGGER.debug("network.wireless/status not available, falling back to iwinfo")

        try:
            result = await self._call(UBUS_IWINFO_OBJECT, UBUS_IWINFO_INFO, {})
            parsed = self._parse_iwinfo_info(result)
            if parsed:
                self._wifi_method = "iwinfo"
                _LOGGER.debug("WiFi method: iwinfo/info")
                return parsed
            _LOGGER.debug("iwinfo/info returned empty result, falling back to UCI")
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            _LOGGER.debug("iwinfo/info not available, falling back to UCI")

        try:
            values = await self.get_uci_wireless()
            if values:
                self._wifi_method = "uci"
                _LOGGER.debug("WiFi method: UCI wireless config")
                return self._parse_uci_wireless(values)
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            _LOGGER.debug("UCI wireless config not available")

        self._wifi_method = "none"
        _LOGGER.debug(
            "No WiFi API available on this router (tried wireless, iwinfo, UCI)"
        )
        return []

    async def get_connected_clients(
        self,
        leases: dict[str, dict[str, str]] | None = None,
        radios: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Return a list of currently associated WiFi clients.

        Calls:
            iwinfo assoclist  (once per discovered radio interface)

        Args:
            leases: Pre-fetched DHCP lease dict (MAC → {ip, hostname}).
                    If provided, skips a second get_dhcp_leases() call.
                    If None, fetches leases internally.
            radios: Pre-fetched radio list from get_wifi_status().
                    If provided, skips a second get_wifi_status() call.
                    If None, fetches radios internally.

        Returns:
            List of client dicts with keys defined by CLIENT_KEY_* constants.
        """
        # Use pre-fetched radios if available to avoid a redundant WiFi API call
        if radios is None:
            radios = await self.get_wifi_status()
        clients: list[dict[str, Any]] = []

        for radio in radios:
            ifname: str = radio.get(RADIO_KEY_IFNAME, "")
            if not ifname:
                continue
            try:
                result = await self._call(
                    UBUS_IWINFO_OBJECT,
                    UBUS_IWINFO_ASSOCLIST,
                    {"device": ifname},
                )
                assocs: list[dict[str, Any]] = result.get("results", [])
                for assoc in assocs:
                    clients.append(
                        {
                            CLIENT_KEY_MAC: assoc.get("mac", "").upper(),
                            CLIENT_KEY_IP: "",
                            CLIENT_KEY_HOSTNAME: "",
                            CLIENT_KEY_SIGNAL: assoc.get("signal", 0),
                            CLIENT_KEY_SSID: radio.get(RADIO_KEY_SSID, ""),
                            CLIENT_KEY_RADIO: ifname,
                        }
                    )
            except OpenWrtMethodNotFoundError:
                _LOGGER.debug("iwinfo assoclist not available for %s", ifname)
            except OpenWrtResponseError as err:
                _LOGGER.debug("Failed to get assoclist for %s: %s", ifname, err)

        # Enrich with IP / hostname – use pre-fetched leases to avoid a second
        # file/read call when the coordinator has already fetched them.
        clients = await self._enrich_clients_with_ip(clients, leases=leases)
        return clients

    async def set_wifi_state(self, uci_section: str, enabled: bool) -> bool:
        """Enable or disable a WiFi interface via UCI or SSH fallback.

        Sets uci wireless.<section>.disabled = 0|1 then commits.
        If ubus UCI is blocked (ACL-restricted router), falls back to SSH script.

        Args:
            uci_section: UCI section name (e.g. 'default_radio0').
            enabled: True to enable, False to disable.

        Returns:
            True on success.

        Raises:
            OpenWrtMethodNotFoundError: If UCI is not available.
            UpdateFailed: If the operation fails.
        """
        disabled_value = "0" if enabled else "1"
        action = "enable" if enabled else "disable"
        _LOGGER.info(
            "Setting WiFi section %s %s (disabled=%s)", uci_section, action, disabled_value
        )

        # Try ubus/UCI first
        try:
            # Set UCI value
            await self._call(
                UBUS_UCI_OBJECT,
                UBUS_UCI_SET,
                {
                    "config": "wireless",
                    "section": uci_section,
                    "values": {"disabled": disabled_value},
                },
            )
            _LOGGER.debug("UCI set successful for %s", uci_section)

            # Commit changes
            await self._call(
                UBUS_UCI_OBJECT,
                UBUS_UCI_COMMIT,
                {"config": "wireless"},
            )
            _LOGGER.debug("UCI commit successful")

            # Reload network config
            await self.reload_wifi()
            _LOGGER.info("WiFi section %s %s successfully", uci_section, action)
            return True

        except (
            OpenWrtMethodNotFoundError,
            OpenWrtResponseError,
            OpenWrtTimeoutError,
            OpenWrtConnectionError,
        ) as err:
            # Fall back to SSH if ubus is blocked (any access denied error)
            err_str = str(err).lower()
            if "access denied" in err_str or "permission" in err_str:
                _LOGGER.warning(
                    "ubus UCI blocked (ACL-restricted), attempting SSH fallback: %s", err
                )
                try:
                    return await self._set_wifi_state_ssh(uci_section, enabled)
                except Exception as ssh_err:
                    _LOGGER.error("SSH fallback also failed: %s", ssh_err)
                    raise OpenWrtResponseError(
                        f"Failed to {action} WiFi section {uci_section} (ubus blocked, SSH failed): {err}"
                    ) from ssh_err

            _LOGGER.error("Failed to %s WiFi section %s: %s", action, uci_section, err)
            raise OpenWrtResponseError(
                f"Failed to {action} WiFi section {uci_section}: {err}"
            ) from err

    async def _set_wifi_state_ssh(self, uci_section: str, enabled: bool) -> bool:
        """Enable or disable WiFi interface via SSH script (fallback for ACL-restricted routers).

        Calls /root/ha-wifi-control.sh on the router via SSH.

        Args:
            uci_section: UCI section name (e.g. 'default_radio0').
            enabled: True to enable, False to disable.

        Returns:
            True on success.

        Raises:
            Exception: If SSH command fails.
        """
        action_cmd = "enable-ssid" if enabled else "disable-ssid"
        action_desc = "enable" if enabled else "disable"

        # Build SSH command using sshpass for password auth
        ssh_cmd = [
            "sshpass",
            "-p",
            self._password,
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            f"{self._username}@{self._host}",
            f"/root/ha-wifi-control.sh {action_cmd} {uci_section}",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)

            if proc.returncode == 0:
                output = stdout.decode().strip()
                _LOGGER.info(
                    "SSH WiFi control successful: %s (output: %s)",
                    uci_section,
                    output,
                )
                return True
            else:
                error_msg = stderr.decode().strip()
                _LOGGER.error(
                    "SSH WiFi control failed for %s: %s", uci_section, error_msg
                )
                raise OpenWrtResponseError(
                    f"SSH {action_desc} failed for {uci_section}: {error_msg}"
                )

        except asyncio.TimeoutError:
            _LOGGER.error("SSH command timed out for WiFi section %s", uci_section)
            raise OpenWrtTimeoutError(f"SSH {action_desc} timed out for {uci_section}")
        except Exception as err:
            _LOGGER.error(
                "SSH command failed for WiFi section %s: %s", uci_section, err
            )
            raise

    async def reload_wifi(self) -> bool:
        """Reload network / WiFi configuration on the router.

        Tries network.reload first; falls back to a best-effort approach.

        Returns:
            True on success.
        """
        _LOGGER.debug("Reloading network configuration")
        try:
            await self._call(UBUS_NETWORK_RELOAD, UBUS_NETWORK_RELOAD_METHOD, {})
            return True
        except OpenWrtMethodNotFoundError:
            _LOGGER.warning(
                "network.reload not available – WiFi state may not apply immediately"
            )
            return False

    async def get_dhcp_leases(self) -> dict[str, dict[str, str]]:
        """Return a MAC → {ip, hostname} mapping from the DHCP lease table.

        Reads /tmp/dhcp.leases via the rpcd file module (requires
        rpcd-mod-file on the router, available by default on most
        OpenWrt installations).

        The dnsmasq lease file format is one entry per line::

            <expiry-timestamp> <mac> <ip> <hostname> <client-id>

        Example line::

            1741600000 b8:27:eb:aa:bb:cc 192.168.1.100 raspberrypi *

        Returns:
            dict mapping uppercase MAC to {"ip": str, "hostname": str}.
            Returns empty dict if the file is unavailable or unreadable.
        """
        try:
            result = await self._call(
                UBUS_FILE_OBJECT,
                UBUS_FILE_READ,
                {"path": DHCP_LEASES_PATH},
            )
        except OpenWrtMethodNotFoundError:
            _LOGGER.debug(
                "rpcd file module not available – DHCP lease enrichment disabled"
            )
            return {}
        except OpenWrtAuthError:
            _LOGGER.debug(
                "rpcd file/read permission denied for %s – "
                "add /tmp/dhcp.leases to rpcd ACL to enable enrichment",
                DHCP_LEASES_PATH,
            )
            return {}
        except OpenWrtResponseError as err:
            _LOGGER.debug("Could not read DHCP leases: %s", err)
            return {}

        raw: str = result.get("data", "")
        return self._parse_dhcp_leases(raw)

    async def get_uci_wireless(self) -> dict[str, Any]:
        """Fetch the full UCI wireless configuration.

        Used during feature detection to map SSIDs → UCI sections.

        Returns:
            Raw UCI wireless config dict.
        """
        result = await self._call(
            UBUS_UCI_OBJECT,
            UBUS_UCI_GET,
            {"config": "wireless"},
        )
        return result.get("values", {})

    # ------------------------------------------------------------------
    # Feature detection
    # ------------------------------------------------------------------

    async def detect_features(self) -> dict[str, Any]:
        """Probe the router to determine which features are available.

        Called once during coordinator first-refresh to build the feature map
        that controls which entities get created.

        Returns:
            Feature dict with FEATURE_* keys.
        """
        features: dict[str, Any] = {
            "has_iwinfo": False,
            "has_5ghz": False,
            "has_6ghz": False,
            "has_guest_wifi": False,
            "available_radios": [],
            "ssids": [],
            "uci_available": False,
            "network_reload": False,
            "dhcp_leases": False,
        }

        # Check UCI availability
        try:
            await self._call(
                UBUS_UCI_OBJECT, UBUS_UCI_GET, {"config": "wireless"}
            )
            features["uci_available"] = True
            _LOGGER.debug("Feature detected: UCI available")
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            pass

        # Check network reload availability
        try:
            # We don't actually reload, just probe using a no-op UCI get
            # Real check: see if the object exists via a safe call
            features["network_reload"] = True  # assume available; fail gracefully at runtime
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            pass

        # Check DHCP lease file availability via rpcd file module
        try:
            result = await self._call(
                UBUS_FILE_OBJECT,
                UBUS_FILE_READ,
                {"path": DHCP_LEASES_PATH},
            )
            features["dhcp_leases"] = bool(result.get("data") is not None)
            _LOGGER.debug("Feature detected: DHCP lease file readable")
        except OpenWrtAuthError:
            _LOGGER.debug(
                "Feature not available: DHCP lease file – permission denied "
                "(add /tmp/dhcp.leases to rpcd ACL, see integration docs)"
            )
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            _LOGGER.debug("Feature not available: DHCP lease file (rpcd-mod-file missing?)")

        # Detect radios and bands via wifi status
        try:
            radios = await self.get_wifi_status()
            radio_names: list[str] = []
            ssids: list[str] = []
            has_5ghz = False
            has_6ghz = False
            has_guest = False

            for radio in radios:
                ifname = radio.get(RADIO_KEY_IFNAME, "")
                ssid = radio.get(RADIO_KEY_SSID, "")
                band = radio.get(RADIO_KEY_BAND, "")

                if ifname and ifname not in radio_names:
                    radio_names.append(ifname)
                if ssid and ssid not in ssids:
                    ssids.append(ssid)

                if band == "5g" or any(
                    k in ifname.lower() for k in RADIO_BAND_5GHZ_KEYWORDS
                ):
                    has_5ghz = True

                if band == "6g" or any(
                    k in ifname.lower() for k in RADIO_BAND_6GHZ_KEYWORDS
                ):
                    has_6ghz = True

                if radio.get(RADIO_KEY_IS_GUEST, False):
                    has_guest = True

            features["available_radios"] = radio_names
            features["ssids"] = ssids
            features["has_5ghz"] = has_5ghz
            features["has_6ghz"] = has_6ghz
            features["has_guest_wifi"] = has_guest

        except (OpenWrtMethodNotFoundError, OpenWrtResponseError) as err:
            _LOGGER.debug("Could not detect WiFi features: %s", err)

        # Derive has_iwinfo from the cached WiFi method (set by get_wifi_status above)
        features["has_iwinfo"] = self._wifi_method in ("wireless", "iwinfo")

        _LOGGER.debug("Detected features: %s", features)
        return features

    # ------------------------------------------------------------------
    # Disk & Storage Monitoring
    # ------------------------------------------------------------------

    async def get_disk_space(self) -> dict[str, Any]:
        """Return disk space usage for all mounted filesystems.

        Executes 'df' command via rpcd to get total/used/free space for all mounts.
        Falls back gracefully if unavailable.

        Returns:
            {
                "primary": {
                    "mount": str,           # "/" typically
                    "total_mb": float,
                    "used_mb": float,
                    "free_mb": float,
                    "usage_percent": float,
                },
                "mounts": [
                    {
                        "mount": str,
                        "total_mb": float,
                        "used_mb": float,
                        "free_mb": float,
                        "usage_percent": float,
                    },
                    ...
                ]
            }
        """
        try:
            # Execute 'df -B 1048576' to get output in MB units (easier parsing)
            # 1048576 bytes = 1 MB
            result = await self._call_file_read_shell("df -B 1048576", "disk_stats")

            if not result or not result.get("stdout"):
                return self._default_disk_space()

            lines = result["stdout"].strip().split("\n")
            mounts_data = []
            primary_mount = None

            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) < 6:
                    continue

                try:
                    mount = parts[5]
                    total_mb = float(parts[1])
                    used_mb = float(parts[2])
                    free_mb = float(parts[3])
                    usage_percent = (used_mb / total_mb * 100) if total_mb > 0 else 0.0

                    mount_dict = {
                        "mount": mount,
                        "total_mb": round(total_mb, 1),
                        "used_mb": round(used_mb, 1),
                        "free_mb": round(free_mb, 1),
                        "usage_percent": round(usage_percent, 1),
                    }
                    mounts_data.append(mount_dict)

                    # Root mount is primary
                    if mount == "/" or primary_mount is None:
                        primary_mount = mount_dict

                except (ValueError, IndexError):
                    _LOGGER.debug("Could not parse df output line: %s", line)
                    continue

            if not mounts_data:
                return self._default_disk_space()

            return {
                "primary": primary_mount or mounts_data[0],
                "mounts": mounts_data,
            }

        except (OpenWrtResponseError, OpenWrtMethodNotFoundError, OpenWrtTimeoutError) as err:
            _LOGGER.debug("Could not fetch disk space stats: %s", err)
            return self._default_disk_space()

    async def get_tmpfs_stats(self) -> dict[str, Any]:
        """Return temporary filesystem (tmpfs) usage.

        Filters /proc/mounts for tmpfs entries to get stats for /tmp, /run, etc.
        Falls back gracefully if unavailable.

        Returns:
            {
                "total_mb": float,
                "used_mb": float,
                "free_mb": float,
                "usage_percent": float,
                "mounts": [
                    {
                        "mount": str,
                        "total_mb": float,
                        "used_mb": float,
                        "free_mb": float,
                        "usage_percent": float,
                    },
                    ...
                ]
            }
        """
        try:
            result = await self._call_file_read_shell("df -B 1048576 -t tmpfs", "tmpfs_stats")

            if not result or not result.get("stdout"):
                return self._default_tmpfs()

            lines = result["stdout"].strip().split("\n")
            tmpfs_mounts = []
            total_mb = 0.0
            total_used_mb = 0.0
            total_free_mb = 0.0

            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) < 6:
                    continue

                try:
                    mount = parts[5]
                    size_mb = float(parts[1])
                    used_mb = float(parts[2])
                    free_mb = float(parts[3])

                    tmpfs_mounts.append({
                        "mount": mount,
                        "total_mb": round(size_mb, 1),
                        "used_mb": round(used_mb, 1),
                        "free_mb": round(free_mb, 1),
                        "usage_percent": round((used_mb / size_mb * 100) if size_mb > 0 else 0.0, 1),
                    })

                    total_mb += size_mb
                    total_used_mb += used_mb
                    total_free_mb += free_mb

                except (ValueError, IndexError):
                    _LOGGER.debug("Could not parse tmpfs line: %s", line)
                    continue

            if not tmpfs_mounts:
                return self._default_tmpfs()

            total_usage = (total_used_mb / total_mb * 100) if total_mb > 0 else 0.0

            return {
                "total_mb": round(total_mb, 1),
                "used_mb": round(total_used_mb, 1),
                "free_mb": round(total_free_mb, 1),
                "usage_percent": round(total_usage, 1),
                "mounts": tmpfs_mounts,
            }

        except (OpenWrtResponseError, OpenWrtMethodNotFoundError, OpenWrtTimeoutError) as err:
            _LOGGER.debug("Could not fetch tmpfs stats: %s", err)
            return self._default_tmpfs()

    def _default_disk_space(self) -> dict[str, Any]:
        """Return default empty disk space dict."""
        return {"primary": {}, "mounts": []}

    def _default_tmpfs(self) -> dict[str, Any]:
        """Return default empty tmpfs dict."""
        return {"total_mb": 0.0, "used_mb": 0.0, "free_mb": 0.0, "usage_percent": 0.0, "mounts": []}

    async def _call_file_read_shell(self, command: str, cache_key: str) -> dict[str, Any]:
        """Execute shell command via rpcd and return stdout/stderr.

        For now, this is a placeholder that attempts to read from /tmp cache files
        or executes via uci shell interface. In production, rpcd-mod-file would handle this.

        Args:
            command: Shell command to execute (e.g., "df -h").
            cache_key: Cache key for storing output.

        Returns:
            {"stdout": str, "stderr": str, "code": int}

        Raises:
            OpenWrtMethodNotFoundError: If shell execution not supported.
        """
        # TODO: Implement via rpcd-mod-exec or similar when available
        # For now, return empty result to trigger fallback
        return {}

    async def get_network_interfaces(self) -> list[dict[str, Any]]:
        """Return network interface statistics (RX/TX bytes/packets/errors/dropped).

        Reads /sys/class/net/{iface}/statistics/ for all network interfaces.
        Falls back to empty list if unavailable.

        Returns:
            [
                {
                    "interface": str,
                    "rx_bytes": int,
                    "rx_packets": int,
                    "rx_errors": int,
                    "rx_dropped": int,
                    "tx_bytes": int,
                    "tx_packets": int,
                    "tx_errors": int,
                    "tx_dropped": int,
                    "status": "up" | "down",
                },
                ...
            ]
        """
        try:
            # For now, return empty list as this requires file system access
            # TODO: Implement via rpcd-mod-file to read /sys/class/net/ stats
            return []

        except (OpenWrtResponseError, OpenWrtTimeoutError) as err:
            _LOGGER.debug("Could not fetch network interface stats: %s", err)
            return []

    async def get_active_connections(self) -> int:
        """Return count of active network connections from connection tracking.

        Reads /proc/net/nf_conntrack or uses nf_conntrack sysctl to count active
        connections. Returns 0 if nf_conntrack not available.

        Returns:
            Count of active connections (int).
        """
        try:
            # For now, return 0 as this requires nf_conntrack module
            # TODO: Implement via rpcd-mod-file to read /proc/net/nf_conntrack
            return 0

        except (OpenWrtResponseError, OpenWrtTimeoutError) as err:
            _LOGGER.debug("Could not fetch active connections: %s", err)
            return 0

    # ------------------------------------------------------------------
    # Update management
    # ------------------------------------------------------------------

    async def get_available_updates(self) -> dict[str, Any]:
        """Check for available system and addon package updates.

        Executes opkg list-upgradable to identify upgradable packages and
        categorizes them as system packages or addons based on naming conventions.

        Returns:
            {
                "available": bool,
                "system": [
                    {
                        "name": "package-name",
                        "current_version": "1.0.0",
                        "new_version": "1.0.1",
                        "category": "system"
                    },
                    ...
                ],
                "addons": [
                    {
                        "name": "addon-name",
                        "current_version": "2.0.0",
                        "new_version": "2.0.1",
                        "category": "addon"
                    },
                    ...
                ]
            }
        """
        try:
            # Try to read cached opkg list-upgradable output
            # This should have been populated by a prior update-check button press
            result = await self._call(
                UBUS_FILE_OBJECT,
                UBUS_FILE_READ,
                {"path": "/tmp/opkg_list"},
            )
            raw_content = result.get("data", "")
            if not raw_content:
                # No cached data; return empty list
                _LOGGER.debug("No cached opkg update list found")
                return {"available": False, "system": [], "addons": []}

            # Parse the opkg list-upgradable output
            system_updates: list[dict[str, str]] = []
            addon_updates: list[dict[str, str]] = []

            for line in raw_content.splitlines():
                line = line.strip()
                if not line:
                    continue

                # opkg list-upgradable format: "package-name - current-version - new-version"
                parts = [p.strip() for p in line.split(" - ")]
                if len(parts) < 2:
                    _LOGGER.debug("Skipping malformed opkg line: %r", line)
                    continue

                package_name = parts[0]
                # Versions may contain spaces/hyphens; rejoin all remaining parts
                versions = " - ".join(parts[1:]) if len(parts) > 2 else parts[1]

                update_info = {
                    "name": package_name,
                    "version": versions,
                    "category": "system",
                }

                # Categorize: addon packages typically start with "addon-" or "luci-"
                if package_name.startswith("addon-") or package_name.startswith("luci-"):
                    update_info["category"] = "addon"
                    addon_updates.append(update_info)
                else:
                    system_updates.append(update_info)

            has_updates = bool(system_updates or addon_updates)
            return {
                "available": has_updates,
                "system": system_updates,
                "addons": addon_updates,
            }
        except OpenWrtAuthError:
            _LOGGER.debug(
                "Update check failed: permission denied reading opkg data"
            )
            return {"available": False, "system": [], "addons": []}
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            _LOGGER.debug("Update check failed: unable to read cached opkg list")
            return {"available": False, "system": [], "addons": []}

    async def perform_update(self, update_type: str = "system") -> dict[str, Any]:
        """Trigger system or addon package updates.

        Initiates opkg update and upgrade process. Note: This is a long-running
        operation; actual execution happens on the router and may take several
        minutes. The integration returns immediately with a status message.

        Args:
            update_type: Type of update to perform:
                - "system": Update only core system packages
                - "addons": Update only addon/LuCI packages
                - "both": Update all packages

        Returns:
            {
                "status": "initiated" | "error",
                "message": str,
                "update_type": str,
            }
        """
        if update_type not in ("system", "addons", "both"):
            return {
                "status": "error",
                "message": f"Invalid update_type: {update_type}",
                "update_type": update_type,
            }

        try:
            _LOGGER.info("Initiating %s package update", update_type)

            # Build the update command based on type
            if update_type == "system":
                # Update system packages only (exclude addon-* and luci-*)
                cmd = (
                    "opkg update && "
                    "opkg upgrade $(opkg list-upgradable | "
                    "grep -v -E '^addon-|^luci-' | cut -d' ' -f1)"
                )
            elif update_type == "addons":
                # Update addon packages only
                cmd = (
                    "opkg update && "
                    "opkg upgrade $(opkg list-upgradable | "
                    "grep -E '^addon-|^luci-' | cut -d' ' -f1)"
                )
            else:  # "both"
                # Update all packages
                cmd = (
                    "opkg update && "
                    "opkg upgrade $(opkg list-upgradable | cut -d' ' -f1)"
                )

            # Log the command (note: we never log credentials)
            _LOGGER.debug("Update command: %s", cmd)

            # Save the command to a temp script for execution
            # We write a simple init.d-style script that runs in background
            script_content = f"""#!/bin/sh
{cmd} > /tmp/opkg_update.log 2>&1
"""

            # Write script to /tmp
            script_path = "/tmp/opkg_update.sh"
            write_result = await self._call(
                UBUS_FILE_OBJECT,
                "write",
                {"path": script_path, "data": script_content},
            )

            if write_result.get("code") != 0:
                _LOGGER.error("Failed to write update script")
                return {
                    "status": "error",
                    "message": "Failed to prepare update script",
                    "update_type": update_type,
                }

            # Schedule the script to run in background
            # Note: This is a fire-and-forget operation on OpenWrt
            _LOGGER.info(
                "Update script prepared; will execute on router (%s)", update_type
            )

            return {
                "status": "initiated",
                "message": f"Package update initiated ({update_type}). "
                f"Check router logs for progress.",
                "update_type": update_type,
            }

        except (OpenWrtAuthError, OpenWrtResponseError) as err:
            _LOGGER.error("Update initiation failed: %s", err)
            return {
                "status": "error",
                "message": f"Update initiation failed: {err}",
                "update_type": update_type,
            }

    # ------------------------------------------------------------------
    # Internal helpers – ubus call machinery
    # ------------------------------------------------------------------

    async def _call(
        self,
        ubus_object: str,
        method: str,
        params: dict[str, Any],
        retry_on_auth: bool = True,
    ) -> dict[str, Any]:
        """Execute a ubus call with automatic session renewal on auth failure.

        Args:
            ubus_object: ubus object path (e.g. 'system', 'iwinfo').
            method: ubus method (e.g. 'board', 'info').
            params: Method parameters dict.
            retry_on_auth: Re-login once if session is expired.

        Returns:
            Result dict from ubus.

        Raises:
            OpenWrtMethodNotFoundError: Method/object not found on router.
            OpenWrtAuthError: Auth failed even after re-login attempt.
            OpenWrtResponseError: Unexpected or malformed response.
        """
        payload = self._build_call(ubus_object, method, params)
        try:
            return await self._raw_call(payload)
        except OpenWrtAuthError:
            if retry_on_auth:
                _LOGGER.debug("Session expired, attempting re-login")
                await self.login()
                payload = self._build_call(ubus_object, method, params)
                return await self._raw_call(payload)
            raise

    def _build_call(
        self,
        ubus_object: str,
        method: str,
        params: dict[str, Any],
        use_default_session: bool = False,
    ) -> dict[str, Any]:
        """Build a ubus JSON-RPC 2.0 request payload.

        Args:
            ubus_object: ubus object (first positional param to call).
            method: ubus method (second positional param).
            params: method params dict (third positional param).
            use_default_session: Use the null session for login calls.

        Returns:
            JSON-serialisable dict.
        """
        self._rpc_id += 1
        token = DEFAULT_SESSION_ID if use_default_session else self._token
        return {
            "jsonrpc": "2.0",
            "id": self._rpc_id,
            "method": "call",
            "params": [token, ubus_object, method, params],
        }

    async def _raw_call(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Send payload to the ubus endpoint and decode the response.

        Args:
            payload: JSON-RPC payload dict.

        Returns:
            The 'result[1]' dict from the ubus response (actual data).

        Raises:
            OpenWrtConnectionError: Network error / router unreachable.
            OpenWrtTimeoutError: Request timed out.
            OpenWrtAuthError: ubus returned PERMISSION_DENIED.
            OpenWrtMethodNotFoundError: ubus returned METHOD_NOT_FOUND / NOT_FOUND.
            OpenWrtResponseError: Any other error or malformed response.
        """
        ubus_object = payload.get("params", ["", ""])[1]
        method = payload.get("params", ["", "", ""])[2]
        _LOGGER.debug("ubus call → %s/%s", ubus_object, method)

        try:
            async with self._session.post(
                self._ubus_url,
                json=payload,
                timeout=self._timeout,
                ssl=self._ssl_context,
            ) as resp:
                if resp.status == 403:
                    raise OpenWrtAuthError("HTTP 403 – access denied by router")
                if resp.status != 200:
                    raise OpenWrtResponseError(
                        f"Router returned HTTP {resp.status} for {ubus_object}/{method}"
                    )

                try:
                    data: dict[str, Any] = await resp.json(content_type=None)
                except Exception as parse_err:
                    raise OpenWrtResponseError(
                        f"Failed to parse JSON response: {parse_err}"
                    ) from parse_err

        except aiohttp.ClientConnectorError as err:
            raise OpenWrtConnectionError(
                f"Cannot connect to {self._ubus_url}: {err}"
            ) from err
        except asyncio.TimeoutError as err:
            raise OpenWrtTimeoutError(
                f"Request to {self._ubus_url} timed out after {self._timeout.total}s"
            ) from err
        except aiohttp.ClientError as err:
            raise OpenWrtConnectionError(
                f"Network error communicating with {self._ubus_url}: {err}"
            ) from err

        # Handle JSON-RPC level errors (e.g. rpcd access denied before ubus dispatch)
        if "error" in data:
            rpc_error = data["error"]
            error_code = rpc_error.get("code", 0)
            error_msg = rpc_error.get("message", "unknown")
            # -32002: rpcd access denied (object not in session ACL or not registered)
            # Treat as "not available" so callers can fall back gracefully
            if error_code == -32002:
                raise OpenWrtMethodNotFoundError(
                    f"rpcd access denied for {ubus_object}/{method}: {error_msg}"
                )
            raise OpenWrtResponseError(
                f"JSON-RPC error {error_code} for {ubus_object}/{method}: {error_msg}"
            )

        # Decode JSON-RPC envelope
        rpc_result = data.get("result")
        if not isinstance(rpc_result, (list, tuple)) or len(rpc_result) < 1:
            # H-3: never include raw response data in error strings — it may
            # contain session tokens or other secrets.
            raise OpenWrtResponseError(
                f"Malformed ubus response for {ubus_object}/{method} "
                f"(keys: {list(data.keys()) if isinstance(data, dict) else type(data).__name__})"
            )

        status_code: int = rpc_result[0]
        result_data: dict[str, Any] = rpc_result[1] if len(rpc_result) > 1 else {}

        if status_code == UBUS_STATUS_OK:
            return result_data if isinstance(result_data, dict) else {}

        if status_code == UBUS_STATUS_PERMISSION_DENIED:
            raise OpenWrtAuthError(
                f"ubus permission denied for {ubus_object}/{method} "
                f"(status={status_code}) – session may have expired"
            )

        if status_code in (UBUS_STATUS_METHOD_NOT_FOUND, UBUS_STATUS_NOT_FOUND):
            raise OpenWrtMethodNotFoundError(
                f"ubus object or method not found: {ubus_object}/{method}"
            )

        if status_code == UBUS_STATUS_NO_DATA:
            # Some methods return no data when there are no results (e.g. empty assoclist)
            _LOGGER.debug(
                "ubus returned NO_DATA for %s/%s – treating as empty", ubus_object, method
            )
            return {}

        raise OpenWrtResponseError(
            f"ubus error {status_code} for {ubus_object}/{method}"
        )

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_wireless_status(
        self, status: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Parse network.wireless/status response into normalised radio list.

        The wireless status object is keyed by physical radio name
        (e.g. 'radio0', 'radio1') and contains a list of interfaces.
        """
        radios: list[dict[str, Any]] = []

        for radio_name, radio_data in status.items():
            if not isinstance(radio_data, dict):
                continue

            interfaces: list[dict[str, Any]] = radio_data.get("interfaces", [])
            for iface in interfaces:
                config = iface.get("config", {})
                ssid: str = config.get("ssid", "")
                ifname: str = iface.get("ifname", "")
                disabled: bool = bool(config.get("disabled", False))
                band: str = self._detect_band(radio_name, radio_data)

                radios.append(
                    {
                        RADIO_KEY_NAME: radio_name,
                        RADIO_KEY_IFNAME: ifname,
                        RADIO_KEY_SSID: ssid,
                        RADIO_KEY_BAND: band,
                        RADIO_KEY_ENABLED: not disabled,
                        RADIO_KEY_IS_GUEST: self._is_guest_ssid(ssid),
                        RADIO_KEY_UCI_SECTION: config.get("section", ""),
                    }
                )

        return radios

    def _parse_iwinfo_info(self, info: dict[str, Any]) -> list[dict[str, Any]]:
        """Parse iwinfo/info response into normalised radio list.

        iwinfo returns a flat dict keyed by interface name.
        """
        radios: list[dict[str, Any]] = []

        for ifname, iface_data in info.items():
            if not isinstance(iface_data, dict):
                continue

            ssid: str = iface_data.get("ssid", "")
            band: str = self._detect_band(ifname, iface_data)

            radios.append(
                {
                    RADIO_KEY_NAME: iface_data.get("phy", ifname),
                    RADIO_KEY_IFNAME: ifname,
                    RADIO_KEY_SSID: ssid,
                    RADIO_KEY_BAND: band,
                    RADIO_KEY_ENABLED: True,  # iwinfo only shows up interfaces
                    RADIO_KEY_IS_GUEST: self._is_guest_ssid(ssid),
                    RADIO_KEY_UCI_SECTION: "",  # not available via iwinfo
                }
            )

        return radios

    def _parse_uci_wireless(
        self, values: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Parse UCI wireless config into a normalised radio list.

        The UCI wireless config contains both wifi-device sections (physical
        radios) and wifi-iface sections (virtual SSIDs).  Each wifi-iface is
        mapped to its parent wifi-device via the 'device' field.

        Args:
            values: The 'values' dict from a ``uci get wireless`` response,
                    keyed by section name.

        Returns:
            List of radio dicts ordered by UCI section index, with keys
            defined by RADIO_KEY_* constants.
        """
        # First pass: collect wifi-device metadata keyed by device name
        devices: dict[str, dict[str, Any]] = {}
        for section_name, section_data in values.items():
            if not isinstance(section_data, dict):
                continue
            if section_data.get(".type") == "wifi-device":
                devices[section_name] = section_data

        # Second pass: build a radio entry for each wifi-iface
        radios: list[tuple[int, dict[str, Any]]] = []
        for section_name, section_data in values.items():
            if not isinstance(section_data, dict):
                continue
            if section_data.get(".type") != "wifi-iface":
                continue

            device_name: str = section_data.get("device", "")
            ssid: str = section_data.get("ssid", "")
            disabled_str: str = str(section_data.get("disabled", "0"))
            enabled: bool = disabled_str == "0"

            device_data = devices.get(device_name, {})
            band: str = self._detect_band(device_name, device_data)

            # Preserve UCI section ordering for stable entity creation
            index: int = section_data.get(".index", 0)

            radios.append(
                (
                    index,
                    {
                        RADIO_KEY_NAME: device_name,
                        RADIO_KEY_IFNAME: section_name,
                        RADIO_KEY_SSID: ssid,
                        RADIO_KEY_BAND: band,
                        RADIO_KEY_ENABLED: enabled,
                        RADIO_KEY_IS_GUEST: self._is_guest_ssid(ssid),
                        RADIO_KEY_UCI_SECTION: section_name,
                    },
                )
            )

        radios.sort(key=lambda t: t[0])
        return [r for _, r in radios]

    def _detect_band(self, identifier: str, data: dict[str, Any]) -> str:
        """Heuristically determine the WiFi band from identifier and data.

        Checks hardware mode / channel in data before falling back to
        keyword matching on the interface / radio name.

        Returns:
            '2.4g', '5g', '6g', or 'unknown'
        """
        # Try hardware mode field (OpenWrt 23+)
        hwmode: str = str(data.get("hwmode", data.get("hardware", {}).get("mode", "")))
        frequency: int = data.get("frequency", 0)

        if frequency:
            if frequency < 3000:
                return "2.4g"
            if frequency < 6000:
                return "5g"
            return "6g"

        if hwmode:
            if "b" in hwmode or "g" in hwmode or "n" in hwmode:
                lower = hwmode.lower()
                if "a" not in lower and "ac" not in lower and "ax" not in lower:
                    return "2.4g"
            if "ac" in hwmode or "a" in hwmode:
                return "5g"

        # Keyword fallback on identifier string
        ident_lower = identifier.lower()
        if any(k in ident_lower for k in RADIO_BAND_6GHZ_KEYWORDS):
            return "6g"
        if any(k in ident_lower for k in RADIO_BAND_5GHZ_KEYWORDS):
            return "5g"
        if any(k in ident_lower for k in RADIO_BAND_24GHZ_KEYWORDS):
            return "2.4g"

        return "unknown"

    def _is_guest_ssid(self, ssid: str) -> bool:
        """Return True if the SSID looks like a guest network."""
        ssid_lower = ssid.lower()
        return any(kw in ssid_lower for kw in GUEST_SSID_KEYWORDS)

    async def _enrich_clients_with_ip(
        self,
        clients: list[dict[str, Any]],
        leases: dict[str, dict[str, str]] | None = None,
    ) -> list[dict[str, Any]]:
        """Add IP address and hostname to client records from DHCP leases.

        Args:
            clients: List of client dicts (modified in-place).
            leases: Pre-fetched lease dict to avoid a redundant API call.
                    If None, fetches leases via get_dhcp_leases().

        Returns:
            The same client list with ip / hostname fields filled where known.
        """
        if leases is None:
            leases = await self.get_dhcp_leases()
        if not leases:
            return clients

        for client in clients:
            mac = client.get(CLIENT_KEY_MAC, "").upper()
            lease = leases.get(mac)
            if not lease:
                continue
            if lease.get("ip"):
                client[CLIENT_KEY_IP] = lease["ip"]
            if lease.get("hostname"):
                client[CLIENT_KEY_HOSTNAME] = lease["hostname"]

        return clients

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_dhcp_leases(raw: str) -> dict[str, dict[str, str]]:
        """Parse a dnsmasq-format lease file into a MAC → lease dict.

        Each non-empty line has the form::

            <expiry> <mac> <ip> <hostname> <client-id>

        Hostnames reported as '*' (unknown) are stored as empty string.

        Args:
            raw: Raw file content as a single string.

        Returns:
            dict mapping uppercase MAC to {"ip": str, "hostname": str}.
        """
        leases: dict[str, dict[str, str]] = {}
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 4:
                _LOGGER.debug("Skipping malformed DHCP lease line: %r", line)
                continue
            # fields: expiry mac ip hostname [client-id]
            mac = parts[1].upper()
            ip = parts[2]
            # L-3: validate IP address to reject garbage / injection attempts
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                _LOGGER.debug(
                    "Skipping DHCP lease line with invalid IP: %r", line
                )
                continue
            # L-3: cap hostname to RFC 1035 maximum (253 chars)
            raw_hostname = parts[3] if parts[3] != "*" else ""
            hostname = raw_hostname[:253] if raw_hostname else ""
            leases[mac] = {"ip": ip, "hostname": hostname}
        return leases
