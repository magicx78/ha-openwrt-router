"""OpenWrt ubus / rpcd JSON-RPC API client."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import ssl
import time
from typing import Any

import aiohttp

from .const import (
    CLIENT_KEY_CONNECTED_SINCE,
    CLIENT_KEY_DHCP_EXPIRES,
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
    PROTOCOL_HTTPS_INSECURE,
    DHCP_LEASES_PATH,
    GUEST_SSID_KEYWORDS,
    RADIO_BAND_24GHZ_KEYWORDS,
    RADIO_BAND_5GHZ_KEYWORDS,
    RADIO_BAND_6GHZ_KEYWORDS,
    RADIO_KEY_BAND,
    RADIO_KEY_BITRATE,
    RADIO_KEY_BSSID,
    RADIO_KEY_CHANNEL,
    RADIO_KEY_ENABLED,
    RADIO_KEY_FREQUENCY,
    RADIO_KEY_HTMODE,
    RADIO_KEY_HWMODE,
    RADIO_KEY_IFNAME,
    RADIO_KEY_IS_GUEST,
    RADIO_KEY_MODE,
    RADIO_KEY_NAME,
    RADIO_KEY_SSID,
    RADIO_KEY_TXPOWER,
    RADIO_KEY_UCI_SECTION,
    UBUS_FILE_OBJECT,
    UBUS_FILE_READ,
    UBUS_IWINFO_ASSOCLIST,
    UBUS_IWINFO_INFO,
    UBUS_IWINFO_OBJECT,
    UBUS_DEVICE_OBJECT,
    UBUS_DEVICE_STATUS,
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


class OpenWrtRpcdSetupError(OpenWrtAuthError):
    """Raised when rpcd is not properly configured on the router.

    This is a subclass of OpenWrtAuthError so existing callers that catch
    the broader exception still work.  config_flow catches this specifically
    to show a more helpful error message with setup instructions.
    """


class OpenWrtConnectionError(Exception):
    """Raised when the router cannot be reached."""


class OpenWrtTimeoutError(Exception):
    """Raised when a request times out."""


class OpenWrtMethodNotFoundError(Exception):
    """Raised when a ubus method is not available on the router."""


class OpenWrtResponseError(Exception):
    """Raised when the router returns an unexpected response."""


def _parse_uci_config(raw: str) -> dict[str, dict[str, Any]]:
    """Parse an OpenWrt UCI config file into a dict of sections.

    Only returns sections of type 'service' (the interesting ones for DDNS).
    Each key is the section name; the value is a dict of option → value.

    UCI format example::

        config service 'duckdns'
            option enabled '1'
            option service_name 'duckdns.org'
            option lookup_host 'myhome.duckdns.org'
    """
    import re as _re

    sections: dict[str, dict[str, Any]] = {}
    current_name: str | None = None
    current_type: str | None = None
    current_data: dict[str, Any] = {}

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # config <type> '<name>'  OR  config <type>
        m = _re.match(r"^config\s+(\S+)(?:\s+'([^']*)')?", line)
        if m:
            # Save previous section
            if current_name and current_type == "service":
                sections[current_name] = current_data
            current_type = m.group(1)
            current_name = m.group(2) or current_type
            current_data = {".type": current_type}
            continue

        # option <key> '<value>'
        m = _re.match(r"^option\s+(\S+)\s+'([^']*)'", line)
        if m and current_name:
            current_data[m.group(1)] = m.group(2)
            continue

        # list <key> '<value>'  (multi-value, rare in ddns)
        m = _re.match(r"^list\s+(\S+)\s+'([^']*)'", line)
        if m and current_name:
            key = m.group(1)
            current_data.setdefault(key, [])
            if isinstance(current_data[key], list):
                current_data[key].append(m.group(2))

    # Flush last section
    if current_name and current_type == "service":
        sections[current_name] = current_data

    return sections


def _parse_port_speed(raw: Any) -> tuple[int | None, str | None]:
    """Parse OpenWrt port speed string into (Mbps, duplex).

    OpenWrt network.device/status returns speed as a string like "100F",
    "1000H", "2500F" (number + F/H for Full/Half duplex) or sometimes as
    an integer (-1 for no link).

    Returns:
        (speed_mbps, duplex) where speed_mbps is None for unknown/no-link,
        and duplex is "full", "half", or None.
    """
    if raw is None:
        return None, None
    if isinstance(raw, str) and raw:
        duplex_char = raw[-1].upper()
        duplex = "full" if duplex_char == "F" else ("half" if duplex_char == "H" else None)
        num_part = raw.rstrip("FfHh")
        try:
            mbps = int(num_part)
            return (mbps if mbps > 0 else None), duplex
        except ValueError:
            return None, None
    try:
        mbps = int(raw)
        return (mbps if mbps > 0 else None), None
    except (TypeError, ValueError):
        return None, None


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

        # Cached hostapd interface names (e.g. ["phy0-ap0"]).
        # Populated on first get_connected_clients() call via discovery.
        # None = not yet discovered; [] = no interfaces found.
        self._hostapd_ifaces: list[str] | None = None

        # True when rpcd ACL blocks hostapd.*/get_clients — SSH fallback is used instead.
        self._hostapd_acl_blocked: bool = False

        # Cached ifname→ssid map from luci-rpc/getWirelessDevices (populated once when
        # hostapd.*/get_status is also ACL-blocked; None = not yet fetched).
        self._luci_rpc_ssid_map: dict[str, str] | None = None

        # L-1: track consecutive login failures to suppress log spam
        self._login_failure_count: int = 0

        # P-6: track consecutive auth failures for backoff (wrong credentials)
        # After MAX_AUTH_FAILURES consecutive failures, stop retrying until reset.
        self._auth_failure_count: int = 0
        self._auth_backoff_until: float = 0.0

        # M-4: warn once when using the root account
        self._root_warning_logged: bool = False

        # Track DDNS availability — None=unknown, False=not available (skip future polls)
        self._ddns_available: bool | None = None

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
            {
                "username": self._username,
                "password": self._password,
                "timeout": 86400,  # 24h — prevents frequent re-logins on devices with short default TTL
            },
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
        # Try to login; if it fails due to ACL, continue with default session.
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
            system info (ubus) or /root/ha-system-metrics.sh (SSH fallback)

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
            If ubus is blocked (ACL-restricted router), falls back to SSH script.
        """
        try:
            result = await self._call(UBUS_SYSTEM_OBJECT, UBUS_SYSTEM_INFO, {})
        except (OpenWrtMethodNotFoundError, OpenWrtAuthError, OpenWrtResponseError) as err:
            # Access denied – try SSH fallback
            err_str = str(err).lower()
            if "access denied" in err_str or "permission" in err_str:
                _LOGGER.warning(
                    "Cannot access system/info via ubus (rpcd ACL restricted), "
                    "attempting SSH fallback"
                )
                try:
                    return await self._get_router_status_ssh()
                except Exception as ssh_err:
                    _LOGGER.warning(
                        "SSH fallback also failed, returning empty metrics: %s", ssh_err
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
        Falls back to SSH script if ubus is blocked (ACL-restricted router).

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
        try:
            result = await self._call(UBUS_NETWORK_OBJECT, UBUS_NETWORK_DUMP, {})
        except (OpenWrtMethodNotFoundError, OpenWrtAuthError, OpenWrtResponseError) as err:
            # ubus blocked – try SSH fallback
            err_str = str(err).lower()
            if "access denied" in err_str or "permission" in err_str:
                _LOGGER.warning(
                    "Cannot access network dump via ubus (rpcd ACL restricted), "
                    "attempting SSH fallback for WAN status"
                )
                try:
                    return await self._get_wan_status_ssh()
                except Exception as ssh_err:
                    _LOGGER.warning(
                        "SSH fallback also failed, returning minimal WAN status: %s",
                        ssh_err,
                    )
                    return {
                        "connected": False,
                        "interface": "",
                        "ipv4": "",
                        "uptime": 0,
                        "rx_bytes": None,
                        "tx_bytes": None,
                    }
            raise
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
        ipv4_entry = ipv4_list[0] if ipv4_list else {}
        ipv4 = ipv4_entry.get("address", "") if isinstance(ipv4_entry, dict) else ""
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

        # SSH Fallback: try to get WiFi status via SSH script
        try:
            _LOGGER.debug("Attempting WiFi status via SSH fallback")
            result = await self._get_wifi_status_ssh()
            if result:
                self._wifi_method = "ssh"
                _LOGGER.debug("WiFi method: SSH fallback")
                return result
        except Exception as e:
            _LOGGER.debug("SSH WiFi fallback failed: %s", e)

        self._wifi_method = "none"
        _LOGGER.debug(
            "No WiFi API available on this router (tried wireless, iwinfo, UCI, SSH)"
        )
        return []

    async def get_ap_interface_details(self) -> list[dict[str, Any]]:
        """Return per-interface AP details.

        Primary path: iwinfo/info per-device (routers with iwinfo via rpcd).
        Fallback: UCI wireless config (routers without iwinfo, e.g. Cudy WR3000).

        Called after get_connected_clients() so that self._hostapd_ifaces is
        already populated.  Each entry mirrors the RADIO_KEY_* schema so that
        OpenWrtAPInterfaceSensor can read from coordinator.data.ap_interfaces.

        Returns:
            List of dicts, one per discovered AP interface.
        """
        result: list[dict[str, Any]] = []

        # Primary path: iwinfo per-device (requires hostapd iface discovery)
        ifnames: list[str] = self._hostapd_ifaces or []
        for ifname in ifnames:
            try:
                info = await self._call(
                    UBUS_IWINFO_OBJECT, UBUS_IWINFO_INFO, {"device": ifname}
                )
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                _LOGGER.debug("iwinfo/info unavailable for %s", ifname)
                continue

            band = self._detect_band(ifname, info)
            ssid: str = info.get("ssid", "")
            result.append(
                {
                    RADIO_KEY_IFNAME: ifname,
                    RADIO_KEY_SSID: ssid,
                    RADIO_KEY_BAND: band,
                    RADIO_KEY_IS_GUEST: self._is_guest_ssid(ssid),
                    RADIO_KEY_MODE: info.get("mode"),
                    RADIO_KEY_BSSID: info.get("bssid"),
                    RADIO_KEY_CHANNEL: info.get("channel"),
                    RADIO_KEY_FREQUENCY: info.get("frequency"),
                    RADIO_KEY_TXPOWER: info.get("txpower"),
                    RADIO_KEY_BITRATE: info.get("bitrate"),
                    RADIO_KEY_HWMODE: info.get("hwmode"),
                    RADIO_KEY_HTMODE: info.get("htmode"),
                    "signal": info.get("signal"),
                    "noise": info.get("noise"),
                    "quality": info.get("quality"),
                    "quality_max": info.get("quality_max"),
                }
            )
            _LOGGER.debug(
                "AP interface %s: mode=%s ch=%s freq=%s hwmode=%s htmode=%s",
                ifname, info.get("mode"), info.get("channel"),
                info.get("frequency"), info.get("hwmode"), info.get("htmode"),
            )

        if result:
            return result

        # Fallback: UCI wireless config for routers without iwinfo via rpcd.
        # Uses UCI section name (e.g. "default_radio0") as stable RADIO_KEY_IFNAME.
        if self._wifi_method == "uci":
            try:
                values = await self.get_uci_wireless()
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                _LOGGER.debug("UCI wireless config unavailable for AP interface details")
                return []

            devices: dict[str, dict[str, Any]] = {}
            ifaces: list[tuple[int, str, dict[str, Any]]] = []
            for section_name, section_data in values.items():
                if not isinstance(section_data, dict):
                    continue
                if section_data.get(".type") == "wifi-device":
                    devices[section_name] = section_data
                elif section_data.get(".type") == "wifi-iface":
                    ifaces.append(
                        (section_data.get(".index", 0), section_name, section_data)
                    )

            for _index, section_name, section_data in sorted(ifaces, key=lambda t: t[0]):
                device_name: str = section_data.get("device", "")
                device_data = devices.get(device_name, {})
                ssid_uci: str = section_data.get("ssid", "")
                mode_uci: str = section_data.get("mode", "ap")
                channel_str = device_data.get("channel")
                channel_val: int | None = (
                    int(channel_str)
                    if channel_str and str(channel_str).isdigit()
                    else None
                )
                band_uci = self._detect_band(device_name, device_data)
                result.append(
                    {
                        RADIO_KEY_IFNAME: section_name,
                        RADIO_KEY_SSID: ssid_uci,
                        RADIO_KEY_BAND: band_uci,
                        RADIO_KEY_IS_GUEST: self._is_guest_ssid(ssid_uci),
                        RADIO_KEY_MODE: mode_uci,
                        RADIO_KEY_BSSID: None,
                        RADIO_KEY_CHANNEL: channel_val,
                        RADIO_KEY_FREQUENCY: None,
                        RADIO_KEY_TXPOWER: None,
                        RADIO_KEY_BITRATE: None,
                        RADIO_KEY_HWMODE: device_data.get("hwmode") or device_data.get("type"),
                        RADIO_KEY_HTMODE: device_data.get("htmode"),
                        "signal": None,
                        "noise": None,
                        "quality": None,
                        "quality_max": None,
                    }
                )
                _LOGGER.debug(
                    "AP UCI interface %s: mode=%s ch=%s htmode=%s band=%s",
                    section_name, mode_uci, channel_val,
                    device_data.get("htmode"), band_uci,
                )

        return result

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

        # Build SSID lookup: ifname → ssid (from radio descriptors)
        ifname_to_ssid: dict[str, str] = {
            r.get(RADIO_KEY_IFNAME, ""): r.get(RADIO_KEY_SSID, "")
            for r in radios
            if r.get(RADIO_KEY_IFNAME)
        }

        # Discover hostapd interfaces — try methods in order of reliability.
        # Results are cached in self._hostapd_ifaces after first successful discovery.
        hostapd_ifnames: list[str] = []

        if self._hostapd_ifaces is not None:
            # Use cached result from previous poll
            hostapd_ifnames = self._hostapd_ifaces
        else:
            # Method 1: iwinfo/devices (OpenWrt 21+/25) — physical ifnames like phy0-ap0
            try:
                devices_result = await self._call(UBUS_IWINFO_OBJECT, "devices", {})
                hostapd_ifnames = devices_result.get("devices", [])
                if hostapd_ifnames:
                    _LOGGER.debug("iwinfo/devices: %s", hostapd_ifnames)
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                _LOGGER.debug("iwinfo/devices not available")

            # Method 2: probe known naming patterns (OpenWrt 23+/25 uses phy<N>-ap<M>)
            # Only runs once — result cached immediately after.
            if not hostapd_ifnames:
                probe_candidates = [
                    f"phy{phy}-ap{ap}" for phy in range(4) for ap in range(4)
                ] + [f"wlan{n}" for n in range(4)]
                found: list[str] = []
                acl_blocked_candidates: list[str] = []
                for candidate in probe_candidates:
                    try:
                        await self._call(f"hostapd.{candidate}", "get_clients", {})
                        found.append(candidate)
                        # Get SSID while we're here
                        try:
                            status = await self._call(f"hostapd.{candidate}", "get_status", {})
                            ssid = status.get("ssid", "")
                            if ssid:
                                ifname_to_ssid[candidate] = ssid
                        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                            pass
                    except (OpenWrtMethodNotFoundError, OpenWrtResponseError) as probe_err:
                        # Distinguish ACL-blocked (object exists) from not-found
                        if "access denied" in str(probe_err).lower():
                            acl_blocked_candidates.append(candidate)
                if found:
                    hostapd_ifnames = found
                    _LOGGER.debug("Discovered hostapd interfaces via probing: %s", found)
                elif acl_blocked_candidates:
                    # rpcd ACL blocks get_clients — interface names are still valid,
                    # use SSH to fetch client data each poll.
                    hostapd_ifnames = acl_blocked_candidates
                    self._hostapd_acl_blocked = True
                    _LOGGER.warning(
                        "hostapd.*/get_clients blocked by rpcd ACL — using SSH fallback "
                        "for client counting. Interfaces: %s. "
                        "Fix: add get_clients/get_status to /usr/share/rpcd/acl.d/",
                        acl_blocked_candidates,
                    )

            # Method 3: UCI radio ifnames (last resort, may be wrong on OpenWrt 25)
            if not hostapd_ifnames:
                hostapd_ifnames = [k for k in ifname_to_ssid if k]
                if hostapd_ifnames:
                    _LOGGER.debug(
                        "Using UCI radio ifnames as hostapd candidates: %s", hostapd_ifnames
                    )

            # Cache the result (even if empty) to avoid re-probing every poll
            self._hostapd_ifaces = hostapd_ifnames

        # Build ifname→ssid map for any hostapd interfaces not yet known
        # Try hostapd.*/get_status first (works even without iwinfo ACL), then iwinfo/info
        for ifname in hostapd_ifnames:
            if ifname in ifname_to_ssid:
                continue
            # Try hostapd get_status (reliable on OpenWrt 25)
            try:
                status = await self._call(f"hostapd.{ifname}", "get_status", {})
                ifname_to_ssid[ifname] = status.get("ssid", "")
                continue
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                pass
            # Fallback: iwinfo/info
            try:
                info = await self._call(UBUS_IWINFO_OBJECT, UBUS_IWINFO_INFO, {"device": ifname})
                ifname_to_ssid[ifname] = info.get("ssid", "")
                continue
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                pass
            # Last fallback: luci-rpc/getWirelessDevices (builds ifname→ssid cache once)
            ssid_from_luci = await self._get_ssid_from_luci_rpc(ifname)
            ifname_to_ssid[ifname] = ssid_from_luci

        # When rpcd ACL blocks hostapd.*/get_clients, use SSH to query ubus directly.
        if self._hostapd_acl_blocked and hostapd_ifnames:
            try:
                ssh_clients = await self._get_clients_via_ssh(hostapd_ifnames, ifname_to_ssid, leases)
                if ssh_clients is not None:
                    return ssh_clients
            except Exception as ssh_err:
                _LOGGER.debug("SSH client fallback failed: %s", ssh_err)

        # Primary: hostapd.*/get_clients — returns {clients: {mac: {signal, ...}}}
        # Preferred in OpenWrt 21+/25; more reliable than iwinfo/assoclist
        seen_macs: set[str] = set()
        for ifname in hostapd_ifnames:
            ssid = ifname_to_ssid.get(ifname, "")
            try:
                result = await self._call(f"hostapd.{ifname}", "get_clients", {})
                hostapd_clients: dict[str, Any] = result.get("clients", {})
                for mac_raw, sta_data in hostapd_clients.items():
                    mac = mac_raw.upper()
                    if mac in seen_macs:
                        continue
                    seen_macs.add(mac)
                    sta = sta_data if isinstance(sta_data, dict) else {}
                    signal = sta.get("signal", 0)
                    connected_time = sta.get("connected_time", 0) or 0
                    clients.append(
                        {
                            CLIENT_KEY_MAC: mac,
                            CLIENT_KEY_IP: "",
                            CLIENT_KEY_HOSTNAME: "",
                            CLIENT_KEY_SIGNAL: signal,
                            CLIENT_KEY_SSID: ssid,
                            CLIENT_KEY_RADIO: ifname,
                            CLIENT_KEY_CONNECTED_SINCE: connected_time,
                            "rx_bytes": sta.get("rx_bytes"),
                            "tx_bytes": sta.get("tx_bytes"),
                        }
                    )
                _LOGGER.debug(
                    "hostapd.%s/get_clients: %d clients (ssid=%s)",
                    ifname, len(hostapd_clients), ssid,
                )
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                # Fallback: iwinfo/assoclist for this interface
                try:
                    result = await self._call(
                        UBUS_IWINFO_OBJECT,
                        UBUS_IWINFO_ASSOCLIST,
                        {"device": ifname},
                    )
                    assocs: list[dict[str, Any]] = result.get("results", [])
                    for assoc in assocs:
                        mac = assoc.get("mac", "").upper()
                        if not mac or mac in seen_macs:
                            continue
                        seen_macs.add(mac)
                        clients.append(
                            {
                                CLIENT_KEY_MAC: mac,
                                CLIENT_KEY_IP: "",
                                CLIENT_KEY_HOSTNAME: "",
                                CLIENT_KEY_SIGNAL: assoc.get("signal", 0),
                                CLIENT_KEY_SSID: ssid,
                                CLIENT_KEY_RADIO: ifname,
                            }
                        )
                except (OpenWrtMethodNotFoundError, OpenWrtResponseError) as err:
                    _LOGGER.debug("Failed to get clients for %s: %s", ifname, err)

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

        # Step 1: Stage UCI change
        staged = False
        set_err: Exception | None = None
        try:
            await self._call(
                UBUS_UCI_OBJECT,
                UBUS_UCI_SET,
                {
                    "config": "wireless",
                    "section": uci_section,
                    "values": {"disabled": disabled_value},
                },
            )
            staged = True
            _LOGGER.debug("UCI set staged for %s (disabled=%s)", uci_section, disabled_value)
        except (
            OpenWrtMethodNotFoundError,
            OpenWrtResponseError,
            OpenWrtTimeoutError,
            OpenWrtConnectionError,
        ) as err:
            set_err = err
            _LOGGER.debug("UCI set failed for %s: %s", uci_section, err)

        # Step 2: Commit — or try alternative apply paths
        if staged:
            try:
                await self._call(UBUS_UCI_OBJECT, UBUS_UCI_COMMIT, {"config": "wireless"})
                _LOGGER.debug("UCI commit successful")
                await self.reload_wifi()
                _LOGGER.info("WiFi section %s %s successfully", uci_section, action)
                return True
            except (
                OpenWrtMethodNotFoundError,
                OpenWrtAuthError,
                OpenWrtResponseError,
                OpenWrtTimeoutError,
                OpenWrtConnectionError,
            ) as commit_err:
                err_str = str(commit_err).lower()
                if isinstance(commit_err, OpenWrtAuthError) or "access denied" in err_str or "permission" in err_str:
                    _LOGGER.warning(
                        "uci/commit blocked — trying uci/apply fallback for %s: %s",
                        uci_section, commit_err,
                    )
                    # Fallback 1: uci/apply — same effect as commit but separate ACL entry
                    try:
                        await self._call(
                            UBUS_UCI_OBJECT,
                            "apply",
                            {"rollback": False, "timeout": 0},
                        )
                        _LOGGER.info(
                            "WiFi section %s %s via uci/apply", uci_section, action
                        )
                        return True
                    except (OpenWrtMethodNotFoundError, OpenWrtAuthError, OpenWrtResponseError, OpenWrtTimeoutError):
                        _LOGGER.debug("uci/apply also blocked")

                    # Revert the staged-but-uncommitted change to keep router clean
                    try:
                        await self._call(
                            UBUS_UCI_OBJECT, "revert", {"config": "wireless"}
                        )
                        _LOGGER.debug("Reverted staged UCI change for wireless")
                    except Exception:
                        pass

                    set_err = commit_err  # surface commit error in final message
                else:
                    _LOGGER.error("UCI commit failed for %s: %s", uci_section, commit_err)
                    raise OpenWrtResponseError(
                        f"Failed to {action} WiFi section {uci_section}: {commit_err}"
                    ) from commit_err

        # Fallback 2: SSH (works even when rpcd ACL blocks uci/commit)
        try:
            return await self._set_wifi_state_ssh(uci_section, enabled)
        except Exception as ssh_err:
            _LOGGER.debug("SSH fallback failed: %s", ssh_err)

        root_err = set_err or Exception("uci/set and uci/commit both blocked")
        raise OpenWrtResponseError(
            f"Cannot {action} WiFi section '{uci_section}': rpcd ACL blocks uci/commit "
            f"and SSH fallback is unavailable. "
            f"Fix: add 'uci commit wireless' permission to the rpcd ACL for this user."
        ) from root_err

    async def _get_router_status_ssh(self) -> dict[str, Any]:
        """Get router status via SSH script (fallback for ACL-restricted routers).

        Calls /root/ha-system-metrics.sh on the router via SSH.

        Returns:
            Dict with uptime, cpu_load, memory metrics.

        Raises:
            Exception: If SSH command fails.
        """
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
            "/root/ha-system-metrics.sh",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)

            if proc.returncode == 0:
                try:
                    data = json.loads(stdout.decode())
                except ValueError as parse_err:
                    raise OpenWrtResponseError(
                        f"SSH system metrics returned invalid JSON: {parse_err}"
                    ) from parse_err
                _LOGGER.debug("SSH system metrics retrieved successfully")
                return {
                    "uptime": data.get("uptime", 0),
                    "load": [0, 0, 0],  # Not available via SSH script
                    "cpu_load": float(data.get("cpu_load", 0.0)),
                    "cpu_load_5min": float(data.get("cpu_load_5min", 0.0)),
                    "cpu_load_15min": float(data.get("cpu_load_15min", 0.0)),
                    "memory": {
                        "total": data.get("memory_total", 0),
                        "free": data.get("memory_free", 0),
                        "cached": data.get("memory_cached", 0),
                        "buffers": data.get("memory_buffers", 0),
                    },
                }
            else:
                error_msg = stderr.decode().strip()
                _LOGGER.error("SSH system metrics failed: %s", error_msg)
                raise OpenWrtResponseError(f"SSH metrics failed: {error_msg}")

        except asyncio.TimeoutError:
            _LOGGER.error("SSH system metrics timed out")
            raise OpenWrtTimeoutError("SSH system metrics timed out")
        except Exception as err:
            _LOGGER.error("SSH system metrics error: %s", err)
            raise

    async def _get_wan_status_ssh(self) -> dict[str, Any]:
        """Get WAN status via SSH script (fallback for ACL-restricted routers).

        Calls /root/ha-wan-status.sh on the router via SSH.

        Returns:
            Dict with WAN connection status and RX/TX bytes.

        Raises:
            Exception: If SSH command fails.
        """
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
            "/root/ha-wan-status.sh",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)

            if proc.returncode == 0:
                try:
                    data = json.loads(stdout.decode())
                except ValueError as parse_err:
                    raise OpenWrtResponseError(
                        f"SSH WAN status returned invalid JSON: {parse_err}"
                    ) from parse_err
                _LOGGER.debug("SSH WAN status retrieved successfully")
                return {
                    "connected": bool(data.get("wan_connected", False)),
                    "interface": "",  # Not available via SSH script
                    "ipv4": "",  # Not available via SSH script
                    "uptime": 0,  # Not available via SSH script
                    "rx_bytes": data.get("rx_bytes"),
                    "tx_bytes": data.get("tx_bytes"),
                }
            else:
                error_msg = stderr.decode().strip()
                _LOGGER.error("SSH WAN status failed: %s", error_msg)
                raise OpenWrtResponseError(f"SSH WAN status failed: {error_msg}")

        except asyncio.TimeoutError:
            _LOGGER.error("SSH WAN status timed out")
            raise OpenWrtTimeoutError("SSH WAN status timed out")
        except Exception as err:
            _LOGGER.error("SSH WAN status error: %s", err)
            raise

    async def _get_clients_via_ssh(
        self,
        ifnames: list[str],
        ifname_to_ssid: dict[str, str],
        leases: dict[str, dict[str, str]] | None,
    ) -> list[dict[str, Any]] | None:
        """Fetch connected WiFi clients via SSH when rpcd ACL blocks hostapd.*/get_clients.

        Runs ``ubus call hostapd.<iface> get_clients`` for each known interface
        over a single SSH connection.

        Returns:
            List of client dicts (same schema as get_connected_clients), or None on failure.
        """
        # Build a shell one-liner that outputs JSON array of {iface, clients} objects.
        iface_args = " ".join(f"hostapd.{i}" for i in ifnames)
        shell_cmd = (
            "first=1; echo '['; "
            f"for iface in {iface_args}; do "
            "[ $first -eq 0 ] && echo ','; first=0; "
            'printf \'{"iface":"%s","data":\' "${iface#hostapd.}"; '
            "ubus call $iface get_clients 2>/dev/null || echo '{\"clients\":{}}'; "
            "echo '}'; "
            "done; echo ']'"
        )
        ssh_cmd = [
            "sshpass", "-p", self._password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            f"{self._username}@{self._host}",
            shell_cmd,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except (asyncio.TimeoutError, Exception) as err:
            _LOGGER.debug("SSH get_clients timed out or failed: %s", err)
            return None

        if proc.returncode != 0:
            _LOGGER.debug(
                "SSH ubus get_clients failed (exit %s) — trying iw fallback",
                proc.returncode,
            )
            return await self._get_clients_via_iw_ssh(ifnames, ifname_to_ssid, leases)

        try:
            entries: list[dict[str, Any]] = json.loads(stdout.decode())
        except ValueError:
            _LOGGER.debug("SSH get_clients returned invalid JSON — trying iw fallback")
            return await self._get_clients_via_iw_ssh(ifnames, ifname_to_ssid, leases)

        clients: list[dict[str, Any]] = []
        seen_macs: set[str] = set()
        for entry in entries:
            ifname: str = entry.get("iface", "")
            ssid = ifname_to_ssid.get(ifname, "")
            hostapd_clients: dict[str, Any] = entry.get("data", {}).get("clients", {})
            for mac_raw, sta_data in hostapd_clients.items():
                mac = mac_raw.upper()
                if mac in seen_macs:
                    continue
                seen_macs.add(mac)
                signal = sta_data.get("signal", 0) if isinstance(sta_data, dict) else 0
                lease = (leases or {}).get(mac, {})
                clients.append(
                    {
                        CLIENT_KEY_MAC: mac,
                        CLIENT_KEY_IP: lease.get("ip", ""),
                        CLIENT_KEY_HOSTNAME: lease.get("hostname", ""),
                        CLIENT_KEY_DHCP_EXPIRES: int(lease.get("expires", 0)),
                        CLIENT_KEY_SIGNAL: signal,
                        CLIENT_KEY_SSID: ssid,
                        CLIENT_KEY_RADIO: ifname,
                    }
                )
        _LOGGER.debug(
            "SSH client fallback: %d clients across %d interfaces",
            len(clients), len(entries),
        )
        return clients

    async def _get_clients_via_iw_ssh(
        self,
        ifnames: list[str],
        ifname_to_ssid: dict[str, str],
        leases: dict[str, dict[str, str]] | None,
    ) -> list[dict[str, Any]] | None:
        """Fetch connected WiFi clients via 'iw dev <iface> station dump' over SSH.

        Read-only alternative to the ubus hostapd fallback — works when the SSH
        user has no access to the ubus socket.  Parses the kernel nl80211
        station table directly.

        Returns:
            List of client dicts (same schema as get_connected_clients), or None on failure.
        """
        if not ifnames:
            return None

        # Build a shell one-liner: print a marker before each iface then dump stations.
        iface_cmds = "; ".join(
            f"echo '=== {i} ==='; iw dev {i} station dump 2>/dev/null"
            for i in ifnames
        )
        ssh_cmd = [
            "sshpass", "-p", self._password,
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            f"{self._username}@{self._host}",
            iface_cmds,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except (asyncio.TimeoutError, Exception) as err:
            _LOGGER.debug("SSH iw station dump timed out or failed: %s", err)
            return None

        output = stdout.decode(errors="replace")
        clients: list[dict[str, Any]] = []
        seen_macs: set[str] = set()
        current_iface = ifnames[0] if ifnames else ""

        for line in output.splitlines():
            line = line.strip()
            # Interface marker injected by the shell command above
            if line.startswith("=== ") and line.endswith(" ==="):
                current_iface = line[4:-4]
                continue
            # "Station aa:bb:cc:dd:ee:ff (on phy0-ap0)"
            if line.startswith("Station "):
                parts = line.split()
                if len(parts) >= 2:
                    mac = parts[1].upper()
                    if mac not in seen_macs:
                        seen_macs.add(mac)
                        lease = (leases or {}).get(mac, {})
                        clients.append(
                            {
                                CLIENT_KEY_MAC: mac,
                                CLIENT_KEY_IP: lease.get("ip", ""),
                                CLIENT_KEY_HOSTNAME: lease.get("hostname", ""),
                                CLIENT_KEY_DHCP_EXPIRES: int(lease.get("expires", 0)),
                                CLIENT_KEY_SIGNAL: 0,
                                CLIENT_KEY_SSID: ifname_to_ssid.get(current_iface, ""),
                                CLIENT_KEY_RADIO: current_iface,
                            }
                        )
                continue
            # "signal:  -65 [-65] dBm"  — update last appended client's signal
            if line.startswith("signal:") and clients:
                parts = line.split()
                try:
                    clients[-1][CLIENT_KEY_SIGNAL] = int(parts[1])
                except (IndexError, ValueError):
                    pass

        _LOGGER.debug(
            "SSH iw fallback: %d clients across %d interfaces",
            len(clients), len(ifnames),
        )
        return clients if clients else None

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
        action_desc = "enable" if enabled else "disable"
        disabled_val = "0" if enabled else "1"

        # Use direct UCI commands — no helper script required on the router
        uci_cmd = (
            f"uci set wireless.{uci_section}.disabled='{disabled_val}' && "
            f"uci commit wireless && "
            f"wifi reload"
        )
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
            uci_cmd,
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

    async def _get_wifi_status_ssh(self) -> list[dict[str, Any]]:
        """Get WiFi status via direct UCI commands over SSH.

        Uses `uci show wireless` — no helper script required on the router.

        Returns:
            List of radio dicts compatible with get_wifi_status() output.

        Raises:
            OpenWrtResponseError: If SSH command fails.
            OpenWrtTimeoutError: If SSH command times out.
        """
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
            "uci show wireless",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)

            if proc.returncode != 0:
                error_msg = stderr.decode().strip()
                _LOGGER.error("SSH WiFi status (uci) failed: %s", error_msg)
                raise OpenWrtResponseError(f"SSH uci show wireless failed: {error_msg}")

            # Parse UCI output: wireless.<section>.<key>='<value>'
            uci: dict[str, dict[str, str]] = {}
            for line in stdout.decode().splitlines():
                m = re.match(r"wireless\.(\w+)\.(\w+)='?([^']*)'?", line)
                if m:
                    section, key, val = m.group(1), m.group(2), m.group(3)
                    uci.setdefault(section, {})[key] = val

            # Group wifi-iface sections by their parent radio device
            radio_ifaces: dict[str, list[tuple[str, dict[str, str]]]] = {}
            for section, attrs in uci.items():
                device = attrs.get("device", "")
                if device and "ssid" in attrs:
                    radio_ifaces.setdefault(device, []).append((section, attrs))

            radios: list[dict[str, Any]] = []
            for radio_name, iface_list in radio_ifaces.items():
                radio_attrs = uci.get(radio_name, {})
                band = radio_attrs.get("band", "unknown")

                for uci_section, attrs in iface_list:
                    is_disabled = attrs.get("disabled", "0") == "1"
                    ssid = attrs.get("ssid", "")
                    is_guest = "guest" in uci_section.lower() or "guest" in ssid.lower()
                    radios.append({
                        RADIO_KEY_NAME: radio_name,
                        RADIO_KEY_BAND: band,
                        RADIO_KEY_ENABLED: not is_disabled,
                        RADIO_KEY_SSID: ssid,
                        RADIO_KEY_IFNAME: uci_section,
                        RADIO_KEY_UCI_SECTION: uci_section,
                        RADIO_KEY_IS_GUEST: is_guest,
                    })

            _LOGGER.debug("SSH WiFi status via uci: %d SSIDs found", len(radios))
            return radios

        except asyncio.TimeoutError:
            _LOGGER.error("SSH WiFi status (uci) timed out")
            raise OpenWrtTimeoutError("SSH uci show wireless timed out")
        except (OpenWrtResponseError, OpenWrtTimeoutError):
            raise
        except Exception as err:
            _LOGGER.error("SSH WiFi status (uci) error: %s", err)
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
                "rpcd file module not available – trying luci-rpc/getDHCPLeases fallback"
            )
            return await self._get_dhcp_leases_luci_rpc()
        except OpenWrtAuthError:
            _LOGGER.debug(
                "rpcd file/read blocked for %s – trying luci-rpc/getDHCPLeases fallback",
                DHCP_LEASES_PATH,
            )
            return await self._get_dhcp_leases_luci_rpc()
        except OpenWrtResponseError as err:
            _LOGGER.debug("Could not read DHCP leases via file/read: %s", err)
            return await self._get_dhcp_leases_luci_rpc()

        raw: str = result.get("data", "")
        return self._parse_dhcp_leases(raw)

    async def _get_dhcp_leases_luci_rpc(self) -> dict[str, dict[str, str]]:
        """Fetch DHCP leases via luci-rpc/getDHCPLeases (fallback for file/read ACL blocks).

        Returns:
            dict mapping uppercase MAC to {"ip": str, "hostname": str}, or {} on failure.
        """
        try:
            result = await self._call("luci-rpc", "getDHCPLeases", {})
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError, OpenWrtAuthError) as err:
            _LOGGER.debug("luci-rpc/getDHCPLeases also unavailable: %s", err)
            return {}

        leases: dict[str, dict[str, str]] = {}
        # Response is a list under key "dhcp_leases" (OpenWrt 25), "leases" (older), or directly a list
        if isinstance(result, dict):
            entries = result.get("dhcp_leases", result.get("leases", result))
        else:
            entries = result
        if not isinstance(entries, list):
            return {}
        for entry in entries:
            mac = entry.get("macaddr", "").upper()
            if not mac:
                continue
            leases[mac] = {
                "ip": entry.get("ipaddr", ""),
                "hostname": entry.get("hostname", ""),
                "expires": int(entry.get("expires", 0)),
            }
        _LOGGER.debug("luci-rpc/getDHCPLeases: %d leases", len(leases))
        return leases

    async def _get_ssid_from_luci_rpc(self, ifname: str) -> str:
        """Return SSID for a given interface name using luci-rpc/getWirelessDevices cache.

        Fetches once and caches in self._luci_rpc_ssid_map.  Used when both
        hostapd.*/get_status and iwinfo/info are blocked by rpcd ACL.

        Args:
            ifname: Physical interface name, e.g. "phy0-ap0".

        Returns:
            SSID string, or "" if unavailable.
        """
        if self._luci_rpc_ssid_map is None:
            # Fetch once and cache
            ssid_map: dict[str, str] = {}
            try:
                result = await self._call("luci-rpc", "getWirelessDevices", {})
                # Response: {radio0: {interfaces: [{ifname: "phy0-ap0", config: {ssid: ...}}]}}
                for _radio, radio_data in result.items():
                    if not isinstance(radio_data, dict):
                        continue
                    for iface in radio_data.get("interfaces", []):
                        iface_name = iface.get("ifname", "")
                        ssid = iface.get("config", {}).get("ssid", "")
                        if iface_name:
                            ssid_map[iface_name] = ssid
                _LOGGER.debug(
                    "luci-rpc/getWirelessDevices: built ssid map for %d interfaces",
                    len(ssid_map),
                )
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError, OpenWrtAuthError) as err:
                _LOGGER.debug("luci-rpc/getWirelessDevices unavailable: %s", err)
            self._luci_rpc_ssid_map = ssid_map

        return self._luci_rpc_ssid_map.get(ifname, "")

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
                "Feature not available: DHCP lease file – permission denied, "
                "trying luci-rpc/getDHCPLeases"
            )
            # Probe luci-rpc as fallback
            try:
                await self._call("luci-rpc", "getDHCPLeases", {})
                features["dhcp_leases"] = True
                _LOGGER.debug("Feature detected: DHCP leases via luci-rpc/getDHCPLeases")
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError, OpenWrtAuthError):
                pass
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            _LOGGER.debug(
                "Feature not available: DHCP lease file (rpcd-mod-file missing?), "
                "trying luci-rpc/getDHCPLeases"
            )
            try:
                await self._call("luci-rpc", "getDHCPLeases", {})
                features["dhcp_leases"] = True
                _LOGGER.debug("Feature detected: DHCP leases via luci-rpc/getDHCPLeases")
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError, OpenWrtAuthError):
                pass

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
        """Return network interface statistics from network.interface/dump.

        Returns:
            [
                {
                    "interface": str,
                    "rx_bytes": int,
                    "tx_bytes": int,
                    "status": "up" | "down",
                },
                ...
            ]
        """
        try:
            result = await self._call(UBUS_NETWORK_OBJECT, UBUS_NETWORK_DUMP, {})
            interfaces: list[dict[str, Any]] = result.get("interface", [])
            return [
                {
                    "interface": iface.get("interface", ""),
                    "rx_bytes": iface.get("statistics", {}).get("rx_bytes", 0),
                    "tx_bytes": iface.get("statistics", {}).get("tx_bytes", 0),
                    "status": "up" if iface.get("up") else "down",
                }
                for iface in interfaces
            ]
        except (OpenWrtResponseError, OpenWrtTimeoutError, OpenWrtMethodNotFoundError) as err:
            _LOGGER.debug("Could not fetch network interface stats: %s", err)
            return []

    async def get_port_stats(self) -> list[dict[str, Any]]:
        """Return per-port link status and traffic counters from network.device/status.

        Queries the network.device ubus object which reports physical switch ports
        (lan1, lan2, lan3, wan, etc.) with link speed and byte counters.

        Filtered out: bridges (br-*), loopback (lo*), VLAN sub-interfaces
        (name contains "."), and tagged interfaces (name contains "@").
        Only devtype "ethernet" entries are included (physical ports and
        DSA conduit interfaces).

        The speed field from OpenWrt is a string like "100F" or "1000F"
        (speed + duplex: F=Full, H=Half) and is parsed to an integer (Mbps).
        Returns None / -1 for unknown or no-link speed.

        Returns:
            [
                {
                    "name": str,          # "lan1", "wan", "eth0", etc.
                    "up": bool,
                    "speed_mbps": int | None,  # Mbps or None if no link / unknown
                    "duplex": str | None,      # "full" | "half" | None
                    "rx_bytes": int,
                    "tx_bytes": int,
                    "rx_packets": int,
                    "tx_packets": int,
                },
                ...
            ]
            Sorted by name. Returns [] if the ubus object is not accessible.
        """
        try:
            result = await self._call(UBUS_DEVICE_OBJECT, UBUS_DEVICE_STATUS, {})
        except (OpenWrtResponseError, OpenWrtTimeoutError, OpenWrtMethodNotFoundError) as err:
            _LOGGER.debug("Port stats unavailable (network.device ACL?): %s", err)
            return []

        ports: list[dict[str, Any]] = []
        for name, dev in result.items():
            if not isinstance(dev, dict):
                continue
            # Skip bridges, loopback, VLAN sub-interfaces, and tagged interfaces
            if (
                name.startswith(("br-", "lo"))
                or "@" in name
                or "." in name
            ):
                continue
            # Only include ethernet devtype entries (physical ports / DSA conduit)
            if dev.get("devtype") not in ("ethernet", None):
                continue

            raw_speed = dev.get("speed")
            speed_mbps, duplex = _parse_port_speed(raw_speed)

            stats = dev.get("statistics", {})
            ports.append({
                "name": name,
                "up": bool(dev.get("up", False)),
                "speed_mbps": speed_mbps,
                "duplex": duplex,
                "rx_bytes": int(stats.get("rx_bytes", 0)),
                "tx_bytes": int(stats.get("tx_bytes", 0)),
                "rx_packets": int(stats.get("rx_packets", 0)),
                "tx_packets": int(stats.get("tx_packets", 0)),
            })

        ports.sort(key=lambda p: p["name"])
        return ports

    async def get_active_connections(self) -> int:
        """Return count of active network connections from nf_conntrack.

        Tries two paths in order:
        1. /proc/sys/net/netfilter/nf_conntrack_count  — single integer, OpenWrt 21+
        2. /proc/net/nf_conntrack                      — full table, count non-empty lines

        Returns 0 if neither path is readable (module not loaded or ACL blocked).

        Returns:
            Count of active connections (int).
        """
        # Fast path: single-number file (preferred, much smaller read)
        try:
            result = await self._call(
                "file", "read",
                {"path": "/proc/sys/net/netfilter/nf_conntrack_count"},
            )
            data: str = result.get("data", "").strip()
            if data.isdigit():
                return int(data)
        except (OpenWrtResponseError, OpenWrtTimeoutError, OpenWrtMethodNotFoundError):
            pass

        # Fallback: full conntrack table, count non-empty lines
        try:
            result = await self._call(
                "file", "read",
                {"path": "/proc/net/nf_conntrack"},
            )
            data = result.get("data", "")
            if data:
                return sum(1 for line in data.splitlines() if line.strip())
        except (OpenWrtResponseError, OpenWrtTimeoutError, OpenWrtMethodNotFoundError) as err:
            _LOGGER.warning(
                "Could not read nf_conntrack (module not loaded or ACL blocked): %s", err
            )

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

            # Execute update via SSH (rpcd-mod-file does not support write)
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
                f"nohup sh -c '{cmd} > /tmp/opkg_update.log 2>&1' &",
            ]
            proc = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
            if proc.returncode != 0:
                error_msg = stderr.decode().strip()
                _LOGGER.error("Update SSH command failed: %s", error_msg)
                return {
                    "status": "error",
                    "message": f"Update SSH command failed: {error_msg}",
                    "update_type": update_type,
                }

            _LOGGER.info("Update initiated on router via SSH (%s)", update_type)
            return {
                "status": "initiated",
                "message": f"Package update initiated ({update_type}). "
                "Check /tmp/opkg_update.log on the router for progress.",
                "update_type": update_type,
            }

        except asyncio.TimeoutError:
            _LOGGER.error("Update SSH command timed out")
            return {
                "status": "error",
                "message": "Update SSH command timed out",
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
    # Service Management (procd / rc)
    # ------------------------------------------------------------------

    async def get_services(self, names: list[str] | None = None) -> list[dict[str, Any]]:
        """Return status for OpenWrt system services.

        Tries rc/list first (stable across versions), then falls back to
        procd service/list (OpenWrt 21+/25).  Results are filtered to the
        requested service names when *names* is provided.

        Args:
            names: Optional list of service names to include.
                   If None, all discovered services are returned.

        Returns:
            List of dicts:  {"name": str, "running": bool, "enabled": bool}
        """
        services: list[dict[str, Any]] = []

        # Method 1: rc/list — returns {name: {running: 0|1, enabled: 0|1}}
        try:
            result = await self._call("rc", "list", {})
            if isinstance(result, dict):
                for svc_name, info in result.items():
                    if not isinstance(info, dict):
                        continue
                    services.append(
                        {
                            "name": svc_name,
                            "running": bool(info.get("running", 0)),
                            "enabled": bool(info.get("enabled", 0)),
                        }
                    )
                if services:
                    _LOGGER.debug("Fetched %d services via rc/list", len(services))
                    if names is not None:
                        services = [s for s in services if s["name"] in names]
                    return services
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError, OpenWrtAuthError) as err:
            _LOGGER.debug("rc/list not available: %s", err)

        # Method 2: procd service/list (OpenWrt 21+/25)
        try:
            result = await self._call("service", "list", {})
            if isinstance(result, dict):
                for svc_name, info in result.items():
                    if not isinstance(info, dict):
                        continue
                    instances = info.get("instances", {})
                    running = any(
                        inst.get("running", False)
                        for inst in instances.values()
                        if isinstance(inst, dict)
                    )
                    services.append(
                        {
                            "name": svc_name,
                            "running": running,
                            "enabled": True,  # procd-managed services are enabled
                        }
                    )
                _LOGGER.debug("Fetched %d services via service/list", len(services))
                if names is not None:
                    services = [s for s in services if s["name"] in names]
                return services
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError, OpenWrtAuthError) as err:
            _LOGGER.warning("Could not fetch service list (rc/list + service/list failed): %s", err)

        return services

    async def control_service(self, name: str, action: str) -> bool:
        """Start, stop, restart, enable, or disable a procd/rc service.

        Args:
            name:   Service name (e.g. "dnsmasq", "firewall").
            action: One of "start", "stop", "restart", "enable", "disable".

        Returns:
            True on success, False on failure.
        """
        _LOGGER.info("Service control: %s %s", action, name)
        try:
            await self._call("rc", "init", {"name": name, "action": action})
            _LOGGER.debug("Service %s %s OK", name, action)
            return True
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError) as err:
            _LOGGER.error("Failed to %s service %s: %s", action, name, err)
            return False

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
        # P-6: if repeated auth failures suggest wrong credentials, stop hammering
        _MAX_AUTH_FAILURES = 3
        if self._auth_failure_count >= _MAX_AUTH_FAILURES:
            now = time.monotonic()
            if now < self._auth_backoff_until:
                raise OpenWrtAuthError(
                    "Authentication blocked after repeated failures — "
                    "check credentials (backoff active)"
                )
            # Backoff expired: reset and try again
            self._auth_failure_count = 0

        payload = self._build_call(ubus_object, method, params)
        try:
            result = await self._raw_call(payload)
            # Successful call resets the auth failure counter
            self._auth_failure_count = 0
            return result
        except OpenWrtAuthError:
            if retry_on_auth:
                _LOGGER.debug("Session expired, attempting re-login")
                try:
                    await self.login()
                    self._auth_failure_count = 0
                except OpenWrtAuthError:
                    self._auth_failure_count += 1
                    # Exponential backoff: 30s, 60s, 120s … capped at 300s
                    backoff = min(30 * (2 ** (self._auth_failure_count - 1)), 300)
                    self._auth_backoff_until = time.monotonic() + backoff
                    _LOGGER.warning(
                        "Auth failure %d/%d — next retry in %ds",
                        self._auth_failure_count,
                        _MAX_AUTH_FAILURES,
                        backoff,
                    )
                    raise
                payload = self._build_call(ubus_object, method, params)
                try:
                    return await self._raw_call(payload)
                except OpenWrtAuthError:
                    # Re-login succeeded but method STILL returns -32002
                    # → genuine ACL restriction, NOT a credential issue.
                    # Convert to MethodNotFoundError so the coordinator
                    # does not trigger ConfigEntryAuthFailed.
                    raise OpenWrtMethodNotFoundError(
                        f"rpcd ACL blocks {ubus_object}/{method} "
                        f"(authenticated OK, method not permitted)"
                    ) from None
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
            # -32002: rpcd access denied. Two root causes that look identical:
            #   (a) method not in user's ACL  → permanent, should not re-login
            #   (b) session token invalid/expired (e.g. rpcd restarted) → transient
            # Raise OpenWrtAuthError so _call re-logins and retries once.
            # If the retry also returns -32002 it's a genuine ACL restriction and
            # OpenWrtAuthError propagates to the caller (who treats it as ACL blocked).
            if error_code == -32002:
                raise OpenWrtAuthError(
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
                        RADIO_KEY_CHANNEL: radio_data.get("channel"),
                        RADIO_KEY_FREQUENCY: radio_data.get("frequency"),
                        RADIO_KEY_HWMODE: radio_data.get("hwmode"),
                        RADIO_KEY_MODE: "Master",  # wireless/status only shows AP interfaces
                        RADIO_KEY_BSSID: None,
                        RADIO_KEY_TXPOWER: None,
                        RADIO_KEY_BITRATE: None,
                        RADIO_KEY_HTMODE: None,
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
                    "noise": iface_data.get("noise"),
                    "signal": iface_data.get("signal"),
                    "quality": iface_data.get("quality"),
                    "quality_max": iface_data.get("quality_max"),
                    RADIO_KEY_MODE: iface_data.get("mode"),
                    RADIO_KEY_BSSID: iface_data.get("bssid"),
                    RADIO_KEY_CHANNEL: iface_data.get("channel"),
                    RADIO_KEY_FREQUENCY: iface_data.get("frequency"),
                    RADIO_KEY_TXPOWER: iface_data.get("txpower"),
                    RADIO_KEY_BITRATE: iface_data.get("bitrate"),
                    RADIO_KEY_HWMODE: iface_data.get("hwmode"),
                    RADIO_KEY_HTMODE: iface_data.get("htmode"),
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
                        # UCI does not expose the real physical ifname (e.g. phy0-ap0).
                        # Leave it empty so get_connected_clients() uses hostapd discovery
                        # instead of blindly constructing "hostapd.<section_name>".
                        RADIO_KEY_IFNAME: "",
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
            if lease.get("expires"):
                client[CLIENT_KEY_DHCP_EXPIRES] = int(lease["expires"])

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
            try:
                expires = int(parts[0])
            except ValueError:
                expires = 0
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
            leases[mac] = {"ip": ip, "hostname": hostname, "expires": expires}
        return leases

    # ------------------------------------------------------------------
    # DDNS status
    # ------------------------------------------------------------------

    async def get_ddns_status(self, uptime_seconds: int = 0) -> list[dict[str, Any]]:
        """Read DDNS service status from OpenWrt.

        Reads /etc/config/ddns via file/read (no UCI ACL required) and parses
        the UCI config format manually.  Falls back to uci/get if the file
        is unreadable.

        Runtime status is read from /var/run/ddns/<section>.{ip,err,update}.
        The .update file contains seconds-since-boot; uptime_seconds converts
        it to a Unix timestamp (approximate — based on previous poll's uptime).

        Returns a list of DDNS service dicts:
            section      — UCI section name (e.g. 'duckdns')
            service_name — DDNS provider (e.g. 'duckdns.org')
            domain       — configured domain (e.g. 'myhome.duckdns.org')
            enabled      — bool
            ip           — last registered IP (from runtime status file)
            last_update  — unix timestamp of last successful update (int | None)
            status       — 'ok' | 'error' | 'unknown'
        """
        # Skip if we already confirmed this device has no DDNS config
        if self._ddns_available is False:
            return []

        # --- Step 1: read /etc/config/ddns via file/read (no ACL restriction) ---
        sections: dict[str, dict[str, Any]] = {}
        try:
            file_result = await self._call(
                UBUS_FILE_OBJECT, UBUS_FILE_READ, {"path": "/etc/config/ddns"}
            )
            raw = file_result.get("data", "")
            if raw:
                sections = _parse_uci_config(raw)
        except Exception:  # noqa: BLE001
            pass

        # --- Fallback: uci/get (may be ACL-blocked on secondary APs) ---
        if not sections:
            try:
                result = await self._call("uci", "get", {"config": "ddns"})
                for k, v in result.get("values", {}).items():
                    if isinstance(v, dict) and v.get(".type") == "service":
                        sections[k] = v
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("DDNS: config unavailable on %s: %s", self._host, err)
                self._ddns_available = False
                return []

        # Mark DDNS as available so future polls skip the discovery overhead
        self._ddns_available = True

        # --- Step 2: for each service section read runtime status file ---
        services: list[dict[str, Any]] = []
        for section_name, section_data in sections.items():
            if not isinstance(section_data, dict):
                continue

            enabled = str(section_data.get("enabled", "0")) == "1"
            service_name = section_data.get("service_name", "")
            domain = section_data.get("lookup_host") or section_data.get("domain", "")

            ip: str = ""
            last_update: int | None = None
            status = "unknown"

            # Read /var/run/ddns/<section>.ip — current IP
            try:
                ip_result = await self._call(
                    UBUS_FILE_OBJECT, UBUS_FILE_READ,
                    {"path": f"/var/run/ddns/{section_name}.ip"},
                )
                ip = (ip_result.get("data", "") or "").strip()
            except Exception:  # noqa: BLE001
                ip = ""

            # Read /var/run/ddns/<section>.err — empty = ok, non-empty = error
            if ip:
                try:
                    err_result = await self._call(
                        UBUS_FILE_OBJECT, UBUS_FILE_READ,
                        {"path": f"/var/run/ddns/{section_name}.err"},
                    )
                    err_data = (err_result.get("data", "") or "").strip()
                    status = "error" if err_data else "ok"
                except Exception:  # noqa: BLE001
                    status = "ok"  # .err missing → assume ok if .ip present
            else:
                status = "unknown"

            # Read /var/run/ddns/<section>.update — seconds since boot
            # Convert to Unix timestamp using uptime_seconds from previous poll.
            try:
                upd_result = await self._call(
                    UBUS_FILE_OBJECT, UBUS_FILE_READ,
                    {"path": f"/var/run/ddns/{section_name}.update"},
                )
                upd_str = (upd_result.get("data", "") or "").strip()
                if upd_str and uptime_seconds > 0:
                    update_uptime = int(upd_str)
                    last_update = int(time.time()) - (uptime_seconds - update_uptime)
            except Exception:  # noqa: BLE001
                last_update = None

            services.append(
                {
                    "section": section_name,
                    "service_name": service_name,
                    "domain": domain,
                    "enabled": enabled,
                    "ip": ip,
                    "last_update": last_update,
                    "status": status,
                }
            )

        return services
