"""OpenWrt ubus / rpcd JSON-RPC API client."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiohttp

from .const import (
    CLIENT_KEY_HOSTNAME,
    CLIENT_KEY_IP,
    CLIENT_KEY_MAC,
    CLIENT_KEY_RADIO,
    CLIENT_KEY_SIGNAL,
    CLIENT_KEY_SSID,
    DEFAULT_SESSION_ID,
    DEFAULT_TIMEOUT,
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
    ) -> None:
        """Initialise the API client.

        Args:
            host: Router hostname or IP address.
            port: HTTP port (default 80).
            username: rpcd username (usually 'root').
            password: rpcd password.
            session: Shared aiohttp ClientSession.
            timeout: Request timeout in seconds.

        Note:
            The password is stored in memory only and is never logged.
        """
        self._host = host
        self._port = port
        self._username = username
        self._password = password  # never logged
        self._session = session
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._ubus_url = f"http://{host}:{port}/ubus"
        self._rpc_id = 0

        # Session token – refreshed on login / expiry
        self._token: str = DEFAULT_SESSION_ID

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

        payload = self._build_call(
            UBUS_SESSION_OBJECT_LOGIN,
            UBUS_SESSION_METHOD_LOGIN,
            {"username": self._username, "password": self._password},
            use_default_session=True,
        )

        try:
            result = await self._raw_call(payload)
        except OpenWrtResponseError as err:
            raise OpenWrtAuthError(f"Login failed: {err}") from err

        token = (result or {}).get("ubus_rpc_session")
        if not token or token == DEFAULT_SESSION_ID:
            raise OpenWrtAuthError(
                "Router returned an invalid session token – check credentials."
            )

        self._token = token
        _LOGGER.debug("Login successful, session established")
        return True

    async def test_connection(self) -> dict[str, Any]:
        """Login and fetch board info; used by config flow to validate setup.

        Returns:
            dict with 'model', 'hostname', 'release' keys.

        Raises:
            OpenWrtAuthError: Wrong credentials.
            OpenWrtConnectionError: Router unreachable.
            OpenWrtTimeoutError: Request timed out.
        """
        await self.login()
        return await self.get_router_info()

    # ------------------------------------------------------------------
    # Public data API
    # ------------------------------------------------------------------

    async def get_router_info(self) -> dict[str, Any]:
        """Return static board information (model, hostname, OpenWrt release).

        Calls:
            system board

        Returns:
            {
                "model": str,
                "hostname": str,
                "release": {"distribution": str, "version": str, ...},
                "mac": str,  # used as unique_id
            }
        """
        result = await self._call(UBUS_SYSTEM_OBJECT, UBUS_SYSTEM_BOARD, {})
        return {
            "model": result.get("model", "OpenWrt Router"),
            "hostname": result.get("hostname", self._host),
            "release": result.get("release", {}),
            "mac": result.get("mac", ""),
            "board_name": result.get("board_name", ""),
            "kernel": result.get("kernel", ""),
        }

    async def get_router_status(self) -> dict[str, Any]:
        """Return dynamic system metrics (uptime, load, memory).

        Calls:
            system info

        Returns:
            {
                "uptime": int,        # seconds since boot
                "load": list[int],    # raw load values (* 65536)
                "cpu_load": float,    # 1-min load average as percentage (0-100)
                "memory": dict,       # total, free, shared, buffered, available (bytes)
            }
        """
        result = await self._call(UBUS_SYSTEM_OBJECT, UBUS_SYSTEM_INFO, {})
        raw_load: list[int] = result.get("load", [0, 0, 0])
        # OpenWrt encodes load averages as integer * 65536
        cpu_load = round(raw_load[0] / 65536 * 100, 1) if raw_load else 0.0
        return {
            "uptime": result.get("uptime", 0),
            "load": raw_load,
            "cpu_load": cpu_load,
            "memory": result.get("memory", {}),
        }

    async def get_wan_status(self) -> dict[str, Any]:
        """Return WAN interface connection status.

        Iterates network.interface dump and selects the first interface
        whose name matches WAN_INTERFACE_NAMES.

        Returns:
            {
                "connected": bool,
                "interface": str,
                "ipv4": str,
                "uptime": int,
            }
        """
        result = await self._call(UBUS_NETWORK_OBJECT, UBUS_NETWORK_DUMP, {})
        interfaces: list[dict[str, Any]] = result.get("interface", [])

        for iface in interfaces:
            iface_name: str = iface.get("interface", "").lower()
            if iface_name in WAN_INTERFACE_NAMES or any(
                iface_name.startswith(w) for w in WAN_INTERFACE_NAMES
            ):
                ipv4_list = iface.get("ipv4-address", [])
                ipv4 = ipv4_list[0].get("address", "") if ipv4_list else ""
                stats: dict[str, Any] = iface.get("statistics", {})
                return {
                    "connected": iface.get("up", False),
                    "interface": iface.get("interface", ""),
                    "ipv4": ipv4,
                    "uptime": iface.get("uptime", 0),
                    "proto": iface.get("proto", ""),
                    "rx_bytes": stats.get("rx_bytes", 0),
                    "tx_bytes": stats.get("tx_bytes", 0),
                }

        # No WAN interface found – treat as disconnected
        _LOGGER.debug("No WAN interface found in network dump")
        return {"connected": False, "interface": "", "ipv4": "", "uptime": 0, "rx_bytes": 0, "tx_bytes": 0}

    async def get_wifi_status(self) -> list[dict[str, Any]]:
        """Return a list of WiFi radio / SSID descriptors.

        Tries wireless.status first (OpenWrt 21+); falls back to
        iwinfo.info per interface if not available.

        Returns:
            List of radio dicts with keys defined by RADIO_KEY_* constants.
        """
        # Attempt 1: network.wireless status (richer data, newer rpcd)
        try:
            result = await self._call(UBUS_WIRELESS_OBJECT, UBUS_WIRELESS_STATUS, {})
            return self._parse_wireless_status(result)
        except OpenWrtMethodNotFoundError:
            _LOGGER.debug(
                "network.wireless/status not available, falling back to iwinfo"
            )

        # Attempt 2: iwinfo.info (widely available fallback)
        try:
            result = await self._call(UBUS_IWINFO_OBJECT, UBUS_IWINFO_INFO, {})
            return self._parse_iwinfo_info(result)
        except OpenWrtMethodNotFoundError:
            _LOGGER.warning(
                "Neither network.wireless nor iwinfo is available on this router"
            )
            return []

    async def get_connected_clients(
        self,
        leases: dict[str, dict[str, str]] | None = None,
    ) -> list[dict[str, Any]]:
        """Return a list of currently associated WiFi clients.

        Calls:
            iwinfo assoclist  (once per discovered radio interface)

        Args:
            leases: Pre-fetched DHCP lease dict (MAC → {ip, hostname}).
                    If provided, skips a second get_dhcp_leases() call.
                    If None, fetches leases internally.

        Returns:
            List of client dicts with keys defined by CLIENT_KEY_* constants.
        """
        # We need interface names – fetch wifi status for discovery
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
        """Enable or disable a WiFi interface via UCI.

        Sets uci wireless.<section>.disabled = 0|1 then commits.

        Args:
            uci_section: UCI section name (e.g. 'default_radio0').
            enabled: True to enable, False to disable.

        Returns:
            True on success.

        Raises:
            OpenWrtMethodNotFoundError: If UCI is not available.
        """
        disabled_value = "0" if enabled else "1"
        _LOGGER.debug(
            "Setting WiFi section %s disabled=%s", uci_section, disabled_value
        )

        await self._call(
            UBUS_UCI_OBJECT,
            UBUS_UCI_SET,
            {
                "config": "wireless",
                "section": uci_section,
                "values": {"disabled": disabled_value},
            },
        )
        await self._call(
            UBUS_UCI_OBJECT,
            UBUS_UCI_COMMIT,
            {"config": "wireless"},
        )
        await self.reload_wifi()
        return True

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

        # Check iwinfo availability
        try:
            await self._call(UBUS_IWINFO_OBJECT, UBUS_IWINFO_INFO, {})
            features["has_iwinfo"] = True
            _LOGGER.debug("Feature detected: iwinfo available")
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            pass

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

        _LOGGER.debug("Detected features: %s", features)
        return features

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

        # Decode JSON-RPC envelope
        rpc_result = data.get("result")
        if not isinstance(rpc_result, (list, tuple)) or len(rpc_result) < 1:
            raise OpenWrtResponseError(
                f"Malformed ubus response for {ubus_object}/{method}: {data}"
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
            hostname = parts[3] if parts[3] != "*" else ""
            leases[mac] = {"ip": ip, "hostname": hostname}
        return leases
