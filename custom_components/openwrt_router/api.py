"""OpenWrt ubus / rpcd JSON-RPC API client."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import shlex
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
    SESSION_LIFETIME_SECONDS,
    SESSION_REFRESH_MARGIN_SECONDS,
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


# -----------------------------------------------------------------------------
# subprocess lifecycle helper — F4 (v1.18.0)
# -----------------------------------------------------------------------------
# Returncode sentinels used by ``_safe_subprocess_exec``.  Real OS returncodes
# are non-negative; the negatives below signal cleanup states to the caller
# without forcing a None / Optional dance through every call site.
SUBPROCESS_RC_TIMEOUT = -1  # process killed because wait_for() timed out
SUBPROCESS_RC_FAILED_TO_SPAWN = -2  # spawn raised before a Process existed
SUBPROCESS_RC_CANCELLED = -3  # caller's task was cancelled mid-flight


async def _safe_subprocess_exec(
    cmd: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: float,
    binary: bool = False,
) -> tuple[int, bytes | str, bytes]:
    """Run a subprocess that NEVER leaks a process or FD on any exit path.

    This is the single entry-point all subprocess.exec calls in this module
    should funnel through.  It guarantees on every termination — success,
    timeout, generic exception, ``CancelledError`` (HA shutdown) — that:

    1. ``proc.kill()`` is invoked if the child is still alive,
    2. ``proc.wait()`` is awaited (no zombies left for procd / kernel reaper),
    3. stdout / stderr pipes are closed (FDs released),

    even when the caller's task is cancelled.

    Args:
        cmd: Argv list, e.g. ``["sshpass", "-e", "ssh", ...]``.
        env: Optional environment overrides (e.g. ``SSHPASS``); ``None`` inherits.
        timeout: Hard timeout in seconds for ``communicate()``.
        binary: When True, stdout is returned as raw ``bytes``; when False (default)
            it is UTF-8-decoded with ``errors="replace"``.  ``brforward`` etc. need
            ``binary=True`` because the byte stream contains NUL bytes.

    Returns:
        ``(rc, stdout, stderr)`` where:
          - ``rc == 0`` → success
          - ``rc == SUBPROCESS_RC_TIMEOUT`` (-1) → killed due to timeout
          - ``rc == SUBPROCESS_RC_FAILED_TO_SPAWN`` (-2) → spawn itself raised
          - ``rc == SUBPROCESS_RC_CANCELLED`` (-3) → re-raised after cleanup
          - any other non-negative int → child exited with that returncode
        ``stdout`` is ``bytes`` if ``binary`` else ``str``.

    Never raises ``asyncio.TimeoutError`` to the caller — the timeout is the
    only normal control-flow path that escapes the wait.  ``CancelledError``
    IS re-raised after cleanup so HA's shutdown sequence works correctly.
    """
    proc: asyncio.subprocess.Process | None = None
    try:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except (OSError, ValueError) as err:
            # OSError covers ENOENT (sshpass missing), permission, fork failure.
            # ValueError covers malformed argv.  Both leave us with no child.
            _LOGGER.debug("subprocess spawn failed: %s (cmd[0]=%s)", err, cmd[0])
            return (
                SUBPROCESS_RC_FAILED_TO_SPAWN,
                b"" if binary else "",
                str(err).encode(),
            )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            return (SUBPROCESS_RC_TIMEOUT, b"" if binary else "", b"timeout")

        rc = proc.returncode if proc.returncode is not None else 0
        stdout: bytes | str = stdout_b if binary else stdout_b.decode(errors="replace")
        return rc, stdout, stderr_b
    finally:
        if proc is not None and proc.returncode is None:
            # Child still alive — escalate terminate → wait → kill → final wait.
            #
            # All `await proc.wait()` calls are wrapped in asyncio.shield so a
            # caller cancel CANNOT interrupt the reap and leave a zombie/FD
            # leak behind.  If a cancel arrives anyway (CancelledError bubbles
            # out of the shielded await once its inner coro completes), we
            # still continue escalation through SIGKILL + final wait, then
            # re-raise CancelledError at the end so the caller sees a clean
            # cancel — but with no leaked process.
            cleanup_cancelled = False

            # SIGTERM (synchronous, no cancel point)
            try:
                proc.terminate()
            except ProcessLookupError:
                pass  # already exited between the check and the call
            except Exception:  # noqa: BLE001
                _LOGGER.debug("subprocess terminate raised", exc_info=True)

            # Shielded wait for graceful exit
            try:
                await asyncio.shield(asyncio.wait_for(proc.wait(), timeout=2.0))
            except asyncio.CancelledError:
                cleanup_cancelled = True
            except asyncio.TimeoutError:
                pass  # still alive — escalate to SIGKILL
            except Exception:  # noqa: BLE001
                _LOGGER.debug("subprocess wait after terminate raised", exc_info=True)

            # If still alive after the graceful wait, SIGKILL + final reap.
            # Note: a pending cancel does NOT cause us to skip this — we must
            # not leave a child process behind.
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("subprocess kill raised", exc_info=True)
                try:
                    await asyncio.shield(asyncio.wait_for(proc.wait(), timeout=2.0))
                except asyncio.CancelledError:
                    cleanup_cancelled = True
                except (asyncio.TimeoutError, Exception):  # noqa: BLE001
                    _LOGGER.debug(
                        "subprocess refused to die after SIGKILL — "
                        "kernel will reap on parent exit"
                    )

            if cleanup_cancelled:
                # Re-raise the cancel that arrived during cleanup so the
                # caller's cancellation semantics are preserved — but only
                # AFTER we've done our best to reap the child.
                raise asyncio.CancelledError()


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
        duplex = (
            "full" if duplex_char == "F" else ("half" if duplex_char == "H" else None)
        )
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


def _parse_ip_addr_output(output: str) -> list[dict[str, Any]]:
    """Parse combined 'ip -o addr show; ip link show' output into interface dicts."""
    up_ifaces: set[str] = set()
    for line in output.splitlines():
        if "state UP" in line or ",UP," in line:
            parts = line.split()
            if len(parts) >= 2:
                up_ifaces.add(parts[1].rstrip(":").split("@")[0])

    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for line in output.splitlines():
        if "inet " not in line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = parts[1].rstrip(":").split("@")[0]
        if iface in seen:
            continue
        seen.add(iface)
        ipv4_addr: str | None = None
        prefix_len: int | None = None
        for i, p in enumerate(parts):
            if p == "inet" and i + 1 < len(parts):
                addr_pfx = parts[i + 1]
                if "/" in addr_pfx:
                    ipv4_addr, pfx = addr_pfx.split("/", 1)
                    try:
                        prefix_len = int(pfx)
                    except ValueError:
                        pass
                break
        out.append(
            {
                "interface": iface,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "status": "up" if iface in up_ifaces else "down",
                "ipv4_addr": ipv4_addr,
                "prefix_len": prefix_len,
            }
        )
    return out


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
        self._token_expires_at: float = 0.0

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

        # True when password-auth SSH is unavailable (router requires key-auth)
        self._ssh_use_key: bool = False

        # Set to True the first time any SSH fallback is actually used.
        self._ssh_fallback_used: bool = False

        # Cached ifname→ssid map from luci-rpc/getWirelessDevices (populated once when
        # hostapd.*/get_status is also ACL-blocked; None = not yet fetched).
        self._luci_rpc_ssid_map: dict[str, str] | None = None

        # L-1: track consecutive login failures to suppress log spam
        self._login_failure_count: int = 0

        # P-6: track consecutive auth failures for backoff (wrong credentials)
        self._auth_failure_count: int = 0
        self._auth_backoff_until: float = 0.0

        # M-4: warn once when using the root account
        self._root_warning_logged: bool = False

        # Track DDNS availability — None=unknown, False=not available (skip future polls)
        self._ddns_available: bool | None = None

    @property
    def uses_ssh_fallback(self) -> bool:
        """True if any API call fell back to SSH in the last poll cycle."""
        return self._ssh_fallback_used

    def reset_ssh_fallback_flag(self) -> None:
        """Reset SSH fallback flag at the start of each poll cycle."""
        self._ssh_fallback_used = False
        self._auth_failure_count = 0
        self._auth_backoff_until = 0.0
        self._root_warning_logged = False

    async def async_close(self) -> None:
        """Release client-side state on integration unload.

        Drops the cached rpcd session token so the on-router session times out
        naturally (default 300s).  Does NOT close ``self._session`` — that is
        the HA-shared aiohttp ClientSession from ``async_get_clientsession()``
        and must stay alive for other integrations.

        Intentionally synchronous (no network I/O): an explicit logout RPC
        could block ``async_unload_entry`` if the router is unreachable.
        """
        self._token = DEFAULT_SESSION_ID
        self._token_expires_at = 0.0
        self._wifi_method = None
        self._hostapd_ifaces = None
        self._luci_rpc_ssid_map = None
        _LOGGER.debug("OpenWrtAPI(%s) closed — session state cleared", self._host)

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
        self._token_expires_at = time.monotonic() + SESSION_LIFETIME_SECONDS
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
                err,
            )
            # Continue anyway – some routers have public read-only APIs

        return await self.get_router_info()

    async def check_capabilities(self) -> dict[str, bool]:
        """Check which ubus capabilities are available on this router.

        Returns a dict of capability_name → bool for use in the config flow
        checklist step. Non-critical failures return False instead of raising.
        """
        results: dict[str, bool] = {}

        async def _probe(
            namespace: str, method: str, params: dict | None = None
        ) -> bool:
            try:
                await self._call(namespace, method, params or {})
                return True
            except Exception:  # noqa: BLE001
                return False

        results["system_info"] = await _probe("system", "info")
        results["network_wireless"] = await _probe("network.wireless", "status")
        results["network_dump"] = await _probe("network.interface", "dump")
        results["file_read"] = await _probe(
            "file", "read", {"path": "/etc/openwrt_release"}
        )
        results["file_list"] = await _probe("file", "list", {"path": "/sys/class/net"})
        results["luci_rpc_dhcp"] = await _probe("luci-rpc", "getDHCPLeases")
        results["iwinfo"] = await _probe("iwinfo", "devices")
        results["uci_get"] = await _probe("uci", "get", {"config": "system"})

        # hostapd: try first known interface name, accept any success
        hostapd_ok = await _probe("hostapd.phy0-ap0", "get_clients")
        if not hostapd_ok:
            hostapd_ok = await _probe("hostapd.phy1-ap0", "get_clients")
        results["hostapd_clients"] = hostapd_ok

        return results

    async def _ensure_fresh_token(self) -> None:
        """Proactively refresh the session token before it expires.

        OpenWrt rpcd ignores the requested timeout on some firmware versions
        and silently invalidates tokens after ~300 s. This prevents mid-poll
        expiry by re-logging in SESSION_REFRESH_MARGIN_SECONDS before deadline.
        """
        if time.monotonic() >= self._token_expires_at - SESSION_REFRESH_MARGIN_SECONDS:
            _LOGGER.debug("Proactive session refresh (token nearing expiry)")
            await self.login()

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
        except (
            OpenWrtMethodNotFoundError,
            OpenWrtAuthError,
            OpenWrtResponseError,
        ) as err:
            # Access denied – try SSH fallback
            err_str = str(err).lower()
            if "access denied" in err_str or "permission" in err_str:
                _LOGGER.warning(
                    "Cannot access system/info via ubus (rpcd ACL restricted), "
                    "attempting SSH fallback"
                )
                self._ssh_fallback_used = True
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
        cpu_load_5min = (
            round(raw_load[1] / 65536 * 100, 1) if len(raw_load) > 1 else 0.0
        )
        cpu_load_15min = (
            round(raw_load[2] / 65536 * 100, 1) if len(raw_load) > 2 else 0.0
        )

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
        except (
            OpenWrtMethodNotFoundError,
            OpenWrtAuthError,
            OpenWrtResponseError,
        ) as err:
            # ubus blocked – try SSH fallback
            err_str = str(err).lower()
            if "access denied" in err_str or "permission" in err_str:
                _LOGGER.warning(
                    "Cannot access network dump via ubus (rpcd ACL restricted), "
                    "attempting SSH fallback for WAN status"
                )
                self._ssh_fallback_used = True
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
                rx_bytes = (
                    int(rx_result.strip()) if isinstance(rx_result, str) else None
                )
            if tx_result:
                tx_bytes = (
                    int(tx_result.strip()) if isinstance(tx_result, str) else None
                )
        except Exception:
            pass

        # SSH fallback if ubus file/read is ACL-blocked.
        # Lifecycle (kill / wait / FD close on every exit path) handled by
        # _run_ssh -> _safe_subprocess_exec.
        if rx_bytes is None and self._password:
            out = await self._run_ssh(
                f"cat /sys/class/net/{iface_name}/statistics/rx_bytes"
                f" /sys/class/net/{iface_name}/statistics/tx_bytes",
                timeout=5.0,
            )
            if out:
                lines = out.strip().splitlines()
                if len(lines) >= 2:
                    try:
                        rx_bytes = int(lines[0].strip())
                        tx_bytes = int(lines[1].strip())
                    except ValueError:
                        _LOGGER.debug(
                            "WAN rx/tx SSH fallback returned non-numeric output"
                        )

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
                result = await self._call(
                    UBUS_WIRELESS_OBJECT, UBUS_WIRELESS_STATUS, {}
                )
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
            _LOGGER.debug(
                "network.wireless/status not available, falling back to iwinfo"
            )

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
        self._ssh_fallback_used = True
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
                ifname,
                info.get("mode"),
                info.get("channel"),
                info.get("frequency"),
                info.get("hwmode"),
                info.get("htmode"),
            )

        if result:
            return result

        # Fallback: UCI wireless config for routers without iwinfo via rpcd.
        # Uses UCI section name (e.g. "default_radio0") as stable RADIO_KEY_IFNAME.
        if self._wifi_method == "uci":
            try:
                values = await self.get_uci_wireless()
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                _LOGGER.debug(
                    "UCI wireless config unavailable for AP interface details"
                )
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

            for _index, section_name, section_data in sorted(
                ifaces, key=lambda t: t[0]
            ):
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
                        RADIO_KEY_HWMODE: device_data.get("hwmode")
                        or device_data.get("type"),
                        RADIO_KEY_HTMODE: device_data.get("htmode"),
                        "signal": None,
                        "noise": None,
                        "quality": None,
                        "quality_max": None,
                    }
                )
                _LOGGER.debug(
                    "AP UCI interface %s: mode=%s ch=%s htmode=%s band=%s",
                    section_name,
                    mode_uci,
                    channel_val,
                    device_data.get("htmode"),
                    band_uci,
                )

        return result

    async def get_sta_interface_details(self) -> list[dict[str, Any]]:
        """Detect wireless STA-mode interfaces (WiFi repeater / mesh backhaul).

        A router that uplinks to another router via WiFi runs a wifi-iface in
        ``mode=sta`` (or ``wds-sta``/``mesh``).  The MAC of that STA interface
        is what the upstream router sees in its associated-clients list.

        Two-stage detection:
            1. ``iwinfo/info`` enumerates all wireless interfaces and reports
               their ``mode``.  STA-mode entries are collected and the own
               MAC is resolved via ``network.device/status``.
            2. UCI ``wireless`` config fallback for routers without iwinfo
               (Cudy WR3000 etc.).  No MAC is available but the presence of
               an STA-mode wifi-iface alone allows ``topology_mesh`` to
               override a misclassified ``lan_uplink`` edge.

        Returns:
            List of dicts ``{ifname, mode, ssid, bssid, mac, signal}``.
            ``mac`` is the STA's own wireless MAC (uppercase, no colons
            normalised) — empty string if it could not be resolved.
            ``bssid`` is the upstream peer's BSSID (uppercase).  Empty list
            on full detection failure.
        """
        sta_modes = {
            "sta",
            "client",
            "station",
            "wds-sta",
            "wds_sta",
            "mesh",
            "mesh point",
        }
        result: list[dict[str, Any]] = []

        # --- Step 1: iwinfo enumeration ----------------------------------
        candidates: list[tuple[str, dict[str, Any]]] = []
        try:
            info_all = await self._call(UBUS_IWINFO_OBJECT, UBUS_IWINFO_INFO, {})
            if isinstance(info_all, dict):
                for ifname, iface_data in info_all.items():
                    if not isinstance(iface_data, dict):
                        continue
                    mode = (iface_data.get("mode") or "").lower()
                    if mode in sta_modes:
                        candidates.append((ifname, iface_data))
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            _LOGGER.debug("iwinfo/info unavailable for STA detection")

        for ifname, iface_data in candidates:
            own_mac = ""
            try:
                dev = await self._call(
                    UBUS_DEVICE_OBJECT, UBUS_DEVICE_STATUS, {"name": ifname}
                )
                if isinstance(dev, dict):
                    own_mac = (dev.get("macaddr") or "").upper()
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                pass
            result.append(
                {
                    "ifname": ifname,
                    "mode": iface_data.get("mode"),
                    "ssid": iface_data.get("ssid", ""),
                    "bssid": (iface_data.get("bssid") or "").upper(),
                    "mac": own_mac,
                    "signal": iface_data.get("signal"),
                }
            )

        if result:
            _LOGGER.debug(
                "STA interfaces (iwinfo): %s",
                [(r["ifname"], r["mode"], r["mac"]) for r in result],
            )
            return result

        # --- Step 2: UCI fallback (no MAC, mode-only) --------------------
        try:
            values = await self.get_uci_wireless()
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            return []
        if not isinstance(values, dict):
            return []
        for section_name, section_data in values.items():
            if not isinstance(section_data, dict):
                continue
            if section_data.get(".type") != "wifi-iface":
                continue
            mode_uci = (section_data.get("mode") or "").lower()
            if mode_uci not in sta_modes:
                continue
            result.append(
                {
                    "ifname": section_name,
                    "mode": mode_uci,
                    "ssid": section_data.get("ssid", ""),
                    "bssid": (section_data.get("bssid") or "").upper(),
                    "mac": "",
                    "signal": None,
                }
            )
        if result:
            _LOGGER.debug(
                "STA interfaces (UCI fallback): %s",
                [(r["ifname"], r["mode"]) for r in result],
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
                            status = await self._call(
                                f"hostapd.{candidate}", "get_status", {}
                            )
                            ssid = status.get("ssid", "")
                            if ssid:
                                ifname_to_ssid[candidate] = ssid
                        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                            pass
                    except (
                        OpenWrtMethodNotFoundError,
                        OpenWrtResponseError,
                    ) as probe_err:
                        # Distinguish ACL-blocked (object exists) from not-found
                        if "access denied" in str(probe_err).lower():
                            acl_blocked_candidates.append(candidate)
                if found:
                    hostapd_ifnames = found
                    _LOGGER.debug(
                        "Discovered hostapd interfaces via probing: %s", found
                    )
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
                        "Using UCI radio ifnames as hostapd candidates: %s",
                        hostapd_ifnames,
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
                info = await self._call(
                    UBUS_IWINFO_OBJECT, UBUS_IWINFO_INFO, {"device": ifname}
                )
                ifname_to_ssid[ifname] = info.get("ssid", "")
                continue
            except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
                pass
            # Last fallback: luci-rpc/getWirelessDevices (builds ifname→ssid cache once)
            ssid_from_luci = await self._get_ssid_from_luci_rpc(ifname)
            ifname_to_ssid[ifname] = ssid_from_luci

        # When rpcd ACL blocks hostapd.*/get_clients, use SSH to query ubus directly.
        if self._hostapd_acl_blocked and hostapd_ifnames:
            self._ssh_fallback_used = True
            try:
                ssh_clients = await self._get_clients_via_ssh(
                    hostapd_ifnames, ifname_to_ssid, leases
                )
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
                            "rx_bytes": (sta.get("bytes") or {}).get("rx")
                            or sta.get("rx_bytes"),
                            "tx_bytes": (sta.get("bytes") or {}).get("tx")
                            or sta.get("tx_bytes"),
                        }
                    )
                _LOGGER.debug(
                    "hostapd.%s/get_clients: %d clients (ssid=%s)",
                    ifname,
                    len(hostapd_clients),
                    ssid,
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
            "Setting WiFi section %s %s (disabled=%s)",
            uci_section,
            action,
            disabled_value,
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
            _LOGGER.debug(
                "UCI set staged for %s (disabled=%s)", uci_section, disabled_value
            )
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
                await self._call(
                    UBUS_UCI_OBJECT, UBUS_UCI_COMMIT, {"config": "wireless"}
                )
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
                if (
                    isinstance(commit_err, OpenWrtAuthError)
                    or "access denied" in err_str
                    or "permission" in err_str
                ):
                    _LOGGER.warning(
                        "uci/commit blocked — trying uci/apply fallback for %s: %s",
                        uci_section,
                        commit_err,
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
                    except (
                        OpenWrtMethodNotFoundError,
                        OpenWrtAuthError,
                        OpenWrtResponseError,
                        OpenWrtTimeoutError,
                    ):
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
                    _LOGGER.error(
                        "UCI commit failed for %s: %s", uci_section, commit_err
                    )
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

    def _ssh_env(self) -> dict[str, str]:
        """Return env dict for sshpass: passes the password via SSHPASS env-var.

        Using ``sshpass -e`` instead of ``sshpass -p <pw>`` avoids leaking the
        password into ``/proc/<pid>/cmdline`` where any local process can read
        it via ``ps aux``.  Always returns a fresh dict so callers can mutate
        without side-effects on subsequent calls.
        """
        env = dict(os.environ)
        env["SSHPASS"] = self._password
        return env

    def _build_ssh_cmd(self, remote_cmd: str) -> list[str]:
        """Build SSH command list, preferring key-auth when password-auth fails.

        For password-auth uses ``sshpass -e`` — the password is passed via the
        SSHPASS env-var (see :meth:`_ssh_env`), NOT on the command line.
        Callers MUST spawn the resulting cmd with ``env=self._ssh_env()``.
        """
        target = f"{self._username}@{self._host}"
        ssh_opts = [
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=8",
        ]
        if self._ssh_use_key:
            return ["ssh", *ssh_opts, target, remote_cmd]
        return ["sshpass", "-e", "ssh", *ssh_opts, target, remote_cmd]

    async def _run_ssh(self, remote_cmd: str, timeout: float = 10.0) -> str | None:
        """Run a remote SSH command and return stdout. Auto-detects key vs. password auth.

        All cleanup (kill, wait, FD close) is delegated to
        :func:`_safe_subprocess_exec` — the helper is leak-free on every exit.
        """
        for _attempt in range(2):
            cmd = self._build_ssh_cmd(remote_cmd)
            # When password-auth is used, sshpass reads the password from
            # the SSHPASS env-var (no command-line exposure). For key-auth
            # the env-var is harmless and ignored.
            env = self._ssh_env() if not self._ssh_use_key else None
            rc, stdout, stderr = await _safe_subprocess_exec(
                cmd, env=env, timeout=timeout, binary=False
            )
            if rc == 255 and b"Permission denied" in stderr and not self._ssh_use_key:
                _LOGGER.debug("SSH password-auth denied, switching to key-auth")
                self._ssh_use_key = True
                continue
            if rc < 0:
                # timeout / spawn-failure / cancel — already logged inside helper
                return None
            # Return stdout even on non-zero exit (partial output is still useful)
            out = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
            return out if out.strip() else None
        return None

    async def _run_ssh_binary(
        self, remote_cmd: str, timeout: float = 10.0
    ) -> bytes | None:
        """Run a remote SSH command and return raw stdout bytes.

        Binary variant of :meth:`_run_ssh` for outputs that contain NUL bytes
        or otherwise must not be UTF-8-decoded — currently used to read
        ``/sys/class/net/br-lan/brforward`` which is a packed 8-byte-record
        binary stream.

        Returns:
            stdout bytes, or ``None`` on timeout / spawn-failure / non-zero
            exit with empty output.
        """
        for _attempt in range(2):
            cmd = self._build_ssh_cmd(remote_cmd)
            env = self._ssh_env() if not self._ssh_use_key else None
            rc, stdout, stderr = await _safe_subprocess_exec(
                cmd, env=env, timeout=timeout, binary=True
            )
            if rc == 255 and b"Permission denied" in stderr and not self._ssh_use_key:
                _LOGGER.debug(
                    "SSH password-auth denied (binary), switching to key-auth"
                )
                self._ssh_use_key = True
                continue
            if rc < 0:
                return None
            assert isinstance(stdout, bytes)
            return stdout if stdout else None
        return None

    async def _run_ssh_detached(
        self, remote_cmd: str, timeout: float = 10.0
    ) -> tuple[int, str, bytes]:
        """Run a fire-and-forget SSH command (e.g. ``opkg update`` via ``nohup``).

        Same return shape as :func:`_safe_subprocess_exec` but always wrapped
        with redirections that detach the remote process from the SSH session,
        so the SSH connection can close while the remote command keeps running
        on the router.

        The remote command is wrapped as::

            nohup sh -c <quoted_remote_cmd> </dev/null >/dev/null 2>&1 &

        where ``<quoted_remote_cmd>`` is produced by :func:`shlex.quote` so
        single-quotes inside ``remote_cmd`` (e.g. ``grep -v -E '^addon-...'``)
        do not break the surrounding quoting and inject shell tokens.

        ``</dev/null`` is critical — without it, OpenWrt's ``procd`` kills the
        child process group when the controlling sshd exits, and the local
        ``proc.communicate()`` will block waiting for the inherited stdout
        pipe.  ``nohup`` + ``&`` gives us SIGHUP-immunity + immediate return.

        If the caller needs to capture the remote output, they should embed
        their own redirection in ``remote_cmd``, e.g.::

            self._run_ssh_detached("opkg update > /tmp/opkg.log 2>&1")
        """
        # shlex.quote emits a single-quoted token with embedded quotes safely
        # escaped (e.g. "a'b" -> "'a'\"'\"'b'") so the remote bash sees
        # remote_cmd as exactly one argument to `sh -c`.
        quoted = shlex.quote(remote_cmd)
        wrapped = f"nohup sh -c {quoted} </dev/null >/dev/null 2>&1 &"
        cmd = self._build_ssh_cmd(wrapped)
        env = self._ssh_env() if not self._ssh_use_key else None
        rc, stdout, stderr = await _safe_subprocess_exec(
            cmd, env=env, timeout=timeout, binary=False
        )
        out = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
        return rc, out, stderr

    # ------------------------------------------------------------------
    # F5 Aggregator (v1.18.0 — SKELETON ONLY, disabled by default)
    # ------------------------------------------------------------------
    # Goal: collapse the 8–15 SSH subprocesses spawned per poll cycle (when
    # rpcd ACL forces fallback) into ONE remote shell invocation that bundles
    # all data into a single JSON response.
    #
    # Architecture (planned for v1.19.0):
    #   1. /root/ha-collect.sh on the router (deployed analogously to the
    #      existing ha-system-metrics.sh) emits a JSON document with:
    #        - "_v":            "1.18.0"   (AGGREGATOR_SCHEMA_VERSION)
    #        - "uptime":        int        (from /proc/uptime)
    #        - "load":          [f, f, f]  (from /proc/loadavg)
    #        - "memory":        {...}      (from /proc/meminfo)
    #        - "wan":           {...}      (statistics + iproute output)
    #        - "wifi":          {...}      (uci show wireless)
    #        - "clients":       [...]      (ubus hostapd.* OR iw fallback)
    #        - "interfaces":    [...]      (ip -o addr show; ip link show)
    #        - "brforward_hex": str        (hexdump'd binary br-lan/brforward)
    #
    #   2. _call_aggregator() runs ONE _run_ssh() for the whole batch,
    #      json.loads'es the response, validates _v matches the integration's
    #      AGGREGATOR_SCHEMA_VERSION (loose match — minor version may drift),
    #      and returns the parsed dict.
    #
    #   3. Coordinator's _async_update_data() detects the feature flag and
    #      uses the aggregator response to populate router_status, wan_status,
    #      wifi_radios, clients, interfaces — bypassing the per-method SSH
    #      fallbacks entirely.
    #
    # Why skeleton only in v1.18.0:
    #   - The 24h diagnostic (scripts/_prod_24h_sample.sh) must first confirm
    #     that the per-poll subprocess rate IS the root cause of the crashes.
    #   - The remote script needs careful testing on real OpenWrt hardware to
    #     handle missing tools (no jq on minimal builds) and avoid blocking
    #     reads on unrelated drivers.
    #   - Schema versioning + drift handling deserves its own dedicated
    #     review — half-shipping it would create a worse failure mode than
    #     today's "lots of subprocesses".
    #
    # Until enabled, _call_aggregator() raises NotImplementedError to make
    # accidental wiring unambiguous in stack traces.

    async def _call_aggregator(self) -> dict[str, Any]:
        """Run /root/ha-collect.sh on the router and return the parsed JSON.

        v1.18.0 skeleton — caller MUST gate this on the ``use_aggregator``
        feature flag.  Currently raises ``NotImplementedError``.

        Returns:
            Parsed aggregator response with at minimum the ``_v`` schema-
            version key.  Caller validates the version against
            :data:`AGGREGATOR_SCHEMA_VERSION` before using payload fields.

        Raises:
            NotImplementedError: Aggregator path is skeleton-only in v1.18.0.
            OpenWrtTimeoutError: SSH command timed out (when implemented).
            OpenWrtResponseError: Script missing / invalid JSON / schema drift
                (when implemented).
        """
        raise NotImplementedError(
            "F5 aggregator path is skeleton-only in v1.18.0; "
            "deploy /root/ha-collect.sh and re-enable in v1.19+. "
            "See api.py F5 section for design notes."
        )

    @staticmethod
    def _parse_aggregator_response(payload: str) -> dict[str, Any]:
        """Parse + version-check the aggregator JSON.

        v1.18.0 skeleton — verifies the ``_v`` key matches the integration's
        schema version (major.minor compare, patch is allowed to drift).

        Args:
            payload: Raw stdout from /root/ha-collect.sh.

        Returns:
            Parsed dict with the ``_v`` field intact for the caller to log.

        Raises:
            OpenWrtResponseError: JSON parse failure or schema-version drift.
        """
        try:
            data = json.loads(payload)
        except ValueError as parse_err:
            raise OpenWrtResponseError(
                f"Aggregator returned invalid JSON: {parse_err}"
            ) from parse_err
        if not isinstance(data, dict) or "_v" not in data:
            raise OpenWrtResponseError(
                "Aggregator response missing schema-version key '_v'"
            )
        from .const import AGGREGATOR_SCHEMA_VERSION

        remote_v = str(data["_v"])
        # Loose compatibility: same major.minor; patch may drift.
        if remote_v.rsplit(".", 1)[0] != AGGREGATOR_SCHEMA_VERSION.rsplit(".", 1)[0]:
            raise OpenWrtResponseError(
                f"Aggregator schema mismatch — remote='{remote_v}', "
                f"integration='{AGGREGATOR_SCHEMA_VERSION}'"
            )
        return data

    async def _get_router_status_ssh(self) -> dict[str, Any]:
        """Get router status via SSH script (fallback for ACL-restricted routers).

        Calls /root/ha-system-metrics.sh on the router via SSH.

        Returns:
            Dict with uptime, cpu_load, memory metrics.

        Raises:
            OpenWrtTimeoutError: SSH command timed out.
            OpenWrtResponseError: SSH command failed or returned invalid JSON.
        """
        cmd = self._build_ssh_cmd("/root/ha-system-metrics.sh")
        env = self._ssh_env() if not self._ssh_use_key else None
        rc, stdout, stderr = await _safe_subprocess_exec(
            cmd, env=env, timeout=10.0, binary=False
        )
        if rc == SUBPROCESS_RC_TIMEOUT:
            _LOGGER.error("SSH system metrics timed out")
            raise OpenWrtTimeoutError("SSH system metrics timed out")
        if rc < 0:
            _LOGGER.error(
                "SSH system metrics subprocess error rc=%d stderr=%s",
                rc,
                stderr.decode(errors="replace").strip(),
            )
            raise OpenWrtResponseError("SSH system metrics: subprocess error")
        if rc != 0:
            error_msg = stderr.decode(errors="replace").strip()
            _LOGGER.error("SSH system metrics failed: %s", error_msg)
            raise OpenWrtResponseError(f"SSH metrics failed: {error_msg}")

        text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
        try:
            data = json.loads(text)
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

    async def _get_wan_status_ssh(self) -> dict[str, Any]:
        """Get WAN status via SSH script (fallback for ACL-restricted routers).

        Calls /root/ha-wan-status.sh on the router via SSH.

        Returns:
            Dict with WAN connection status and RX/TX bytes.

        Raises:
            OpenWrtTimeoutError: SSH command timed out.
            OpenWrtResponseError: SSH command failed or returned invalid JSON.
        """
        cmd = self._build_ssh_cmd("/root/ha-wan-status.sh")
        env = self._ssh_env() if not self._ssh_use_key else None
        rc, stdout, stderr = await _safe_subprocess_exec(
            cmd, env=env, timeout=10.0, binary=False
        )
        if rc == SUBPROCESS_RC_TIMEOUT:
            _LOGGER.error("SSH WAN status timed out")
            raise OpenWrtTimeoutError("SSH WAN status timed out")
        if rc < 0:
            _LOGGER.error(
                "SSH WAN status subprocess error rc=%d stderr=%s",
                rc,
                stderr.decode(errors="replace").strip(),
            )
            raise OpenWrtResponseError("SSH WAN status: subprocess error")
        if rc != 0:
            error_msg = stderr.decode(errors="replace").strip()
            _LOGGER.error("SSH WAN status failed: %s", error_msg)
            raise OpenWrtResponseError(f"SSH WAN status failed: {error_msg}")

        text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
        try:
            data = json.loads(text)
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
        cmd = self._build_ssh_cmd(shell_cmd)
        env = self._ssh_env() if not self._ssh_use_key else None
        rc, stdout, _stderr = await _safe_subprocess_exec(
            cmd, env=env, timeout=10.0, binary=False
        )
        if rc == SUBPROCESS_RC_TIMEOUT:
            _LOGGER.debug("SSH get_clients timed out")
            return None
        if rc < 0:
            _LOGGER.debug("SSH get_clients subprocess error rc=%d", rc)
            return None
        if rc != 0:
            _LOGGER.debug(
                "SSH ubus get_clients failed (exit %s) — trying iw fallback", rc
            )
            return await self._get_clients_via_iw_ssh(ifnames, ifname_to_ssid, leases)

        text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
        try:
            entries: list[dict[str, Any]] = json.loads(text)
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
            len(clients),
            len(entries),
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
            f"echo '=== {i} ==='; iw dev {i} station dump 2>/dev/null" for i in ifnames
        )
        cmd = self._build_ssh_cmd(iface_cmds)
        env = self._ssh_env() if not self._ssh_use_key else None
        rc, stdout, _stderr = await _safe_subprocess_exec(
            cmd, env=env, timeout=10.0, binary=False
        )
        if rc == SUBPROCESS_RC_TIMEOUT:
            _LOGGER.debug("SSH iw station dump timed out")
            return None
        if rc < 0:
            _LOGGER.debug("SSH iw station dump subprocess error rc=%d", rc)
            return None

        output = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")
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
            len(clients),
            len(ifnames),
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
        cmd = self._build_ssh_cmd(uci_cmd)
        env = self._ssh_env() if not self._ssh_use_key else None

        rc, stdout, stderr = await _safe_subprocess_exec(
            cmd, env=env, timeout=10.0, binary=False
        )

        if rc == SUBPROCESS_RC_TIMEOUT:
            _LOGGER.error("SSH command timed out for WiFi section %s", uci_section)
            raise OpenWrtTimeoutError(f"SSH {action_desc} timed out for {uci_section}")
        if rc < 0:
            # spawn-failure or cancel — surface as response error
            _LOGGER.error(
                "SSH command failed for WiFi section %s (rc=%d, stderr=%s)",
                uci_section,
                rc,
                stderr.decode(errors="replace").strip(),
            )
            raise OpenWrtResponseError(
                f"SSH {action_desc} failed for {uci_section}: subprocess error"
            )
        if rc == 0:
            output = (
                stdout.strip()
                if isinstance(stdout, str)
                else stdout.decode(errors="replace").strip()
            )
            _LOGGER.info(
                "SSH WiFi control successful: %s (output: %s)",
                uci_section,
                output,
            )
            return True
        error_msg = stderr.decode(errors="replace").strip()
        _LOGGER.error("SSH WiFi control failed for %s: %s", uci_section, error_msg)
        raise OpenWrtResponseError(
            f"SSH {action_desc} failed for {uci_section}: {error_msg}"
        )

    async def _get_wifi_status_ssh(self) -> list[dict[str, Any]]:
        """Get WiFi status via direct UCI commands over SSH.

        Uses `uci show wireless` — no helper script required on the router.

        Returns:
            List of radio dicts compatible with get_wifi_status() output.

        Raises:
            OpenWrtResponseError: If SSH command fails.
            OpenWrtTimeoutError: If SSH command times out.
        """
        cmd = self._build_ssh_cmd("uci show wireless")
        env = self._ssh_env() if not self._ssh_use_key else None
        rc, stdout, stderr = await _safe_subprocess_exec(
            cmd, env=env, timeout=10.0, binary=False
        )

        if rc == SUBPROCESS_RC_TIMEOUT:
            _LOGGER.error("SSH WiFi status (uci) timed out")
            raise OpenWrtTimeoutError("SSH uci show wireless timed out")
        if rc < 0:
            _LOGGER.error(
                "SSH WiFi status (uci) subprocess error rc=%d stderr=%s",
                rc,
                stderr.decode(errors="replace").strip(),
            )
            raise OpenWrtResponseError("SSH uci show wireless: subprocess error")
        if rc != 0:
            error_msg = stderr.decode(errors="replace").strip()
            _LOGGER.error("SSH WiFi status (uci) failed: %s", error_msg)
            raise OpenWrtResponseError(f"SSH uci show wireless failed: {error_msg}")

        text = stdout if isinstance(stdout, str) else stdout.decode(errors="replace")

        # Parse UCI output: wireless.<section>.<key>='<value>'
        uci: dict[str, dict[str, str]] = {}
        for line in text.splitlines():
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
                radios.append(
                    {
                        RADIO_KEY_NAME: radio_name,
                        RADIO_KEY_BAND: band,
                        RADIO_KEY_ENABLED: not is_disabled,
                        RADIO_KEY_SSID: ssid,
                        RADIO_KEY_IFNAME: uci_section,
                        RADIO_KEY_UCI_SECTION: uci_section,
                        RADIO_KEY_IS_GUEST: is_guest,
                    }
                )

        _LOGGER.debug("SSH WiFi status via uci: %d SSIDs found", len(radios))
        return radios

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
        except (
            OpenWrtMethodNotFoundError,
            OpenWrtResponseError,
            OpenWrtAuthError,
        ) as err:
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
            except (
                OpenWrtMethodNotFoundError,
                OpenWrtResponseError,
                OpenWrtAuthError,
            ) as err:
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
            await self._call(UBUS_UCI_OBJECT, UBUS_UCI_GET, {"config": "wireless"})
            features["uci_available"] = True
            _LOGGER.debug("Feature detected: UCI available")
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError):
            pass

        # Check network reload availability
        try:
            # We don't actually reload, just probe using a no-op UCI get
            # Real check: see if the object exists via a safe call
            features["network_reload"] = (
                True  # assume available; fail gracefully at runtime
            )
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
                _LOGGER.debug(
                    "Feature detected: DHCP leases via luci-rpc/getDHCPLeases"
                )
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
                _LOGGER.debug(
                    "Feature detected: DHCP leases via luci-rpc/getDHCPLeases"
                )
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

        except (
            OpenWrtResponseError,
            OpenWrtMethodNotFoundError,
            OpenWrtTimeoutError,
        ) as err:
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
            result = await self._call_file_read_shell(
                "df -B 1048576 -t tmpfs", "tmpfs_stats"
            )

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

                    tmpfs_mounts.append(
                        {
                            "mount": mount,
                            "total_mb": round(size_mb, 1),
                            "used_mb": round(used_mb, 1),
                            "free_mb": round(free_mb, 1),
                            "usage_percent": round(
                                (used_mb / size_mb * 100) if size_mb > 0 else 0.0, 1
                            ),
                        }
                    )

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

        except (
            OpenWrtResponseError,
            OpenWrtMethodNotFoundError,
            OpenWrtTimeoutError,
        ) as err:
            _LOGGER.debug("Could not fetch tmpfs stats: %s", err)
            return self._default_tmpfs()

    def _default_disk_space(self) -> dict[str, Any]:
        """Return default empty disk space dict."""
        return {"primary": {}, "mounts": []}

    def _default_tmpfs(self) -> dict[str, Any]:
        """Return default empty tmpfs dict."""
        return {
            "total_mb": 0.0,
            "used_mb": 0.0,
            "free_mb": 0.0,
            "usage_percent": 0.0,
            "mounts": [],
        }

    async def _call_file_read_shell(
        self, command: str, cache_key: str
    ) -> dict[str, Any]:
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
            out = []
            for iface in interfaces:
                ipv4_list = iface.get("ipv4-address") or []
                first_ipv4 = ipv4_list[0] if ipv4_list else {}
                # Use l3_device (e.g. "br-lan.10") for VLAN detection;
                # fall back to logical name (e.g. "lan") if l3_device absent.
                l3_device: str = iface.get("l3_device", "") or iface.get(
                    "interface", ""
                )
                out.append(
                    {
                        "interface": l3_device,
                        "logical_name": iface.get("interface", ""),
                        "rx_bytes": iface.get("statistics", {}).get("rx_bytes", 0),
                        "tx_bytes": iface.get("statistics", {}).get("tx_bytes", 0),
                        "status": "up" if iface.get("up") else "down",
                        "ipv4_addr": first_ipv4.get("address"),
                        "prefix_len": first_ipv4.get("mask"),
                    }
                )
            return out
        except (
            OpenWrtResponseError,
            OpenWrtTimeoutError,
            OpenWrtMethodNotFoundError,
            OpenWrtAuthError,
        ) as err:
            _LOGGER.debug(
                "network.interface/dump failed: %s — trying SSH fallback", err
            )
            self._ssh_fallback_used = True
            return await self._get_network_interfaces_ssh()

    async def _get_network_interfaces_ssh(self) -> list[dict[str, Any]]:
        """SSH fallback: parse 'ip -o addr show' for interface and VLAN data."""
        out = await self._run_ssh("ip -o addr show; ip link show", timeout=10.0)
        if out is None:
            _LOGGER.debug("SSH fallback for network interfaces returned no data")
            return []
        return _parse_ip_addr_output(out)

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
        except (
            OpenWrtResponseError,
            OpenWrtTimeoutError,
            OpenWrtMethodNotFoundError,
        ) as err:
            _LOGGER.debug("Port stats unavailable (network.device ACL?): %s", err)
            return []

        ports: list[dict[str, Any]] = []
        for name, dev in result.items():
            if not isinstance(dev, dict):
                continue
            # Skip bridges, loopback, VLAN sub-interfaces, and tagged interfaces
            if name.startswith(("br-", "lo")) or "@" in name or "." in name:
                continue
            # Include ethernet and DSA switch ports; skip wifi, tun, etc.
            if dev.get("devtype") not in ("ethernet", "dsa", None):
                continue

            raw_speed = dev.get("speed")
            speed_mbps, duplex = _parse_port_speed(raw_speed)

            stats = dev.get("statistics", {})
            ports.append(
                {
                    "name": name,
                    "up": bool(dev.get("up", False)),
                    "speed_mbps": speed_mbps,
                    "duplex": duplex,
                    "rx_bytes": int(stats.get("rx_bytes", 0)),
                    "tx_bytes": int(stats.get("tx_bytes", 0)),
                    "rx_packets": int(stats.get("rx_packets", 0)),
                    "tx_packets": int(stats.get("tx_packets", 0)),
                }
            )

        ports.sort(key=lambda p: p["name"])
        return ports

    async def get_port_vlan_map(self) -> dict[str, list[int]]:
        """Return mapping of port name → list of VLAN IDs from UCI network config.

        Queries uci/get for "network" config and parses:
        - DSA bridge-vlan sections (@bridge-vlan[*]) — OpenWrt 21+
        - Legacy swconfig switch_vlan sections (@switch_vlan[*]) — OpenWrt 19 and older

        Returns:
            {"lan1": [10, 20], "lan2": [10], "wan": []}
            Returns {} on any error (ACL block, UCI unavailable, parse failure).
        """
        try:
            result = await self._call(
                UBUS_UCI_OBJECT, UBUS_UCI_GET, {"config": "network"}
            )
        except (
            OpenWrtResponseError,
            OpenWrtTimeoutError,
            OpenWrtMethodNotFoundError,
            OpenWrtAuthError,
        ) as err:
            _LOGGER.debug("Port VLAN map unavailable (UCI): %s", err)
            return {}

        values = result.get("values", {})
        port_vlan: dict[str, list[int]] = {}

        for section in values.values():
            if not isinstance(section, dict):
                continue
            stype = section.get(".type", "")

            # DSA bridge-vlan: device = port name, vids = list of VLAN IDs
            if stype == "bridge-vlan":
                device = section.get("device", "")
                vids = section.get("vids", [])
                if not device:
                    continue
                if isinstance(vids, str):
                    vids = [vids]
                parsed: list[int] = []
                for vid in vids:
                    try:
                        # VID may be "10" or "10:t" (tagged) — strip suffix
                        parsed.append(int(str(vid).split(":")[0]))
                    except (ValueError, TypeError):
                        pass
                if parsed:
                    port_vlan.setdefault(device, [])
                    port_vlan[device].extend(
                        v for v in parsed if v not in port_vlan[device]
                    )

            # Legacy swconfig switch_vlan: ports = "0 1 2t" style string
            elif stype == "switch_vlan":
                vid_str = section.get("vid") or section.get("vlan")
                ports_str = section.get("ports", "")
                if not vid_str or not ports_str:
                    continue
                try:
                    vid = int(vid_str)
                except (ValueError, TypeError):
                    continue
                for token in str(ports_str).split():
                    # token like "1", "2t" (tagged), "0u" (untagged) — skip CPU port (usually 6)
                    port_num_str = token.rstrip("tu")
                    try:
                        port_num = int(port_num_str)
                    except (ValueError, TypeError):
                        continue
                    if port_num >= 6:
                        continue
                    port_name = f"lan{port_num}" if port_num > 0 else "wan"
                    port_vlan.setdefault(port_name, [])
                    if vid not in port_vlan[port_name]:
                        port_vlan[port_name].append(vid)

        return port_vlan

    async def get_bridge_fdb(self) -> dict[str, str]:
        """Return MAC-address → port-name mapping from the bridge forwarding database.

        Strategy (tries in order):
        1. file/read on /sys/class/net/br-lan/brforward binary (no exec needed)
        2. /sys/class/net/br-lan/brforward binary via SSH fallback

        Note: file/exec is intentionally NOT used — rpcd leaks memory per exec call
        when stdout is large, causing gradual RAM exhaustion over polling cycles.

        Returns:
            {"aa:bb:cc:dd:ee:ff": "lan1", ...}
            Returns {} on total failure.
        """

        # Build port_no → interface name map from sysfs (via file/read, no exec)
        async def _get_port_map() -> dict[int, str]:
            port_map: dict[int, str] = {}
            try:
                # Read bridge members from sysfs — each brport has a port_no file
                for_result = await self._call(
                    UBUS_FILE_OBJECT,
                    "list",
                    {"path": "/sys/class/net", "depth": 1},
                )
                ifaces = [
                    e.get("name", "")
                    for e in for_result.get("entries", [])
                    if e.get("type") == "directory"
                ]
            except Exception:  # noqa: BLE001
                ifaces = ["lan1", "lan2", "lan3", "lan4", "wan", "eth0", "eth1"]
            for iface in ifaces:
                try:
                    pno_result = await self._call(
                        UBUS_FILE_OBJECT,
                        "read",
                        {"path": f"/sys/class/net/{iface}/brport/port_no"},
                    )
                    pno_str = (pno_result.get("data") or "").strip()
                    if pno_str:
                        port_map[int(pno_str, 16)] = iface
                except Exception:  # noqa: BLE001
                    pass
            return port_map

        # Method 1: file/read on brforward binary (avoids file/exec memory leak)
        try:
            port_no_map = await _get_port_map()
            result = await self._call(
                UBUS_FILE_OBJECT,
                "read",
                {"path": "/sys/class/net/br-lan/brforward"},
            )
            raw = result.get("data", "") or ""
            # brforward is base64-encoded when returned via file/read
            import base64

            fdb_bytes = base64.b64decode(raw) if raw else b""
            if fdb_bytes and len(fdb_bytes) % 8 == 0:
                fdb: dict[str, str] = {}
                for i in range(len(fdb_bytes) // 8):
                    chunk = fdb_bytes[i * 8 : (i + 1) * 8]
                    mac = ":".join(f"{b:02x}" for b in chunk[:6])
                    port_no = chunk[6]
                    iface = port_no_map.get(port_no)
                    if iface and iface.startswith(("lan", "wan", "eth")):
                        fdb[mac] = iface
                if fdb:
                    _LOGGER.debug("Bridge FDB via file/read: %d entries", len(fdb))
                    return fdb
        except (
            OpenWrtResponseError,
            OpenWrtTimeoutError,
            OpenWrtMethodNotFoundError,
            OpenWrtAuthError,
        ) as err:
            _LOGGER.debug("Bridge FDB via file/read unavailable: %s", err)

        # Method 2: /sys/class/net/br-lan/brforward binary via SSH (no bridge binary)
        try:
            port_map_cmd = (
                "for iface in $(ls /sys/class/net/); do "
                "  pn=$(cat /sys/class/net/$iface/brport/port_no 2>/dev/null); "
                '  [ -n "$pn" ] && echo "$pn $iface"; '
                "done"
            )
            port_out = await self._run_ssh(port_map_cmd)
            if not port_out:
                return {}
            port_no_map: dict[int, str] = {}
            for line in port_out.splitlines():
                parts = line.strip().split()
                if len(parts) == 2:
                    try:
                        port_no_map[int(parts[0], 16)] = parts[1]
                    except ValueError:
                        pass
            if not port_no_map:
                return {}

            # Read brforward binary directly via SSH (raw bytes, no base64 needed).
            # The output stream contains NUL bytes — must use the binary helper.
            fdb_bytes = await self._run_ssh_binary(
                "cat /sys/class/net/br-lan/brforward", timeout=8.0
            )
            if not fdb_bytes or len(fdb_bytes) % 8 != 0:
                return {}

            fdb = {}
            for i in range(len(fdb_bytes) // 8):
                chunk = fdb_bytes[i * 8 : (i + 1) * 8]
                mac = ":".join(f"{b:02x}" for b in chunk[:6])
                port_no = chunk[6]
                iface = port_no_map.get(port_no)
                if iface and iface.startswith(("lan", "wan", "eth")):
                    fdb[mac] = iface
            _LOGGER.debug("Bridge FDB via brforward SSH: %d entries", len(fdb))
            return fdb
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Bridge FDB SSH fallback failed: %s", err)
            return {}

    async def get_trunk_port_map(self) -> dict[str, str]:
        """Return {host_ip → port_name} by combining ARP table + bridge FDB.

        Strategy:
        1. Read /proc/net/arp via SSH → IP → MAC mapping
        2. Combine with get_bridge_fdb() (MAC → port)
        → IP → port

        Returns empty dict on failure (graceful degradation).
        """
        try:
            fdb = await self.get_bridge_fdb()
            if not fdb:
                return {}

            arp_out = await self._run_ssh("cat /proc/net/arp")
            if not arp_out:
                return {}

            result: dict[str, str] = {}
            for line in arp_out.splitlines()[1:]:  # skip header
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip, _hw, flags, mac = parts[:4]
                try:
                    if not (int(flags, 16) & 0x2):  # only reachable entries
                        continue
                except ValueError:
                    continue
                port = fdb.get(mac.lower())
                if port:
                    result[ip] = port
            _LOGGER.debug("Trunk port map (ARP+FDB): %s", result)
            return result
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("get_trunk_port_map failed: %s", err)
            return {}

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
                "file",
                "read",
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
                "file",
                "read",
                {"path": "/proc/net/nf_conntrack"},
            )
            data = result.get("data", "")
            if data:
                return sum(1 for line in data.splitlines() if line.strip())
        except (
            OpenWrtResponseError,
            OpenWrtTimeoutError,
            OpenWrtMethodNotFoundError,
        ) as err:
            _LOGGER.warning(
                "Could not read nf_conntrack (module not loaded or ACL blocked): %s",
                err,
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
                if package_name.startswith("addon-") or package_name.startswith(
                    "luci-"
                ):
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
            _LOGGER.debug("Update check failed: permission denied reading opkg data")
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

            # Execute update via SSH (rpcd-mod-file does not support write).
            # Caller-side log redirection so the user can tail it on the router.
            # _run_ssh_detached wraps with nohup + </dev/null + & so opkg keeps
            # running after the sshd channel closes — and the lifecycle helper
            # guarantees no leaked subprocess locally on the HA host.
            rc, _stdout, stderr = await self._run_ssh_detached(
                f"{cmd} > /tmp/opkg_update.log 2>&1", timeout=30.0
            )
            if rc == SUBPROCESS_RC_TIMEOUT:
                _LOGGER.error("Update SSH command timed out")
                return {
                    "status": "error",
                    "message": "Update SSH command timed out",
                    "update_type": update_type,
                }
            if rc != 0:
                error_msg = stderr.decode(errors="replace").strip()
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

    async def get_services(
        self, names: list[str] | None = None
    ) -> list[dict[str, Any]]:
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
        except (
            OpenWrtMethodNotFoundError,
            OpenWrtResponseError,
            OpenWrtAuthError,
        ) as err:
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
        except (
            OpenWrtMethodNotFoundError,
            OpenWrtResponseError,
            OpenWrtAuthError,
        ) as err:
            _LOGGER.warning(
                "Could not fetch service list (rc/list + service/list failed): %s", err
            )

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
        await self._ensure_fresh_token()

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
                "ubus returned NO_DATA for %s/%s – treating as empty",
                ubus_object,
                method,
            )
            return {}

        raise OpenWrtResponseError(
            f"ubus error {status_code} for {ubus_object}/{method}"
        )

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_wireless_status(self, status: dict[str, Any]) -> list[dict[str, Any]]:
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

    def _parse_uci_wireless(self, values: dict[str, Any]) -> list[dict[str, Any]]:
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
                _LOGGER.debug("Skipping DHCP lease line with invalid IP: %r", line)
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
                    UBUS_FILE_OBJECT,
                    UBUS_FILE_READ,
                    {"path": f"/var/run/ddns/{section_name}.ip"},
                )
                ip = (ip_result.get("data", "") or "").strip()
            except Exception:  # noqa: BLE001
                ip = ""

            # Read /var/run/ddns/<section>.err — empty = ok, non-empty = error
            if ip:
                try:
                    err_result = await self._call(
                        UBUS_FILE_OBJECT,
                        UBUS_FILE_READ,
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
                    UBUS_FILE_OBJECT,
                    UBUS_FILE_READ,
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
