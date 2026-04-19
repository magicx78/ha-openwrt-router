"""DataUpdateCoordinator for the OpenWrt Router integration."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from datetime import UTC, datetime, timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import (
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtTimeoutError,
    OpenWrtResponseError,
)
from .const import (
    CLIENT_KEY_CONNECTED_SINCE,
    CLIENT_KEY_MAC,
    BOARD_REFRESH_CYCLES,
    CONF_FRITZBOX_HOST,
    CONF_FRITZBOX_PASSWORD,
    CONF_FRITZBOX_PORT,
    CONF_FRITZBOX_USER,
    DEFAULT_FRITZBOX_HOST,
    DEFAULT_FRITZBOX_PORT,
    DEFAULT_SERVICES,
    DOMAIN,
    CPU_HISTORY_MAX_POINTS,
    DSL_HISTORY_INTERVAL_CYCLES,
    DSL_HISTORY_MAX_POINTS,
    KEY_CPU_HISTORY,
    FEATURE_AVAILABLE_RADIOS,
    FEATURE_DHCP_LEASES,
    FEATURE_HAS_5GHZ,
    FEATURE_HAS_6GHZ,
    FEATURE_HAS_GUEST_WIFI,
    FEATURE_HAS_IWINFO,
    FEATURE_HAS_SERVICES,
    FEATURE_UCI_AVAILABLE,
    KEY_CLIENT_COUNT,
    KEY_CLIENTS,
    KEY_CPU_LOAD,
    KEY_DDNS_STATUS,
    KEY_DHCP_LEASES,
    KEY_DSL_HISTORY,
    KEY_DSL_STATS,
    KEY_FEATURES,
    KEY_MEMORY,
    KEY_PING_MS,
    KEY_PORT_STATS,
    KEY_ROUTER_INFO,
    KEY_SERVICES,
    KEY_UPDATES_AVAILABLE,
    KEY_UPTIME,
    KEY_WAN_CONNECTED,
    KEY_WAN_STATUS,
    KEY_WAN_TRAFFIC,
    KEY_WIFI_RADIOS,
    RADIO_KEY_BAND,
    RADIO_KEY_IS_GUEST,
    SCAN_INTERVAL_SECONDS,
)
from .fritzbox import get_dsl_stats, get_wan_traffic

_LOGGER = logging.getLogger(__name__)


class OpenWrtCoordinatorData:
    """Typed container for data fetched by the coordinator each poll cycle.

    Attributes:
        router_info: Static board information (model, hostname, release).
        uptime: System uptime in seconds.
        cpu_load: 1-minute CPU load average as percentage (0-100).
        memory: Memory stats dict (total, free, shared, buffered bytes).
        wan_status: WAN interface status dict.
        wan_connected: Convenience bool derived from wan_status.
        wifi_radios: List of normalised radio / SSID descriptors.
        clients: List of currently associated WiFi clients (ip/hostname enriched).
        client_count: Number of connected clients.
        dhcp_leases: MAC → {ip, hostname} mapping from the DHCP lease table.
        updates_available: Update status and list of available packages.
        features: Feature detection map (populated on first refresh).
    """

    def __init__(self) -> None:
        """Initialise with sensible defaults."""
        self.router_info: dict[str, Any] = {}
        self.uptime: int = 0
        self.cpu_load: float = 0.0
        self.cpu_load_5min: float = 0.0
        self.cpu_load_15min: float = 0.0
        self.memory: dict[str, Any] = {}
        self.wan_status: dict[str, Any] = {}
        self.wan_connected: bool = False
        self.wifi_radios: list[dict[str, Any]] = []
        self.clients: list[dict[str, Any]] = []
        self.client_count: int = 0
        self.dhcp_leases: dict[str, dict[str, str]] = {}
        self.disk_space: dict[str, Any] = {}
        self.tmpfs: dict[str, Any] = {}
        self.network_interfaces: list[dict[str, Any]] = []
        self.port_stats: list[dict[str, Any]] = []
        self.active_connections: int = 0
        self.updates_available: dict[str, Any] = {"available": False, "system": [], "addons": []}
        self.services: list[dict[str, Any]] = []
        self.ap_interfaces: list[dict[str, Any]] = []
        self.features: dict[str, Any] = {}
        # Fritz!Box DSL data (gateway only)
        self.dsl_stats: dict[str, Any] = {}
        self.wan_traffic: dict[str, Any] = {}
        self.ping_ms: float | None = None
        self.dsl_history: list[dict[str, Any]] = []   # filled by coordinator from _dsl_history
        # DuckDNS / DDNS status (gateway only)
        self.ddns_status: list[dict[str, Any]] = []
        # Per-router event history (status changes, spikes) — max 30 entries
        self.events: list[dict[str, Any]] = []
        # CPU + memory history (1h rolling window at 30s resolution)
        self.cpu_history: list[dict[str, Any]] = []
        # Port VLAN mapping (port name → list of VLAN IDs) from UCI
        self.port_vlan_map: dict[str, list[int]] = {}
        # Bridge FDB: MAC address → port name
        self.port_fdb_map: dict[str, str] = {}

    def as_dict(self) -> dict[str, Any]:
        """Return data as a plain dict (used for diagnostics)."""
        return {
            KEY_ROUTER_INFO: self.router_info,
            KEY_UPTIME: self.uptime,
            KEY_CPU_LOAD: self.cpu_load,
            "cpu_load_5min": self.cpu_load_5min,
            "cpu_load_15min": self.cpu_load_15min,
            KEY_MEMORY: self.memory,
            KEY_WAN_STATUS: self.wan_status,
            KEY_WAN_CONNECTED: self.wan_connected,
            KEY_WIFI_RADIOS: self.wifi_radios,
            KEY_CLIENTS: self.clients,
            KEY_CLIENT_COUNT: self.client_count,
            KEY_DHCP_LEASES: self.dhcp_leases,
            "disk_space": self.disk_space,
            "tmpfs": self.tmpfs,
            "network_interfaces": self.network_interfaces,
            KEY_PORT_STATS: self.port_stats,
            "active_connections": self.active_connections,
            KEY_UPDATES_AVAILABLE: self.updates_available,
            KEY_SERVICES: self.services,
            "ap_interfaces": self.ap_interfaces,
            KEY_FEATURES: self.features,
            KEY_DSL_STATS: self.dsl_stats,
            KEY_WAN_TRAFFIC: self.wan_traffic,
            KEY_PING_MS: self.ping_ms,
            KEY_DSL_HISTORY: self.dsl_history,
            KEY_DDNS_STATUS: self.ddns_status,
            KEY_CPU_HISTORY: self.cpu_history,
        }


class OpenWrtCoordinator(DataUpdateCoordinator[OpenWrtCoordinatorData]):
    """Coordinator that polls the OpenWrt router every SCAN_INTERVAL_SECONDS.

    Architecture notes:
    - A single coordinator instance per config entry is created in __init__.py.
    - All entities subscribe to the coordinator and read from coordinator.data.
    - Entities never call the API directly.
    - Feature detection runs once on the first successful refresh and is
      stored in coordinator.data.features.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        api: OpenWrtAPI,
        entry_title: str,
        entry: Any | None = None,
    ) -> None:
        """Initialise the coordinator.

        Args:
            hass: Home Assistant instance.
            api: Authenticated OpenWrtAPI instance.
            entry_title: Human-readable config entry title for logging.
            entry: Config entry (used to read Fritz!Box options).
        """
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry_title}",
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
        )
        self.api = api
        self._entry = entry
        self._features_detected = False
        self._board_poll_count = 0
        self._client_first_seen: dict[str, datetime] = {}
        self._prev_interface_bytes: dict[str, dict[str, int]] = {}
        self._prev_poll_time: datetime | None = None
        self._consecutive_auth_failures: int = 0
        # DSL history: deque of {ts, dsl_down, dsl_up, ping_ms} — 24 h at 60s resolution
        self._dsl_history: deque[dict[str, Any]] = deque(maxlen=DSL_HISTORY_MAX_POINTS)
        self._history_cycle_count: int = 0
        # CPU history: deque of {ts, cpu, mem} — 1h at 30s resolution
        self._cpu_history: deque[dict[str, Any]] = deque(maxlen=CPU_HISTORY_MAX_POINTS)
        # Event timeline tracking
        self._event_history: deque[dict[str, Any]] = deque(maxlen=30)
        self._prev_wan_connected: bool | None = None
        self._cpu_warn_active: bool = False
        self._mem_warn_active: bool = False

    # ------------------------------------------------------------------
    # DataUpdateCoordinator interface
    # ------------------------------------------------------------------

    async def _async_update_data(self) -> OpenWrtCoordinatorData:
        """Fetch all data from the router.

        Called automatically by HA on the update interval.

        Returns:
            Populated OpenWrtCoordinatorData instance.

        Raises:
            ConfigEntryAuthFailed: Credentials are invalid (triggers re-auth flow).
            UpdateFailed: Any other error that prevents data retrieval.
        """
        data = OpenWrtCoordinatorData()

        try:
            # --- Feature detection (runs once after first successful login) ---
            if not self._features_detected:
                await self._detect_features(data)

            # --- Static router info (model, hostname) ---
            # Fetched on first cycle and every BOARD_REFRESH_CYCLES thereafter.
            # Hostname changes are rare; this avoids a wasted call every 30 s.
            self._board_poll_count += 1
            if self._board_poll_count == 1 or self._board_poll_count % BOARD_REFRESH_CYCLES == 0:
                data.router_info = await self.api.get_router_info()
            else:
                data.router_info = self.data.router_info if self.data else {}

            # --- Priority 1: WiFi & Core Status (critical for switches) ---
            # Must run before optional monitoring calls
            data.wan_status = await self.api.get_wan_status()
            data.wan_connected = data.wan_status.get("wan_connected", False) or data.wan_status.get("connected", False)

            try:
                data.wifi_radios = await self.api.get_wifi_status()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("WiFi status unavailable (ACL?): %s", err)
                data.wifi_radios = self.data.wifi_radios if self.data else []

            data.dhcp_leases = await self.api.get_dhcp_leases()
            data.clients = await self.api.get_connected_clients(
                leases=data.dhcp_leases,
                radios=data.wifi_radios,
            )
            data.client_count = len(data.clients)

            # --- AP Interface Details (channel, freq, txpower, hwmode, etc.) ---
            # Called after get_connected_clients() so _hostapd_ifaces is populated.
            # Falls back gracefully to [] if iwinfo is unavailable.
            try:
                data.ap_interfaces = await self.api.get_ap_interface_details()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching AP interface details: %s", err)
                data.ap_interfaces = []

            # --- Fritz!Box DSL stats + ping + DuckDNS ---
            # Skipped on cycle 1 (first_refresh at startup) to avoid blocking
            # HA bootstrap. All three have external timeouts that would push
            # startup past HA's stage-2 deadline with multiple coordinators.
            if self._board_poll_count > 1:
                opts = self._entry.options if self._entry else {}
                fb_host: str = opts.get(CONF_FRITZBOX_HOST, DEFAULT_FRITZBOX_HOST)
                fb_user: str = opts.get(CONF_FRITZBOX_USER, "")
                fb_pass: str = opts.get(CONF_FRITZBOX_PASSWORD, "")
                fb_port: int = opts.get(CONF_FRITZBOX_PORT, DEFAULT_FRITZBOX_PORT)

                if fb_user:  # only poll Fritz!Box when credentials are configured
                    try:
                        from homeassistant.helpers.aiohttp_client import async_get_clientsession
                        session = async_get_clientsession(self.hass)
                        dsl, traffic = await asyncio.gather(
                            get_dsl_stats(session, fb_host, fb_user, fb_pass, fb_port),
                            get_wan_traffic(session, fb_host, fb_user, fb_pass, fb_port),
                            return_exceptions=True,
                        )
                        data.dsl_stats = dsl if isinstance(dsl, dict) else {}
                        data.wan_traffic = traffic if isinstance(traffic, dict) else {}
                    except Exception as err:  # noqa: BLE001
                        _LOGGER.warning("Fritz!Box poll failed: %s", err)
                        data.dsl_stats = self.data.dsl_stats if self.data else {}
                        data.wan_traffic = self.data.wan_traffic if self.data else {}
                else:
                    data.dsl_stats = {}
                    data.wan_traffic = {}

                # Latency: TCP connect to 8.8.8.8:53
                try:
                    t0 = time.monotonic()
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection("8.8.8.8", 53), timeout=3.0
                    )
                    data.ping_ms = round((time.monotonic() - t0) * 1000, 1)
                    writer.close()
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    data.ping_ms = None

                # DuckDNS status (only on gateway with WAN connected)
                if data.wan_connected:
                    try:
                        prev_uptime = self.data.uptime if self.data else 0
                        data.ddns_status = await self.api.get_ddns_status(
                            uptime_seconds=prev_uptime
                        )
                    except Exception as err:  # noqa: BLE001
                        _LOGGER.debug("DDNS status unavailable: %s", err)
                        data.ddns_status = self.data.ddns_status if self.data else []
                else:
                    data.ddns_status = self.data.ddns_status if self.data else []

                # DSL history: record every DSL_HISTORY_INTERVAL_CYCLES poll cycles
                self._history_cycle_count += 1
                if self._history_cycle_count >= DSL_HISTORY_INTERVAL_CYCLES:
                    self._history_cycle_count = 0
                    self._dsl_history.append({
                        "ts": int(time.time()),
                        "dsl_down": data.dsl_stats.get("downstream_kbps", 0),
                        "dsl_up": data.dsl_stats.get("upstream_kbps", 0),
                        "ping_ms": data.ping_ms,
                    })
            else:
                # First poll: carry forward empty defaults — no external calls
                data.dsl_stats = {}
                data.wan_traffic = {}
                data.ping_ms = None
                data.ddns_status = []

            data.dsl_history = list(self._dsl_history)

            # --- Per-client online time tracking ---
            now = datetime.now(UTC)
            current_macs: set[str] = set()
            for client in data.clients:
                mac: str = client.get(CLIENT_KEY_MAC, "")
                if not mac:
                    continue
                current_macs.add(mac)
                if mac not in self._client_first_seen:
                    self._client_first_seen[mac] = now
                client[CLIENT_KEY_CONNECTED_SINCE] = (
                    self._client_first_seen[mac].isoformat()
                )
            # Remove MACs that are no longer connected
            self._client_first_seen = {
                mac: ts
                for mac, ts in self._client_first_seen.items()
                if mac in current_macs
            }

            # --- Priority 2: Dynamic system status ---
            status = await self.api.get_router_status()
            data.uptime = status.get("uptime", 0)
            data.cpu_load = status.get("cpu_load", 0.0)
            data.cpu_load_5min = status.get("cpu_load_5min", 0.0)
            data.cpu_load_15min = status.get("cpu_load_15min", 0.0)
            data.memory = status.get("memory", {})

            # --- Priority 3: Extended Monitoring (optional, graceful fallback) ---
            # These are non-critical; failures don't affect core functionality
            try:
                data.disk_space = await self.api.get_disk_space()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching disk space: %s", err)
                data.disk_space = {}

            try:
                data.tmpfs = await self.api.get_tmpfs_stats()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching tmpfs stats: %s", err)
                data.tmpfs = {}

            try:
                data.network_interfaces = await self.api.get_network_interfaces()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching network interfaces: %s", err)
                data.network_interfaces = []

            try:
                data.port_stats = await self.api.get_port_stats()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching port stats: %s", err)
                data.port_stats = []

            try:
                data.port_vlan_map = await self.api.get_port_vlan_map()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching port VLAN map: %s", err)
                data.port_vlan_map = {}

            try:
                data.port_fdb_map = await self.api.get_bridge_fdb()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching bridge FDB: %s", err)
                data.port_fdb_map = {}

            # --- CPU history (30s resolution, 1h rolling window) ---
            import time as _time
            mem = data.memory
            mem_total = mem.get("total", 0) or 0
            mem_free = (mem.get("free", 0) or 0) + (mem.get("buffered", 0) or 0)
            mem_pct = round((1.0 - mem_free / mem_total) * 100.0, 1) if mem_total > 0 else 0.0
            self._cpu_history.append({
                "ts": int(_time.time()),
                "cpu": round(data.cpu_load, 1),
                "mem": mem_pct,
            })
            data.cpu_history = list(self._cpu_history)

            # --- Bandwidth rate calculation (bytes/s) ---
            poll_now = datetime.now(UTC)
            if self._prev_poll_time is not None:
                elapsed = (poll_now - self._prev_poll_time).total_seconds()
                if elapsed > 0:
                    for iface in data.network_interfaces:
                        ifname = iface.get("interface", "")
                        prev = self._prev_interface_bytes.get(ifname, {})
                        for key, rate_key in (("rx_bytes", "rx_rate"), ("tx_bytes", "tx_rate")):
                            curr = iface.get(key) or 0
                            prev_val = prev.get(key, 0) or 0
                            delta = curr - prev_val
                            iface[rate_key] = round(max(0, delta) / elapsed, 2) if delta >= 0 else 0
            self._prev_poll_time = poll_now
            self._prev_interface_bytes = {
                iface.get("interface", ""): {
                    "rx_bytes": iface.get("rx_bytes") or 0,
                    "tx_bytes": iface.get("tx_bytes") or 0,
                }
                for iface in data.network_interfaces
                if iface.get("interface")
            }

            try:
                data.active_connections = await self.api.get_active_connections()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching active connections: %s", err)
                data.active_connections = 0

            # --- Service status (dnsmasq, firewall, etc.) ---
            if self.data and self.data.features.get(FEATURE_HAS_SERVICES, False):
                try:
                    data.services = await self.api.get_services(names=DEFAULT_SERVICES)
                except Exception as err:  # noqa: BLE001
                    _LOGGER.debug("Error fetching service status: %s", err)
                    data.services = self.data.services if self.data else []
            elif not self._features_detected:
                # First poll: try fetching services regardless (feature detection hasn't run yet)
                try:
                    data.services = await self.api.get_services(names=DEFAULT_SERVICES)
                except Exception as err:  # noqa: BLE001
                    _LOGGER.debug("Error fetching service status on first poll: %s", err)
                    data.services = []

            # Carry forward features from the previous cycle.
            # Only applies when detection already ran in a prior cycle –
            # on the first poll data.features was just set by _detect_features()
            # and must not be overwritten (self.data is still None then).
            if self._features_detected and not data.features:
                data.features = self.data.features if self.data else {}

        except OpenWrtAuthError as err:
            self._consecutive_auth_failures += 1
            _MAX_CONSECUTIVE = 3
            if self._consecutive_auth_failures >= _MAX_CONSECUTIVE:
                # Persistent failure: credentials are genuinely wrong.
                # Reset counter so the next setup attempt starts fresh.
                self._consecutive_auth_failures = 0
                raise ConfigEntryAuthFailed(
                    f"Authentication failed for OpenWrt router: {err}"
                ) from err
            # Transient failure (session refresh hiccup, brief network issue):
            # raise UpdateFailed so HA skips this poll and retries in 30 s.
            _LOGGER.warning(
                "Auth error (attempt %d/%d — will retry before showing re-auth dialog): %s",
                self._consecutive_auth_failures,
                _MAX_CONSECUTIVE,
                err,
            )
            raise UpdateFailed(
                f"Auth error (transient, attempt {self._consecutive_auth_failures}/{_MAX_CONSECUTIVE}): {err}"
            ) from err

        except OpenWrtConnectionError as err:
            self._consecutive_auth_failures = 0
            raise UpdateFailed(
                f"Cannot connect to OpenWrt router: {err}"
            ) from err

        except OpenWrtTimeoutError as err:
            self._consecutive_auth_failures = 0
            raise UpdateFailed(
                f"OpenWrt router request timed out: {err}"
            ) from err

        except OpenWrtResponseError as err:
            self._consecutive_auth_failures = 0
            raise UpdateFailed(
                f"Unexpected response from OpenWrt router: {err}"
            ) from err

        except Exception as err:  # noqa: BLE001
            _LOGGER.exception("Unexpected error fetching OpenWrt data")
            raise UpdateFailed(f"Unexpected error: {err}") from err

        self._consecutive_auth_failures = 0
        self._record_events(data)
        return data

    # ------------------------------------------------------------------
    # Event timeline
    # ------------------------------------------------------------------

    def _record_events(self, data: OpenWrtCoordinatorData) -> None:
        """Detect state changes and append events to the ring buffer."""
        ts = int(time.time())

        # WAN connect / disconnect
        if self._prev_wan_connected is not None and data.wan_connected != self._prev_wan_connected:
            if data.wan_connected:
                self._event_history.appendleft({
                    "ts": ts, "type": "info",
                    "message": "WAN verbunden",
                    "detail": data.wan_status.get("ipv4_address") or data.wan_status.get("address") or "",
                })
            else:
                self._event_history.appendleft({
                    "ts": ts, "type": "error",
                    "message": "WAN getrennt",
                })
        self._prev_wan_connected = data.wan_connected

        # CPU spike (>= 80%) / recovery (< 65%)
        cpu = data.cpu_load
        if not self._cpu_warn_active and cpu >= 80:
            self._cpu_warn_active = True
            self._event_history.appendleft({
                "ts": ts, "type": "warn",
                "message": "CPU-Last erhöht",
                "detail": f"{cpu:.0f}%",
            })
        elif self._cpu_warn_active and cpu < 65:
            self._cpu_warn_active = False
            self._event_history.appendleft({
                "ts": ts, "type": "info",
                "message": "CPU-Last normalisiert",
                "detail": f"{cpu:.0f}%",
            })

        # Memory spike (>= 90%) / recovery (< 80%)
        # Use effective pressure: exclude reclaimable kernel buffers so a
        # large disk-cache doesn't falsely trigger the warning threshold.
        # Formula: (total - free - buffered) / total
        mem_total = data.memory.get("total", 0) or 0
        mem_free = data.memory.get("free", 0) or 0
        mem_buffered = data.memory.get("buffered", 0) or 0
        mem_pct = round(100 * (mem_total - mem_free - mem_buffered) / mem_total) if mem_total > 0 else 0
        if not self._mem_warn_active and mem_pct >= 90:
            self._mem_warn_active = True
            self._event_history.appendleft({
                "ts": ts, "type": "warn",
                "message": "RAM-Auslastung erhöht",
                "detail": f"{mem_pct}%",
            })
        elif self._mem_warn_active and mem_pct < 80:
            self._mem_warn_active = False
            self._event_history.appendleft({
                "ts": ts, "type": "info",
                "message": "RAM-Auslastung normalisiert",
                "detail": f"{mem_pct}%",
            })

        data.events = list(self._event_history)

    # ------------------------------------------------------------------
    # Feature detection
    # ------------------------------------------------------------------

    async def _detect_features(self, data: OpenWrtCoordinatorData) -> None:
        """Run feature detection and store results in data.features.

        Only called once per coordinator lifetime (on first successful refresh).
        Results are then carried forward in subsequent polls.

        Args:
            data: The OpenWrtCoordinatorData being built for this poll.
        """
        _LOGGER.debug("Running OpenWrt feature detection")
        try:
            features = await self.api.detect_features()

            # Probe service management availability
            try:
                svcs = await self.api.get_services(names=DEFAULT_SERVICES)
                features[FEATURE_HAS_SERVICES] = len(svcs) > 0
                data.services = svcs
            except Exception:  # noqa: BLE001
                features[FEATURE_HAS_SERVICES] = False

            data.features = features
            self._features_detected = True

            _LOGGER.info(
                "OpenWrt feature detection complete: "
                "iwinfo=%s, 5GHz=%s, 6GHz=%s, guest=%s, radios=%s, dhcp_leases=%s",
                features.get(FEATURE_HAS_IWINFO),
                features.get(FEATURE_HAS_5GHZ),
                features.get(FEATURE_HAS_6GHZ),
                features.get(FEATURE_HAS_GUEST_WIFI),
                features.get(FEATURE_AVAILABLE_RADIOS),
                features.get(FEATURE_DHCP_LEASES),
            )
        except Exception as err:  # noqa: BLE001
            # Feature detection failure is non-fatal – continue with empty features
            _LOGGER.warning(
                "Feature detection failed, some entities may not be created: %s", err
            )
            data.features = {}
            # Still mark as done to avoid spamming on every poll
            self._features_detected = True

    # ------------------------------------------------------------------
    # Convenience accessors (used by entities)
    # ------------------------------------------------------------------

    @property
    def router_info(self) -> dict[str, Any]:
        """Return static router info from latest data."""
        if self.data:
            return self.data.router_info
        return {}

    @property
    def features(self) -> dict[str, Any]:
        """Return detected feature map."""
        if self.data:
            return self.data.features
        return {}

    def get_radio_by_band(self, band: str) -> dict[str, Any] | None:
        """Return the first radio matching the given band string.

        Args:
            band: '2.4g', '5g', or '6g'.

        Returns:
            Radio dict or None if not found.
        """
        if not self.data:
            return None
        for radio in self.data.wifi_radios:
            if radio.get(RADIO_KEY_BAND) == band:
                return radio
        return None

    def get_guest_radio(self) -> dict[str, Any] | None:
        """Return the first radio marked as a guest network.

        Returns:
            Radio dict or None if no guest network detected.
        """
        if not self.data:
            return None
        for radio in self.data.wifi_radios:
            if radio.get(RADIO_KEY_IS_GUEST, False):
                return radio
        return None

    def get_client_by_mac(self, mac: str) -> dict[str, Any] | None:
        """Look up a client by MAC address.

        Args:
            mac: Uppercase MAC address string (e.g. 'AA:BB:CC:DD:EE:FF').

        Returns:
            Client dict or None.
        """
        if not self.data:
            return None
        mac_upper = mac.upper()
        for client in self.data.clients:
            if client.get(CLIENT_KEY_MAC, "").upper() == mac_upper:
                return client
        return None

    def is_client_connected(self, mac: str) -> bool:
        """Return True if the given MAC is in the current client list."""
        return self.get_client_by_mac(mac) is not None

    # ------------------------------------------------------------------
    # Feature flag helpers
    # ------------------------------------------------------------------

    @property
    def has_iwinfo(self) -> bool:
        """Return True if iwinfo is available on the router."""
        return bool(self.features.get(FEATURE_HAS_IWINFO, False))

    @property
    def has_5ghz(self) -> bool:
        """Return True if a 5 GHz radio was detected."""
        return bool(self.features.get(FEATURE_HAS_5GHZ, False))

    @property
    def has_6ghz(self) -> bool:
        """Return True if a 6 GHz radio was detected."""
        return bool(self.features.get(FEATURE_HAS_6GHZ, False))

    @property
    def has_guest_wifi(self) -> bool:
        """Return True if a guest WiFi SSID was detected."""
        return bool(self.features.get(FEATURE_HAS_GUEST_WIFI, False))

    @property
    def uci_available(self) -> bool:
        """Return True if UCI is available (required for WiFi switches)."""
        return bool(self.features.get(FEATURE_UCI_AVAILABLE, False))

    @property
    def available_radios(self) -> list[str]:
        """Return list of detected radio interface names."""
        return list(self.features.get(FEATURE_AVAILABLE_RADIOS, []))

    @property
    def has_dhcp_leases(self) -> bool:
        """Return True if DHCP lease file is readable on the router."""
        return bool(self.features.get(FEATURE_DHCP_LEASES, False))

    # TODO: add bandwidth_data property once bandwidth sensors are implemented
    # TODO: add traffic_stats property once traffic statistics are implemented
    # TODO: add per_client_online_time once client time tracking is implemented
