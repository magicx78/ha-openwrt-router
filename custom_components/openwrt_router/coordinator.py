"""DataUpdateCoordinator for the OpenWrt Router integration."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import (
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtMethodNotFoundError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
)
from .channel_plan import Radio, phy_of, radios_from_ap_interfaces
from .client_stability import (
    STICKY_HOLD_SECONDS,
    UNSTABLE_RECONNECTS,
    WEAK_SIGNAL_DBM,
    AssociationTracker,
    HoldTimer,
    parse_usteer_clients,
    sticky_candidates,
    unstable_top,
)
from .const import (
    BOARD_REFRESH_CYCLES,
    CLIENT_KEY_CONNECTED_SINCE,
    CLIENT_KEY_LAST_SEEN,
    CLIENT_KEY_MAC,
    CPU_HISTORY_MAX_POINTS,
    DEFAULT_SERVICES,
    DFS_EVIDENCE_SECONDS,
    DHCP_CONFIG_REFRESH_CYCLES,
    DHCP_CONFIG_RETRY_CYCLES,
    DOMAIN,
    ERROR_TYPE_AUTH,
    ERROR_TYPE_CONNECTION,
    ERROR_TYPE_RESPONSE,
    ERROR_TYPE_TIMEOUT,
    EVENT_DFS,
    EVENT_DHCP,
    EVENT_WIFI,
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
    KEY_CPU_HISTORY,
    KEY_CPU_LOAD,
    KEY_DDNS_STATUS,
    KEY_DHCP_LEASES,
    KEY_FEATURES,
    KEY_LLDP_NEIGHBORS,
    KEY_LLDP_STATUS,
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
    LLDP_STATUS_UNAVAILABLE,
    LOG_EVENT_COOLDOWN_SECONDS,
    LOG_EVENTS_PER_FETCH,
    LOG_READ_INTERVAL_CYCLES,
    LOG_READ_LINES,
    LOG_READ_LINES_MAX,
    LOG_READ_LINES_MIN,
    LOG_STATUS_ERROR,
    LOG_STATUS_NOT_PERMITTED,
    LOG_STATUS_OK,
    LOG_STATUS_PENDING,
    NOTIFICATION_FAILURE_THRESHOLD,
    RADIO_KEY_BAND,
    RADIO_KEY_IS_GUEST,
    RAM_AVAILABLE_MIN_BYTES,
    RAM_PRESSURE_CLEAR_PCT,
    RAM_PRESSURE_HIGH_PCT,
    RAM_PRESSURE_HOLD_SECONDS,
    SCAN_INTERVAL_SECONDS,
    TOPOLOGY_SNAPSHOT_INTERVAL_CYCLES,
    TOPOLOGY_SNAPSHOT_MAX,
    USTEER_RETRY_CYCLES,
    USTEER_STATUS_OK,
    USTEER_STATUS_PENDING,
    USTEER_STATUS_UNAVAILABLE,
)
from .dhcp_health import Pool, parse_dhcp_config, pool_usage
from .issues import (
    ISSUE_RAM_HIGH,
    async_clear_issue,
    async_raise_issue,
    ram_high_issue_id,
)
from .log_parser import (
    CATEGORY_DFS,
    CATEGORY_DHCP,
    CATEGORY_WIFI,
    DFS_CHANNEL_CHANGE,
    DFS_EVIDENCE_KINDS,
    WIFI_CONNECTED,
    WIFI_DISCONNECTED,
    EventLimiter,
    LogCursor,
    LogEvent,
    RollingCounter,
)

if TYPE_CHECKING:
    from .fleet import FleetOutageTracker

_LOGGER = logging.getLogger(__name__)


def calc_memory_pressure(memory: dict[str, Any]) -> dict[str, Any]:
    """Return RAM pressure derived from ubus ``system info`` memory stats.

    Pressure is ``1 - available/total``: the share of RAM the kernel could not
    hand out without swapping or OOM-killing. ``available`` (MemAvailable) is
    reported by procd on current firmware. Without it (older procd, SSH
    fallback) it is estimated as free + buffers + page cache minus shmem,
    because tmpfs pages sit in the page cache but cannot be reclaimed.

    An ``available`` that is not a number, or 0 while ``free`` is not, is
    treated as missing (estimate) rather than as 100 % pressure.

    Returns:
        ``{"pressure_pct", "pressure_ratio", "available_mb", "available_bytes",
        "estimated"}`` or ``{}`` when the stats are missing or unusable.
        ``pressure_ratio`` is unrounded and used for the thresholds.
    """
    if not isinstance(memory, dict):
        return {}
    total = _as_int(memory.get("total"))
    if total is None or total <= 0:
        return {}
    free = _as_int(memory.get("free")) or 0
    available = _as_int(memory.get("available"))
    estimated = available is None or (available == 0 and free > 0)
    if estimated:
        buffered = _as_int(memory.get("buffered", memory.get("buffers"))) or 0
        reclaimable_cache = max(
            (_as_int(memory.get("cached")) or 0) - (_as_int(memory.get("shared")) or 0),
            0,
        )
        available = free + buffered + reclaimable_cache
    available = min(max(available, 0), total)
    ratio = 1.0 - available / total
    return {
        "pressure_pct": round(ratio * 100.0, 1),
        "pressure_ratio": ratio,
        "available_mb": round(available / 1024 / 1024, 1),
        "available_bytes": available,
        "estimated": estimated,
    }


def _iso_ms(time_ms: int) -> str | None:
    """Epoch milliseconds → ISO 8601 (UTC); None for 0/missing."""
    if not time_ms:
        return None
    return datetime.fromtimestamp(time_ms / 1000, UTC).isoformat()


def _as_int(value: Any) -> int | None:
    """Return value as int, None if missing or not a number."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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
        # Derived from memory, see calc_memory_pressure()
        self.memory_pressure: dict[str, Any] = {}
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
        self.updates_available: dict[str, Any] = {
            "available": False,
            "system": [],
            "addons": [],
        }
        self.services: list[dict[str, Any]] = []
        self.ap_interfaces: list[dict[str, Any]] = []
        # STA-mode wireless interfaces (WiFi repeater / mesh backhaul).
        # Used by topology_mesh to detect wireless-uplinked routers via their
        # own STA MAC.
        self.sta_interfaces: list[dict[str, Any]] = []
        self.features: dict[str, Any] = {}
        # Native WAN throughput (rx/tx byte deltas) — gateway only
        self.wan_traffic: dict[str, Any] = {}
        self.ping_ms: float | None = None
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
        # ARP/neighbour table: MAC address → IPv4 (resolves static-IP devices)
        self.arp_table: dict[str, str] = {}
        # Topology snapshots: compact state history for before/after comparison
        self.topology_snapshots: list[dict[str, Any]] = []
        # trunk_port_map: {ap_host_ip → gateway_port_name} from ARP + bridge FDB
        self.trunk_port_map: dict[str, str] = {}
        # LLDP neighbors (list of neighbor dicts) + capability status.
        # Preferred source for router-to-router wiring; empty when lldpd is
        # absent. Never fails a poll — only lowers topology confidence.
        self.lldp_neighbors: list[dict[str, Any]] = []
        self.lldp_status: str = LLDP_STATUS_UNAVAILABLE
        # Router log ingest (F6): status and counters, see _ingest_log()
        self.log_status: str = LOG_STATUS_PENDING
        self.log_stats: dict[str, Any] = {}
        # DFS (F3): {"events_24h", "by_type", "last_event"}
        self.dfs: dict[str, Any] = {}
        # DHCP health (F5): usage per active pool, MACs of static hosts
        # (static MACs are not part of as_dict / diagnostics)
        self.dhcp_pools: list[dict[str, Any]] = []
        self.dhcp_static_macs: frozenset[str] = frozenset()
        # Client stability (F4), see _client_stability_snapshot()
        self.client_stability: dict[str, Any] = {}
        # True wenn network_interfaces / port_vlan_map aus dem Cache stammen (Router offline)
        self.vlans_stale: bool = False
        # Connectivity health tracking (used by binary_sensor / sensor platform)
        self.error_type: str | None = None
        self.consecutive_failures: int = 0
        self.last_seen: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return data as a plain dict (used for diagnostics)."""
        return {
            KEY_ROUTER_INFO: self.router_info,
            KEY_UPTIME: self.uptime,
            KEY_CPU_LOAD: self.cpu_load,
            "cpu_load_5min": self.cpu_load_5min,
            "cpu_load_15min": self.cpu_load_15min,
            KEY_MEMORY: self.memory,
            "memory_pressure": self.memory_pressure,
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
            "sta_interfaces": self.sta_interfaces,
            KEY_FEATURES: self.features,
            KEY_WAN_TRAFFIC: self.wan_traffic,
            KEY_PING_MS: self.ping_ms,
            KEY_DDNS_STATUS: self.ddns_status,
            KEY_CPU_HISTORY: self.cpu_history,
            "arp_table": self.arp_table,
            KEY_LLDP_NEIGHBORS: self.lldp_neighbors,
            KEY_LLDP_STATUS: self.lldp_status,
            "log_status": self.log_status,
            "log_stats": self.log_stats,
            "dfs": self.dfs,
            "dhcp_pools": self.dhcp_pools,
            "client_stability": self.client_stability,
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
        entry: ConfigEntry | None = None,
        poll_offset_seconds: int = 0,
    ) -> None:
        """Initialise the coordinator.

        Args:
            hass: Home Assistant instance.
            api: Authenticated OpenWrtAPI instance.
            entry_title: Human-readable config entry title for logging.
            entry: Config entry; forwarded to the base class — explicit passing
                is required from HA 2026.8 (implicit ContextVar lookup is removed).
        """
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry_title}",
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
            config_entry=entry,
        )
        self.api = api
        self._entry = entry
        self._features_detected = False
        self._board_poll_count = 0
        self._poll_offset_seconds = poll_offset_seconds
        self._poll_count = 0
        self._throttled = False  # True when interval is doubled due to high CPU load
        self._ssh_fallback_notified = False  # True after HA notification was fired
        self._client_first_seen: dict[str, datetime] = {}
        self._prev_interface_bytes: dict[str, dict[str, int]] = {}
        self._prev_poll_time: datetime | None = None
        self._consecutive_auth_failures: int = 0
        # Outage tracking — kept on the coordinator, not on self.data, because
        # every successful poll replaces self.data with a fresh object.
        self._failure_count: int = 0
        self._failure_since: datetime | None = None
        self._outage_tracker: FleetOutageTracker | None = None
        # CPU history: deque of {ts, cpu, mem} — 1h at 30s resolution
        self._cpu_history: deque[dict[str, Any]] = deque(maxlen=CPU_HISTORY_MAX_POINTS)
        # Event timeline tracking
        self._event_history: deque[dict[str, Any]] = deque(maxlen=30)
        # Topology snapshots: compact AP/client state every 5 min, max 20 entries
        self._topology_snapshots: deque[dict[str, Any]] = deque(
            maxlen=TOPOLOGY_SNAPSHOT_MAX
        )
        self._snapshot_cycle_count: int = 0
        self._prev_wan_connected: bool | None = None
        self._cpu_warn_active: bool = False
        self._mem_warn_active: bool = False
        # RAM pressure Repairs issue: start of the current high-pressure phase
        # and whether the issue is currently raised.
        self._mem_high_since: datetime | None = None
        self._mem_last_check: datetime | None = None
        self._ram_issue_active: bool = False
        # Router log ingest (F6): position in the logd ring buffer, event
        # rate limit and 24 h counters survive between polls.
        self._log_cursor = LogCursor()
        self._log_limiter = EventLimiter(
            LOG_EVENTS_PER_FETCH, LOG_EVENT_COOLDOWN_SECONDS * 1000
        )
        self._log_counter = RollingCounter(24 * 3600 * 1000)
        self._log_status: str = LOG_STATUS_PENDING
        self._log_lines: int = LOG_READ_LINES
        self._device_id: str | None = None
        self._log_totals: dict[str, int] = {
            "lines_processed": 0,
            "baseline_lines": 0,
            "missed_lines": 0,
            "events_fired": 0,
            "events_suppressed": 0,
        }
        # DFS (F3): radios of the previous poll keyed by (phy, band), recent
        # DFS log lines as evidence (time_ms, phy, kind), last DFS event.
        self._prev_radios: dict[tuple[str, str], Radio] | None = None
        self._recent_dfs: deque[tuple[int, str, str]] = deque(maxlen=64)
        self._last_dfs_event: dict[str, Any] | None = None
        # DHCP health (F5): parsed `uci get dhcp`, see _fetch_dhcp_config()
        self._dhcp_config_fetched = False
        self._dhcp_pools: list[Pool] = []
        self._dhcp_static_macs: frozenset[str] = frozenset()
        # Client stability (F4): associations/reconnects from the log,
        # sticky (usteer) and weak-signal timers.
        self._assoc = AssociationTracker()
        self._sticky_timer = HoldTimer()
        self._weak_timer = HoldTimer()
        self._sticky_now: dict[str, dict[str, Any]] = {}
        self._usteer_status: str = USTEER_STATUS_PENDING
        self._channel_changes = RollingCounter(24 * 3600 * 1000, max_items=500)
        # Poll number of the last log fetch: a fetch pulled forward by a
        # channel change restarts the LOG_READ_INTERVAL_CYCLES rhythm, so the
        # adaptive line count always covers the same span.
        self._last_log_poll: int | None = None
        # Stale-data cache: letzte bekannte Werte für VLAN-Badges bei Offline-Router
        self._last_known_network_interfaces: list[dict[str, Any]] = []
        self._last_known_port_vlan_map: dict[str, list[int]] = {}

    # ------------------------------------------------------------------
    # DataUpdateCoordinator interface
    # ------------------------------------------------------------------

    async def _first_poll_optional(self, coro_factory, default, label):
        """Await a core call, tolerating an ACL block on the first poll only.

        During the very first refresh (setup) a core ubus method may still be
        denied by an rpcd ACL that was only just deployed — ``_call`` surfaces
        that as :class:`OpenWrtMethodNotFoundError`. Letting it raise would turn
        into ``UpdateFailed`` → ``ConfigEntryNotReady`` and leave the entry stuck
        in "retrying" even though the router is reachable and mostly usable. So
        on the first poll we fall back to ``default`` for that specific ACL-block
        signal. Every other error — connection, timeout, auth, response, or an
        unexpected exception — propagates unchanged, and steady-state polls keep
        the strict fail-fast behaviour.

        Args:
            coro_factory: Zero-arg callable returning the awaitable to run.
            default: Value to use when the call is skipped on the first poll.
            label: Short name for debug logging.
        """
        try:
            return await coro_factory()
        except OpenWrtMethodNotFoundError as err:
            if self._board_poll_count != 1:
                raise
            _LOGGER.debug("%s unavailable on first poll (ACL block): %s", label, err)
            return default

    async def _async_update_data(self) -> OpenWrtCoordinatorData:
        """Fetch all data from the router.

        Called automatically by HA on the update interval.

        Returns:
            Populated OpenWrtCoordinatorData instance.

        Raises:
            ConfigEntryAuthFailed: Credentials are invalid (triggers re-auth flow).
            UpdateFailed: Any other error that prevents data retrieval.
        """
        self._poll_count += 1
        self.api.reset_ssh_fallback_flag()
        # Apply stagger offset once on the second poll (first regular poll after setup).
        # Spreads multiple coordinators evenly across the scan interval.
        if self._poll_count == 2 and self._poll_offset_seconds > 0:
            _LOGGER.debug(
                "Stagger offset: delaying first regular poll by %ds",
                self._poll_offset_seconds,
            )
            await asyncio.sleep(self._poll_offset_seconds)

        data = OpenWrtCoordinatorData()

        try:
            # --- Feature detection (runs once after first successful login) ---
            if not self._features_detected:
                await self._detect_features(data)

            # --- Static router info (model, hostname) ---
            # Fetched on first cycle and every BOARD_REFRESH_CYCLES thereafter.
            # Hostname changes are rare; this avoids a wasted call every 30 s.
            self._board_poll_count += 1
            if (
                self._board_poll_count == 1
                or self._board_poll_count % BOARD_REFRESH_CYCLES == 0
            ):
                data.router_info = await self.api.get_router_info()
            else:
                data.router_info = self.data.router_info if self.data else {}

            # --- Priority 1: WiFi & Core Status (critical for switches) ---
            # Must run before optional monitoring calls
            data.wan_status = await self._first_poll_optional(
                self.api.get_wan_status, {}, "WAN status"
            )
            data.wan_connected = data.wan_status.get(
                "wan_connected", False
            ) or data.wan_status.get("connected", False)

            try:
                data.wifi_radios = await self.api.get_wifi_status()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("WiFi status unavailable (ACL?): %s", err)
                data.wifi_radios = self.data.wifi_radios if self.data else []

            data.dhcp_leases = await self._first_poll_optional(
                self.api.get_dhcp_leases, {}, "DHCP leases"
            )
            data.clients = await self._first_poll_optional(
                lambda: self.api.get_connected_clients(
                    leases=data.dhcp_leases,
                    radios=data.wifi_radios,
                ),
                [],
                "connected clients",
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

            # --- STA Interface Details (WiFi repeater / mesh backhaul) ---
            try:
                data.sta_interfaces = await self.api.get_sta_interface_details()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching STA interface details: %s", err)
                data.sta_interfaces = []

            # --- Native WAN throughput + ping + DuckDNS ---
            # Skipped on cycle 1 (first_refresh at startup) to avoid blocking
            # HA bootstrap. The ping/DDNS calls have external timeouts that would
            # push startup past HA's stage-2 deadline with multiple coordinators.
            if self._board_poll_count > 1:
                # Native WAN throughput: delta of rx/tx bytes between polls
                prev = self.data.wan_status if self.data else {}
                rx_prev = prev.get("rx_bytes") or 0
                tx_prev = prev.get("tx_bytes") or 0
                rx_now = data.wan_status.get("rx_bytes") or 0
                tx_now = data.wan_status.get("tx_bytes") or 0
                rx_delta = rx_now - rx_prev if rx_now >= rx_prev else 0
                tx_delta = tx_now - tx_prev if tx_now >= tx_prev else 0
                data.wan_traffic = {
                    "downstream_bps": rx_delta // SCAN_INTERVAL_SECONDS,
                    "upstream_bps": tx_delta // SCAN_INTERVAL_SECONDS,
                }

                # Latency: TCP connect to 8.8.8.8:53
                try:
                    t0 = time.monotonic()
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection("8.8.8.8", 53), timeout=3.0
                    )
                    data.ping_ms = round((time.monotonic() - t0) * 1000, 1)
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:  # noqa: BLE001, S110
                        pass
                except (TimeoutError, OSError):
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
            else:
                # First poll: carry forward empty defaults — no external calls
                data.wan_traffic = {}
                data.ping_ms = None
                data.ddns_status = []

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
                client[CLIENT_KEY_CONNECTED_SINCE] = self._client_first_seen[
                    mac
                ].isoformat()
                # last_seen = this poll (client is currently associated)
                client[CLIENT_KEY_LAST_SEEN] = now.isoformat()
            # Remove MACs that are no longer connected
            self._client_first_seen = {
                mac: ts
                for mac, ts in self._client_first_seen.items()
                if mac in current_macs
            }

            # --- Priority 2: Dynamic system status ---
            status = await self._first_poll_optional(
                self.api.get_router_status, {}, "router status"
            )
            data.uptime = status.get("uptime", 0)
            data.cpu_load = status.get("cpu_load", 0.0)
            data.cpu_load_5min = status.get("cpu_load_5min", 0.0)
            data.cpu_load_15min = status.get("cpu_load_15min", 0.0)
            data.memory = status.get("memory", {})
            data.memory_pressure = calc_memory_pressure(data.memory)

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
                if data.network_interfaces:
                    self._last_known_network_interfaces = data.network_interfaces
                data.vlans_stale = False
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching network interfaces: %s", err)
                data.network_interfaces = self._last_known_network_interfaces
                data.vlans_stale = bool(self._last_known_network_interfaces)

            try:
                data.port_stats = await self.api.get_port_stats()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching port stats: %s", err)
                data.port_stats = []

            try:
                data.port_vlan_map = await self.api.get_port_vlan_map()
                if data.port_vlan_map:
                    self._last_known_port_vlan_map = data.port_vlan_map
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching port VLAN map: %s", err)
                data.port_vlan_map = self._last_known_port_vlan_map

            try:
                data.port_fdb_map = await self.api.get_bridge_fdb()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching bridge FDB: %s", err)
                data.port_fdb_map = {}

            try:
                data.arp_table = await self.api.get_arp_table()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching ARP table: %s", err)
                data.arp_table = {}

            try:
                data.trunk_port_map = await self.api.get_trunk_port_map(
                    fdb=data.port_fdb_map, arp=data.arp_table
                )
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching trunk port map: %s", err)
                data.trunk_port_map = {}

            # LLDP neighbors — preferred source for router-to-router wiring.
            # Optional: a failure here NEVER fails the poll and does NOT flip the
            # SSH-fallback/degraded state (get_lldp_neighbors uses _run_ssh).
            try:
                (
                    data.lldp_neighbors,
                    data.lldp_status,
                ) = await self.api.get_lldp_neighbors()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching LLDP neighbors: %s", err)
                data.lldp_neighbors = []
                data.lldp_status = LLDP_STATUS_UNAVAILABLE

            # Router log (F6): every LOG_READ_INTERVAL_CYCLES polls, skipped on
            # the setup poll. A channel change (F3) fetches it right away so
            # that DFS lines explaining the change are already known.
            # Never fails the poll.
            channel_changes = self._detect_channel_changes(data)
            log_due = (
                self._last_log_poll is None
                or self._board_poll_count - self._last_log_poll
                >= LOG_READ_INTERVAL_CYCLES
            )
            if self._board_poll_count > 1 and (channel_changes or log_due):
                self._last_log_poll = self._board_poll_count
                await self._ingest_log(data)
            for change in channel_changes:
                self._fire_channel_change(change)
            now_ms = int(time.time() * 1000)
            data.log_status = self._log_status
            counts = self._log_counter.counts(now_ms)
            data.log_stats = {**self._log_totals, "counts_24h": counts}
            dfs_counts = {
                key.split(".", 1)[1]: n
                for key, n in counts.items()
                if key.startswith(f"{CATEGORY_DFS}.")
            }
            dfs_counts.update(self._channel_changes.counts(now_ms))
            data.dfs = {
                "events_24h": sum(dfs_counts.values()),
                "by_type": dfs_counts,
                "last_event": self._last_dfs_event,
            }

            # DHCP pools and static hosts (F5): first on poll 2, then every
            # DHCP_CONFIG_REFRESH_CYCLES polls while the router serves a pool
            # (dumb APs with ignored pools are asked once). Never fails the poll.
            if self._board_poll_count > 1 and (
                not self._dhcp_config_fetched
                or (
                    self._dhcp_pools
                    and self._board_poll_count % DHCP_CONFIG_REFRESH_CYCLES == 0
                )
                or self._board_poll_count % DHCP_CONFIG_RETRY_CYCLES == 0
            ):
                await self._fetch_dhcp_config()
            # A pool counts only while dnsmasq runs (dumb AP with the service
            # disabled but no "ignore" in its config). Services are fetched
            # later in the poll, so the previous poll's state is used.
            dnsmasq_stopped = any(
                s.get("name") == "dnsmasq" and s.get("running") is False
                for s in (self.data.services if self.data else [])
                if isinstance(s, dict)
            )
            data.dhcp_pools = (
                []
                if dnsmasq_stopped
                else pool_usage(
                    self._dhcp_pools, data.network_interfaces, data.dhcp_leases
                )
            )
            data.dhcp_static_macs = self._dhcp_static_macs

            # Client stability (F4): usteer on the polls between the log
            # fetches (spreads the two ~40 KB answers). Never fails the poll.
            if (
                self._board_poll_count > 1
                and self._board_poll_count % LOG_READ_INTERVAL_CYCLES == 1
                and (
                    self._usteer_status != USTEER_STATUS_UNAVAILABLE
                    or self._board_poll_count % USTEER_RETRY_CYCLES == 1
                )
            ):
                await self._fetch_usteer(now_ms)
            data.client_stability = self._client_stability_snapshot(data, now_ms)

            # --- CPU history (30s resolution, 1h rolling window) ---
            import time as _time

            mem = data.memory
            mem_total = mem.get("total", 0) or 0
            mem_free = (mem.get("free", 0) or 0) + (mem.get("buffered", 0) or 0)
            mem_pct = (
                round((1.0 - mem_free / mem_total) * 100.0, 1) if mem_total > 0 else 0.0
            )
            self._cpu_history.append(
                {
                    "ts": int(_time.time()),
                    "cpu": round(data.cpu_load, 1),
                    "mem": mem_pct,
                }
            )
            data.cpu_history = list(self._cpu_history)

            # --- Topology snapshots (every TOPOLOGY_SNAPSHOT_INTERVAL_CYCLES polls) ---
            self._snapshot_cycle_count += 1
            if self._snapshot_cycle_count >= TOPOLOGY_SNAPSHOT_INTERVAL_CYCLES:
                self._snapshot_cycle_count = 0
                self._topology_snapshots.append(
                    {
                        "ts": int(_time.time()),
                        "routers": [
                            {
                                "id": c.get("mac", ""),
                                "hostname": c.get("hostname", ""),
                                "ip": c.get("ip", ""),
                                "status": "online",
                            }
                            for c in data.clients
                        ],
                        "client_count": data.client_count,
                        "wan_connected": data.wan_connected,
                    }
                )
            data.topology_snapshots = list(self._topology_snapshots)

            # --- Bandwidth rate calculation (bytes/s) ---
            poll_now = datetime.now(UTC)
            if self._prev_poll_time is not None:
                elapsed = (poll_now - self._prev_poll_time).total_seconds()
                if elapsed > 0:
                    for iface in data.network_interfaces:
                        ifname = iface.get("interface", "")
                        prev = self._prev_interface_bytes.get(ifname, {})
                        for key, rate_key in (
                            ("rx_bytes", "rx_rate"),
                            ("tx_bytes", "tx_rate"),
                        ):
                            curr = iface.get(key) or 0
                            prev_val = prev.get(key, 0) or 0
                            delta = curr - prev_val
                            iface[rate_key] = (
                                round(max(0, delta) / elapsed, 2) if delta >= 0 else 0
                            )
            self._prev_poll_time = poll_now
            # Rebuild from current interfaces only — removes stale entries for
            # interfaces that no longer exist (tunnels, temporary VLANs, etc.)
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
                    _LOGGER.debug(
                        "Error fetching service status on first poll: %s", err
                    )
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
                self._consecutive_auth_failures = 0
                raise ConfigEntryAuthFailed(
                    f"Authentication failed for OpenWrt router: {err}"
                ) from err
            _LOGGER.warning(
                "Auth error (attempt %d/%d — will retry before showing re-auth dialog): %s",
                self._consecutive_auth_failures,
                _MAX_CONSECUTIVE,
                err,
            )
            self._record_failure(ERROR_TYPE_AUTH)
            raise UpdateFailed(
                f"Auth error (transient, attempt {self._consecutive_auth_failures}/{_MAX_CONSECUTIVE}): {err}"
            ) from err

        except OpenWrtConnectionError as err:
            self._consecutive_auth_failures = 0
            self._record_failure(ERROR_TYPE_CONNECTION)
            raise UpdateFailed(f"Cannot connect to OpenWrt router: {err}") from err

        except OpenWrtTimeoutError as err:
            self._consecutive_auth_failures = 0
            self._record_failure(ERROR_TYPE_TIMEOUT)
            raise UpdateFailed(f"OpenWrt router request timed out: {err}") from err

        except OpenWrtResponseError as err:
            self._consecutive_auth_failures = 0
            self._record_failure(ERROR_TYPE_RESPONSE)
            raise UpdateFailed(
                f"Unexpected response from OpenWrt router: {err}"
            ) from err

        except OpenWrtMethodNotFoundError as err:
            # ACL block / missing ubus method past the first poll. The
            # first-poll case is already tolerated in _first_poll_optional;
            # afterwards it must surface as UpdateFailed (see its docstring),
            # not as a raw exception HA logs as "unexpected error".
            self._consecutive_auth_failures = 0
            self._record_failure(ERROR_TYPE_RESPONSE)
            raise UpdateFailed(
                f"ubus method blocked or missing on OpenWrt router: {err}"
            ) from err

        except (RuntimeError, ValueError, TypeError, AttributeError, KeyError) as err:
            _LOGGER.exception("Unexpected error fetching OpenWrt data")
            self._record_failure(ERROR_TYPE_CONNECTION)
            raise UpdateFailed(f"Unexpected error: {err}") from err

        self._consecutive_auth_failures = 0
        self._failure_count = 0
        self._failure_since = None
        data.last_seen = datetime.now(UTC)
        data.consecutive_failures = 0
        data.error_type = None
        if self._outage_tracker is not None and self._entry is not None:
            self._outage_tracker.report_up(self._entry.entry_id)
        self._record_events(data)
        self._check_memory_pressure(data, data.last_seen)

        # SSH-Fallback-Erkennung: HA-Warnung + Poll auf 5 min reduzieren
        if self.api.uses_ssh_fallback and not self._ssh_fallback_notified:
            self._ssh_fallback_notified = True
            from homeassistant.components.persistent_notification import async_create

            async_create(
                self.hass,
                (
                    f"**{self.name}** verwendet SSH-Fallback für einige Datenabrufe, "
                    f"da ubus-Berechtigungen fehlen (z.B. `file/exec`, `file/stat`).\n\n"
                    f"Das erhöht die Router-Last erheblich.\n\n"
                    f"**Empfohlen:** Einstellungen → Geräte & Dienste → OpenWrt Router → "
                    f"**Konfigurieren** — der Berechtigungs-Check kann die rpcd-ACL "
                    f"automatisch auf den Router schreiben (ubus bzw. SSH-Fallback).\n\n"
                    f"Alternativ manuell mit `scripts/ha-openwrt-router.json` aus dem "
                    f"[Repository](https://github.com/magicx78/ha-openwrt-router):\n\n"
                    f"```\nscp scripts/ha-openwrt-router.json root@{self.api._host}:"
                    f"/usr/share/rpcd/acl.d/ha-openwrt-router.json\n"
                    f"ssh root@{self.api._host} /etc/init.d/rpcd restart\n```\n\n"
                    f"Poll-Intervall wurde auf 5 Minuten reduziert bis das Problem behoben ist."
                ),
                title=f"OpenWrt Router: SSH-Fallback aktiv ({self.api._host})",
                notification_id=f"openwrt_ssh_fallback_{self.api._host}",
            )
            self.update_interval = timedelta(seconds=300)
            _LOGGER.warning(
                "%s: SSH-Fallback aktiv — Poll auf 300s reduziert. "
                "ACL auf Router aktualisieren um ubus vollständig zu nutzen.",
                self.name,
            )

        # Adaptive polling: double interval when router is overloaded (load > 100%),
        # restore normal interval once load drops back below 80%.
        cpu = data.cpu_load
        normal_interval = timedelta(seconds=SCAN_INTERVAL_SECONDS)
        throttled_interval = timedelta(seconds=SCAN_INTERVAL_SECONDS * 2)
        if not self._throttled and cpu > 100:
            self._throttled = True
            self.update_interval = throttled_interval
            _LOGGER.warning(
                "%s: CPU load %.0f%% — reducing poll frequency to %ds",
                self.name,
                cpu,
                SCAN_INTERVAL_SECONDS * 2,
            )
        elif self._throttled and cpu < 80:
            self._throttled = False
            self.update_interval = normal_interval
            _LOGGER.info(
                "%s: CPU load %.0f%% — restoring normal poll frequency (%ds)",
                self.name,
                cpu,
                SCAN_INTERVAL_SECONDS,
            )

        return data

    # ------------------------------------------------------------------
    # Outage tracking
    # ------------------------------------------------------------------

    def attach_outage_tracker(self, tracker: FleetOutageTracker) -> None:
        """Report outages of this router to the fleet-wide tracker (wired in __init__)."""
        self._outage_tracker = tracker

    def _record_failure(self, error_type: str) -> None:
        """Count a failed poll; report the router as down past the threshold."""
        self._failure_count += 1
        if self._failure_since is None:
            self._failure_since = datetime.now(UTC)
        if self.data:
            self.data.error_type = error_type
            self.data.consecutive_failures = self._failure_count
        if (
            self._failure_count >= NOTIFICATION_FAILURE_THRESHOLD
            and self._outage_tracker is not None
            and self._entry is not None
        ):
            self._outage_tracker.report_down(
                self._entry.entry_id, error_type, self._failure_since
            )

    # ------------------------------------------------------------------
    # Router log
    # ------------------------------------------------------------------

    async def _ingest_log(self, data: OpenWrtCoordinatorData) -> None:
        """Fetch new logd lines, count them and fire Wi-Fi/DHCP events.

        Lines already in the buffer on the first fetch (or after a logd
        restart) are only counted. Without ``log read`` permission the status
        becomes ``not_permitted``; no error ever fails the poll.
        """
        try:
            entries = await self.api.get_log_entries(self._log_lines)
        except OpenWrtMethodNotFoundError as err:
            if self._log_status != LOG_STATUS_NOT_PERMITTED:
                _LOGGER.info(
                    "%s: router log not readable (rpcd ACL older than v6 or no "
                    "logd): %s",
                    self.name,
                    err,
                )
            self._log_status = LOG_STATUS_NOT_PERMITTED
            return
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("%s: router log fetch failed: %s", self.name, err)
            self._log_status = LOG_STATUS_ERROR
            return

        try:
            self._process_log(entries, data)
        except Exception:
            _LOGGER.debug("%s: router log processing failed", self.name, exc_info=True)
            self._log_status = LOG_STATUS_ERROR
            return
        self._log_status = LOG_STATUS_OK

    def _process_log(
        self, entries: list[dict[str, Any]], data: OpenWrtCoordinatorData
    ) -> None:
        result = self._log_cursor.ingest(entries)
        now_ms = int(time.time() * 1000)
        for event in result.events:
            # Router time only when plausible: a dumb AP without NTP sync
            # would otherwise put lines outside the 24 h window.
            ts = event.time_ms
            if not now_ms - 24 * 3600 * 1000 <= ts <= now_ms + 300_000:
                ts = now_ms
            self._log_counter.add(ts, event.key)
            if event.category == CATEGORY_WIFI and event.mac:
                if event.kind == WIFI_CONNECTED:
                    self._assoc.connected(event.mac, ts)
                elif event.kind == WIFI_DISCONNECTED:
                    self._assoc.disconnected(event.mac, ts)
            if (
                event.category == CATEGORY_DFS
                and event.interface
                and event.kind in DFS_EVIDENCE_KINDS
            ):
                # Evidence is compared with HA time: new lines count as "now"
                # (router clocks without NTP drift), baseline lines keep the
                # plausible router time.
                self._recent_dfs.append(
                    (
                        ts if result.baseline else now_ms,
                        self._phy_of_iface(event.interface, data),
                        event.kind,
                    )
                )
        self._log_totals["lines_processed"] += result.new_lines
        self._log_totals["missed_lines"] += result.missed
        if result.missed:
            self._log_lines = LOG_READ_LINES_MAX
        elif not result.baseline:
            self._log_lines = min(
                max(int(result.new_lines * 1.5) + 20, LOG_READ_LINES_MIN),
                LOG_READ_LINES_MAX,
            )
        if result.baseline:
            self._log_totals["baseline_lines"] += result.new_lines
            return
        fire, suppressed = self._log_limiter.select(result.events, now_ms)
        self._log_totals["events_suppressed"] += suppressed
        for event in fire:
            self._fire_log_event(event, data)
        self._log_totals["events_fired"] += len(fire)

    @staticmethod
    def _phy_of_iface(ifname: str, data: OpenWrtCoordinatorData) -> str:
        """phy of an AP interface: iwinfo's ``phy`` (wlan1 on older
        firmware), the name prefix (phy1-ap0) only as fallback."""
        for iface in data.ap_interfaces:
            if iface.get("ifname") == ifname and iface.get("phy"):
                return str(iface["phy"])
        return phy_of(ifname)

    def _router_device_id(self) -> str | None:
        """Device registry id of this router (logbook filters by device_id)."""
        if self._device_id is None and self._entry is not None:
            try:
                device = dr.async_get(self.hass).async_get_device(
                    identifiers={(DOMAIN, self._entry.entry_id)}
                )
            except Exception:  # noqa: BLE001
                device = None
            self._device_id = device.id if device is not None else None
        return self._device_id

    def _fire_log_event(self, event: LogEvent, data: OpenWrtCoordinatorData) -> None:
        """Fire the wifi/dhcp/dfs event for one log line."""
        if event.category == CATEGORY_DFS:
            self._fire_dfs_event(
                {
                    "type": event.kind,
                    "radio": self._phy_of_iface(event.interface or "", data),
                    "interface": event.interface,
                    "frequency": event.frequency,
                    "channel": event.channel,
                    "dfs_related": True,
                    "evidence": [event.kind],
                    "time": _iso_ms(event.time_ms),
                    "message": event.message,
                }
            )
            return
        hostname = None
        if event.mac:
            hostname = (data.dhcp_leases.get(event.mac) or {}).get("hostname")
            if not hostname:
                client = next(
                    (
                        c
                        for c in data.clients
                        if str(c.get(CLIENT_KEY_MAC, "")).upper() == event.mac
                    ),
                    None,
                )
                hostname = (client or {}).get("hostname")
        payload: dict[str, Any] = {
            "entry_id": self._entry.entry_id if self._entry else None,
            "device_id": self._router_device_id(),
            "router": self._entry.title if self._entry else self.name,
            "type": event.kind,
            "mac": event.mac,
            "hostname": hostname or None,
            "interface": event.interface,
            "time": _iso_ms(event.time_ms),
            "message": event.message,
        }
        if event.category == CATEGORY_DHCP:
            payload["ip"] = event.ip
            self.hass.bus.async_fire(EVENT_DHCP, payload)
        else:
            self.hass.bus.async_fire(EVENT_WIFI, payload)

    async def _fetch_usteer(self, now_ms: int) -> None:
        """Refresh sticky-client candidates from usteer."""
        try:
            raw = await self.api.get_usteer_clients()
        except OpenWrtMethodNotFoundError as err:
            if self._usteer_status != USTEER_STATUS_UNAVAILABLE:
                _LOGGER.debug("%s: usteer not available: %s", self.name, err)
            self._usteer_status = USTEER_STATUS_UNAVAILABLE
            self._sticky_now = {}
            self._sticky_timer.update(set(), now_ms)
            return
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("%s: usteer fetch failed: %s", self.name, err)
            return
        self._usteer_status = USTEER_STATUS_OK
        self._sticky_now = sticky_candidates(parse_usteer_clients(raw))
        self._sticky_timer.update(self._sticky_now, now_ms)

    def _client_stability_snapshot(
        self, data: OpenWrtCoordinatorData, now_ms: int
    ) -> dict[str, Any]:
        """Sticky/weak clients held >= STICKY_HOLD_SECONDS, 24 h counters."""
        names = {
            str(mac).upper(): (lease or {}).get("hostname")
            for mac, lease in data.dhcp_leases.items()
        }
        connected: dict[str, dict[str, Any]] = {}
        for client in data.clients:
            mac = str(client.get(CLIENT_KEY_MAC, "")).upper()
            if mac:
                connected[mac] = client
                names.setdefault(mac, client.get("hostname"))
        band_by_iface = {
            iface.get("ifname"): iface.get("band") for iface in data.ap_interfaces
        }

        weak = {
            mac: client
            for mac, client in connected.items()
            if isinstance(client.get("signal"), int)
            and client["signal"] != 0
            and client["signal"] <= WEAK_SIGNAL_DBM
        }
        self._weak_timer.update(weak, now_ms)
        held_weak = self._weak_timer.held(now_ms, STICKY_HOLD_SECONDS)
        held_sticky = self._sticky_timer.held(now_ms, STICKY_HOLD_SECONDS)
        counts = self._assoc.counts(now_ms)
        unstable = unstable_top(counts)
        for item in unstable:
            item["hostname"] = names.get(item["mac"]) or None
        return {
            "usteer": self._usteer_status,
            "sticky": [
                {
                    "mac": mac,
                    "hostname": names.get(mac) or None,
                    **self._sticky_now[mac],
                    "since": _iso_ms(since),
                }
                for mac, since in sorted(held_sticky.items())
                if mac in self._sticky_now and mac in connected
            ],
            "weak": [
                {
                    "mac": mac,
                    "hostname": names.get(mac) or None,
                    "signal": weak[mac]["signal"],
                    "band": band_by_iface.get(weak[mac].get("radio")),
                    "since": _iso_ms(since),
                }
                for mac, since in sorted(held_weak.items())
                if mac in weak
            ],
            "clients": counts,
            "unstable": unstable,
            "unstable_count": sum(
                1 for c in counts.values() if c["reconnects_24h"] >= UNSTABLE_RECONNECTS
            ),
        }

    async def _fetch_dhcp_config(self) -> None:
        """Refresh pools and static hosts; keep the old ones on errors."""
        try:
            values = await self.api.get_dhcp_config()
        except OpenWrtMethodNotFoundError as err:
            _LOGGER.debug("%s: uci dhcp not readable: %s", self.name, err)
            self._dhcp_config_fetched = True
            return
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("%s: uci dhcp fetch failed: %s", self.name, err)
            return
        self._dhcp_config_fetched = True
        self._dhcp_pools, self._dhcp_static_macs = parse_dhcp_config(values)

    def _detect_channel_changes(
        self, data: OpenWrtCoordinatorData
    ) -> list[tuple[Radio, Radio]]:
        """Return (before, after) per radio whose channel or width changed.

        An empty poll (iwinfo failed) keeps the previous state. A radio
        missing from a non-empty poll (switched off) is forgotten, so coming
        back on another channel later is not reported as a change. Without
        ``htmode`` the width is unknown and the previous one is kept.
        """
        current = {
            (r.phy, r.band): r
            for r in radios_from_ap_interfaces(
                "", "", data.ap_interfaces, data.sta_interfaces
            )
        }
        if not current:
            return []
        no_htmode = {
            str(iface.get("phy") or phy_of(str(iface.get("ifname") or "")))
            for iface in data.ap_interfaces
            if not iface.get("htmode")
        }
        previous, self._prev_radios = self._prev_radios, current
        if previous is None:
            return []
        changes: list[tuple[Radio, Radio]] = []
        for key, after in current.items():
            before = previous.get(key)
            if before is None:
                continue
            if after.phy in no_htmode:
                after = replace(after, width=before.width)
                current[key] = after
            if (before.channel, before.width) != (after.channel, after.width):
                changes.append((before, after))
        return changes

    def _fire_channel_change(self, change: tuple[Radio, Radio]) -> None:
        """Fire a channel_change DFS event; DFS-related only with log evidence."""
        before, after = change
        now_ms = int(time.time() * 1000)
        cutoff = now_ms - DFS_EVIDENCE_SECONDS * 1000
        evidence = (
            sorted(
                {
                    kind
                    for ts, phy, kind in self._recent_dfs
                    if phy == after.phy and ts >= cutoff
                }
            )
            if after.band == "5g"  # DFS exists only in 5 GHz
            else []
        )
        self._channel_changes.add(now_ms, DFS_CHANNEL_CHANGE)
        self._fire_dfs_event(
            {
                "type": DFS_CHANNEL_CHANGE,
                "radio": after.phy,
                "band": after.band,
                "old_channel": before.channel,
                "new_channel": after.channel,
                "old_width_mhz": before.width,
                "new_width_mhz": after.width,
                "dfs_related": bool(evidence),
                "evidence": evidence,
                "backhaul": after.backhaul,
                "time": _iso_ms(now_ms),
            }
        )
        _LOGGER.info(
            "%s: %s channel %s/%s MHz → %s/%s MHz%s",
            self.name,
            after.phy,
            before.channel,
            before.width,
            after.channel,
            after.width,
            f" (DFS: {', '.join(evidence)})" if evidence else "",
        )

    def _fire_dfs_event(self, fields: dict[str, Any]) -> None:
        payload: dict[str, Any] = {
            "entry_id": self._entry.entry_id if self._entry else None,
            "device_id": self._router_device_id(),
            "router": self._entry.title if self._entry else self.name,
            **fields,
        }
        self._last_dfs_event = payload
        self.hass.bus.async_fire(EVENT_DFS, payload)

    # ------------------------------------------------------------------
    # RAM pressure
    # ------------------------------------------------------------------

    def _check_memory_pressure(
        self, data: OpenWrtCoordinatorData, now: datetime
    ) -> None:
        """Raise/clear the ``ram_high_<entry_id>`` Repairs issue.

        High = pressure above RAM_PRESSURE_HIGH_PCT or available RAM below
        RAM_AVAILABLE_MIN_BYTES. The issue appears after the router stayed
        high for RAM_PRESSURE_HOLD_SECONDS without a single normal reading in
        between, and disappears once the pressure is below
        RAM_PRESSURE_CLEAR_PCT with enough RAM available (hysteresis). Polls
        without usable memory stats change nothing; a gap of more than two
        poll intervals since the last usable reading (router unreachable)
        restarts the hold time.
        """
        pressure = data.memory_pressure
        if not pressure:
            return
        last_check, self._mem_last_check = self._mem_last_check, now
        interval = self.update_interval or timedelta(seconds=SCAN_INTERVAL_SECONDS)
        if last_check is not None and now - last_check > 2 * interval:
            self._mem_high_since = None
        pct = pressure["pressure_ratio"] * 100.0
        low_available = pressure["available_bytes"] < RAM_AVAILABLE_MIN_BYTES
        high = pct > RAM_PRESSURE_HIGH_PCT or low_available

        if self._ram_issue_active:
            if pct < RAM_PRESSURE_CLEAR_PCT and not low_available:
                self._ram_issue_active = False
                self._mem_high_since = None
                if self._entry is not None:
                    async_clear_issue(
                        self.hass, ram_high_issue_id(self._entry.entry_id)
                    )
                _LOGGER.info("%s: RAM pressure back to normal (%.1f%%)", self.name, pct)
            return

        if not high:
            self._mem_high_since = None
            return
        if self._mem_high_since is None:
            self._mem_high_since = now
        if (now - self._mem_high_since).total_seconds() < RAM_PRESSURE_HOLD_SECONDS:
            return

        self._ram_issue_active = True
        since = dt_util.as_local(self._mem_high_since).strftime("%Y-%m-%d %H:%M")
        if self._entry is not None:
            async_raise_issue(
                self.hass,
                ram_high_issue_id(self._entry.entry_id),
                ISSUE_RAM_HIGH,
                ir.IssueSeverity.WARNING,
                {
                    "router": self._entry.title,
                    "pressure": f"{pressure['pressure_pct']:.0f}",
                    "available_mb": f"{pressure['available_mb']:.0f}",
                    "since": since,
                },
            )
        _LOGGER.warning(
            "%s: RAM pressure %.1f%% (%.1f MB available) since %s",
            self.name,
            pct,
            pressure["available_mb"],
            since,
        )

    # ------------------------------------------------------------------
    # Event timeline
    # ------------------------------------------------------------------

    def _record_events(self, data: OpenWrtCoordinatorData) -> None:
        """Detect state changes and append events to the ring buffer."""
        ts = int(time.time())

        # WAN connect / disconnect
        if (
            self._prev_wan_connected is not None
            and data.wan_connected != self._prev_wan_connected
        ):
            if data.wan_connected:
                self._event_history.appendleft(
                    {
                        "ts": ts,
                        "type": "info",
                        "message": "WAN verbunden",
                        "detail": data.wan_status.get("ipv4_address")
                        or data.wan_status.get("address")
                        or "",
                    }
                )
            else:
                self._event_history.appendleft(
                    {
                        "ts": ts,
                        "type": "error",
                        "message": "WAN getrennt",
                    }
                )
        self._prev_wan_connected = data.wan_connected

        # CPU spike (>= 80%) / recovery (< 65%)
        cpu = data.cpu_load
        if not self._cpu_warn_active and cpu >= 80:
            self._cpu_warn_active = True
            self._event_history.appendleft(
                {
                    "ts": ts,
                    "type": "warn",
                    "message": "CPU-Last erhöht",
                    "detail": f"{cpu:.0f}%",
                }
            )
        elif self._cpu_warn_active and cpu < 65:
            self._cpu_warn_active = False
            self._event_history.appendleft(
                {
                    "ts": ts,
                    "type": "info",
                    "message": "CPU-Last normalisiert",
                    "detail": f"{cpu:.0f}%",
                }
            )

        # Memory spike (>= 90%) / recovery (< 80%)
        # Use effective pressure: exclude reclaimable kernel buffers so a
        # large disk-cache doesn't falsely trigger the warning threshold.
        # Formula: (total - free - buffered) / total
        mem_total = data.memory.get("total", 0) or 0
        mem_free = data.memory.get("free", 0) or 0
        mem_buffered = data.memory.get("buffered", 0) or 0
        mem_pct = (
            round(100 * (mem_total - mem_free - mem_buffered) / mem_total)
            if mem_total > 0
            else 0
        )
        if not self._mem_warn_active and mem_pct >= 90:
            self._mem_warn_active = True
            self._event_history.appendleft(
                {
                    "ts": ts,
                    "type": "warn",
                    "message": "RAM-Auslastung erhöht",
                    "detail": f"{mem_pct}%",
                }
            )
        elif self._mem_warn_active and mem_pct < 80:
            self._mem_warn_active = False
            self._event_history.appendleft(
                {
                    "ts": ts,
                    "type": "info",
                    "message": "RAM-Auslastung normalisiert",
                    "detail": f"{mem_pct}%",
                }
            )

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
