"""DataUpdateCoordinator for the OpenWrt Router integration."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from collections.abc import Callable
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
    OpenWrtAuthBackoffError,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtMethodNotFoundError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
    OpenWrtUpdateCheckRunningError,
)
from .channel_plan import Radio, phy_of, radios_from_ap_interfaces
from .client_stability import (
    STICKY_HOLD_SECONDS,
    UNSTABLE_RECONNECTS,
    WEAK_SIGNAL_DBM,
    AssociationTracker,
    HoldTimer,
    iface_band,
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
    CPU_HISTORY_WINDOW_SECONDS,
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
    SSH_FALLBACK_INTERVAL_SECONDS,
    THROTTLED_INTERVAL_SECONDS,
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

# WAN rate averaging window bounds (seconds between two counter samples).
# Below the minimum (a manual refresh right after a poll) the average is too
# noisy; above the maximum (long outage) it no longer describes "now".
_WAN_RATE_MIN_INTERVAL_S = 5.0
_WAN_RATE_MAX_INTERVAL_S = 900.0


def _as_counter(value: Any) -> int | None:
    """Return a byte counter as a non-negative int, else None.

    The ubus path delivers ints; the SSH status script may deliver numeric
    strings or floats. Booleans are never counters.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value >= 0:
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


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


def _cpu_load_basis(data: OpenWrtCoordinatorData) -> str:
    """Describe what a cpu_load percentage refers to (throttle log lines)."""
    if data.cpu_cores:
        basis = f"{data.cpu_cores} core(s)"
    else:
        basis = "core count unknown, not normalised"
    if data.load_average:
        basis += f", load average {data.load_average[0]:.2f}"
    return basis


class OpenWrtCoordinatorData:
    """Typed container for data fetched by the coordinator each poll cycle.

    Attributes:
        router_info: Static board information (model, hostname, release).
        uptime: System uptime in seconds.
        cpu_load: 1-minute load as % of total CPU capacity (load average
            divided by cpu_cores; above 100 the run queue exceeds the cores).
        cpu_cores: Logical CPU count used for cpu_load, None = unknown (then
            cpu_load is not divided, i.e. 1 core is assumed).
        load_average: Raw 1/5/15-minute load averages, e.g. [1.22, 0.9, 0.7];
            empty when unknown (SSH fallback).
        memory: Memory stats dict (total, free, shared, buffered bytes).
        wan_status: WAN interface status dict.
        wan_connected: Convenience bool derived from wan_status.
        wifi_radios: List of normalised radio / SSID descriptors.
        clients: List of currently associated WiFi clients (ip/hostname enriched).
        client_count: Number of connected clients.
        dhcp_leases: MAC → {ip, hostname} mapping from the DHCP lease table.
        updates_available: Result of the last "check for updates" (count,
            package list, package manager, last_check); last_check is None
            until the first check. Carried across polls, never polled.
        features: Feature detection map (populated on first refresh).
    """

    def __init__(self) -> None:
        """Initialise with sensible defaults."""
        self.router_info: dict[str, Any] = {}
        self.uptime: int = 0
        self.cpu_load: float = 0.0
        self.cpu_load_5min: float = 0.0
        self.cpu_load_15min: float = 0.0
        self.cpu_cores: int | None = None
        self.load_average: list[float] = []
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
            "count": 0,
            "packages": [],
            "system": [],
            "addons": [],
            "package_manager": None,
            "index_refreshed": None,
            "last_check": None,
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
        # False on the first poll, which skips the ping: ping_ms None then
        # means "not measured yet", not "no answer".
        self.ping_checked: bool = False
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
            "cpu_cores": self.cpu_cores,
            "load_average": self.load_average,
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
            # Per-client counters (MACs) stay out of diagnostics
            "client_stability": {
                k: v for k, v in self.client_stability.items() if k != "clients"
            },
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
        # The stagger offset delays only the first *scheduled* poll; refreshes
        # requested by switches/buttons are never delayed.
        self._stagger_pending = poll_offset_seconds > 0
        self._poll_count = 0
        # One warning with traceback per streak of unexpected poll errors
        self._unexpected_error_logged = False
        self._throttled = False  # True when interval is doubled due to high CPU load
        self._ssh_fallback_notified = False  # True after HA notification was fired
        self._client_first_seen: dict[str, datetime] = {}
        self._prev_interface_bytes: dict[str, dict[str, int | None]] = {}
        self._prev_poll_time: datetime | None = None
        # Last valid WAN counter sample (monotonic time, rx, tx, interface)
        self._wan_sample: tuple[float, int, int, str] | None = None
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
        self._last_usteer_poll: int | None = None
        # Fleet lookup usteer node -> (band, ssid), wired in __init__
        self._node_resolver: Callable[[], dict[str, Any]] | None = None
        self._channel_changes = RollingCounter(24 * 3600 * 1000, max_items=500)
        # Poll number of the last log fetch: a fetch pulled forward by a
        # channel change restarts the LOG_READ_INTERVAL_CYCLES rhythm, so the
        # adaptive line count always covers the same span.
        self._last_log_poll: int | None = None
        # Stale-data cache: letzte bekannte Werte für VLAN-Badges bei Offline-Router
        self._last_known_network_interfaces: list[dict[str, Any]] = []
        self._last_known_port_vlan_map: dict[str, list[int]] = {}
        # Result of the last package update check (button press only — polls
        # never run the package manager) and a lock against parallel checks.
        self._package_updates: dict[str, Any] | None = None
        self._package_check_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # DataUpdateCoordinator interface
    # ------------------------------------------------------------------

    async def _handle_refresh_interval(self, _now: datetime | None = None) -> None:
        """Run a scheduled poll; delay the first one by the stagger offset.

        Spreads multiple coordinators evenly across the scan interval. Only
        the timer path comes through here — ``async_request_refresh`` (switch,
        button) never waits for the offset. If a requested refresh ran during
        the wait it already scheduled the next poll, so this one is dropped.
        """
        if self._stagger_pending:
            self._stagger_pending = False
            _LOGGER.debug(
                "Stagger offset: delaying first scheduled poll by %ds",
                self._poll_offset_seconds,
            )
            # The handle of the timer that fired is still stored here (the
            # base method clears it). Clear it now so that a non-None value
            # after the wait means a requested refresh rescheduled meanwhile.
            self._unsub_refresh = None
            await asyncio.sleep(self._poll_offset_seconds)
            if self._unsub_refresh is not None:
                return
        await super()._handle_refresh_interval(_now)

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
        try:
            return await self._async_poll()
        finally:
            # The API keeps one SSH connection open for the duration of a poll
            # (fallback paths, LLDP). Release it when the poll is over — also
            # after a failure — so the router does not hold an idle session
            # until the next poll.
            release = getattr(self.api, "async_release_ssh", None)
            if release is not None:
                try:
                    await release()
                except Exception:
                    _LOGGER.debug("Releasing the SSH connection failed", exc_info=True)

    async def _async_poll(self) -> OpenWrtCoordinatorData:
        """Run one poll cycle (body of :meth:`_async_update_data`)."""
        self._poll_count += 1
        self.api.reset_ssh_fallback_flag()

        data = OpenWrtCoordinatorData()
        if self._package_updates is not None:
            data.updates_available = self._package_updates

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
            # Time of the counter read; the rate below is computed later in the
            # poll, after calls whose duration varies from poll to poll.
            wan_sampled_at = time.monotonic()
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

            # --- Native WAN throughput (bit/s) ---
            # Pure arithmetic on the WAN byte counters already fetched above —
            # no network call, so it is not gated by the first-poll skip below.
            data.wan_traffic = self._compute_wan_traffic(
                data.wan_status, wan_sampled_at
            )

            # --- Ping + DuckDNS ---
            # Skipped on cycle 1 (first_refresh at startup) to avoid blocking
            # HA bootstrap. The ping/DDNS calls have external timeouts that would
            # push startup past HA's stage-2 deadline with multiple coordinators.
            if self._board_poll_count > 1:
                data.ping_checked = True
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
            data.cpu_cores = status.get("cpu_cores")
            data.load_average = status.get("load_average") or []
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

            # One `network.device status {}` per poll feeds both the interface
            # byte counters and the port stats.
            try:
                device_status = await self.api.get_device_status()
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching device status: %s", err)
                device_status = {}

            try:
                data.network_interfaces = await self.api.get_network_interfaces(
                    device_status=device_status
                )
                if data.network_interfaces:
                    self._last_known_network_interfaces = data.network_interfaces
                data.vlans_stale = False
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Error fetching network interfaces: %s", err)
                # Copies without rates: stale counters must not read as 0 B/s.
                data.network_interfaces = [
                    {**iface, "rx_rate": None, "tx_rate": None}
                    for iface in self._last_known_network_interfaces
                ]
                data.vlans_stale = bool(self._last_known_network_interfaces)

            try:
                data.port_stats = await self.api.get_port_stats(
                    device_status=device_status
                )
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

            # Client stability (F4): usteer every LOG_READ_INTERVAL_CYCLES
            # polls but never in the same poll as the log (spreads the two
            # ~40 KB answers). Never fails the poll.
            usteer_interval = (
                USTEER_RETRY_CYCLES
                if self._usteer_status == USTEER_STATUS_UNAVAILABLE
                else LOG_READ_INTERVAL_CYCLES
            )
            if (
                self._board_poll_count > 1
                and self._last_log_poll != self._board_poll_count
                and (
                    self._last_usteer_poll is None
                    or self._board_poll_count - self._last_usteer_poll
                    >= usteer_interval
                )
            ):
                self._last_usteer_poll = self._board_poll_count
                await self._fetch_usteer(data, now_ms)
            data.client_stability = self._client_stability_snapshot(data, now_ms)

            # --- CPU history (one point per poll, time-based 1h window) ---
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
            cutoff = int(_time.time()) - CPU_HISTORY_WINDOW_SECONDS
            while self._cpu_history and self._cpu_history[0]["ts"] < cutoff:
                self._cpu_history.popleft()
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
            # A rate needs two valid samples of the same interface. Without
            # one (first sample, new interface, unknown counter, counter
            # reset) the rate is None — unknown, not 0 B/s. A stale cache
            # (interface fetch failed) keeps the previous baseline.
            if not data.vlans_stale:
                poll_now = datetime.now(UTC)
                elapsed = (
                    (poll_now - self._prev_poll_time).total_seconds()
                    if self._prev_poll_time is not None
                    else 0.0
                )
                for iface in data.network_interfaces:
                    prev = self._prev_interface_bytes.get(iface.get("interface", ""))
                    for key, rate_key in (
                        ("rx_bytes", "rx_rate"),
                        ("tx_bytes", "tx_rate"),
                    ):
                        curr = iface.get(key)
                        prev_val = prev.get(key) if prev else None
                        if (
                            elapsed > 0
                            and isinstance(curr, int)
                            and isinstance(prev_val, int)
                            and curr >= prev_val
                        ):
                            iface[rate_key] = round((curr - prev_val) / elapsed, 2)
                        else:
                            iface[rate_key] = None
                self._prev_poll_time = poll_now
                # Rebuild from current interfaces only — removes stale entries
                # for interfaces that no longer exist (tunnels, temporary VLANs)
                self._prev_interface_bytes = {
                    iface.get("interface", ""): {
                        "rx_bytes": iface.get("rx_bytes"),
                        "tx_bytes": iface.get("tx_bytes"),
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

        except OpenWrtAuthBackoffError as err:
            # Blocked by the API's auth backoff without a login attempt: a
            # failed poll, but no new evidence against the credentials, so it
            # does not count towards the reauth threshold.
            self._record_failure(ERROR_TYPE_AUTH)
            raise UpdateFailed(f"Authentication backoff active: {err}") from err

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

        except (ConfigEntryAuthFailed, UpdateFailed):
            raise

        except Exception as err:
            # Anything else (OSError, IndexError, a parser bug, ...) must still
            # count as a failed poll, otherwise the outage counter and the
            # fleet Repairs issue stay silent. CancelledError is a
            # BaseException and passes through untouched.
            self._record_failure(ERROR_TYPE_CONNECTION)
            if not self._unexpected_error_logged:
                self._unexpected_error_logged = True
                _LOGGER.warning(
                    "%s: Unexpected error fetching OpenWrt data",
                    self.name,
                    exc_info=True,
                )
            else:
                _LOGGER.debug(
                    "%s: Unexpected error fetching OpenWrt data: %r", self.name, err
                )
            raise UpdateFailed(f"Unexpected error: {err!r}") from err

        self._unexpected_error_logged = False
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
            _LOGGER.warning(
                "%s: SSH-Fallback aktiv — Poll auf %ds reduziert. "
                "ACL auf Router aktualisieren um ubus vollständig zu nutzen.",
                self.name,
                SSH_FALLBACK_INTERVAL_SECONDS,
            )

        # Adaptive polling: double interval when router is overloaded (load > 100%),
        # restore normal interval once load drops back below 80%. cpu_load is
        # per core (% of total CPU capacity), so > 100% means the run queue
        # really exceeds the cores — not just a load average above 1.0.
        cpu = data.cpu_load
        if not self._throttled and cpu > 100:
            self._throttled = True
            _LOGGER.warning(
                "%s: CPU load %.0f%% (%s) — reducing poll frequency to %ds",
                self.name,
                cpu,
                _cpu_load_basis(data),
                THROTTLED_INTERVAL_SECONDS,
            )
        elif self._throttled and cpu < 80:
            self._throttled = False
            _LOGGER.info(
                "%s: CPU load %.0f%% (%s) — restoring normal poll frequency (%ds)",
                self.name,
                cpu,
                _cpu_load_basis(data),
                SCAN_INTERVAL_SECONDS,
            )

        # Derived from the current state on every poll, so a repaired ACL or
        # a recovered CPU takes effect without a reload.
        self.update_interval = self._interval_for_state()

        return data

    def _interval_for_state(self) -> timedelta:
        """Return the poll interval for the state of the last poll.

        SSH fallback (300 s) wins over CPU throttling (120 s); otherwise the
        default scan interval applies.
        """
        if self.api.uses_ssh_fallback:
            return timedelta(seconds=SSH_FALLBACK_INTERVAL_SECONDS)
        if self._throttled:
            return timedelta(seconds=THROTTLED_INTERVAL_SECONDS)
        return timedelta(seconds=SCAN_INTERVAL_SECONDS)

    # ------------------------------------------------------------------
    # WAN throughput
    # ------------------------------------------------------------------

    def _compute_wan_traffic(
        self, wan_status: dict[str, Any], now: float
    ) -> dict[str, Any]:
        """Return the WAN throughput in bit/s from two byte-counter samples.

        The rate is the counter delta divided by the *measured* time between
        the counter reads (``now`` = monotonic time of this read): the poll
        interval is adaptive (60/120/300 s) and manual refreshes shorten it,
        so a fixed divisor would be wrong.

        A failed counter read keeps the last valid sample, so the next valid
        read averages over the longer gap instead of producing a spike from
        a zero baseline. A refresh right after a poll keeps the last rate.
        Counters of a different interface (fallback to another "up"
        interface) start a new baseline instead of being compared.

        Returns:
            ``{"downstream_bps", "upstream_bps", "interval_s", "sampled_at"}``
            or ``{}`` when there is no usable previous sample, a counter went
            backwards (interface restart, reboot) or the gap is too long.
        """
        rx = _as_counter(wan_status.get("rx_bytes"))
        tx = _as_counter(wan_status.get("tx_bytes"))
        if rx is None or tx is None:
            return {}
        iface = str(wan_status.get("interface") or "")

        prev = self._wan_sample
        if (
            prev is not None
            and prev[3] == iface
            and now - prev[0] < _WAN_RATE_MIN_INTERVAL_S
        ):
            return self.data.wan_traffic if self.data else {}
        self._wan_sample = (now, rx, tx, iface)
        if prev is None or prev[3] != iface:
            return {}

        elapsed = now - prev[0]
        rx_delta = rx - prev[1]
        tx_delta = tx - prev[2]
        if elapsed > _WAN_RATE_MAX_INTERVAL_S or rx_delta < 0 or tx_delta < 0:
            return {}
        return {
            "downstream_bps": round(rx_delta * 8 / elapsed),
            "upstream_bps": round(tx_delta * 8 / elapsed),
            "interval_s": round(elapsed),
            "sampled_at": datetime.now(UTC).isoformat(),
        }

    # ------------------------------------------------------------------
    # Outage tracking
    # ------------------------------------------------------------------

    async def async_check_package_updates(self) -> dict[str, Any]:
        """Run the package update check and publish the result.

        Called on user request (button) only. The result is kept on the
        coordinator so every following poll carries it forward without
        running the package manager again.

        Raises:
            OpenWrtUpdateCheckRunningError: A check is already running; a
                second one is refused instead of queueing behind it.
            OpenWrtUpdateCheckError: Propagated from the API.
        """
        if self._package_check_lock.locked():
            raise OpenWrtUpdateCheckRunningError(
                "An update check is already running on this router"
            )
        async with self._package_check_lock:
            result = await self.api.check_package_updates()
        packages: list[dict[str, str]] = result.get("packages", [])
        # LuCI and add-on packages apart from the base system, as before.
        addons = [p for p in packages if p["name"].startswith(("addon-", "luci-"))]
        system = [p for p in packages if p not in addons]
        updates: dict[str, Any] = {
            "available": bool(packages),
            "count": len(packages),
            "packages": packages,
            "system": system,
            "addons": addons,
            "package_manager": result.get("package_manager"),
            "index_refreshed": result.get("index_refreshed"),
            "last_check": dt_util.utcnow().isoformat(),
        }
        self._package_updates = updates
        if self.data is not None:
            self.data.updates_available = updates
            self.async_update_listeners()
        return updates

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
            plausible = now_ms - 24 * 3600 * 1000 <= ts <= now_ms + 300_000
            if not plausible:
                ts = now_ms
            self._log_counter.add(ts, event.key)
            # Old baseline lines with an unusable time would land at "now"
            # and pair up as reconnects: leave them out of the client stats.
            if (
                event.category == CATEGORY_WIFI
                and event.mac
                and (plausible or not result.baseline)
            ):
                if event.kind == WIFI_CONNECTED:
                    self._assoc.connected(event.mac, ts, event.interface)
                elif event.kind == WIFI_DISCONNECTED:
                    self._assoc.disconnected(event.mac, ts, event.interface)
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
        """Device registry id of this router (logbook filters by device_id).

        Looked up in this entry's own devices via
        ``async_get_device_by_identifier`` (HA 2026.8+). Older cores (floor
        2026.2) only have ``async_get_device``, deprecated since 2026.9 and
        removed in 2027.8.
        """
        if self._device_id is None and self._entry is not None:
            identifier = (DOMAIN, self._entry.entry_id)
            try:
                dev_reg = dr.async_get(self.hass)
                get_by_identifier = getattr(
                    dev_reg, "async_get_device_by_identifier", None
                )
                if get_by_identifier is not None:
                    device = get_by_identifier(identifier, self._entry.entry_id)
                else:
                    device = dev_reg.async_get_device(identifiers={identifier})
            except Exception:
                _LOGGER.debug(
                    "%s: router device lookup failed", self.name, exc_info=True
                )
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

    def attach_node_resolver(self, resolver: Callable[[], dict[str, Any]]) -> None:
        """Fleet lookup for usteer remote nodes (wired in __init__)."""
        self._node_resolver = resolver

    async def _fetch_usteer(self, data: OpenWrtCoordinatorData, now_ms: int) -> None:
        """Refresh sticky-client candidates from usteer.

        Not permitted or no usteer object (uhttpd answers "object not found"
        as response error) → ``not_available`` and the signal fallback; any
        other error drops the candidates so nothing stale stays sticky.
        """
        try:
            raw = await self.api.get_usteer_clients()
        except (OpenWrtMethodNotFoundError, OpenWrtResponseError) as err:
            if self._usteer_status != USTEER_STATUS_UNAVAILABLE:
                _LOGGER.debug("%s: usteer not available: %s", self.name, err)
            self._usteer_status = USTEER_STATUS_UNAVAILABLE
            self._sticky_now = {}
            self._sticky_timer.update(set(), now_ms)
            return
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("%s: usteer fetch failed: %s", self.name, err)
            self._sticky_now = {}
            self._sticky_timer.update(set(), now_ms)
            return
        node_info: dict[str, Any] = {
            f"hostapd.{iface.get('ifname')}": (
                iface_band(iface),
                iface.get("ssid") or None,
            )
            for iface in data.ap_interfaces
            if iface.get("ifname")
        }
        if self._node_resolver is not None:
            try:
                node_info.update(self._node_resolver())
            except Exception:
                _LOGGER.debug("%s: usteer node lookup failed", self.name, exc_info=True)
        self._usteer_status = USTEER_STATUS_OK
        self._sticky_now = sticky_candidates(parse_usteer_clients(raw), node_info)
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
                        "detail": data.wan_status.get("ipv4") or "",
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
