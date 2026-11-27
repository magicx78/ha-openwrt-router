"""Constants for the OpenWrt Router integration."""

from __future__ import annotations

# Integration domain
DOMAIN = "openwrt_router"
INTEGRATION_NAME = "OpenWrt Router"

# Default connection values
DEFAULT_HOST = ""
DEFAULT_PORT = 443
DEFAULT_USERNAME = "root"
DEFAULT_PROTOCOL = "https-insecure"

# Protocol options
PROTOCOL_HTTP = "http"
PROTOCOL_HTTPS = "https"
PROTOCOL_HTTPS_INSECURE = "https-insecure"


def url_scheme_for(protocol: str) -> str:
    """Return the URL scheme for a stored protocol value.

    `https-insecure` is an internal marker meaning "HTTPS without certificate
    verification". HA's device_registry rejects any configuration_url whose
    scheme is not `http` or `https` (ValueError), so we must collapse the
    marker back to `https` whenever we build a URL that HA might validate.
    """
    return (
        "https" if protocol == PROTOCOL_HTTPS_INSECURE else (protocol or PROTOCOL_HTTP)
    )


# HTTP / ubus
UBUS_PATH = "/ubus"
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_SESSION_ID = "00000000000000000000000000000000"

# Session management
# OpenWrt default rpcd TTL is 300s regardless of the requested timeout.
# We track expiry and refresh 60s before deadline to avoid mid-poll expiry.
SESSION_LIFETIME_SECONDS = 300
SESSION_REFRESH_MARGIN_SECONDS = 60

# rpcd's `file read` returns at most 4 KiB of a procfs file. An ARP read of
# this size (or with an incomplete last line) is treated as truncated and
# supplemented by luci-rpc getHostHints.
ARP_READ_TRUNCATION_BYTES = 4000

# Fallback of api.get_active_connections over /proc/net/nf_conntrack (1.49.1,
# Traffic Analytics F2 / risk 3): bounded in time, bytes and counted lines.
# A read near rpcd's procfs size (CONNTRACK_READ_TRUNCATION_BYTES, below),
# a cut last line or a cap reached makes the count a lower bound
# (api.last_conntrack_count_complete is False). Same file/read call as
# before (no file/exec, whose large output leaks rpcd memory; no new ACL).
CONNTRACK_TABLE_TIMEOUT_S = 5.0
CONNTRACK_TABLE_MAX_BYTES = 256 * 1024
CONNTRACK_TABLE_MAX_LINES = 2048
# rpcd reads a procfs file with one read() of 4096 bytes and the kernel hands
# out whole conntrack lines only (190-340 bytes each, more with labels, zone
# or secctx), so a cut table ends on a newline and is often well below 4000
# bytes (1.49.3 review: 1170 of 2000 cut tables passed the old check). A reply
# is cut once it is so large that one more line might not have fitted:
# 4096 minus the longest line we assume (600 bytes) = 3496 bytes.
CONNTRACK_RPCD_READ_BYTES = 4096
CONNTRACK_LINE_MAX_BYTES = 600
CONNTRACK_READ_TRUNCATION_BYTES = CONNTRACK_RPCD_READ_BYTES - CONNTRACK_LINE_MAX_BYTES

# Server-side rpcd session timeout requested at login.
# Must be comfortably larger than the client refresh interval
# (SESSION_LIFETIME_SECONDS) so a session never expires mid-poll, but small
# enough that an orphaned session (one whose explicit destroy failed because
# the router was briefly unreachable) self-heals quickly instead of lingering.
# NOTE: every login destroys the previous session (see OpenWrtAPI.login), so
# sessions do not accumulate; this value only bounds the lifetime of a rare
# orphan. Keep > SESSION_LIFETIME_SECONDS.
SESSION_LOGIN_TIMEOUT_SECONDS = 600

# Update interval
SCAN_INTERVAL_SECONDS = 60
# Interval while the router is overloaded (CPU load > 100 % per core)
THROTTLED_INTERVAL_SECONDS = SCAN_INTERVAL_SECONDS * 2
# Interval while the last poll needed the SSH fallback (rpcd ACL incomplete);
# takes precedence over throttling. Derived anew on every poll.
SSH_FALLBACK_INTERVAL_SECONDS = 300

# How many poll cycles between re-fetching static board info (model, hostname, release).
# 10 cycles × 60 s = ~10 minutes.  Hostname changes are rare; this avoids a
# system/board call on every poll while still detecting changes eventually.
BOARD_REFRESH_CYCLES = 10

# Config entry keys
CONF_HOST = "host"
CONF_PORT = "port"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_PROTOCOL = "protocol"

# Runtime data keys (stored in coordinator / entry.runtime_data)
DATA_COORDINATOR = "coordinator"
DATA_API = "api"

# ubus subsystems / methods
UBUS_SESSION_LOGIN = "session"
UBUS_SESSION_METHOD_LOGIN = "login"
UBUS_SESSION_METHOD_DESTROY = "destroy"
UBUS_SESSION_OBJECT_LOGIN = "session"

UBUS_SYSTEM_OBJECT = "system"
UBUS_SYSTEM_BOARD = "board"
UBUS_SYSTEM_INFO = "info"
UBUS_SYSTEM_REBOOT = "reboot"

UBUS_NETWORK_OBJECT = "network.interface"
UBUS_NETWORK_DUMP = "dump"
UBUS_NETWORK_INTERFACE = "status"

UBUS_DEVICE_OBJECT = "network.device"
UBUS_DEVICE_STATUS = "status"

UBUS_IWINFO_OBJECT = "iwinfo"
UBUS_IWINFO_INFO = "info"
UBUS_IWINFO_ASSOCLIST = "assoclist"
UBUS_IWINFO_SCAN = "scan"

UBUS_WIRELESS_OBJECT = "network.wireless"
UBUS_WIRELESS_STATUS = "status"

UBUS_UCI_OBJECT = "uci"
UBUS_UCI_GET = "get"
UBUS_UCI_SET = "set"
UBUS_UCI_COMMIT = "commit"

UBUS_NETWORK_RELOAD = "network"
UBUS_NETWORK_RELOAD_METHOD = "reload"

# rpcd file module (for reading /tmp/dhcp.leases)
UBUS_FILE_OBJECT = "file"
UBUS_FILE_READ = "read"
DHCP_LEASES_PATH = "/tmp/dhcp.leases"

# Known WAN interface names (OpenWrt conventions across versions), matched
# exactly; the stems in WAN_INTERFACE_PREFIXES also match with a suffix
# ("wan6", "wwan0", "wan_lte", "lte1"). See api.is_wan_interface().
WAN_INTERFACE_NAMES = (
    "wan",
    "wan6",
    "pppoe-wan",
    "wwan",
    "lte",
    "modem",
    "umts",
    "3g",
    "4g",
    "5g",
)
WAN_INTERFACE_PREFIXES = ("wan", "wwan", "lte", "modem", "umts")
# netifd protocols that only exist on an upstream link: PPP over Ethernet or
# ATM (DSL) and the cellular protocols. dhcp/static/none say nothing by
# themselves (a dumb AP's lan is static or dhcp too).
WAN_PROTOS = frozenset(
    {"pppoe", "pppoa", "qmi", "mbim", "ncm", "modemmanager", "3g", "wwan"}
)

# Radio / WiFi band detection keywords
RADIO_BAND_24GHZ_KEYWORDS = ("2.4", "2g", "bgn", "g_band", "radio0")
RADIO_BAND_5GHZ_KEYWORDS = ("5", "5g", "ac", "a_band", "radio1")
RADIO_BAND_6GHZ_KEYWORDS = ("6", "6g", "ax6", "radio2")

# Guest SSID detection keywords (case-insensitive)
GUEST_SSID_KEYWORDS = ("guest", "gast", "visitor", "public", "hotspot")

# Feature flags stored in coordinator
FEATURE_HAS_IWINFO = "has_iwinfo"
FEATURE_HAS_5GHZ = "has_5ghz"
FEATURE_HAS_6GHZ = "has_6ghz"
FEATURE_HAS_GUEST_WIFI = "has_guest_wifi"
FEATURE_AVAILABLE_RADIOS = "available_radios"
FEATURE_SSIDS = "ssids"
FEATURE_UCI_AVAILABLE = "uci_available"
FEATURE_NETWORK_RELOAD = "network_reload"
FEATURE_DHCP_LEASES = "dhcp_leases"

# Connectivity / health sensor suffixes
SUFFIX_CONNECTIVITY = "connectivity"
SUFFIX_WAN_CONNECTIVITY = "wan_connectivity"
SUFFIX_ROUTER_STATUS = "router_status"
SUFFIX_CHANNEL_PLAN = "channel_plan"
SUFFIX_LOG_STATUS = "log_status"
SUFFIX_DFS_EVENTS_24H = "dfs_events_24h"
# Per DHCP pool: f"{entry_id}_{SUFFIX_DHCP_POOL}-{pool}" (hyphen keeps the
# legacy-migration substrings like "_rate"/"_ap_" out of user pool names)
SUFFIX_DHCP_POOL = "dhcp_pool"
SUFFIX_STICKY_CLIENTS = "sticky_clients"
SUFFIX_UNSTABLE_CLIENTS = "unstable_clients"

# Error type values stored in coordinator.data.error_type
ERROR_TYPE_CONNECTION = "connection"
ERROR_TYPE_AUTH = "auth"
ERROR_TYPE_TIMEOUT = "timeout"
ERROR_TYPE_RESPONSE = "response"

# A router counts as down (Repairs issue / outage event) after this many
# consecutive poll failures
NOTIFICATION_FAILURE_THRESHOLD = 3

# A failing router's last client list stops counting for presence after
# NOTIFICATION_FAILURE_THRESHOLD failed polls or this many seconds of failure
# (whichever comes first; polls can slow down to 120/300 s)
PRESENCE_STALE_AFTER_S = 300

# Fired on outage start/end, payload see fleet.FleetOutageTracker
EVENT_OUTAGE = f"{DOMAIN}_outage_event"

# RAM pressure Repairs issue (coordinator._check_memory_pressure).
# Pressure = 1 - available/total. The issue is raised once the pressure stays
# above RAM_PRESSURE_HIGH_PCT (or available below RAM_AVAILABLE_MIN_BYTES) for
# RAM_PRESSURE_HOLD_SECONDS and cleared below RAM_PRESSURE_CLEAR_PCT.
RAM_PRESSURE_HIGH_PCT = 85.0
RAM_PRESSURE_CLEAR_PCT = 80.0
RAM_PRESSURE_HOLD_SECONDS = 15 * 60
RAM_AVAILABLE_MIN_BYTES = 16 * 1024 * 1024

# Entity unique ID suffixes
SUFFIX_UPTIME = "uptime"
SUFFIX_WAN_STATUS = "wan_status"
SUFFIX_CLIENT_COUNT = "client_count"
SUFFIX_WIFI_24 = "wifi_24ghz"
SUFFIX_WIFI_50 = "wifi_5ghz"
SUFFIX_WIFI_60 = "wifi_6ghz"
SUFFIX_GUEST_WIFI = "guest_wifi"
SUFFIX_RELOAD_WIFI = "reload_wifi"
SUFFIX_REBOOT = "reboot"
SUFFIX_CHECK_UPDATES = "check_updates"
# Retired "install updates" button: no longer created; kept so the orphaned
# registry entry's unique_id stays documented.
SUFFIX_PERFORM_UPDATES = "perform_updates"
SUFFIX_NETWORK_TOPOLOGY = "network_topology"
SUFFIX_CPU_LOAD = "cpu_load"
SUFFIX_CPU_LOAD_5MIN = "cpu_load_5min"
SUFFIX_CPU_LOAD_15MIN = "cpu_load_15min"
SUFFIX_MEMORY_USAGE = "memory_usage"
SUFFIX_MEMORY_TOTAL = "memory_total"
SUFFIX_MEMORY_USED = "memory_used"
SUFFIX_MEMORY_FREE = "memory_free"
SUFFIX_MEMORY_CACHED = "memory_cached"
SUFFIX_MEMORY_SHARED = "memory_shared"
SUFFIX_MEMORY_BUFFERED = "memory_buffered"
SUFFIX_DISK_TOTAL = "disk_total"
SUFFIX_DISK_USED = "disk_used"
SUFFIX_DISK_FREE = "disk_free"
SUFFIX_DISK_USAGE = "disk_usage"
SUFFIX_TMPFS_TOTAL = "tmpfs_total"
SUFFIX_TMPFS_USED = "tmpfs_used"
SUFFIX_TMPFS_FREE = "tmpfs_free"
SUFFIX_TMPFS_USAGE = "tmpfs_usage"
SUFFIX_WAN_IP = "wan_ip"
SUFFIX_WAN_RX = "wan_rx"
SUFFIX_WAN_TX = "wan_tx"
SUFFIX_ACTIVE_CONNECTIONS = "active_connections"
SUFFIX_PLATFORM_ARCHITECTURE = "platform_architecture"
SUFFIX_FIRMWARE = "firmware"
SUFFIX_UPDATE_STATUS = "update_status"
SUFFIX_UPDATES_AVAILABLE = "updates_available"
SUFFIX_TOPOLOGY_SNAPSHOT = "network_topology"
SUFFIX_TOPOLOGY_STATUS = "topology_status"

# Device tracker
SOURCE_TYPE_ROUTER = "router"

# Diagnostics redact keys
DIAGNOSTICS_REDACTED = "**REDACTED**"
DIAGNOSTICS_REDACT_KEYS = {
    "password",
    "token",
    "ubus_rpc_session",
    "secret",
    "key",
    "auth",
}
# Exact key names that identify a person, a device or the network (HA
# convention, async_redact_data).  Matched by equality, not substring, so
# "interface" or "logical_name" stay readable.
DIAGNOSTICS_TO_REDACT = {
    "address",
    "bssid",
    "chassis_id",
    "domain",
    "host",
    "hostname",
    "ip",
    "ipv4",
    "ipv4_addr",
    "ipv4_address",
    "mac",
    "management_ip",
    # Entry title (defaults to the router hostname or host) in DFS event payloads
    "router",
    "ssid",
    "ssids",
    "username",
    "web_url",
}
# client_stability lists of individual clients (MAC + hostname each).
DIAGNOSTICS_CLIENT_LISTS = ("sticky", "weak", "unstable")

# OpenWrt version compatibility
# Minimum supported: OpenWrt 19.07 (ubus/rpcd baseline)
# Tested on: OpenWrt 24.10
OPENWRT_MIN_VERSION = "19.07"

# Coordinator data keys
KEY_ROUTER_INFO = "router_info"
KEY_PORT_STATS = "port_stats"
KEY_UPTIME = "uptime"
KEY_WAN_STATUS = "wan_status"
KEY_WAN_CONNECTED = "wan_connected"
KEY_WIFI_RADIOS = "wifi_radios"
KEY_CLIENTS = "clients"
KEY_CLIENT_COUNT = "client_count"
KEY_FEATURES = "features"
KEY_CPU_LOAD = "cpu_load"
KEY_MEMORY = "memory"
KEY_UPDATES_AVAILABLE = "updates_available"
KEY_SYSTEM_UPDATES = "system_updates"
KEY_ADDON_UPDATES = "addon_updates"

# WiFi radio state keys
RADIO_KEY_NAME = "name"
RADIO_KEY_SSID = "ssid"
RADIO_KEY_BAND = "band"
RADIO_KEY_ENABLED = "enabled"
RADIO_KEY_IS_GUEST = "is_guest"
RADIO_KEY_IFNAME = "ifname"
RADIO_KEY_UCI_SECTION = "uci_section"

# AP Interface detail keys (from iwinfo/info and network.wireless/status)
RADIO_KEY_CHANNEL = "channel"
RADIO_KEY_FREQUENCY = "frequency"
RADIO_KEY_TXPOWER = "txpower"
RADIO_KEY_BITRATE = "bitrate"
RADIO_KEY_HWMODE = "hwmode"
RADIO_KEY_HTMODE = "htmode"
RADIO_KEY_MODE = "mode"  # "Master" | "Client" | "Monitor" | None
RADIO_KEY_BSSID = "bssid"
# Physical radio of an AP interface and center channel of its bonded block
# (iwinfo info; used by channel_plan.py)
RADIO_KEY_PHY = "phy"
RADIO_KEY_CENTER_CHAN1 = "center_chan1"
# True on an AP interface built from the UCI config without an `ifname`
# option: RADIO_KEY_IFNAME then holds the UCI section name, not the kernel
# interface name that clients and usteer report, so clients per AP are unknown.
RADIO_KEY_IFNAME_IS_SECTION = "ifname_is_section"

# Client data keys
CLIENT_KEY_MAC = "mac"
CLIENT_KEY_IP = "ip"
CLIENT_KEY_HOSTNAME = "hostname"
CLIENT_KEY_SSID = "ssid"
CLIENT_KEY_SIGNAL = "signal"
CLIENT_KEY_RADIO = "radio"

# Error strings (used in config flow)
ERROR_CANNOT_CONNECT = "cannot_connect"
ERROR_INVALID_AUTH = "invalid_auth"
ERROR_UNKNOWN = "unknown"
ERROR_TIMEOUT = "timeout"
ERROR_INVALID_HOST = "invalid_host"
ERROR_RPCD_SETUP = "rpcd_setup_required"
ERROR_ACL_DEPLOY_FAILED = "acl_deploy_failed"
ERROR_ACL_DEPLOY_NO_CHANGE = "acl_deploy_no_change"
ERROR_ACL_ALREADY_CURRENT = "acl_already_current"
# 1.44.0: nothing written because an approved tiered ACL was kept, or
# because the ACL could not be read (network blip) — own messages.
ERROR_ACL_TIERED_KEPT = "acl_tiered_kept"
ERROR_ACL_CHECK_TRANSIENT = "acl_check_transient"

CLIENT_KEY_CONNECTED_SINCE = "connected_since"
CLIENT_KEY_DHCP_EXPIRES = "dhcp_expires"

# Enriched client data keys (v1.26.0 — device/topology detection improvements).
# All optional; absent/empty keys keep the client shape backward compatible.
CLIENT_KEY_VENDOR = "vendor"  # OUI-derived manufacturer, e.g. "Cudy" | None
# True for a locally administered (randomised, "private") MAC: no vendor
CLIENT_KEY_RANDOM_MAC = "random_mac"
CLIENT_KEY_CONNECTION_TYPE = "connection_type"  # see CONNECTION_TYPE_*
CLIENT_KEY_CONFIDENCE = "confidence"  # see CONFIDENCE_*
CLIENT_KEY_SOURCE = "source"  # detection source, e.g. "iwinfo" | "fdb" | "dhcp"
CLIENT_KEY_WEB_URL = "web_url"  # "http://<ip>" when an IP is known, else None
CLIENT_KEY_LAST_SEEN = "last_seen"  # ISO timestamp of most recent observation
CLIENT_KEY_VLAN_IDS = "vlan_ids"  # list[int] of VLAN memberships (may be empty)

# Connection-type enum (how a device reaches the router)
CONNECTION_TYPE_WIRED = "wired"
CONNECTION_TYPE_WIRELESS = "wireless"
CONNECTION_TYPE_ROUTER_UPLINK = "router_uplink"
CONNECTION_TYPE_UNKNOWN = "unknown"

# Confidence enum (how certain the detection is)
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

# Detection-source priority order (highest-trust first). Used to decide which
# source "wins" when the same MAC is observed via several sources.
SOURCE_LLDP = "lldp"
SOURCE_HOSTAPD = "hostapd"
SOURCE_IWINFO = "iwinfo"
SOURCE_DHCP = "dhcp"
SOURCE_ARP = "arp"
SOURCE_FDB = "fdb"
SOURCE_OUI = "oui"

# ---------------------------------------------------------------------------
# LLDP (link-layer discovery) — preferred source for router-to-router wiring
# ---------------------------------------------------------------------------
# lldpd does NOT expose a ubus object on stock OpenWrt, so LLDP is read via the
# existing asyncssh transport (`lldpcli -f json show neighbors`). It is an
# OPTIONAL capability: missing lldpd/SSH never fails setup, it only lowers
# router-to-router detection confidence. Reading LLDP must NOT flip the
# degraded/SSH-fallback state (use OpenWrtAPI._run_ssh, not the client path).
# NOTE: `-f json` is a GLOBAL option and MUST precede the command — lldpd 1.0.20
# (OpenWrt 25.x) rejects the trailing form `show neighbors -f json` with
# "unknown command from argument 3: -f". Verified on real hardware.
LLDP_CLI_NEIGHBORS_CMD = "lldpcli -f json show neighbors"
LLDP_CLI_CHECK_CMD = "command -v lldpcli"
LLDP_INIT_ENABLED_CMD = "/etc/init.d/lldpd enabled"

# lldp_status values (coordinator + capability)
LLDP_STATUS_OK = "ok"  # lldpcli usable, >=0 neighbors returned
LLDP_STATUS_NO_NEIGHBORS = "no_neighbors"  # usable but no neighbors seen
LLDP_STATUS_UNAVAILABLE = "unavailable"  # lldpcli/lldpd/SSH not available
LLDP_STATUS_ERROR = "error"  # unexpected exception (only real failures)

# LLDP is read over SSH, so it is NOT fetched on every poll: neighbors change
# when someone re-cables, not every 60 s. An "unavailable" verdict is retried
# on a slower cadence so installing lldpd later takes effect without reloading
# the config entry (both in seconds).
LLDP_REFRESH_INTERVAL = 600.0
LLDP_UNAVAILABLE_RETRY_INTERVAL = 1800.0

# Data that only the SSH fallback can supply on some routers (disk and tmpfs
# usage when ``system info`` has no ``root``/``tmp`` fields, OpenWrt < 21.02)
# is refreshed over SSH at most this often (seconds) and served from a cache
# in between; it changes on the timescale of package installs, not polls.
SSH_SLOW_REFRESH_INTERVAL = 600.0

# The hostapd interface list (which SSIDs have an AP interface) is discovered
# once and cached; it is re-discovered when a radio reports an unknown kernel
# ifname, after a Wi-Fi change made through this integration, and otherwise
# at most this often (seconds), so a list that was empty or incomplete at
# setup does not stick until the next reload.
HOSTAPD_REDISCOVER_INTERVAL = 600.0

# The bridge port map ({port number: interface}) behind the port-to-device
# mapping costs one ``file list`` plus one ``brport/port_no`` read per
# interface over ubus. Bridge membership changes when someone re-cables or
# adds an SSID, so the map is rebuilt at most this often (seconds) — and at
# once when the FDB names a port number the map does not know.
BRIDGE_PORT_MAP_REFRESH_INTERVAL = 600.0

# rpcd ``rc/list`` is NOT called on every poll: rpcd before 2026-05-31
# (upstream d06d2a8, e.g. rpcd 2025.12.03 on OpenWrt 25.12.1) leaks ~4.7 KB
# per call. Service running state comes from procd ``service/list`` instead;
# rc/list only supplies the "enabled" flags, refreshed this rarely (seconds).
RC_LIST_REFRESH_INTERVAL = 6 * 3600.0

# Coordinator data keys
KEY_LLDP_NEIGHBORS = "lldp_neighbors"
KEY_LLDP_STATUS = "lldp_status"

# LLDP neighbor dict keys (output of _parse_lldpcli_json)
LLDP_KEY_LOCAL_INTERFACE = "local_interface"
LLDP_KEY_CHASSIS_ID = "chassis_id"
LLDP_KEY_CHASSIS_NAME = "chassis_name"
LLDP_KEY_MGMT_IP = "management_ip"
LLDP_KEY_PORT_ID = "port_id"
LLDP_KEY_PORT_DESCR = "port_descr"
LLDP_KEY_CAPABILITIES = "capabilities"  # list[str] e.g. ["Router", "Bridge"]

# Optional capability id (config-flow checklist). NOT in the required set.
CAP_LLDP_NEIGHBORS = "lldp_neighbors"

# WAN throughput / connectivity coordinator data keys (native OpenWrt)
KEY_WAN_TRAFFIC = "wan_traffic"
KEY_PING_MS = "ping_ms"
KEY_DDNS_STATUS = "ddns_status"

# CPU history: one point per poll over a time-based 1 h rolling window. Points
# older than the window are dropped, so the span no longer depends on the poll
# interval (60/120/300 s). MAX_POINTS only caps memory: it covers the window at
# 30 s spacing, leaving headroom for refreshes requested between polls.
CPU_HISTORY_WINDOW_SECONDS = 3600
CPU_HISTORY_MAX_POINTS = 120
KEY_CPU_HISTORY = "cpu_history"

# Topology snapshots: one snapshot every 10 poll cycles (5 min), max 20 = ~100 min history
TOPOLOGY_SNAPSHOT_INTERVAL_CYCLES = 10
TOPOLOGY_SNAPSHOT_MAX = 20
KEY_TOPOLOGY_SNAPSHOTS = "topology_snapshots"

# Options flag: include the raw per-port mapping trace (FDB/DHCP/ARP MACs and
# assignment reasons) in the topology snapshot endpoint. Off by default —
# payload guard; HA diagnostics only ever get the redacted summary.
CONF_TOPOLOGY_PORT_DEBUG = "topology_port_debug"
DEFAULT_TOPOLOGY_PORT_DEBUG = False

# Options flag: open the topology sidebar panel and its snapshot API (DHCP
# leases, ARP, FDB, WAN IP, …) to non-admin users. Off by default — admins only.
# The panel is shared by all entries: it is public if ANY loaded entry has it on.
CONF_TOPOLOGY_PANEL_ALL_USERS = "topology_panel_all_users"
DEFAULT_TOPOLOGY_PANEL_ALL_USERS = False

# Options flag: enable the per-radio / per-AP / per-port sensors in one go
# instead of one click per entity (disabled by default, see extended_sensors.py).
CONF_EXTENDED_WIFI_SENSORS = "extended_wifi_sensors"
DEFAULT_EXTENDED_WIFI_SENSORS = False
# Internal option: unique_ids that were already enabled when the switch went
# on, so switching it off restores exactly the previous state.
OPT_EXTENDED_WIFI_PREEXISTING = "_extended_wifi_preexisting"

# TODO: parental control - add UBUS_PARENTAL_OBJECT

# DHCP lease data key (coordinator)
KEY_DHCP_LEASES = "dhcp_leases"

# Service Management (procd / rc)
UBUS_RC_OBJECT = "rc"
UBUS_RC_LIST = "list"
UBUS_RC_INIT = "init"
UBUS_SERVICE_OBJECT = "service"
UBUS_SERVICE_LIST = "list"

# logd ring buffer (F6 log ingest, ACL v6)
UBUS_LOG_OBJECT = "log"
UBUS_LOG_READ = "read"
# Fetched every LOG_READ_INTERVAL_CYCLES polls (~165 B per line); 1 = every
# poll from poll 2 on (RT3-D: near-realtime events via the log). The first
# fetch asks for LOG_READ_LINES; later fetches size themselves to 1.5x the
# lines seen last time (LOG_READ_LINES_MIN..MAX), and after a gap ("missed"
# lines) the next fetch takes LOG_READ_LINES_MAX (about the whole buffer).
LOG_READ_INTERVAL_CYCLES = 1
LOG_READ_LINES = 250
LOG_READ_LINES_MIN = 100
LOG_READ_LINES_MAX = 700
# HA events from log lines: at most LOG_EVENTS_PER_FETCH per fetch and one per
# type and MAC within LOG_EVENT_COOLDOWN_SECONDS.
LOG_EVENTS_PER_FETCH = 10
LOG_EVENT_COOLDOWN_SECONDS = 300
EVENT_WIFI = f"{DOMAIN}_wifi_event"
EVENT_DHCP = f"{DOMAIN}_dhcp_event"
# DFS log lines and per-radio channel/width changes between two polls (F3).
# A change counts as DFS-related only with a DFS log line of the same radio
# within DFS_EVIDENCE_SECONDS.
EVENT_DFS = f"{DOMAIN}_dfs_event"
DFS_EVIDENCE_SECONDS = 15 * 60

# DHCP health (F5): pools and static hosts from `uci get dhcp`, refreshed
# every DHCP_CONFIG_REFRESH_CYCLES polls on routers with an active pool.
DHCP_CONFIG_REFRESH_CYCLES = 10
# Routers without an active pool (or without uci access) are asked again
# this rarely, so a pool enabled later shows up without a reload.
DHCP_CONFIG_RETRY_CYCLES = 60

# Client stability (F4): usteer's fleet-wide client view (ACL v6), fetched
# every USTEER_READ_INTERVAL_CYCLES polls from poll 3 on, independent of the
# log rhythm (RT3-D: the log is read on every poll, so usteer must not wait
# for a poll without a log read); a router without usteer is asked again
# every USTEER_RETRY_CYCLES polls.
UBUS_USTEER_OBJECT = "usteer"
UBUS_USTEER_GET_CLIENTS = "get_clients"
USTEER_READ_INTERVAL_CYCLES = 2
USTEER_RETRY_CYCLES = 30
USTEER_STATUS_PENDING = "pending"
USTEER_STATUS_OK = "ok"
USTEER_STATUS_UNAVAILABLE = "not_available"
LOG_STATUS_PENDING = "pending"
LOG_STATUS_OK = "ok"
# Not "unavailable": that state is reserved by HA for unreachable entities.
LOG_STATUS_NOT_PERMITTED = "not_permitted"
LOG_STATUS_ERROR = "error"

# Services to monitor/control by default (OpenWrt critical services)
DEFAULT_SERVICES = ["dnsmasq", "dropbear", "firewall", "network", "uhttpd", "wpad"]

KEY_SERVICES = "services"
FEATURE_HAS_SERVICES = "has_services"

# ---------------------------------------------------------------------------
# F5 Aggregator (v1.18.0 — skeleton only, NOT enabled by default)
# ---------------------------------------------------------------------------
# When the SSH-fallback path is active, each poll opens 8–15 asyncssh
# connections (one per ubus call replacement).  The aggregator collapses all
# of those into ONE remote shell invocation that returns a single JSON
# document — reducing the per-poll SSH connection count to 1 per router.
#
# Status v1.18.0: SKELETON ONLY.  The aggregator path is gated behind
# `CONF_USE_AGGREGATOR` and disabled by default.  Production rollout is
# planned for v1.19.0 once the 24h diagnostic data confirms F5 is needed.
CONF_USE_AGGREGATOR = "use_aggregator"
DEFAULT_USE_AGGREGATOR = False
AGGREGATOR_SCHEMA_VERSION = "1.18.0"
AGGREGATOR_REMOTE_SCRIPT_PATH = "/root/ha-collect.sh"

# ---------------------------------------------------------------------------
# Network intelligence (plan 2026-11-16, P2): fleet-wide event store
# ---------------------------------------------------------------------------
# One HA Store file for all routers (.storage/openwrt_router.intelligence).
INTEL_STORE_KEY = f"{DOMAIN}.intelligence"
INTEL_STORE_VERSION = 1
INTEL_STORE_MINOR_VERSION = 1
# Writes are batched: at most one store write per this many seconds.
INTEL_SAVE_DELAY_SECONDS = 300
# Hard limit of the store file; the oldest events are trimmed before a save.
INTEL_MAX_STORE_BYTES = 1_500_000
# Retention pruning of events and counters runs at most this often.
INTEL_PRUNE_INTERVAL_SECONDS = 300

# Network intelligence (P6): score, entities, bus event.
# Fired when an incident root is opened, reopened or resolved (plan c9, AK11).
EVENT_INCIDENT = f"{DOMAIN}_incident_event"
# Dispatcher signal: the engine has a new view (score, counts) for entities.
SIGNAL_NET_INTEL = f"{DOMAIN}_net_intel_updated"
# A new root is announced only after this settle time (a parent may still
# appear, e.g. an outage needs several failed polls) ...
INTEL_ANNOUNCE_SETTLE_SECONDS = 90
# ... and at the latest after this long, even while a router is late.
INTEL_ANNOUNCE_HOLD_MAX_SECONDS = 900
# Per-router entities (unique_id f"{entry_id}_{suffix}").
SUFFIX_NET_HEALTH = "net_health"
SUFFIX_INCIDENTS_ACTIVE = "incidents_active"
SUFFIX_WIFI_RECONNECTS_1H = "wifi_reconnects_1h"
SUFFIX_WIFI_AUTH_ERRORS_1H = "wifi_auth_errors_1h"
SUFFIX_WAN_STABILITY = "wan_stability"
SUFFIX_INCIDENT_CRITICAL = "incident_critical"
SUFFIX_MAINTENANCE_MODE = "maintenance_mode"
# Fleet entities: one set per HA instance, on the anchor entry (plan F1).
FLEET_UID_PREFIX = f"{DOMAIN}_fleet_"
UID_FLEET_NET_HEALTH = f"{FLEET_UID_PREFIX}net_health"
UID_FLEET_INCIDENTS_ACTIVE = f"{FLEET_UID_PREFIX}incidents_active"
UID_FLEET_INCIDENT_CRITICAL = f"{FLEET_UID_PREFIX}incident_critical"

# ---------------------------------------------------------------------------
# Client stability (plan 2026-11-16-client-stability): history per client
# ---------------------------------------------------------------------------
# Own HA Store file (.storage/openwrt_router.client_history), own size cap.
CLIENT_STORE_KEY = f"{DOMAIN}.client_history"
CLIENT_STORE_VERSION = 1
CLIENT_STORE_MINOR_VERSION = 1
# At most one store write per this many seconds (nothing written unchanged).
CLIENT_SAVE_DELAY_SECONDS = 300
# Default size cap of the store file (settable 1..8 MB).
CLIENT_MAX_STORE_MB = 3
# Entities: at most this many selected clients, five sensors each.
CLIENT_ENTITY_MAX = 25
# Entity view and dispatcher update at most this often.
CLIENT_PUBLISH_SECONDS = 60
# Dispatcher signal: the client stability view changed.
SIGNAL_CLIENT_STABILITY = f"{DOMAIN}_client_stability_updated"
# Per-client sensors (unique_id f"{CLIENT_UID_PREFIX}{mac12}_{key}").
CLIENT_UID_PREFIX = f"{DOMAIN}_client_"

# ---------------------------------------------------------------------------
# Realtime event stream (plan 2026-11-16-realtime-rca, RT2): ubus SSE
# subscribe via uhttpd-mod-ubus (GET /ubus/subscribe/<object>).
# ---------------------------------------------------------------------------
# Events buffered per subscription; on overflow the oldest is dropped.
STREAM_QUEUE_MAX = 512
# Reconnect backoff in seconds: 2, 4, 8 ... capped at 300, minus up to 20 %
# jitter; back to the start after a connection that stayed up for 120 s.
STREAM_BACKOFF_INITIAL = 2
STREAM_BACKOFF_MAX = 300
STREAM_BACKOFF_JITTER = 0.2
STREAM_BACKOFF_RESET_AFTER = 120
# Missing ":subscribe" ACL right: retry only after this many seconds.
STREAM_NO_PERMISSION_RETRY = 3600
# The server sends no keepalive; a stream silent this long is reconnected.
STREAM_IDLE_TIMEOUT = 600
# TCP/TLS connect budget and the read budget of a non-SSE error body.
STREAM_CONNECT_TIMEOUT = 10
# Largest accepted event (sum of its data lines); bigger ones are dropped.
STREAM_EVENT_MAX_BYTES = 65536
# How long stop() waits for the subscription task to end.
STREAM_STOP_TIMEOUT = 5
# Never subscribed: hostapd-auth waits up to 1 s for an answer from every
# subscriber, so a subscriber there delays each client login.
STREAM_FORBIDDEN_OBJECTS = frozenset({"hostapd-auth"})
# States of one subscription (ubus_stream.UbusSubscription).
STREAM_STATE_IDLE = "idle"
STREAM_STATE_CONNECTING = "connecting"
STREAM_STATE_UP = "up"
STREAM_STATE_BACKOFF = "backoff"
STREAM_STATE_NO_PERMISSION = "no_permission"
STREAM_STATE_NOT_FOUND = "not_found"
STREAM_STATE_PAUSED = "paused"
STREAM_STATE_STOPPED = "stopped"

# ---------------------------------------------------------------------------
# Enterprise core, part 1 (router identity, registry, audit; plan
# docs/plans/2026-11-17-enterprise-core.md). Store keys, ids and event names
# live in core_models.py; only the knobs of the stores are here.
# ---------------------------------------------------------------------------
# Store minor versions (major = core_models.CORE_STORE_VERSION = 1).
ROUTER_REGISTRY_STORE_MINOR_VERSION = 1
AUDIT_STORE_MINOR_VERSION = 1
# Delayed writes: one pending write at a time, flushed on the last unload.
ROUTER_REGISTRY_SAVE_DELAY_SECONDS = 30
AUDIT_SAVE_DELAY_SECONDS = 60
# Reference fingerprint: at most this many MACs are kept per router.
ROUTER_FINGERPRINT_MAX_MACS = 64
# The hostname a freshly flashed / reset OpenWrt reports.
OPENWRT_DEFAULT_HOSTNAME = "OpenWrt"
# Model api.get_router_info() reports when system/board is not readable.
ROUTER_INFO_FALLBACK_MODEL = "OpenWrt Router"
# Enterprise core, part 2 (guard, version store, configuration API).
CONFIG_CATALOG_STORE_MINOR_VERSION = 1
INSTALLATION_KEY_STORE_MINOR_VERSION = 1
# last_seen_at updates of a deduplicated backup are written delayed.
CONFIG_CATALOG_SAVE_DELAY_SECONDS = 30
# Provider call limits of the configuration API (seconds).
CONFIG_PROVIDER_COLLECT_TIMEOUT_SECONDS = 180
CONFIG_PROVIDER_CALL_TIMEOUT_SECONDS = 60
CONFIG_PROVIDER_PROBE_TIMEOUT_SECONDS = 60
CONFIG_PROVIDER_RESTORE_TIMEOUT_SECONDS = 300

# ---------------------------------------------------------------------------
# Configuration manager wiring (plan docs/plans/2026-11-18-config-manager-
# integration.md, sections 2-7). The option config_backup_enabled itself
# lives in core_models (OPTION_CONFIG_BACKUP_ENABLED, default OFF).
# ---------------------------------------------------------------------------
OPTION_CONFIG_BACKUP_SCHEDULE = "config_backup_schedule"
CONFIG_BACKUP_SCHEDULE_DAILY = "daily"
CONFIG_BACKUP_SCHEDULE_OFF = "off"
CONFIG_BACKUP_SCHEDULES = (CONFIG_BACKUP_SCHEDULE_DAILY, CONFIG_BACKUP_SCHEDULE_OFF)
DEFAULT_CONFIG_BACKUP_SCHEDULE = CONFIG_BACKUP_SCHEDULE_DAILY
OPTION_CONFIG_BACKUP_TIME = "config_backup_time"  # local time, "HH:MM:SS"
DEFAULT_CONFIG_BACKUP_TIME = "03:30:00"
OPTION_CONFIG_DRIFT_CHECK = "config_drift_check"
DEFAULT_CONFIG_DRIFT_CHECK = True
# Runtime: one per HA instance, released after the last entry.
CONFIG_MANAGER_MODULE = "config_manager"
# Own event prefix: registering it is what entitles the module to its key
# (contract §11.5); the module emits config_manager.backup_blocked below it.
CONFIG_MANAGER_EVENT_PREFIX = f"{CONFIG_MANAGER_MODULE}."
# Purpose of the module key that salts user pseudonyms in route answers.
CONFIG_ROUTE_PSEUDONYM_PURPOSE = "route_user_pseudonym"
DATA_CONFIG_MANAGER = f"{DOMAIN}_config_manager"
DATA_CONFIG_VIEWS_BOUND = f"{DOMAIN}_config_views_bound"
SIGNAL_CONFIG_MANAGER = f"{DOMAIN}_config_manager_update"
# Schedule tick (memory only; router contact only when a run is due).
CONFIG_MANAGER_TICK_SECONDS = 300
# Daily run: per-router offset in [0, CONFIG_STAGGER_SECONDS) after the time.
CONFIG_STAGGER_SECONDS = 3600
# Release change: wait this long after the first sighting of a new release.
CONFIG_RELEASE_CHANGE_DELAY_SECONDS = 300
# Drift: at most this many automatic drift versions per router and day.
CONFIG_DRIFT_VERSIONS_PER_DAY = 4
# Versions read at start to rebuild the memory of the schedule.
CONFIG_MANAGER_HISTORY_LIMIT = 20
# Service create_config_backup.
SERVICE_CREATE_CONFIG_BACKUP = "create_config_backup"
CONFIG_NOTE_MAX_LENGTH = 200
# Entities (unique_id f"{router_id}_{suffix}").
SUFFIX_CONFIG_LAST_BACKUP = "config_last_backup"
SUFFIX_CONFIG_BACKUP_STATUS = "config_backup_status"
SUFFIX_CONFIG_VERSIONS = "config_versions"
SUFFIX_CONFIG_DRIFT = "config_drift"
CONFIG_STATUS_OK = "ok"
CONFIG_STATUS_PARTIAL = "partial"
CONFIG_STATUS_FAILED = "failed"
CONFIG_STATUS_RUNNING = "running"
CONFIG_STATUS_DISABLED = "disabled"
CONFIG_STATUS_NEVER = "never"
CONFIG_BACKUP_STATUSES = (
    CONFIG_STATUS_OK,
    CONFIG_STATUS_PARTIAL,
    CONFIG_STATUS_FAILED,
    CONFIG_STATUS_RUNNING,
    CONFIG_STATUS_DISABLED,
    CONFIG_STATUS_NEVER,
)
# --- end configuration manager wiring

# --- Security Center ---
# Release 1.46.0 part 1 (plan docs/plans/2026-11-17-security-center.md):
# one fleet-wide center per HA instance, default off. Store like client
# stability: own HA Store, size cap, delayed save, flush on the last unload.
SEC_STORE_KEY = f"{DOMAIN}.security_center"
SEC_STORE_VERSION = 1
SEC_STORE_MINOR_VERSION = 1
SEC_STORE_MAX_BYTES = 512 * 1024
SEC_SAVE_DELAY_SECONDS = 60
# Default UDP port of the syslog receiver (security_syslog.py, part 2).
SEC_DEFAULT_SYSLOG_PORT = 5514
# Own incidents (sec_*): at most this many, resolved ones are dropped first.
SEC_INCIDENT_CAP = 100
# Timeline: at most this many entries, none older than this many days.
SEC_TIMELINE_MAX = 2000
SEC_TIMELINE_DAYS = 14
# Traffic Analytics notes (``traffic_indicator``) in that timeline: at most
# this many, the oldest goes first (1.49.3). At 20 per hour over 14 days they
# could reach 6720 and push every security entry out; they never displace a
# security entry, on overflow they make room first.
SEC_TIMELINE_TRAFFIC_MAX = 500
# An open incident without a new finding for this long is resolved.
SEC_INCIDENT_AUTO_RESOLVE_SECONDS = 86400
# A drift whose configuration areas are still unknown after this long is
# fed as "areas unknown" (limitation, never "nothing changed").
SEC_DRIFT_RESOLVE_WINDOW_SECONDS = 3600
# Pending drift areas are looked up again at most this often from polls.
SEC_DRIFT_RETRY_SECONDS = 60
# Example E: a configuration change at most this long before a new finding
# of the same router is linked to it as a hint (no causality claim).
SEC_DRIFT_HINT_WINDOW_SECONDS = 3600
DATA_SECURITY_CENTER = f"{DOMAIN}_security_center"
# --- end Security Center
# --- Security Center part 2 ---
# Release 1.46.0 part 2: syslog receiver (path A), HTTP routes, fleet
# sensors. Syslog lines are foreign, forgeable input (UDP from the LAN):
# every limit below drops and counts, nothing is buffered without a cap.
# The receiver listens on all IPv4 addresses (routers send to HA's LAN IP);
# only senders whose address is a router's management address are taken.
SEC_SYSLOG_BIND_HOST = "0.0.0.0"
# Records waiting for the center; more are dropped (``dropped_buffer``).
SEC_SYSLOG_BUFFER_MAX = 4000
# Buffered records that make the center drain before the next poll.
SEC_SYSLOG_DRAIN_AT = 500
# Token buckets (lines per second, burst): per sender and in total.
SEC_SYSLOG_SENDER_RATE = 50.0
SEC_SYSLOG_SENDER_BURST = 500
SEC_SYSLOG_TOTAL_RATE = 200.0
SEC_SYSLOG_TOTAL_BURST = 2000
# A receiver that could not listen is tried again at most this often.
SEC_SYSLOG_RETRY_SECONDS = 300
# Window of the "last hour" counters of the fleet sensors.
SEC_COUNT_WINDOW_SECONDS = 3600
SIGNAL_SECURITY_CENTER = f"{DOMAIN}_security_center_updated"
DATA_SECURITY_VIEWS_BOUND = f"{DOMAIN}_security_views_bound"
DATA_SECURITY_ENTITIES = f"{DOMAIN}_security_entities"
UID_FLEET_SECURITY_SCORE = f"{FLEET_UID_PREFIX}security_score"
UID_FLEET_SECURITY_HINTS_ACTIVE = f"{FLEET_UID_PREFIX}security_hints_active"
UID_FLEET_SECURITY_HINTS_CRITICAL = f"{FLEET_UID_PREFIX}security_hints_critical"
UID_FLEET_SECURITY_UNKNOWN_DEVICES = f"{FLEET_UID_PREFIX}security_unknown_devices"
UID_FLEET_SECURITY_FIREWALL_EVENTS = f"{FLEET_UID_PREFIX}security_firewall_events_1h"
UID_FLEET_SECURITY_WIFI_AUTH_FAILURES = (
    f"{FLEET_UID_PREFIX}security_wifi_auth_failures_1h"
)
UID_FLEET_SECURITY_COVERAGE = f"{FLEET_UID_PREFIX}security_coverage"
# --- end Security Center part 2
# --- Network Diagnostics ---
# Release 1.47.0 part 1 (diag_runtime.py / diag_store.py): one fleet-wide
# engine per HA instance, default off. Off: no router call, no packet, no
# write. On: passive evaluation of the poll; active HA probes only as a
# manual run by an admin or, if an admin enabled it, periodically against
# confirmed targets.
DIAG_STORE_KEY = f"{DOMAIN}.net_diagnostics"
DIAG_STORE_VERSION = 1
DIAG_STORE_MINOR_VERSION = 1
DIAG_SAVE_DELAY_SECONDS = 60
# Periodic HA probe round (only with periodic probing on and confirmed
# targets); the scheduler's minimum interval is 60 s.
DIAG_DEFAULT_INTERVAL_SECONDS = 300
DIAG_MIN_INTERVAL_SECONDS = 60
DIAG_MAX_INTERVAL_SECONDS = 86400
# History bounds (diag_store): router measurement points, series of the HA
# point and of each router point (separate quotas: one never evicts or
# starves another), hour and day buckets per series, restart gap records.
DIAG_MAX_POINTS = 64
DIAG_MAX_SERIES_HA = 32
DIAG_MAX_SERIES_PER_ROUTER = 8
DIAG_MAX_HOUR_BUCKETS = 7 * 24 + 1
DIAG_MAX_DAY_BUCKETS = 31
DIAG_MAX_GAP_RECORDS = 64
# Targets an admin may configure (diag_targets allows up to 64).
DIAG_MAX_TARGETS = 16
# A router with less uptime than this was just restarted: findings settle.
DIAG_SETTLE_SECONDS = 300
# Loss baselines are fed the loss over this many rounds.
DIAG_LOSS_ROUNDS = 3
# The module key is asked for again at most this often while missing.
DIAG_MODULE_KEY_RETRY_SECONDS = 300
DATA_NET_DIAGNOSTICS = f"{DOMAIN}_net_diagnostics"
# Part 2 (diag_views.py, diag_entities.py, diag_context.py): routes, the
# bounded entity set (six fleet sensors, one gateway sensor per router that
# already has a device) and the context of a finding.
SIGNAL_NET_DIAGNOSTICS = f"{DOMAIN}_net_diagnostics_updated"
DATA_DIAG_VIEWS_BOUND = f"{DOMAIN}_diag_views_bound"
DATA_DIAG_ENTITIES = f"{DOMAIN}_diag_entities"
UID_FLEET_DIAG_SCORE = f"{FLEET_UID_PREFIX}diag_quality_score"
UID_FLEET_DIAG_COVERAGE = f"{FLEET_UID_PREFIX}diag_monitoring_coverage"
UID_FLEET_DIAG_FINDINGS = f"{FLEET_UID_PREFIX}diag_findings_active"
UID_FLEET_DIAG_LATENCY = f"{FLEET_UID_PREFIX}diag_ha_internet_latency"
UID_FLEET_DIAG_LOSS = f"{FLEET_UID_PREFIX}diag_ha_internet_loss"
UID_FLEET_DIAG_DNS = f"{FLEET_UID_PREFIX}diag_dns_response_time"
# Per router (on the router's existing device): ``<entry_id><suffix>``.
DIAG_GATEWAY_UID_SUFFIX = "_diag_gateway_reachable"
# Context of a finding: configuration changes / security incidents of the
# same router this long before (or, detected late, after) the finding.
DIAG_CONTEXT_WINDOW_SECONDS = 1800
# Drift notes kept in memory for the context, per router (its oldest is
# dropped first, counted; the router's context is then "partial").
DIAG_CONFIG_NOTES_PER_ROUTER = 16
# The Security Center overview is read at most this often per router.
DIAG_CONTEXT_CACHE_SECONDS = 60
# --- end Network Diagnostics


# --- WiFi RF Intelligence (1.48.0) ---
# Per-entry options (options flow), all OFF by default. Read on every poll,
# so saving them needs no reload. With wifi_rf_enabled off nothing of the
# module runs and the router sees not a single extra call.
OPTION_WIFI_RF_ENABLED = "wifi_rf_enabled"
OPTION_WIFI_RF_GET_STATUS = "wifi_rf_get_status"  # hostapd.<if> get_status
OPTION_WIFI_RF_ASSOCLIST = "wifi_rf_assoclist"  # iwinfo assoclist
OPTION_WIFI_RF_LISTS = "wifi_rf_lists_at_start"  # iwinfo freqlist/txpowerlist
OPTION_WIFI_RF_SURVEY = "wifi_rf_survey"  # iwinfo survey (needs rf.survey right)
OPTION_WIFI_RF_EVERY_N_POLLS = "wifi_rf_every_n_polls"
WIFI_RF_SWITCH_OPTIONS = (
    OPTION_WIFI_RF_ENABLED,
    OPTION_WIFI_RF_GET_STATUS,
    OPTION_WIFI_RF_ASSOCLIST,
    OPTION_WIFI_RF_LISTS,
    OPTION_WIFI_RF_SURVEY,
)
DEFAULT_WIFI_RF_EVERY_N_POLLS = 5
WIFI_RF_EVERY_N_POLLS_MIN = 1
WIFI_RF_EVERY_N_POLLS_MAX = 60
# Extra periodic reads never run more often than rf_guard's
# POLL_READ_MIN_INTERVAL_S (300 s) per router, radio and kind, whatever N
# says; this much poll jitter is tolerated below that floor.
WIFI_RF_FLOOR_TOLERANCE_S = 5.0
# Overall time limit of one round of extra calls of one router.
WIFI_RF_ROUND_TIMEOUT_S = 20.0
# Capability probes after an error back off up to this long.
WIFI_RF_PROBE_BACKOFF_MAX_S = 3600.0
DATA_WIFI_RF_CENTER = f"{DOMAIN}_wifi_rf_center"
DATA_WIFI_RF_VIEWS_BOUND = f"{DOMAIN}_wifi_rf_views_bound"
WIFI_RF_STORE_KEY = f"{DOMAIN}.wifi_rf"
WIFI_RF_STORE_VERSION = 1
# 1.52.3: 900 s (was 300 s). The whole file is rewritten each time (13 radios
# about 2.9 MB); a crash loses at most this much of the history.
WIFI_RF_SAVE_DELAY_SECONDS = 900
# Hard store limits: each series has its own quota; only the file limit
# below evicts (the oldest buckets, 1.52.3).
WIFI_RF_MAX_RADIOS = 32  # the fleet of 2026-11 has 13 radios
WIFI_RF_MAX_HOURLY_BUCKETS = 8 * 24 + 2  # per radio and series (8 days)
WIFI_RF_MAX_DAILY_BUCKETS = 31 + 1  # per radio and series
# Raw points (memory only, for the 1 h window) per radio and series.
WIFI_RF_MAX_RAW_POINTS = 240
# File limit (1.52.3: 8 MB, was 2 MB). A radio with all seven series at its
# bucket caps takes about 238 kB with values as the sources deliver them
# (utilization and retry rate unrounded, the rest whole numbers): 13 radios
# about 3.1 MB, 32 radios about 7.6 MB, so the radio cap fits. With every
# float field at full precision it is about 283 kB (32 radios 9.0 MB) and
# trimming starts at about 28 radios. Over the limit the oldest buckets are
# trimmed to WIFI_RF_TRIM_HEADROOM below it (hourly first, then daily).
WIFI_RF_MAX_STORE_BYTES = 8_000_000
WIFI_RF_TRIM_HEADROOM = 0.05
# Part 2 (wifi_rf_entities.py): a bounded entity set, pushed by SIGNAL_WIFI_RF.
# Fleet: three sensors (no device). Per router with RF on and an existing
# device: AP RF health, plus three sensors per radio for at most
# WIFI_RF_RADIO_ENTITIES_MAX radios. Never one entity per client or per
# foreign network. Unique ids: fleet ``UID_FLEET_WIFI_RF_*``, router
# ``<entry_id>_wifi_rf_ap_health``, radio ``<entry_id>_wifi_rf_<radio>_<metric>``.
SIGNAL_WIFI_RF = f"{DOMAIN}_wifi_rf_updated"
DATA_WIFI_RF_ENTITIES = f"{DOMAIN}_wifi_rf_entities"
UID_FLEET_WIFI_RF_HEALTH = f"{FLEET_UID_PREFIX}wifi_rf_health_score"
UID_FLEET_WIFI_RF_ROAMING = f"{FLEET_UID_PREFIX}wifi_rf_roaming_problems"
UID_FLEET_WIFI_RF_RECOMMENDATIONS = f"{FLEET_UID_PREFIX}wifi_rf_recommendations"
WIFI_RF_UID_INFIX = "_wifi_rf_"
WIFI_RF_RADIO_ENTITIES_MAX = 4  # radios per router (tri-band plus one spare)
# --- end WiFi RF Intelligence


# --- Traffic Analytics (Phase 5) ---
# Plan docs/plans/2026-11-20-traffic-analytics-bauplan.md (§5, §11): store
# keys, signals and unique-id prefixes only; limits live in traffic_const.py.
# Default off: without "enabled" nothing is written, emitted or called.
TRAFFIC_FINE_STORE_KEY = f"{DOMAIN}.traffic_fine"
TRAFFIC_COARSE_STORE_KEY = f"{DOMAIN}.traffic_coarse"
TRAFFIC_STORE_VERSION = 1
TRAFFIC_STORE_MINOR_VERSION = 1
TRAFFIC_FINE_STORE_MAX_BYTES = 2 * 1024 * 1024
TRAFFIC_COARSE_STORE_MAX_BYTES = 2 * 1024 * 1024
DATA_TRAFFIC_ANALYTICS = f"{DOMAIN}_traffic_analytics"
DATA_TRAFFIC_VIEWS_BOUND = f"{DOMAIN}_traffic_views_bound"
SIGNAL_TRAFFIC_ANALYTICS = f"{DOMAIN}_traffic_analytics_updated"
UID_FLEET_TRAFFIC_ANOMALIES = f"{FLEET_UID_PREFIX}traffic_anomalies"
UID_FLEET_TRAFFIC_COVERAGE = f"{FLEET_UID_PREFIX}traffic_coverage"
# Phase K: the switch is an option per router (options flow, like WiFi RF);
# saving it needs no reload. Off (default) on every router: no listener, no
# store access, no entity, no router call. The module runs while at least
# one router has it on.
OPTION_TRAFFIC_ENABLED = "traffic_enabled"
OPTION_TRAFFIC_HISTORY_PROFILE = "traffic_history_profile"
OPTION_TRAFFIC_STATION_DETAIL = "traffic_station_detail"  # iwinfo assoclist
OPTION_TRAFFIC_SYSFS_FALLBACK = "traffic_sysfs_fallback"  # file read sysfs
OPTION_TRAFFIC_OFFLOAD_PROBE = "traffic_offload_probe"  # uci get firewall
TRAFFIC_SWITCH_OPTIONS = (
    OPTION_TRAFFIC_ENABLED,
    OPTION_TRAFFIC_STATION_DETAIL,
    OPTION_TRAFFIC_SYSFS_FALLBACK,
    OPTION_TRAFFIC_OFFLOAD_PROBE,
)
TRAFFIC_HISTORY_PROFILES = ("compact", "standard")
DEFAULT_TRAFFIC_HISTORY_PROFILE = "compact"
# Entities (traffic_entities.py), pushed by SIGNAL_TRAFFIC_ANALYTICS. Router
# sensors: ``<entry_id>_traffic_<key>``; optional client sensors (at most
# TRAFFIC_CLIENT_SENSORS_MAX clients, chosen in the panel settings):
# ``openwrt_router_fleet_traffic_client_<client_ref>_<down|up>``.
DATA_TRAFFIC_ENTITIES = f"{DOMAIN}_traffic_entities"
TRAFFIC_UID_INFIX = "_traffic_"
UID_FLEET_TRAFFIC_CLIENT_PREFIX = f"{FLEET_UID_PREFIX}traffic_client_"
TRAFFIC_CLIENT_SENSORS_MAX = 20
# --- Ende Traffic Analytics ---


# --- Network Time Machine (Phase A) ---
# A read layer over the modules that already keep history (tm_sources,
# tm_query, tm_views): no store, no router call, no listener, no task.
# ONE fleet-wide switch, off by default. It lives in the options of every
# router entry (the options flow writes the value through to all entries);
# the Time Machine is on while any entry has it on.
OPTION_TIME_MACHINE_ENABLED = "time_machine_enabled"
DEFAULT_TIME_MACHINE_ENABLED = False
DATA_TIME_MACHINE_VIEWS_BOUND = f"{DOMAIN}_time_machine_views_bound"
DATA_TIME_MACHINE_STATS = f"{DOMAIN}_time_machine_stats"  # memory only
# Phase B/C (own index, tm_store / tm_engine / tm_clients): created only
# while the Time Machine is on. Client histories have their own switch,
# also off by default and also written through to every router entry; it
# has an effect only while the Time Machine itself is on.
OPTION_TIME_MACHINE_CLIENTS = "time_machine_clients"
DEFAULT_TIME_MACHINE_CLIENTS = False
DATA_TIME_MACHINE_ENGINE = f"{DOMAIN}_time_machine_engine"
TIME_MACHINE_STORE_KEY = f"{DOMAIN}.time_machine"
TIME_MACHINE_STORE_VERSION = 1
TIME_MACHINE_STORE_MINOR_VERSION = 2  # 1.52.0: seen, clients_cov, lost
SERVICE_TIME_MACHINE_FORGET_CLIENT = "time_machine_forget_client"
SERVICE_TIME_MACHINE_CLEAR = "time_machine_clear_history"
# --- Ende Network Time Machine ---
