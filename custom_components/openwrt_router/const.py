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
    return "https" if protocol == PROTOCOL_HTTPS_INSECURE else (protocol or PROTOCOL_HTTP)

# HTTP / ubus
UBUS_PATH = "/ubus"
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_SESSION_ID = "00000000000000000000000000000000"

# Session management
# OpenWrt default rpcd TTL is 300s regardless of the requested timeout.
# We track expiry and refresh 60s before deadline to avoid mid-poll expiry.
SESSION_LIFETIME_SECONDS = 300
SESSION_REFRESH_MARGIN_SECONDS = 60

# Update interval
SCAN_INTERVAL_SECONDS = 60

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
UBUS_SESSION_OBJECT_LOGIN = "session"

UBUS_SYSTEM_OBJECT = "system"
UBUS_SYSTEM_BOARD = "board"
UBUS_SYSTEM_INFO = "info"

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

# Known WAN interface names (OpenWrt conventions across versions)
WAN_INTERFACE_NAMES = ("wan", "wan6", "pppoe-wan", "wwan")

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

# Error type values stored in coordinator.data.error_type
ERROR_TYPE_CONNECTION = "connection"
ERROR_TYPE_AUTH = "auth"
ERROR_TYPE_TIMEOUT = "timeout"
ERROR_TYPE_RESPONSE = "response"

# Persistent notification fires after this many consecutive poll failures
NOTIFICATION_FAILURE_THRESHOLD = 3

# Entity unique ID suffixes
SUFFIX_UPTIME = "uptime"
SUFFIX_WAN_STATUS = "wan_status"
SUFFIX_CLIENT_COUNT = "client_count"
SUFFIX_WIFI_24 = "wifi_24ghz"
SUFFIX_WIFI_50 = "wifi_5ghz"
SUFFIX_WIFI_60 = "wifi_6ghz"
SUFFIX_GUEST_WIFI = "guest_wifi"
SUFFIX_RELOAD_WIFI = "reload_wifi"
SUFFIX_CHECK_UPDATES = "check_updates"
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
RADIO_KEY_MODE = "mode"    # "Master" | "Client" | "Monitor" | None
RADIO_KEY_BSSID = "bssid"

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

CLIENT_KEY_CONNECTED_SINCE = "connected_since"
CLIENT_KEY_DHCP_EXPIRES = "dhcp_expires"

# Fritz!Box config (stored in config entry data, set during setup)
CONF_FRITZBOX_HOST = "fritzbox_host"
CONF_FRITZBOX_USER = "fritzbox_user"
CONF_FRITZBOX_PASSWORD = "fritzbox_password"
CONF_FRITZBOX_PORT = "fritzbox_port"
DEFAULT_FRITZBOX_HOST = "172.16.1.254"
DEFAULT_FRITZBOX_PORT = 49000

# Switch config (stored in config entry data, set during setup)
CONF_SWITCH_HOST = "switch_host"
CONF_SWITCH_PORT = "switch_port"
CONF_SWITCH_PROTOCOL = "switch_protocol"
CONF_SWITCH_USERNAME = "switch_username"
CONF_SWITCH_PASSWORD = "switch_password"
DEFAULT_SWITCH_PORT = 443

# Fritz!Box coordinator data keys
KEY_DSL_STATS = "dsl_stats"
KEY_WAN_TRAFFIC = "wan_traffic"
KEY_DSL_HISTORY = "dsl_history"   # list of HistoryPoint dicts
KEY_PING_MS = "ping_ms"
KEY_DDNS_STATUS = "ddns_status"

# History: store one point every N poll cycles (N × 30s = interval)
# 2 cycles × 30s = 60s resolution, 1440 points = 24h
DSL_HISTORY_INTERVAL_CYCLES = 2
DSL_HISTORY_MAX_POINTS = 1440

# CPU history: one point per poll (30s resolution), 120 points = 1h rolling window
CPU_HISTORY_MAX_POINTS = 120
KEY_CPU_HISTORY = "cpu_history"

# Topology snapshots: one snapshot every 10 poll cycles (5 min), max 20 = ~100 min history
TOPOLOGY_SNAPSHOT_INTERVAL_CYCLES = 10
TOPOLOGY_SNAPSHOT_MAX = 20
KEY_TOPOLOGY_SNAPSHOTS = "topology_snapshots"

# TODO: parental control - add UBUS_PARENTAL_OBJECT

# DHCP lease data key (coordinator)
KEY_DHCP_LEASES = "dhcp_leases"

# Service Management (procd / rc)
UBUS_RC_OBJECT = "rc"
UBUS_RC_LIST = "list"
UBUS_RC_INIT = "init"
UBUS_SERVICE_OBJECT = "service"
UBUS_SERVICE_LIST = "list"

# Services to monitor/control by default (OpenWrt critical services)
DEFAULT_SERVICES = ["dnsmasq", "dropbear", "firewall", "network", "uhttpd", "wpad"]

KEY_SERVICES = "services"
FEATURE_HAS_SERVICES = "has_services"
