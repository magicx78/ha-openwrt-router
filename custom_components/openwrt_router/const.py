"""Constants for the OpenWrt Router integration."""

from __future__ import annotations

# Integration domain
DOMAIN = "openwrt_router"
INTEGRATION_NAME = "OpenWrt Router"

# Default connection values
DEFAULT_HOST = ""
DEFAULT_PORT = 80
DEFAULT_USERNAME = "root"
DEFAULT_VERIFY_SSL = False

# HTTP / ubus
UBUS_PATH = "/ubus"
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_SESSION_ID = "00000000000000000000000000000000"

# Update interval
SCAN_INTERVAL_SECONDS = 30

# How many poll cycles between re-fetching static board info (model, hostname, release).
# 20 cycles × 30 s = ~10 minutes.  Hostname changes are rare; this avoids a
# system/board call on every poll while still detecting changes eventually.
BOARD_REFRESH_CYCLES = 20

# Config entry keys
CONF_HOST = "host"
CONF_PORT = "port"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"

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

# Entity unique ID suffixes
SUFFIX_UPTIME = "uptime"
SUFFIX_WAN_STATUS = "wan_status"
SUFFIX_CLIENT_COUNT = "client_count"
SUFFIX_WIFI_24 = "wifi_24ghz"
SUFFIX_WIFI_50 = "wifi_5ghz"
SUFFIX_WIFI_60 = "wifi_6ghz"
SUFFIX_GUEST_WIFI = "guest_wifi"
SUFFIX_RELOAD_WIFI = "reload_wifi"
SUFFIX_CPU_LOAD = "cpu_load"
SUFFIX_MEMORY_USAGE = "memory_usage"
SUFFIX_MEMORY_FREE = "memory_free"
SUFFIX_WAN_IP = "wan_ip"
SUFFIX_WAN_RX = "wan_rx"
SUFFIX_WAN_TX = "wan_tx"
SUFFIX_FIRMWARE = "firmware"

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
KEY_UPTIME = "uptime"
KEY_WAN_STATUS = "wan_status"
KEY_WAN_CONNECTED = "wan_connected"
KEY_WIFI_RADIOS = "wifi_radios"
KEY_CLIENTS = "clients"
KEY_CLIENT_COUNT = "client_count"
KEY_FEATURES = "features"
KEY_CPU_LOAD = "cpu_load"
KEY_MEMORY = "memory"

# WiFi radio state keys
RADIO_KEY_NAME = "name"
RADIO_KEY_SSID = "ssid"
RADIO_KEY_BAND = "band"
RADIO_KEY_ENABLED = "enabled"
RADIO_KEY_IS_GUEST = "is_guest"
RADIO_KEY_IFNAME = "ifname"
RADIO_KEY_UCI_SECTION = "uci_section"

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

# TODO: per-client online time - add CLIENT_KEY_CONNECTED_SINCE
# TODO: parental control - add UBUS_PARENTAL_OBJECT
# TODO: link quality metrics - add CLIENT_KEY_SIGNAL_QUALITY, CLIENT_KEY_NOISE

# DHCP lease data key (coordinator)
KEY_DHCP_LEASES = "dhcp_leases"
