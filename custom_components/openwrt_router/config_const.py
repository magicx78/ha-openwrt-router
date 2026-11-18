"""Constants for the configuration manager (backups, UCI snapshots, drift).

Plan: docs/plans/2026-11-17-config-manager.md, section 11.1. Everything the
config_* modules share lives here, not in const.py.

Area and risk values are plain strings. config_diff defines the StrEnums
``Area``/``Risk`` with exactly these values, so both compare equal.

This module is pure: no Home Assistant imports, no I/O.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from types import MappingProxyType
from typing import Final

_LOGGER = logging.getLogger(__name__)

_MIB: Final = 1024 * 1024

# ---------------------------------------------------------------------------
# Archive checks (plan section 7)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    """Hard limits for validating a ``sysupgrade -b`` archive in memory."""

    max_compressed: int = 16 * _MIB
    max_uncompressed_total: int = 64 * _MIB
    max_member_size: int = 16 * _MIB
    max_members: int = 5000
    max_ratio: int = 200
    max_name_length: int = 255


DEFAULT_ARCHIVE_LIMITS: Final = ArchiveLimits()

# Absolute symlink targets OpenWrt itself creates (e.g. zoneinfo links, and
# /etc/resolv.conf -> /tmp/resolv.conf when a backup covers all of /etc).
# The archive is never extracted, so a link into runtime trees is harmless.
ARCHIVE_SYMLINK_ABS_PREFIXES: Final[tuple[str, ...]] = (
    "/etc/",
    "/usr/",
    "/lib/",
    "/tmp/",
    "/var/",
    "/proc/",
)
# Configs an archive must contain under etc/config/, otherwise "incomplete".
ARCHIVE_REQUIRED_CONFIGS: Final[frozenset[str]] = frozenset({"network", "system"})
ARCHIVE_CONFIG_PREFIX: Final = "etc/config/"
GZIP_MAGIC: Final = b"\x1f\x8b"

# ---------------------------------------------------------------------------
# UCI configs read for the snapshot (plan section 2.2, same list as the ACL)
# ---------------------------------------------------------------------------

UCI_CONFIGS: Final[tuple[str, ...]] = (
    "network",
    "wireless",
    "firewall",
    "dhcp",
    "system",
    "dropbear",
    "uhttpd",
    "rpcd",
    "ddns",
    "sqm",
    "usteer",
    "mwan3",
    "upnpd",
    "openvpn",
)

# ---------------------------------------------------------------------------
# Secrets (plan section 14)
# ---------------------------------------------------------------------------

MASK_PLACEHOLDER: Final = "***"
# redact_text works on at most this many characters (review H4); longer
# text is cut first and gets the marker appended. stderr is cut at 4 KiB
# already, so only hostile or broken input reaches the cap.
REDACT_MAX_CHARS: Final = 65536
REDACT_TRUNCATED: Final = " [truncated]"
# Snapshot form of a secret value: {"secret": "<hmac16>"} (plan 3.2 point 6).
SECRET_MARKER_KEY: Final = "secret"
SECRET_DIGEST_LENGTH: Final = 16
SECRET_DIGEST_MIN_KEY_BYTES: Final = 16

# 14.1 exact option names, independent of the config.
SECRET_OPTIONS: Final[frozenset[str]] = frozenset(
    {
        "key",
        "key1",
        "key2",
        "key3",
        "key4",
        "password",
        "passwd",
        "psk",
        "sae_password",
        "auth_secret",
        "acct_secret",
        "dae_secret",
        "priv_key_pwd",
        "private_key",
        "preshared_key",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth_key",
        "shared_secret",
        "pre_shared_key",
        "pin",
        "pincode",
        "wps_pin",
        "r0kh",
        "r1kh",
        "mesh_psk",
        "nas_secret",
        # Review C2. network: 6in4 tunnelbroker update key, raw pppd
        # options (may carry "password …"), GRE tunnel keys, openconnect
        # OTP secret and form fields; openvpn: static TLS keys and the
        # PKCS#12 bundle; luci session store; generic key spellings.
        "updatekey",
        "pppd_options",
        "authkey",
        "sharedkey",
        "privkey",
        "otp",
        "ikey",
        "okey",
        "token_secret",
        "form_entry",
        "tls_auth",
        "tls_crypt",
        "tls_crypt_v2",
        "pkcs12",
        "sauth",
    }
)


@dataclass(frozen=True, slots=True)
class SecretContextRule:
    """Options that are secret inside a given config/section type (globs)."""

    config: str
    section_type: str
    options: frozenset[str]


# 14.1 context-dependent names. The masking treats these names as secret
# everywhere as well (over-masking is harmless, under-masking is not).
SECRET_CONTEXT_OPTIONS: Final[tuple[SecretContextRule, ...]] = (
    SecretContextRule(
        "ddns",
        "service",
        frozenset({"password", "param_enc", "param_opt", "update_url"}),
    ),
    SecretContextRule("rpcd", "login", frozenset({"password"})),
    SecretContextRule("network", "interface", frozenset({"password", "pincode"})),
    SecretContextRule(
        "network", "wireguard_*", frozenset({"private_key", "preshared_key"})
    ),
    SecretContextRule(
        "openvpn", "*", frozenset({"auth_user_pass", "askpass", "secret", "key"})
    ),
)

# Not UCI options, but names that carry credentials in HTTP bodies, headers
# and command output (plan 14.3: the ubus session token).
SECRET_EXTRA_NAMES: Final[frozenset[str]] = frozenset(
    {
        "sessionid",
        "session_id",
        "ubus_rpc_session",
        "authorization",
        "proxy_authorization",
        "cookie",
        "set_cookie",
    }
)

# Safety net for unknown names. Plan 14.1 pattern plus "pwd" and "apikey".
# Matched with re.search against the lower-case name, "-" normalised to "_".
# Review C2 widened it: "key" at the end of a word (also CamelCase
# "accessKey" -> "accesskey", digits allowed: "key2") or followed by "_"
# ("key_value"), "auth…key", "*_options" (raw daemon options such as
# pppd_options), a standalone "otp" and "cookie" (l2tpv3 cookies).
SECRET_OPTION_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"(pass|secret|token|psk|private|credential|pwd|apikey|cookie"
        r"|key\d*$|key_|auth[a-z0-9_]{0,32}key|_options$|(?:^|_)otp(?:$|_)|pin$)"
    ),
)

# Names the pattern would hit but whose value is not secret and is needed.
# Applies only to the pattern, never to SECRET_OPTIONS or context names.
# Entries are lower-case: the check runs on the normalised (lower-case) name.
# dropbear PasswordAuth/RootPasswordAuth are on/off switches; the diff must
# show "on -> off" because they decide whether HA can still log in. The
# rest are hostapd/wireless, dropbear, openvpn and RADIUS settings whose
# names look like secrets (review C2, exact list).
SECRET_OPTION_WHITELIST: Final[frozenset[str]] = frozenset(
    {
        "ft_psk_generate_local",
        "keepalive",
        "persistent_keepalive",
        "key_mgmt",
        "passwordauth",
        "rootpasswordauth",
        "maxauthtries",
        "sae_pwe",
        "sae_require_mfp",
        "wpa_group_rekey",
        "wpa_disable_eapol_key_retries",
        "wpa_strict_rekey",
        "auth_cache",
        "r0_key_lifetime",
        "auth_type",
        "auth_nocache",
        "key_direction",
        "auth_server",
        "auth_port",
        "acct_server",
        "acct_port",
        "macfilter",
        "maclist",
    }
)

# 14.2 archive members whose content never leaves HA (path + presence only).
# fnmatch globs against the normalised, lower-case member name; "*" also
# matches "/", so "etc/wireguard/*" covers sub-directories.
SECRET_ARCHIVE_PATHS: Final[tuple[str, ...]] = (
    "etc/shadow",
    "etc/shadow-",
    "etc/passwd",
    "etc/passwd-",
    "etc/dropbear/*",
    "root/.ssh/*",
    "*/.ssh/*",
    "etc/uhttpd.key",
    "etc/config/rpcd",
    "etc/config/wireless",
    "etc/config/network",
    "etc/config/ddns",
    "etc/config/openvpn",
    "etc/config/acme",
    "etc/wireguard/*",
    "etc/openvpn/*",
    "etc/acme/*",
    "etc/ssl/private/*",
    "etc/luci-uploads/*",
    "etc/ipsec.secrets",
    "etc/swanctl/*",
    "etc/ppp/chap-secrets",
    "etc/ppp/pap-secrets",
    "etc/crontabs/*",
    "*.psk",
    "*.key",
    "*.p12",
    "*.pfx",
)

# ---------------------------------------------------------------------------
# Areas and risks (plan section 11.6)
# ---------------------------------------------------------------------------

AREA_VLAN: Final = "vlan"
AREA_INTERFACE: Final = "interface"
AREA_MGMT_IP: Final = "mgmt_ip"
AREA_FIREWALL: Final = "firewall"
AREA_DHCP: Final = "dhcp"
AREA_DNS: Final = "dns"
AREA_WLAN: Final = "wlan"
AREA_ROUTING: Final = "routing"
AREA_SERVICES: Final = "services"
AREA_SSH: Final = "ssh"
AREA_SYSTEM: Final = "system"
AREA_OTHER: Final = "other"

AREAS: Final[tuple[str, ...]] = (
    AREA_VLAN,
    AREA_INTERFACE,
    AREA_MGMT_IP,
    AREA_FIREWALL,
    AREA_DHCP,
    AREA_DNS,
    AREA_WLAN,
    AREA_ROUTING,
    AREA_SERVICES,
    AREA_SSH,
    AREA_SYSTEM,
    AREA_OTHER,
)

RISK_CRITICAL: Final = "critical"
RISK_HIGH: Final = "high"
RISK_MEDIUM: Final = "medium"
RISK_LOW: Final = "low"

# Highest first; index = severity rank.
RISKS: Final[tuple[str, ...]] = (RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW)

# A pure reordering of a list or of sections.
RISK_REORDERED: Final = RISK_LOW

# Fallback area per config when no RISK_RULES entry matches.
AREA_RULES: Final = MappingProxyType(
    {
        "network": AREA_INTERFACE,
        "wireless": AREA_WLAN,
        "firewall": AREA_FIREWALL,
        "dhcp": AREA_DHCP,
        "system": AREA_SYSTEM,
        "dropbear": AREA_SSH,
        "uhttpd": AREA_SSH,
        "rpcd": AREA_SSH,
        "ddns": AREA_SERVICES,
        "sqm": AREA_SERVICES,
        "usteer": AREA_SERVICES,
        "mwan3": AREA_SERVICES,
        "upnpd": AREA_SERVICES,
        "openvpn": AREA_SERVICES,
    }
)

# Fallback risk per area. Unknown configs land in OTHER = medium (conservative).
AREA_DEFAULT_RISK: Final = MappingProxyType(
    {
        AREA_VLAN: RISK_CRITICAL,
        AREA_INTERFACE: RISK_HIGH,
        AREA_MGMT_IP: RISK_CRITICAL,
        AREA_FIREWALL: RISK_HIGH,
        AREA_DHCP: RISK_MEDIUM,
        AREA_DNS: RISK_MEDIUM,
        AREA_WLAN: RISK_MEDIUM,
        AREA_ROUTING: RISK_HIGH,
        AREA_SERVICES: RISK_LOW,
        AREA_SSH: RISK_CRITICAL,
        AREA_SYSTEM: RISK_LOW,
        AREA_OTHER: RISK_MEDIUM,
    }
)

# Value-dependent rules are not expressible in the static table; config_diff
# applies them on top (they can only raise the risk):
# - MGMT_IP: network.interface carrying the host HA talks to (mgmt_host),
#   options below -> critical.
MGMT_IP_OPTIONS: Final[frozenset[str]] = frozenset(
    {"ipaddr", "netmask", "proto", "device", "ifname", "gateway", "ip6addr"}
)
# - Uplink by name (also in the static table) or by api.is_wan_interface.
UPLINK_INTERFACE_NAMES: Final[frozenset[str]] = frozenset({"wan", "wan6", "wwan"})
# - firewall rule/redirect without "dest" targets the router itself (input)
#   -> critical; same for any firewall rule touching the SSH port.
FIREWALL_INPUT_SECTION_TYPES: Final[frozenset[str]] = frozenset({"rule", "redirect"})
SSH_PORTS: Final[frozenset[str]] = frozenset({"22"})
# Review M3, all "critical":
# - LuCI/ubus ports (uhttpd); the listen_http(s) ports of the uhttpd config
#   count too. Hit by an input rule (no dest) or by any redirect (DNAT).
MGMT_WEB_PORTS: Final[frozenset[str]] = frozenset({"80", "443"})
# - a whole section of these types added or removed (zone, bridge, VLAN,
#   interface: each can cut HA off the router),
SECTION_PRESENCE_CRITICAL: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("firewall", "zone"),
        ("network", "bridge-vlan"),
        ("network", "device"),
        ("network", "interface"),
    }
)
# - with the management interface not known for sure (mgmt_host is a host
#   name, or its IP is on no interface statically, e.g. DHCP): a change to
#   these options of any non-uplink interface.
MGMT_ADDRESS_OPTIONS: Final[frozenset[str]] = MGMT_IP_OPTIONS | frozenset(
    {"ip6assign", "ip6hint", "ip6ifaceid", "ip6prefix", "ip6gw"}
)


@dataclass(frozen=True, slots=True)
class RiskRule:
    """One row of the static classification table.

    ``config`` and ``section_type`` are fnmatch globs (lower-case).
    ``section_names`` restricts to named sections (None = any).
    ``options`` restricts to option names (None = any, including a whole
    section being added or removed, i.e. option None).
    """

    config: str
    section_type: str
    area: str
    risk: str
    options: frozenset[str] | None = None
    section_names: frozenset[str] | None = None


def _opts(*names: str) -> frozenset[str]:
    return frozenset(names)


# First match wins, so specific/critical rows come first.
RISK_RULES: Final[tuple[RiskRule, ...]] = (
    # Uplinks (plan: Uplink -> critical, area INTERFACE).
    RiskRule(
        "network",
        "interface",
        AREA_INTERFACE,
        RISK_CRITICAL,
        section_names=UPLINK_INTERFACE_NAMES,
    ),
    # VLAN, DSA and swconfig.
    RiskRule("network", "bridge-vlan", AREA_VLAN, RISK_CRITICAL),
    RiskRule("network", "switch_vlan", AREA_VLAN, RISK_CRITICAL),
    RiskRule("network", "switch", AREA_VLAN, RISK_CRITICAL),
    RiskRule("network", "switch_port", AREA_VLAN, RISK_CRITICAL),
    RiskRule(
        "network",
        "device",
        AREA_VLAN,
        RISK_CRITICAL,
        options=_opts("ports", "type", "vid", "ifname"),
    ),
    RiskRule("network", "device", AREA_INTERFACE, RISK_HIGH),
    # DNS on interfaces, then interfaces in general.
    RiskRule(
        "network",
        "interface",
        AREA_DNS,
        RISK_MEDIUM,
        options=_opts("dns", "dns_search", "peerdns", "dns_metric"),
    ),
    RiskRule("network", "interface", AREA_INTERFACE, RISK_HIGH),
    RiskRule("network", "wireguard_*", AREA_INTERFACE, RISK_HIGH),
    # Routing.
    RiskRule("network", "route", AREA_ROUTING, RISK_HIGH),
    RiskRule("network", "route6", AREA_ROUTING, RISK_HIGH),
    RiskRule("network", "rule", AREA_ROUTING, RISK_HIGH),
    RiskRule("network", "rule6", AREA_ROUTING, RISK_HIGH),
    RiskRule("network", "globals", AREA_INTERFACE, RISK_MEDIUM),
    RiskRule("network", "*", AREA_INTERFACE, RISK_HIGH),
    # Firewall: input policy and zone membership can lock HA out.
    RiskRule("firewall", "defaults", AREA_FIREWALL, RISK_CRITICAL),
    RiskRule(
        "firewall",
        "zone",
        AREA_FIREWALL,
        RISK_CRITICAL,
        options=_opts("input", "network", "device", "subnet"),
    ),
    RiskRule("firewall", "*", AREA_FIREWALL, RISK_HIGH),
    # Management access.
    RiskRule("dropbear", "*", AREA_SSH, RISK_CRITICAL),
    RiskRule("uhttpd", "*", AREA_SSH, RISK_CRITICAL),
    RiskRule("rpcd", "*", AREA_SSH, RISK_CRITICAL),
    # WLAN.
    RiskRule("wireless", "wifi-iface", AREA_WLAN, RISK_HIGH),
    RiskRule(
        "wireless",
        "wifi-device",
        AREA_WLAN,
        RISK_MEDIUM,
        options=_opts(
            "channel",
            "channels",
            "htmode",
            "country",
            "txpower",
            "cell_density",
            "beacon_int",
        ),
    ),
    RiskRule("wireless", "wifi-device", AREA_WLAN, RISK_HIGH),
    RiskRule("wireless", "*", AREA_WLAN, RISK_MEDIUM),
    # DHCP and DNS (dnsmasq lives in the dhcp config).
    RiskRule("dhcp", "dnsmasq", AREA_DNS, RISK_MEDIUM),
    RiskRule("dhcp", "domain", AREA_DNS, RISK_MEDIUM),
    RiskRule("dhcp", "*", AREA_DHCP, RISK_MEDIUM),
    # Services.
    RiskRule("mwan3", "*", AREA_SERVICES, RISK_MEDIUM),
    RiskRule("openvpn", "*", AREA_SERVICES, RISK_MEDIUM),
    RiskRule("sqm", "*", AREA_SERVICES, RISK_LOW),
    RiskRule("ddns", "*", AREA_SERVICES, RISK_LOW),
    RiskRule("upnpd", "*", AREA_SERVICES, RISK_LOW),
    RiskRule("usteer", "*", AREA_SERVICES, RISK_LOW),
    # System.
    RiskRule("system", "*", AREA_SYSTEM, RISK_LOW),
)


def lookup_risk_rule(
    config: str,
    section_type: str,
    option: str | None,
    *,
    section_name: str = "",
) -> tuple[str, str]:
    """Return (area, risk) from the static table, with fallbacks.

    Only the static part. Value-dependent upgrades (MGMT_IP, firewall input,
    SSH port, is_wan_interface) are applied by config_diff.
    """
    cfg = config.lower()
    stype = section_type.lower()
    opt = option.lower() if option is not None else None
    name = section_name.lower()
    for rule in RISK_RULES:
        if not fnmatchcase(cfg, rule.config):
            continue
        if not fnmatchcase(stype, rule.section_type):
            continue
        if rule.section_names is not None and name not in rule.section_names:
            continue
        if rule.options is not None and (opt is None or opt not in rule.options):
            continue
        return rule.area, rule.risk
    area = AREA_RULES.get(cfg, AREA_OTHER)
    return area, AREA_DEFAULT_RISK[area]


# ---------------------------------------------------------------------------
# Fetching (plan sections 2.4, 9.3)
# ---------------------------------------------------------------------------

FETCH_METHOD_CGI: Final = "cgi"
FETCH_METHOD_SSH: Final = "ssh"
FETCH_METHODS: Final[tuple[str, ...]] = (FETCH_METHOD_CGI, FETCH_METHOD_SSH)
FETCH_JOB: Final = "job"
FETCH_UCI: Final = "uci"
FETCH_PACKAGELIST: Final = "packagelist"

# Seconds. cgi/ssh/job from plan 9.3; uci (per config) and packagelist are
# not in the plan and chosen here.
FETCH_TIMEOUTS: Final = MappingProxyType(
    {
        FETCH_METHOD_CGI: 60.0,
        FETCH_METHOD_SSH: 120.0,
        FETCH_JOB: 180.0,
        FETCH_UCI: 30.0,
        FETCH_PACKAGELIST: 60.0,
    }
)
FETCH_RETRY_DELAY_S: Final = 900
# A path that answered not_available/permission is skipped this long.
FETCH_SKIP_TTL_S: Final = 86400
# stderr kept from SSH, only to derive the error class, never logged raw.
STDERR_MAX_BYTES: Final = 4096
STREAM_CHUNK_BYTES: Final = 65536
# Router-supplied inventory fields (board name, model, release, kernel,
# package names and versions) longer than this are dropped, not cut: a cut
# value would pose as a real board name (review H4). Real values are far
# shorter (board names < 64, versions < 40 characters).
ROUTER_FIELD_MAX_CHARS: Final = 256
INVENTORY_MAX_PACKAGES: Final = 8192
# One UCI config text (``uci show`` output, an etc/config file of an archive)
# above this size is never parsed but reported as too large (review M6).
# Real configs stay far below (a large dhcp with 500 hosts is ~60 KiB).
# api.py's _CONFIG_UCI_SHOW_MAX_BYTES must equal this value.
UCI_TEXT_MAX_BYTES: Final = _MIB

# ---------------------------------------------------------------------------
# Drift and events (plan sections 3.3, 9.1, 8.4)
# ---------------------------------------------------------------------------

DRIFT_DEBOUNCE_S: Final = 300
DRIFT_MIN_INTERVAL_S: Final = 3600
FAILURE_EVENT_COOLDOWN_S: Final = 86400
SNAPSHOT_STALE_S: Final = 86400

# ---------------------------------------------------------------------------
# Error classes (plan section 12.2)
# ---------------------------------------------------------------------------

ERR_UNREACHABLE: Final = "unreachable"
ERR_TIMEOUT: Final = "timeout"
ERR_AUTH: Final = "auth"
ERR_PERMISSION: Final = "permission"
ERR_NOT_AVAILABLE: Final = "not_available"
ERR_TOO_LARGE: Final = "too_large"
ERR_INCOMPLETE: Final = "incomplete"
ERR_INVALID: Final = "invalid"
ERR_CHECKSUM_MISMATCH: Final = "checksum_mismatch"
ERR_STORAGE_FULL: Final = "storage_full"
ERR_STORAGE_ERROR: Final = "storage_error"

ERROR_CLASSES: Final[tuple[str, ...]] = (
    ERR_UNREACHABLE,
    ERR_TIMEOUT,
    ERR_AUTH,
    ERR_PERMISSION,
    ERR_NOT_AVAILABLE,
    ERR_TOO_LARGE,
    ERR_INCOMPLETE,
    ERR_INVALID,
    ERR_CHECKSUM_MISMATCH,
    ERR_STORAGE_FULL,
    ERR_STORAGE_ERROR,
)

# Errors that end the fetch chain at once (plan 2.3): the next method would
# ask the same dead router.
CHAIN_ABORT_ERRORS: Final[frozenset[str]] = frozenset({ERR_UNREACHABLE, ERR_TIMEOUT})
# Errors that mark a method as skipped for FETCH_SKIP_TTL_S.
CHAIN_SKIP_ERRORS: Final[frozenset[str]] = frozenset(
    {ERR_NOT_AVAILABLE, ERR_PERMISSION}
)

# Warning (not an error) from the archive/snapshot cross-check (plan 7).
WARN_CONFIG_MISSING_IN_ARCHIVE: Final = "config_missing_in_archive"
