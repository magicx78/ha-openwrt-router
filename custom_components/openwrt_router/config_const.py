"""Constants for the configuration manager (backups, UCI snapshots, drift).

Plan: docs/plans/2026-11-17-config-manager.md, section 11.1. Everything the
config_* modules share lives here, not in const.py.

Area and risk values are plain strings. config_diff defines the StrEnums
``Area``/``Risk`` with exactly these values, so both compare equal.

Secrets are masked by ``core_masking`` only; this module adds the thin
bridge for the names the core does not catch yet (section "Secrets").

This module is pure: no Home Assistant imports, no I/O.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from fnmatch import fnmatchcase
from types import MappingProxyType
from typing import Any, Final

from .core_masking import (
    MASK,
    MAX_DEPTH,
    READABLE_CONTEXT_OPTIONS,
    SAFE_KEYS,
    is_secret_key,
    is_secret_option,
    is_secret_path,
    is_snapshot_secret,
    mask_for_output,
    mask_value,
    redact_text,
)

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
)
# Single allowed targets outside the prefixes. Only /etc/mtab -> /proc/mounts
# is needed; a /proc prefix would allow /proc/1/root (= "/") (review L3).
ARCHIVE_SYMLINK_ABS_EXACT: Final[frozenset[str]] = frozenset({"/proc/mounts"})
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
# Secrets (plan section 14): core_masking plus a thin bridge
# ---------------------------------------------------------------------------
#
# There is exactly one masking, ``core_masking`` (contract
# docs/dev/configuration-api-v1.md section 13): names, patterns, whitelist,
# archive paths, digest, placeholder and free-text rules all come from it.
# The names and the pattern below are only what the configuration manager
# caught before the switch and core_masking 1.44.0 does not ("gap in the
# core, bridged here"). The functions further down put them ON TOP of the
# core (secret if the core OR the bridge says so); they never lift a core
# decision. Each gap has an acceptance test in tests/test_config_mask.py
# (``test_bridge_*``); once the core covers a name, drop it here.

# Exact UCI option names that are secret in every config. network: GRE keys
# (ikey/okey), openconnect OTP secret and form fields, generic key
# spellings; openvpn: static TLS keys and the PKCS#12 bundle (the core reads
# them as file paths and keeps them readable); luci session store; usteer
# key_value (the core keeps it readable). An exact name here wins over the
# core's readable names.
CONFIG_EXTRA_SECRET_OPTIONS: Final[frozenset[str]] = frozenset(
    {
        "authkey",
        "form_entry",
        "ikey",
        "key_value",
        "okey",
        "otp",
        "pkcs12",
        "privkey",
        "sauth",
        "sharedkey",
        "tls_auth",
        "tls_crypt",
        "tls_crypt_v2",
    }
)

# Safety net for unknown names, the part of the former pattern the core's
# precise pattern lacks: "key" at the end of a word (also CamelCase
# "accessKey"), "key_" ("key_value"), "auth...key", raw daemon options
# ("*_options"), a standalone "otp" and "cookie" ("peer_cookie"). Searched
# in the normalised name. The core's readable names (SAFE_KEYS and every
# name of READABLE_CONTEXT_OPTIONS, in any config, as the former whitelist)
# are exempt from it, never from the exact names above.
CONFIG_EXTRA_SECRET_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"cookie|key\d*$|key_|auth[a-z0-9_]{0,32}key|_options$|(?:^|_)otp(?:$|_)"
)


def _normalised_option(name: str) -> str:
    """Lower case, ``-`` as ``_``, no quotes/leading dashes, last dotted part.

    The same normalisation as core_masking applies to names.
    """
    norm = name.strip().strip("'\"").lower().replace("-", "_").lstrip("_")
    return norm.rsplit(".", 1)[-1]


_CORE_READABLE_NAMES: Final[frozenset[str]] = SAFE_KEYS | frozenset(
    name for rule in READABLE_CONTEXT_OPTIONS for name in rule.options
)


def _bridge_secret(norm: str) -> bool:
    """True if the bridge (not the core) calls a normalised name secret."""
    if norm in CONFIG_EXTRA_SECRET_OPTIONS:
        return True
    return norm not in _CORE_READABLE_NAMES and bool(
        CONFIG_EXTRA_SECRET_PATTERN.search(norm)
    )


def is_config_secret_option(config: str, section_type: str, option: str) -> bool:
    """True if UCI ``config.<section_type>.option`` holds a secret.

    The snapshot decision (digest marker instead of the value) and the diff's
    secret flag: the core's precise rule
    (:func:`core_masking.is_snapshot_secret`, readable switches such as
    dropbear ``PasswordAuth`` or wireless ``sae_pwe`` stay plain text) OR
    the bridge above.
    """
    if is_snapshot_secret(config, section_type, option):
        return True
    if not isinstance(option, str):
        return False
    norm = _normalised_option(option)
    return bool(norm) and _bridge_secret(norm)


def _is_bridge_name(name: object) -> bool:
    """True for a mapping key / free-text name the bridge calls secret."""
    if isinstance(name, bytes):
        name = name.decode("utf-8", errors="replace")
    if not isinstance(name, str):
        return False
    norm = _normalised_option(name)
    return bool(norm) and _bridge_secret(norm)


# Record shapes as core_masking reads them: a change record names its
# option, a field record its field; these keys then carry the values.
_RECORD_VALUE_KEYS: Final = frozenset(
    {"old", "new", "value", "values", "before", "after", "current", "previous"}
)
_RECORD_NAME_KEYS: Final = ("key", "name", "field", "param", "parameter", "setting")


def _record_is_bridge_secret(mapping: Mapping[Any, Any]) -> bool:
    option = mapping.get("option")
    if isinstance(option, str):
        return _is_bridge_name(option)
    return any(_is_bridge_name(mapping.get(key)) for key in _RECORD_NAME_KEYS)


def _bridge_value(key: Any, value: Any, masked: bool) -> tuple[bool, Any]:
    """(True, masked value) if the bridge masks ``value`` under ``key``."""
    if masked or _is_bridge_name(key):
        return True, mask_value(value)
    if isinstance(key, bytes) and is_secret_path(key.decode("utf-8", errors="replace")):
        # The core checks archive paths on str keys only.
        keep = value is None or isinstance(value, bool | int | float)
        return True, value if keep else MASK
    return False, value


def _bridge_namedtuple(obj: Any, stack: set[int], depth: int) -> Any:
    """A namedtuple read like a record (the field names decide).

    The core masks a namedtuple by field name only, so a change record as a
    namedtuple (``option="key"``, ``old=…``) would keep its values; and it
    rebuilds the type without a fallback. Here the record rule is applied
    (core OR bridge), the secret fields are masked, and a type that refuses
    the masked values becomes a dict.
    """
    as_map = dict(zip(obj._fields, obj, strict=False))
    option = as_map.get("option")
    record = _record_is_bridge_secret(as_map) or (
        isinstance(option, str)
        and is_secret_option(
            str(as_map.get("config") or ""),
            str(as_map.get("section_type", as_map.get("type")) or ""),
            option,
        )
    )
    items = [
        mask_value(item)
        if (record and name.lower() in _RECORD_VALUE_KEYS)
        or is_secret_key(name)
        or _is_bridge_name(name)
        else _bridge(item, stack, depth + 1)
        for name, item in as_map.items()
    ]
    try:
        return type(obj)(*items)
    except Exception:  # noqa: BLE001 - a custom __new__ may refuse the mask
        return dict(zip(obj._fields, items, strict=False))


def _bridge(obj: Any, stack: set[int], depth: int) -> Any:
    """Copy of ``obj`` with only the bridge's secrets masked.

    Walks what core_masking walks (mappings, dataclasses, lists, tuples,
    namedtuples); everything else, deeper nesting and cycles are left to
    the core, which masks or truncates them.
    """
    is_dc = is_dataclass(obj) and not isinstance(obj, type)
    if depth > MAX_DEPTH or not (is_dc or isinstance(obj, Mapping | list | tuple)):
        return obj
    ident = id(obj)
    if ident in stack:
        return MASK  # a cycle, masked as the core masks it
    stack.add(ident)
    try:
        if is_dc:
            obj = {f.name: getattr(obj, f.name) for f in fields(obj)}
        if isinstance(obj, Mapping):
            masked = _record_is_bridge_secret(obj)
            out: dict[Any, Any] = {}
            for key, value in obj.items():
                in_record = masked and isinstance(key, str)
                hit, new = _bridge_value(
                    key, value, in_record and key.lower() in _RECORD_VALUE_KEYS
                )
                out[key] = new if hit else _bridge(value, stack, depth + 1)
            return out
        if isinstance(obj, tuple) and hasattr(obj, "_fields"):
            return _bridge_namedtuple(obj, stack, depth)
        items = [_bridge(item, stack, depth + 1) for item in obj]
        return items if isinstance(obj, list) else tuple(items)
    finally:
        stack.discard(ident)


def is_config_secret_name(name: object) -> bool:
    """The name decision of :func:`config_mask_for_output` for a mapping key.

    :func:`core_masking.is_secret_key` (broad: readable switches without a
    config such as ``sae_pwe`` count as secret) OR the bridge.
    """
    return is_secret_key(name) or _is_bridge_name(name)


def config_mask_for_output(data: Any) -> Any:
    """:func:`core_masking.mask_for_output` with the bridge's names on top.

    The last barrier before HTTP responses, logs and events of the
    configuration manager. Never mutates ``data``.
    """
    return mask_for_output(_bridge(data, set(), 0))


# Free-text heads after which a value follows (UCI file line, assignment /
# JSON pair, command-line flag). Names are taken possessively from the start
# of a run of name characters, so the scan stays linear.
_TEXT_HEAD_RES: Final = (
    re.compile(r"\b(?:option|list)[ \t]+(['\"]?)(?P<name>[A-Za-z0-9_.\-]++)\1[ \t]+"),
    re.compile(
        r"(?P<q>[\"']?)(?<![\w.@\[\]\-])(?P<name>[\w.@\[\]\-]++)(?P=q)[ \t]*[=:][ \t]*"
    ),
    re.compile(r"(?<![\w\-])(?P<name>--?[A-Za-z][A-Za-z0-9_\-]*+)[ \t]+(?=[^\s\-])"),
)
# A quoted value the core masked after an assignment, a tab or a flag,
# followed by more text on the same line: the core ends a quoted value at
# its closing quote and keeps the rest ("psk='a' x S", "psk='a'; S"). As
# before the switch, the rest of such a line goes too (over-masking on
# purpose). Unquoted values already run to the end of the line in the core.
_MASKED_THEN_REST_RE: Final = re.compile(
    r"(?P<head>(?:[=:]|(?<!\S)--?[A-Za-z][A-Za-z0-9_\-]*+)[ \t]*+|\t)"
    r"(?P<value>(?P<q>['\"])" + re.escape(MASK) + r"(?P=q))(?P<rest>[^\r\n]+)"
)


def _mask_rest(match: re.Match[str]) -> str:
    rest = match.group("rest")
    if not rest.strip():
        return match.group(0)
    return f"{match.group('head')}{match.group('value')} {MASK}"


def _mask_bridge_heads(text: str, head_re: re.Pattern[str]) -> str:
    """Mask the rest of the line after every head naming a bridge secret."""
    out: list[str] = []
    pos = 0
    for match in head_re.finditer(text):
        if match.start() < pos or not _is_bridge_name(match.group("name")):
            continue
        end = text.find("\n", match.end())
        end = len(text) if end < 0 else end
        if end > match.end() and text[end - 1] == "\r":
            end -= 1
        if end <= match.end():
            continue
        value = text[match.end() : end]
        quoted = len(value) >= 2 and value[0] in "'\"" and value[-1] == value[0]
        out.append(text[pos : match.end()])
        out.append(f"{value[0]}{MASK}{value[0]}" if quoted else MASK)
        pos = end
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


def config_redact_text(text: object) -> str:
    """:func:`core_masking.redact_text` with the bridge on top.

    After the core: values after a head naming a bridge secret (``option
    ikey '…'``, ``okey=…``, ``--form-entry …``) are masked to the end of the
    line, and so is the rest of a line after a value the core masked. The
    core already cut the text to its length limit, so this stays linear.
    """
    out = redact_text(text)
    for head_re in _TEXT_HEAD_RES:
        out = _mask_bridge_heads(out, head_re)
    return _MASKED_THEN_REST_RE.sub(_mask_rest, out)


# Review M4: archive members a restore writes back that decide how one logs
# in (passwords, SSH keys, SSH host keys, the uhttpd TLS key pair). Same
# glob rules as core_masking.SECRET_ARCHIVE_PATHS. Only their presence is
# reported.
ACCESS_ARCHIVE_PATHS: Final[tuple[str, ...]] = (
    "etc/shadow",
    "etc/passwd",
    "etc/dropbear/authorized_keys",
    "etc/dropbear/*host_key*",
    "*/.ssh/authorized_keys*",
    "etc/uhttpd.key",
    "etc/uhttpd.crt",
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
# Manual router work of the manager (routes and service): one manual
# backup (R5 / service) and one manual live check (R8 live, R10, R12) per
# router at most every this many seconds; earlier -> 429 + Retry-After.
MANUAL_BACKUP_MIN_GAP_S: Final = 60
MANUAL_LIVE_CHECK_MIN_GAP_S: Final = 60
# Retry-After of a 409 while the router (or the fleet slot) is busy.
ROUTER_BUSY_RETRY_AFTER_S: Final = 30
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
# Not in the plan: the pinned SSH path refused (first-seen host key pending,
# other key, no pin store). The core's class for a refused call; never
# skipped for FETCH_SKIP_TTL_S (an admin may confirm the key at any time).
ERR_DENIED: Final = "denied"

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
    ERR_DENIED,
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
