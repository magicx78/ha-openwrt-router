"""Parse the OpenWrt logd ring buffer (``ubus call log read``) into events.

Pure functions and small state holders, no HA imports. Log lines are
untrusted router output: they are only matched against fixed patterns, never
executed, and the raw message is truncated before it leaves this module.

Entry shape (logd, OpenWrt 25.12)::

    {"msg": "hostapd: phy0-ap1: AP-STA-CONNECTED <mac> auth_alg=open",
     "id": 411704, "priority": 30, "source": 1, "time": 1793094113364}

``id`` grows monotonically per logd instance (a router reboot or logd
restart starts again at a low value), ``time`` is epoch milliseconds.

Kernel lines (``source`` 0) carry no process prefix; logread adds the
"kernel: " itself. Their exact form, and that of netifd, procd, odhcpd and
dnsmasq resolver lines, was not seen live (plan 2026-11-16, A6): the
patterns follow the upstream sources and are optional. No match means "no
data", never "healthy".
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

CATEGORY_WIFI = "wifi"
CATEGORY_DHCP = "dhcp"
CATEGORY_DFS = "dfs"
# Infrastructure lines (network intelligence, P3)
CATEGORY_LINK = "link"  # carrier of a network device (kernel, netifd)
CATEGORY_IFACE = "iface"  # logical netifd interface (wan, lan, ...)
CATEGORY_SYSTEM = "system"  # procd crash loop, kernel OOM kill
CATEGORY_DNS = "dns"  # dnsmasq resolver trouble
# Categories that become HA bus events (wifi/dhcp/dfs, unchanged); the
# others only feed the counters and the network intelligence engine.
FIRE_CATEGORIES = frozenset({CATEGORY_WIFI, CATEGORY_DHCP, CATEGORY_DFS})

WIFI_CONNECTED = "connected"
WIFI_DISCONNECTED = "disconnected"
WIFI_PSK_MISMATCH = "psk_mismatch"
WIFI_INACTIVITY = "inactivity_timeout"
WIFI_HANDSHAKE_FAILED = "handshake_failed"
# Network intelligence (P4). Normal operation, counted only:
WIFI_DEAUTH = "deauth"
WIFI_DISASSOC = "disassoc"
WIFI_HANDSHAKE_COMPLETED = "handshake_completed"
WIFI_STEER_CONNECTED = "usteer_connected"
WIFI_STEER_DISCONNECTED = "usteer_disconnected"
# Problems, stored by the engine but never fired as HA events (the bus
# keeps its P1 kinds). None of these was seen live (plan, P4).
WIFI_ASSOC_REJECTED = "assoc_rejected"
WIFI_SAE_FAILED = "sae_failed"
# wpa_supplicant of the router's own uplink (sta interface), no client MAC
WIFI_BACKHAUL_AUTH_FAILED = "backhaul_auth_failed"

# ``LogEvent.reason``: the plain-text reason of a hostapd line, normalised.
# hostapd at the default log level writes no ``reason=`` codes (live check).
REASON_INACTIVITY = "inactivity"
REASON_LOCAL_REQUEST = "local_request"
REASON_PRUNE = "prune"
REASON_OTHER = "other"
REASON_TIMEOUT = "timeout"
REASON_INVALID_MIC = "invalid_mic"
REASON_FAILED = "failed"
REASON_PSK = "psk"
REASON_MAX_STA = "max_sta"
REASON_BLOCKED = "blocked"

DHCP_ACK = "ack"
DHCP_NAK = "nak"
DHCP_DECLINE = "decline"
DHCP_NO_ADDRESS = "no_address"
DHCP_ODHCPD_ERROR = "odhcpd_error"

LINK_UP = "up"
LINK_DOWN = "down"
IFACE_UP = "up"
IFACE_DOWN = "down"
IFACE_LINK_LOST = "link_lost"
SYSTEM_CRASH_LOOP = "service_crash_loop"
SYSTEM_OOM_KILL = "oom_kill"
DNS_QUERY_LIMIT = "query_limit"
DNS_NO_SERVERS = "no_servers"
DNS_SEND_FAILED = "send_failed"

# hostapd DFS-* lines (radar detection, channel availability check)
DFS_RADAR_DETECTED = "radar_detected"
DFS_CAC_START = "cac_start"
DFS_CAC_COMPLETED = "cac_completed"
DFS_CAC_FAILED = "cac_failed"
DFS_NOP_FINISHED = "nop_finished"
DFS_NEW_CHANNEL = "new_channel"
DFS_PRE_CAC_EXPIRED = "pre_cac_expired"
# Not a log line: a radio's channel/width differed between two polls
DFS_CHANNEL_CHANGE = "channel_change"
# DFS lines that explain a channel change. cac_start/nop_finished are not:
# a manual switch onto a DFS channel also starts a CAC.
DFS_EVIDENCE_KINDS = frozenset({DFS_RADAR_DETECTED, DFS_NEW_CHANNEL, DFS_CAC_FAILED})

# Parsed for the counters (and client statistics) but never fired as event:
# they are normal operation and would crowd out the problems.
COUNT_ONLY_KINDS = frozenset(
    {
        (CATEGORY_WIFI, WIFI_CONNECTED),
        (CATEGORY_WIFI, WIFI_DISCONNECTED),
        (CATEGORY_DHCP, DHCP_ACK),
        # The engine derives port flaps and WAN reconnects from these lines
        # together with the poll, so the same change is not stored twice.
        (CATEGORY_LINK, LINK_UP),
        (CATEGORY_LINK, LINK_DOWN),
        (CATEGORY_IFACE, IFACE_UP),
        (CATEGORY_IFACE, IFACE_DOWN),
        (CATEGORY_IFACE, IFACE_LINK_LOST),
        # odhcpd repeats its errors on every RA/DHCPv6 round: count only.
        (CATEGORY_DHCP, DHCP_ODHCPD_ERROR),
        # P4: the WLAN detectors read these, they are no events of their own.
        (CATEGORY_WIFI, WIFI_DEAUTH),
        (CATEGORY_WIFI, WIFI_DISASSOC),
        (CATEGORY_WIFI, WIFI_HANDSHAKE_COMPLETED),
        (CATEGORY_WIFI, WIFI_STEER_CONNECTED),
        (CATEGORY_WIFI, WIFI_STEER_DISCONNECTED),
    }
)

# Stored by the network intelligence engine but never fired on the HA bus:
# the bus keeps exactly the kinds it had before P4.
ENGINE_ONLY_KINDS = frozenset(
    {
        (CATEGORY_WIFI, WIFI_ASSOC_REJECTED),
        (CATEGORY_WIFI, WIFI_SAE_FAILED),
        (CATEGORY_WIFI, WIFI_BACKHAUL_AUTH_FAILED),
    }
)

MESSAGE_MAX_LEN = 200

# Plausible logd timestamps (ms); anything else is treated as missing.
_TIME_MIN_MS = 946_684_800_000  # 2000-01-01
_TIME_MAX_MS = 4_102_444_800_000  # 2100-01-01

# Order in which events get the per-fetch budget (lower first): a burst of
# routine inactivity timeouts must not push out a wrong-password event.
_PRIORITY = {
    (CATEGORY_DFS, DFS_RADAR_DETECTED): 0,
    (CATEGORY_WIFI, WIFI_PSK_MISMATCH): 0,
    (CATEGORY_WIFI, WIFI_HANDSHAKE_FAILED): 0,
    (CATEGORY_DHCP, DHCP_NO_ADDRESS): 1,
    (CATEGORY_DHCP, DHCP_NAK): 1,
    (CATEGORY_DHCP, DHCP_DECLINE): 1,
    (CATEGORY_WIFI, WIFI_INACTIVITY): 5,
}
_DEFAULT_PRIORITY = 3

_MAC = r"(?P<mac>[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]+)"
_PROCESS_RE = re.compile(r"^(?P<proc>[\w.-]+)(?:\[\d+\])?: (?P<body>.*)$", re.DOTALL)
_HOSTAPD_IFACE_RE = re.compile(r"^(?P<iface>[\w.-]+): (?P<rest>.*)$", re.DOTALL)

_HOSTAPD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (WIFI_CONNECTED, re.compile(rf"^AP-STA-CONNECTED {_MAC}\b")),
    (WIFI_DISCONNECTED, re.compile(rf"^AP-STA-DISCONNECTED {_MAC}\b")),
    (WIFI_PSK_MISMATCH, re.compile(rf"^AP-STA-POSSIBLE-PSK-MISMATCH {_MAC}\b")),
    (
        WIFI_INACTIVITY,
        re.compile(rf"^STA {_MAC} IEEE 802\.11: deauthenticated due to inactivity"),
    ),
    (
        WIFI_HANDSHAKE_FAILED,
        re.compile(
            rf"^STA {_MAC} WPA: .*(?:handshake failed|EAPOL-Key timeout|invalid MIC)",
            re.IGNORECASE,
        ),
    ),
    # P4. Live: "deauthenticated due to local deauth request",
    # "disassociated due to inactivity", "disassociated" (no reason).
    (
        WIFI_DEAUTH,
        re.compile(
            rf"^STA {_MAC} IEEE 802\.11: deauthenticated(?: due to (?P<why>.+))?$"
        ),
    ),
    (
        WIFI_DISASSOC,
        re.compile(
            rf"^STA {_MAC} IEEE 802\.11: disassociated(?: due to (?P<why>.+))?$"
        ),
    ),
    # Live (ap5): the station associated with another BSS of this hostapd.
    (WIFI_DISASSOC, re.compile(rf"^Prune association for {_MAC}(?P<prune>)")),
    (WIFI_HANDSHAKE_COMPLETED, re.compile(rf"^EAPOL-4WAY-HS-COMPLETED {_MAC}\b")),
    # Not seen live: hostapd control events and IEEE 802.11 logger lines.
    (
        WIFI_ASSOC_REJECTED,
        re.compile(rf"^AP-REJECTED-(?P<why>MAX-STA|BLOCKED-STA) {_MAC}\b"),
    ),
    (
        WIFI_ASSOC_REJECTED,
        re.compile(
            rf"^STA {_MAC} IEEE 802\.11: .*\bassoc\w* .*(?:reject|denied)",
            re.IGNORECASE,
        ),
    ),
    (WIFI_SAE_FAILED, re.compile(rf"^SAE-UNKNOWN-PASSWORD-IDENTIFIER {_MAC}\b")),
    (
        WIFI_SAE_FAILED,
        re.compile(
            rf"^STA {_MAC} IEEE 802\.11: .*\bSAE\b.*(?:fail|mismatch|reject|invalid)",
            re.IGNORECASE,
        ),
    ),
)
_REASONS = (
    ("inactivity", REASON_INACTIVITY),
    ("local deauth request", REASON_LOCAL_REQUEST),
)
_REJECT_REASONS = {"MAX-STA": REASON_MAX_STA, "BLOCKED-STA": REASON_BLOCKED}
# wpa_supplicant (router uplink), not seen live
_SUPPLICANT_RE = re.compile(
    r"^(?P<iface>[\w.-]+): WPA: 4-Way Handshake failed - "
    r"pre-shared key may be incorrect"
)
# usteer (Prio 14), live: "station <mac> disconnected from node hostapd.phy1-ap1"
_USTEER_RE = re.compile(
    rf"^station {_MAC} (?P<dir>connected to|disconnected from) node (?P<node>\S{{1,64}})$"
)

# dnsmasq with --log-dhcp prefixes the transaction id ("1234567 DHCPACK(…)").
_DHCP_RE = re.compile(
    r"^(?:\d+ )?DHCP(?P<type>[A-Z]+)\((?P<iface>[^)]*)\) (?P<rest>.*)$", re.DOTALL
)
# The MAC must end there: a DHCPv6 DUID ("00:01:00:01:…") is not a MAC.
_DHCP_REST_RE = re.compile(
    rf"^(?:{_IP} )?{_MAC}(?![0-9A-Fa-f:])(?P<tail>.*)$", re.DOTALL
)
_DHCP_TYPES = {"ACK": DHCP_ACK, "NAK": DHCP_NAK, "DECLINE": DHCP_DECLINE}

_DFS_RE = re.compile(r"^DFS-(?P<what>[A-Z-]+)(?P<args>(?: .*)?)$", re.DOTALL)
_DFS_KINDS = {
    "RADAR-DETECTED": DFS_RADAR_DETECTED,
    "CAC-START": DFS_CAC_START,
    "CAC-COMPLETED": DFS_CAC_COMPLETED,
    "NOP-FINISHED": DFS_NOP_FINISHED,
    "NEW-CHANNEL": DFS_NEW_CHANNEL,
    "PRE-CAC-EXPIRED": DFS_PRE_CAC_EXPIRED,
}
# logd source of kernel lines (ubox log/syslog.h: SOURCE_KLOG)
_SOURCE_KLOG = 0
_KERNEL_PREFIX_RE = re.compile(r"^(?:kernel: )?(?:\[\s*\d+\.\d+\]\s*)?")
# "mt7530-mdio mdio-bus:1f lan1: Link is Up - 1Gbps/Full - flow control rx/tx"
_KERNEL_LINK_RE = re.compile(
    r"(?:^|\s)(?P<dev>[\w.@-]{1,32}): Link is (?P<state>Up|Down)\b"
)
_KERNEL_OOM_RE = re.compile(
    r"Out of memory: Kill(?:ed)? process \d+ \((?P<proc>[^)]{1,64})\)"
)
_NETIFD_LINK_RE = re.compile(
    r"^Network device '(?P<dev>[^']{1,32})' link is (?P<state>up|down)\b"
)
_NETIFD_IFACE_RE = re.compile(
    r"^Interface '(?P<iface>[^']{1,32})' "
    r"(?:is now (?P<state>up|down)\b|has (?P<lost>link connectivity loss))"
)
_PROCD_CRASH_RE = re.compile(
    r"^Instance (?P<svc>[\w.-]{1,64})::(?P<inst>[\w.-]{1,64}) s in a crash loop"
)
_DNS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (DNS_QUERY_LIMIT, re.compile(r"^Maximum number of concurrent DNS queries")),
    (DNS_NO_SERVERS, re.compile(r"^no servers found in ")),
    (DNS_SEND_FAILED, re.compile(r"^failed to send packet")),
)
_ODHCPD_ERROR_RE = re.compile(r"\b(?:failed|error)\b", re.IGNORECASE)

_DFS_FREQ_RE = re.compile(r"\bfreq=(?P<v>\d{4,5})\b")
_DFS_CHAN_RE = re.compile(r"\bchan=(?P<v>\d{1,3})\b")
_DFS_SUCCESS_RE = re.compile(r"\bsuccess=(?P<v>\d)\b")


@dataclass(frozen=True)
class LogEvent:
    """One recognised log line."""

    category: str
    kind: str
    log_id: int
    time_ms: int
    mac: str | None = None
    interface: str | None = None
    ip: str | None = None
    message: str = ""
    frequency: int | None = None
    channel: int | None = None
    # Infrastructure lines only: the program that wrote the line (kernel,
    # netifd, procd, odhcpd, dnsmasq) and the service/process it is about.
    process: str | None = None
    name: str | None = None
    # Wi-Fi lines (P4): normalised plain-text reason (``REASON_*``).
    reason: str | None = None

    @property
    def key(self) -> str:
        """Counter key ``<category>.<kind>``."""
        return f"{self.category}.{self.kind}"


def parse_entry(entry: Any) -> LogEvent | None:
    """Return a LogEvent for a recognised line, else None (also on bad input)."""
    if not isinstance(entry, dict):
        return None
    msg = entry.get("msg")
    log_id = entry.get("id")
    if (
        not isinstance(msg, str)
        or not isinstance(log_id, int)
        or isinstance(log_id, bool)
    ):
        return None
    time_ms = entry.get("time")
    if (
        not isinstance(time_ms, int)
        or isinstance(time_ms, bool)
        or not _TIME_MIN_MS <= time_ms <= _TIME_MAX_MS
    ):
        time_ms = 0
    message = msg[:MESSAGE_MAX_LEN]
    source = entry.get("source")
    if source == _SOURCE_KLOG and not isinstance(source, bool):
        return _parse_kernel(msg, log_id, time_ms, message)
    if msg.startswith("kernel: "):
        return _parse_kernel(msg, log_id, time_ms, message)
    match = _PROCESS_RE.match(msg)
    if not match:
        return None
    proc, body = match.group("proc"), match.group("body")
    if proc == "hostapd":
        return _parse_hostapd(body, log_id, time_ms, message)
    if proc.startswith("dnsmasq"):
        return _parse_dhcp(body, log_id, time_ms, message) or _parse_dns(
            body, log_id, time_ms, message
        )
    if proc == "netifd":
        return _parse_netifd(body, log_id, time_ms, message)
    if proc == "procd":
        return _parse_procd(body, log_id, time_ms, message)
    if proc == "odhcpd":
        return _parse_odhcpd(body, log_id, time_ms, message)
    if proc == "usteer":
        return _parse_usteer(body, log_id, time_ms, message)
    if proc == "wpa_supplicant":
        return _parse_supplicant(body, log_id, time_ms, message)
    return None


def _parse_usteer(
    body: str, log_id: int, time_ms: int, message: str
) -> LogEvent | None:
    match = _USTEER_RE.match(body)
    if not match:
        return None
    node = match.group("node")
    return LogEvent(
        category=CATEGORY_WIFI,
        kind=WIFI_STEER_CONNECTED
        if match.group("dir") == "connected to"
        else WIFI_STEER_DISCONNECTED,
        log_id=log_id,
        time_ms=time_ms,
        mac=match.group("mac").upper(),
        interface=node.removeprefix("hostapd."),
        message=message,
        process="usteer",
    )


def _parse_supplicant(
    body: str, log_id: int, time_ms: int, message: str
) -> LogEvent | None:
    match = _SUPPLICANT_RE.match(body)
    if not match:
        return None
    return LogEvent(
        category=CATEGORY_WIFI,
        kind=WIFI_BACKHAUL_AUTH_FAILED,
        log_id=log_id,
        time_ms=time_ms,
        interface=match.group("iface"),
        message=message,
        process="wpa_supplicant",
        reason=REASON_PSK,
    )


def _wifi_reason(kind: str, hit: re.Match[str]) -> str | None:
    """Normalised reason of a hostapd Wi-Fi line (None = none given)."""
    groups = hit.groupdict()
    if kind == WIFI_INACTIVITY:
        return REASON_INACTIVITY
    if kind == WIFI_HANDSHAKE_FAILED:
        text = hit.string.lower()
        if "timeout" in text:
            return REASON_TIMEOUT
        if "invalid mic" in text:
            return REASON_INVALID_MIC
        return REASON_FAILED
    if "prune" in groups:
        return REASON_PRUNE
    why = groups.get("why")
    if not why:
        return None
    if kind == WIFI_ASSOC_REJECTED:
        return _REJECT_REASONS.get(why, REASON_OTHER)
    for text, reason in _REASONS:
        if why.startswith(text):
            return reason
    return REASON_OTHER


def _parse_kernel(msg: str, log_id: int, time_ms: int, message: str) -> LogEvent | None:
    body = _KERNEL_PREFIX_RE.sub("", msg, count=1)
    link = _KERNEL_LINK_RE.search(body)
    if link:
        return LogEvent(
            category=CATEGORY_LINK,
            kind=LINK_UP if link.group("state") == "Up" else LINK_DOWN,
            log_id=log_id,
            time_ms=time_ms,
            interface=link.group("dev"),
            message=message,
            process="kernel",
        )
    oom = _KERNEL_OOM_RE.search(body)
    if oom:
        return LogEvent(
            category=CATEGORY_SYSTEM,
            kind=SYSTEM_OOM_KILL,
            log_id=log_id,
            time_ms=time_ms,
            message=message,
            process="kernel",
            name=oom.group("proc"),
        )
    return None


def _parse_netifd(
    body: str, log_id: int, time_ms: int, message: str
) -> LogEvent | None:
    link = _NETIFD_LINK_RE.match(body)
    if link:
        return LogEvent(
            category=CATEGORY_LINK,
            kind=LINK_UP if link.group("state") == "up" else LINK_DOWN,
            log_id=log_id,
            time_ms=time_ms,
            interface=link.group("dev"),
            message=message,
            process="netifd",
        )
    iface = _NETIFD_IFACE_RE.match(body)
    if not iface:
        return None
    if iface.group("lost"):
        kind = IFACE_LINK_LOST
    else:
        kind = IFACE_UP if iface.group("state") == "up" else IFACE_DOWN
    return LogEvent(
        category=CATEGORY_IFACE,
        kind=kind,
        log_id=log_id,
        time_ms=time_ms,
        interface=iface.group("iface"),
        message=message,
        process="netifd",
    )


def _parse_procd(body: str, log_id: int, time_ms: int, message: str) -> LogEvent | None:
    crash = _PROCD_CRASH_RE.match(body)
    if not crash:
        return None
    return LogEvent(
        category=CATEGORY_SYSTEM,
        kind=SYSTEM_CRASH_LOOP,
        log_id=log_id,
        time_ms=time_ms,
        interface=crash.group("inst"),
        message=message,
        process="procd",
        name=crash.group("svc"),
    )


def _parse_odhcpd(
    body: str, log_id: int, time_ms: int, message: str
) -> LogEvent | None:
    if not _ODHCPD_ERROR_RE.search(body):
        return None
    return LogEvent(
        category=CATEGORY_DHCP,
        kind=DHCP_ODHCPD_ERROR,
        log_id=log_id,
        time_ms=time_ms,
        message=message,
        process="odhcpd",
    )


def _parse_dns(body: str, log_id: int, time_ms: int, message: str) -> LogEvent | None:
    for kind, pattern in _DNS_PATTERNS:
        if pattern.match(body):
            return LogEvent(
                category=CATEGORY_DNS,
                kind=kind,
                log_id=log_id,
                time_ms=time_ms,
                message=message,
                process="dnsmasq",
            )
    return None


def _parse_hostapd(
    body: str, log_id: int, time_ms: int, message: str
) -> LogEvent | None:
    match = _HOSTAPD_IFACE_RE.match(body)
    if not match:
        return None
    rest = match.group("rest")
    dfs = _DFS_RE.match(rest)
    if dfs:
        return _parse_dfs(dfs, match.group("iface"), log_id, time_ms, message)
    for kind, pattern in _HOSTAPD_PATTERNS:
        hit = pattern.match(rest)
        if hit:
            return LogEvent(
                category=CATEGORY_WIFI,
                kind=kind,
                log_id=log_id,
                time_ms=time_ms,
                mac=hit.group("mac").upper(),
                interface=match.group("iface"),
                message=message,
                reason=_wifi_reason(kind, hit),
            )
    return None


def _parse_dfs(
    match: re.Match[str], iface: str, log_id: int, time_ms: int, message: str
) -> LogEvent | None:
    kind = _DFS_KINDS.get(match.group("what"))
    if kind is None:
        return None
    args = match.group("args")
    if kind == DFS_CAC_COMPLETED:
        success = _DFS_SUCCESS_RE.search(args)
        if success and success.group("v") == "0":
            kind = DFS_CAC_FAILED
    freq_hit = _DFS_FREQ_RE.search(args)
    chan_hit = _DFS_CHAN_RE.search(args)
    frequency = int(freq_hit.group("v")) if freq_hit else None
    channel = int(chan_hit.group("v")) if chan_hit else None
    if channel is None and frequency is not None and 5000 < frequency < 5900:
        channel = (frequency - 5000) // 5
    return LogEvent(
        category=CATEGORY_DFS,
        kind=kind,
        log_id=log_id,
        time_ms=time_ms,
        interface=iface,
        message=message,
        frequency=frequency,
        channel=channel,
    )


def _parse_dhcp(body: str, log_id: int, time_ms: int, message: str) -> LogEvent | None:
    match = _DHCP_RE.match(body)
    if not match:
        return None
    rest = _DHCP_REST_RE.match(match.group("rest"))
    if not rest:
        return None
    if "no address available" in rest.group("tail"):
        kind = DHCP_NO_ADDRESS
    else:
        kind = _DHCP_TYPES.get(match.group("type"))
        if kind is None:
            return None
    return LogEvent(
        category=CATEGORY_DHCP,
        kind=kind,
        log_id=log_id,
        time_ms=time_ms,
        mac=rest.group("mac").upper(),
        interface=match.group("iface") or None,
        ip=rest.group("ip"),
        message=message,
    )


@dataclass
class IngestResult:
    """Outcome of one ``LogCursor.ingest`` call."""

    events: list[LogEvent] = field(default_factory=list)
    new_lines: int = 0
    missed: int = 0
    baseline: bool = False


class LogCursor:
    """Remember the last seen log id and hand out only new lines.

    The first fetch (and the first after a logd restart) is a baseline: its
    lines are returned with ``baseline=True`` so they are counted but trigger
    no events. A restart shows as the newest id going backwards, or as the
    remembered last line having changed (same id, other time) or vanished
    while older ids are still in the answer.
    """

    def __init__(self) -> None:
        self.last_id: int | None = None
        self.last_time: Any = None

    def ingest(self, entries: Iterable[Any]) -> IngestResult:
        valid = [
            e
            for e in entries
            if isinstance(e, dict)
            and isinstance(e.get("id"), int)
            and not isinstance(e.get("id"), bool)
        ]
        valid.sort(key=lambda e: e["id"])
        result = IngestResult()
        if not valid:
            return result
        newest = valid[-1]["id"]
        if self.last_id is None or newest < self.last_id or self._restarted(valid):
            result.baseline = True
            fresh = valid
        else:
            fresh = [e for e in valid if e["id"] > self.last_id]
            if fresh and fresh[0]["id"] > self.last_id + 1:
                result.missed = fresh[0]["id"] - self.last_id - 1
        self.last_id = newest
        self.last_time = valid[-1].get("time")
        result.new_lines = len(fresh)
        result.events = [ev for e in fresh if (ev := parse_entry(e)) is not None]
        return result

    def _restarted(self, valid: list[dict[str, Any]]) -> bool:
        if self.last_id is None or valid[0]["id"] > self.last_id:
            return False  # last line not in range: a gap, not a restart
        anchor = next((e for e in valid if e["id"] == self.last_id), None)
        return anchor is None or anchor.get("time") != self.last_time


class EventLimiter:
    """At most ``per_fetch`` events per fetch, one per (kind, MAC) per window.

    Lines without a MAC (DFS) are keyed by interface and frequency, so a
    radar on the new channel is not swallowed by the one on the old channel.
    """

    def __init__(self, per_fetch: int, window_ms: int) -> None:
        self.per_fetch = per_fetch
        self.window_ms = window_ms
        self._last: dict[tuple[str, str, str | None], int] = {}

    def select(
        self, events: Iterable[LogEvent], now_ms: int
    ) -> tuple[list[LogEvent], int]:
        """Return (events to fire, number suppressed)."""
        self._last = {
            k: t for k, t in self._last.items() if now_ms - t < self.window_ms
        }
        fire: list[LogEvent] = []
        suppressed = 0
        ranked = sorted(
            events,
            key=lambda e: _PRIORITY.get((e.category, e.kind), _DEFAULT_PRIORITY),
        )
        for event in ranked:
            if (
                event.category not in FIRE_CATEGORIES
                or (event.category, event.kind) in COUNT_ONLY_KINDS
                or (event.category, event.kind) in ENGINE_ONLY_KINDS
            ):
                continue
            key = (
                event.category,
                event.kind,
                event.mac or f"{event.interface}@{event.frequency}",
            )
            if key in self._last or len(fire) >= self.per_fetch:
                suppressed += 1
                continue
            self._last[key] = now_ms
            fire.append(event)
        fire.sort(key=lambda e: e.log_id)
        return fire, suppressed


class RollingCounter:
    """Count keys over a sliding time window (bounded memory)."""

    def __init__(self, window_ms: int, max_items: int = 20000) -> None:
        self.window_ms = window_ms
        self._items: deque[tuple[int, str]] = deque(maxlen=max_items)

    def add(self, time_ms: int, key: str) -> None:
        self._items.append((time_ms, key))

    def counts(self, now_ms: int) -> dict[str, int]:
        """Return {key: count} for items newer than the window."""
        cutoff = now_ms - self.window_ms
        while self._items and self._items[0][0] < cutoff:
            self._items.popleft()
        out: dict[str, int] = {}
        for time_ms, key in self._items:
            if time_ms >= cutoff:
                out[key] = out.get(key, 0) + 1
        return dict(sorted(out.items()))
