"""Parse the OpenWrt logd ring buffer (``ubus call log read``) into events.

Pure functions and small state holders, no HA imports. Log lines are
untrusted router output: they are only matched against fixed patterns, never
executed, and the raw message is truncated before it leaves this module.

Entry shape (logd, OpenWrt 25.12)::

    {"msg": "hostapd: phy0-ap1: AP-STA-CONNECTED <mac> auth_alg=open",
     "id": 411704, "priority": 30, "source": 1, "time": 1793094113364}

``id`` grows monotonically per logd instance (a router reboot or logd
restart starts again at a low value), ``time`` is epoch milliseconds.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

CATEGORY_WIFI = "wifi"
CATEGORY_DHCP = "dhcp"

WIFI_CONNECTED = "connected"
WIFI_DISCONNECTED = "disconnected"
WIFI_PSK_MISMATCH = "psk_mismatch"
WIFI_INACTIVITY = "inactivity_timeout"
WIFI_HANDSHAKE_FAILED = "handshake_failed"

DHCP_ACK = "ack"
DHCP_NAK = "nak"
DHCP_DECLINE = "decline"
DHCP_NO_ADDRESS = "no_address"

# Parsed for the counters (and client statistics) but never fired as event:
# they are normal operation and would crowd out the problems.
COUNT_ONLY_KINDS = frozenset(
    {
        (CATEGORY_WIFI, WIFI_CONNECTED),
        (CATEGORY_WIFI, WIFI_DISCONNECTED),
        (CATEGORY_DHCP, DHCP_ACK),
    }
)

MESSAGE_MAX_LEN = 200

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
)

_DHCP_RE = re.compile(
    r"^DHCP(?P<type>[A-Z]+)\((?P<iface>[^)]*)\) (?P<rest>.*)$", re.DOTALL
)
_DHCP_REST_RE = re.compile(rf"^(?:{_IP} )?{_MAC}(?P<tail>.*)$", re.DOTALL)
_DHCP_TYPES = {"ACK": DHCP_ACK, "NAK": DHCP_NAK, "DECLINE": DHCP_DECLINE}


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
    if not isinstance(time_ms, int) or isinstance(time_ms, bool):
        time_ms = 0
    match = _PROCESS_RE.match(msg)
    if not match:
        return None
    proc, body = match.group("proc"), match.group("body")
    message = msg[:MESSAGE_MAX_LEN]
    if proc == "hostapd":
        return _parse_hostapd(body, log_id, time_ms, message)
    if proc.startswith("dnsmasq"):
        return _parse_dhcp(body, log_id, time_ms, message)
    return None


def _parse_hostapd(
    body: str, log_id: int, time_ms: int, message: str
) -> LogEvent | None:
    match = _HOSTAPD_IFACE_RE.match(body)
    if not match:
        return None
    rest = match.group("rest")
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
            )
    return None


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

    The first fetch (and the first after a logd restart, detected by the
    newest id going backwards) is a baseline: its lines are returned with
    ``baseline=True`` so they are counted but trigger no events.
    """

    def __init__(self) -> None:
        self.last_id: int | None = None

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
        if self.last_id is None or newest < self.last_id:
            result.baseline = True
            fresh = valid
        else:
            fresh = [e for e in valid if e["id"] > self.last_id]
            if fresh and fresh[0]["id"] > self.last_id + 1:
                result.missed = fresh[0]["id"] - self.last_id - 1
        self.last_id = newest
        result.new_lines = len(fresh)
        result.events = [ev for e in fresh if (ev := parse_entry(e)) is not None]
        return result


class EventLimiter:
    """At most ``per_fetch`` events per fetch, one per (kind, MAC) per window."""

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
        for event in events:
            if (event.category, event.kind) in COUNT_ONLY_KINDS:
                continue
            key = (event.category, event.kind, event.mac)
            if key in self._last or len(fire) >= self.per_fetch:
                suppressed += 1
                continue
            self._last[key] = now_ms
            fire.append(event)
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
