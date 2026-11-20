"""Syslog receiver of the Security Center (release 1.46.0 part 2, path A).

A local UDP listener in Home Assistant for the routers' remote log
(``logd`` ``log_ip`` / ``log_port``, one line per datagram). It implements
the ``LogSource`` protocol of ``security_logsrc`` and parses every line with
``security_logfmt.parse_remote_line``. It never sends anything and never
contacts a router; it only receives what the routers are configured to send.

Every datagram is foreign, forgeable input:

* only senders on the allowlist are taken (the routers' management
  addresses from the router registry, set by the center); others are
  dropped and counted (``dropped_sender``) without keeping any state per
  unknown address,
* a line is cut at ``MAX_LINE_BYTES`` (``truncated``), the rest is never
  read or kept,
* token buckets per sender and in total (``dropped_rate``) and a bounded
  buffer (``dropped_buffer``) keep memory and CPU bounded,
* the router id of a record is the allowlist's, never the line's HOST field,
* without a known zone offset the time of a line is its receive time
  (``ts_estimated``); a line dated into the future cannot move any mark.

Honest limit: a UDP sender address can be spoofed in the LAN, so the
allowlist filters noise and mistakes, it does not authenticate a router.

No line, address or host name is ever logged; log messages carry counters,
the port and exception type names only. Bind errors make the receiver
``not_available`` with a reason; they are never raised to the caller.
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import logging
import math
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from .const import (
    SEC_SYSLOG_BIND_HOST,
    SEC_SYSLOG_BUFFER_MAX,
    SEC_SYSLOG_DRAIN_AT,
    SEC_SYSLOG_SENDER_BURST,
    SEC_SYSLOG_SENDER_RATE,
    SEC_SYSLOG_TOTAL_BURST,
    SEC_SYSLOG_TOTAL_RATE,
)
from .security_logfmt import (
    OUTCOME_INVALID,
    OUTCOME_PARSED,
    OUTCOME_UNPARSED,
    parse_remote_line,
)
from .security_logsrc import (
    MAX_LINE_BYTES,
    KeyAssigner,
    SecLogRecord,
    SourceStats,
)
from .security_model import LogPath, valid_router_id

_LOGGER = logging.getLogger(__name__)

# Why the receiver is not listening (``reason`` of the log-path sources).
REASON_PORT_IN_USE: Final = "port_in_use"
REASON_PERMISSION_DENIED: Final = "permission_denied"
REASON_ADDRESS_UNAVAILABLE: Final = "address_not_available"
REASON_BIND_FAILED: Final = "bind_failed"
REASON_NOT_STARTED: Final = "receiver_not_started"
REASON_STOPPED: Final = "receiver_stopped"
# Lines of a router were dropped by the rate limits or the full buffer
# within the last RATE_LIMITED_HOLD_S (review 3, #8): its log sources are
# "limited", never "fine" while lines get lost.
REASON_RATE_LIMITED: Final = "rate_limited"
RATE_LIMITED_HOLD_S: Final = 300.0

_IN_USE: Final = frozenset({errno.EADDRINUSE, 10048})  # 10048: WSAEADDRINUSE
_DENIED: Final = frozenset({errno.EACCES, errno.EPERM, 10013})  # WSAEACCES
_NO_ADDR: Final = frozenset({errno.EADDRNOTAVAIL, 10049})  # WSAEADDRNOTAVAIL

_COUNTER_NAMES: Final = SourceStats.__slots__


def bind_reason(err: BaseException) -> str:
    """Reason code of a failed bind (no message text: it may carry paths)."""
    code = getattr(err, "errno", None)
    win = getattr(err, "winerror", None)
    for value in (code, win):
        if value in _IN_USE:
            return REASON_PORT_IN_USE
        if value in _DENIED:
            return REASON_PERMISSION_DENIED
        if value in _NO_ADDR:
            return REASON_ADDRESS_UNAVAILABLE
    return REASON_BIND_FAILED


def sender_address(value: Any) -> str | None:
    """Canonical text of an IP address literal; None for anything else.

    An IPv4-mapped IPv6 address becomes its IPv4 form; a zone id is cut.
    Host names are not resolved (no DNS lookup): they give None.
    """
    if not isinstance(value, str) or not 0 < len(value) <= 64:
        return None
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0].strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


@dataclass(frozen=True, kw_only=True, slots=True)
class SyslogLimits:
    """Caps of one receiver (defaults from ``const``)."""

    sender_rate: float = SEC_SYSLOG_SENDER_RATE
    sender_burst: float = SEC_SYSLOG_SENDER_BURST
    total_rate: float = SEC_SYSLOG_TOTAL_RATE
    total_burst: float = SEC_SYSLOG_TOTAL_BURST
    buffer_max: int = SEC_SYSLOG_BUFFER_MAX
    drain_at: int = SEC_SYSLOG_DRAIN_AT
    max_line: int = MAX_LINE_BYTES


class _Bucket:
    """Token bucket (``rate`` per second, at most ``burst`` tokens)."""

    __slots__ = ("burst", "last", "rate", "tokens")

    def __init__(self, rate: float, burst: float, now: float) -> None:
        self.rate = max(0.0, float(rate))
        self.burst = max(1.0, float(burst))
        self.tokens = self.burst
        self.last = now

    def take(self, now: float) -> bool:
        elapsed = now - self.last
        if elapsed > 0:
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        # a clock that went back neither refills nor drains the bucket
        self.last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class _SyslogProtocol(asyncio.DatagramProtocol):
    """Hands every datagram to the receiver (which never raises)."""

    def __init__(self, receiver: SyslogReceiver) -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self._receiver.receive(data, addr)

    def error_received(self, exc: Exception) -> None:
        self._receiver.note_socket_error(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        self._receiver.note_closed()


class SyslogReceiver:
    """UDP syslog listener: ``LogSource`` of the path ``syslog``.

    ``port`` and ``host`` are where it listens; ``clock`` gives the receive
    time (epoch seconds); ``tz_offset_of(router_id)`` the router's zone
    offset in seconds, None when unknown (then times are estimated);
    ``on_backlog`` is called (soon, on the event loop) when
    ``limits.drain_at`` records wait, so the center drains before its next
    poll. A receiver is started once; after ``close`` a new one is made.
    """

    name = LogPath.SYSLOG.value

    def __init__(
        self,
        *,
        port: int,
        host: str = SEC_SYSLOG_BIND_HOST,
        clock: Callable[[], float] = time.time,
        tz_offset_of: Callable[[str], float | None] | None = None,
        on_backlog: Callable[[], None] | None = None,
        limits: SyslogLimits | None = None,
    ) -> None:
        """Create a receiver that does not listen yet."""
        self.port = int(port)
        self.host = host
        self.limits = limits or SyslogLimits()
        self._clock = clock
        self._tz_offset_of = tz_offset_of
        self._on_backlog = on_backlog
        self._transport: asyncio.DatagramTransport | None = None
        self._started = False
        self._closed = False
        self.reason: str | None = REASON_NOT_STARTED
        self._senders: dict[str, str] = {}
        self._buckets: dict[str, _Bucket] = {}
        self._total: _Bucket | None = None
        self._buffer: deque[SecLogRecord] = deque()
        self._assigner = KeyAssigner()
        self._counts: dict[str, int] = dict.fromkeys(_COUNTER_NAMES, 0)
        self._extra: dict[str, int] = {"errors": 0, "socket_errors": 0}
        self._wake_pending = False
        # router id -> receive time of its last line lost to a limit
        self._limited_at: dict[str, float] = {}

    def __repr__(self) -> str:
        """No addresses or router ids."""
        return (
            f"SyslogReceiver(port={self.port}, listening={self.listening}, "
            f"senders={len(self._senders)}, buffered={len(self._buffer)})"
        )

    # --- state ------------------------------------------------------------------

    @property
    def listening(self) -> bool:
        """True while the socket is bound."""
        return self._transport is not None and not self._closed

    @property
    def bound_port(self) -> int | None:
        """The port the socket is bound to (differs from ``port`` only for 0)."""
        if self._transport is None:
            return None
        sock = self._transport.get_extra_info("sockname")
        if isinstance(sock, tuple) and len(sock) >= 2 and isinstance(sock[1], int):
            return sock[1]
        return None

    @property
    def router_ids(self) -> frozenset[str]:
        """Router ids of the allowed senders."""
        return frozenset(self._senders.values())

    def now(self) -> float:
        """The receiver's clock (receive times of its records)."""
        return float(self._clock())

    def limited_routers(self, now: float | None = None) -> frozenset[str]:
        """Allowed routers that lost lines to a limit in the last hold time.

        Rate limits and the full buffer both count; the state decays
        ``RATE_LIMITED_HOLD_S`` after the last lost line (receive clock).
        """
        when = self.now() if now is None else now
        for router in [
            r
            for r, at in self._limited_at.items()
            if not 0 <= when - at < RATE_LIMITED_HOLD_S
        ]:
            del self._limited_at[router]
        allowed = set(self._senders.values())
        return frozenset(r for r in self._limited_at if r in allowed)

    def _note_limited(self, router: str, now: float) -> None:
        self._limited_at[router] = now

    def set_senders(self, senders: Mapping[str, str]) -> None:
        """Replace the allowlist: address literal -> contract router id.

        Entries with no address literal or no contract router id are left
        out; an address named for two routers is left out (ambiguous).
        """
        clean: dict[str, str] = {}
        doubled: set[str] = set()
        for raw, router in senders.items():
            address = sender_address(raw)
            rid = valid_router_id(router)
            if address is None or rid is None:
                continue
            if address in clean and clean[address] != rid:
                doubled.add(address)
            clean[address] = rid
        for address in doubled:
            clean.pop(address, None)
        self._senders = clean
        for address in [a for a in self._buckets if a not in clean]:
            del self._buckets[address]
        routers = set(clean.values())
        for router in [r for r in self._limited_at if r not in routers]:
            del self._limited_at[router]

    # --- LogSource ----------------------------------------------------------------

    async def async_start(self) -> None:
        """Bind the socket; a failure sets ``reason`` and is not raised."""
        if self._started or self._closed:
            return
        self._started = True
        loop = asyncio.get_running_loop()
        try:
            transport, _protocol = await loop.create_datagram_endpoint(
                lambda: _SyslogProtocol(self), local_addr=(self.host, self.port)
            )
        except OSError as err:
            self.reason = bind_reason(err)
            _LOGGER.warning(
                "Security Center: the syslog receiver cannot listen on UDP port "
                "%d (%s); the firewall and DNS log sources stay unavailable",
                self.port,
                self.reason,
            )
            return
        if self._closed:  # closed while binding
            transport.close()
            return
        self._transport = transport
        self.reason = None
        _LOGGER.debug("Security Center: syslog receiver listens on UDP %d", self.port)

    async def async_stop(self) -> None:
        """Close the socket (see ``close``)."""
        self.close()

    def close(self) -> None:
        """Close the socket and drop the buffer; idempotent."""
        self._closed = True
        transport, self._transport = self._transport, None
        if transport is not None:
            try:
                transport.close()
            except Exception:  # noqa: BLE001 - closing never fails the caller
                _LOGGER.debug("Security Center: syslog socket close failed")
        self._buffer.clear()
        self.reason = REASON_STOPPED

    def drain(self, max_records: int) -> list[SecLogRecord]:
        """Up to ``max_records`` records in arrival order; never blocks."""
        out: list[SecLogRecord] = []
        buffer = self._buffer
        while buffer and len(out) < max(0, max_records):
            out.append(buffer.popleft())
        return out

    def stats(self) -> SourceStats:
        """Counters only (no address, router or line)."""
        return SourceStats.from_counts(self._counts)

    def status(self) -> dict[str, Any]:
        """Listening state, reason, port and counters (no identities)."""
        return {
            "listening": self.listening,
            "reason": None if self.listening else self.reason,
            "port": self.port,
            "senders": len(self._senders),
            "buffered": len(self._buffer),
            "stats": self.stats().to_dict(),
            "errors": dict(self._extra),
        }

    # --- receiving ---------------------------------------------------------------

    def receive(self, data: bytes, addr: Any) -> None:
        """One datagram (from the protocol, or a test); never raises."""
        try:
            self._receive(data, addr)
        except Exception as err:  # noqa: BLE001 - foreign input never breaks HA
            self._extra["errors"] += 1
            _LOGGER.debug(
                "Security Center: datagram not handled (%s)", type(err).__name__
            )

    def _receive(self, data: bytes, addr: Any) -> None:
        counts = self._counts
        counts["received"] += 1
        if self._closed:
            return
        host = addr[0] if isinstance(addr, tuple) and addr else None
        address = sender_address(host)
        router = self._senders.get(address) if address is not None else None
        if router is None:
            counts["dropped_sender"] += 1
            return
        now = self.now()
        if not math.isfinite(now):
            counts["invalid"] += 1
            return
        if not self._take(address, now):
            counts["dropped_rate"] += 1
            self._note_limited(router, now)
            return
        if len(self._buffer) >= self.limits.buffer_max:
            counts["dropped_buffer"] += 1
            self._note_limited(router, now)
            return
        size = len(data)
        cut = size > self.limits.max_line
        raw = bytes(data[: self.limits.max_line]) if cut else bytes(data)
        result = parse_remote_line(
            raw,
            router=router,
            path=self.name,
            recv=now,
            tz_offset_s=self._tz_offset(router),
            assigner=self._assigner,
            truncated=cut,
        )
        if result.outcome in (OUTCOME_PARSED, OUTCOME_UNPARSED, OUTCOME_INVALID):
            counts[result.outcome] += 1
        if result.truncated or cut:
            counts["truncated"] += 1
        if result.ts_estimated:
            counts["ts_estimated"] += 1
        if result.ts_future:
            counts["ts_future"] += 1
        if result.record is None:
            return
        self._buffer.append(result.record)
        if len(self._buffer) >= self.limits.drain_at:
            self._wake()

    def _take(self, address: str, now: float) -> bool:
        limits = self.limits
        bucket = self._buckets.get(address)
        if bucket is None:
            bucket = _Bucket(limits.sender_rate, limits.sender_burst, now)
            self._buckets[address] = bucket
        if self._total is None:
            self._total = _Bucket(limits.total_rate, limits.total_burst, now)
        if not bucket.take(now):
            return False
        return self._total.take(now)

    def _tz_offset(self, router: str) -> float | None:
        if self._tz_offset_of is None:
            return None
        try:
            return self._tz_offset_of(router)
        except Exception:  # noqa: BLE001 - unknown offset: estimated time
            return None

    def _wake(self) -> None:
        if self._wake_pending or self._on_backlog is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._wake_pending = True
        loop.call_soon(self._fire_backlog)

    def _fire_backlog(self) -> None:
        self._wake_pending = False
        if self._closed or self._on_backlog is None:
            return
        try:
            self._on_backlog()
        except Exception as err:  # noqa: BLE001 - the receiver goes on
            self._extra["errors"] += 1
            _LOGGER.debug("Security Center: log drain failed (%s)", type(err).__name__)

    def note_socket_error(self, exc: BaseException) -> None:
        """An ICMP error or similar on the socket: counted, not raised."""
        self._extra["socket_errors"] += 1
        _LOGGER.debug("Security Center: syslog socket error (%s)", type(exc).__name__)

    def note_closed(self) -> None:
        """The transport is gone (closed by us or by the loop)."""
        if not self._closed:
            self._transport = None
            self.reason = REASON_STOPPED

    def forget_router(self, router: str) -> None:
        """Drop the key state of a forgotten router (its records stay out)."""
        self._assigner.forget_router(router)
        self._senders = {a: r for a, r in self._senders.items() if r != router}
        self._limited_at.pop(router, None)
        self._buffer = deque(r for r in self._buffer if r.router != router)

    def footprint(self) -> dict[str, int]:
        """Sizes of the bounded state (memory checks)."""
        return {
            "senders": len(self._senders),
            "buckets": len(self._buckets),
            "buffered": len(self._buffer),
        }


__all__ = [
    "RATE_LIMITED_HOLD_S",
    "REASON_ADDRESS_UNAVAILABLE",
    "REASON_BIND_FAILED",
    "REASON_NOT_STARTED",
    "REASON_PERMISSION_DENIED",
    "REASON_PORT_IN_USE",
    "REASON_RATE_LIMITED",
    "REASON_STOPPED",
    "SyslogLimits",
    "SyslogReceiver",
    "bind_reason",
    "sender_address",
]
