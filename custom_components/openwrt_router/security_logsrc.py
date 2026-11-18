"""Off-router log delivery: common interface, record format v1 and dedup.

Security Center, plan ``docs/plans/2026-11-17-security-center.md`` 4.2-4.4.
Pure module: no I/O, no clock (every time is a float epoch second passed in
by the caller), no Home Assistant import of its own. Core symbols are used
only through ``security_model`` (``clean_text``, ``LogPath``, ``DataSource``,
``SourceStatus``, ``source_status``).

Two delivery paths (A: syslog listener in HA, B: collector) produce the same
:class:`SecLogRecord`; the analysis sees records only and never the path.
:class:`Deduper` keeps the same line from counting twice when the path
changes, when the router re-sends its log ring (``logread -f`` restart) or
when the router clock jumps.

Dedup key (plan 4.3): ``sha1(router | second | proc | msg)[:16]`` plus a
running index for identical lines in the same second of one stream
(:class:`KeyAssigner`). ``second`` is the UTC second of ``ts``; a record
whose time is estimated (no zone offset known) uses the router's own wall
clock second instead (``L<n>``), because its ``ts`` is the receive time and
would differ between two deliveries of the same line.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from types import MappingProxyType
from typing import Any, Final, Protocol, runtime_checkable

from .security_model import (
    DEFAULT_STALE_AFTER_S,
    DataSource,
    LogPath,
    SourceStatus,
    clean_text,
    log_path_capability,
    source_status,
)

_LOGGER = logging.getLogger(__name__)

SCHEMA_VERSION: Final = 1
# Caps (plan 4.2 and 4.6). Lines are foreign, forgeable input.
MAX_LINE_BYTES: Final = 2048
MAX_MSG_CHARS: Final = 512
MAX_PROC_CHARS: Final = 64
MAX_ROUTER_CHARS: Final = 128
MAX_FIELDS: Final = 32
MAX_FIELD_VALUE_CHARS: Final = 255

DEFAULT_KEY_WINDOW_S: Final = 600.0  # plan 4.3: keys of the last 10 min
DEFAULT_MAX_KEYS: Final = 20_000  # plan 4.3: at most 20 000 keys per router
DEFAULT_GRACE_S: Final = 2.0  # plan 4.3: accept ts > hwm - 2 s
DEFAULT_HOLD_S: Final = 60.0
DEFAULT_MAX_HELD: Final = 5_000
DEFAULT_SPREAD_S: Final = 120.0
DEFAULT_MAX_ROUTERS: Final = 256
# A line may be at most this far ahead of its receive time (clock skew,
# batching); anything later is forged or a broken clock (review H1).
DEFAULT_MAX_FUTURE_S: Final = 120.0
# Share of a held run that must share one clock offset to be live.
DEFAULT_LIVE_SHARE: Final = 0.8
# Out-of-order window of the running index (seconds, review L2).
DEFAULT_ORDER_WINDOW_S: Final = 5

# Records that show a data source of the detectors is being delivered: only
# the kinds the detectors read (``fw.accept`` is no blocked connection).
KIND_SOURCES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "fw.drop": DataSource.FIREWALL_LOG.value,
        "fw.reject": DataSource.FIREWALL_LOG.value,
        "dns.query": DataSource.DNS_QUERY_LOG.value,
        "dns.reply": DataSource.DNS_QUERY_LOG.value,
    }
)

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")  # disjoint classes: linear
_KEY_RE = re.compile(r"[0-9a-f]{16}:\d{1,6}")
_KIND_RE = re.compile(r"[a-z][a-z0-9_]{0,15}\.[a-z0-9_]{1,32}")
_FIELD_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_TOKEN_RE = re.compile(r"[a-z][a-z0-9_]{0,15}")
_INT_LIMIT = 2**63
# Field names the parsers write (skip the name check for them).
_KNOWN_FIELDS: Final = frozenset(
    {"fmt", "unconfirmed", "ts_estimated", "ts_future", "truncated", "zone"}
    | {"dest_zone", "dir"}
    | {"src", "dst", "proto", "spt", "dpt", "in_if", "out_if", "client", "name"}
    | {"rcode", "qtype", "qid", "source", "user", "reason", "method", "mac"}
    | {"iface", "ip", "frequency", "channel"}
)


def safe_text(value: object, max_len: int) -> str:
    """Untrusted text made safe: ANSI sequences cut, ``clean_text`` applied.

    ``security_model.clean_text`` drops every control and format character
    (newlines, ESC, bidi overrides); the parameters of an ANSI sequence
    behind its ESC would stay as text, so the whole sequence goes first.
    Fast path: printable text (no control, format or separator character
    other than the space) only needs the strip that ``clean_text`` does.
    """
    text = value if isinstance(value, str) else str(value)
    text = text[: max(1, max_len) * 4]
    if "\x1b" in text:
        text = _ANSI_RE.sub("", text)
    if text.isprintable():
        stripped = text.strip()
        if len(stripped) <= max_len:
            return stripped
    return clean_text(text, max_len)


def cap_fields(fields: Mapping[str, Any]) -> MappingProxyType[str, Any]:
    """Read-only copy with at most ``MAX_FIELDS`` plain, capped values.

    Keys must be short lower-case names; values str (cleaned, capped),
    int, finite float, bool or None. Everything else is dropped.
    """
    out: dict[str, Any] = {}
    for seen, (name, value) in enumerate(fields.items()):
        if len(out) >= MAX_FIELDS or seen >= MAX_FIELDS * 4:
            break
        if name not in _KNOWN_FIELDS and (
            not isinstance(name, str) or not _FIELD_NAME_RE.fullmatch(name)
        ):
            continue
        if value is None or isinstance(value, bool):
            out[name] = value
        elif isinstance(value, int):
            if -_INT_LIMIT < value < _INT_LIMIT:
                out[name] = value
        elif isinstance(value, float):
            if math.isfinite(value):
                out[name] = value
        elif isinstance(value, str):
            out[name] = safe_text(value, MAX_FIELD_VALUE_CHARS)
    return MappingProxyType(out)


# =============================================================================
# Record format v1
# =============================================================================


@dataclass(frozen=True, kw_only=True, slots=True)
class SecLogRecord:
    """One normalised off-router log line (plan 4.2, version 1).

    ``router`` is chosen by the caller and should be the registry router id
    (``rtr_`` + 32 hex): the detectors ignore and count records with any
    other value (``DetectorSet.invalid_router``). ``fields`` is read-only. Markers in ``fields``:
    ``fmt`` (format id), ``unconfirmed`` (True when the line format was
    built from upstream documentation and not seen on a real router),
    ``ts_estimated`` (no zone offset: ``ts`` is the receive time),
    ``ts_future`` (the line's own time lay too far after its receive time:
    ``ts`` is the receive time) and ``truncated`` (line or message cut at a
    cap).
    """

    router: str
    ts: float
    recv: float
    path: str
    pri: int | None
    proc: str
    pid: int | None
    msg: str
    kind: str | None
    fields: Mapping[str, Any]
    key: str
    v: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Freeze ``fields`` (read-only view of a copy)."""
        if not isinstance(self.fields, MappingProxyType):
            object.__setattr__(self, "fields", cap_fields(self.fields))

    def __repr__(self) -> str:
        """No message or fields: they hold identities."""
        return (
            f"SecLogRecord(kind={self.kind!r}, proc={self.proc!r}, "
            f"ts={self.ts!r}, path={self.path!r}, key={self.key!r})"
        )

    @property
    def unconfirmed(self) -> bool:
        """True if the line format is not confirmed on a real router."""
        return self.fields.get("unconfirmed") is True

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (unmasked: never log it)."""
        return {
            "v": self.v,
            "router": self.router,
            "ts": self.ts,
            "recv": self.recv,
            "path": self.path,
            "pri": self.pri,
            "proc": self.proc,
            "pid": self.pid,
            "msg": self.msg,
            "kind": self.kind,
            "fields": dict(self.fields),
            "key": self.key,
        }

    @classmethod
    def from_dict(cls, data: Any) -> SecLogRecord | None:
        """Lenient inverse of :meth:`to_dict`; None (never raises) if unusable.

        Accepts schema major version 1 in any minor form (``1``, ``1.2``,
        ``"1.3"``); unknown keys are ignored, caps and text cleaning are
        applied again (a collector answer is foreign input too).
        """
        if not isinstance(data, Mapping) or _major(data.get("v")) != SCHEMA_VERSION:
            return None
        router = data.get("router")
        ts, recv = _finite(data.get("ts")), _finite(data.get("recv"))
        key = data.get("key")
        if (
            not isinstance(router, str)
            or not 0 < len(router) <= MAX_ROUTER_CHARS
            or ts is None
            or recv is None
            or not isinstance(key, str)
            or not _KEY_RE.fullmatch(key)
        ):
            return None
        path = data.get("path")
        kind = data.get("kind")
        fields = data.get("fields")
        return cls(
            router=router,
            ts=ts,
            recv=recv,
            path=path if isinstance(path, str) and _TOKEN_RE.fullmatch(path) else "",
            pri=_small_int(data.get("pri"), 0, 191),
            proc=safe_text(data.get("proc") or "", MAX_PROC_CHARS),
            pid=_small_int(data.get("pid"), 0, 2**31),
            msg=safe_text(data.get("msg") or "", MAX_MSG_CHARS),
            kind=kind if isinstance(kind, str) and _KIND_RE.fullmatch(kind) else None,
            fields=cap_fields(fields if isinstance(fields, Mapping) else {}),
            key=key,
        )


def _major(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return int(value)
    if isinstance(value, str) and len(value) <= 16:
        head = value.split(".", 1)[0]
        return int(head) if head.isdigit() else None
    return None


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _small_int(value: Any, low: int, high: int) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high:
        return value
    return None


# =============================================================================
# Dedup key
# =============================================================================


def second_token(ts: float, *, estimated: bool, local_wall: int | None) -> str:
    """Second part of the dedup key: UTC second, or ``L<wall>`` if estimated."""
    if estimated and local_wall is not None:
        return f"L{local_wall}"
    return str(math.floor(ts))


def base_hash(router: str, second: str, proc: str, msg: str) -> str:
    """``sha1(router|second|proc|msg)[:16]`` (plan 4.3)."""
    raw = f"{router}|{second}|{proc}|{msg}".encode("utf-8", "backslashreplace")
    return hashlib.sha1(raw, usedforsecurity=False).hexdigest()[:16]


def make_key(router: str, second: str, proc: str, msg: str, index: int = 0) -> str:
    """Full dedup key ``<base hash>:<running index>``."""
    return f"{base_hash(router, second, proc, msg)}:{index}"


def _second_number(second: str) -> int | None:
    """Numeric value of a second token (``"123"`` or ``"L123"``)."""
    digits = second.removeprefix("L")
    body = digits.removeprefix("-")
    return int(digits) if body.isdigit() and len(body) <= 12 else None


@dataclass(slots=True)
class _KeyState:
    newest: int
    counts: dict[str, int] = field(default_factory=dict)  # "second|hash" → next


class KeyAssigner:
    """Running index for identical lines within one second of one stream.

    One instance per stream (per delivery path, or for the ``log read``
    hook). The index of ``(router, second, line)`` is kept while that second
    lies within ``order_window_s`` of the router's newest second, so a line
    arriving out of order still continues its own count (review L2). A line
    further back than that starts a new run of indices (a re-sent stretch
    of the log gets the same keys as the first delivery), while three
    identical lines in one second stay three records. Bounded by
    ``max_per_second`` entries per router.
    """

    def __init__(
        self,
        *,
        max_routers: int = DEFAULT_MAX_ROUTERS,
        max_per_second: int = 20_000,
        order_window_s: int = DEFAULT_ORDER_WINDOW_S,
    ) -> None:
        """Create an empty assigner (bounded per router)."""
        self._max_routers = max(1, int(max_routers))
        self._max_per_second = max(1, int(max_per_second))
        self._order_window_s = max(0, int(order_window_s))
        self._state: dict[str, _KeyState] = {}

    def assign(self, router: str, second: str, proc: str, msg: str) -> str:
        """Key of the next line ``(router, second, proc, msg)`` of this stream."""
        base = base_hash(router, second, proc, msg)
        state = self._state.get(router)
        if state is None and len(self._state) >= self._max_routers:
            return f"{base}:0"
        number = _second_number(second)
        if state is None or number is None:
            state = _KeyState(newest=number or 0)
            self._state[router] = state
        elif number > state.newest:
            state.newest = number
            self._forget_before(state, number - self._order_window_s)
        elif number < state.newest - self._order_window_s:
            state = _KeyState(newest=number)  # far back: a re-sent stretch
            self._state[router] = state
        slot = f"{second}|{base}"
        counts = state.counts
        index = counts.get(slot, 0)
        if index or len(counts) < self._max_per_second:
            counts[slot] = index + 1
        return f"{base}:{index}"

    def forget_router(self, router: str) -> None:
        """Drop the key state of a forgotten router."""
        self._state.pop(router, None)

    @staticmethod
    def _forget_before(state: _KeyState, oldest: int) -> None:
        stale = [
            k
            for k in state.counts
            if (n := _second_number(k.split("|", 1)[0])) is None or n < oldest
        ]
        for key in stale:
            del state.counts[key]


# =============================================================================
# Counters
# =============================================================================


@dataclass(frozen=True, kw_only=True, slots=True)
class SourceStats:
    """Counters of one delivery path; no identities (no router, IP or MAC)."""

    received: int = 0
    parsed: int = 0  # line recognised (kind set)
    unparsed: int = 0  # valid line, unknown content (kind None, kept)
    invalid: int = 0  # no valid syslog head: no record
    truncated: int = 0
    ts_estimated: int = 0
    ts_future: int = 0  # line dated after its receive time: time = receive time
    dropped_sender: int = 0
    dropped_rate: int = 0
    dropped_buffer: int = 0

    @classmethod
    def from_counts(cls, counts: Mapping[str, Any]) -> SourceStats:
        """Build from a counter mapping; unknown names and non-ints ignored."""
        known = cls.__slots__
        return cls(
            **{
                name: value
                for name, value in counts.items()
                if name in known
                and isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
            }
        )

    def to_dict(self) -> dict[str, int]:
        """Plain counter mapping."""
        return asdict(self)


@dataclass(frozen=True, kw_only=True, slots=True)
class DedupStats:
    """Counters of the :class:`Deduper`; no identities."""

    accepted: int = 0
    dup_key: int = 0  # same key seen before
    dup_old: int = 0  # held old lines judged a re-send and dropped
    held: int = 0  # old lines held for a decision
    released: int = 0  # held lines judged new (clock jump) and passed on
    held_overflow: int = 0  # dropped: hold buffer full
    epoch_resets: int = 0  # router clock moved: high-water mark restarted
    untracked: int = 0  # passed on without dedup (router cap reached)
    hwm_clamped: int = 0  # a mark ahead of the receive time was lowered

    def to_dict(self) -> dict[str, int]:
        """Plain counter mapping."""
        return asdict(self)


# =============================================================================
# Delivery path interface
# =============================================================================


@runtime_checkable
class LogSource(Protocol):
    """One delivery path of off-router log lines (plan 4.2)."""

    name: str  # "syslog" | "collector" ("off" for NullLogSource)

    async def async_start(self) -> None:
        """Start receiving (bind the socket, start polling)."""

    async def async_stop(self) -> None:
        """Stop receiving and release resources."""

    def drain(self, max_records: int) -> list[SecLogRecord]:
        """Up to ``max_records`` records received so far; never blocks."""

    def stats(self) -> SourceStats:
        """Counters only, no identities."""


class NullLogSource:
    """The "off" setting: delivers nothing, every path source not available."""

    name = LogPath.OFF.value  # the "off" setting (plan 4.1): no path

    async def async_start(self) -> None:
        """Nothing to start."""

    async def async_stop(self) -> None:
        """Nothing to stop."""

    def drain(self, max_records: int) -> list[SecLogRecord]:
        """Never any record."""
        return []

    def stats(self) -> SourceStats:
        """All counters zero."""
        return SourceStats()

    def status(self, source: str, *, now: float) -> SourceStatus:
        """``not_available`` (disabled) for every source."""
        return source_status(source, now=now, last_ok=None, enabled=False)


# =============================================================================
# Dedup and high-water mark
# =============================================================================


@dataclass(slots=True)
class _Run:
    """Old lines (ts below the high-water mark) waiting for a decision."""

    first_recv: float
    min_skew: float
    max_skew: float
    max_ts: float
    held: list[SecLogRecord] = field(default_factory=list)
    keys: set[str] = field(default_factory=set)
    replay: bool = False  # a line accepted earlier came again: a re-send


@dataclass(slots=True)
class _RouterState:
    keys: OrderedDict[str, float] = field(default_factory=OrderedDict)
    hwm: float | None = None
    run: _Run | None = None


class Deduper:
    """Per-router key set and high-water mark (plan 4.3) across all paths.

    Rules per record (state per router only; one router never affects
    another):

    1. Key seen within ``window_s`` (at most ``max_keys``) → duplicate.
    2. No mark yet, ``ts > hwm - grace_s``, or a *fresh* line (``recv - ts
       <= grace_s``: dated about when it arrived) → accepted. A fresh line
       cannot be part of an old log ring (recent lines are caught by their
       key), so no forged mark can hold a live line back.
    3. Older and unknown → held. A held run is a *re-send* (dropped) if a
       line accepted earlier came again while it was open (a duplicate
       inside the run itself is only dropped), or if fewer than
       ``live_share`` of its lines share one delay ``recv - ts`` (within
       ``spread_s`` of the median; a replayed ring arrives in one burst
       with very different ages). Otherwise it is *live* with a router
       clock that jumped back (reboot, NTP step): its lines with that delay
       are released, the few others (e.g. one forged old-dated line) are
       dropped. A run is decided when the stream catches up (``ts > hwm -
       grace_s``) or ``hold_s`` after it started; in the latter case the
       mark restarts at the newest released ``ts`` (new clock epoch).
    4. The mark never rises above ``recv + max_future_s`` of the line that
       sets it, and a mark found above the current receive time plus
       ``max_future_s`` (stored, or left by a run) is lowered to it
       (``hwm_clamped``): a forged future date cannot hold real lines back.

    Known limits: a re-send consisting only of lines older than the key
    window whose ages differ by less than ``spread_s`` (router log idle for
    longer than the window) is taken as live and passes again. During a
    clock jump of the router (lines not fresh), a forged copy of a line
    accepted earlier marks the open run as a re-send and drops it
    (``dup_old`` counts it); live lines are never affected.
    """

    def __init__(
        self,
        *,
        window_s: float = DEFAULT_KEY_WINDOW_S,
        max_keys: int = DEFAULT_MAX_KEYS,
        grace_s: float = DEFAULT_GRACE_S,
        hold_s: float = DEFAULT_HOLD_S,
        max_held: int = DEFAULT_MAX_HELD,
        spread_s: float = DEFAULT_SPREAD_S,
        max_routers: int = DEFAULT_MAX_ROUTERS,
        max_future_s: float = DEFAULT_MAX_FUTURE_S,
        live_share: float = DEFAULT_LIVE_SHARE,
    ) -> None:
        """Create an empty deduper (all limits are parameters)."""
        self.max_future_s = max(0.0, float(max_future_s))
        self.live_share = min(1.0, max(0.5, float(live_share)))
        self.window_s = float(window_s)
        self.max_keys = max(1, int(max_keys))
        self.grace_s = float(grace_s)
        self.hold_s = float(hold_s)
        self.max_held = max(0, int(max_held))
        self.spread_s = float(spread_s)
        self.max_routers = max(1, int(max_routers))
        self._routers: dict[str, _RouterState] = {}
        self._counts: dict[str, int] = dict.fromkeys(DedupStats.__slots__, 0)

    def __repr__(self) -> str:
        """No router ids."""
        return f"Deduper(routers={len(self._routers)})"

    # --- public -------------------------------------------------------------

    def filter(self, records: Iterable[SecLogRecord], now: float) -> list[SecLogRecord]:
        """New records of this batch in arrival order (held ones may follow)."""
        out: list[SecLogRecord] = []
        self._prune(now)
        for record in records:
            self._push(record, out)
        self.flush(now, out)
        return out

    def flush(
        self, now: float, out: list[SecLogRecord] | None = None
    ) -> list[SecLogRecord]:
        """Decide runs older than ``hold_s``; returns released records."""
        out = [] if out is None else out
        for state in self._routers.values():
            run = state.run
            if run is not None and now - run.first_recv >= self.hold_s:
                self._resolve(state, out, timed_out=True, now=now)
        return out

    def forget_router(self, router: str) -> None:
        """Drop the state of a forgotten router, held records included."""
        self._routers.pop(router, None)

    def hwm(self, router: str) -> float | None:
        """High-water mark of ``router`` (largest accepted ``ts``)."""
        state = self._routers.get(router)
        return None if state is None else state.hwm

    def stats(self) -> DedupStats:
        """Counters only."""
        return DedupStats(**self._counts)

    def footprint(self) -> dict[str, int]:
        """Sizes of the bounded state (memory checks)."""
        return {
            "routers": len(self._routers),
            "keys": sum(len(s.keys) for s in self._routers.values()),
            "held": sum(len(s.run.held) for s in self._routers.values() if s.run),
        }

    def to_dict(self) -> dict[str, Any]:
        """Store form: the high-water marks only (keys stay in RAM)."""
        return {
            "v": SCHEMA_VERSION,
            "hwm": {r: s.hwm for r, s in self._routers.items() if s.hwm is not None},
        }

    @classmethod
    def from_dict(cls, data: Any, **kwargs: Any) -> Deduper:
        """Deduper with stored marks; bad or unknown-version data is skipped."""
        deduper = cls(**kwargs)
        if not isinstance(data, Mapping) or _major(data.get("v")) != SCHEMA_VERSION:
            return deduper
        marks = data.get("hwm")
        for router, mark in marks.items() if isinstance(marks, Mapping) else ():
            value = _finite(mark)
            if (
                isinstance(router, str)
                and 0 < len(router) <= MAX_ROUTER_CHARS
                and value is not None
                and len(deduper._routers) < deduper.max_routers
            ):
                deduper._routers[router] = _RouterState(hwm=value)
        return deduper

    # --- internals ----------------------------------------------------------

    def _count(self, name: str, n: int = 1) -> None:
        self._counts[name] += n

    def _prune(self, now: float) -> None:
        cutoff = now - self.window_s
        for state in self._routers.values():
            keys = state.keys
            while keys and next(iter(keys.values())) < cutoff:
                keys.popitem(last=False)

    def _state(self, router: str) -> _RouterState | None:
        state = self._routers.get(router)
        if state is None and len(self._routers) < self.max_routers:
            state = _RouterState()
            self._routers[router] = state
        return state

    def _push(self, record: SecLogRecord, out: list[SecLogRecord]) -> None:
        state = self._state(record.router)
        if state is None:
            self._count("untracked")
            out.append(record)
            return
        self._cap_mark(state, record.recv)
        run = state.run
        if run is not None and record.recv - run.first_recv >= self.hold_s:
            self._resolve(state, out, timed_out=True, now=record.recv)
            run = None
        if record.key in state.keys:
            self._count("dup_key")
            if run is not None:
                run.replay = True
            return
        caught_up = state.hwm is None or record.ts > state.hwm - self.grace_s
        if caught_up or record.recv - record.ts <= self.grace_s:
            if run is not None and caught_up:
                self._resolve(state, out, timed_out=False, now=record.recv)
            self._accept(state, record, out)
            return
        self._hold(state, record)

    def _cap_mark(self, state: _RouterState, recv: float) -> None:
        """Lower a mark that lies further ahead than ``recv + max_future_s``."""
        limit = recv + self.max_future_s
        if state.hwm is not None and state.hwm > limit:
            state.hwm = limit
            self._count("hwm_clamped")

    def _accept(
        self, state: _RouterState, record: SecLogRecord, out: list[SecLogRecord]
    ) -> None:
        state.keys[record.key] = record.recv
        if len(state.keys) > self.max_keys:
            state.keys.popitem(last=False)
        mark = min(record.ts, record.recv + self.max_future_s)
        if state.hwm is None or mark > state.hwm:
            state.hwm = mark
        out.append(record)
        self._count("accepted")

    def _hold(self, state: _RouterState, record: SecLogRecord) -> None:
        skew = record.recv - record.ts
        run = state.run
        if run is None:
            run = _Run(
                first_recv=record.recv, min_skew=skew, max_skew=skew, max_ts=record.ts
            )
            state.run = run
        if record.key in run.keys:
            self._count("dup_key")  # only dropped: no evidence of a re-send
            return
        if len(run.held) >= self.max_held:
            self._count("held_overflow")
            return
        run.held.append(record)
        run.keys.add(record.key)
        run.min_skew = min(run.min_skew, skew)
        run.max_skew = max(run.max_skew, skew)
        run.max_ts = max(run.max_ts, record.ts)
        self._count("held")

    def _resolve(
        self,
        state: _RouterState,
        out: list[SecLogRecord],
        *,
        timed_out: bool,
        now: float,
    ) -> None:
        run = state.run
        state.run = None
        if run is None:
            return
        live = [] if run.replay else self._live_part(run.held)
        if not live:
            self._count("dup_old", len(run.held))
            _LOGGER.debug("Dropped %d re-sent old log lines", len(run.held))
            self._cap_mark(state, now)
            return
        self._count("dup_old", len(run.held) - len(live))
        for record in live:
            if record.key in state.keys:
                self._count("dup_key")
                continue
            state.keys[record.key] = record.recv
            if len(state.keys) > self.max_keys:
                state.keys.popitem(last=False)
            out.append(record)
            self._count("released")
        if timed_out:
            state.hwm = max(r.ts for r in live)
            self._count("epoch_resets")
            _LOGGER.debug("Router clock moved back: high-water mark restarted")
        self._cap_mark(state, now)

    def _live_part(self, held: list[SecLogRecord]) -> list[SecLogRecord]:
        """Held lines sharing the run's typical delay; [] for a re-send."""
        if not held:
            return []
        delays = sorted(r.recv - r.ts for r in held)
        median = delays[len(delays) // 2]
        live = [r for r in held if abs(r.recv - r.ts - median) <= self.spread_s]
        return live if len(live) >= self.live_share * len(held) else []


# =============================================================================
# Liveness
# =============================================================================


class Liveness:
    """Last delivery per router and data source, as ``SourceStatus``.

    A source is ``not_available`` until a record of it arrived (never
    "fine" by silence) and ``stale`` after ``stale_after_s`` without one.
    Sources: ``KIND_SOURCES`` (firewall log, DNS query log) and, for any
    record, the capability of its delivery path. Times are receive times.

    Honest limit: syslog lines are forgeable (UDP, any sender address), so
    liveness only says "this path delivers such lines", never proof that the
    router logs them. Records whose time had to be replaced
    (``ts_future``) do not count for a detector source, and ``fw.accept``
    does not count for the firewall log the detectors read.
    """

    def __init__(
        self,
        *,
        stale_after_s: float = DEFAULT_STALE_AFTER_S,
        max_routers: int = DEFAULT_MAX_ROUTERS,
    ) -> None:
        """Create an empty tracker."""
        self.stale_after_s = float(stale_after_s)
        self.max_routers = max(1, int(max_routers))
        self._last: dict[str, dict[str, float]] = {}

    def __repr__(self) -> str:
        """No router ids."""
        return f"Liveness(routers={len(self._last)})"

    def observe(self, records: Iterable[SecLogRecord]) -> None:
        """Note the receive time of each record per router and source."""
        for record in records:
            seen = self._last.get(record.router)
            if seen is None:
                if len(self._last) >= self.max_routers:
                    continue
                seen = self._last[record.router] = {}
            future = record.fields.get("ts_future") is True
            sources = [None if future else KIND_SOURCES.get(record.kind or "")]
            if record.path in (LogPath.SYSLOG.value, LogPath.COLLECTOR.value):
                sources.append(log_path_capability(record.path))
            for source in sources:
                if source is not None and record.recv > seen.get(source, -math.inf):
                    seen[source] = record.recv

    def forget_router(self, router: str) -> None:
        """Drop the receive times of a forgotten router."""
        self._last.pop(router, None)

    def last_ok(self, router: str, source: str) -> float | None:
        """Receive time of the newest record of ``source`` from ``router``."""
        return self._last.get(router, {}).get(source)

    def status(
        self, router: str, source: str, *, now: float, enabled: bool = True
    ) -> SourceStatus:
        """``SourceStatus`` of one source of one router (``enabled=False``: off)."""
        return source_status(
            source,
            now=now,
            last_ok=self.last_ok(router, source),
            enabled=enabled,
            stale_after_s=self.stale_after_s,
        )

    def statuses(
        self, router: str, *, now: float, enabled: bool = True
    ) -> dict[str, SourceStatus]:
        """Status of every path-delivered detector source of ``router``."""
        return {
            source: self.status(router, source, now=now, enabled=enabled)
            for source in sorted(set(KIND_SOURCES.values()))
        }
