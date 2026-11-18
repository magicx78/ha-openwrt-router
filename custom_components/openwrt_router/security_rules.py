"""Security Center detectors, sliding windows and correlation (stage 2, pure).

No clock, no I/O, no HA: every time is a float passed in. Input types are
narrow Protocols / mappings, so the Network Intelligence events
(``NetEvent``, ``LogEvent``) and the off-router log records (``SecLogRecord``
of ``security_logsrc.py``, plan 4.2; not imported here) plug in unchanged.

Wording (plan 3): a finding is an *indicator* or a *hint*. No detector ever
claims an attack, a deauth attack or confirmed DNS tunnelling, and none sets
``confirmed`` (log text is forgeable, counters prove nothing).

Every detector has ``id``, ``sources`` (capability names it needs),
``describe()`` and ``evaluate(now, statuses)``. For a router whose source is
missing or stale the result is ``not_available`` / ``stale`` with the
missing sources, never "no finding". Memory is bounded everywhere: windows
are bucketed, every router has its own LRU of at most ``max_keys`` keys and
at most ``max_routers`` routers are kept; one router's restart resets only
that router's windows (:class:`RestartGuard`).

Log lines are forgeable (review H1-H3, M1). No state that one line or one
router's flood can set may silently swallow another router's, client's or
detector's events: a time more than ``max_ahead_s`` ahead of the reference
(receive time, else the evaluation clock) is clamped and counted
(``future_ts``), a router's evictions only hit that router, and every lost
state shows up as ``limitation`` (``capacity``, ``baseline_capacity``) with
``evicted`` while the window runs.

Core contract symbols are only used through ``security_model``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import math
from collections import OrderedDict, deque
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Final, Protocol

from .security_baseline import BaselineBook, BaselineStatus
from .security_model import (
    Availability,
    DataSource,
    Endpoint,
    SecCategory,
    SecurityEvent,
    Severity,
    SourceStatus,
    assess,
    event_type,
    make_correlation_id,
    make_dedup_key,
    make_event_id,
    missing_status,
    normalize_mac,
)

_LOGGER = logging.getLogger(__name__)

STORE_VERSION: Final = 1
DEFAULT_MAX_KEYS: Final = 2048
DEFAULT_MAX_ROUTERS: Final = 256
# Routers with own detector state (fleet of a handful of routers; worst case
# max_routers x max_keys slots per detector, see _BaseDetector).
DEFAULT_DETECTOR_ROUTERS: Final = 16
# Tolerance for a time ahead of its reference (clock skew, batching).
DEFAULT_MAX_AHEAD_S: Final = 120.0
WINDOW_BUCKETS: Final = 30  # resolution = window / 30
LIMIT_CAPACITY: Final = "capacity"  # state of the router was evicted/refused
LIMIT_BASELINE_CAPACITY: Final = "baseline_capacity"  # a baseline was evicted

# --- Wi-Fi event kinds (net_rules / log_parser vocabulary, plan 1.4) --------
AUTH_FAIL_KINDS: Final = frozenset(
    {"wifi.psk_mismatch", "wifi.handshake_failed", "wifi.sae_failed"}
    | {"wifi.backhaul_auth_failed"}
)
ASSOC_KINDS: Final = frozenset(
    {"wifi.connected", "wifi.assoc_rejected", "wifi.reconnect"}
)
SUCCESS_KINDS: Final = frozenset(
    {"wifi.connected", "wifi.handshake_completed", "wifi.roam", "wifi.usteer_connected"}
)
DEAUTH_KINDS: Final = frozenset(
    {"wifi.deauth", "wifi.disassoc", "wifi.mass_disconnect"}
)
AUTH_WAVE_KIND: Final = "wifi.auth_wave"
# Off-router record kinds (SecLogRecord.kind, plan 4.2).
FW_KINDS: Final = frozenset({"fw.drop", "fw.reject"})
DEST_ZONE_UNKNOWN: Final = "dest_zone_unknown"
DNS_QUERY_KIND: Final = "dns.query"
DNS_REPLY_KIND: Final = "dns.reply"  # dnsmasq writes the rcode only here
NXDOMAIN_CODES: Final = frozenset({"nxdomain", "3"})


# =============================================================================
# Sliding windows
# =============================================================================


class WindowCounter:
    """Event count over the last ``window_s`` seconds in fixed-size buckets.

    Memory: at most ``(window_s + max_ahead_s) / resolution_s + 2`` buckets
    (30 for the window plus 6 for a 600 s window with the default tolerance;
    plus 60 for a 60 s window). A value older than the newest bucket goes
    into its own bucket (at most that many steps back); values older than
    the window are dropped. A time more than ``max_ahead_s`` after the last
    known now (``count`` time or :meth:`see_now`) is clamped to that now and
    counted in ``clamped``; a bucket that is that far ahead at ``count`` time
    (added before any now was known) is moved to now. So one forged future
    time can never expire the real events (review H2).
    """

    __slots__ = (
        "_buckets",
        "_now",
        "_total",
        "clamped",
        "max_ahead_s",
        "resolution_s",
        "window_s",
    )

    def __init__(
        self,
        window_s: float,
        resolution_s: float | None = None,
        *,
        max_ahead_s: float = DEFAULT_MAX_AHEAD_S,
    ) -> None:
        """Create an empty window."""
        self.window_s = max(1.0, float(window_s))
        res = resolution_s if resolution_s else self.window_s / WINDOW_BUCKETS
        self.resolution_s = max(0.001, float(res))
        self.max_ahead_s = max(0.0, float(max_ahead_s))
        self._buckets: deque[list[float]] = deque()
        self._total = 0.0
        self._now: float | None = None
        self.clamped = 0

    def __len__(self) -> int:
        """Number of buckets held (for memory checks)."""
        return len(self._buckets)

    def see_now(self, now: float | None) -> None:
        """Note a trusted current time (receive or evaluation time)."""
        if now is not None and (self._now is None or now > self._now):
            self._now = now

    def add(self, ts: float, n: float = 1.0) -> None:
        """Count ``n`` events at ``ts``."""
        if self._now is not None and ts > self._now + self.max_ahead_s:
            ts = self._now
            self.clamped += 1
        start = math.floor(ts / self.resolution_s) * self.resolution_s
        buckets = self._buckets
        if buckets and start <= buckets[-1][0] - self.window_s - self.max_ahead_s:
            return  # far older than the window: dropped
        self._put(start, n)
        self._total += n
        self._expire(buckets[-1][0] - self.max_ahead_s)

    def _put(self, start: float, n: float) -> None:
        buckets = self._buckets
        index = len(buckets)
        while index and buckets[index - 1][0] > start:
            index -= 1
        if index and buckets[index - 1][0] == start:
            buckets[index - 1][1] += n
        else:
            buckets.insert(index, [start, n])

    def count(self, now: float) -> float:
        """Events within ``window_s`` before ``now``."""
        self.see_now(now)
        self._heal(now)
        self._expire(now)
        return self._total

    def _heal(self, now: float) -> None:
        buckets = self._buckets
        moved = 0.0
        while buckets and buckets[-1][0] > now + self.max_ahead_s:
            moved += buckets.pop()[1]
            self.clamped += 1
        if moved:
            self._put(math.floor(now / self.resolution_s) * self.resolution_s, moved)

    def _expire(self, now: float) -> None:
        limit = now - self.window_s
        buckets = self._buckets
        while buckets and buckets[0][0] + self.resolution_s <= limit:
            self._total -= buckets.popleft()[1]
        if not buckets:
            self._total = 0.0

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "window_s": self.window_s,
            "resolution_s": self.resolution_s,
            "buckets": [list(b) for b in self._buckets],
        }

    @classmethod
    def from_dict(cls, data: Any) -> WindowCounter | None:
        """Lenient inverse of :meth:`to_dict`."""
        if not isinstance(data, Mapping) or not _is_num(data.get("window_s")):
            return None
        res = data.get("resolution_s")
        win = cls(data["window_s"], res if _is_num(res) else None)
        rows = data.get("buckets")
        for row in rows if isinstance(rows, list) else ():
            if isinstance(row, list) and len(row) == 2 and all(map(_is_num, row)):
                win.add(float(row[0]), float(row[1]))
        return win


class DistinctWindow:
    """Distinct items seen in the last ``window_s`` seconds (at most ``max_items``).

    Ordered by last sighting; expiry pops from the front (O(1) amortised).
    When more than ``max_items`` are live the oldest is dropped and
    ``saturated`` is set: the count is then a lower bound. A time more than
    ``max_ahead_s`` after the last known now is clamped to it (``clamped``);
    an item that far ahead at ``count`` time is moved to now, so a forged
    future item cannot block the expiry of the others (review H2).
    """

    __slots__ = (
        "_max_ts",
        "_now",
        "_seen",
        "clamped",
        "max_ahead_s",
        "max_items",
        "saturated",
        "window_s",
    )

    def __init__(
        self,
        window_s: float,
        max_items: int = 512,
        *,
        max_ahead_s: float = DEFAULT_MAX_AHEAD_S,
    ) -> None:
        """Create an empty window."""
        self.window_s = max(1.0, float(window_s))
        self.max_items = max(1, int(max_items))
        self.max_ahead_s = max(0.0, float(max_ahead_s))
        self._seen: OrderedDict[str, float] = OrderedDict()
        self.saturated = False
        self._now: float | None = None
        self._max_ts: float | None = None
        self.clamped = 0

    def __len__(self) -> int:
        """Items held (for memory checks)."""
        return len(self._seen)

    def see_now(self, now: float | None) -> None:
        """Note a trusted current time (receive or evaluation time)."""
        if now is not None and (self._now is None or now > self._now):
            self._now = now

    def add(self, item: str, ts: float) -> None:
        """Note ``item`` at ``ts``."""
        if self._now is not None and ts > self._now + self.max_ahead_s:
            ts = self._now
            self.clamped += 1
        seen = self._seen
        old = seen.get(item)
        seen[item] = ts if old is None else max(ts, old)
        seen.move_to_end(item)
        if self._max_ts is None or ts > self._max_ts:
            self._max_ts = ts
        if len(seen) > self.max_items:
            seen.popitem(last=False)
            self.saturated = True
        self._expire(ts - self.max_ahead_s)

    def count(self, now: float) -> int:
        """Distinct items within the window."""
        self._heal(now)
        self._expire(now)
        return len(self._seen)

    def items(self, now: float) -> tuple[str, ...]:
        """Live items, oldest first."""
        self._heal(now)
        self._expire(now)
        return tuple(self._seen)

    def _heal(self, now: float) -> None:
        self.see_now(now)
        limit = now + self.max_ahead_s
        if self._max_ts is None or self._max_ts <= limit:
            return
        seen = self._seen
        for item in [i for i, ts in seen.items() if ts > limit]:
            seen[item] = now
            seen.move_to_end(item)
            self.clamped += 1
        self._max_ts = max(seen.values(), default=None)

    def discard_prefix(self, prefix: str) -> None:
        """Drop every item starting with ``prefix`` (router reset)."""
        for item in [i for i in self._seen if i.startswith(prefix)]:
            del self._seen[item]

    def _expire(self, now: float) -> None:
        seen = self._seen
        limit = now - self.window_s
        while seen:
            item, ts = next(iter(seen.items()))
            if ts >= limit:
                break
            del seen[item]

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (items may be identities: never log it)."""
        return {
            "window_s": self.window_s,
            "max_items": self.max_items,
            "items": [[k, ts] for k, ts in self._seen.items()],
            "saturated": self.saturated,
        }

    @classmethod
    def from_dict(cls, data: Any) -> DistinctWindow | None:
        """Lenient inverse of :meth:`to_dict`."""
        if not isinstance(data, Mapping) or not _is_num(data.get("window_s")):
            return None
        size = data.get("max_items")
        win = cls(data["window_s"], size if isinstance(size, int) else 512)
        rows = data.get("items")
        for row in rows if isinstance(rows, list) else ():
            if (
                isinstance(row, list)
                and len(row) == 2
                and isinstance(row[0], str)
                and _is_num(row[1])
            ):
                win.add(row[0], float(row[1]))
        win.saturated = data.get("saturated") is True or win.saturated
        return win


def _is_num(value: Any) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def counter_delta(previous: float | None, current: float | None) -> float | None:
    """Increase of a monotonic counter; None on a rollback (restart) or gap."""
    if not _is_num(previous) or not _is_num(current):
        return None
    if current < previous:  # type: ignore[operator]
        return None
    return float(current) - float(previous)  # type: ignore[arg-type]


class RestartGuard:
    """Detects a router restart from its uptime going backwards."""

    def __init__(self, *, tolerance_s: float = 5.0, max_routers: int = 256) -> None:
        """Create an empty guard."""
        self.tolerance_s = float(tolerance_s)
        self.max_routers = max(1, int(max_routers))
        self._last: OrderedDict[str, float] = OrderedDict()

    def observe(self, router_id: str, uptime: float | None) -> bool:
        """True if ``uptime`` is lower than the last one (restart)."""
        if not _is_num(uptime):
            return False
        last = self._last.get(router_id)
        self._last[router_id] = float(uptime)  # type: ignore[arg-type]
        self._last.move_to_end(router_id)
        if len(self._last) > self.max_routers:
            self._last.popitem(last=False)
        return last is not None and uptime + self.tolerance_s < last  # type: ignore[operator]


# =============================================================================
# Inputs
# =============================================================================


class LogRecord(Protocol):
    """Narrow view of ``SecLogRecord`` (plan 4.2): ``router``, ``ts``, ``kind``, ``fields``."""

    @property
    def router(self) -> str:
        """Router id (contract router id)."""

    @property
    def ts(self) -> float:
        """UTC seconds."""

    @property
    def kind(self) -> str | None:
        """Normalised kind, e.g. ``fw.drop`` or ``dns.query``."""

    @property
    def fields(self) -> Mapping[str, Any]:
        """Parsed fields."""


def _get(obj: Any, name: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


@dataclass(frozen=True, kw_only=True, slots=True)
class WifiSignal:
    """One Wi-Fi fact normalised from a ``NetEvent``/``LogEvent``/mapping."""

    ts: float
    router_id: str
    kind: str
    client: str | None = field(default=None, repr=False)
    ap: str | None = field(default=None, repr=False)


def wifi_signal(obj: Any, *, router_id: str | None = None) -> WifiSignal | None:
    """Normalise a NI event; None when it lacks time, router or kind.

    Reads ``NetEvent`` (``ts``, ``router``, ``kind`` = ``wifi.x``,
    ``subject["mac"]``/``["iface"]``), ``LogEvent`` (``time_ms``,
    ``category`` + ``kind``, ``mac``, ``interface``; router from the
    caller) and mappings with the same names.
    """
    kind = _get(obj, "kind")
    if not isinstance(kind, str) or not kind:
        return None
    category = _get(obj, "category")
    category = getattr(category, "value", category)
    if "." not in kind and isinstance(category, str):
        kind = f"{category}.{kind}"
    ts = _get(obj, "ts")
    if not _is_num(ts):
        ms = _get(obj, "time_ms")
        ts = ms / 1000.0 if _is_num(ms) else None
    router = router_id or _get(obj, "router_id") or _get(obj, "router")
    if ts is None or not isinstance(router, str) or not router:
        return None
    subject = _get(obj, "subject")
    subject = subject if isinstance(subject, Mapping) else {}
    mac = _get(obj, "mac") or subject.get("mac")
    ap = _get(obj, "interface") or subject.get("iface") or _get(obj, "ap")
    return WifiSignal(
        ts=float(ts),
        router_id=router,
        kind=kind,
        client=normalize_mac(mac),
        ap=ap if isinstance(ap, str) and ap else None,
    )


# =============================================================================
# Detector framework
# =============================================================================


@dataclass(frozen=True, kw_only=True, slots=True)
class DetectorResult:
    """Outcome of one detector for one router (``router_id`` None = fleet)."""

    detector_id: str
    router_id: str | None
    status: Availability
    events: tuple[SecurityEvent, ...] = ()
    missing: tuple[str, ...] = ()
    learning: bool = False
    # Available but partly blind, e.g. DEST_ZONE_UNKNOWN (inter-VLAN) or
    # LIMIT_CAPACITY: an empty result then means "nothing seen", not "all
    # clear". Several limitations are joined with ",".
    limitation: str | None = None
    unattributed: int = 0  # records in the window that could not be judged
    evicted: int = 0  # window state / baselines lost in the window (capacity)

    @property
    def limitations(self) -> tuple[str, ...]:
        """The single limitations (empty when there is none)."""
        return tuple(self.limitation.split(",")) if self.limitation else ()

    @property
    def available(self) -> bool:
        """True if the detector could judge (an empty result means "nothing")."""
        return self.status is Availability.AVAILABLE


class Detector(Protocol):
    """What the Security Center needs from a detector."""

    id: str
    sources: frozenset[str]
    input_kind: str  # "wifi", "log" or "drift"

    def describe(self) -> str:
        """One-line English description with the active thresholds."""

    def feed(self, item: Any) -> None:
        """Take one normalised input (WifiSignal or LogRecord)."""

    def evaluate(
        self, now: float, statuses: Mapping[str, Mapping[str, SourceStatus]]
    ) -> tuple[DetectorResult, ...]:
        """Results per router; ``statuses`` = router_id → source → status."""

    def reset_router(self, router_id: str) -> None:
        """Forget all window state of one router (restart)."""

    def state_size(self) -> int:
        """Number of stored window entries (memory check)."""


def check_sources(
    required: Iterable[str], statuses: Mapping[str, SourceStatus]
) -> tuple[Availability, tuple[str, ...]]:
    """Worst availability of ``required`` and the sources that are not usable."""
    missing: list[str] = []
    worst = Availability.AVAILABLE
    for source in sorted(required):
        status = statuses.get(source) or missing_status(source)
        if status.availability is Availability.NOT_AVAILABLE:
            worst = Availability.NOT_AVAILABLE
            missing.append(source)
        elif status.availability is Availability.STALE:
            if worst is Availability.AVAILABLE:
                worst = Availability.STALE
            missing.append(source)
    return worst, tuple(missing)


def join_limitations(*limits: str | None) -> str | None:
    """Several limitations as one ``limitation`` value (None if none)."""
    parts = [p for limit in limits if limit for p in limit.split(",")]
    return ",".join(dict.fromkeys(parts)) or None


class _Slot:
    """Per-key window state (``size`` counts every stored entry)."""

    __slots__ = (
        "count",
        "distinct",
        "examples",
        "extra",
        "last_fail",
        "last_ok",
        "parts",
        "sampled",
    )

    def __init__(self) -> None:
        self.count: WindowCounter | None = None
        self.extra: WindowCounter | None = None
        self.distinct: DistinctWindow | None = None
        self.parts: dict[str, WindowCounter] | None = None  # per-router counts
        self.examples: list[str] = []
        self.last_fail: float | None = None
        self.last_ok: float | None = None
        self.sampled: float | None = None  # last baseline sample (review M4)

    def windows(self) -> Iterator[WindowCounter | DistinctWindow]:
        for win in (self.count, self.extra, self.distinct):
            if win is not None:
                yield win
        if self.parts:
            yield from self.parts.values()

    def see_now(self, now: float | None) -> None:
        for win in self.windows():
            win.see_now(now)

    def size(self) -> int:
        return (
            1
            + sum(len(win) for win in self.windows())
            + (len(self.parts) if self.parts else 0)
            + len(self.examples)
            + (self.sampled is not None)
        )


class _BaseDetector:
    """Shared window keeping, cooldown and per-router evaluation.

    State per router (review H3): every router has its own LRU of at most
    ``max_keys`` keys, so a flood at one router only evicts that router's
    keys; at most ``max_routers`` routers are kept (a further router is not
    stored). Worst case per detector: ``max_routers * max_keys`` slots. Each
    eviction or refused input is counted per router; while such a loss lies
    inside ``window_s`` the router's result carries ``limitation`` =
    ``capacity`` and ``evicted``, so "no finding" is never reported over
    lost state.

    Times (review H2): an input time more than ``max_ahead_s`` after its
    reference is clamped to the reference and counted in ``future_ts``. The
    reference is the record's ``recv`` (receive time) if it has one, else
    the last evaluation time plus the last evaluation interval (at most
    ``window_s``).
    """

    id: str = ""
    name: str = ""
    input_kind: str = "wifi"
    category: SecCategory = SecCategory.WIFI
    sources: frozenset[str] = frozenset()
    data_source: str = ""

    def __init__(
        self,
        *,
        window_s: float,
        threshold: float,
        max_keys: int = DEFAULT_MAX_KEYS,
        max_routers: int = DEFAULT_DETECTOR_ROUTERS,
        max_ahead_s: float = DEFAULT_MAX_AHEAD_S,
        cooldown_s: float | None = None,
    ) -> None:
        self.window_s = float(window_s)
        self.threshold = threshold
        self.max_keys = max(1, int(max_keys))
        self.max_routers = max(1, int(max_routers))
        self.max_ahead_s = max(0.0, float(max_ahead_s))
        self.cooldown_s = self.window_s if cooldown_s is None else float(cooldown_s)
        self.evicted = 0  # slots evicted or inputs refused (all time)
        self.future_ts = 0  # input times clamped to their reference
        self._slots: dict[tuple[str, ...], _Slot] = {}
        self._lru: dict[str, OrderedDict[tuple[str, ...], None]] = {}
        self._reported: OrderedDict[tuple[str, ...], float] = OrderedDict()
        self._loss: OrderedDict[tuple[str, str], WindowCounter] = OrderedDict()
        self._clock: float | None = None  # last evaluation time
        self._interval = 0.0  # last evaluation interval
        self._ref: float | None = None  # reference time of the current input
        self._cur_ts = 0.0  # (clamped) time of the current input

    def __repr__(self) -> str:
        """No keys (they hold identities)."""
        return f"{type(self).__name__}(keys={len(self._slots)})"

    def describe(self) -> str:
        return f"{self.name} (threshold {self.threshold:g} in {self.window_s:g} s)"

    # --- state -------------------------------------------------------------

    def _accept_ts(self, ts: float, recv: Any = None) -> float:
        """Input time, clamped to its reference if too far ahead (H2)."""
        ref: float | None = float(recv) if _is_num(recv) else None
        if ref is None and self._clock is not None:
            ref = self._clock + self._interval
        self._ref = ref
        if ref is not None and ts > ref + self.max_ahead_s:
            self.future_ts += 1
            ts = ref
        self._cur_ts = ts
        return ts

    def _tick(self, now: float) -> None:
        """Note an evaluation time (reference for inputs without recv)."""
        if self._clock is not None and now > self._clock:
            self._interval = min(now - self._clock, self.window_s)
        if self._clock is None or now > self._clock:
            self._clock = now

    def _slot(self, key: tuple[str, ...]) -> _Slot:
        slot = self._slots.get(key)
        if slot is not None:
            self._lru[key[0]].move_to_end(key)
            slot.see_now(self._ref)
            return slot
        router = key[0]
        lru = self._lru.get(router)
        if lru is None:
            if len(self._lru) >= self.max_routers:
                self._note_loss(router, LIMIT_CAPACITY, self._cur_ts)
                return self._new_slot()  # router table full: not stored
            lru = self._lru[router] = OrderedDict()
        if len(lru) >= self.max_keys:
            old, _ = lru.popitem(last=False)
            del self._slots[old]
            self._reported.pop(old, None)
            self._note_loss(router, LIMIT_CAPACITY, self._cur_ts)
        slot = self._new_slot()
        slot.see_now(self._ref)
        self._slots[key] = slot
        lru[key] = None
        return slot

    def _new_slot(self) -> _Slot:
        slot = _Slot()
        slot.count = WindowCounter(self.window_s, max_ahead_s=self.max_ahead_s)
        return slot

    def _note_loss(self, router: str, reason: str, ts: float, n: int = 1) -> None:
        """Count lost state of ``router`` (shown as limitation in the window)."""
        if n <= 0:
            return
        if reason == LIMIT_CAPACITY:
            self.evicted += n
        key = (router, reason)
        win = self._loss.get(key)
        if win is None:
            if len(self._loss) >= 2 * self.max_routers:
                self._loss.popitem(last=False)
            win = self._loss[key] = WindowCounter(
                self.window_s, max_ahead_s=self.max_ahead_s
            )
        else:
            self._loss.move_to_end(key)
        win.add(ts, n)

    def _limits(self, router: str, now: float) -> tuple[str | None, int]:
        """``(limitation, evicted)`` of ``router`` from losses in the window."""
        limits: list[str] = []
        lost = 0
        for reason in (LIMIT_CAPACITY, LIMIT_BASELINE_CAPACITY):
            win = self._loss.get((router, reason))
            count = int(win.count(now)) if win is not None else 0
            if count > 0:
                limits.append(reason)
                lost += count
        return join_limitations(*limits), lost

    def reset_router(self, router_id: str) -> None:
        for key in self._lru.pop(router_id, {}):
            self._slots.pop(key, None)
        for key in [k for k in self._reported if k and k[0] == router_id]:
            del self._reported[key]

    def state_size(self) -> int:
        """Every stored entry: slots and their windows, cooldowns, losses."""
        return (
            sum(slot.size() for slot in self._slots.values())
            + len(self._reported)
            + len(self._lru)
            + sum(1 + len(win) for win in self._loss.values())
        )

    def _routers(self, statuses: Mapping[str, Any]) -> list[str]:
        return sorted(set(statuses) | {r for r in self._lru if r})

    # --- evaluation ----------------------------------------------------------

    def evaluate(
        self, now: float, statuses: Mapping[str, Mapping[str, SourceStatus]]
    ) -> tuple[DetectorResult, ...]:
        self._tick(now)
        results = []
        for router in self._routers(statuses):
            status, missing = check_sources(self.sources, statuses.get(router, {}))
            if status is not Availability.AVAILABLE:
                results.append(
                    DetectorResult(
                        detector_id=self.id,
                        router_id=router,
                        status=status,
                        missing=missing,
                    )
                )
                continue
            events, learning = self._evaluate_router(router, now)
            limitation, lost = self._limits(router, now)
            results.append(
                DetectorResult(
                    detector_id=self.id,
                    router_id=router,
                    status=Availability.AVAILABLE,
                    events=tuple(events),
                    learning=learning,
                    limitation=limitation,
                    evicted=lost,
                )
            )
        return tuple(results)

    def _router_slots(self, router: str) -> list[tuple[tuple[str, ...], _Slot]]:
        return [(key, self._slots[key]) for key in self._lru.get(router, ())]

    def _evaluate_router(
        self, router: str, now: float
    ) -> tuple[list[SecurityEvent], bool]:
        events = []
        for key, slot in self._router_slots(router):
            event = self._check(key, slot, now)
            if event is not None and self._may_report(key, now):
                events.append(event)
        return events, False

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        raise NotImplementedError

    def _may_report(self, key: tuple[str, ...], now: float) -> bool:
        """Cooldown per key: only this key is held back, never another one."""
        last = self._reported.get(key)
        if last is not None and 0 <= now - last < self.cooldown_s:
            return False
        self._reported[key] = now
        self._reported.move_to_end(key)
        if len(self._reported) > self.max_keys * self.max_routers:
            self._reported.popitem(last=False)
        return True

    def _event(
        self,
        *,
        router_id: str | None,
        now: float,
        key: tuple[str, ...],
        severity: Severity = Severity.INFO,
        indicators: int = 1,
        client: str | None = None,
        src: Endpoint | None = None,
        dst: Endpoint | None = None,
        evidence: Sequence[str] = (),
        confidence: float = 0.5,
    ) -> SecurityEvent:
        bucket = math.floor(now / max(1.0, self.window_s))
        return SecurityEvent(
            event_id=make_event_id(self.id, *key, bucket),
            ts=now,
            type=event_type(self.id),
            router_id=router_id,
            # The whole key (AP, zone, area, client ...) tells findings apart:
            # dedup never merges two APs or two configuration areas (M2).
            dedup_key=make_dedup_key(self.id, *key[1:]),
            category=self.category,
            severity=severity,
            assessment=assess(indicators, data_source=self.data_source),
            data_source=self.data_source,
            client=client,
            src=src,
            dst=dst,
            evidence=(f"window_s={self.window_s:g}", *evidence),
            confidence=confidence,
        )


# =============================================================================
# (1) Wi-Fi detectors on Network Intelligence events
# =============================================================================


class _WifiDetector(_BaseDetector):
    input_kind = "wifi"
    category = SecCategory.WIFI
    sources = frozenset({DataSource.WIFI_EVENTS})
    data_source = DataSource.WIFI_EVENTS

    def feed(self, item: Any) -> None:
        if isinstance(item, WifiSignal):
            ts = self._accept_ts(item.ts)
            self._feed(item if ts == item.ts else replace(item, ts=ts))

    def _feed(self, sig: WifiSignal) -> None:
        raise NotImplementedError


class WifiAuthRepeatDetector(_WifiDetector):
    """Repeated authentication failures of one client at one router.

    Fewer than ``threshold`` failures never report (a typo then success stays
    normal). At or above it the finding is reported; a later successful
    connect lowers it to info but never hides it, and roaming never hides
    authentication failures.
    """

    id = "wifi_auth_repeat"
    name = "Repeated Wi-Fi authentication failures of one client"

    def __init__(
        self, *, window_s: float = 600.0, threshold: int = 5, **kw: Any
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)

    def _feed(self, sig: WifiSignal) -> None:
        if sig.client is None:
            return
        if sig.kind in AUTH_FAIL_KINDS:
            slot = self._slot((sig.router_id, sig.client))
            slot.count.add(sig.ts)  # type: ignore[union-attr]
            slot.last_fail = max(sig.ts, slot.last_fail or sig.ts)
        elif sig.kind in SUCCESS_KINDS:
            slot = self._slots.get((sig.router_id, sig.client))
            if slot is not None:
                slot.last_ok = max(sig.ts, slot.last_ok or sig.ts)

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        failures = slot.count.count(now)  # type: ignore[union-attr]
        if failures < self.threshold:
            return None
        recovered = (
            slot.last_ok is not None
            and slot.last_fail is not None
            and slot.last_ok >= slot.last_fail
        )
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            client=key[1],
            severity=Severity.INFO if recovered else Severity.WARNING,
            evidence=(f"auth_failures={failures:g}", f"connected_after={recovered}"),
        )


class WifiAuthManyClientsDetector(_WifiDetector):
    """Many different clients with authentication failures at one AP."""

    id = "wifi_auth_many_clients"
    name = "Authentication failures of many different clients at one AP"

    def __init__(
        self, *, window_s: float = 300.0, threshold: int = 5, **kw: Any
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)

    def _new_slot(self) -> _Slot:
        slot = _Slot()
        slot.distinct = DistinctWindow(
            self.window_s,
            max_items=max(64, 4 * self.threshold),
            max_ahead_s=self.max_ahead_s,
        )
        slot.count = WindowCounter(
            self.window_s, max_ahead_s=self.max_ahead_s
        )  # NI auth-wave markers
        return slot

    def _feed(self, sig: WifiSignal) -> None:
        if sig.kind in AUTH_FAIL_KINDS and sig.client is not None:
            slot = self._slot((sig.router_id, sig.ap or ""))
            slot.distinct.add(sig.client, sig.ts)  # type: ignore[union-attr]
        elif sig.kind == AUTH_WAVE_KIND:
            self._slot((sig.router_id, sig.ap or "")).count.add(sig.ts)  # type: ignore[union-attr]

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        clients = slot.distinct.count(now)  # type: ignore[union-attr]
        if clients < self.threshold:
            return None
        waves = slot.count.count(now)  # type: ignore[union-attr]
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            severity=Severity.WARNING,
            evidence=(
                f"clients={clients}",
                f"saturated={slot.distinct.saturated}",  # type: ignore[union-attr]
                f"ni_auth_wave={waves:g}",
            ),
        )


class WifiAssocBurstDetector(_WifiDetector):
    """Many association attempts of one client (roams are not counted)."""

    id = "wifi_assoc_burst"
    name = "Frequent association attempts of one client"

    def __init__(
        self, *, window_s: float = 600.0, threshold: int = 20, **kw: Any
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)

    def _feed(self, sig: WifiSignal) -> None:
        if sig.kind in ASSOC_KINDS and sig.client is not None:
            self._slot((sig.router_id, sig.client)).count.add(sig.ts)  # type: ignore[union-attr]

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        attempts = slot.count.count(now)  # type: ignore[union-attr]
        if attempts < self.threshold:
            return None
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            client=key[1],
            evidence=(f"attempts={attempts:g}",),
        )


class WifiDeauthClusterDetector(_WifiDetector):
    """Cluster of deauth/disassoc lines at one router (indicator only).

    hostapd's default log level writes no reason codes, and frames forged by
    a third party never reach the AP log: this never claims an attack.
    """

    id = "wifi_deauth_cluster"
    name = "Deauthentication/disassociation cluster (indicator, no reason codes)"

    def __init__(
        self, *, window_s: float = 60.0, threshold: int = 15, **kw: Any
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)

    def _feed(self, sig: WifiSignal) -> None:
        if sig.kind in DEAUTH_KINDS:
            self._slot((sig.router_id, sig.ap or "")).count.add(sig.ts)  # type: ignore[union-attr]

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        lines = slot.count.count(now)  # type: ignore[union-attr]
        if lines < self.threshold:
            return None
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            evidence=(f"disconnect_lines={lines:g}", "reason_codes=unavailable"),
            confidence=0.3,
        )


class WifiMultiApAuthDetector(_WifiDetector):
    """Authentication failures of one client at several APs/routers.

    A shared pattern indicator across the fleet (``router_id`` None); it does
    not claim an attack. Keys are per client, items are ``router/ap``; the
    failures are counted per router, so one router's restart forgets only
    that router's share (review L5).
    """

    id = "wifi_multi_ap_auth"
    name = "Authentication failures of one client at several APs (pattern indicator)"

    def __init__(
        self,
        *,
        window_s: float = 900.0,
        threshold: int = 2,
        min_failures: int = 3,
        **kw: Any,
    ) -> None:
        super().__init__(window_s=window_s, threshold=max(2, threshold), **kw)
        self.min_failures = int(min_failures)

    def _new_slot(self) -> _Slot:
        slot = _Slot()
        slot.distinct = DistinctWindow(
            self.window_s,
            max_items=64,
            max_ahead_s=self.max_ahead_s,
        )
        slot.parts = {}
        return slot

    def _feed(self, sig: WifiSignal) -> None:
        if sig.kind not in AUTH_FAIL_KINDS or sig.client is None:
            return
        slot = self._slot(("", sig.client))
        slot.distinct.add(f"{sig.router_id}/{sig.ap or ''}", sig.ts)  # type: ignore[union-attr]
        parts = slot.parts if slot.parts is not None else {}
        part = parts.get(sig.router_id)
        if part is None:
            if len(parts) >= self.max_routers:
                self._note_loss("", LIMIT_CAPACITY, sig.ts)
                return
            part = WindowCounter(self.window_s, max_ahead_s=self.max_ahead_s)
            parts[sig.router_id] = part
            slot.parts = parts
        part.see_now(self._ref)
        part.add(sig.ts)

    def reset_router(self, router_id: str) -> None:
        for slot in self._slots.values():
            slot.distinct.discard_prefix(f"{router_id}/")  # type: ignore[union-attr]
            if slot.parts:
                slot.parts.pop(router_id, None)

    def evaluate(
        self, now: float, statuses: Mapping[str, Mapping[str, SourceStatus]]
    ) -> tuple[DetectorResult, ...]:
        self._tick(now)
        usable = {
            r
            for r, st in statuses.items()
            if check_sources(self.sources, st)[0] is Availability.AVAILABLE
        }
        missing = tuple(sorted(set(statuses) - usable))
        if not usable:
            return (
                DetectorResult(
                    detector_id=self.id,
                    router_id=None,
                    status=Availability.NOT_AVAILABLE,
                    missing=(*self.sources, *missing),
                ),
            )
        events = []
        for key, slot in self._router_slots(""):
            event = self._check(key, slot, now)
            if event is not None and self._may_report(key, now):
                events.append(event)
        limitation, lost = self._limits("", now)
        return (
            DetectorResult(
                detector_id=self.id,
                router_id=None,
                status=Availability.AVAILABLE,
                events=tuple(events),
                missing=missing,
                limitation=limitation,
                evicted=lost,
            ),
        )

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        places = slot.distinct.items(now)  # type: ignore[union-attr]
        failures = sum(part.count(now) for part in (slot.parts or {}).values())
        if len(places) < self.threshold or failures < self.min_failures:
            return None
        routers = {p.split("/", 1)[0] for p in places}
        return self._event(
            router_id=None,
            now=now,
            key=key,
            client=key[1],
            severity=Severity.WARNING,
            evidence=(
                f"aps={len(places)}",
                f"routers={len(routers)}",
                f"auth_failures={failures:g}",
                "pattern=indicator",
            ),
        )


# =============================================================================
# (2) Firewall and DNS detectors on off-router log records
# =============================================================================


def _field(record: Any, name: str) -> Any:
    fields = _get(record, "fields")
    return fields.get(name) if isinstance(fields, Mapping) else None


def _record_router(record: Any) -> str | None:
    router = _get(record, "router_id") or _get(record, "router")
    return router if isinstance(router, str) and router else None


def _text(value: Any, max_len: int = 64) -> str:
    return (
        value[:max_len]
        if isinstance(value, str)
        else ("" if value is None else str(value)[:max_len])
    )


def _port_of(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    return value if isinstance(value, int) and 0 <= value <= 65535 else None


class _LogDetector(_BaseDetector):
    input_kind = "log"
    kinds: frozenset[str] = frozenset()

    def feed(self, item: Any) -> None:
        if _get(item, "kind") not in self.kinds:
            return
        router = _record_router(item)
        ts = _get(item, "ts")
        if router is None or not _is_num(ts):
            return
        self._feed(router, self._accept_ts(float(ts), _get(item, "recv")), item)

    def _feed(self, router: str, ts: float, record: Any) -> None:
        raise NotImplementedError


class FirewallBlockedDetector(_LogDetector):
    """Blocked connections per zone against the zone's own baseline.

    A high count alone is no evidence: the detector stays silent while the
    baseline learns, and steady background noise (typical for the ``wan``
    zone) becomes the baseline, so it stays normal. One sample per
    ``window_s`` and zone; zero is a valid sample only while the source is
    available (missing data is never 0).
    """

    id = "fw_blocked"
    name = "Unusual number of blocked connections per zone (baseline)"
    category = SecCategory.FIREWALL
    sources = frozenset({DataSource.FIREWALL_LOG})
    data_source = DataSource.FIREWALL_LOG
    kinds = FW_KINDS

    def __init__(
        self,
        *,
        window_s: float = 300.0,
        threshold: int = 50,
        baseline: BaselineBook | None = None,
        **kw: Any,
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)
        self.baseline = baseline if baseline is not None else BaselineBook()

    def _feed(self, router: str, ts: float, record: Any) -> None:
        zone = _text(_field(record, "zone"), 32) or "?"
        self._slot((router, zone)).count.add(ts)  # type: ignore[union-attr]

    def _key(self, key: tuple[str, ...]) -> str:
        return f"{key[0]}|{self.id}|{key[1]}"

    def reset_router(self, router_id: str) -> None:
        super().reset_router(router_id)
        self.baseline.mark_gap(prefix=f"{router_id}|{self.id}|")

    def _evaluate_router(
        self, router: str, now: float
    ) -> tuple[list[SecurityEvent], bool]:
        events: list[SecurityEvent] = []
        learning = False
        group = f"{router}|{self.id}"
        for key, slot in self._router_slots(router):
            if slot.sampled is not None and now - slot.sampled < self.window_s:
                continue
            slot.sampled = now
            value = slot.count.count(now)  # type: ignore[union-attr]
            verdict = self.baseline.observe(self._key(key), value, now, group=group)
            if verdict.status is not BaselineStatus.READY:
                learning = learning or verdict.status is BaselineStatus.LEARNING
                continue
            if (
                verdict.anomalous
                and value >= self.threshold
                and self._may_report(key, now)
            ):
                events.append(
                    self._event(
                        router_id=router,
                        now=now,
                        key=key,
                        src=None,
                        dst=Endpoint(zone=key[1]),
                        severity=Severity.WARNING,
                        evidence=(
                            f"zone={key[1]}",
                            f"blocked={value:g}",
                            f"baseline={verdict.mean:.1f}",
                            f"z={verdict.z:.1f}",
                        ),
                    )
                )
        lost = self.baseline.pop_evictions(group)
        self._note_loss(router, LIMIT_BASELINE_CAPACITY, now, lost)
        return events, learning


class FirewallPortScanDetector(_LogDetector):
    """Many different destination ports blocked from one source (indicator).

    Zones in ``noise_zones`` (default ``wan``: the internet scans everyone)
    are not watched.
    """

    id = "fw_port_scan_hint"
    name = "Many different blocked destination ports from one source (indicator)"
    category = SecCategory.FIREWALL
    sources = frozenset({DataSource.FIREWALL_LOG})
    data_source = DataSource.FIREWALL_LOG
    kinds = FW_KINDS

    def __init__(
        self,
        *,
        window_s: float = 300.0,
        threshold: int = 20,
        noise_zones: Iterable[str] = ("wan",),
        **kw: Any,
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)
        self.noise_zones = frozenset(noise_zones)

    def _new_slot(self) -> _Slot:
        slot = _Slot()
        slot.distinct = DistinctWindow(
            self.window_s,
            max_items=max(64, 2 * self.threshold),
            max_ahead_s=self.max_ahead_s,
        )
        return slot

    def _feed(self, router: str, ts: float, record: Any) -> None:
        zone = _text(_field(record, "zone"), 32)
        src = _text(_field(record, "src"))
        port = _port_of(_field(record, "dpt"))
        if not src or port is None or zone in self.noise_zones:
            return
        self._slot((router, zone, src)).distinct.add(str(port), ts)  # type: ignore[union-attr]

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        ports = slot.distinct.count(now)  # type: ignore[union-attr]
        if ports < self.threshold:
            return None
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            src=Endpoint(addr=key[2], zone=key[1]),
            severity=Severity.WARNING,
            evidence=(f"zone={key[1]}", f"distinct_ports={ports}"),
        )


DEFAULT_MGMT_PORTS: Final = frozenset({22, 23, 80, 443, 8080, 8443})


class FirewallMgmtAccessDetector(_LogDetector):
    """Repeated blocked attempts from watched zones on management targets.

    ``watch_zones`` (default ``guest``, ``iot``) and the management
    definition (``mgmt_addrs``, ``mgmt_ports``) are parameters.
    """

    id = "fw_mgmt_access"
    name = "Repeated blocked attempts on management addresses/ports"
    category = SecCategory.FIREWALL
    sources = frozenset({DataSource.FIREWALL_LOG})
    data_source = DataSource.FIREWALL_LOG
    kinds = FW_KINDS

    def __init__(
        self,
        *,
        window_s: float = 600.0,
        threshold: int = 3,
        watch_zones: Iterable[str] = ("guest", "iot"),
        mgmt_addrs: Iterable[str] = (),
        mgmt_ports: Iterable[int] = DEFAULT_MGMT_PORTS,
        **kw: Any,
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)
        self.watch_zones = frozenset(watch_zones)
        self.mgmt_addrs = frozenset(mgmt_addrs)
        self.mgmt_ports = frozenset(mgmt_ports)

    def _feed(self, router: str, ts: float, record: Any) -> None:
        zone = _text(_field(record, "zone"), 32)
        if zone not in self.watch_zones:
            return
        dst = _text(_field(record, "dst"))
        port = _port_of(_field(record, "dpt"))
        direction = _text(_field(record, "dir"), 16).lower()
        to_router = direction in ("in", "input") and port in self.mgmt_ports
        if not (dst in self.mgmt_addrs or to_router):
            return
        src = _text(_field(record, "src"))
        self._slot((router, zone, src)).count.add(ts)  # type: ignore[union-attr]

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        attempts = slot.count.count(now)  # type: ignore[union-attr]
        if attempts < self.threshold:
            return None
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            src=Endpoint(addr=key[2] or None, zone=key[1]),
            severity=Severity.WARNING,
            evidence=(f"zone={key[1]}", f"attempts={attempts:g}"),
        )


class FirewallInterVlanDetector(_LogDetector):
    """Repeated blocked forwards between internal zones (inter-VLAN attempts).

    fw4 log lines never name the destination zone (``dest_zone`` None), so a
    blocked forward alone could just as well be lan to wan. A record counts
    only with a known destination zone: from the record, or from
    ``dest_subnets`` (caller-supplied ``{"192.168.1.0/24": "lan", ...}``,
    longest prefix wins; a destination outside every listed subnet is
    external, not inter-VLAN). Otherwise the record is *unattributable*: it
    is counted, never guessed, and the result carries
    ``limitation="dest_zone_unknown"`` so that "no finding" is not mistaken
    for "all clear".
    """

    id = "fw_inter_vlan"
    name = "Repeated blocked inter-VLAN connection attempts"
    category = SecCategory.VLAN
    sources = frozenset({DataSource.FIREWALL_LOG})
    data_source = DataSource.FIREWALL_LOG
    kinds = FW_KINDS

    def __init__(
        self,
        *,
        window_s: float = 600.0,
        threshold: int = 5,
        wan_zones: Iterable[str] = ("wan", "wan6"),
        allowed_pairs: Iterable[tuple[str, str]] = (),
        dest_subnets: Mapping[str, str] | None = None,
        **kw: Any,
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)
        self.wan_zones = frozenset(wan_zones)
        self.allowed_pairs = frozenset(tuple(p) for p in allowed_pairs)
        # ValueError on a malformed subnet: a configuration error of the caller.
        self.dest_subnets = tuple(
            sorted(
                (
                    (ipaddress.ip_network(net, strict=False), _text(zone, 32))
                    for net, zone in (dest_subnets or {}).items()
                ),
                key=lambda item: item[0].prefixlen,
                reverse=True,
            )
        )
        self._meta: dict[str, _Slot] = {}

    def _dest_zone(self, record: Any) -> str | None:
        """Destination zone; ``""`` = external, None = not determinable."""
        given = _field(record, "dest_zone") or _field(record, "dst_zone")
        if given:
            return _text(given, 32)
        if not self.dest_subnets:
            return None
        try:
            addr = ipaddress.ip_address(_text(_field(record, "dst")))
        except ValueError:
            return None
        for net, zone in self.dest_subnets:
            if addr.version == net.version and addr in net:
                return zone
        return ""

    def _meta_slot(self, router: str) -> _Slot | None:
        slot = self._meta.get(router)
        if slot is None:
            if len(self._meta) >= self.max_routers:
                self._note_loss(router, LIMIT_CAPACITY, self._cur_ts)
                return None  # router table full: reported as capacity
            slot = _Slot()
            slot.count = WindowCounter(
                self.window_s, max_ahead_s=self.max_ahead_s
            )  # attributed forwards
            slot.extra = WindowCounter(
                self.window_s, max_ahead_s=self.max_ahead_s
            )  # unattributable forwards
            self._meta[router] = slot
        slot.see_now(self._ref)
        return slot

    def _feed(self, router: str, ts: float, record: Any) -> None:
        if _text(_field(record, "dir"), 16).lower() != "forward":
            return
        zone = _text(_field(record, "zone"), 32)
        if not zone or zone in self.wan_zones:
            return
        dest_zone = self._dest_zone(record)
        meta = self._meta_slot(router)
        if meta is None:
            return
        if dest_zone is None:
            meta.extra.add(ts)  # type: ignore[union-attr]
            return
        meta.count.add(ts)  # type: ignore[union-attr]
        if not dest_zone or dest_zone in self.wan_zones or dest_zone == zone:
            return
        if (zone, dest_zone) in self.allowed_pairs:
            return
        src = _text(_field(record, "src"))
        self._slot((router, zone, dest_zone, src)).count.add(ts)  # type: ignore[union-attr]

    def evaluate(
        self, now: float, statuses: Mapping[str, Mapping[str, SourceStatus]]
    ) -> tuple[DetectorResult, ...]:
        """Like every detector, plus the honest limitation per router.

        Limited when unattributable forwards are in the window, or when
        there is no subnet map and no record with a destination zone was
        seen (the detector then cannot see inter-VLAN traffic at all). A
        capacity limitation of the base class is kept.
        """
        out = []
        for result in super().evaluate(now, statuses):
            if not result.available:
                out.append(result)
                continue
            meta = self._meta.get(result.router_id or "")
            unknown = int(meta.extra.count(now)) if meta else 0  # type: ignore[union-attr]
            known = meta.count.count(now) if meta else 0  # type: ignore[union-attr]
            limited = unknown > 0 or (not self.dest_subnets and known <= 0)
            out.append(
                replace(
                    result,
                    unattributed=unknown,
                    limitation=join_limitations(
                        result.limitation, DEST_ZONE_UNKNOWN if limited else None
                    ),
                )
            )
        return tuple(out)

    def reset_router(self, router_id: str) -> None:
        super().reset_router(router_id)
        self._meta.pop(router_id, None)

    def state_size(self) -> int:
        return super().state_size() + sum(s.size() for s in self._meta.values())

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        attempts = slot.count.count(now)  # type: ignore[union-attr]
        if attempts < self.threshold:
            return None
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            src=Endpoint(addr=key[3] or None, zone=key[1]),
            dst=Endpoint(zone=key[2] or None),
            severity=Severity.WARNING,
            evidence=(
                f"from_zone={key[1]}",
                f"to_zone={key[2] or '?'}",
                f"attempts={attempts:g}",
            ),
        )


DRIFT_KIND: Final = "config.drift"
# Configuration areas whose change can affect segmentation (prefix match).
SEGMENTATION_AREAS: Final = (
    "firewall.zone",
    "firewall.forwarding",
    "firewall.rule",
    "network.vlan",
    "network.bridge-vlan",
    "network.device",
    "network.interface",
    "wireless.wifi-iface",
)


class VlanDriftDetector(_BaseDetector):
    """Segmentation-relevant configuration changes (drift events, parameter).

    Input: drift records of the later config-drift component in the same
    narrow shape as log records (``router``, ``ts``, ``kind`` =
    ``config.drift``, ``fields`` with ``area`` and ``critical``). Without
    the ``config.drift`` capability the result is ``not_available``; this
    module never reads the configuration itself.
    """

    id = "vlan_segmentation_drift"
    name = "Segmentation-relevant configuration change (drift)"
    input_kind = "drift"
    category = SecCategory.VLAN
    sources = frozenset({DataSource.CONFIG_DRIFT})
    data_source = DataSource.CONFIG_DRIFT

    def __init__(
        self,
        *,
        window_s: float = 3600.0,
        threshold: int = 1,
        areas: Iterable[str] = SEGMENTATION_AREAS,
        **kw: Any,
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)
        self.areas = tuple(areas)

    def _new_slot(self) -> _Slot:
        slot = _Slot()
        slot.count = WindowCounter(
            self.window_s, max_ahead_s=self.max_ahead_s
        )  # all relevant changes
        slot.extra = WindowCounter(
            self.window_s, max_ahead_s=self.max_ahead_s
        )  # critical ones
        return slot

    def feed(self, item: Any) -> None:
        if _get(item, "kind") != DRIFT_KIND:
            return
        router = _record_router(item)
        ts = _get(item, "ts")
        area = _text(_field(item, "area"), 48).lower()
        if router is None or not _is_num(ts) or not area.startswith(self.areas):
            return
        when = self._accept_ts(float(ts), _get(item, "recv"))
        slot = self._slot((router, area))
        slot.count.add(when)  # type: ignore[union-attr]
        if _field(item, "critical") is True:
            slot.extra.add(when)  # type: ignore[union-attr]

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        changes = slot.count.count(now)  # type: ignore[union-attr]
        if changes < self.threshold:
            return None
        critical = slot.extra.count(now)  # type: ignore[union-attr]
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            severity=Severity.WARNING if critical else Severity.INFO,
            evidence=(
                f"area={key[1]}",
                f"changes={changes:g}",
                f"critical={critical:g}",
            ),
        )


def name_digest(name: str) -> str:
    """Short digest of a domain name (counting without keeping the name)."""
    return hashlib.blake2b(name.lower().encode("utf-8"), digest_size=8).hexdigest()


def label_entropy(label: str) -> float:
    """Shannon entropy in bits per character."""
    if not label:
        return 0.0
    counts: dict[str, int] = {}
    for ch in label:
        counts[ch] = counts.get(ch, 0) + 1
    size = len(label)
    return -sum(c / size * math.log2(c / size) for c in counts.values())


class _DnsDetector(_LogDetector):
    category = SecCategory.DNS
    sources = frozenset({DataSource.DNS_QUERY_LOG})
    data_source = DataSource.DNS_QUERY_LOG
    kinds = frozenset({DNS_QUERY_KIND})

    def __init__(self, *, keep_names: bool = False, **kw: Any) -> None:
        super().__init__(**kw)
        self.keep_names = bool(keep_names)  # plain-text names only on request

    def _client(self, record: Any) -> str:
        return _text(_field(record, "client"))

    def _remember(self, slot: _Slot, name: str) -> None:
        if (
            self.keep_names
            and name
            and len(slot.examples) < 3
            and name not in slot.examples
        ):
            slot.examples.append(name[:100])

    def _names(self, slot: _Slot) -> tuple[str, ...]:
        return tuple(f"example={n}" for n in slot.examples) if self.keep_names else ()


class DnsRateDetector(_DnsDetector):
    """Query rate of one client against that client's own baseline."""

    id = "dns_rate"
    name = "Unusual DNS query rate of one client (per-device baseline)"

    def __init__(
        self,
        *,
        window_s: float = 300.0,
        threshold: int = 100,
        baseline: BaselineBook | None = None,
        **kw: Any,
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)
        self.baseline = baseline if baseline is not None else BaselineBook()

    def _feed(self, router: str, ts: float, record: Any) -> None:
        client = self._client(record)
        if client:
            self._slot((router, client)).count.add(ts)  # type: ignore[union-attr]

    def reset_router(self, router_id: str) -> None:
        super().reset_router(router_id)
        self.baseline.mark_gap(prefix=f"{router_id}|{self.id}|")

    def _evaluate_router(
        self, router: str, now: float
    ) -> tuple[list[SecurityEvent], bool]:
        events: list[SecurityEvent] = []
        learning = False
        group = f"{router}|{self.id}"
        for key, slot in self._router_slots(router):
            if slot.sampled is not None and now - slot.sampled < self.window_s:
                continue
            slot.sampled = now
            value = slot.count.count(now)  # type: ignore[union-attr]
            verdict = self.baseline.observe(
                f"{key[0]}|{self.id}|{key[1]}", value, now, group=group
            )
            if verdict.status is not BaselineStatus.READY:
                learning = learning or verdict.status is BaselineStatus.LEARNING
                continue
            if (
                verdict.anomalous
                and value >= self.threshold
                and self._may_report(key, now)
            ):
                events.append(
                    self._event(
                        router_id=router,
                        now=now,
                        key=key,
                        client=key[1],
                        evidence=(
                            f"queries={value:g}",
                            f"baseline={verdict.mean:.1f}",
                            f"z={verdict.z:.1f}",
                        ),
                    )
                )
        lost = self.baseline.pop_evictions(group)
        self._note_loss(router, LIMIT_BASELINE_CAPACITY, now, lost)
        return events, learning


class DnsNxdomainDetector(_DnsDetector):
    """Cluster of NXDOMAIN answers for one client.

    dnsmasq writes the answer code only in its reply lines (``dns.reply``,
    ``rcode="NXDOMAIN"``); the query line carries none. Questions are
    counted from ``dns.query``, NXDOMAIN answers from ``dns.reply`` (and
    from a ``dns.query`` record that already carries an rcode). Only this
    detector reads replies, so the rate and many-domains detectors never
    count one question twice. A reply without a client (dnsmasq without
    ``--log-queries=extra``) cannot be attributed and is skipped.
    """

    id = "dns_nxdomain_cluster"
    name = "NXDOMAIN cluster of one client"
    kinds = frozenset({DNS_QUERY_KIND, DNS_REPLY_KIND})

    def __init__(
        self,
        *,
        window_s: float = 300.0,
        threshold: int = 30,
        min_ratio: float = 0.5,
        **kw: Any,
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)
        self.min_ratio = float(min_ratio)

    def _new_slot(self) -> _Slot:
        slot = _Slot()
        slot.count = WindowCounter(
            self.window_s, max_ahead_s=self.max_ahead_s
        )  # questions (dns.query)
        slot.extra = WindowCounter(
            self.window_s, max_ahead_s=self.max_ahead_s
        )  # NXDOMAIN
        return slot

    def _feed(self, router: str, ts: float, record: Any) -> None:
        client = self._client(record)
        if not client:
            return
        slot = self._slot((router, client))
        if _get(record, "kind") == DNS_QUERY_KIND:
            slot.count.add(ts)  # type: ignore[union-attr]
        if _text(_field(record, "rcode"), 16).lower() in NXDOMAIN_CODES:
            slot.extra.add(ts)  # type: ignore[union-attr]
            self._remember(slot, _text(_field(record, "name"), 255))

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        nx = slot.extra.count(now)  # type: ignore[union-attr]
        # A reply whose query line was lost still stands for one question.
        total = max(slot.count.count(now), nx)  # type: ignore[union-attr]
        if nx < self.threshold or total <= 0 or nx / total < self.min_ratio:
            return None
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            client=key[1],
            evidence=(f"nxdomain={nx:g}", f"queries={total:g}", *self._names(slot)),
        )


class DnsManyDomainsDetector(_DnsDetector):
    """Many different domains queried by one client (names kept as digests)."""

    id = "dns_many_domains"
    name = "Many different domains queried by one client"

    def __init__(
        self, *, window_s: float = 300.0, threshold: int = 200, **kw: Any
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)

    def _new_slot(self) -> _Slot:
        slot = _Slot()
        slot.distinct = DistinctWindow(
            self.window_s,
            max_items=2 * int(self.threshold),
            max_ahead_s=self.max_ahead_s,
        )
        return slot

    def _feed(self, router: str, ts: float, record: Any) -> None:
        client = self._client(record)
        name = _text(_field(record, "name"), 255)
        if not client or not name:
            return
        slot = self._slot((router, client))
        slot.distinct.add(name_digest(name), ts)  # type: ignore[union-attr]
        self._remember(slot, name)

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        names = slot.distinct.count(now)  # type: ignore[union-attr]
        if names < self.threshold:
            return None
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            client=key[1],
            evidence=(f"distinct_domains={names}", *self._names(slot)),
        )


class DnsTunnelHintDetector(_DnsDetector):
    """Long or high-entropy labels from one client (hint, never confirmed)."""

    id = "dns_tunnel_hint"
    name = "Long/high-entropy DNS labels (tunnelling hint, never confirmed)"

    def __init__(
        self,
        *,
        window_s: float = 300.0,
        threshold: int = 10,
        long_label: int = 50,
        entropy_min_len: int = 24,
        entropy_bits: float = 4.0,
        **kw: Any,
    ) -> None:
        super().__init__(window_s=window_s, threshold=threshold, **kw)
        self.long_label = int(long_label)
        self.entropy_min_len = int(entropy_min_len)
        self.entropy_bits = float(entropy_bits)

    def is_odd(self, name: str) -> bool:
        """True for a name with a long or high-entropy label."""
        for label in name.split("."):
            if len(label) >= self.long_label:
                return True
            if (
                len(label) >= self.entropy_min_len
                and label_entropy(label) >= self.entropy_bits
            ):
                return True
        return False

    def _feed(self, router: str, ts: float, record: Any) -> None:
        client = self._client(record)
        name = _text(_field(record, "name"), 255)
        if client and name and self.is_odd(name):
            slot = self._slot((router, client))
            slot.count.add(ts)  # type: ignore[union-attr]
            self._remember(slot, name)

    def _check(
        self, key: tuple[str, ...], slot: _Slot, now: float
    ) -> SecurityEvent | None:
        odd = slot.count.count(now)  # type: ignore[union-attr]
        if odd < self.threshold:
            return None
        return self._event(
            router_id=key[0],
            now=now,
            key=key,
            client=key[1],
            evidence=(f"odd_names={odd:g}", "tunnelling=hint", *self._names(slot)),
            confidence=0.3,
        )


# =============================================================================
# Detector set
# =============================================================================


class DetectorSet:
    """Runs a list of detectors; routes inputs; handles router restarts.

    All baseline detectors share ONE ``BaselineBook`` (one size limit, one
    later store); ``baseline`` is that book.
    """

    def __init__(
        self, detectors: Iterable[Detector], *, baseline: BaselineBook | None = None
    ) -> None:
        """Take the detectors (unique ids, at most one baseline book)."""
        self.detectors: tuple[Detector, ...] = tuple(detectors)
        ids = [d.id for d in self.detectors]
        if len(ids) != len(set(ids)):
            raise ValueError("detector ids must be unique")
        books = {
            id(book): book
            for book in [
                baseline,
                *(getattr(d, "baseline", None) for d in self.detectors),
            ]
            if book is not None
        }
        if len(books) > 1:
            raise ValueError("baseline detectors must share one BaselineBook")
        self.baseline: BaselineBook = (
            next(iter(books.values())) if books else BaselineBook()
        )
        self.guard = RestartGuard()

    def feed_wifi(self, items: Iterable[Any], *, router_id: str | None = None) -> int:
        """Feed NI events / Wi-Fi signals; returns the number accepted."""
        accepted = 0
        wifi = [d for d in self.detectors if d.input_kind == "wifi"]
        for item in items:
            sig = (
                item
                if isinstance(item, WifiSignal)
                else wifi_signal(item, router_id=router_id)
            )
            if sig is None:
                continue
            accepted += 1
            for det in wifi:
                det.feed(sig)
        return accepted

    def feed_records(self, records: Iterable[Any]) -> None:
        """Feed off-router log records (``SecLogRecord``-like)."""
        logs = [d for d in self.detectors if d.input_kind == "log"]
        for record in records:
            for det in logs:
                det.feed(record)

    def feed_drift(self, records: Iterable[Any]) -> None:
        """Feed config-drift records (from the later drift component)."""
        drift = [d for d in self.detectors if d.input_kind == "drift"]
        for record in records:
            for det in drift:
                det.feed(record)

    def note_uptime(self, router_id: str, uptime: float | None) -> bool:
        """Reset that router's windows when its uptime went backwards."""
        if not self.guard.observe(router_id, uptime):
            return False
        self.reset_router(router_id)
        _LOGGER.debug("Router restart: windows of one router reset")
        return True

    def reset_router(self, router_id: str) -> None:
        """Forget all window state of ``router_id`` in every detector."""
        for det in self.detectors:
            det.reset_router(router_id)

    def evaluate(
        self, now: float, statuses: Mapping[str, Mapping[str, SourceStatus]]
    ) -> tuple[DetectorResult, ...]:
        """All detector results (per router, fleet detectors with router None)."""
        out: list[DetectorResult] = []
        for det in self.detectors:
            out.extend(det.evaluate(now, statuses))
        return tuple(out)

    def state_size(self) -> int:
        """Total stored window entries of all detectors."""
        return sum(det.state_size() for det in self.detectors)

    def describe(self) -> dict[str, str]:
        """``id`` → description."""
        return {det.id: det.describe() for det in self.detectors}


def default_detectors(
    *,
    keep_names: bool = False,
    watch_zones: Iterable[str] = ("guest", "iot"),
    mgmt_addrs: Iterable[str] = (),
    mgmt_ports: Iterable[int] = DEFAULT_MGMT_PORTS,
    noise_zones: Iterable[str] = ("wan",),
    dest_subnets: Mapping[str, str] | None = None,
    max_keys: int = DEFAULT_MAX_KEYS,
    baseline: BaselineBook | None = None,
) -> DetectorSet:
    """All stage-2 detectors with their documented default thresholds.

    Exactly one ``BaselineBook`` (``baseline`` or a new one) is shared by
    every baseline detector.
    """
    kw: dict[str, Any] = {"max_keys": max_keys}
    book = baseline if baseline is not None else BaselineBook()
    return DetectorSet(
        [
            WifiAuthRepeatDetector(**kw),
            WifiAuthManyClientsDetector(**kw),
            WifiAssocBurstDetector(**kw),
            WifiDeauthClusterDetector(**kw),
            WifiMultiApAuthDetector(**kw),
            FirewallBlockedDetector(baseline=book, **kw),
            FirewallPortScanDetector(noise_zones=noise_zones, **kw),
            FirewallMgmtAccessDetector(
                watch_zones=watch_zones,
                mgmt_addrs=mgmt_addrs,
                mgmt_ports=mgmt_ports,
                **kw,
            ),
            FirewallInterVlanDetector(dest_subnets=dest_subnets, **kw),
            VlanDriftDetector(**kw),
            DnsRateDetector(keep_names=keep_names, baseline=book, **kw),
            DnsNxdomainDetector(keep_names=keep_names, **kw),
            DnsManyDomainsDetector(keep_names=keep_names, **kw),
            DnsTunnelHintDetector(keep_names=keep_names, **kw),
        ],
        baseline=book,
    )


# =============================================================================
# (3) Correlation
# =============================================================================


@dataclass(frozen=True, kw_only=True, slots=True)
class IncidentRef:
    """Read-only reference to an existing NI incident (never modified).

    ``clients`` empty = router-scoped; ``router_ids`` empty = any router.
    """

    incident_id: str
    start: float
    end: float | None = None
    router_ids: tuple[str, ...] = ()
    clients: tuple[str, ...] = field(default=(), repr=False)


@dataclass(frozen=True, kw_only=True, slots=True)
class EventGroup:
    """Events that belong together (one ``correlation_id``)."""

    correlation_id: str
    events: tuple[SecurityEvent, ...]
    router_ids: tuple[str, ...]
    first_ts: float
    last_ts: float
    client: str | None = field(default=None, repr=False)

    @property
    def count(self) -> int:
        """Occurrences including merged duplicates."""
        return sum(e.count for e in self.events)


def _client_key(client: str | None) -> str | None:
    if client is None:
        return None
    return normalize_mac(client) or client.strip().lower()


def _group_key(event: SecurityEvent) -> tuple[str, str]:
    client = _client_key(event.client)
    if client is not None:
        return ("client", client)  # the same client links routers
    return ("router", event.router_id or "-")  # otherwise routers stay apart


def dedup_events(
    events: Iterable[SecurityEvent], *, cooldown_s: float = 300.0
) -> list[SecurityEvent]:
    """Merge duplicates (same ``dedup_scope`` within ``cooldown_s``) by count.

    The scope is the core's ``(router_id or "-", type, dedup_key)``. Events
    with a different scope (another client, router, type or endpoint) are
    never merged or dropped.
    """
    ordered = sorted(events, key=lambda e: (e.ts, e.event_id))
    out: list[SecurityEvent] = []
    open_: dict[tuple[str, str, str], int] = {}
    for event in ordered:
        key = event.dedup_scope
        idx = open_.get(key)
        if idx is not None:
            prev = out[idx]
            if event.ts - (prev.last_ts or prev.ts) <= cooldown_s:
                out[idx] = prev.merged_with(event)
                continue
        open_[key] = len(out)
        out.append(event)
    return out


def correlate(
    events: Iterable[SecurityEvent],
    *,
    gap_s: float = 300.0,
    cooldown_s: float | None = None,
    incidents: Iterable[IncidentRef] = (),
) -> tuple[EventGroup, ...]:
    """Group related events and link existing incidents (pure).

    1. duplicates (same dedup key within ``cooldown_s``, default ``gap_s``)
       are merged with a count, nothing is dropped;
    2. events of the same client (across routers) or, without client, of
       the same router form a group while the gap between them stays within
       ``gap_s``; simultaneous events of different routers without a shared
       client stay in separate groups;
    3. every event gets the group's ``correlation_id``; incidents whose
       router/client and time match are *added* to ``linked_incident_ids``
       (existing links stay; the incidents themselves are never changed).
    """
    merged = dedup_events(
        events, cooldown_s=gap_s if cooldown_s is None else cooldown_s
    )
    linker = _IncidentIndex(incidents, gap_s)
    groups: list[list[SecurityEvent]] = []
    open_: dict[tuple[str, str], tuple[int, float]] = {}
    for event in merged:
        key = _group_key(event)
        slot = open_.get(key)
        if slot is not None and event.ts - slot[1] <= gap_s:
            groups[slot[0]].append(event)
            open_[key] = (slot[0], max(slot[1], event.last_ts or event.ts))
        else:
            open_[key] = (len(groups), event.last_ts or event.ts)
            groups.append([event])
    return tuple(_finish(group, linker) for group in groups)


def _finish(group: list[SecurityEvent], linker: _IncidentIndex) -> EventGroup:
    first = group[0]
    key = _group_key(first)
    cid = make_correlation_id(*key, first.event_id)
    events = tuple(
        replace(
            e,
            correlation_id=cid,
            linked_incident_ids=(*e.linked_incident_ids, *linker.match(e)),
        )
        for e in group
    )
    routers = tuple(sorted({e.router_id for e in events if e.router_id}))
    return EventGroup(
        correlation_id=cid,
        events=events,
        router_ids=routers,
        first_ts=min(e.ts for e in events),
        last_ts=max(e.last_ts or e.ts for e in events),
        client=_client_key(first.client),
    )


class _IncidentIndex:
    """Incidents indexed by client and router for O(1) lookups per event."""

    def __init__(self, incidents: Iterable[IncidentRef], gap_s: float) -> None:
        self.gap_s = gap_s
        self.by_client: dict[str, list[IncidentRef]] = {}
        self.by_router: dict[str, list[IncidentRef]] = {}
        self.anywhere: list[IncidentRef] = []
        for inc in incidents:
            if inc.clients:
                for client in inc.clients:
                    key = _client_key(client)
                    if key is not None:
                        self.by_client.setdefault(key, []).append(inc)
            elif inc.router_ids:
                for router in inc.router_ids:
                    self.by_router.setdefault(router, []).append(inc)
            else:
                self.anywhere.append(inc)

    def match(self, event: SecurityEvent) -> Iterator[str]:
        client = _client_key(event.client)
        candidates: list[IncidentRef] = list(self.anywhere)
        if client is not None:
            candidates += self.by_client.get(client, [])
        if event.router_id:
            candidates += self.by_router.get(event.router_id, [])
        for inc in candidates:
            if inc.clients and inc.router_ids and event.router_id not in inc.router_ids:
                continue
            end = math.inf if inc.end is None else inc.end
            last = event.last_ts or event.ts
            if inc.start - self.gap_s <= last and event.ts <= end + self.gap_s:
                yield inc.incident_id


def results_events(results: Iterable[DetectorResult]) -> list[SecurityEvent]:
    """All events of available results (helper for the caller)."""
    return [e for r in results if r.available for e in r.events]


def unavailable(results: Iterable[DetectorResult]) -> list[DetectorResult]:
    """Results that could not be judged (not_available / stale)."""
    return [r for r in results if not r.available]
