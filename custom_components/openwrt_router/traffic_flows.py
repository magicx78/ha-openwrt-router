"""Flow records and bounded conntrack snapshots (task §8; plan §5, §8; Phase E).

Pure processing only: the HTTP entry for an external collector is
``traffic_collector`` (Phase K), and nothing here calls a router (no
conntrack dump, no new ubus call).

**Collector flows** (:func:`normalise_collector_flow`): one record of the
``traffic.collector.v1`` schema (plan §8), kind ``flow`` only, becomes a
:class:`~.traffic_model.FlowRecord` or a named rejection (unknown field,
invalid value, time in the future / older than 24 h / longer than 1 h). A
client MAC becomes ``client_ref`` at once (core pseudonym with the module
key) and is never kept; without the key such a record is refused
(``module_key_missing``, never a silent fallback).

**Conntrack snapshots** (:func:`parse_conntrack`, :func:`evaluate_snapshot`):
a bounded text snapshot as a collector delivers it
(``/proc/net/nf_conntrack`` or ``conntrack -L`` lines). A snapshot is a
moment, **not a flow history**: connections that ended before it or opened
after it are not in it, and a connection that is not listed is *unknown*,
never "not there" (:meth:`SnapshotEvaluation.connection_seen` gives True or
None, never False). NAT (reply tuple differs from the original) and hardware
offload flags lower the coverage visibly; counters without
``nf_conntrack_acct`` are None, never 0. Each entry gives two records, one
per direction (``orig``/``reply`` bytes), both addressed with the original
tuple (the client's view, before NAT).

**Kinds** (``FlowKind``): ``observed`` (seen by the source), ``aggregated``
(the source merged connections), ``estimated_category`` (the source only
estimated a category), ``unknown`` (the source did not say).

**Storage** (:class:`FlowStore`): RAM only, hard limits (2000 in total, 500
per feed = router x origin), configurable time to live, every discard
counted; a full feed drops its own oldest record, never one of another
feed; a full store refuses. Raw addresses stay in memory and never reach a
log; output (:meth:`FlowStore.query`) has core pseudonyms (``ipa_...``,
``cli_...``) only. What may be stored later are the anonymised aggregates of
:meth:`FlowStore.aggregates` (``client_ref`` x protocol x heuristic class,
no address). Without any flow source the state is ``no_flow_source``; an
empty result is never "no traffic".
"""

from __future__ import annotations

import ipaddress
import logging
import math
import re
from collections import Counter, OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from .core_masking import pseudonymise_identifier
from .traffic_const import (
    FEED_COLLECTOR,
    FEED_CONNTRACK,
    FLOW_MAX_AGE_S,
    FLOW_MAX_FUTURE_S,
    FLOW_MAX_SPAN_S,
    FLOW_MAX_STRING,
    FLOW_PROTOCOLS,
    FLOW_STATE_NO_SOURCE,
    FLOW_STATE_NOT_READY,
    FLOW_STATE_READY,
    FLOW_STATE_SILENT,
    FLOW_TTL_MAX_S,
    FLOW_TTL_MIN_S,
    FLOW_TTL_S,
    MAX_FLOW_AGGREGATES,
    MAX_FLOW_FEEDS,
    MAX_FLOW_QUERY,
    MAX_FLOWS_PER_FEED,
    MAX_FLOWS_TOTAL,
    MAX_SNAPSHOT_ENTRIES,
    MAX_SNAPSHOT_LINE,
    REASON_ACCT_OFF,
    REASON_EMPTY_IS_NOT_NO_TRAFFIC,
    REASON_FLOW_SOURCE_SILENT,
    REASON_INVISIBLE_IS_UNKNOWN,
    REASON_MODULE_KEY_MISSING,
    REASON_NAT_SEEN,
    REASON_SNAPSHOT_NOT_HISTORY,
    REASON_SNAPSHOT_TRUNCATED,
    REJECT_BAD_FIELD,
    REJECT_FUTURE,
    REJECT_KEY_MISSING,
    REJECT_NOT_FLOW,
    REJECT_NOT_OBJECT,
    REJECT_SPAN,
    REJECT_TOO_OLD,
    REJECT_UNKNOWN_FIELD,
)
from .traffic_model import (
    Coverage,
    CoverageReason,
    FlowDirection,
    FlowKind,
    FlowRecord,
    Source,
    valid_client_ref,
    valid_router_id,
)
from .traffic_protocols import classify

_LOGGER = logging.getLogger(__name__)

COLLECTOR_FIELDS: Final = frozenset(
    {
        "kind",
        "router_id",
        "window",
        "direction",
        "proto",
        "src",
        "dst",
        "src_port",
        "dst_port",
        "client_mac",
        "vlan_id",
        "bytes",
        "packets",
        "observation",
    }
)
_OBSERVATIONS: Final = {
    "observed": FlowKind.OBSERVED,
    "aggregated": FlowKind.AGGREGATED,
    "estimated_category": FlowKind.ESTIMATED_CATEGORY,
}


class FlowRejected(ValueError):
    """A record that is not taken; ``reason`` is a fixed code."""

    def __init__(self, reason: str) -> None:
        """Rejection with a fixed reason code (no value from the record)."""
        super().__init__(reason)
        self.reason = reason


# --- small validators -------------------------------------------------------------


def _ip(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > FLOW_MAX_STRING:
        raise FlowRejected(REJECT_BAD_FIELD)
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError:
        raise FlowRejected(REJECT_BAD_FIELD) from None


def _int(
    value: Any, *, upper: int | None = None, allow_none: bool = True
) -> int | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FlowRejected(REJECT_BAD_FIELD)
    if upper is not None and value > upper:
        raise FlowRejected(REJECT_BAD_FIELD)
    return value


def _time(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise FlowRejected(REJECT_BAD_FIELD)
    if not math.isfinite(value):
        raise FlowRejected(REJECT_BAD_FIELD)
    return float(value)


def _vlan(value: Any) -> int | None:
    vid = _int(value, upper=4094)
    if vid is not None and vid < 1:
        raise FlowRejected(REJECT_BAD_FIELD)
    return vid


# --- collector records ----------------------------------------------------------------


def normalise_collector_flow(
    raw: Any,
    *,
    now: float,
    module_key: bytes | None,
) -> FlowRecord:
    """One collector record (schema v1, kind ``flow``) as a FlowRecord.

    Raises :class:`FlowRejected` with a fixed reason; the record is never
    logged (it holds addresses).
    """
    if not isinstance(raw, Mapping):
        raise FlowRejected(REJECT_NOT_OBJECT)
    if set(raw) - COLLECTOR_FIELDS:
        raise FlowRejected(REJECT_UNKNOWN_FIELD)
    if raw.get("kind") != "flow":
        raise FlowRejected(REJECT_NOT_FLOW)
    router_id = raw.get("router_id")
    if router_id is not None and not valid_router_id(router_id):
        raise FlowRejected(REJECT_BAD_FIELD)
    window = raw.get("window")
    if not isinstance(window, Mapping) or set(window) - {"start", "end"}:
        raise FlowRejected(REJECT_BAD_FIELD)
    start, end = _time(window.get("start")), _time(window.get("end"))
    if end < start:
        raise FlowRejected(REJECT_BAD_FIELD)
    if end - start > FLOW_MAX_SPAN_S:
        raise FlowRejected(REJECT_SPAN)
    if end > now + FLOW_MAX_FUTURE_S:
        raise FlowRejected(REJECT_FUTURE)
    if end < now - FLOW_MAX_AGE_S:
        raise FlowRejected(REJECT_TOO_OLD)
    try:
        direction = FlowDirection(raw.get("direction"))
    except ValueError:
        raise FlowRejected(REJECT_BAD_FIELD) from None
    proto = raw.get("proto")
    if proto not in FLOW_PROTOCOLS:
        raise FlowRejected(REJECT_BAD_FIELD)
    observation = raw.get("observation")
    if observation is None:
        kind = FlowKind.UNKNOWN
    elif observation in _OBSERVATIONS:
        kind = _OBSERVATIONS[observation]
    else:
        raise FlowRejected(REJECT_BAD_FIELD)
    client_ref = None
    mac = raw.get("client_mac")
    if mac is not None:
        if not isinstance(mac, str) or len(mac) > FLOW_MAX_STRING:
            raise FlowRejected(REJECT_BAD_FIELD)
        if module_key is None:
            raise FlowRejected(REJECT_KEY_MISSING)
        try:
            client_ref = pseudonymise_identifier("client", mac, module_key)
        except (TypeError, ValueError):
            raise FlowRejected(REJECT_BAD_FIELD) from None
    return FlowRecord(
        router_id=router_id,
        client_ref=client_ref,
        vlan_id=_vlan(raw.get("vlan_id")),
        proto=proto,
        src=_ip(raw.get("src")),
        dst=_ip(raw.get("dst")),
        src_port=_int(raw.get("src_port"), upper=65535),
        dst_port=_int(raw.get("dst_port"), upper=65535),
        start=start,
        end=end,
        bytes=_int(raw.get("bytes")),
        packets=_int(raw.get("packets")),
        direction=direction,
        kind=kind,
        source=Source.COLLECTOR,
        nat_seen=None,
    )


# --- conntrack snapshot --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConntrackTuple:
    """One direction of a conntrack entry (raw, RAM only)."""

    src: str
    dst: str
    sport: int | None
    dport: int | None
    packets: int | None
    bytes: int | None


@dataclass(frozen=True, slots=True)
class ConntrackEntry:
    """One parsed conntrack line (raw addresses, RAM only)."""

    proto: str
    state: str | None
    orig: ConntrackTuple
    reply: ConntrackTuple | None
    flags: frozenset[str]

    @property
    def nat_seen(self) -> bool | None:
        """True when the reply tuple shows rewritten addresses (None: no reply)."""
        if self.reply is None:
            return None
        return self.reply.src != self.orig.dst or self.reply.dst != self.orig.src

    @property
    def offloaded(self) -> bool:
        """Flow offloading flag: kernel counters stop for this connection."""
        return bool(self.flags & {"OFFLOAD", "HW_OFFLOAD"})


@dataclass(frozen=True, slots=True)
class ConntrackSnapshot:
    """A bounded parse of one snapshot."""

    entries: tuple[ConntrackEntry, ...]
    truncated: bool
    invalid_lines: int


_TRANSPORTS: Final = frozenset(
    {"tcp", "udp", "icmp", "icmpv6", "sctp", "udplite", "gre"}
)
_STATE_RE: Final = re.compile(r"[A-Z_]{2,20}")


def _tuple(values: Mapping[str, str]) -> ConntrackTuple:
    src = _ip(values.get("src"))
    dst = _ip(values.get("dst"))
    if src is None or dst is None:
        raise FlowRejected(REJECT_BAD_FIELD)

    def num(name: str, upper: int | None = None) -> int | None:
        text = values.get(name)
        if text is None:
            return None
        if not text.isdigit():
            raise FlowRejected(REJECT_BAD_FIELD)
        return _int(int(text), upper=upper)

    return ConntrackTuple(
        src=src,
        dst=dst,
        sport=num("sport", 65535),
        dport=num("dport", 65535),
        packets=num("packets"),
        bytes=num("bytes"),
    )


def parse_conntrack_line(line: str) -> ConntrackEntry:
    """One conntrack line; :class:`FlowRejected` when it is not one."""
    if len(line) > MAX_SNAPSHOT_LINE:
        raise FlowRejected(REJECT_BAD_FIELD)
    proto: str | None = None
    state: str | None = None
    flags: set[str] = set()
    sides: list[dict[str, str]] = [{}]
    for token in line.split():
        if token.startswith("[") and token.endswith("]"):
            flags.add(token[1:-1])
            continue
        if "=" in token:
            name, _, value = token.partition("=")
            if name == "src" and "src" in sides[-1]:
                if len(sides) == 2:
                    break  # only two tuples per entry
                sides.append({})
            if name in ("src", "dst", "sport", "dport", "packets", "bytes"):
                sides[-1].setdefault(name, value)
            continue
        low = token.lower()
        if proto is None and low in _TRANSPORTS:
            proto = low
        elif proto is not None and _STATE_RE.fullmatch(token):
            state = token
    if proto is None:
        raise FlowRejected(REJECT_BAD_FIELD)
    orig = _tuple(sides[0])
    reply = _tuple(sides[1]) if len(sides) > 1 and sides[1] else None
    return ConntrackEntry(proto, state, orig, reply, frozenset(flags))


def parse_conntrack(
    text: str | Iterable[str], *, max_entries: int = MAX_SNAPSHOT_ENTRIES
) -> ConntrackSnapshot:
    """Parse at most ``max_entries`` lines; the rest marks it ``truncated``."""
    lines = text.splitlines() if isinstance(text, str) else text
    entries: list[ConntrackEntry] = []
    invalid = 0
    truncated = False
    for line in lines:
        if not isinstance(line, str):
            invalid += 1
            continue
        if not line.strip():
            continue
        if len(entries) >= max_entries:
            truncated = True
            break
        try:
            entries.append(parse_conntrack_line(line))
        except FlowRejected:
            invalid += 1
    return ConntrackSnapshot(tuple(entries), truncated, invalid)


@dataclass(frozen=True, slots=True)
class SnapshotEvaluation:
    """Records of one snapshot plus what they cannot tell."""

    router_id: str | None
    captured_at: float
    records: tuple[FlowRecord, ...]
    entries: int
    truncated: bool
    invalid_lines: int
    nat_seen: int
    offloaded: int
    without_accounting: int
    unattributed: int
    coverage: Coverage
    coverage_reasons: tuple[str, ...]
    complete_history: bool = False
    _seen: frozenset[tuple[str, str, str, int | None, int | None]] = field(
        default=frozenset(), repr=False
    )

    def connection_seen(
        self, proto: str, src: str, dst: str, sport: int | None, dport: int | None
    ) -> bool | None:
        """True if listed; None otherwise (unknown, never "not there")."""
        try:
            key = (proto, _ip(src) or "", _ip(dst) or "", sport, dport)
        except FlowRejected:
            return None
        return True if key in self._seen else None

    def summary(self) -> dict[str, Any]:
        """Counts and coverage only (no address)."""
        return {
            "entries": self.entries,
            "records": len(self.records),
            "truncated": self.truncated,
            "invalid_lines": self.invalid_lines,
            "nat_seen": self.nat_seen,
            "offloaded": self.offloaded,
            "without_accounting": self.without_accounting,
            "unattributed": self.unattributed,
            "coverage": self.coverage.value,
            "coverage_reasons": list(self.coverage_reasons),
            "complete_history": self.complete_history,
            "not_listed_means": REASON_INVISIBLE_IS_UNKNOWN,
        }


def evaluate_snapshot(
    snapshot: ConntrackSnapshot,
    *,
    router_id: str | None,
    captured_at: float,
    client_ref_of_ip: Callable[[str], str | None] | None = None,
) -> SnapshotEvaluation:
    """Records and coverage of a parsed snapshot (see the module docstring).

    ``client_ref_of_ip`` maps an original source address to a client
    pseudonym (None: unknown); without it no record is attributed. The
    start of a connection is not in a snapshot: ``start == end ==
    captured_at`` (the moment it was seen).
    """
    if router_id is not None and not valid_router_id(router_id):
        raise ValueError("router_id must be rtr_<32 hex> or None")
    records: list[FlowRecord] = []
    seen: set[tuple[str, str, str, int | None, int | None]] = set()
    nat = offloaded = no_acct = unattributed = 0
    for entry in snapshot.entries:
        orig = entry.orig
        seen.add((entry.proto, orig.src, orig.dst, orig.sport, orig.dport))
        nat_seen = entry.nat_seen
        nat += nat_seen is True
        offloaded += entry.offloaded
        if orig.bytes is None:
            no_acct += 1
        ref = None
        if client_ref_of_ip is not None:
            try:
                found = client_ref_of_ip(orig.src)
            except Exception:  # noqa: BLE001 - no attribution, never an error
                found = None
            ref = found if valid_client_ref(found) else None
        if ref is None:
            unattributed += 1
        proto = entry.proto if entry.proto in FLOW_PROTOCOLS else "other"
        if entry.proto == "icmpv6":
            proto = "icmp"
        sides = [(FlowDirection.ORIG, orig)]
        if entry.reply is not None:
            sides.append((FlowDirection.REPLY, entry.reply))
        for direction, side in sides:
            records.append(
                FlowRecord(
                    router_id=router_id,
                    client_ref=ref,
                    vlan_id=None,
                    proto=proto,
                    src=orig.src,
                    dst=orig.dst,
                    src_port=orig.sport,
                    dst_port=orig.dport,
                    start=captured_at,
                    end=captured_at,
                    bytes=side.bytes,
                    packets=side.packets,
                    direction=direction,
                    kind=FlowKind.OBSERVED,
                    source=Source.COLLECTOR,
                    nat_seen=nat_seen,
                )
            )
    reasons = {REASON_SNAPSHOT_NOT_HISTORY}
    if snapshot.truncated:
        reasons.add(REASON_SNAPSHOT_TRUNCATED)
    if nat:
        reasons.add(REASON_NAT_SEEN)
    if offloaded:
        reasons.add(CoverageReason.HW_OFFLOAD_ON.value)
    if no_acct:
        reasons.add(REASON_ACCT_OFF)
    coverage = Coverage.PARTIAL if snapshot.entries else Coverage.UNKNOWN
    return SnapshotEvaluation(
        router_id=router_id,
        captured_at=captured_at,
        records=tuple(records),
        entries=len(snapshot.entries),
        truncated=snapshot.truncated,
        invalid_lines=snapshot.invalid_lines,
        nat_seen=nat,
        offloaded=offloaded,
        without_accounting=no_acct,
        unattributed=unattributed,
        coverage=coverage,
        coverage_reasons=tuple(sorted(reasons)),
        _seen=frozenset(seen),
    )


# --- RAM store -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FlowSourceState:
    """Whether a flow source exists and its records can be shown."""

    state: str
    reason: str | None
    feeds: int
    records: int

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "state": self.state,
            "reason": self.reason,
            "feeds": self.feeds,
            "records": self.records,
        }


@dataclass(frozen=True, slots=True)
class FlowQuery:
    """Pseudonymised flow rows; an empty list is never "no traffic"."""

    source: FlowSourceState
    rows: tuple[dict[str, Any], ...]
    complete: bool = False
    notes: tuple[str, ...] = (
        REASON_EMPTY_IS_NOT_NO_TRAFFIC,
        REASON_INVISIBLE_IS_UNKNOWN,
    )

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "source": self.source.to_dict(),
            "rows": [dict(r) for r in self.rows],
            "complete": self.complete,
            "notes": list(self.notes),
        }


@dataclass(slots=True)
class _Entry:
    record: FlowRecord
    arrived: float
    feed: str


def _pseudo_ip(value: str | None, key: bytes) -> str | None:
    if value is None:
        return None
    try:
        return pseudonymise_identifier("ip", value, key)
    except (TypeError, ValueError):
        return None


class FlowStore:
    """Bounded RAM store of flow records (see the module docstring)."""

    def __init__(
        self,
        *,
        max_total: int = MAX_FLOWS_TOTAL,
        max_per_feed: int = MAX_FLOWS_PER_FEED,
        ttl_s: float = FLOW_TTL_S,
    ) -> None:
        """Empty store."""
        self._max_total = max_total
        self._max_feed = max_per_feed
        self.ttl_s = self._clamp_ttl(ttl_s)
        self._feeds: dict[str, deque[_Entry]] = {}
        # Last record time per feed, bounded (MAX_FLOW_FEEDS) and pruned
        # with the TTL; ``_had_source`` keeps "silent" after the prune.
        self._last_seen: dict[str, float] = {}
        self._had_source = False
        self._total = 0
        self._aggregates: OrderedDict[tuple[str | None, str, str], list[int]] = (
            OrderedDict()
        )
        self.counters: Counter[str] = Counter()

    @staticmethod
    def _clamp_ttl(ttl_s: Any) -> float:
        if isinstance(ttl_s, bool) or not isinstance(ttl_s, int | float):
            return FLOW_TTL_S
        if not math.isfinite(ttl_s):
            return FLOW_TTL_S
        return float(min(FLOW_TTL_MAX_S, max(FLOW_TTL_MIN_S, ttl_s)))

    def set_ttl(self, ttl_s: Any, now: float) -> float:
        """Configure the retention (clamped) and prune at once."""
        self.ttl_s = self._clamp_ttl(ttl_s)
        self.prune(now)
        return self.ttl_s

    def __len__(self) -> int:
        """Records held."""
        return self._total

    @staticmethod
    def feed_of(origin: str, router_id: str | None) -> str:
        """Feed name of an origin (collector flow / conntrack) and router."""
        return f"{origin}:{router_id or '-'}"

    # -- adding ------------------------------------------------------------------------

    def add(self, record: FlowRecord, *, origin: str, now: float) -> bool:
        """Keep one record; False when the store is full (counted)."""
        feed = self.feed_of(origin, record.router_id)
        self.prune(now)
        self._seen(feed, now)
        queue = self._feeds.get(feed)
        if queue is not None and len(queue) >= self._max_feed:
            queue.popleft()
            self._total -= 1
            self.counters["dropped_flows_feed_full"] += 1
        elif self._total >= self._max_total:
            self.counters["dropped_flows_store_full"] += 1
            return False
        if queue is None:
            queue = self._feeds[feed] = deque()
        queue.append(_Entry(record, now, feed))
        self._total += 1
        self.counters["accepted_flows"] += 1
        self._aggregate(record)
        return True

    def can_take(
        self, records: Iterable[FlowRecord], *, origin: str, now: float
    ) -> bool:
        """True if ``add`` would keep every one of ``records`` (no refusal).

        Used by the collector intake so a call is kept completely or not at
        all; a full feed dropping its own oldest record is no refusal.
        """
        self.prune(now)
        sizes = {feed: len(q) for feed, q in self._feeds.items()}
        total = self._total
        for record in records:
            feed = self.feed_of(origin, record.router_id)
            if sizes.get(feed, 0) >= self._max_feed:
                continue
            if total >= self._max_total:
                return False
            sizes[feed] = sizes.get(feed, 0) + 1
            total += 1
        return True

    def add_collector(
        self, raws: Iterable[Any], *, now: float, module_key: bytes | None
    ) -> tuple[int, list[tuple[int, str]]]:
        """Normalise and keep collector records; (accepted, [(index, reason)])."""
        accepted = 0
        rejected: list[tuple[int, str]] = []
        for index, raw in enumerate(raws):
            try:
                record = normalise_collector_flow(raw, now=now, module_key=module_key)
            except FlowRejected as err:
                rejected.append((index, err.reason))
                self.counters[f"rejected_{err.reason}"] += 1
                continue
            except (TypeError, ValueError):
                rejected.append((index, REJECT_BAD_FIELD))
                self.counters[f"rejected_{REJECT_BAD_FIELD}"] += 1
                continue
            if self.add(record, origin=FEED_COLLECTOR, now=now):
                accepted += 1
            else:
                rejected.append((index, "store_full"))
        return accepted, rejected

    def add_snapshot(self, evaluation: SnapshotEvaluation, *, now: float) -> int:
        """Keep the records of a snapshot; returns how many were kept."""
        kept = 0
        for record in evaluation.records:
            kept += self.add(record, origin=FEED_CONNTRACK, now=now)
        self._seen(self.feed_of(FEED_CONNTRACK, evaluation.router_id), now)
        self.counters["snapshots"] += 1
        return kept

    def _seen(self, feed: str, now: float) -> None:
        """Note a sign of life of ``feed``; a new feed over the bound
        pushes out the one heard from longest ago (with its records)."""
        self._had_source = True
        if feed not in self._last_seen and len(self._last_seen) >= MAX_FLOW_FEEDS:
            oldest = min(self._last_seen, key=self._last_seen.__getitem__)
            del self._last_seen[oldest]
            queue = self._feeds.pop(oldest, None)
            if queue is not None:
                self._total -= len(queue)
            self.counters["dropped_feeds"] += 1
        self._last_seen[feed] = now

    def _aggregate(self, record: FlowRecord) -> None:
        """Anonymised aggregate: client_ref x proto x heuristic class (no IP)."""
        label = classify(record.proto, record.src_port, record.dst_port).label
        key = (record.client_ref, record.proto, label)
        values = self._aggregates.get(key)
        if values is None:
            if len(self._aggregates) >= MAX_FLOW_AGGREGATES:
                self.counters["dropped_aggregates"] += 1
                return
            values = self._aggregates[key] = [0, 0, 0]
        values[0] += 1
        values[1] += record.bytes or 0
        values[2] += record.packets or 0

    # -- maintenance ---------------------------------------------------------------------

    def prune(self, now: float) -> int:
        """Drop records older than the TTL; returns how many."""
        cutoff = now - self.ttl_s
        gone = 0
        for feed in list(self._feeds):
            queue = self._feeds[feed]
            while queue and queue[0].arrived < cutoff:
                queue.popleft()
                gone += 1
            if not queue:
                del self._feeds[feed]
        for feed in [f for f, t in self._last_seen.items() if t < cutoff]:
            if feed not in self._feeds:
                del self._last_seen[feed]
        self._total -= gone
        self.counters["expired_flows"] += gone
        return gone

    def clear(self) -> None:
        """Forget every record and aggregate (counters stay)."""
        self._feeds.clear()
        self._last_seen.clear()
        self._had_source = False
        self._aggregates.clear()
        self._total = 0

    # -- reading ---------------------------------------------------------------------------

    def source_state(self, now: float, *, module_key: bytes | None) -> FlowSourceState:
        """``no_flow_source`` / ``source_silent`` / ``not_ready`` / ``ready``."""
        self.prune(now)
        live = [f for f, t in self._last_seen.items() if now - t <= self.ttl_s]
        if not self._had_source:
            return FlowSourceState(
                FLOW_STATE_NO_SOURCE,
                CoverageReason.NEEDS_FLOW_SOURCE.value,
                0,
                0,
            )
        if not live:
            return FlowSourceState(
                FLOW_STATE_SILENT, REASON_FLOW_SOURCE_SILENT, len(self._last_seen), 0
            )
        if module_key is None:
            return FlowSourceState(
                FLOW_STATE_NOT_READY, REASON_MODULE_KEY_MISSING, len(live), self._total
            )
        return FlowSourceState(FLOW_STATE_READY, None, len(live), self._total)

    def query(
        self,
        now: float,
        *,
        module_key: bytes | None,
        router_id: str | None = None,
        client_ref: str | None = None,
        proto: str | None = None,
        limit: int = MAX_FLOW_QUERY,
    ) -> FlowQuery:
        """Newest records first, pseudonymised; nothing while not ready."""
        state = self.source_state(now, module_key=module_key)
        if state.state != FLOW_STATE_READY or module_key is None:
            return FlowQuery(state, ())
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            limit = MAX_FLOW_QUERY
        limit = min(limit, MAX_FLOW_QUERY)
        entries = [
            e
            for q in self._feeds.values()
            for e in q
            if (router_id is None or e.record.router_id == router_id)
            and (client_ref is None or e.record.client_ref == client_ref)
            and (proto is None or e.record.proto == proto)
        ]
        entries.sort(key=lambda e: (-e.arrived, -e.record.end, e.feed))
        rows = tuple(self._public(e, module_key) for e in entries[:limit])
        return FlowQuery(state, rows)

    @staticmethod
    def _public(entry: _Entry, key: bytes) -> dict[str, Any]:
        record = entry.record
        guess = classify(record.proto, record.src_port, record.dst_port)
        return {
            "router_id": record.router_id,
            "client_ref": record.client_ref,
            "attribution": "client" if record.client_ref else "unknown",
            "vlan_id": record.vlan_id,
            "proto": record.proto,
            "src": _pseudo_ip(record.src, key),
            "dst": _pseudo_ip(record.dst, key),
            "src_port": record.src_port,
            "dst_port": record.dst_port,
            "start": record.start,
            "end": record.end,
            "bytes": record.bytes,
            "packets": record.packets,
            "direction": record.direction.value,
            "kind": record.kind.value,
            "source": record.source.value,
            "origin": entry.feed.split(":", 1)[0],
            "snapshot": entry.feed.startswith(FEED_CONNTRACK),
            "nat_seen": record.nat_seen,
            "protocol": guess.to_dict(),
        }

    def aggregates(self) -> list[dict[str, Any]]:
        """Anonymised aggregates (the only flow data that may be stored)."""
        return [
            {
                "client_ref": ref,
                "proto": proto,
                "class": label,
                "heuristic": True,
                "flows": v[0],
                "bytes": v[1],
                "packets": v[2],
            }
            for (ref, proto, label), v in sorted(
                self._aggregates.items(),
                key=lambda kv: (kv[0][0] or "", kv[0][1], kv[0][2]),
            )
        ]

    def summary(self) -> dict[str, Any]:
        """Counts only (no address, no client id)."""
        return {
            "records": self._total,
            "feeds": len(self._feeds),
            "ttl_s": self.ttl_s,
            "limits": {"total": self._max_total, "per_feed": self._max_feed},
            "aggregates": len(self._aggregates),
            **dict(self.counters),
        }
