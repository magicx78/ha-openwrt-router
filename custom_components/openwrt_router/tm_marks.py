"""Network Time Machine, Phases B/C: the marks of the own index.

Pure module (no Home Assistant import, no clock read): the mark model, its
packed store form and :class:`MarkIndex`, the bounded in-memory index that
``tm_store`` persists and ``tm_engine`` / ``tm_clients`` fill. Plan
``docs/plans/2026-11-21-network-time-machine.md`` §5.1, §5.5, §5.7.

**A mark** carries only codes, numbers and ids: a time on the millisecond
grid, a kind (``tm_sources.KIND_GROUP``), the contract ``router_id``, a
severity, a code (lower-case dotted token), an optional interval end with
its state (``open`` / ``closed`` / ``unknown``), the client pseudonym
(16 hex of ``tmc_…``, clients only), up to eight numeric params, a
reference into a source module (``audit`` / ``incident``) and two peer
routers (uplink parent before/after, roaming source/target). No MAC, IP,
host name, SSID or netdev name exists in this model; :func:`unpack`
refuses any field that does not match its pattern.

**Store form.** One string per mark (HA writes store files indented: a
JSON list per mark would cost one line per field), fields separated by
``|``; routers as indexes into a table written next to the marks. A row
that does not parse is skipped and counted, never the whole file.

**Bounds** (plan §5.5, retention 14 days per F1): three quotas that never
evict each other (infrastructure 3000, references 2000, clients 10000;
together the total of 15000), the oldest closed mark *of the same quota*
goes first and is counted (an open interval only when its quota holds
nothing else, ``evicted_open``); per client and UTC day at most 200 new marks, the
rest is folded into one ``client_flapping`` mark with a counter. Updates of
an existing mark (closing an interval) are never capped.

**Lost marks** (1.52.0, Phase D): ``MarkIndex.lost`` holds per quota the
latest moment a mark that is gone without the retention reached (its end,
or for an open interval the newest time the index knew): evicted marks,
marks trimmed for the size limit, the marks of a removed router and cleared
histories. ``tm_state`` answers "unknown" up to it instead of reconstructing
a state from an incomplete list. Pruned marks (older than the retention)
are not counted: the retention bound covers them.
"""

from __future__ import annotations

import heapq
import math
import re
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from .tm_sources import (
    GROUP_ADMINISTRATION,
    GROUP_CLIENTS,
    GROUP_CONFIGURATION,
    GROUP_DISRUPTION,
    GROUP_SECURITY,
    KIND_GROUP,
    PARAMS_MAX,
    SEVERITIES,
    SOURCE_TM_CLIENTS,
    SOURCE_TM_INDEX,
    SOURCE_TM_REFS,
)

# --- sources of the own index (additive to tm_sources.SOURCE_IDS) ----------------------

# ``tm_index``: infrastructure, radio, topology, own marks; ``tm_refs``:
# references to audit entries (admins only); ``tm_clients``: client sessions
# (admins, own switch). Defined in ``tm_sources``.

# Kinds of reference marks (taken from the audit log as soon as published):
# configuration and disruption entries of the modules, so they stay on the
# timeline after the audit ring evicted them (plan R8).
REF_KINDS: Final = frozenset(
    {
        "config_drift",
        "config_event",
        "rf_event",
        "diag_finding",
        "traffic_anomaly",
        "security_incident",
    }
)
CLIENT_KINDS: Final = frozenset(
    k for k, group in KIND_GROUP.items() if group == GROUP_CLIENTS
)
INTERVAL_KINDS: Final = frozenset(
    {
        "router_down",
        "lan_down",
        "observation_gap",
        "ha_gap",
        "radio_down",
        "client_session",
        "client_flapping",
    }
)

# --- quotas and limits (plan §5.5) -----------------------------------------------------

QUOTA_INFRA: Final = "infrastructure"
QUOTA_REFS: Final = "references"
QUOTA_CLIENTS: Final = "clients"
QUOTAS: Final[Mapping[str, int]] = {
    QUOTA_INFRA: 3000,
    QUOTA_REFS: 2000,
    QUOTA_CLIENTS: 10000,
}
MAX_MARKS: Final = sum(QUOTAS.values())  # 15000
RETENTION_S: Final = 14 * 86_400.0  # F1
CLIENT_DAY_CAP: Final = 200
DAY_S: Final = 86_400

_REF_QUOTA_GROUPS: Final = frozenset(
    {GROUP_CONFIGURATION, GROUP_DISRUPTION, GROUP_SECURITY, GROUP_ADMINISTRATION}
)

END_OPEN: Final = "open"
END_CLOSED: Final = "closed"
END_UNKNOWN: Final = "unknown"
END_STATES: Final = (END_OPEN, END_CLOSED, END_UNKNOWN)
_END_CODE: Final = {END_OPEN: "o", END_CLOSED: "c", END_UNKNOWN: "u"}
_END_OF_CODE: Final = {v: k for k, v in _END_CODE.items()}
_SEV_CODE: Final = {"info": "i", "warning": "w", "critical": "c"}
_SEV_OF_CODE: Final = {v: k for k, v in _SEV_CODE.items()}

CODE_MAX: Final = 64
_CODE = re.compile(r"[a-z0-9_]{1,40}(?:\.[a-z0-9_]{1,40}){0,3}")
_PARAM_KEY = re.compile(r"[a-z][a-z0-9_]{0,23}")
_CLIENT = re.compile(r"[0-9a-f]{16}")
_ROUTER_ID = re.compile(r"rtr_[0-9a-f]{32}")
_REF_TYPE = re.compile(r"[a-z]{1,16}")
_REF_ID = re.compile(r"[A-Za-z0-9_.:-]{1,80}")
_INT = re.compile(r"-?[0-9]{1,16}")
_NUM = re.compile(r"-?[0-9]{1,16}(?:\.[0-9]{1,6})?")


def quota_of(kind: str) -> str:
    """The quota a kind counts against (never another quota's room)."""
    group = KIND_GROUP[kind]
    if group == GROUP_CLIENTS:
        return QUOTA_CLIENTS
    if group in _REF_QUOTA_GROUPS:
        return QUOTA_REFS
    return QUOTA_INFRA


def source_of(kind: str) -> str:
    """The timeline source a stored mark is shown under."""
    if kind in CLIENT_KINDS:
        return SOURCE_TM_CLIENTS
    if kind in REF_KINDS:
        return SOURCE_TM_REFS
    return SOURCE_TM_INDEX


def to_ms(value: float) -> int:
    """Epoch seconds -> integer milliseconds, rounded down (the mark grid)."""
    return math.floor(value * 1000)


def code_of(value: Any) -> str | None:
    """A fixed code (lower-case dotted token, at most 64 characters) or None."""
    if isinstance(value, str) and len(value) <= CODE_MAX and _CODE.fullmatch(value):
        return value
    return None


def clean_params(params: Mapping[str, Any] | None) -> dict[str, int | float]:
    """Finite numbers under valid keys only, at most PARAMS_MAX (bools as 0/1)."""
    out: dict[str, int | float] = {}
    for key, value in (params or {}).items():
        if len(out) >= PARAMS_MAX:
            break
        if not isinstance(key, str) or not _PARAM_KEY.fullmatch(key):
            continue
        if isinstance(value, bool):
            out[key] = int(value)
        elif isinstance(value, int):
            out[key] = value
        elif isinstance(value, float) and math.isfinite(value):
            out[key] = round(value, 3)
    return out


@dataclass(slots=True)
class Mark:
    """One mark of the own index (see the module doc)."""

    seq: int
    ts: float
    kind: str
    router: str | None
    severity: str
    code: str | None
    end: float | None = None
    end_state: str | None = None
    client: str | None = None
    params: dict[str, int | float] = field(default_factory=dict)
    ref: tuple[str, str] | None = None
    peers: tuple[str | None, str | None] | None = None
    derived: bool = False

    @property
    def source(self) -> str:
        """Timeline source of the mark."""
        return source_of(self.kind)

    @property
    def quota(self) -> str:
        """Quota of the mark."""
        return quota_of(self.kind)

    @property
    def is_open(self) -> bool:
        """An interval whose end has not been seen yet."""
        return self.end_state == END_OPEN

    @property
    def last_ts(self) -> float:
        """The later of start and end (for the retention)."""
        return max(self.ts, self.end) if self.end is not None else self.ts


# --- packed form ------------------------------------------------------------------------


def _num(value: float) -> str:
    if isinstance(value, int):
        return str(value)
    text = f"{value:.3f}".rstrip("0").rstrip(".")
    return text if text not in ("", "-0") else "0"


def pack(mark: Mark, router_ix: Mapping[str, int]) -> str:
    """One store row of ``mark`` (routers as indexes of ``router_ix``)."""

    def rix(router: str | None) -> str:
        return "" if router is None else str(router_ix[router])

    params = ";".join(f"{k}={_num(v)}" for k, v in mark.params.items())
    ref = f"{mark.ref[0]}/{mark.ref[1]}" if mark.ref is not None else ""
    peers = f"{rix(mark.peers[0])},{rix(mark.peers[1])}" if mark.peers else ""
    return "|".join(
        (
            str(mark.seq),
            str(to_ms(mark.ts)),
            mark.kind,
            rix(mark.router),
            _SEV_CODE[mark.severity],
            mark.code or "",
            "" if mark.end is None else str(to_ms(mark.end)),
            _END_CODE[mark.end_state] if mark.end_state else "",
            mark.client or "",
            params,
            ref,
            peers,
            "1" if mark.derived else "",
        )
    )


class BadRow(ValueError):
    """A store row that does not parse (skipped and counted)."""


def _router(raw: str, routers: list[str]) -> str | None:
    if raw == "":
        return None
    if not _INT.fullmatch(raw) or not 0 <= int(raw) < len(routers):
        raise BadRow("router")
    return routers[int(raw)]


def unpack(row: Any, routers: list[str]) -> Mark:
    """A mark of a store row; BadRow for anything unexpected."""
    if not isinstance(row, str) or len(row) > 600:
        raise BadRow("row")
    parts = row.split("|")
    if len(parts) != 13:
        raise BadRow("fields")
    seq, ts, kind, rix, sev, code, end, es, client, params, ref, peers, derived = parts
    if not _INT.fullmatch(seq) or int(seq) < 0 or not _INT.fullmatch(ts):
        raise BadRow("seq/ts")
    if kind not in KIND_GROUP or sev not in _SEV_OF_CODE:
        raise BadRow("kind/severity")
    if code and code_of(code) is None:
        raise BadRow("code")
    if end and not _INT.fullmatch(end):
        raise BadRow("end")
    if es and es not in _END_OF_CODE:
        raise BadRow("end_state")
    if client and not _CLIENT.fullmatch(client):
        raise BadRow("client")
    if (kind in CLIENT_KINDS) != bool(client):
        raise BadRow("client kind")
    values: dict[str, int | float] = {}
    for item in params.split(";") if params else ():
        key, _, raw = item.partition("=")
        if not _PARAM_KEY.fullmatch(key) or not _NUM.fullmatch(raw):
            raise BadRow("params")
        values[key] = float(raw) if "." in raw else int(raw)
    if len(values) > PARAMS_MAX:
        raise BadRow("params")
    ref_pair: tuple[str, str] | None = None
    if ref:
        ref_type, _, ref_id = ref.partition("/")
        if not _REF_TYPE.fullmatch(ref_type) or not _REF_ID.fullmatch(ref_id):
            raise BadRow("ref")
        ref_pair = (ref_type, ref_id)
    peer_pair: tuple[str | None, str | None] | None = None
    if peers:
        before, sep, after = peers.partition(",")
        if not sep:
            raise BadRow("peers")
        peer_pair = (_router(before, routers), _router(after, routers))
    if derived not in ("", "1"):
        raise BadRow("derived")
    end_value = int(end) / 1000 if end else None
    end_state = _END_OF_CODE[es] if es else None
    if (end_state is None) != (kind not in INTERVAL_KINDS):
        raise BadRow("interval")
    return Mark(
        seq=int(seq),
        ts=int(ts) / 1000,
        kind=kind,
        router=_router(rix, routers),
        severity=_SEV_OF_CODE[sev],
        code=code or None,
        end=end_value,
        end_state=end_state,
        client=client or None,
        params=values,
        ref=ref_pair,
        peers=peer_pair,
        derived=derived == "1",
    )


def valid_router_id(value: Any) -> bool:
    """A contract router id ``rtr_<32 hex>``."""
    return isinstance(value, str) and bool(_ROUTER_ID.fullmatch(value))


def valid_client(value: Any) -> bool:
    """16 hex of a ``tmc_`` pseudonym."""
    return isinstance(value, str) and bool(_CLIENT.fullmatch(value))


def valid_ref_id(value: Any) -> bool:
    """An id the store may keep as a reference."""
    return isinstance(value, str) and bool(_REF_ID.fullmatch(value))


# --- the index --------------------------------------------------------------------------

COUNTER_NAMES: Final = (
    "added",
    "evicted_infrastructure",
    "evicted_references",
    "evicted_clients",
    "evicted_open",
    "pruned",
    "client_day_capped",
    "bad_marks",
    "forgotten",
    "cleared",
    "router_removed",
)


class MarkIndex:
    """All marks of the own index in memory, bounded (see the module doc).

    Never raises on its own data; every entry point takes the time as an
    argument (no clock read).
    """

    def __init__(
        self,
        *,
        quotas: Mapping[str, int] = QUOTAS,
        retention_s: float = RETENTION_S,
        client_day_cap: int = CLIENT_DAY_CAP,
    ) -> None:
        """An empty index."""
        self.quotas = dict(quotas)
        self.retention_s = retention_s
        self.client_day_cap = client_day_cap
        self.marks: dict[int, Mark] = {}
        self.next_seq = 1
        # Eviction order (review S2, 1.51.0): the heaps hold the closed marks
        # (and point marks) only; open intervals wait in ``_open`` and join
        # their heap when they are closed. An open interval is evicted only
        # when its quota holds nothing else.
        self._heaps: dict[str, list[tuple[float, int]]] = {q: [] for q in QUOTAS}
        self._open: dict[str, set[int]] = {q: set() for q in QUOTAS}
        self._count: dict[str, int] = dict.fromkeys(QUOTAS, 0)
        # client marks created per (client, UTC day) and the flapping mark
        self._day: dict[tuple[str, int], int] = {}
        self._flap: dict[tuple[str, int], int] = {}
        self._refs: dict[tuple[str, str], int] = {}
        self.counters: dict[str, int] = dict.fromkeys(COUNTER_NAMES, 0)
        # 1.52.0: per quota, up to when marks are gone (see the module doc)
        self.lost: dict[str, float] = {}
        self._newest = -math.inf  # the latest start or end of any mark
        self.changed = False
        # marks changed since the store last packed them (its row cache)
        self.touched: set[int] = set()

    def __len__(self) -> int:
        """Number of marks."""
        return len(self.marks)

    def __iter__(self) -> Iterator[Mark]:
        """All marks (insertion order)."""
        return iter(list(self.marks.values()))

    def count(self, quota: str) -> int:
        """Marks of one quota."""
        return self._count.get(quota, 0)

    def get(self, seq: int | None) -> Mark | None:
        """The mark with ``seq`` (None if gone)."""
        return None if seq is None else self.marks.get(seq)

    def by_ref(self, ref_type: str, ref_id: str) -> Mark | None:
        """The reference mark of one source record (None if unknown)."""
        return self.get(self._refs.get((ref_type, ref_id)))

    # -- insert ----------------------------------------------------------------------

    def _insert(self, mark: Mark) -> None:
        quota = mark.quota
        self._newest = max(self._newest, mark.last_ts)
        self.marks[mark.seq] = mark
        if mark.is_open:
            self._open[quota].add(mark.seq)
        else:
            heapq.heappush(self._heaps[quota], (mark.ts, mark.seq))
        self._count[quota] += 1
        if mark.ref is not None:
            self._refs[mark.ref] = mark.seq
        self.next_seq = max(self.next_seq, mark.seq + 1)

    def note_lost(self, marks: Iterable[Mark], now: float | None = None) -> None:
        """Marks gone before their retention: raise ``lost`` of their quota
        to their end (an open one: ``now``, else the newest known time)."""
        for mark in marks:
            if mark.is_open:
                upto = max(mark.ts, self._newest, now if now is not None else mark.ts)
            else:
                upto = mark.last_ts
            quota = mark.quota
            if upto > self.lost.get(quota, -math.inf):
                self.lost[quota] = upto
                self.changed = True

    def restore_lost(self, raw: Any) -> None:
        """``lost`` as stored (known quotas, finite numbers only)."""
        if not isinstance(raw, Mapping):
            return
        for quota, value in raw.items():
            if (
                quota in QUOTAS
                and isinstance(value, int | float)
                and not isinstance(value, bool)
                and math.isfinite(value)
            ):
                self.lost[quota] = max(self.lost.get(quota, -math.inf), float(value))

    def restore(self, marks: Iterable[Mark]) -> None:
        """Marks read from the store (no counting, quotas enforced)."""
        for mark in sorted(marks, key=lambda m: (m.ts, m.seq)):
            if mark.seq in self.marks:
                self.counters["bad_marks"] += 1
                continue
            self._make_room(mark.quota)
            self._insert(mark)
            if mark.client is not None and mark.kind != "client_flapping":
                key = (mark.client, int(mark.ts // DAY_S))
                self._day[key] = self._day.get(key, 0) + 1
            elif mark.client is not None:
                self._flap[(mark.client, int(mark.ts // DAY_S))] = mark.seq

    def _make_room(self, quota: str) -> None:
        """Evict the oldest marks of ``quota`` until one more fits: closed
        marks first, an open interval only when nothing else is left (its
        owner sees it gone and books the end without it)."""
        heap = self._heaps[quota]
        opened = self._open[quota]
        while self._count[quota] >= self.quotas[quota]:
            if heap:
                _ts, seq = heapq.heappop(heap)
                mark = self.marks.get(seq)
                if mark is None or mark.quota != quota or mark.is_open:
                    continue  # stale heap entry
            elif opened:
                seq = min(opened, key=lambda s: (self.marks[s].ts, s))
                self.counters["evicted_open"] += 1
            else:
                return
            gone = self._delete(seq)
            if gone is not None:
                self.note_lost((gone,))
            self.counters[f"evicted_{quota}"] += 1

    def add(
        self,
        *,
        ts: float,
        kind: str,
        router: str | None,
        severity: str = "info",
        code: str | None = None,
        end: float | None = None,
        end_state: str | None = None,
        client: str | None = None,
        params: Mapping[str, Any] | None = None,
        ref: tuple[str, str] | None = None,
        peers: tuple[str | None, str | None] | None = None,
        derived: bool = False,
    ) -> Mark | None:
        """Add one mark; None when it is refused (bad data, client day cap).

        Over the daily cap of a client the mark is not added: the client's
        ``client_flapping`` mark of that day counts it instead.
        """
        if (
            kind not in KIND_GROUP
            or severity not in SEVERITIES
            or not isinstance(ts, int | float)
            or isinstance(ts, bool)
            or not math.isfinite(ts)
            or (router is not None and not valid_router_id(router))
            or (client is not None and not valid_client(client))
            or ((kind in CLIENT_KINDS) != (client is not None))
            or ((kind in INTERVAL_KINDS) != (end_state is not None))
            or (end_state is not None and end_state not in END_STATES)
            or (ref is not None and not valid_ref_id(ref[1]))
        ):
            self.counters["bad_marks"] += 1
            return None
        if peers is not None and any(
            p is not None and not valid_router_id(p) for p in peers
        ):
            peers = None
        start = to_ms(ts) / 1000
        if end is not None:
            end = max(start, to_ms(end) / 1000)  # never before its start
        if client is not None and kind != "client_flapping":
            day = int(start // DAY_S)
            used = self._day.get((client, day), 0)
            if used >= self.client_day_cap:
                self._flapping(client, day, start)
                return None
            self._day[(client, day)] = used + 1
        if ref is not None and ref in self._refs:
            return self.marks.get(self._refs[ref])
        quota = quota_of(kind)
        self._make_room(quota)
        mark = Mark(
            seq=self.next_seq,
            ts=start,
            kind=kind,
            router=router,
            severity=severity,
            code=code_of(code),
            end=end,
            end_state=end_state,
            client=client,
            params=clean_params(params),
            ref=ref,
            peers=peers,
            derived=derived,
        )
        self._insert(mark)
        self.counters["added"] += 1
        self.changed = True
        return mark

    def _flapping(self, client: str, day: int, ts: float) -> None:
        self.counters["client_day_capped"] += 1
        flap = self.get(self._flap.get((client, day)))
        if flap is not None:
            flap.params["suppressed"] = int(flap.params.get("suppressed", 0)) + 1
            flap.end = max(flap.end or flap.ts, ts)
            self.touched.add(flap.seq)
            self.changed = True
            return
        mark = self.add(
            ts=ts,
            kind="client_flapping",
            router=None,
            severity="warning",
            code="flapping",
            end=ts,
            end_state=END_CLOSED,
            client=client,
            params={"suppressed": 1, "cap": self.client_day_cap},
        )
        if mark is not None:
            self._flap[(client, day)] = mark.seq

    # -- update ----------------------------------------------------------------------

    def close(self, seq: int | None, end: float, state: str = END_CLOSED) -> bool:
        """Close an open interval (end never before its start)."""
        mark = self.get(seq)
        if mark is None or not mark.is_open:
            return False
        mark.end = max(mark.ts, to_ms(end) / 1000)
        mark.end_state = state
        self._newest = max(self._newest, mark.end)
        quota = mark.quota
        self._open[quota].discard(mark.seq)
        heapq.heappush(self._heaps[quota], (mark.ts, mark.seq))
        self.touched.add(mark.seq)
        self.changed = True
        return True

    def bump(self, seq: int | None, key: str, by: int = 1) -> None:
        """Add ``by`` to one numeric param of a mark."""
        mark = self.get(seq)
        if mark is None or not _PARAM_KEY.fullmatch(key):
            return
        if key not in mark.params and len(mark.params) >= PARAMS_MAX:
            return
        mark.params[key] = int(mark.params.get(key, 0)) + by
        self.touched.add(mark.seq)
        self.changed = True

    def open_marks(self) -> list[Mark]:
        """Every open interval."""
        return [m for m in self.marks.values() if m.is_open]

    # -- delete ----------------------------------------------------------------------

    def _delete(self, seq: int) -> Mark | None:
        mark = self.marks.pop(seq, None)
        if mark is None:
            return None
        self._count[mark.quota] -= 1
        self._open[mark.quota].discard(seq)
        if mark.ref is not None and self._refs.get(mark.ref) == seq:
            del self._refs[mark.ref]
        self.changed = True
        return mark

    def _compact(self, quota: str) -> None:
        """Rebuild a heap after many deletions (stale entries)."""
        heap = self._heaps[quota]
        if len(heap) > 2 * self._count[quota] + 64:
            self._heaps[quota] = [
                (m.ts, m.seq)
                for m in self.marks.values()
                if m.quota == quota and not m.is_open
            ]
            heapq.heapify(self._heaps[quota])

    def remove_where(self, keep_if: Any) -> int:
        """Delete every mark for which ``keep_if(mark)`` is False."""
        doomed = [seq for seq, m in self.marks.items() if not keep_if(m)]
        for seq in doomed:
            self._delete(seq)
        for quota in QUOTAS:
            self._compact(quota)
        return len(doomed)

    def prune(self, now: float) -> int:
        """Drop closed marks that ended before the retention (open ones stay)."""
        cutoff = now - self.retention_s
        dropped = self.remove_where(lambda m: m.is_open or m.last_ts >= cutoff)
        oldest_day = int(cutoff // DAY_S) - 1
        for table in (self._day, self._flap):
            for key in [k for k in table if k[1] < oldest_day]:
                del table[key]
        self.counters["pruned"] += dropped
        return dropped

    def forget_client(self, client: str) -> int:
        """Delete every mark of one client pseudonym."""
        dropped = self.remove_where(lambda m: m.client != client)
        for table in (self._day, self._flap):
            for key in [k for k in table if k[0] == client]:
                del table[key]
        self.counters["forgotten"] += dropped
        return dropped

    def forget_router(self, router: str, now: float | None = None) -> int:
        """Delete every mark of a removed router (also as a roam peer).

        Marks of other routers that name it as a peer (an uplink change, a
        roam) go too: their quota counts as ``lost`` up to them (1.52.0).
        """
        doomed = [
            m
            for m in self.marks.values()
            if m.router == router or router in (m.peers or ())
        ]
        self.note_lost((m for m in doomed if m.router != router), now)
        seqs = {m.seq for m in doomed}
        dropped = self.remove_where(lambda m: m.seq not in seqs)
        self.counters["router_removed"] += dropped
        return dropped

    def clear(self, *, clients_only: bool, now: float | None = None) -> int:
        """Delete all client marks, or all marks (``lost`` up to ``now``)."""
        doomed = [
            m for m in self.marks.values() if not clients_only or m.client is not None
        ]
        self.note_lost(doomed, now)
        if now is not None and doomed:
            for quota in {m.quota for m in doomed}:
                self.lost[quota] = max(self.lost.get(quota, -math.inf), now)
        if clients_only:
            dropped = self.remove_where(lambda m: m.client is None)
        else:
            dropped = self.remove_where(lambda _m: False)
        self._day.clear()
        self._flap.clear()
        self.counters["cleared"] += dropped
        return dropped

    # -- read ------------------------------------------------------------------------

    def window(self, source: str, since: float, until: float) -> list[Mark]:
        """Marks of ``source`` with ``since <= ts < until`` (unsorted)."""
        return [
            m
            for m in self.marks.values()
            if since <= m.ts < until and m.source == source
        ]

    def spanning_in(self, source: str, since: float) -> list[Mark]:
        """Intervals of ``source`` that began before ``since`` and reach
        into the window: open, or ended at or after ``since`` (unsorted).

        The same for every page of one window (it does not depend on
        ``until``), so ``tm_query.merge`` can put them on exactly one page.
        """
        return [
            m
            for m in self.marks.values()
            if m.source == source
            and m.ts < since
            and m.end_state is not None
            and (m.is_open or (m.end is not None and m.end >= since))
        ]

    def sessions(
        self,
        since: float,
        until: float,
        *,
        client: str | None = None,
        router: str | None = None,
    ) -> list[Mark]:
        """``client_session`` marks that overlap ``[since, until)``.

        A session overlaps when it started before ``until`` and is open or
        ended at or after ``since``.
        """
        return [
            m
            for m in self.marks.values()
            if m.kind == "client_session"
            and m.ts < until
            and (m.is_open or (m.end is not None and m.end >= since))
            and (client is None or m.client == client)
            and (router is None or m.router == router)
        ]

    def stats(self) -> dict[str, Any]:
        """Counts per quota and the counters (no ids)."""
        return {
            "marks": len(self.marks),
            "by_quota": {q: self._count[q] for q in QUOTAS},
            "quotas": dict(self.quotas),
            "open": sum(1 for m in self.marks.values() if m.is_open),
            "clients": len({m.client for m in self.marks.values() if m.client}),
            **self.counters,
        }


__all__ = [
    "CLIENT_DAY_CAP",
    "CLIENT_KINDS",
    "END_CLOSED",
    "END_OPEN",
    "END_STATES",
    "END_UNKNOWN",
    "INTERVAL_KINDS",
    "MAX_MARKS",
    "QUOTAS",
    "QUOTA_CLIENTS",
    "QUOTA_INFRA",
    "QUOTA_REFS",
    "REF_KINDS",
    "RETENTION_S",
    "SOURCE_TM_CLIENTS",
    "SOURCE_TM_INDEX",
    "SOURCE_TM_REFS",
    "BadRow",
    "Mark",
    "MarkIndex",
    "clean_params",
    "code_of",
    "pack",
    "quota_of",
    "source_of",
    "to_ms",
    "unpack",
]
