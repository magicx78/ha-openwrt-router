"""Network Time Machine, Phase D (1.52.0): state at a moment, comparison.

Plan ``docs/plans/2026-11-21-network-time-machine.md`` §5.4, §8 (views 2
and 3), §9 D. Read only: no router call, no listener, no task, no store
write; everything comes from the own index (``tm_marks``), its followed
stretches (``tm_store.Segment``) and the read functions of the modules
(Network Intelligence incidents, Configuration Manager versions, Traffic
``window_at``, WiFi RF ``window_at``).

**Reconstruction.** Per router the engine stores stretches in which it
followed the polls (``seen``), each with the radios of its first poll with
radios and the first settled (two polls) uplink and role. The state at T is
that base plus every mark of the stretch up to T (channel changes, radios
off and on, uplink and role changes), and the intervals that cover T
(outages, observation gaps). Nothing is interpolated:

* **derived** (``derived: true``): every reconstructed value. "Reachable" is
  always derived (no outage was seen, the router was followed); "not
  reachable" carries the flag of the outage mark (derived when its start
  lies before the index ran, or for a LAN outage seen from HA's side).
* **unknown** (value None with ``reason``): before the retention
  (``beyond_retention``), outside the index's runs (``not_recorded``), in a
  restart gap (``ha_gap``) or an observation gap (``observation_gap``), up
  to a lost mark (``evicted``: a mark of the quota was evicted, trimmed or
  deleted before its retention), while the router was not followed or
  before its first radio / settled topology read (``not_observed``), while
  it was down (radios and topology ``router_down`` / ``lan_down``), when a
  mark cannot be matched to one radio of a band (``ambiguous_radio``) or
  does not fit the state it changes (``inconsistent``), and for uplink and
  role within ``TOPOLOGY_SETTLE_S`` before a change was settled, and before
  the end of a stretch whose next stretch does not go on seamlessly
  (``settling``: the change may have begun up to two polls earlier).

The time resolution is the poll: a value holds from the poll that saw it
(a radio's "off" from the first poll that missed it) until the next mark.
A failed poll shorter than ``tm_engine.GAP_MIN_S`` leaves no gap (engine
rule), so the router counts as reachable there.

**Rights** (plan §6): the router table, intervals (``NON_ADMIN_GROUPS``),
Network Intelligence incidents (not of client scope) and the hour values
of Traffic (WAN points) and WiFi RF (per band, never a radio or netdev
name) are for every user who may open the tab. The configuration versions
are for administrators; clients (sessions covering T, counts per access
point) for administrators while the client switch is on. A non-admin who
sends a client key gets 400 ``admin_only`` before its value is looked at.

See ``docs/time-machine.md`` §20-§23 for the exact format.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from homeassistant.core import HomeAssistant

from .tm_engine import _band_num
from .tm_marks import QUOTA_CLIENTS, QUOTA_INFRA, RETENTION_S, Mark
from .tm_query import (
    API_VERSION,
    DEFAULT_LIMIT,
    MAX_LIMIT,
    MAX_WINDOW_S,
    STATUS_OFF,
    STATUS_OK,
    STATUS_PARTIAL,
    STATUS_UNAVAILABLE,
    QueryError,
    _allowed,
    _cursor,
    _newest_first,
    _time,
    cursor_of,
    time_machine_enabled,
)
from .tm_sources import (
    KIND_GROUP,
    NON_ADMIN_GROUPS,
    REASON_ADMIN_ONLY,
    REASON_CLIENTS_OFF,
    REASON_MODULE_OFF,
    REASON_NOT_LOADED,
    REASON_NOT_RUNNING,
    RouterMap,
    build_router_map,
    index_mark,
    jump_target,
    ms_floor,
    ref_of,
    stored_mark_id,
    token,
)

_LOGGER = logging.getLogger(__name__)

STATE_QUERY_KEYS: Final = frozenset(
    {"at", "router_id", "clients_limit", "clients_cursor"}
)
COMPARE_QUERY_KEYS: Final = frozenset({"t1", "t2", "router_id"})
_CLIENT_KEYS: Final = frozenset({"clients_limit", "clients_cursor"})

# Hard limits of one answer.
ROUTERS_MAX: Final = 64
INTERVALS_MAX: Final = 100
INCIDENTS_MAX: Final = 100
VERSIONS_MAX: Final = 100
# How long before a settled uplink / role change the old value is not
# certain any more: two polls of the slowest interval (300 s, SSH fallback)
# plus one of margin. The engine accepts a change after two equal polls.
TOPOLOGY_SETTLE_S: Final = 900.0
HOUR_S: Final = 3600
# Marks turned over between two yields to the event loop.
YIELD_EVERY: Final = 2000

# Reasons of an unknown value (fixed codes).
R_BEYOND_RETENTION: Final = "beyond_retention"
R_NOT_RECORDED: Final = "not_recorded"
R_HA_GAP: Final = "ha_gap"
R_OBSERVATION_GAP: Final = "observation_gap"
R_EVICTED: Final = "evicted"
R_NOT_OBSERVED: Final = "not_observed"
R_ROUTER_DOWN: Final = "router_down"
R_LAN_DOWN: Final = "lan_down"
R_AMBIGUOUS: Final = "ambiguous_radio"
R_INCONSISTENT: Final = "inconsistent"
R_SETTLING: Final = "settling"
R_FLAPPING: Final = "flapping"
R_REOPENED: Final = "reopened_since"
R_PRUNED: Final = "source_pruned"
R_CUT: Final = "cut"
R_UNREADABLE: Final = "unreadable"
UNKNOWN_REASONS: Final = (
    R_BEYOND_RETENTION,
    R_NOT_RECORDED,
    R_HA_GAP,
    R_OBSERVATION_GAP,
    R_EVICTED,
    R_NOT_OBSERVED,
    R_ROUTER_DOWN,
    R_LAN_DOWN,
    R_AMBIGUOUS,
    R_INCONSISTENT,
    R_SETTLING,
)
_GLOBAL: Final = frozenset(
    {R_BEYOND_RETENTION, R_NOT_RECORDED, R_HA_GAP, R_OBSERVATION_GAP, R_EVICTED}
)

PART_OK: Final = "ok"
PART_PARTIAL: Final = "partial"
PART_UNKNOWN: Final = "unknown"
PART_OFF: Final = "off"
PART_UNREADABLE: Final = "unreadable"

_ROUTER_ID = re.compile(r"rtr_[0-9a-f]{32}")
_INT = re.compile(r"[0-9]{1,4}")
_INTERVAL_KINDS: Final = (
    "router_down",
    "lan_down",
    "observation_gap",
    "ha_gap",
    "radio_down",
)
_RADIO_KINDS: Final = frozenset({"channel_changed", "radio_down", "radio_up"})
_TOPO_KINDS: Final = frozenset({"uplink_changed", "router_role_changed"})


# --- query ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StateQuery:
    """A checked state query (``at`` on the millisecond grid)."""

    at: float
    router_id: str | None = None
    clients_limit: int = DEFAULT_LIMIT
    clients_cursor: tuple[int, str | None] | None = None


@dataclass(frozen=True, slots=True)
class CompareQuery:
    """A checked comparison of two moments (``t1 < t2``)."""

    t1: float
    t2: float
    router_id: str | None = None


def _known_keys(query: Mapping[str, str], keys: frozenset[str]) -> None:
    for key in query:
        if key not in keys:
            raise QueryError("query", "unknown_key")


def _router(query: Mapping[str, str]) -> str | None:
    router_id = query.get("router_id")
    if router_id is not None and not _ROUTER_ID.fullmatch(router_id):
        raise QueryError("router_id")
    return router_id


def _moment(query: Mapping[str, str], name: str, now: float) -> float | None:
    value = _time(query, name)
    if value is None:
        return None
    value = ms_floor(value)
    if value > now:
        raise QueryError(name, "out_of_range")
    return value


def parse_state_query(
    query: Mapping[str, str], now: float, *, admin: bool
) -> StateQuery:
    """Check every key and value (QueryError with field and fixed reason).

    A client key from a non-admin is refused before its value is read.
    """
    _known_keys(query, STATE_QUERY_KEYS)
    if not admin:
        for key in sorted(_CLIENT_KEYS):
            if key in query:
                raise QueryError(key, "admin_only")
    at = _moment(query, "at", now)
    if at is None:
        at = ms_floor(now)
    limit = DEFAULT_LIMIT
    raw = query.get("clients_limit")
    if raw is not None:
        if not _INT.fullmatch(raw) or not 1 <= int(raw) <= MAX_LIMIT:
            raise QueryError("clients_limit", "out_of_range")
        limit = int(raw)
    try:
        cursor = _cursor(query.get("clients_cursor"))
    except QueryError:
        raise QueryError("clients_cursor") from None
    if cursor is not None and cursor[0] > at * 1000:
        raise QueryError("clients_cursor", "out_of_range")
    return StateQuery(at, _router(query), limit, cursor)


def parse_compare_query(query: Mapping[str, str], now: float) -> CompareQuery:
    """``t1`` and ``t2`` (both needed, ``t1 < t2``, at most 14 days apart)."""
    _known_keys(query, COMPARE_QUERY_KEYS)
    t1 = _moment(query, "t1", now)
    t2 = _moment(query, "t2", now)
    if t1 is None:
        raise QueryError("t1", "missing")
    if t2 is None:
        raise QueryError("t2", "missing")
    if t1 >= t2:
        raise QueryError("window", "empty")
    if t2 - t1 > MAX_WINDOW_S:
        raise QueryError("window", "too_large")
    return CompareQuery(t1, t2, _router(query))


# --- reconstruction ------------------------------------------------------------------


def _covers(mark: Mark, at: float) -> bool:
    """An interval holds ``at``: started at or before it, open or ending
    after it (an interval ends at its end, exclusive)."""
    if mark.ts > at:
        return False
    return mark.is_open or (mark.end is not None and at < mark.end)


def _band_name(key: str) -> str:
    return key.rstrip("0123456789")


def _value(value: Any, *, derived: bool) -> dict[str, Any]:
    return {"value": value, "derived": derived, "reason": None}


def _unknown(reason: str) -> dict[str, Any]:
    return {"value": None, "derived": False, "reason": reason}


class Snapshot:
    """The own index taken apart once per request (see the module doc).

    Pure: built from marks and stored meta data, no Home Assistant call, so
    the reconstruction is tested through the engine's real write path.
    """

    def __init__(
        self,
        marks: Iterable[Mark],
        *,
        coverage: Iterable[Iterable[float | None]],
        seen: Mapping[str, list[Any]],
        lost: Mapping[str, float],
        clients_cov: Iterable[Iterable[float | None]] = (),
        now: float,
    ) -> None:
        """Sort the marks by role (one pass)."""
        self.now = now
        self.coverage = [
            (float(a), math.inf if b is None else float(b))
            for a, b in (tuple(p) for p in coverage)
            if a is not None
        ]
        self.clients_cov = [
            (float(a), math.inf if b is None else float(b))
            for a, b in (tuple(p) for p in clients_cov)
            if a is not None
        ]
        self.seen = {rid: list(segs) for rid, segs in seen.items()}
        self.lost = dict(lost)
        self.down: dict[str, list[Mark]] = {}
        self.gaps: dict[str, list[Mark]] = {}
        self.radio: dict[str, list[Mark]] = {}
        self.topo: dict[str, list[Mark]] = {}
        self.lan: list[Mark] = []
        self.ha_gaps: list[Mark] = []
        self.fleet_gaps: list[Mark] = []
        self.flapping: list[Mark] = []
        self.sessions: list[Mark] = []
        self.client_marks: list[Mark] = []
        self.intervals: list[Mark] = []
        self.own: list[Mark] = []
        self.routers: set[str] = set(self.seen)
        for mark in marks:
            self._take(mark)
        for table in (self.radio, self.topo):
            for items in table.values():
                items.sort(key=lambda m: (m.ts, m.seq))

    def _take(self, mark: Mark) -> None:
        kind, rid = mark.kind, mark.router
        if mark.client is not None:
            self.client_marks.append(mark)
            if kind == "client_session":
                self.sessions.append(mark)
            elif kind == "client_flapping":
                self.flapping.append(mark)
            return
        self.own.append(mark)
        if kind in _INTERVAL_KINDS:
            self.intervals.append(mark)
        if rid is not None:
            self.routers.add(rid)
        if kind == "router_down" and rid is not None:
            self.down.setdefault(rid, []).append(mark)
        elif kind == "observation_gap":
            if rid is None:
                self.fleet_gaps.append(mark)
            else:
                self.gaps.setdefault(rid, []).append(mark)
        elif kind == "lan_down":
            self.lan.append(mark)
        elif kind == "ha_gap":
            self.ha_gaps.append(mark)
        elif kind in _RADIO_KINDS and rid is not None:
            self.radio.setdefault(rid, []).append(mark)
        elif kind in _TOPO_KINDS and rid is not None:
            self.topo.setdefault(rid, []).append(mark)

    # -- global ------------------------------------------------------------------------

    def global_reason(self, at: float) -> str | None:
        """Why nothing at ``at`` can be said (None: reconstructable)."""
        if at < self.now - RETENTION_S:
            return R_BEYOND_RETENTION
        if any(_covers(m, at) for m in self.ha_gaps):
            return R_HA_GAP
        if any(_covers(m, at) for m in self.fleet_gaps):
            return R_OBSERVATION_GAP
        if not any(a <= at < b for a, b in self.coverage):
            return R_NOT_RECORDED
        if at <= self.lost.get(QUOTA_INFRA, -math.inf):
            return R_EVICTED
        return None

    def segment(self, rid: str, at: float) -> Any:
        """The followed stretch holding ``at`` (None: not followed)."""
        for seg in self.seen.get(rid, ()):
            if seg.start <= at and (at < seg.end if seg.end is not None else True):
                return seg
        return None

    def _next_segment(self, rid: str, seg: Any) -> Any:
        segs = self.seen.get(rid, [])
        for i, item in enumerate(segs):
            if item is seg and i + 1 < len(segs):
                return segs[i + 1]
        return None

    # -- per router --------------------------------------------------------------------

    def reachable(self, rid: str, at: float) -> dict[str, Any]:
        """``value`` True / False / None (see the module doc)."""
        reason = self.global_reason(at)
        if reason is not None:
            return _unknown(reason)
        for mark in self.down.get(rid, ()):
            if _covers(mark, at):
                return _value(False, derived=mark.derived)
        if any(_covers(m, at) for m in self.lan):
            return {
                "value": False,
                "derived": True,
                "reason": None,
                "cause": R_LAN_DOWN,
            }
        if any(_covers(m, at) for m in self.gaps.get(rid, ())):
            return _unknown(R_OBSERVATION_GAP)
        if self.segment(rid, at) is None:
            return _unknown(R_NOT_OBSERVED)
        return _value(True, derived=True)

    def _blocked(self, reach: Mapping[str, Any]) -> str | None:
        if reach["value"] is False:
            return R_LAN_DOWN if reach.get("cause") == R_LAN_DOWN else R_ROUTER_DOWN
        if reach["value"] is None:
            return reach["reason"]
        return None

    def radios(
        self, rid: str, at: float, reach: Mapping[str, Any]
    ) -> tuple[dict[str, Any], int]:
        """The radios at ``at`` and the number of marks applied."""
        blocked = self._blocked(reach)
        if blocked is not None:
            return _radio_block(None, blocked), 0
        seg = self.segment(rid, at)
        if seg is None or seg.radios_at is None or at < seg.radios_at:
            return _radio_block(None, R_NOT_OBSERVED), 0
        if seg.radios_at < self.now - RETENTION_S:
            # marks after the base may be pruned already (engine: REBASE_S)
            return _radio_block(None, R_BEYOND_RETENTION), 0
        if seg.radios_at < self.lost.get(QUOTA_INFRA, -math.inf):
            # a mark after the base is gone (the engine rebases then)
            return _radio_block(None, R_EVICTED), 0
        walk = _RadioWalk(seg.radios)
        end = seg.end if seg.end is not None else math.inf
        absent = False
        events: list[tuple[float, int, Mark]] = []
        for mark in self.radio.get(rid, ()):
            if mark.ts > at:
                break
            if mark.kind == "radio_down" and mark.ts < seg.radios_at:
                # began before the base: the engine had dropped the radio
                # from its state already, so the base lacks it; while it is
                # off at ``at`` the list is not complete
                if _covers(mark, at):
                    absent = True
                continue
            # a radio_down may begin at the base poll itself (the radio was
            # still in the base), any other mark only after it
            low_ok = (
                mark.ts >= seg.radios_at
                if mark.kind == "radio_down"
                else (mark.ts > seg.radios_at)
            )
            if low_ok and mark.ts < end:
                events.append((mark.ts, mark.seq, mark))
        events.sort(key=lambda e: (e[0], e[1]))
        for _ts, _seq, mark in events:
            if not walk.apply(mark):
                return _radio_block(None, R_INCONSISTENT), len(events)
        return _radio_block(walk.items(at), None, absent=absent), len(events)

    def topology(
        self, rid: str, at: float, reach: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any], int]:
        """``(uplink, role, marks applied)`` at ``at``."""
        blocked = self._blocked(reach)
        if blocked is not None:
            return _unknown(blocked), _unknown(blocked), 0
        seg = self.segment(rid, at)
        if seg is None or seg.topo_at is None or at < seg.topo_at:
            return _unknown(R_NOT_OBSERVED), _unknown(R_NOT_OBSERVED), 0
        if seg.topo_at < self.now - RETENTION_S:
            gone = _unknown(R_BEYOND_RETENTION)
            return gone, gone, 0
        if seg.topo_at < self.lost.get(QUOTA_INFRA, -math.inf):
            gone = _unknown(R_EVICTED)
            return gone, gone, 0
        parent, role = seg.parent, seg.role
        end = seg.end if seg.end is not None else math.inf
        applied = 0
        for mark in self.topo.get(rid, ()):
            if mark.ts > at:
                break
            if not seg.topo_at < mark.ts < end:
                continue
            applied += 1
            if mark.kind == "uplink_changed":
                before, after = mark.peers or (None, None)
                if (before or "") != parent:
                    bad = _unknown(R_INCONSISTENT)
                    return bad, bad, applied
                parent = after or ""
            elif mark.code in ("gateway", "node"):
                role = "g" if mark.code == "gateway" else "n"
            else:
                bad = _unknown(R_INCONSISTENT)
                return bad, bad, applied
        if any(at < m.ts <= at + TOPOLOGY_SETTLE_S for m in self.topo.get(rid, ())):
            return _unknown(R_SETTLING), _unknown(R_SETTLING), applied
        if seg.end is not None and at > seg.end - TOPOLOGY_SETTLE_S:
            nxt = self._next_segment(rid, seg)
            seamless = (
                nxt is not None and nxt.start == seg.end and nxt.topo_at == nxt.start
            )
            if not seamless:
                return _unknown(R_SETTLING), _unknown(R_SETTLING), applied
        if role not in ("g", "n"):
            return _unknown(R_NOT_OBSERVED), _unknown(R_NOT_OBSERVED), applied
        uplink = _value(parent or None, derived=True)
        return (
            uplink,
            _value("gateway" if role == "g" else "node", derived=True),
            applied,
        )

    # -- clients -------------------------------------------------------------------------

    def clients_reason(self, at: float) -> tuple[str, str | None]:
        """``(state, reason)`` of the client list at ``at``."""
        reason = self.global_reason(at)
        if reason is not None:
            return PART_UNKNOWN, reason
        if at <= self.lost.get(QUOTA_CLIENTS, -math.inf):
            return PART_UNKNOWN, R_EVICTED
        if not any(a <= at < b for a, b in self.clients_cov):
            return PART_UNKNOWN, R_NOT_RECORDED
        day = int(at // 86_400)
        if any(int(m.ts // 86_400) == day and m.ts <= at for m in self.flapping):
            return PART_PARTIAL, R_FLAPPING
        return PART_OK, None

    def sessions_at(self, at: float) -> list[Mark]:
        """Client sessions covering ``at``."""
        return [m for m in self.sessions if _covers(m, at)]


class _RadioWalk:
    """Radios of one stretch, changed mark by mark (see ``Snapshot.radios``)."""

    def __init__(self, base: Mapping[str, tuple[int, int]]) -> None:
        # key -> channel, width (None: unknown), down mark, unknown reason
        self.keys: dict[str, list[Any]] = {
            key: [chan, width, None, None] for key, (chan, width) in base.items()
        }

    def _band(self, band: Any) -> list[str]:
        return [k for k in self.keys if _band_num(k) == band]

    def _spoil(self, keys: list[str]) -> None:
        for key in keys:
            self.keys[key][3] = R_AMBIGUOUS

    def apply(self, mark: Mark) -> bool:
        """One mark; False when it fits no radio at all (inconsistent)."""
        params = mark.params
        if mark.kind == "radio_up":
            # no band in the mark: the radio whose "off" mark the engine
            # closed at this very poll
            downs = [k for k, v in self.keys.items() if v[2] is not None]
            hits = [k for k in downs if self.keys[k][2].end == mark.ts]
            if len(hits) != 1:
                self._spoil(hits or list(self.keys))
                return True
            item = self.keys[hits[0]]
            if item[3] is None:
                item[0], item[1], item[2] = params.get("channel"), None, None
            return True
        band = self._band(params.get("band"))
        if not band:
            return False
        live = [k for k in band if self.keys[k][3] is None]
        if mark.kind == "channel_changed":
            hits = [
                k
                for k in live
                if self.keys[k][2] is None
                and self.keys[k][0] == params.get("channel_from")
                and self.keys[k][1] in (None, params.get("width_from"))
            ]
            if len(hits) != 1:
                self._spoil(band)
                return True
            item = self.keys[hits[0]]
            item[0], item[1] = params.get("channel_to"), params.get("width_to")
        elif mark.kind == "radio_down":
            hits = [
                k
                for k in live
                if self.keys[k][2] is None and self.keys[k][0] == params.get("channel")
            ]
            if len(hits) != 1:
                self._spoil(band)
                return True
            self.keys[hits[0]][2] = mark
        return True

    def items(self, at: float) -> list[dict[str, Any]]:
        out = []
        for key in sorted(self.keys):
            chan, width, down, reason = self.keys[key]
            state = "up"
            if reason is None and down is not None and not _covers(down, at):
                # its end lies before ``at`` but no "on" mark followed: an
                # end "unknown" (restart, unload) or a lost mark
                reason = (
                    R_NOT_OBSERVED if down.end_state == "unknown" else R_INCONSISTENT
                )
            if reason is not None:
                chan = width = None
                state = "unknown"
            elif down is not None:
                state = "down"
            out.append(
                {
                    "key": key,
                    "band": _band_name(key),
                    "channel": chan,
                    "width": width,
                    "state": state,
                    "reason": reason,
                }
            )
        return out


def _radio_block(
    items: list[dict[str, Any]] | None, reason: str | None, *, absent: bool = False
) -> dict[str, Any]:
    if items is None:
        return {"state": PART_UNKNOWN, "reason": reason, "derived": False, "items": []}
    partial = absent or any(i["state"] == "unknown" for i in items)
    return {
        "state": PART_PARTIAL if partial else PART_OK,
        "reason": R_NOT_OBSERVED if absent else None,
        "derived": True,
        "items": items,
    }


async def async_snapshot(engine: Any, now: float) -> Snapshot:
    """The engine's index taken apart (yields every ``YIELD_EVERY`` marks)."""
    marks = list(engine.index.marks.values())
    store = engine.store
    snap = Snapshot(
        (),
        coverage=store.coverage,
        seen=store.seen,
        lost=engine.index.lost,
        clients_cov=store.clients_cov,
        now=now,
    )
    for i, mark in enumerate(marks):
        if i and i % YIELD_EVERY == 0:
            await asyncio.sleep(0)
        snap._take(mark)
    for table in (snap.radio, snap.topo):
        for items in table.values():
            items.sort(key=lambda m: (m.ts, m.seq))
    return snap


# --- answers ---------------------------------------------------------------------------


def _peer(rid: str | None, routers: RouterMap) -> dict[str, Any] | None:
    if not rid:
        return None
    return {"router_id": rid, "router_name": routers.name_of(rid)}


def router_state(
    snap: Snapshot, rid: str, at: float, routers: RouterMap
) -> tuple[dict[str, Any], int]:
    """One router at ``at`` (no client data) and the marks applied."""
    reach = snap.reachable(rid, at)
    radios, n_radio = snap.radios(rid, at, reach)
    uplink, role, n_topo = snap.topology(rid, at, reach)
    reach = {k: v for k, v in reach.items() if k != "cause"}
    uplink = {**uplink, "value": _peer(uplink["value"], routers)}
    return (
        {
            "router_id": rid,
            "router_name": routers.name_of(rid),
            "reachable": reach,
            "role": role,
            "uplink": uplink,
            "radios": radios,
        },
        n_radio + n_topo,
    )


def _intervals(
    snap: Snapshot, at: float, routers: RouterMap, admin: bool, router_id: str | None
) -> tuple[list[dict[str, Any]], int]:
    found = [
        m
        for m in snap.intervals
        if _covers(m, at) and (router_id is None or m.router in (router_id, None))
    ]
    found.sort(key=lambda m: (-m.ts, m.seq))
    out = []
    for mark in found:
        item = index_mark(mark, routers)
        if _allowed(item, admin):
            out.append(item)
    return out[:INTERVALS_MAX], len(out)


def _incident_state(inc: Any, at: float) -> tuple[str | None, str | None]:
    """``("open" | "unknown" | None, reason)`` of an NI incident at ``at``."""
    first = getattr(inc, "first_seen", None)
    if not isinstance(first, int | float) or first > at:
        return None, None
    reopened = getattr(inc, "reopened_at", None)
    resolved = getattr(inc, "resolved_at", None)
    if isinstance(reopened, int | float):
        if at < reopened:
            # it was resolved some time before the reopen; when is lost
            return "unknown", R_REOPENED
        if isinstance(resolved, int | float) and reopened <= resolved <= at:
            return None, None
        return "open", None
    if isinstance(resolved, int | float) and resolved <= at:
        return None, None
    return "open", None


def _ni_incidents(
    hass: HomeAssistant, routers: RouterMap, router_id: str | None
) -> tuple[list[Any] | None, str | None, bool]:
    """``(incidents, unreadable reason, maybe pruned)`` of the running NI."""
    from .net_engine import async_get_engine
    from .net_events import MAX_INCIDENTS

    engine = async_get_engine(hass)
    if engine is None:
        return None, REASON_NOT_RUNNING, False
    if getattr(engine, "loaded", False) is not True:
        return None, REASON_NOT_LOADED, False
    try:
        incidents = list(engine.machine.peek())
    except Exception:  # noqa: BLE001 - a broken machine reads as unreadable
        return None, R_UNREADABLE, False
    droppable = sum(
        1
        for inc in incidents
        if str(getattr(getattr(inc, "status", None), "value", ""))
        in ("resolved", "ignored")
    )
    return incidents, None, droppable >= MAX_INCIDENTS - 1


def _incident_item(inc: Any, routers: RouterMap) -> dict[str, Any] | None:
    raw = list(getattr(inc, "routers", None) or [])
    scope = getattr(getattr(inc, "scope", None), "value", getattr(inc, "scope", None))
    if scope == "client":
        return None
    if scope == "fleet" or len(raw) > 1:
        rid, fleet = None, True
    elif raw:
        rid, fleet = routers.router_of_entry(raw[0]), False
    else:
        rid, fleet = None, False
    ref = ref_of("network_intelligence", "incident", getattr(inc, "id", None))
    severity = getattr(getattr(inc, "severity", None), "value", None)
    return {
        "id": ref["id"],
        "type": token(getattr(inc, "type", None)),
        "severity": severity if severity in ("info", "warning", "critical") else "info",
        "router_id": rid,
        "router_name": routers.name_of(rid),
        "fleet": fleet,
        "since": getattr(inc, "reopened_at", None) or getattr(inc, "first_seen", None),
        "ref": ref,
        "target": jump_target(ref),
    }


def incidents_at(
    incidents: list[Any] | None,
    reason: str | None,
    pruned: bool,
    at: float,
    routers: RouterMap,
    router_id: str | None,
) -> dict[str, Any]:
    """NI incidents open (or of unknown state) at ``at``."""
    if incidents is None:
        off = reason in (REASON_NOT_RUNNING, REASON_NOT_LOADED)
        return {
            "state": PART_OFF if off else PART_UNREADABLE,
            "reason": reason,
            "items": [],
            "total": 0,
            "truncated": False,
        }
    items = []
    for inc in incidents:
        state, why = _incident_state(inc, at)
        if state is None:
            continue
        item = _incident_item(inc, routers)
        if item is None or (
            router_id is not None and item["router_id"] not in (router_id, None)
        ):
            continue
        items.append({**item, "state": state, "reason": why})
    items.sort(key=lambda i: (-(i["since"] or 0), i["id"] or ""))
    return {
        "state": PART_PARTIAL if pruned else PART_OK,
        "reason": R_PRUNED if pruned else None,
        "items": items[:INCIDENTS_MAX],
        "total": len(items),
        "truncated": len(items) > INCIDENTS_MAX,
    }


async def _versions(
    hass: HomeAssistant, admin: bool
) -> tuple[list[Any] | None, str | None, bool]:
    """``(records newest first, reason, cut)`` of the Configuration Manager."""
    from .core_models import MAX_LIST_LIMIT, OPTION_CONFIG_BACKUP_ENABLED
    from .tm_sources import SourceUnreadable, _config_api, domain_entries

    if not admin:
        return None, REASON_ADMIN_ONLY, False
    if not any(
        getattr(e, "options", {}).get(OPTION_CONFIG_BACKUP_ENABLED) is True
        for e in domain_entries(hass)
    ):
        return None, REASON_MODULE_OFF, False
    try:
        api = await _config_api(hass)
        records = await api.async_list_backups(limit=MAX_LIST_LIMIT)
    except SourceUnreadable as err:
        return None, err.reason, False
    except Exception as err:  # noqa: BLE001 - one part never breaks the answer
        _LOGGER.debug(
            "Time Machine state: versions unreadable (%s)", type(err).__name__
        )
        return None, R_UNREADABLE, False
    if not isinstance(records, list | tuple):
        return None, R_UNREADABLE, False
    return list(records), None, len(records) >= MAX_LIST_LIMIT


def _version_item(record: Any, routers: RouterMap) -> dict[str, Any]:
    ref = ref_of("config_manager", "version", record.backup_id, record.backup_id)
    return {
        "router_id": record.router_id,
        "router_name": routers.name_of(record.router_id),
        "version_id": ref["version_id"],
        "created_at": record.created_at.timestamp(),
        "code": token(f"{record.reason.value}.{record.status.value}"),
        "ref": ref,
        "target": jump_target(ref),
    }


def config_at(
    records: list[Any] | None,
    reason: str | None,
    cut: bool,
    at: float,
    rids: list[str],
    routers: RouterMap,
) -> dict[str, Any]:
    """Per router the newest kept version created at or before ``at``.

    Kept versions are thinned (GFS): it is the newest *kept* one, not
    necessarily the configuration that ran at ``at``.
    """
    if records is None:
        state = (
            PART_OFF
            if reason in (REASON_ADMIN_ONLY, REASON_MODULE_OFF)
            else PART_UNREADABLE
        )
        return {"state": state, "reason": reason, "items": []}
    items = []
    missing = False
    for rid in rids:
        found = next(
            (
                r
                for r in records
                if r.router_id == rid and r.created_at.timestamp() <= at
            ),
            None,
        )
        if found is None:
            missing = missing or cut
            continue
        items.append(_version_item(found, routers))
    return {
        "state": PART_PARTIAL if missing else PART_OK,
        "reason": R_CUT if missing else None,
        "items": items,
    }


def _hour(at: float) -> tuple[float, float]:
    start = math.floor(at / HOUR_S) * HOUR_S
    return float(start), float(start + HOUR_S)


_TRAFFIC_FIELDS: Final = (
    "state",
    "reason",
    "rx_bytes",
    "tx_bytes",
    "avg_rx_bps",
    "avg_tx_bps",
    "peak_rx_bps",
    "peak_tx_bps",
    "download",
    "upload",
    "time_coverage",
    "coverage",
)


def traffic_at(hass: HomeAssistant, rid: str, at: float) -> dict[str, Any]:
    """WAN hour values of the hour holding ``at`` (no point or netdev name)."""
    from .traffic_correlate import async_get_traffic_read_api

    start, end = _hour(at)
    api = async_get_traffic_read_api(hass)
    if api is None:
        return {
            "state": PART_OFF,
            "reason": REASON_NOT_RUNNING,
            "hour": start,
            "wan": [],
        }
    status = api.status()
    if status.get("state") == "off":
        return {
            "state": PART_OFF,
            "reason": REASON_MODULE_OFF,
            "hour": start,
            "wan": [],
        }
    wan = []
    for point in api.points(rid):
        if point.get("scope") != "wan":
            continue
        raw = api.window_at(point.get("point_id"), start, end)
        wan.append({k: raw.get(k) for k in _TRAFFIC_FIELDS})
    return {"state": PART_OK, "reason": None, "hour": start, "wan": wan}


def utilization_at(hass: HomeAssistant, rid: str, at: float) -> dict[str, Any]:
    """Channel utilization of the hour holding ``at`` per band (no radio id)."""
    from .rf_center import async_get_rf_center

    start, end = _hour(at)
    center = async_get_rf_center(hass)
    if center is None:
        return {
            "state": PART_OFF,
            "reason": REASON_NOT_RUNNING,
            "hour": start,
            "radios": [],
        }
    if center.status != "ready":
        return {
            "state": PART_OFF,
            "reason": REASON_NOT_LOADED,
            "hour": start,
            "radios": [],
        }
    radios = [
        {
            "band": item.get("band"),
            "state": item.get("state"),
            "mean": item.get("mean"),
            "minimum": item.get("minimum"),
            "maximum": item.get("maximum"),
            "count": item.get("count"),
        }
        for item in center.window_at(rid, start, end).values()
    ]
    radios.sort(key=lambda r: (str(r["band"]), -(r["mean"] or 0)))
    return {"state": PART_OK, "reason": None, "hour": start, "radios": radios}


def _session_item(
    mark: Mark, mark_id: str | None, routers: RouterMap, names: Any
) -> dict[str, Any]:
    item = index_mark(mark, routers, client_name=names(mark.client) if names else None)
    return {
        "id": mark_id or item["id"],
        "client": item["client"],
        "client_name": item["client_name"],
        "router_id": item["router_id"],
        "router_name": item["router_name"],
        "start": item["ts"],
        "end": item["end"],
        "end_state": item["end_state"],
        "band": item["params"].get("band"),
        "derived": bool(mark.derived) or mark.end_state == "unknown",
    }


def clients_at(
    snap: Snapshot,
    engine: Any,
    at: float,
    routers: RouterMap,
    *,
    admin: bool,
    router_id: str | None,
    limit: int = DEFAULT_LIMIT,
    cursor: tuple[int, str | None] | None = None,
    items: bool = True,
) -> dict[str, Any]:
    """Sessions covering ``at`` (administrators, client switch on)."""
    empty: dict[str, Any] = {
        "items": [],
        "per_router": [],
        "total": 0,
        "truncated": False,
        "next_cursor": None,
    }
    if not admin:
        return {"state": PART_OFF, "reason": REASON_ADMIN_ONLY, **empty}
    if not engine.clients_wanted:
        return {"state": PART_OFF, "reason": REASON_CLIENTS_OFF, **empty}
    state, reason = snap.clients_reason(at)
    if state == PART_UNKNOWN:
        return {"state": state, "reason": reason, **empty}
    found = [
        m for m in snap.sessions_at(at) if router_id is None or m.router == router_id
    ]
    per = Counter(m.router for m in found)
    per_router = [
        {"router_id": rid, "router_name": routers.name_of(rid), "clients": n}
        for rid, n in sorted(per.items(), key=lambda kv: (kv[0] is None, kv[0] or ""))
    ]
    out: dict[str, Any] = {
        "state": state,
        "reason": reason,
        **empty,
        "per_router": per_router,
        "total": len(found),
    }
    if not items:
        return out
    ordered = _newest_first(found, cursor, stored_mark_id)
    recorder = engine.recorder
    names = recorder.name_of if recorder is not None else None
    page = ordered
    if len(ordered) > limit:
        page = ordered[:limit]
        last, last_id = page[-1]
        out["truncated"] = True
        out["next_cursor"] = cursor_of(last.ts, last_id or stored_mark_id(last))
    out["items"] = [_session_item(m, mid, routers, names) for m, mid in page]
    return out


def off_state_body(
    now: float, status: str = STATUS_OFF, reason: str | None = None
) -> dict[str, Any]:
    """The state answer while off or not running (nothing read)."""
    return {
        "v": API_VERSION,
        "status": status,
        "reason": reason,
        "generated_at": round(now, 3),
        "at": None,
        "known": False,
        "unknown_reason": None,
        "basis": None,
        "routers": [],
        "routers_truncated": False,
        "intervals": [],
        "intervals_total": 0,
        "intervals_truncated": False,
        "incidents": None,
        "config": None,
        "clients": None,
    }


def _engine_or_status(
    hass: HomeAssistant, now: float
) -> tuple[Any, dict[str, Any] | None]:
    from .tm_engine import async_get_time_machine

    if not time_machine_enabled(hass):
        return None, off_state_body(now)
    engine = async_get_time_machine(hass)
    if engine is None or not engine.loaded:
        reason = REASON_NOT_RUNNING if engine is None else REASON_NOT_LOADED
        return None, off_state_body(now, STATUS_UNAVAILABLE, reason)
    return engine, None


def _router_ids(snap: Snapshot, routers: RouterMap, router_id: str | None) -> list[str]:
    rids = sorted(set(routers.by_entry.values()) | snap.routers)
    if router_id is not None:
        rids = [r for r in rids if r == router_id]
    return rids


def state_body(
    hass: HomeAssistant,
    engine: Any,
    snap: Snapshot,
    at: float,
    routers: RouterMap,
    *,
    admin: bool,
    now: float,
    router_id: str | None = None,
    incidents: tuple[list[Any] | None, str | None, bool] | None = None,
    versions: tuple[list[Any] | None, str | None, bool] | None = None,
    clients_limit: int = DEFAULT_LIMIT,
    clients_cursor: tuple[int, str | None] | None = None,
    client_items: bool = True,
) -> dict[str, Any]:
    """The state at ``at`` (see the module doc and docs §20)."""
    rids = _router_ids(snap, routers, router_id)
    reason = snap.global_reason(at)
    applied = 0
    table = []
    for rid in rids[:ROUTERS_MAX]:
        item, n = router_state(snap, rid, at, routers)
        applied += n
        item["traffic"] = traffic_at(hass, rid, at)
        item["utilization"] = utilization_at(hass, rid, at)
        table.append(item)
    intervals, total = _intervals(snap, at, routers, admin, router_id)
    incidents = incidents or _ni_incidents(hass, routers, router_id)
    config = config_at(
        *(versions or (None, REASON_ADMIN_ONLY, False)), at, rids, routers
    )
    clients = clients_at(
        snap,
        engine,
        at,
        routers,
        admin=admin,
        router_id=router_id,
        limit=clients_limit,
        cursor=clients_cursor,
        items=client_items,
    )
    incident_part = incidents_at(*incidents, at, routers, router_id)
    parts = (
        incident_part["state"] == PART_UNREADABLE,
        config["state"] == PART_UNREADABLE,
    )
    recorded = [a for a, _b in snap.coverage]
    return {
        "v": API_VERSION,
        "status": STATUS_PARTIAL if any(parts) else STATUS_OK,
        "reason": None,
        "generated_at": round(now, 3),
        "at": at,
        "known": reason is None,
        "unknown_reason": reason,
        "basis": {
            "retention_from": round(now - RETENTION_S, 3),
            "recorded_from": min(recorded) if recorded else None,
            "marks_applied": applied,
            "intervals": total,
        },
        "routers": table,
        "routers_truncated": len(rids) > ROUTERS_MAX,
        "intervals": intervals,
        "intervals_total": total,
        "intervals_truncated": total > INTERVALS_MAX,
        "incidents": incident_part,
        "config": config,
        "clients": clients,
    }


async def async_state(
    hass: HomeAssistant, query: StateQuery, *, admin: bool, now: float
) -> dict[str, Any]:
    """``GET …/timemachine/state``."""
    engine, body = _engine_or_status(hass, now)
    if body is not None:
        return body
    routers = build_router_map(hass)
    snap = await async_snapshot(engine, now)
    versions = await _versions(hass, admin)
    return state_body(
        hass,
        engine,
        snap,
        query.at,
        routers,
        admin=admin,
        now=now,
        router_id=query.router_id,
        incidents=_ni_incidents(hass, routers, query.router_id),
        versions=versions,
        clients_limit=query.clients_limit,
        clients_cursor=query.clients_cursor,
    )


# --- comparison --------------------------------------------------------------------------


def _diff(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    a, b = before.get("value"), after.get("value")
    if before.get("reason") is not None or after.get("reason") is not None:
        state = "unknown"
    else:
        state = "same" if a == b else "changed"
    return {"from": a, "to": b, "state": state}


def _radio_diff(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> list[dict[str, Any]]:
    if before["state"] == PART_UNKNOWN or after["state"] == PART_UNKNOWN:
        return [
            {
                "key": None,
                "band": None,
                "from": None,
                "to": None,
                "state": "unknown",
                "reason": before["reason"] or after["reason"],
            }
        ]
    one = {i["key"]: i for i in before["items"]}
    two = {i["key"]: i for i in after["items"]}
    out = []
    for key in sorted(set(one) | set(two)):
        a, b = one.get(key), two.get(key)
        view_a = None if a is None else {k: a[k] for k in ("channel", "width", "state")}
        view_b = None if b is None else {k: b[k] for k in ("channel", "width", "state")}
        if a is None or b is None or "unknown" in (a["state"], b["state"]):
            state = "unknown"
        elif (a["channel"], a["state"]) != (b["channel"], b["state"]):
            state = "changed"
        elif a["width"] is None or b["width"] is None:
            state = "unknown"  # the width after a radio came back is unknown
        else:
            state = "same" if a["width"] == b["width"] else "changed"
        out.append(
            {
                "key": key,
                "band": _band_name(key),
                "from": view_a,
                "to": view_b,
                "state": state,
                "reason": None,
            }
        )
    return out


def compare_body(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    snap: Snapshot,
    query: CompareQuery,
    routers: RouterMap,
    *,
    admin: bool,
    now: float,
    incidents: tuple[list[Any] | None, str | None, bool],
    versions: tuple[list[Any] | None, str | None, bool],
) -> dict[str, Any]:
    """Only the differences of two states, plus what happened between."""
    t1, t2 = query.t1, query.t2
    one = {r["router_id"]: r for r in before["routers"]}
    two = {r["router_id"]: r for r in after["routers"]}
    count_a = {c["router_id"]: c["clients"] for c in before["clients"]["per_router"]}
    count_b = {c["router_id"]: c["clients"] for c in after["clients"]["per_router"]}
    clients_known = before["clients"]["state"] in (PART_OK, PART_PARTIAL) and after[
        "clients"
    ]["state"] in (PART_OK, PART_PARTIAL)
    changes = []
    for rid in sorted(set(one) | set(two)):
        a, b = one.get(rid), two.get(rid)
        if a is None or b is None:
            continue
        entry: dict[str, Any] = {
            "router_id": rid,
            "router_name": routers.name_of(rid),
            "reachable": _diff(a["reachable"], b["reachable"]),
            "role": _diff(a["role"], b["role"]),
            "uplink": _diff(a["uplink"], b["uplink"]),
            "radios": [
                d for d in _radio_diff(a["radios"], b["radios"]) if d["state"] != "same"
            ],
            "clients": None,
        }
        if admin and clients_known:
            ca, cb = count_a.get(rid, 0), count_b.get(rid, 0)
            entry["clients"] = {"from": ca, "to": cb, "delta": cb - ca}
        if (
            any(entry[k]["state"] != "same" for k in ("reachable", "role", "uplink"))
            or entry["radios"]
            or (entry["clients"] and entry["clients"]["delta"])
        ):
            changes.append(entry)
    groups: Counter[str] = Counter()
    # client marks only for administrators while the client list is known
    counted = [*snap.own, *(snap.client_marks if admin and clients_known else ())]
    for mark in counted:
        if not t1 < mark.ts <= t2:
            continue
        if query.router_id is not None and mark.router not in (query.router_id, None):
            continue
        group = KIND_GROUP[mark.kind]
        if admin or group in NON_ADMIN_GROUPS:
            groups[group] += 1
    opened, resolved = [], []
    items, reason, pruned = incidents
    for inc in items or ():
        item = _incident_item(inc, routers)
        if item is None or (
            query.router_id is not None
            and item["router_id"] not in (query.router_id, None)
        ):
            continue
        first, done = (
            getattr(inc, "first_seen", None),
            getattr(inc, "resolved_at", None),
        )
        if isinstance(first, int | float) and t1 < first <= t2:
            opened.append({**item, "at": first})
        if isinstance(done, int | float) and t1 < done <= t2:
            resolved.append({**item, "at": done})
    for seq in (opened, resolved):
        seq.sort(key=lambda i: (-i["at"], i["id"] or ""))
    config: dict[str, Any]
    records, vreason, cut = versions
    if records is None:
        state = (
            PART_OFF
            if vreason in (REASON_ADMIN_ONLY, REASON_MODULE_OFF)
            else PART_UNREADABLE
        )
        config = {
            "state": state,
            "reason": vreason,
            "items": [],
            "total": 0,
            "truncated": False,
            "diffs": [],
        }
    else:
        between = [
            r
            for r in records
            if t1 < r.created_at.timestamp() <= t2
            and (query.router_id is None or r.router_id == query.router_id)
        ]
        old = {i["router_id"]: i["version_id"] for i in before["config"]["items"]}
        new = {i["router_id"]: i["version_id"] for i in after["config"]["items"]}
        diffs = [
            {
                "router_id": rid,
                "from_version_id": old.get(rid),
                "to_version_id": new[rid],
            }
            for rid in sorted(new)
            if new[rid] is not None and old.get(rid) != new[rid]
        ]
        oldest = records[-1].created_at.timestamp() if records else None
        partial = cut and (oldest is None or oldest > t1)
        config = {
            "state": PART_PARTIAL if partial else PART_OK,
            "reason": R_CUT if partial else None,
            "items": [_version_item(r, routers) for r in between[:VERSIONS_MAX]],
            "total": len(between),
            "truncated": len(between) > VERSIONS_MAX,
            "diffs": diffs,
        }
    return {
        "v": API_VERSION,
        "status": STATUS_PARTIAL
        if STATUS_PARTIAL in (before["status"], after["status"])
        else STATUS_OK,
        "reason": None,
        "generated_at": round(now, 3),
        "t1": t1,
        "t2": t2,
        "before": before,
        "after": after,
        "changes": {
            "routers": changes,
            "marks": {
                "count": sum(groups.values()),
                "by_group": dict(sorted(groups.items())),
            },
            "incidents": {
                "state": (
                    PART_OFF
                    if reason in (REASON_NOT_RUNNING, REASON_NOT_LOADED)
                    else PART_UNREADABLE
                )
                if items is None
                else (PART_PARTIAL if pruned else PART_OK),
                "reason": reason if items is None else (R_PRUNED if pruned else None),
                "opened": opened[:INCIDENTS_MAX],
                "resolved": resolved[:INCIDENTS_MAX],
                "truncated": len(opened) > INCIDENTS_MAX
                or len(resolved) > INCIDENTS_MAX,
            },
            "config_versions": config,
        },
    }


def off_compare_body(
    now: float, status: str = STATUS_OFF, reason: str | None = None
) -> dict[str, Any]:
    """The comparison while off or not running."""
    return {
        "v": API_VERSION,
        "status": status,
        "reason": reason,
        "generated_at": round(now, 3),
        "t1": None,
        "t2": None,
        "before": None,
        "after": None,
        "changes": None,
    }


async def async_compare(
    hass: HomeAssistant, query: CompareQuery, *, admin: bool, now: float
) -> dict[str, Any]:
    """``GET …/timemachine/compare``."""
    engine, body = _engine_or_status(hass, now)
    if body is not None:
        return off_compare_body(now, body["status"], body["reason"])
    routers = build_router_map(hass)
    snap = await async_snapshot(engine, now)
    incidents = _ni_incidents(hass, routers, query.router_id)
    versions = await _versions(hass, admin)
    states = []
    for at in (query.t1, query.t2):
        states.append(
            state_body(
                hass,
                engine,
                snap,
                at,
                routers,
                admin=admin,
                now=now,
                router_id=query.router_id,
                incidents=incidents,
                versions=versions,
                client_items=False,
            )
        )
        await asyncio.sleep(0)
    return compare_body(
        states[0],
        states[1],
        snap,
        query,
        routers,
        admin=admin,
        now=now,
        incidents=incidents,
        versions=versions,
    )


__all__ = [
    "COMPARE_QUERY_KEYS",
    "STATE_QUERY_KEYS",
    "TOPOLOGY_SETTLE_S",
    "UNKNOWN_REASONS",
    "CompareQuery",
    "Snapshot",
    "StateQuery",
    "async_compare",
    "async_snapshot",
    "async_state",
    "parse_compare_query",
    "parse_state_query",
    "router_state",
]
