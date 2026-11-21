"""Network Time Machine, Phase A: query, merge, rights and paging.

Parses the strict query of ``GET .../timemachine/timeline``, reads the
requested sources one after the other through ``tm_sources`` (no listener,
no task, no store), keeps what the user may see and returns one stable,
versioned answer (``v`` 1, see ``docs/time-machine.md``):

* the window is half-open, ``[from, until)`` in epoch seconds, both bounds
  rounded up to the millisecond grid of the marks (``tm_sources.ms_floor``);
  24 h by default, 14 days at most;
* marks are sorted newest first, ties by mark id (stable);
* a page holds at most ``limit`` marks. ``next_cursor`` (1.51.0, review S3)
  is the position after the page's last mark (``<ms>`` or ``<ms>:<id>``);
  sent back as ``cursor`` with the same window it continues there, also
  inside one millisecond. ``next_until`` (for older clients) never splits
  marks of the same timestamp (unless one timestamp alone holds more; the
  rest of it is then reachable over the cursor only);
* a source whose read was cut bounds the page: it is complete only above
  its ``edge`` (the oldest read entry of the window, client entries
  included). The page keeps the marks after the edge's millisecond and
  ``next_until`` is the millisecond after the edge, so the next page reads
  that millisecond whole (review K4); only when the edge's millisecond is
  the last one of the window, the page keeps it and the rest of it is cut.
  ``next_until`` is set even when the page holds no mark (review S1), and
  the source says ``cut`` (``next_page`` / ``unreachable``), so a gap of one
  source never looks like a quiet time.

Rights (plan §6, F4/F5): administrators see every mark of Phase A. Other
users (only while the panel is open to all; the route checks that) see the
groups ``NON_ADMIN_GROUPS``; the core audit and the configuration versions
are not read for them (``off`` / ``admin_only``). Each source's ``state``,
``count`` and ``oldest`` are taken after the rights (review K2): a non-admin
learns neither that marks he may not see exist nor when. Client marks do
not exist in Phase A: the sources' client entries are only counted, and
only administrators get that count (``omitted_client_marks`` is 0 for
others).

Phases B/C (additive, still ``v`` 1): the own index adds ``tm_index``,
``tm_refs`` and ``tm_clients`` (read by default with the others). Doubles
are dropped before the rights and counted per source (``duplicates``):

* an audit entry is shown by ``core_audit`` while the audit still holds it;
  its reference mark in ``tm_refs`` (same audit id) is dropped;
* an outage, reachability or channel event of ``ni_events``
  (``COVERED_NI_KINDS``) is dropped only when ``tm_index`` holds a mark of
  the same meaning for the same router close in time (``NI_MATCH_S``; an
  NI "down" inside the index's outage interval). Everything else stays.

Intervals of the own index that began before ``from`` and reach into the
window (open, or ended at or after ``from``) belong to it (1.51.0, review
S4) but are never in ``marks``: only with ``spans=1`` they come in the
field ``spanning`` (``spans_in: true``), newest start first, at most
``SPANNING_MAX`` (``spanning_truncated``), not counted against ``limit``,
under the same rights and filters. A client asks ``spans=1`` on its first
page and pages on without it, so each comes once.

Client sessions have their own query (:func:`parse_sessions_query`,
:func:`sessions_page`, administrators only): sessions that overlap the
window, newest start first (ties by id), paged like the timeline
(``next_cursor``, and ``next_until`` on the start for older clients).
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from homeassistant.core import HomeAssistant

from .const import OPTION_TIME_MACHINE_ENABLED
from .tm_sources import (
    ALL_SOURCE_IDS,
    KIND_GROUP,
    KINDS,
    NON_ADMIN_GROUPS,
    SEVERITIES,
    SEVERITY_RANK,
    SOURCE_CORE_AUDIT,
    SOURCE_NI_EVENTS,
    SOURCE_TM_INDEX,
    SOURCE_TM_REFS,
    STATE_EMPTY,
    STATE_OK,
    STATE_UNREADABLE,
    ReadFn,
    ReadRequest,
    SourceResult,
    async_read_source,
    build_router_map,
    domain_entries,
    ms_ceil,
    ms_next,
)

_LOGGER = logging.getLogger(__name__)

API_VERSION: Final = 1
STATUS_OK: Final = "ok"
STATUS_PARTIAL: Final = "partial"  # at least one requested source unreadable
STATUS_OFF: Final = "off"
# ``cut`` of a source in the answer (additive, 1.50.0 review): its read was
# cut; older entries of the window come on the next page / cannot be read.
CUT_NEXT_PAGE: Final = "next_page"
CUT_UNREACHABLE: Final = "unreachable"

DEFAULT_WINDOW_S: Final = 86_400.0  # 24 h
MAX_WINDOW_S: Final = 14 * 86_400.0  # 14 days (F1)
DEFAULT_LIMIT: Final = 200
MAX_LIMIT: Final = 500
TIME_MAX: Final = 4_102_444_800.0  # 2100-01-01
QUERY_KEYS: Final = frozenset(
    {
        "from",
        "until",
        "source",
        "router_id",
        "kind",
        "min_severity",
        "limit",
        # additive (1.51.0, review S3/S4)
        "cursor",
        "spans",
    }
)
# Intervals reaching into the window, at most this many (``spanning``).
SPANNING_MAX: Final = 200
QUERY_VALUE_MAX: Final = 96

_TIME = re.compile(r"[0-9]{1,10}(?:\.[0-9]{1,6})?")
_INT = re.compile(r"[0-9]{1,4}")
# ``cursor``: ``<ms>`` (everything older than that millisecond) or
# ``<ms>:<mark id>`` (that millisecond after the id, then everything older).
_CURSOR = re.compile(r"([0-9]{1,13})(?::(tmm_[0-9a-f]{16}))?")
_ROUTER_ID = re.compile(r"rtr_[0-9a-f]{32}")


class QueryError(Exception):
    """A refused query: ``field`` and a fixed ``reason`` (never the input)."""

    def __init__(self, field: str, reason: str = "invalid") -> None:
        """Remember field and reason."""
        super().__init__(f"{field}: {reason}")
        self.field = field
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Query:
    """A checked timeline query."""

    since: float
    until: float
    sources: tuple[str, ...] = ALL_SOURCE_IDS
    router_id: str | None = None
    kind: str | None = None
    min_severity: str | None = None
    limit: int = DEFAULT_LIMIT
    # additive (1.51.0): continue after this position (ms, mark id or None)
    cursor: tuple[int, str | None] | None = None
    # additive (1.51.0): also answer the intervals reaching into the window
    spans: bool = False


@dataclass(slots=True)
class Stats:
    """In-memory counters for diagnostics (no content, never stored)."""

    requests: int = 0
    unreadable: dict[str, int] = field(default_factory=dict)
    last_duration_ms: float | None = None
    last_marks: int | None = None

    def as_dict(self) -> dict[str, Any]:
        """Plain counters."""
        return {
            "requests": self.requests,
            "unreadable": dict(sorted(self.unreadable.items())),
            "last_duration_ms": self.last_duration_ms,
            "last_marks": self.last_marks,
        }


def time_machine_enabled(hass: HomeAssistant) -> bool:
    """The fleet-wide switch: on while any router entry has it on."""
    return any(
        isinstance(getattr(entry, "options", None), Mapping)
        and entry.options.get(OPTION_TIME_MACHINE_ENABLED) is True
        for entry in domain_entries(hass)
    )


# --- query ------------------------------------------------------------------------------


def _time(query: Mapping[str, str], name: str) -> float | None:
    raw = query.get(name)
    if raw is None:
        return None
    if not _TIME.fullmatch(raw):
        raise QueryError(name)
    value = float(raw)
    if value > TIME_MAX:
        raise QueryError(name, "out_of_range")
    return value


def _cursor(raw: str | None) -> tuple[int, str | None] | None:
    if raw is None:
        return None
    match = _CURSOR.fullmatch(raw)
    if match is None:
        raise QueryError("cursor")
    return int(match.group(1)), match.group(2)


def cursor_of(ts: float, mark_id: str | None = None) -> str:
    """The ``cursor`` value of a position (``next_cursor``)."""
    ms = round(ts * 1000)
    return f"{ms}:{mark_id}" if mark_id else str(ms)


def _after(ts: float, mark_id: str, cursor: tuple[int, str | None] | None) -> bool:
    """Lies the item after ``cursor`` in the order newest first, then id?"""
    if cursor is None:
        return True
    ms, cid = cursor
    own = round(ts * 1000)
    return own < ms or (cid is not None and own == ms and mark_id > cid)


def _spans(query: Mapping[str, str]) -> bool:
    raw = query.get("spans")
    if raw is None:
        return False
    if raw not in ("0", "1"):
        raise QueryError("spans")
    return raw == "1"


def parse_query(query: Mapping[str, str], now: float) -> Query:
    """Check every key and value; QueryError (field, fixed reason) else.

    ``query`` holds each key once (the route refuses repeats and unknown
    keys before). ``source`` is a comma list of source ids.
    """
    for key, value in query.items():
        if key not in QUERY_KEYS:
            raise QueryError("query", "unknown_key")
        if len(value) > QUERY_VALUE_MAX:
            raise QueryError(key, "too_long")
    since = _time(query, "from")
    until = _time(query, "until")
    if until is None:
        until = float(math.floor(now) + 1)
    if since is None:
        since = until - DEFAULT_WINDOW_S
    # On the grid of the marks: a mark lies in exactly one page (review K1).
    since, until = ms_ceil(since), ms_ceil(until)
    if since >= until:
        raise QueryError("window", "empty")
    if until - since > MAX_WINDOW_S:
        raise QueryError("window", "too_large")
    sources = ALL_SOURCE_IDS
    raw = query.get("source")
    if raw is not None:
        picked = raw.split(",")
        if any(p not in ALL_SOURCE_IDS for p in picked):
            raise QueryError("source", "unknown")
        if len(set(picked)) != len(picked):
            raise QueryError("source", "repeated")
        sources = tuple(s for s in ALL_SOURCE_IDS if s in picked)
    router_id = query.get("router_id")
    if router_id is not None and not _ROUTER_ID.fullmatch(router_id):
        raise QueryError("router_id")
    kind = query.get("kind")
    if kind is not None and kind not in KIND_GROUP:
        raise QueryError("kind", "unknown")
    min_severity = query.get("min_severity")
    if min_severity is not None and min_severity not in SEVERITY_RANK:
        raise QueryError("min_severity", "unknown")
    limit = DEFAULT_LIMIT
    raw_limit = query.get("limit")
    if raw_limit is not None:
        if not _INT.fullmatch(raw_limit) or not 1 <= int(raw_limit) <= MAX_LIMIT:
            raise QueryError("limit", "out_of_range")
        limit = int(raw_limit)
    cursor = _cursor(query.get("cursor"))
    if cursor is not None and not since * 1000 <= cursor[0] <= until * 1000:
        raise QueryError("cursor", "out_of_range")
    return Query(
        since,
        until,
        sources,
        router_id,
        kind,
        min_severity,
        limit,
        cursor,
        _spans(query),
    )


# --- answer -----------------------------------------------------------------------------


def off_body(now: float) -> dict[str, Any]:
    """The answer while the Time Machine is off: nothing read, nothing shown."""
    return {
        "v": API_VERSION,
        "status": STATUS_OFF,
        "generated_at": round(now, 3),
        "window": {"from": None, "until": None},
        "marks": [],
        "sources": [],
        "omitted_client_marks": 0,
        "truncated": False,
        "next_until": None,
        "next_cursor": None,
        "spanning": [],
        "spanning_truncated": False,
    }


def _allowed(mark: Mapping[str, Any], admin: bool) -> bool:
    """May this user see the mark at all (rights only, no query filter)?"""
    return admin or mark["group"] in NON_ADMIN_GROUPS


def _visible(mark: Mapping[str, Any], query: Query, admin: bool) -> bool:
    if not _allowed(mark, admin):
        return False
    if query.router_id is not None and mark["router_id"] != query.router_id:
        return False
    if query.kind is not None and mark["kind"] != query.kind:
        return False
    return query.min_severity is None or (
        SEVERITY_RANK[mark["severity"]] >= SEVERITY_RANK[query.min_severity]
    )


def _edge(result: SourceResult) -> float | None:
    """Where a cut read ends (None: not cut, or nothing of the window read)."""
    if not result.truncated or result.unreachable:
        return None
    return result.edge if result.edge is not None else result.oldest


# NI events with the same meaning as a mark of the own index (review S1,
# 1.51.0). ``lan.uplink`` (an uplink *port* without link) is shown as
# ``uplink_changed`` but means something else than the index's change of the
# parent router: never a double.
COVERED_NI_KINDS: Final = frozenset(
    {"router_down", "router_up", "lan_down", "lan_up", "channel_changed"}
)
# Index intervals an NI event of this kind lies in (start, or end for "up").
_DOWN_OF: Final = {"router_up": "router_down", "lan_up": "lan_down"}
# How far apart the two sides of one event may lie (seconds). Both follow
# the same outage tracker and the same polls: the index's outage starts at
# the first failed poll and NI's event follows the report (two more failed
# polls and the settle time later), so an NI "down" is matched against the
# whole index interval; "up" comes from the same tracker call on both sides;
# a channel change is seen by the index at the next poll after the router's
# log time. 180 s = three regular polls (60 s), or one poll plus margin at
# 120 s (CPU load); at 300 s (SSH fallback) a channel change may stay
# double. In doubt the NI event stays: rather twice than lost.
NI_MATCH_S: Final = 180.0
_READ: Final = (STATE_OK, STATE_EMPTY)


def _ni_double(mark: Mapping[str, Any], spans: Mapping[tuple[str, Any], list]) -> bool:
    """Does the own index hold the same event (meaning, router, time)?"""
    kind, router, ts = mark["kind"], mark["router_id"], mark["ts"]
    if kind not in COVERED_NI_KINDS or (router is None and not mark["fleet"]):
        return False
    if kind in ("router_down", "lan_down"):
        return any(
            start - NI_MATCH_S <= ts <= (math.inf if end is None else end + NI_MATCH_S)
            for start, end in spans.get((kind, router), ())
        )
    if any(
        abs(start - ts) <= NI_MATCH_S for start, _e in spans.get((kind, router), ())
    ):
        return True
    down = _DOWN_OF.get(kind)
    return down is not None and any(
        end is not None and abs(end - ts) <= NI_MATCH_S
        for _s, end in spans.get((down, router), ())
    )


def drop_duplicates(results: list[SourceResult]) -> None:
    """Drop doubles between sources (see the module doc); counts them."""
    by_source = {r.source: r for r in results}
    audit = by_source.get(SOURCE_CORE_AUDIT)
    refs = by_source.get(SOURCE_TM_REFS)
    if audit is not None and refs is not None and audit.state in _READ:
        shown = {m["ref"]["id"] for m in audit.marks if m["ref"].get("id")}
        keep = [m for m in refs.marks if m["ref"].get("id") not in shown]
        refs.duplicates += len(refs.marks) - len(keep)
        refs.marks = keep
    index = by_source.get(SOURCE_TM_INDEX)
    ni = by_source.get(SOURCE_NI_EVENTS)
    if index is not None and ni is not None and index.state in _READ:
        spans: dict[tuple[str, Any], list[tuple[float, float | None]]] = {}
        for m in (*index.marks, *index.spanning):
            if m["kind"] in COVERED_NI_KINDS:
                end = m["end"] if m["end_state"] != "open" else None
                spans.setdefault((m["kind"], m["router_id"]), []).append((m["ts"], end))
        keep = [m for m in ni.marks if not _ni_double(m, spans)]
        ni.duplicates += len(ni.marks) - len(keep)
        ni.marks = keep


def merge(
    results: Iterable[SourceResult], query: Query, *, admin: bool, now: float
) -> dict[str, Any]:
    """One answer of the read sources (doubles, filters, rights, order, paging)."""
    results = list(results)
    drop_duplicates(results)
    # A cut source is complete only above its edge: the page keeps what lies
    # after the edge's millisecond, the next page starts with it (K4). Only
    # when that millisecond ends the window, the page keeps it (no progress
    # otherwise) and the rest of it is cut.
    bounds = []
    for r in results:
        edge = _edge(r)
        if edge is not None:
            after = ms_next(edge)
            bounds.append(after if after < query.until else edge)
    cutoff = max(bounds) if bounds else None
    marks = [
        m
        for r in results
        for m in r.marks
        if (cutoff is None or m["ts"] >= cutoff)
        and _after(m["ts"], m["id"], query.cursor)
        and _visible(m, query, admin)
    ]
    marks.sort(key=lambda m: (-m["ts"], m["id"]))
    next_until = cutoff
    # below a cut source's edge (nothing left when it is the window's start)
    next_cursor = (
        cursor_of(cutoff) if cutoff is not None and cutoff > query.since else None
    )
    truncated = cutoff is not None or any(r.truncated for r in results)
    if len(marks) > query.limit:
        page = marks[: query.limit]
        boundary = page[-1]["ts"]
        whole = [m for m in page if m["ts"] > boundary]
        # Without a cursor a page keeps a millisecond together (next_until);
        # one millisecond with more marks than ``limit`` is cut there, and
        # ``next_cursor`` goes on inside it (review S3).
        marks = whole or page
        next_until = marks[-1]["ts"]
        next_cursor = cursor_of(marks[-1]["ts"], marks[-1]["id"])
        truncated = True
    if next_until is not None and next_until <= query.since:
        next_until = None
    spanning: list[dict[str, Any]] = []
    if query.spans:
        spanning = [m for r in results for m in r.spanning if _visible(m, query, admin)]
        spanning.sort(key=lambda m: (-m["ts"], m["id"]))
    on_page: dict[str, list[dict[str, Any]]] = {}
    for mark in marks:
        on_page.setdefault(mark["source"], []).append(mark)
    sources = []
    for r in results:
        mine = on_page.get(r.source, [])
        state = r.state
        if state in (STATE_OK, STATE_EMPTY):
            # after the rights (K2); a cut source is never "empty" (S1)
            shown = (*r.marks, *r.spanning) if query.spans else r.marks
            allowed = any(_allowed(m, admin) for m in shown)
            state = STATE_OK if allowed or r.truncated else STATE_EMPTY
        cut = None
        if r.truncated:
            if _edge(r) is None:
                cut = CUT_UNREACHABLE
            elif next_until is not None or next_cursor is not None:
                cut = CUT_NEXT_PAGE
        sources.append(
            {
                "id": r.source,
                "state": state,
                "reason": r.reason,
                "count": len(mine),
                # the oldest of the source's marks on this page (after rights
                # and filters; K2), None without one
                "oldest": mine[-1]["ts"] if mine else None,
                "truncated": r.truncated,
                "cut": cut,
                # additive (1.51.0): marks dropped as doubles of another source
                "duplicates": r.duplicates,
            }
        )
    return {
        "v": API_VERSION,
        "status": STATUS_PARTIAL
        if any(r.state == STATE_UNREADABLE for r in results)
        else STATUS_OK,
        "generated_at": round(now, 3),
        "window": {"from": query.since, "until": query.until},
        "marks": marks,
        "sources": sources,
        # The count of left-out client entries is for administrators only
        # (1.50.0): a non-admin learns nothing about clients, not even how
        # many there were.
        "omitted_client_marks": sum(r.omitted_client for r in results) if admin else 0,
        "truncated": truncated,
        "next_until": next_until,
        # additive (1.51.0, review S3): where the next page starts, also
        # inside one millisecond; send it back as ``cursor`` with the same
        # window
        "next_cursor": next_cursor,
        # additive (1.51.0, review S4): only with ``spans=1``
        "spanning": spanning[:SPANNING_MAX],
        "spanning_truncated": len(spanning) > SPANNING_MAX,
    }


async def async_timeline(
    hass: HomeAssistant,
    query: Query,
    *,
    admin: bool,
    now: float,
    stats: Stats | None = None,
    readers: Mapping[str, ReadFn] | None = None,
) -> dict[str, Any]:
    """Read the requested sources (one at a time) and merge them."""
    started = time.monotonic()
    routers = build_router_map(hass)
    until = query.until
    if query.cursor is not None:
        # read what lies at or before the cursor's millisecond
        ms, cid = query.cursor
        until = min(until, (ms + (1 if cid else 0)) / 1000)
    req = ReadRequest(query.since, until, admin, now)
    results: list[SourceResult] = []
    for source in query.sources:
        results.append(
            await async_read_source(hass, source, req, routers, readers=readers)
        )
        await asyncio.sleep(0)  # let the loop breathe between sources
    body = merge(results, query, admin=admin, now=now)
    if stats is not None:
        stats.requests += 1
        for r in results:
            if r.state == STATE_UNREADABLE:
                stats.unreadable[r.source] = stats.unreadable.get(r.source, 0) + 1
        stats.last_duration_ms = round((time.monotonic() - started) * 1000, 1)
        stats.last_marks = len(body["marks"])
    return body


# --- client sessions (Phase C) -------------------------------------------------------

STATUS_CLIENTS_OFF: Final = "clients_off"
STATUS_UNAVAILABLE: Final = "unavailable"
SESSION_QUERY_KEYS: Final = frozenset(
    {"from", "until", "client", "router_id", "limit", "cursor"}
)
_CLIENT = re.compile(r"tmc_[0-9a-f]{16}")


@dataclass(frozen=True, slots=True)
class SessionQuery:
    """A checked sessions query (window as in :class:`Query`)."""

    since: float
    until: float
    client: str | None = None
    router_id: str | None = None
    limit: int = DEFAULT_LIMIT
    # additive (1.51.0, review S3): as in :class:`Query`
    cursor: tuple[int, str | None] | None = None


def parse_sessions_query(query: Mapping[str, str], now: float) -> SessionQuery:
    """Like :func:`parse_query`; ``client`` is a ``tmc_`` pseudonym."""
    for key in query:
        if key not in SESSION_QUERY_KEYS:
            raise QueryError("query", "unknown_key")
    client = query.get("client")
    if client is not None and not _CLIENT.fullmatch(client):
        raise QueryError("client")
    base = parse_query(
        {k: v for k, v in query.items() if k not in ("client", "cursor")}, now
    )
    # Sessions that began before ``from`` belong to the window too: the
    # cursor may lie before it, never after ``until``.
    cursor = _cursor(query.get("cursor"))
    if cursor is not None and cursor[0] > base.until * 1000:
        raise QueryError("cursor", "out_of_range")
    return SessionQuery(
        base.since, base.until, client, base.router_id, base.limit, cursor
    )


def sessions_body(
    status: str,
    now: float,
    query: SessionQuery | None = None,
    *,
    reason: str | None = None,
    recording: bool = False,
) -> dict[str, Any]:
    """An answer without sessions (off, clients off, unavailable)."""
    return {
        "v": API_VERSION,
        "status": status,
        "reason": reason,
        "generated_at": round(now, 3),
        "window": {
            "from": query.since if query else None,
            "until": query.until if query else None,
        },
        "recording": recording,
        "sessions": [],
        "truncated": False,
        "next_until": None,
        "next_cursor": None,
    }


def _newest_first(
    marks: list[Any],
    cursor: tuple[int, str | None] | None,
    id_of: Callable[[Any], str],
) -> list[tuple[Any, str | None]]:
    """Stored marks after ``cursor``, newest first, ties by id.

    The id (a hash) is computed only where the order or the cursor needs it:
    for marks sharing a millisecond (review K6: 10000 sessions otherwise
    cost ~7 ms of hashing on the event loop).
    """
    out: list[tuple[Any, str | None]] = []
    for mark in marks:
        if cursor is not None:
            own = round(mark.ts * 1000)
            if own > cursor[0]:
                continue
            if own == cursor[0]:
                mark_id = id_of(mark)
                if cursor[1] is None or mark_id <= cursor[1]:
                    continue
                out.append((mark, mark_id))
                continue
        out.append((mark, None))
    out.sort(key=lambda p: -p[0].ts)
    i = 0
    while i < len(out):
        j = i + 1
        while j < len(out) and out[j][0].ts == out[i][0].ts:
            j += 1
        if j - i > 1:
            tied = [(m, mid or id_of(m)) for m, mid in out[i:j]]
            tied.sort(key=lambda p: p[1])
            out[i:j] = tied
        i = j
    return out


def sessions_page(
    hass: HomeAssistant, query: SessionQuery, *, now: float
) -> dict[str, Any]:
    """Client sessions overlapping the window (administrators only; the
    route checks that). Newest start first; a page never splits sessions
    of the same start (unless one start alone holds more)."""
    from .tm_engine import async_get_time_machine
    from .tm_sources import (
        REASON_NOT_LOADED,
        REASON_NOT_RUNNING,
        index_mark,
        stored_mark_id,
    )

    if not time_machine_enabled(hass):
        return sessions_body(STATUS_OFF, now)
    engine = async_get_time_machine(hass)
    if engine is None or not engine.loaded:
        reason = REASON_NOT_RUNNING if engine is None else REASON_NOT_LOADED
        return sessions_body(STATUS_UNAVAILABLE, now, query, reason=reason)
    recorder = engine.recorder
    recording = recorder is not None and recorder.attached
    if not engine.clients_wanted:
        return sessions_body(STATUS_CLIENTS_OFF, now, query)
    routers = build_router_map(hass)
    client = query.client[4:] if query.client else None
    found = _newest_first(
        engine.index.sessions(
            query.since, query.until, client=client, router=query.router_id
        ),
        query.cursor,
        stored_mark_id,
    )
    next_until = None
    next_cursor = None
    truncated = False
    if len(found) > query.limit:
        page = found[: query.limit]
        boundary = page[-1][0].ts
        whole = [p for p in page if p[0].ts > boundary]
        # as the timeline: next_until keeps a start together, next_cursor
        # goes on inside one start too (review S3)
        found = whole or page
        last, last_id = found[-1]
        next_until = last.ts
        next_cursor = cursor_of(last.ts, last_id or stored_mark_id(last))
        truncated = True
        if next_until <= query.since:
            next_until = None
    sessions = []
    for mark, _id in found:
        item = index_mark(
            mark,
            routers,
            client_name=recorder.name_of(mark.client) if recorder else None,
        )
        sessions.append(
            {
                "id": item["id"],
                "client": item["client"],
                "client_name": item["client_name"],
                "router_id": item["router_id"],
                "router_name": item["router_name"],
                "start": item["ts"],
                "end": item["end"],
                "end_state": item["end_state"],
                "band": item["params"].get("band"),
                "params": item["params"],
                "derived": item["derived"],
            }
        )
    body = sessions_body(STATUS_OK, now, query, recording=recording)
    body["sessions"] = sessions
    body["truncated"] = truncated
    body["next_until"] = next_until
    body["next_cursor"] = next_cursor
    return body


__all__ = [
    "API_VERSION",
    "CUT_NEXT_PAGE",
    "CUT_UNREACHABLE",
    "DEFAULT_LIMIT",
    "KINDS",
    "MAX_LIMIT",
    "MAX_WINDOW_S",
    "SEVERITIES",
    "Query",
    "QueryError",
    "SessionQuery",
    "Stats",
    "async_timeline",
    "drop_duplicates",
    "merge",
    "off_body",
    "parse_query",
    "parse_sessions_query",
    "sessions_body",
    "sessions_page",
    "time_machine_enabled",
]
