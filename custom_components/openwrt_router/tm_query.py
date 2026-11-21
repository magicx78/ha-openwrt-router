"""Network Time Machine, Phase A: query, merge, rights and paging.

Parses the strict query of ``GET .../timemachine/timeline``, reads the
requested sources one after the other through ``tm_sources`` (no listener,
no task, no store), keeps what the user may see and returns one stable,
versioned answer (``v`` 1, see ``docs/time-machine.md``):

* the window is half-open, ``[from, until)`` in epoch seconds; 24 h by
  default, 14 days at most;
* marks are sorted newest first, ties by mark id (stable);
* a page holds at most ``limit`` marks and never splits marks of the same
  second (unless one second alone holds more): ``next_until`` is the
  ``until`` of the next page;
* a source that was cut by its read limit bounds the page: marks older than
  its oldest read entry are left for the next page, so a gap of one source
  never looks like a quiet time.

Rights (plan §6, F4/F5): administrators see every mark of Phase A. Other
users (only while the panel is open to all; the route checks that) see the
groups ``NON_ADMIN_GROUPS``; the core audit and the configuration versions
are not read for them (``off`` / ``admin_only``). Client marks do not exist
in Phase A: the sources' client entries are only counted.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from homeassistant.core import HomeAssistant

from .const import OPTION_TIME_MACHINE_ENABLED
from .tm_sources import (
    KIND_GROUP,
    KINDS,
    NON_ADMIN_GROUPS,
    SEVERITIES,
    SEVERITY_RANK,
    SOURCE_IDS,
    STATE_UNREADABLE,
    ReadFn,
    ReadRequest,
    SourceResult,
    async_read_source,
    build_router_map,
    domain_entries,
)

_LOGGER = logging.getLogger(__name__)

API_VERSION: Final = 1
STATUS_OK: Final = "ok"
STATUS_PARTIAL: Final = "partial"  # at least one requested source unreadable
STATUS_OFF: Final = "off"

DEFAULT_WINDOW_S: Final = 86_400.0  # 24 h
MAX_WINDOW_S: Final = 14 * 86_400.0  # 14 days (F1)
DEFAULT_LIMIT: Final = 200
MAX_LIMIT: Final = 500
TIME_MAX: Final = 4_102_444_800.0  # 2100-01-01
QUERY_KEYS: Final = frozenset(
    {"from", "until", "source", "router_id", "kind", "min_severity", "limit"}
)
QUERY_VALUE_MAX: Final = 96

_TIME = re.compile(r"[0-9]{1,10}(?:\.[0-9]{1,6})?")
_INT = re.compile(r"[0-9]{1,4}")
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
    sources: tuple[str, ...] = SOURCE_IDS
    router_id: str | None = None
    kind: str | None = None
    min_severity: str | None = None
    limit: int = DEFAULT_LIMIT


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
    if since >= until:
        raise QueryError("window", "empty")
    if until - since > MAX_WINDOW_S:
        raise QueryError("window", "too_large")
    sources = SOURCE_IDS
    raw = query.get("source")
    if raw is not None:
        picked = raw.split(",")
        if any(p not in SOURCE_IDS for p in picked):
            raise QueryError("source", "unknown")
        if len(set(picked)) != len(picked):
            raise QueryError("source", "repeated")
        sources = tuple(s for s in SOURCE_IDS if s in picked)
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
    return Query(since, until, sources, router_id, kind, min_severity, limit)


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
    }


def _visible(mark: Mapping[str, Any], query: Query, admin: bool) -> bool:
    if not admin and mark["group"] not in NON_ADMIN_GROUPS:
        return False
    if query.router_id is not None and mark["router_id"] != query.router_id:
        return False
    if query.kind is not None and mark["kind"] != query.kind:
        return False
    return query.min_severity is None or (
        SEVERITY_RANK[mark["severity"]] >= SEVERITY_RANK[query.min_severity]
    )


def merge(
    results: Iterable[SourceResult], query: Query, *, admin: bool, now: float
) -> dict[str, Any]:
    """One answer of the read sources (filters, rights, order, paging)."""
    results = list(results)
    # A source cut by its read limit is complete only down to its oldest
    # read entry: the page stops there (the next page continues).
    cut_offs = [
        r.oldest for r in results if r.truncated and r.oldest is not None and r.marks
    ]
    cutoff = max(cut_offs) if cut_offs else None
    marks = [
        m
        for r in results
        for m in r.marks
        if (cutoff is None or m["ts"] >= cutoff) and _visible(m, query, admin)
    ]
    marks.sort(key=lambda m: (-m["ts"], m["id"]))
    next_until = cutoff
    truncated = cutoff is not None or any(r.truncated for r in results)
    if len(marks) > query.limit:
        page = marks[: query.limit]
        boundary = page[-1]["ts"]
        whole = [m for m in page if m["ts"] > boundary]
        # one second with more marks than ``limit`` is cut (flagged)
        marks = whole or page
        next_until = marks[-1]["ts"]
        truncated = True
    if next_until is not None and next_until <= query.since:
        next_until = None
    counts: dict[str, int] = {}
    for mark in marks:
        counts[mark["source"]] = counts.get(mark["source"], 0) + 1
    sources = [
        {
            "id": r.source,
            "state": r.state,
            "reason": r.reason,
            "count": counts.get(r.source, 0),
            "oldest": r.oldest,
            "truncated": r.truncated,
        }
        for r in results
    ]
    return {
        "v": API_VERSION,
        "status": STATUS_PARTIAL
        if any(r.state == STATE_UNREADABLE for r in results)
        else STATUS_OK,
        "generated_at": round(now, 3),
        "window": {"from": query.since, "until": query.until},
        "marks": marks,
        "sources": sources,
        "omitted_client_marks": sum(r.omitted_client for r in results),
        "truncated": truncated,
        "next_until": next_until,
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
    req = ReadRequest(query.since, query.until, admin, now)
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


__all__ = [
    "API_VERSION",
    "DEFAULT_LIMIT",
    "KINDS",
    "MAX_LIMIT",
    "MAX_WINDOW_S",
    "SEVERITIES",
    "Query",
    "QueryError",
    "Stats",
    "async_timeline",
    "merge",
    "off_body",
    "parse_query",
    "time_machine_enabled",
]
