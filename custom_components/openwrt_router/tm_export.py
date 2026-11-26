"""Network Time Machine, Phase E (1.52.0): the export of one window.

``GET …/timemachine/export`` (``tm_views``): administrators only. The marks
of one window as JSON, with the fields of the timeline (``tm_query``) and
the intervals reaching into it, ready to be saved by the browser
(``Content-Disposition: attachment``). Nothing is written to disk here.

* **no names or addresses**: ``router_name``, ``client_name``, ``text`` and
  the names of ``peers`` are always null (the ids stay); client marks are
  left out altogether (only their count, ``omitted_client_marks``): a
  stable client pseudonym in a file that leaves Home Assistant would tie
  one person's movements together. The other fields carry ids, codes and
  numbers only (``tm_sources`` builds them that way).
* **full pages** (review I): client marks are left out in the query itself
  (``Query.no_clients``: ``tm_clients`` is not read, a module entry naming a
  client is filtered before the page is cut), so a page holds up to
  ``EXPORT_MAX_MARKS`` exportable marks. ``omitted_client_marks`` counts the
  client marks of the whole window (own client marks plus module entries
  naming a client), the same on every page of one window.
* **hard limit**: ``EXPORT_MAX_MARKS`` marks per answer; more is marked
  with ``truncated`` and ``next_cursor`` (the cursor of the timeline, sent
  back as ``cursor`` with the same window), nothing is dropped silently.
* **audited**: every export is an audit entry ``time_machine.exported``
  (counts only, the user as actor) written before the answer leaves; if
  it cannot be written the export is refused (503 ``audit_unavailable``).
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from typing import Any, Final

from homeassistant.core import HomeAssistant

from .tm_marks import QUOTA_CLIENTS
from .tm_query import (
    API_VERSION,
    QUERY_KEYS,
    STATUS_OFF,
    STATUS_UNAVAILABLE,
    Query,
    async_timeline,
    time_machine_enabled,
)
from .tm_sources import REASON_NOT_LOADED, REASON_NOT_RUNNING

_LOGGER = logging.getLogger(__name__)

EXPORT_KIND: Final = "openwrt_router.time_machine.export"
EXPORT_MAX_MARKS: Final = 5000
EXPORT_EVENT: Final = "time_machine.exported"
# The timeline keys without ``limit`` (fixed), ``spans`` (always on) and
# ``client`` (client marks are never exported).
EXPORT_QUERY_KEYS: Final = QUERY_KEYS - {"limit", "spans", "client"}
_NAMES: Final = ("router_name", "client_name", "text")
# Marks handled between two yields to the event loop (review I).
EXPORT_YIELD_EVERY: Final = 1000


class ExportRefused(Exception):
    """The audit entry could not be written: no export."""


async def _client_marks_in(engine: Any, since: float, until: float) -> int:
    """Own client marks with ``since <= ts < until`` (yields)."""
    found = 0
    for i, mark in enumerate(list(engine.index.marks.values())):
        if i and i % (EXPORT_YIELD_EVERY * 4) == 0:
            await asyncio.sleep(0)
        if mark.quota == QUOTA_CLIENTS and since <= mark.ts < until:
            found += 1
    return found


def export_mark(mark: dict[str, Any]) -> dict[str, Any]:
    """One timeline mark without names (the same keys)."""
    out = dict(mark)
    for key in _NAMES:
        if key in out:
            out[key] = None
    peers = out.get("peers")
    if isinstance(peers, dict):
        out["peers"] = {
            side: None
            if peer is None
            else {"router_id": peer.get("router_id"), "router_name": None}
            for side, peer in peers.items()
        }
    return out


def _empty(now: float, status: str, reason: str | None) -> dict[str, Any]:
    return {
        "v": API_VERSION,
        "kind": EXPORT_KIND,
        "status": status,
        "reason": reason,
        "generated_at": round(now, 3),
        "window": {"from": None, "until": None},
        "limit": EXPORT_MAX_MARKS,
        "marks": [],
        "spanning": [],
        "sources": [],
        "truncated": False,
        "spanning_truncated": False,
        "next_cursor": None,
        "omitted_client_marks": 0,
    }


async def async_export(
    hass: HomeAssistant, query: Query, *, now: float, user_id: str | None
) -> dict[str, Any]:
    """The export body (admins only, checked by the route).

    Raises :class:`ExportRefused` when the audit entry cannot be written.
    """
    from .tm_engine import async_get_time_machine

    if not time_machine_enabled(hass):
        return _empty(now, STATUS_OFF, None)
    engine = async_get_time_machine(hass)
    if engine is None or not engine.loaded:
        reason = REASON_NOT_RUNNING if engine is None else REASON_NOT_LOADED
        return _empty(now, STATUS_UNAVAILABLE, reason)
    wide = dataclasses.replace(
        query, limit=EXPORT_MAX_MARKS, spans=True, client=None, no_clients=True
    )
    body = await async_timeline(hass, wide, admin=True, now=now)
    omitted = int(body.get("omitted_client_marks") or 0)
    omitted += int(body.get("excluded_client_marks") or 0)
    omitted += await _client_marks_in(engine, wide.since, wide.until)
    marks: list[dict[str, Any]] = []
    spanning: list[dict[str, Any]] = []
    done = 0
    for target, items in ((marks, body["marks"]), (spanning, body["spanning"])):
        for mark in items:
            done += 1
            if done % EXPORT_YIELD_EVERY == 0:
                await asyncio.sleep(0)
            if mark.get("client") is not None:
                omitted += 1  # never (no_clients); kept as a last guard
                continue
            target.append(export_mark(mark))
    out = {
        "v": API_VERSION,
        "kind": EXPORT_KIND,
        "status": body["status"],
        "reason": None,
        "generated_at": body["generated_at"],
        "window": body["window"],
        "limit": EXPORT_MAX_MARKS,
        "marks": marks,
        "spanning": spanning,
        "sources": [
            {k: v for k, v in s.items() if k != "count"}
            | {"count": sum(1 for m in marks if m["source"] == s["id"])}
            for s in body["sources"]
        ],
        "truncated": body["truncated"],
        "spanning_truncated": body["spanning_truncated"],
        "next_cursor": body["next_cursor"],
        "omitted_client_marks": omitted,
    }
    await engine.async_bind_core()
    written = engine.emit_checked(
        EXPORT_EVENT,
        data={
            "marks": len(marks),
            "spanning": len(spanning),
            "omitted_client_marks": omitted,
            "truncated": bool(out["truncated"]),
            "window_s": round(wide.until - wide.since),
        },
        user_id=user_id,
    )
    if not written:
        raise ExportRefused
    return out


__all__ = [
    "EXPORT_EVENT",
    "EXPORT_KIND",
    "EXPORT_MAX_MARKS",
    "EXPORT_QUERY_KEYS",
    "ExportRefused",
    "async_export",
    "export_mark",
]
