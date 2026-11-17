"""Read-only views of the network intelligence for the panel API (P7).

The routes in ``topology_panel.py`` parse the request with the ``parse_*``
helpers and answer with the dicts built here. Everything reads the engine's
memory (``view``, ring, automaton); nothing here talks to a router.

``cause_level`` (RT6) is graded in ``net_rules.cause_level`` from the
cause status, the confidence and the independent source families of the
evidence (the stored events, looked up in the ring)::

    cause_status confirmed                                  -> "confirmed"
    hypothesis, confidence >= 0.7, >= 2 source families     -> "likely"
    hypothesis, confidence >= 0.4                           -> "possible"
    otherwise (lower confidence, no cause)                  -> "unknown"

An inferred topology edge caps the confidence at 0.6 (AK6), so a cause that
rests on one is at most "possible".
"""

from __future__ import annotations

import logging
import math
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .net_events import (
    Category,
    Incident,
    IncidentStatus,
    NetEvent,
    Severity,
)
from .net_rules import (
    WIFI_AUTH_KINDS,
    WIFI_RECONNECT_KIND,
    counted_incidents,
    counts_for_router,
    events_by_id,
    incident_area,
    incident_cause_level,
    suppressed_child,
)

_LOGGER = logging.getLogger(__name__)

_DAY = 86400

EVENTS_LIMIT_DEFAULT = 100
EVENTS_LIMIT_MAX = 500
INCIDENTS_LIMIT_DEFAULT = 100
INCIDENTS_LIMIT_MAX = 200
# Events of the event chain in an incident detail (newest kept).
CHAIN_LIMIT = 100
TOP_CLIENTS = 10
IGNORE_DAYS_MAX = 365
_PARAM_MAX = 128

_STATUS_ORDER = {
    IncidentStatus.ACTIVE: 0,
    IncidentStatus.ACKNOWLEDGED: 1,
    IncidentStatus.IGNORED: 2,
    IncidentStatus.RESOLVED: 3,
}
_SEVERITIES = tuple(s.value for s in Severity)

type NameOf = Callable[[str], str]


class QueryError(ValueError):
    """A request parameter or body is invalid (HTTP 400)."""


# --- request parsing -------------------------------------------------------------


def _text(query: Mapping[str, str], name: str) -> str | None:
    value = query.get(name)
    if value is None or value == "":
        return None
    if len(value) > _PARAM_MAX:
        raise QueryError(f"{name}: too long")
    return value


def _int(query: Mapping[str, str], name: str, default: int, upper: int) -> int:
    raw = _text(query, name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise QueryError(f"{name}: whole number expected") from None
    if not 1 <= value <= upper:
        raise QueryError(f"{name}: must be between 1 and {upper}")
    return value


def _time(query: Mapping[str, str], name: str) -> float | None:
    raw = _text(query, name)
    if raw is None:
        return None
    try:
        value = float(raw)
    except ValueError:
        raise QueryError(f"{name}: epoch seconds expected") from None
    if not math.isfinite(value):
        raise QueryError(f"{name}: epoch seconds expected")
    return value


def _choice(query: Mapping[str, str], name: str, allowed: Iterable[str]) -> str | None:
    allowed = tuple(allowed)  # a generator would be used up by the check
    raw = _text(query, name)
    if raw is not None and raw not in allowed:
        raise QueryError(f"{name}: one of {', '.join(sorted(allowed))} expected")
    return raw


def parse_events_query(query: Mapping[str, str]) -> dict[str, Any]:
    """Filters of ``GET intelligence/events`` (plan c10)."""
    since = _time(query, "since")
    until = _time(query, "until")
    if since is not None and until is not None and until <= since:
        raise QueryError("until: must be after since")
    return {
        "router": _text(query, "router"),
        "category": _choice(query, "category", (c.value for c in Category)),
        "severity": _choice(query, "severity", _SEVERITIES),
        "kind": _text(query, "kind"),
        "since": since,
        "until": until,
        "mac": _text(query, "mac"),
        "limit": _int(query, "limit", EVENTS_LIMIT_DEFAULT, EVENTS_LIMIT_MAX),
        "before": _text(query, "before"),
    }


def parse_incidents_query(query: Mapping[str, str]) -> dict[str, Any]:
    """Filters of ``GET intelligence/incidents``; ``status`` may list several
    values separated by commas."""
    statuses: frozenset[IncidentStatus] | None = None
    raw = _text(query, "status")
    if raw is not None:
        try:
            statuses = frozenset(IncidentStatus(s) for s in raw.split(","))
        except ValueError:
            allowed = ", ".join(s.value for s in IncidentStatus)
            raise QueryError(f"status: one or more of {allowed} expected") from None
    return {
        "status": statuses,
        "router": _text(query, "router"),
        "severity": _choice(query, "severity", _SEVERITIES),
        "limit": _int(query, "limit", INCIDENTS_LIMIT_DEFAULT, INCIDENTS_LIMIT_MAX),
    }


def parse_status_body(body: Any) -> tuple[str, float | None]:
    """Body of ``POST intelligence/incidents/{id}``: new status, ignore days."""
    if not isinstance(body, dict):
        raise QueryError("body: object expected")
    unknown = set(body) - {"status", "ignore_days"}
    if unknown:
        raise QueryError(f"{min(unknown)}: unknown key")
    status = body.get("status")
    allowed = (
        IncidentStatus.ACKNOWLEDGED.value,
        IncidentStatus.IGNORED.value,
        IncidentStatus.ACTIVE.value,
    )
    if status not in allowed:
        raise QueryError(f"status: one of {', '.join(allowed)} expected")
    days = body.get("ignore_days")
    if days is None:
        return status, None
    if status != IncidentStatus.IGNORED.value:
        raise QueryError("ignore_days: only with status ignored")
    if (
        isinstance(days, bool)
        or not isinstance(days, (int, float))
        or not 0 < days <= IGNORE_DAYS_MAX
    ):
        raise QueryError(f"ignore_days: number above 0 and up to {IGNORE_DAYS_MAX}")
    return status, float(days)


# --- answers ---------------------------------------------------------------------


def engine_now(engine: Any, wall: float) -> float:
    """The wall clock, but never behind the engine's last step (its clock
    never goes backwards, so durations and windows stay consistent)."""
    last = engine.machine.last_now
    return wall if last is None else max(wall, last)


def _empty_counts() -> dict[str, int]:
    return dict.fromkeys(_SEVERITIES, 0)


def router_badges(
    incidents: Iterable[Incident], now: float | None = None
) -> dict[str, dict[str, int]]:
    """Counted incidents (open roots at ``now``) per router and severity:
    the warning symbols of the topology (snapshot ``attributes.incidents``).
    Fleet incidents count for no single router (``counts_for_router``)."""
    out: dict[str, dict[str, int]] = {}
    for inc in counted_incidents(incidents, now):
        for router in inc.routers:
            if counts_for_router(inc, router):
                out.setdefault(router, _empty_counts())[inc.severity.value] += 1
    return out


def event_dict(event: NetEvent, name_of: NameOf) -> dict[str, Any]:
    """An event for the panel: the full record plus the router name."""
    out = event.to_dict()
    out["router_name"] = name_of(event.router)
    return out


def incident_dict(
    inc: Incident,
    name_of: NameOf,
    now: float,
    *,
    known: Mapping[str, Incident] | None = None,
    evidence: bool = False,
    events: Mapping[str, NetEvent] | None = None,
) -> dict[str, Any]:
    """An incident for the panel; without ``evidence`` only its count.

    Extra fields: ``cause_level`` (graded with the stored ``events`` by id;
    without them from one family at most), ``area`` (score area, None = none),
    ``router_names``, ``duration_s`` (current episode: since the reopen or
    the first sighting, up to the resolve time, also of an ignored
    incident whose condition ended, or ``now``) and ``child``
    (a silent child of a known incident, ``suppressed_child``: it does not
    count on its own).
    """
    out = inc.to_dict()
    items = out.pop("evidence")
    if evidence:
        out["evidence"] = items
    out["evidence_count"] = len(items)
    out["cause_level"] = incident_cause_level(inc, events or {}).value
    out["area"] = incident_area(inc.type)
    out["router_names"] = [name_of(r) for r in inc.routers]
    start = inc.reopened_at if inc.reopened_at is not None else inc.first_seen
    # the condition ended: resolved, or ignored and cleared since (P7 review)
    end = (
        inc.resolved_at
        if inc.status in (IncidentStatus.RESOLVED, IncidentStatus.IGNORED)
        else None
    )
    if end is None:
        end = max(now, inc.last_seen)
    out["duration_s"] = max(0.0, round(end - start, 1))
    out["child"] = suppressed_child(inc, known or {}, now)
    return out


def summary(engine: Any, name_of: NameOf, now: float) -> dict[str, Any]:
    """``GET intelligence/summary``: score and coverage per router and fleet,
    counted incidents by severity, event counts of the last 24 h, the WLAN
    clients with the most problem events."""
    incidents = engine.machine.peek()
    badges = router_badges(incidents, now)
    counted = counted_incidents(incidents, now)
    by_severity = _empty_counts()
    for inc in counted:
        by_severity[inc.severity.value] += 1
    open_states = (IncidentStatus.ACTIVE, IncidentStatus.ACKNOWLEDGED)
    view = engine.view
    routers = []
    for router, rv in sorted(view.routers.items()):
        routers.append(
            {
                "id": router,
                "name": name_of(router),
                "score": rv.score.score,
                "coverage": rv.score.coverage,
                "areas": rv.score.areas,
                "offline": rv.score.offline,
                "maintenance": rv.maintenance,
                "incidents_active": rv.incidents_active,
                "critical": rv.critical,
                "reconnects_1h": rv.reconnects_1h,
                "auth_errors_1h": rv.auth_errors_1h,
                "wan_reconnects_24h": rv.wan_reconnects_24h,
                "incidents": badges.get(router, _empty_counts()),
            }
        )
    since = now - _DAY
    by_category: Counter[str] = Counter()
    events_by_severity: Counter[str] = Counter()
    clients: dict[str, dict[str, Any]] = {}
    for event in engine.ring:
        if event.ts < since or event.ts > now:
            continue
        by_category[event.category.value] += event.count
        events_by_severity[event.severity.value] += event.count
        mac = event.subject.get("mac") if event.category is Category.WIFI else None
        if not isinstance(mac, str) or not mac:
            continue
        entry = clients.setdefault(
            mac.upper(),
            {
                "mac": mac.upper(),
                "router": event.router,
                "events": 0,
                "reconnects": 0,
                "auth_errors": 0,
                "last_ts": event.ts,
            },
        )
        entry["events"] += event.count
        if event.kind == WIFI_RECONNECT_KIND:
            entry["reconnects"] += event.count
        elif event.kind in WIFI_AUTH_KINDS:
            entry["auth_errors"] += event.count
        if event.ts >= entry["last_ts"]:
            entry["last_ts"] = event.ts
            entry["router"] = event.router
    top = sorted(clients.values(), key=lambda c: (-c["events"], c["mac"]))[:TOP_CLIENTS]
    for client in top:
        client["router_name"] = name_of(client["router"])
    fleet = view.fleet
    until = engine.settings.get("maintenance", {}).get("fleet_until")
    return {
        "generated_at": now,
        "loaded": engine.loaded,
        "load_failed": engine.load_failed,
        "fleet": {
            "score": fleet.score,
            "coverage": fleet.coverage,
            "routers": fleet.routers,
            "maintenance": fleet.maintenance,
            "maintenance_until": until if isinstance(until, (int, float)) else None,
            "incidents_active": fleet.incidents_active,
            "critical": fleet.critical,
        },
        "routers": routers,
        "incidents": by_severity,
        "incidents_open_total": sum(1 for i in incidents if i.status in open_states),
        "incidents_ignored": sum(
            1 for i in incidents if i.status is IncidentStatus.IGNORED
        ),
        "events_24h": dict(sorted(by_category.items())),
        "events_24h_by_severity": {
            s: events_by_severity.get(s, 0) for s in _SEVERITIES
        },
        "events_stored": len(engine.ring),
        "wifi": {"top_clients": top},
    }


def events_page(
    engine: Any, name_of: NameOf, filters: Mapping[str, Any]
) -> dict[str, Any]:
    """``GET intelligence/events``: newest first (store order).

    ``before`` is the id of the last event of the previous page; an id that
    is no longer stored ends the list (empty page). ``next_before`` is set
    when more events match.
    """
    mac = filters.get("mac")
    wanted_mac = mac.upper() if mac else None
    before = filters.get("before")
    limit = filters["limit"]
    started = before is None
    out: list[dict[str, Any]] = []
    more = False
    for event in reversed(list(engine.ring)):
        if not started:
            started = event.id == before
            continue
        if not _event_matches(event, filters, wanted_mac):
            continue
        if len(out) == limit:
            more = True
            break
        out.append(event_dict(event, name_of))
    return {
        "events": out,
        "next_before": out[-1]["id"] if more and out else None,
        "limit": limit,
    }


def _event_matches(
    event: NetEvent, filters: Mapping[str, Any], wanted_mac: str | None
) -> bool:
    since = filters.get("since")
    until = filters.get("until")
    return (
        (filters.get("router") is None or event.router == filters["router"])
        and (filters.get("category") is None or event.category == filters["category"])
        and (filters.get("severity") is None or event.severity == filters["severity"])
        and (filters.get("kind") is None or event.kind == filters["kind"])
        and (since is None or event.ts >= since)
        and (until is None or event.ts < until)
        and (
            wanted_mac is None
            or str(event.subject.get("mac", "")).upper() == wanted_mac
        )
    )


def _concerns(inc: Incident, router: str) -> bool:
    return router in inc.routers or inc.scope_key == router


def _sort_key(inc: Incident) -> tuple[int, int, float]:
    return (_STATUS_ORDER.get(inc.status, 9), -inc.severity.rank, -inc.last_seen)


def incidents_page(
    engine: Any, name_of: NameOf, filters: Mapping[str, Any], now: float
) -> dict[str, Any]:
    """``GET intelligence/incidents``: open before acknowledged, ignored and
    resolved; within that the most severe, then the newest first."""
    incidents = engine.machine.peek()
    known = {i.id: i for i in incidents}
    statuses = filters.get("status")
    router = filters.get("router")
    severity = filters.get("severity")
    matched = [
        inc
        for inc in incidents
        if (statuses is None or inc.status in statuses)
        and (router is None or _concerns(inc, router))
        and (severity is None or inc.severity == severity)
    ]
    matched.sort(key=_sort_key)
    limit = filters["limit"]
    events = events_by_id(engine.ring)
    return {
        "incidents": [
            incident_dict(inc, name_of, now, known=known, events=events)
            for inc in matched[:limit]
        ],
        "total": len(matched),
        "limit": limit,
    }


def incident_detail(
    engine: Any, incident_id: str, name_of: NameOf, now: float
) -> dict[str, Any] | None:
    """``GET intelligence/incidents/{id}``: the incident with its evidence
    (each with the stored event, if still in the ring), parent, children and
    the event chain (evidence and follow-up events by time, newest
    ``CHAIN_LIMIT``). None = unknown id."""
    inc = engine.machine.get(incident_id)
    if inc is None:
        return None
    incidents = engine.machine.peek()
    known = {i.id: i for i in incidents}
    evidence_ids = {e.get("id") for e in inc.evidence if isinstance(e.get("id"), str)}
    stored: dict[str, NetEvent] = {}
    follow_ups: list[NetEvent] = []
    events = events_by_id(engine.ring)
    for event in events.values():
        if event.id in evidence_ids:
            stored[event.id] = event
        elif event.parent_id == incident_id:
            follow_ups.append(event)
    detail = incident_dict(inc, name_of, now, known=known, evidence=True, events=events)
    detail["evidence"] = [
        {
            **item,
            "event": event_dict(stored[item["id"]], name_of)
            if item.get("id") in stored
            else None,
        }
        for item in detail["evidence"]
    ]
    chain = sorted([*stored.values(), *follow_ups], key=lambda e: (e.ts, e.id))[
        -CHAIN_LIMIT:
    ]
    parent = engine.machine.get(inc.parent_id) if inc.parent_id else None
    children = sorted(
        (i for i in incidents if i.parent_id == incident_id), key=_sort_key
    )
    return {
        "incident": detail,
        "parent": incident_dict(parent, name_of, now, known=known, events=events)
        if parent
        else None,
        "children": [
            incident_dict(c, name_of, now, known=known, events=events) for c in children
        ],
        "chain": [
            {
                **event_dict(e, name_of),
                "role": "evidence" if e.id in stored else "follow_up",
            }
            for e in chain
        ],
    }
