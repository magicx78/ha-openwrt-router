"""Data model for the network intelligence engine (events, incidents, counters).

Pure module, no Home Assistant imports. Time is never read from the clock
here: every function that needs "now" takes it as an argument.

Persistence contract: ``to_dict`` produces JSON-safe dicts, ``from_dict``
rebuilds the object leniently so a damaged store never crashes the load.
``from_dict`` returns ``None`` (it never raises) for a record that lacks a
required key, has a value of the wrong type for a required key, or carries an
invalid enum value. Unknown keys are ignored; missing optional keys (and
optional keys of the wrong type) fall back to the defaults.
"""

from __future__ import annotations

import copy
import logging
import math
from collections import deque
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, TypeVar

_LOGGER = logging.getLogger(__name__)

RETENTION_DAYS = 30
MAX_EVENTS = 3000
MAX_INCIDENTS = 500
MAX_EVIDENCE = 20
# Evidence entries per incident in the store file (compact form, P5): 500
# open incidents with 20 entries each alone need about 1.5 MB as HA writes
# it; with 5 they need about 0.54 MB and leave the rest for events.
STORE_EVIDENCE = 5
# Resolve reason of a router_unreachable whose entry was unloaded (P5
# review E7): its children get no after-window (P7 review E13).
ROUTER_REMOVED = "router_removed"
HOURLY_KEEP_HOURS = 48
CLOCK_SKEW_LIMIT = 300.0

_HOUR = 3600
_DAY = 86400
_MAX_BUCKET = 10**9  # hours since 1970 are about 490000; larger is damaged data


class Category(StrEnum):
    """Event category (plan c2)."""

    WIFI = "wifi"
    DHCP = "dhcp"
    SYSTEM = "system"
    LAN = "lan"
    WAN = "wan"
    DNS = "dns"
    MESH = "mesh"


class Origin(StrEnum):
    """Directly measured or derived."""

    OBSERVED = "observed"
    INFERRED = "inferred"


class Source(StrEnum):
    """Where an event came from."""

    LOG = "log"
    HOSTAPD = "hostapd"
    POLL = "poll"
    PROCD = "procd"
    NETIFD = "netifd"
    FLEET = "fleet"
    USTEER = "usteer"
    LLDP = "lldp"
    TOPOLOGY = "topology"


class Severity(StrEnum):
    """Event / incident severity."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Ordering value: info < warning < critical."""
        return _SEVERITY_RANK[self.value]


_SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}


class CauseStatus(StrEnum):
    """``confirmed`` only with measurement data, otherwise ``hypothesis``."""

    CONFIRMED = "confirmed"
    HYPOTHESIS = "hypothesis"


class IncidentStatus(StrEnum):
    """Incident life cycle."""

    ACTIVE = "active"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"
    IGNORED = "ignored"


class Scope(StrEnum):
    """What an incident is about; ``scope_key`` names the instance."""

    CLIENT = "client"
    RADIO = "radio"
    PORT = "port"
    ROUTER = "router"
    SEGMENT = "segment"
    FLEET = "fleet"


_E = TypeVar("_E", bound=StrEnum)


# --- lenient value readers (store data is untrusted) -----------------------


def _num(value: Any) -> float | None:
    """Finite number (not bool) as float, else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:  # an int beyond float range
        return None
    return number if math.isfinite(number) else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, value))


def _opt(data: Mapping[str, Any], key: str, reader: Any, default: Any) -> Any:
    """Optional key: read with ``reader`` or fall back to ``default``."""
    value = reader(data.get(key))
    return default if value is None else value


def _opt_str(data: Mapping[str, Any], key: str) -> str | None:
    value = data.get(key)
    return value if isinstance(value, str) else None


def _copy_json(value: dict[str, Any]) -> dict[str, Any]:
    """Copy of a flat dict; only nested containers are deep-copied (fast path)."""
    return {
        key: copy.deepcopy(item) if isinstance(item, (dict, list)) else item
        for key, item in value.items()
    }


def _opt_dict(data: Mapping[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    return copy.deepcopy(value) if isinstance(value, dict) else {}


class _InvalidRecord(ValueError):
    """Internal: a stored record cannot be used."""


def _enum(cls: type[_E], value: Any) -> _E:
    try:
        return cls(value)
    except ValueError as err:
        raise _InvalidRecord(f"invalid {cls.__name__}: {value!r}") from err


def _opt_enum(cls: type[_E], data: Mapping[str, Any], key: str, default: _E) -> _E:
    """Optional enum: missing/None gives the default, a bad value invalidates."""
    value = data.get(key)
    return default if value is None else _enum(cls, value)


def _require(data: Mapping[str, Any], *keys: str) -> None:
    for key in keys:
        if key not in data:
            raise _InvalidRecord(f"missing key: {key}")


# --- NetEvent ---------------------------------------------------------------


@dataclass(frozen=True)
class NetEvent:
    """One observed or inferred fact about the network."""

    id: str
    ts: float
    router: str
    category: Category
    kind: str
    origin: Origin = Origin.OBSERVED
    source: Source = Source.LOG
    subject: dict[str, Any] = field(default_factory=dict)
    signal: int | None = None
    count: int = 1
    severity: Severity = Severity.INFO
    cause: str | None = None
    cause_status: CauseStatus | None = None
    confidence: float = 1.0
    msg_key: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    maintenance: bool = False
    src_ts: float | None = None
    clock_skew: bool = False
    # P5: the incident this event is a follow-up of (correlation), or None
    parent_id: str | None = None

    def to_dict(self, *, compact: bool = False) -> dict[str, Any]:
        """JSON-safe dict, enums as plain strings.

        ``compact`` (the store format) leaves out fields that hold their
        default, and ``msg_key`` when it equals ``kind``; ``from_dict``
        restores both, and still reads the full form.
        """
        full = {
            "id": self.id,
            "ts": self.ts,
            "router": self.router,
            "category": self.category.value,
            "kind": self.kind,
            "origin": self.origin.value,
            "source": self.source.value,
            "subject": _copy_json(self.subject),
            "signal": self.signal,
            "count": self.count,
            "severity": self.severity.value,
            "cause": self.cause,
            "cause_status": self.cause_status.value if self.cause_status else None,
            "confidence": self.confidence,
            "msg_key": self.msg_key,
            "params": _copy_json(self.params),
            "maintenance": self.maintenance,
            "src_ts": self.src_ts,
            "clock_skew": self.clock_skew,
            "parent_id": self.parent_id,
        }
        if not compact:
            return full
        out = {
            key: value
            for key, value in full.items()
            if key in _EVENT_REQUIRED or value != _EVENT_DEFAULTS.get(key, _MISSING)
        }
        if self.msg_key == self.kind:
            out.pop("msg_key", None)
        else:
            out["msg_key"] = self.msg_key  # also "" (differs from the default)
        return out

    @classmethod
    def from_dict(cls, data: Any) -> NetEvent | None:
        """Rebuild from a stored dict; ``None`` if unusable (see module doc)."""
        if not isinstance(data, dict):
            return None
        try:
            return cls._build(data)
        except _InvalidRecord as err:
            _LOGGER.debug("Skipping stored event: %s", err)
            return None

    @classmethod
    def _build(cls, data: dict[str, Any]) -> NetEvent:
        _require(data, "id", "ts", "router", "category", "kind")
        ev_id, router, kind = data["id"], data["router"], data["kind"]
        ts = _num(data["ts"])
        if (
            ts is None
            or not isinstance(ev_id, str)
            or not isinstance(router, str)
            or not isinstance(kind, str)
        ):
            raise _InvalidRecord("wrong type in required key")
        status = data.get("cause_status")
        return cls(
            id=ev_id,
            ts=ts,
            router=router,
            category=_enum(Category, data["category"]),
            kind=kind,
            origin=_opt_enum(Origin, data, "origin", Origin.OBSERVED),
            source=_opt_enum(Source, data, "source", Source.LOG),
            subject=_opt_dict(data, "subject"),
            signal=_int(data.get("signal")),
            count=max(1, _opt(data, "count", _int, 1)),
            severity=_opt_enum(Severity, data, "severity", Severity.INFO),
            cause=_opt_str(data, "cause"),
            cause_status=None if status is None else _enum(CauseStatus, status),
            confidence=_clamp01(_opt(data, "confidence", _num, 1.0)),
            # Missing: the compact form left it out because it equals kind.
            msg_key=kind if "msg_key" not in data else _opt_str(data, "msg_key") or "",
            params=_opt_dict(data, "params"),
            maintenance=data.get("maintenance") is True,
            src_ts=_num(data.get("src_ts")),
            clock_skew=data.get("clock_skew") is True,
            parent_id=_opt_str(data, "parent_id"),
        )


_MISSING = object()
_EVENT_REQUIRED = frozenset({"id", "ts", "router", "category", "kind"})
# Values ``NetEvent.to_dict(compact=True)`` leaves out (the field defaults).
_EVENT_DEFAULTS: dict[str, Any] = {
    "origin": Origin.OBSERVED.value,
    "source": Source.LOG.value,
    "subject": {},
    "signal": None,
    "count": 1,
    "severity": Severity.INFO.value,
    "cause": None,
    "cause_status": None,
    "confidence": 1.0,
    "params": {},
    "maintenance": False,
    "src_ts": None,
    "clock_skew": False,
    "parent_id": None,
}


# --- Incident ---------------------------------------------------------------


@dataclass
class Incident:
    """A tracked problem, deduplicated by (``type``, ``scope_key``)."""

    id: str
    type: str
    scope: Scope
    scope_key: str
    status: IncidentStatus = IncidentStatus.ACTIVE
    severity: Severity = Severity.INFO
    confidence: float = 1.0
    origin: Origin = Origin.OBSERVED
    cause: str | None = None
    cause_status: CauseStatus | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    parent_id: str | None = None
    children: int = 0
    routers: list[str] = field(default_factory=list)
    affected: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    resolved_at: float | None = None
    reopen_count: int = 0
    occurrences: int = 0
    ignore_until: float | None = None
    # P5 review E6: start of the current episode after a reopen (the
    # correlation links a reopened incident by this time, not first_seen)
    reopened_at: float | None = None
    # P6 review L2: the cause was taken over from the parent when linking
    # (set by the correlation, not guessed from the value on release)
    cause_inherited: bool = False
    # P7 review E13: why the incident resolved (the transition reason, e.g.
    # ``ROUTER_REMOVED``); None while open and after a reopen
    resolve_reason: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        """Dedup key."""
        return (self.type, self.scope_key)

    def copy(self) -> Incident:
        """Independent copy (lists and dicts duplicated)."""
        return replace(
            self,
            evidence=copy.deepcopy(self.evidence),
            routers=list(self.routers),
        )

    def to_dict(self, *, compact: bool = False) -> dict[str, Any]:
        """JSON-safe dict, enums as plain strings.

        ``compact`` (the store format, P5) leaves out optional fields that
        hold their default, and ``last_seen`` when it equals ``first_seen``,
        and keeps only the newest ``STORE_EVIDENCE`` evidence entries;
        ``from_dict`` restores the fields and still reads the full form.
        """
        full = {
            "id": self.id,
            "type": self.type,
            "scope": self.scope.value,
            "scope_key": self.scope_key,
            "status": self.status.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "origin": self.origin.value,
            "cause": self.cause,
            "cause_status": self.cause_status.value if self.cause_status else None,
            "evidence": copy.deepcopy(self.evidence),
            "parent_id": self.parent_id,
            "children": self.children,
            "routers": list(self.routers),
            "affected": self.affected,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "resolved_at": self.resolved_at,
            "reopen_count": self.reopen_count,
            "occurrences": self.occurrences,
            "ignore_until": self.ignore_until,
            "reopened_at": self.reopened_at,
            "cause_inherited": self.cause_inherited,
            "resolve_reason": self.resolve_reason,
        }
        if not compact:
            return full
        out = {
            key: value
            for key, value in full.items()
            if key in _INCIDENT_REQUIRED
            or value != _INCIDENT_DEFAULTS.get(key, _MISSING)
        }
        if self.last_seen == self.first_seen:
            out.pop("last_seen", None)
        if len(self.evidence) > STORE_EVIDENCE:
            out["evidence"] = out["evidence"][-STORE_EVIDENCE:]
        return out

    @classmethod
    def from_dict(cls, data: Any) -> Incident | None:
        """Rebuild from a stored dict; ``None`` if unusable (see module doc)."""
        if not isinstance(data, dict):
            return None
        try:
            return cls._build(data)
        except _InvalidRecord as err:
            _LOGGER.debug("Skipping stored incident: %s", err)
            return None

    @classmethod
    def _build(cls, data: dict[str, Any]) -> Incident:
        _require(data, "id", "type", "scope", "scope_key", "status", "first_seen")
        inc_id, inc_type, key = data["id"], data["type"], data["scope_key"]
        first_seen = _num(data["first_seen"])
        if (
            first_seen is None
            or not isinstance(inc_id, str)
            or not isinstance(inc_type, str)
            or not isinstance(key, str)
        ):
            raise _InvalidRecord("wrong type in required key")
        status = data.get("cause_status")
        evidence = data.get("evidence")
        routers = data.get("routers")
        return cls(
            id=inc_id,
            type=inc_type,
            scope=_enum(Scope, data["scope"]),
            scope_key=key,
            status=_enum(IncidentStatus, data["status"]),
            severity=_opt_enum(Severity, data, "severity", Severity.INFO),
            confidence=_clamp01(_opt(data, "confidence", _num, 1.0)),
            origin=_opt_enum(Origin, data, "origin", Origin.OBSERVED),
            cause=_opt_str(data, "cause"),
            cause_status=None if status is None else _enum(CauseStatus, status),
            evidence=[
                copy.deepcopy(e)
                for e in (evidence if isinstance(evidence, list) else [])
                if isinstance(e, dict)
            ][-MAX_EVIDENCE:],
            parent_id=_opt_str(data, "parent_id"),
            children=max(0, _opt(data, "children", _int, 0)),
            routers=[
                r
                for r in (routers if isinstance(routers, list) else [])
                if isinstance(r, str)
            ],
            affected=max(0, _opt(data, "affected", _int, 0)),
            first_seen=first_seen,
            last_seen=_opt(data, "last_seen", _num, first_seen),
            resolved_at=_num(data.get("resolved_at")),
            reopen_count=max(0, _opt(data, "reopen_count", _int, 0)),
            occurrences=max(0, _opt(data, "occurrences", _int, 0)),
            ignore_until=_num(data.get("ignore_until")),
            reopened_at=_num(data.get("reopened_at")),
            cause_inherited=data.get("cause_inherited") is True,
            resolve_reason=_opt_str(data, "resolve_reason"),
        )


_INCIDENT_REQUIRED = frozenset(
    {"id", "type", "scope", "scope_key", "status", "first_seen"}
)
# Values ``Incident.to_dict(compact=True)`` leaves out (the field defaults).
_INCIDENT_DEFAULTS: dict[str, Any] = {
    "severity": Severity.INFO.value,
    "confidence": 1.0,
    "origin": Origin.OBSERVED.value,
    "cause": None,
    "cause_status": None,
    "evidence": [],
    "parent_id": None,
    "children": 0,
    "routers": [],
    "affected": 0,
    "resolved_at": None,
    "reopen_count": 0,
    "occurrences": 0,
    "ignore_until": None,
    "reopened_at": None,
    "cause_inherited": False,
    "resolve_reason": None,
}


def prune_incidents(
    incidents: Iterable[Incident],
    now: float,
    *,
    max_count: int = MAX_INCIDENTS,
    retention_days: int = RETENTION_DAYS,
) -> list[Incident]:
    """Return the incidents to keep (new list, input order preserved).

    Active and acknowledged incidents are never dropped, whatever the cap.
    Resolved and ignored ones older than the retention go first; if the list
    is still over ``max_count``, the oldest resolved (then ignored) follow.
    """
    items = list(incidents)
    cutoff = now - retention_days * _DAY
    items = [i for i in items if not (_droppable(i) and i.last_seen < cutoff)]
    excess = len(items) - max_count
    if excess <= 0:
        return items
    candidates = sorted(
        (i for i in items if _droppable(i)),
        key=lambda i: (i.status is IncidentStatus.IGNORED, i.last_seen),
    )
    drop = {id(i) for i in candidates[:excess]}
    return [i for i in items if id(i) not in drop]


def _droppable(incident: Incident) -> bool:
    return incident.status in (IncidentStatus.RESOLVED, IncidentStatus.IGNORED)


# --- EventRing --------------------------------------------------------------


class EventRing:
    """Bounded event buffer: at most ``max_count`` events, none older than ``max_age``.

    Iteration order is insertion order (oldest first, newest last). The oldest
    entries are dropped first. Age is judged by ``NetEvent.ts``; events with a
    timestamp in the future (clock went backwards) are kept.
    """

    def __init__(
        self, max_count: int = MAX_EVENTS, max_age: float = RETENTION_DAYS * _DAY
    ) -> None:
        self.max_count = max_count
        self.max_age = max_age
        self._items: deque[NetEvent] = deque(maxlen=max_count)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[NetEvent]:
        return iter(self._items)

    def add(self, event: NetEvent) -> None:
        """Append an event; the oldest one falls out when the ring is full."""
        self._items.append(event)

    def prune(self, now: float) -> int:
        """Drop events older than ``max_age``; return how many were dropped."""
        cutoff = now - self.max_age
        keep = [e for e in self._items if e.ts >= cutoff]
        dropped = len(self._items) - len(keep)
        if dropped:
            self._items = deque(keep, maxlen=self.max_count)
        return dropped

    def resize(self, max_count: int, max_age: float) -> int:
        """Apply new limits (P7 settings); return how many events were dropped.

        A smaller ``max_count`` keeps the newest events; events beyond the
        new ``max_age`` go with the next ``prune``.
        """
        before = len(self._items)
        self.max_count = max_count
        self.max_age = max_age
        self._items = deque(self._items, maxlen=max_count)
        return before - len(self._items)

    def shift(self, delta: float) -> None:
        """Move every event's ``ts`` by ``delta`` (large clock jump back).

        ``src_ts`` (the router's own time) stays as it was.
        """
        if delta:
            self._items = deque(
                (replace(e, ts=e.ts + delta) for e in self._items),
                maxlen=self.max_count,
            )

    def set_parents(self, links: Mapping[str, str]) -> int:
        """Set ``parent_id`` of the events in ``links`` (event id -> incident
        id); return how many changed. Events that have a parent keep it."""
        if not links:
            return 0
        changed = 0
        items: list[NetEvent] = []
        for event in self._items:
            parent = links.get(event.id)
            if parent is not None and event.parent_id is None:
                event = replace(event, parent_id=parent)
                changed += 1
            items.append(event)
        if changed:
            self._items = deque(items, maxlen=self.max_count)
        return changed

    def remove_router(self, entry_id: str) -> int:
        """Drop all events of one router; return how many were removed."""
        keep = [e for e in self._items if e.router != entry_id]
        removed = len(self._items) - len(keep)
        if removed:
            self._items = deque(keep, maxlen=self.max_count)
        return removed

    def filter(
        self,
        *,
        router: str | None = None,
        category: Category | str | None = None,
        severity: Severity | str | None = None,
        kind: str | None = None,
        since: float | None = None,
        until: float | None = None,
        mac: str | None = None,
        limit: int | None = None,
    ) -> list[NetEvent]:
        """Events matching all given criteria, oldest first.

        ``severity`` matches exactly; ``since`` is inclusive, ``until``
        exclusive; ``mac`` is compared case-insensitively against
        ``subject["mac"]``. With ``limit`` the newest ``limit`` matches
        are returned.
        """
        wanted_mac = mac.upper() if mac else None
        out = [
            e
            for e in self._items
            if (router is None or e.router == router)
            and (category is None or e.category == category)
            and (severity is None or e.severity == severity)
            and (kind is None or e.kind == kind)
            and (since is None or e.ts >= since)
            and (until is None or e.ts < until)
            and (
                wanted_mac is None
                or str(e.subject.get("mac", "")).upper() == wanted_mac
            )
        ]
        if limit is not None:
            out = out[-limit:] if limit > 0 else []
        return out

    def to_list(self, *, compact: bool = False) -> list[dict[str, Any]]:
        """All events as JSON-safe dicts, oldest first (see ``NetEvent.to_dict``)."""
        return [e.to_dict(compact=compact) for e in self._items]

    @classmethod
    def from_list(
        cls,
        records: Any,
        max_count: int = MAX_EVENTS,
        max_age: float = RETENTION_DAYS * _DAY,
    ) -> EventRing:
        """Load stored records; unusable ones are skipped."""
        ring = cls(max_count, max_age)
        if not isinstance(records, list):
            return ring
        for record in records:
            event = NetEvent.from_dict(record)
            if event is not None:
                ring.add(event)
        return ring


# --- Counters ---------------------------------------------------------------


class EventCounters:
    """Hourly then daily counters per (router, kind).

    Hourly buckets live for ``HOURLY_KEEP_HOURS`` (48 h); older ones are
    folded into daily buckets, which live ``retention_days``. Bucket indexes
    are ``ts // 3600`` and ``ts // 86400`` (UTC).
    """

    def __init__(self, retention_days: int = RETENTION_DAYS) -> None:
        self.retention_days = retention_days
        # router -> kind -> {"h": {hour: n}, "d": {day: n}}
        self._data: dict[str, dict[str, dict[str, dict[int, int]]]] = {}

    def add(self, router: str, kind: str, ts: float, n: int = 1) -> None:
        """Count ``n`` occurrences at time ``ts``.

        Ignored unless ``n`` is an int >= 1 and ``ts`` a finite number.
        """
        if _int(n) is None or n < 1 or _num(ts) is None:
            return
        buckets = self._data.setdefault(router, {}).setdefault(kind, {"h": {}, "d": {}})
        hour = int(ts // _HOUR)
        buckets["h"][hour] = buckets["h"].get(hour, 0) + n

    def prune(self, now: float) -> None:
        """Fold hourly buckets older than 48 h into days; drop old days."""
        hour_cutoff = int(now // _HOUR) - HOURLY_KEEP_HOURS
        day_cutoff = int(now // _DAY) - self.retention_days
        for router in list(self._data):
            kinds = self._data[router]
            for kind in list(kinds):
                buckets = kinds[kind]
                for hour in [h for h in buckets["h"] if h <= hour_cutoff]:
                    day = hour // 24
                    buckets["d"][day] = buckets["d"].get(day, 0) + buckets["h"].pop(
                        hour
                    )
                for day in [d for d in buckets["d"] if d <= day_cutoff]:
                    del buckets["d"][day]
                if not buckets["h"] and not buckets["d"]:
                    del kinds[kind]
            if not kinds:
                del self._data[router]

    def hourly(self, router: str, kind: str, now: float, hours: int) -> int:
        """Occurrences in the last ``hours`` hour buckets (max 48)."""
        buckets = self._data.get(router, {}).get(kind)
        if not buckets:
            return 0
        first = int(now // _HOUR) - hours
        return sum(n for h, n in buckets["h"].items() if h > first)

    def daily(self, router: str, kind: str, now: float, days: int) -> int:
        """Occurrences in the last ``days`` day buckets (hourly ones included)."""
        buckets = self._data.get(router, {}).get(kind)
        if not buckets:
            return 0
        first = int(now // _DAY) - days
        hourly = sum(n for h, n in buckets["h"].items() if h // 24 > first)
        return hourly + sum(n for d, n in buckets["d"].items() if d > first)

    def remove_router(self, entry_id: str) -> None:
        """Forget all counters of one router."""
        self._data.pop(entry_id, None)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe: ``{router: {kind: {"h": {"<hour>": n}, "d": {"<day>": n}}}}``."""
        return {
            router: {
                kind: {
                    "h": {str(h): n for h, n in b["h"].items()},
                    "d": {str(d): n for d, n in b["d"].items()},
                }
                for kind, b in kinds.items()
            }
            for router, kinds in self._data.items()
        }

    @classmethod
    def from_dict(
        cls, data: Any, retention_days: int = RETENTION_DAYS
    ) -> EventCounters:
        """Load leniently: malformed routers, kinds and buckets are skipped."""
        counters = cls(retention_days)
        if not isinstance(data, dict):
            return counters
        for router, kinds in data.items():
            if not isinstance(router, str) or not isinstance(kinds, dict):
                continue
            for kind, raw in kinds.items():
                if not isinstance(kind, str) or not isinstance(raw, dict):
                    continue
                hourly = _load_buckets(raw.get("h"))
                daily = _load_buckets(raw.get("d"))
                if hourly or daily:
                    counters._data.setdefault(router, {})[kind] = {
                        "h": hourly,
                        "d": daily,
                    }
        return counters


def _load_buckets(raw: Any) -> dict[int, int]:
    out: dict[int, int] = {}
    if not isinstance(raw, dict):
        return out
    for key, value in raw.items():
        try:
            index = int(key)
        except (TypeError, ValueError):
            continue
        if abs(index) > _MAX_BUCKET:  # beyond any real hour or day
            continue
        count = _int(value)
        if count is not None and count > 0:
            out[index] = count
    return out


# --- Redaction --------------------------------------------------------------

_EVENT_KEEP = (
    "category",
    "kind",
    "origin",
    "source",
    "severity",
    "cause",
    "cause_status",
    "confidence",
    "msg_key",
    "signal",
    "count",
    "ts",
    "src_ts",
    "maintenance",
    "clock_skew",
)
_INCIDENT_KEEP = (
    "id",
    "type",
    "scope",
    "status",
    "severity",
    "confidence",
    "origin",
    "cause",
    "cause_status",
    "children",
    "affected",
    "first_seen",
    "last_seen",
    "resolved_at",
    "reopen_count",
    "occurrences",
    "ignore_until",
)


def redact_event(data: Mapping[str, Any]) -> dict[str, Any]:
    """Identity-free copy of an event dict.

    Whitelist: ``id`` (carries the router id), ``router``, ``subject``
    (mac, ssid, ...) and ``params`` are dropped.
    """
    return {k: data[k] for k in _EVENT_KEEP if k in data}


def redact_incident(data: Mapping[str, Any]) -> dict[str, Any]:
    """Identity-free copy of an incident dict.

    ``scope_key`` (often a MAC), ``routers`` and the evidence ids are
    dropped; the router count and the evidence kinds and times stay.
    """
    out = {k: data[k] for k in _INCIDENT_KEEP if k in data}
    routers = data.get("routers")
    if isinstance(routers, list):
        out["router_count"] = len(routers)
    evidence = data.get("evidence")
    if isinstance(evidence, list):
        out["evidence"] = [
            {k: e[k] for k in ("kind", "ts") if k in e}
            for e in evidence
            if isinstance(e, dict)
        ]
    return out


def redact_record(data: Mapping[str, Any]) -> dict[str, Any]:
    """Redact an incident (has ``type``) or an event (has ``kind``)."""
    if "type" in data and "scope" in data:
        return redact_incident(data)
    return redact_event(data)
