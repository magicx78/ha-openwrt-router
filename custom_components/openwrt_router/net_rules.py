"""Rules for the network intelligence engine: default settings and alarm state machine.

Pure module, no Home Assistant imports. Time is never read from the clock:
every entry point takes ``now`` (epoch seconds). Later work packages add the
detectors, correlation and health score to this module; this part holds only

* ``DEFAULT_SETTINGS`` / ``merge_settings`` (plan c7 and c8), and
* ``AlarmMachine``: turns evidence into ``Incident`` life cycles.

Rule modes (key ``mode`` of each ``thresholds`` entry, not user-editable)::

    window  count >= ``count`` evidence within ``window`` s opens; resolves when
            the last ``clear`` s hold fewer than ``clear_below`` (default 1)
            evidence. ``clear`` defaults to the general ``auto_resolve``.
    level   evidence carries ``value``; a value >= ``raise`` is a raising poll.
            ``debounce`` consecutive raising polls (and, if ``hold`` is set,
            ``hold`` s since the first of them) open the incident. A value
            below ``clear`` resolves it; values in between change nothing
            (hysteresis). Without any poll for ``auto_resolve`` s it resolves.
    event   a ``window`` rule with ``count`` 1 and no ``clear``: the first
            evidence opens, the general ``auto_resolve`` closes it later.

Other keys: ``cooldown`` (a trigger less than that many seconds after a
resolve reopens the same incident), ``severity``, optional ``escalate``
(``{"severity", "value"}`` for level rules, ``{"severity", "count", "window"}``
for window rules) and detector parameters the machine ignores.
"""

from __future__ import annotations

import copy
import logging
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .net_events import (
    CLOCK_SKEW_LIMIT,
    MAX_EVIDENCE,
    MAX_INCIDENTS,
    CauseStatus,
    Incident,
    IncidentStatus,
    NetEvent,
    Origin,
    Scope,
    Severity,
    prune_incidents,
)

_LOGGER = logging.getLogger(__name__)

INFERRED_CONFIDENCE_CAP = 0.6
MAX_TRACK_ENTRIES = 200
_DEFAULT_AUTO_RESOLVE = 1800.0
_DEFAULT_IGNORE_SECONDS = 7 * 86400.0


# --- default settings (plan c7, c8) -------------------------------------------


def _window(
    count: int,
    window: int,
    clear: int,
    cooldown: int,
    severity: str = "warning",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "mode": "window",
        "count": count,
        "window": window,
        "clear": clear,
        "cooldown": cooldown,
        "severity": severity,
        **extra,
    }


def _level(
    raise_at: float,
    clear: float,
    debounce: int,
    cooldown: int,
    severity: str = "warning",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "mode": "level",
        "raise": raise_at,
        "clear": clear,
        "debounce": debounce,
        "cooldown": cooldown,
        "severity": severity,
        **extra,
    }


def _event(cooldown: int, severity: str = "warning", **extra: Any) -> dict[str, Any]:
    return {
        "mode": "event",
        "count": 1,
        "cooldown": cooldown,
        "severity": severity,
        **extra,
    }


# Treat as read-only: use merge_settings() to get a private copy.
DEFAULT_SETTINGS: dict[str, Any] = {
    "schema": 1,
    "retention_days": 30,
    "max_events": 3000,
    "notify_min_severity": "warning",
    "score": {
        "weights": {"wifi": 30, "system": 25, "lan": 15, "wan": 20, "dhcp_dns": 10},
        "penalty": {"critical": 40, "warning": 15, "info": 3},
        "min_coverage": 0.5,
        "min_area_coverage": 0.3,
    },
    "thresholds": {
        # WLAN
        "wifi_reconnect_storm": _window(5, 600, 1800, 3600),
        "wifi_auth_failures": _window(3, 600, 1800, 3600),
        "wifi_auth_wave": _window(10, 600, 1800, 3600, clear_below=2, min_sources=3),
        "wifi_mass_disconnect": _event(600, window=30, min_clients=5, min_ratio=0.5),
        # value 1 = no IP although connected (dhcp_missing), 0 = has a lease
        "wifi_no_ip": _level(
            1, 1, 2, 3600, "info", dhcp_missing_after=180, warn_clients_per_ap=3
        ),
        "wifi_dhcp_after_connect": _window(1, 60, 1800, 3600),
        "wifi_band_flapping": _window(4, 600, 1800, 3600, "info"),
        "wifi_roam_flapping": _window(4, 600, 1800, 3600, "info"),
        # value = number of weak clients; the dBm limits are for the detector
        "wifi_weak_clients": _level(
            3, 3, 1, 3600, "info", hold=600, weak_dbm=-75, clear_dbm=-70
        ),
        # "3 of 5 measurements" is simplified to consecutive measurements
        "wifi_channel_busy": _level(70, 55, 3, 3600, "info"),
        # System
        "system_cpu_high": _level(80, 65, 3, 900),
        "system_ram_high": _level(85, 80, 1, 0, hold=900),
        "system_reboot": _event(0),
        "system_service_restart": _window(
            1,
            3600,
            600,
            900,
            escalate={"severity": "critical", "count": 3, "window": 3600},
        ),
        "system_clock_skew": _level(120, 30, 3, 3600),
        "system_conntrack_jump": _level(3.0, 1.5, 3, 3600, "info", min_count=5000),
        # LAN
        "lan_port_flap": _window(3, 600, 1800, 3600),
        "lan_port_speed_drop": _level(1, 1, 2, 3600),
        # value = error ratio in percent
        "lan_port_errors": _level(0.1, 0.01, 1, 3600, min_packets=1000, interval=300),
        "lan_port_load": _level(90, 70, 5, 1800, "info"),
        "lan_uplink_down": _level(
            1,
            1,
            1,
            600,
            "critical",
            inferred_severity="warning",
            inferred_confidence=0.6,
        ),
        "lan_lldp_change": _event(0, "info", states=2),
        # WAN
        "wan_down": _level(1, 1, 1, 300, "critical"),
        "wan_unstable": _window(3, 3600, 7200, 3600),
        "wan_ip_changed": _event(0, "info"),
        # DHCP
        "dhcp_pool_full": _level(
            90, 85, 2, 3600, escalate={"severity": "critical", "value": 98}
        ),
        "dhcp_conflict": _window(1, 3600, 3600, 3600),
        # general
        "auto_resolve": {"clear": 1800},
        "ignored": {"duration": 7 * 86400},
    },
    "exclusions": {"macs": [], "ssids": [], "routers": [], "incident_types": []},
    "maintenance": {"fleet_until": None},
    "optional_sources": {"hostapd_status": False},
}

_SEVERITY_KEYS = frozenset({"severity", "notify_min_severity", "inferred_severity"})
_FIXED_KEYS = frozenset({"schema", "mode"})
# Whole numbers >= 1 (a float like 3000.0 is accepted and stored as int).
_INT_KEYS = frozenset(
    {"count", "debounce", "clear_below", "retention_days", "max_events"}
)
_INT_UPPER = {"retention_days": 365, "max_events": 10_000}
# Durations that must be > 0 (``clear`` too, except in level rules).
_POSITIVE_KEYS = frozenset({"window", "duration"})
_FRACTION_KEYS = frozenset(
    {"min_coverage", "min_area_coverage", "min_ratio", "inferred_confidence"}
)
# Measured levels and dBm limits: any finite number.
_FREE_KEYS = frozenset({"raise", "value", "weak_dbm", "clear_dbm"})


def merge_settings(stored: Any) -> dict[str, Any]:
    """Overlay stored settings on the defaults; return a private deep copy.

    Unknown keys, values of the wrong type, non-finite numbers, values out
    of range and invalid severity names are discarded (the default stays).
    Ranges: counts, ``debounce``, ``clear_below`` whole numbers >= 1
    (``retention_days`` <= 365, ``max_events`` <= 10000); ``window``,
    ``duration`` and a duration ``clear`` > 0; fractions 0..1; level
    thresholds (``raise``, level ``clear``, ``escalate.value``) and dBm
    limits free; everything else >= 0. ``schema`` and the rule ``mode``
    cannot be changed.
    """
    return _overlay(DEFAULT_SETTINGS, stored, "", None)


def _overlay(default: Any, stored: Any, key: str, mode: str | None) -> Any:
    if isinstance(default, dict):
        if not isinstance(stored, dict):
            return copy.deepcopy(default)
        sub_mode = default.get("mode", mode)
        return {
            k: _overlay(v, stored[k], k, sub_mode) if k in stored else copy.deepcopy(v)
            for k, v in default.items()
        }
    if key in _FIXED_KEYS:
        return copy.deepcopy(default)
    if isinstance(default, list):
        if not isinstance(stored, list):
            return list(default)
        return [s for s in stored if isinstance(s, str)]
    if not _valid_leaf(default, stored, key, mode):
        return copy.deepcopy(default)
    return int(stored) if key in _INT_KEYS else stored


def _valid_leaf(default: Any, stored: Any, key: str, mode: str | None) -> bool:
    if key in _SEVERITY_KEYS:
        return isinstance(stored, str) and stored in Severity._value2member_map_
    if default is None:
        return stored is None or _is_number(stored)
    if isinstance(default, bool):
        return isinstance(stored, bool)
    if isinstance(default, (int, float)):
        return _is_number(stored) and _in_bounds(key, float(stored), mode)
    return isinstance(stored, type(default))


def _in_bounds(key: str, value: float, mode: str | None) -> bool:
    if key in _FREE_KEYS or (key == "clear" and mode == "level"):
        return True
    if key in _INT_KEYS:
        return value.is_integer() and 1 <= value <= _INT_UPPER.get(key, math.inf)
    if key == "clear" or key in _POSITIVE_KEYS:
        return value > 0
    if key in _FRACTION_KEYS:
        return 0 <= value <= 1
    return value >= 0


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


# --- evidence in, transitions out -------------------------------------------------


class TransitionState(StrEnum):
    """What happened to an incident during one ``update`` call."""

    OPENED = "opened"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    UPDATED = "updated"


@dataclass(frozen=True)
class Evidence:
    """One fact fed to the machine for an incident (``type``, ``scope_key``).

    ``value`` is the measured level for level rules; window rules count each
    evidence ``count`` times. Evidence marked ``maintenance`` is ignored.
    """

    type: str
    scope_key: str
    scope: Scope = Scope.ROUTER
    kind: str = ""
    event_id: str | None = None
    value: float | None = None
    count: int = 1
    router: str | None = None
    affected: int = 0
    severity: Severity | None = None
    confidence: float = 1.0
    origin: Origin = Origin.OBSERVED
    cause: str | None = None
    cause_status: CauseStatus | None = None
    maintenance: bool = False

    @classmethod
    def from_event(
        cls,
        event: NetEvent,
        type_: str,
        scope: Scope,
        scope_key: str,
        value: float | None = None,
    ) -> Evidence:
        """Build evidence from a ``NetEvent``."""
        return cls(
            type=type_,
            scope_key=scope_key,
            scope=scope,
            kind=event.kind,
            event_id=event.id,
            value=value,
            count=event.count,
            router=event.router,
            confidence=event.confidence,
            origin=event.origin,
            cause=event.cause,
            cause_status=event.cause_status,
            maintenance=event.maintenance,
        )


@dataclass(frozen=True)
class Transition:
    """A change of an incident; ``incident`` is a snapshot (a copy)."""

    state: TransitionState
    incident: Incident
    reason: str = ""


@dataclass(frozen=True)
class ClockStep:
    """Result of ``AlarmMachine.sync_clock``.

    ``now`` is the time to use for this step (never below the previous one
    for small backward steps); ``shift`` is how far all stored times were
    moved (0, or negative after a large backward jump).
    """

    now: float
    shift: float = 0.0


# Stale handling for a loaded incident whose type has no rule (yet): it
# resolves after the general ``auto_resolve`` without evidence.
_FALLBACK_RULE: dict[str, Any] = {"mode": "event", "count": 1, "cooldown": 0}


# --- internal per-(type, scope_key) tracking state ------------------------------------


@dataclass
class _Track:
    """Timers and counters behind one (type, scope_key); not part of ``Incident``."""

    type: str
    scope_key: str
    incident_id: str | None = None
    live: bool = False
    # window rules: [ts, count, event_id, kind]; level rules: the raising streak
    entries: list[list[Any]] | None = None
    last_evidence: float | None = None
    last_obs: float | None = None
    streak: int = 0
    pending_since: float | None = None

    def __post_init__(self) -> None:
        if self.entries is None:
            self.entries = []

    def reset_streak(self) -> None:
        self.streak = 0
        self.pending_since = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "scope_key": self.scope_key,
            "incident_id": self.incident_id,
            "live": self.live,
            "entries": [list(e) for e in self.entries or []],
            "last_evidence": self.last_evidence,
            "last_obs": self.last_obs,
            "streak": self.streak,
            "pending_since": self.pending_since,
        }

    @classmethod
    def from_dict(cls, data: Any) -> _Track | None:
        if not isinstance(data, dict):
            return None
        kind, key = data.get("type"), data.get("scope_key")
        if not isinstance(kind, str) or not isinstance(key, str):
            return None
        raw = data.get("entries")
        entries = [
            [float(e[0]), int(e[1]), e[2] if isinstance(e[2], str) else None, str(e[3])]
            for e in (raw if isinstance(raw, list) else [])
            if _valid_entry(e)
        ][-MAX_TRACK_ENTRIES:]
        incident_id = data.get("incident_id")
        streak = data.get("streak")
        return cls(
            type=kind,
            scope_key=key,
            incident_id=incident_id if isinstance(incident_id, str) else None,
            live=data.get("live") is True,
            entries=entries,
            last_evidence=_opt_num(data.get("last_evidence")),
            last_obs=_opt_num(data.get("last_obs")),
            streak=streak
            if isinstance(streak, int) and not isinstance(streak, bool) and streak > 0
            else 0,
            pending_since=_opt_num(data.get("pending_since")),
        )


def _opt_num(value: Any) -> float | None:
    return float(value) if _is_number(value) else None


def _valid_entry(entry: Any) -> bool:
    return (
        isinstance(entry, list)
        and len(entry) == 4
        and _is_number(entry[0])
        and isinstance(entry[1], int)
        and not isinstance(entry[1], bool)
        and entry[1] > 0
    )


# --- the state machine -------------------------------------------------------------------


class AlarmMachine:
    """Manages ``Incident`` life cycles per (``type``, ``scope_key``).

    Usage: call ``update(now, evidence)`` once per poll (also with no
    evidence, to let time-based transitions happen) and act on the returned
    transitions. Each transition is reported exactly once.

    Silent states: an ``ignored`` incident (until ``ignore_until``) emits no
    transitions at all; this holds for its (``type``, ``scope_key``) even
    after it resolved silently: a return before ``ignore_until`` reopens it
    silently, whatever the cooldown. An ``acknowledged`` incident emits no
    ``opened`` / ``updated`` / ``reopened`` but does emit ``resolved``.

    Severity only rises while an incident is open (escalation is sticky); a
    rise by rule or by evidence is reported as ``updated``. A reopen starts
    again from the rule severity and counts only evidence after the resolve.

    Dedup: one incident per (``type``, ``scope_key``); for window rules an
    evidence whose ``event_id`` is already among the tracked entries is
    dropped, so a re-read log line is not counted twice. Level rules take at
    most one observation per poll: a second one at the same ``now`` is
    dropped, so debounce counts polls, not evidence.

    Maintenance: evidence flagged ``maintenance`` never counts and breaks a
    running series (window entries, debounce streak, hold) of a
    (``type``, ``scope_key``) without an open incident.

    Types without a rule: their evidence is ignored; a loaded open incident
    of such a type resolves after the general ``auto_resolve``.

    Clock jumps (see ``sync_clock``): a step back of up to
    ``CLOCK_SKEW_LIMIT`` counts as "no time passed" (``now`` is held at the
    previous value). A larger step back shifts all stored timestamps by the
    same amount, so elapsed times stay as they were and nothing resolves or
    opens because of the jump. A forward jump cannot be told apart from real
    elapsed time: open incidents resolve, but ``resolved_at`` is the moment
    the condition cleared (last evidence + ``clear``), not the jumped clock;
    old window entries age out, and a level ``hold`` or debounce streak
    restarts after ``auto_resolve`` without polls, so a jump alone never
    opens an incident. Retention pruning pauses after a forward jump of more
    than ``CLOCK_SKEW_LIMIT`` until the clock moves on normally again.
    """

    def __init__(
        self,
        settings: Mapping[str, Any] | None = None,
        *,
        max_incidents: int = MAX_INCIDENTS,
    ) -> None:
        self._settings = merge_settings(settings)
        self._max_incidents = max_incidents
        self._incidents: dict[str, Incident] = {}
        self._tracks: dict[tuple[str, str], _Track] = {}
        self._seq = 0
        self._last_now: float | None = None
        self._prune_held = False

    # -- public ---------------------------------------------------------------

    @property
    def prune_held(self) -> bool:
        """True after a forward clock jump until time moves on normally."""
        return self._prune_held

    @property
    def last_now(self) -> float | None:
        """The effective time of the previous step, None before the first."""
        return self._last_now

    def sync_clock(self, now: float) -> ClockStep:
        """Advance the machine clock to ``now``; see the class doc on jumps.

        ``update`` calls this itself. A caller that stamps its own records
        (the engine) calls it first and uses ``ClockStep.now`` for them and
        for the following ``update``; ``ClockStep.shift`` tells it how far
        to move its own stored times. Raises ``ValueError`` for a time that
        is not a finite number.
        """
        if not _is_number(now):
            raise ValueError(f"invalid time: {now!r}")
        now = float(now)
        shift = 0.0
        last = self._last_now
        if last is not None:
            step = now - last
            if step < 0:
                if -step <= CLOCK_SKEW_LIMIT:
                    now = last  # small step back: no time passed
                else:
                    shift = step
                    self._shift(step)
            elif step > CLOCK_SKEW_LIMIT:
                self._prune_held = True
            elif step > 0:
                self._prune_held = False
        self._last_now = now
        return ClockStep(now, shift)

    def set_settings(self, settings: Mapping[str, Any] | None) -> None:
        """Replace the settings (merged over the defaults)."""
        self._settings = merge_settings(settings)

    def incidents(self) -> list[Incident]:
        """Copies of all incidents, oldest first."""
        return [i.copy() for i in self._incidents.values()]

    def get(self, incident_id: str) -> Incident | None:
        """Copy of one incident, or None."""
        inc = self._incidents.get(incident_id)
        return inc.copy() if inc else None

    def update(self, now: float, evidence: Iterable[Evidence] = ()) -> list[Transition]:
        """Advance time to ``now``, apply ``evidence``, return the transitions."""
        if not _is_number(now):
            _LOGGER.debug("Ignoring update with invalid time %r", now)
            return []
        out: list[Transition] = []
        now = self.sync_clock(now).now
        self._resolve_stale(now, out)
        self._expire_ignores(now, out)
        for item in evidence:
            self._ingest(now, item, out)
        if not self._prune_held:
            self._prune(now)
        return out

    def acknowledge(self, incident_id: str) -> bool:
        """Mark an active incident as acknowledged; False if it is not active."""
        inc = self._incidents.get(incident_id)
        if inc is None or inc.status is not IncidentStatus.ACTIVE:
            return False
        inc.status = IncidentStatus.ACKNOWLEDGED
        return True

    def ignore(self, incident_id: str, now: float, until: float | None = None) -> bool:
        """Suppress an open incident until ``until`` (default: settings duration).

        False if the incident is unknown or resolved, ``now`` is not a finite
        number, or ``until`` is not a finite number after ``now``.
        """
        if not _is_number(now) or (
            until is not None and (not _is_number(until) or until <= now)
        ):
            return False
        inc = self._incidents.get(incident_id)
        if inc is None or inc.status is IncidentStatus.RESOLVED:
            return False
        inc.status = IncidentStatus.IGNORED
        inc.ignore_until = until if until is not None else now + self._ignore_seconds()
        return True

    def remove_router(self, entry_id: str) -> int:
        """Forget a removed router; return how many incidents were dropped.

        Dropped with their tracks: incidents that only concern this router
        (``routers`` holds nothing else) and incidents whose ``scope_key`` is
        the router or starts with ``"<entry_id>:"`` (router-scoped keys). In
        incidents shared with other routers it is only taken off
        ``routers``. Tracks with such a ``scope_key`` go as well.
        """
        prefix = f"{entry_id}:"
        dropped = [
            inc_id
            for inc_id, inc in self._incidents.items()
            if (inc.routers and set(inc.routers) <= {entry_id})
            or inc.scope_key == entry_id
            or inc.scope_key.startswith(prefix)
        ]
        for inc_id in dropped:
            del self._incidents[inc_id]
        for inc in self._incidents.values():
            if entry_id in inc.routers:
                inc.routers = [r for r in inc.routers if r != entry_id]
        for key, track in list(self._tracks.items()):
            if (
                track.incident_id in dropped
                or track.scope_key == entry_id
                or track.scope_key.startswith(prefix)
            ):
                del self._tracks[key]
        return len(dropped)

    # -- persistence ---------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe state (settings are not included)."""
        return {
            "seq": self._seq,
            "last_now": self._last_now,
            "incidents": [i.to_dict() for i in self._incidents.values()],
            "tracks": [t.to_dict() for t in self._tracks.values()],
        }

    @classmethod
    def from_dict(
        cls,
        data: Any,
        settings: Mapping[str, Any] | None = None,
        *,
        max_incidents: int = MAX_INCIDENTS,
    ) -> AlarmMachine:
        """Restore leniently: unusable records are skipped, never raised."""
        machine = cls(settings, max_incidents=max_incidents)
        if not isinstance(data, dict):
            return machine
        for raw in _as_list(data.get("incidents")):
            inc = Incident.from_dict(raw)
            if inc is not None:
                machine._incidents[inc.id] = inc
        for raw in _as_list(data.get("tracks")):
            track = _Track.from_dict(raw)
            if track is not None:
                machine._tracks[(track.type, track.scope_key)] = track
        machine._seq = max(_as_int(data.get("seq")), machine._highest_id())
        machine._last_now = _opt_num(data.get("last_now"))
        machine._reconcile()
        return machine

    # -- internals -------------------------------------------------------------------

    def _highest_id(self) -> int:
        best = 0
        for inc_id in self._incidents:
            tail = inc_id.rpartition("-")[2]
            if tail.isdigit():
                best = max(best, int(tail))
        return best

    def _reconcile(self) -> None:
        """Make restored incidents and tracks agree; recreate lost tracks.

        Per (``type``, ``scope_key``) the track points at the open incident,
        else at the newest one, so a reopen inside the cooldown still works
        when the stored tracks were lost.
        """
        for track in self._tracks.values():
            if track.incident_id not in self._incidents:
                track.incident_id = None
                track.live = False
        latest: dict[tuple[str, str], Incident] = {}
        for inc in sorted(self._incidents.values(), key=lambda i: i.last_seen):
            cur = latest.get(inc.key)
            if cur is None or _is_open(inc) or not _is_open(cur):
                latest[inc.key] = inc
        for key, inc in latest.items():
            track = self._tracks.get(key)
            if track is None:
                track = self._tracks[key] = _Track(*key)
            cur = self._incidents.get(track.incident_id or "")
            if cur is None or (cur is not inc and not _is_open(cur)):
                track.incident_id = inc.id
                cur = inc
            track.live = _is_open(cur)
            if track.live and track.last_evidence is None:
                track.last_evidence = cur.last_seen
                track.last_obs = cur.last_seen
                track.entries = [[cur.last_seen, 1, None, ""]]

    def _shift(self, delta: float) -> None:
        for track in self._tracks.values():
            for entry in track.entries or []:
                entry[0] += delta
            track.last_evidence = _shifted(track.last_evidence, delta)
            track.last_obs = _shifted(track.last_obs, delta)
            track.pending_since = _shifted(track.pending_since, delta)
        for inc in self._incidents.values():
            inc.first_seen += delta
            inc.last_seen += delta
            inc.resolved_at = _shifted(inc.resolved_at, delta)
            inc.ignore_until = _shifted(inc.ignore_until, delta)
            for item in inc.evidence:
                if _is_number(item.get("ts")):
                    item["ts"] += delta

    def _rule(self, type_: str) -> dict[str, Any] | None:
        rule = self._settings["thresholds"].get(type_)
        if isinstance(rule, dict) and rule.get("mode") in ("window", "level", "event"):
            return rule
        return None

    def _auto_resolve(self) -> float:
        value = self._settings["thresholds"].get("auto_resolve", {}).get("clear")
        return float(value) if _is_number(value) else _DEFAULT_AUTO_RESOLVE

    def _ignore_seconds(self) -> float:
        value = self._settings["thresholds"].get("ignored", {}).get("duration")
        return float(value) if _is_number(value) else _DEFAULT_IGNORE_SECONDS

    def _next_id(self) -> str:
        self._seq += 1
        return f"inc-{self._seq}"

    def _live_incident(self, track: _Track) -> Incident | None:
        if track.live and track.incident_id:
            return self._incidents.get(track.incident_id)
        return None

    # -- time-based steps --------------------------------------------------------------

    def _resolve_stale(self, now: float, out: list[Transition]) -> None:
        for track in self._tracks.values():
            rule = self._rule(track.type)
            if rule is None:
                if self._live_incident(track) is None:
                    continue
                rule = _FALLBACK_RULE
            if rule["mode"] == "level":
                self._stale_level(track, now, out)
            else:
                self._stale_window(track, rule, now, out)

    def _stale_level(self, track: _Track, now: float, out: list[Transition]) -> None:
        last = track.last_obs
        inc = self._live_incident(track)
        if last is None and inc is not None:
            last = inc.last_seen
        if last is None or now - last < self._auto_resolve():
            return
        if inc is not None:
            self._resolve(
                track, inc, min(now, last + self._auto_resolve()), out, "no_data"
            )
        else:
            track.reset_streak()
            track.entries = []

    def _stale_window(
        self, track: _Track, rule: dict[str, Any], now: float, out: list[Transition]
    ) -> None:
        _count, _window, clear, clear_below = self._window_params(rule)
        self._trim(track, rule, now)
        inc = self._live_incident(track)
        if inc is None:
            return
        last = track.last_evidence if track.last_evidence is not None else inc.last_seen
        if clear_below <= 1:
            quiet = now - last >= clear
        else:
            quiet = _sum_within(track, clear, now) < clear_below
        if quiet:
            self._resolve(track, inc, min(now, last + clear), out, "quiet")

    def _expire_ignores(self, now: float, out: list[Transition]) -> None:
        for inc in self._incidents.values():
            if (
                inc.status is not IncidentStatus.IGNORED
                or inc.ignore_until is None
                or inc.ignore_until > now
            ):
                continue
            inc.ignore_until = None
            track = self._tracks.get(inc.key)
            if track is not None and track.live and track.incident_id == inc.id:
                inc.status = IncidentStatus.ACTIVE
                out.append(
                    Transition(TransitionState.UPDATED, inc.copy(), "ignore_expired")
                )
            else:
                inc.status = IncidentStatus.RESOLVED
                if inc.resolved_at is None:
                    inc.resolved_at = now

    def _prune(self, now: float) -> None:
        kept = prune_incidents(
            self._incidents.values(),
            now,
            max_count=self._max_incidents,
            retention_days=self._settings["retention_days"],
        )
        self._incidents = {i.id: i for i in kept}
        for key, track in list(self._tracks.items()):
            if track.incident_id not in self._incidents:
                track.incident_id = None
                track.live = False
            if (
                track.incident_id is None
                and not track.entries
                and track.streak == 0
                and track.pending_since is None
            ):
                del self._tracks[key]

    # -- evidence ----------------------------------------------------------------------

    def _ingest(self, now: float, item: Evidence, out: list[Transition]) -> None:
        rule = self._rule(item.type)
        if rule is None:
            return
        key = (item.type, item.scope_key)
        if item.maintenance:
            # Never counts, and breaks a running series (not an open incident).
            track = self._tracks.get(key)
            if track is not None and self._live_incident(track) is None:
                track.reset_streak()
                track.entries = []
            return
        if rule["mode"] == "level":
            if not _is_number(item.value):
                return
            track = self._tracks.setdefault(key, _Track(*key))
            self._ingest_level(now, item, rule, track, out)
        else:
            track = self._tracks.setdefault(key, _Track(*key))
            self._ingest_window(now, item, rule, track, out)

    def _ingest_window(
        self,
        now: float,
        item: Evidence,
        rule: dict[str, Any],
        track: _Track,
        out: list[Transition],
    ) -> None:
        n = _evidence_count(item.count)
        assert track.entries is not None
        if item.event_id is not None and any(
            e[2] == item.event_id for e in track.entries
        ):
            return  # the same event fed twice (re-read log line, double ingest)
        track.entries.append([now, n, item.event_id, item.kind])
        track.last_evidence = now
        self._trim(track, rule, now)
        inc = self._live_incident(track)
        if inc is not None:
            changed = self._absorb(inc, item, now, n)
            changed = self._escalate(inc, rule, track, now, None) or changed
            self._finish_update(inc, changed, out)
            return
        count, window, _clear, _below = self._window_params(rule)
        total = _sum_within(track, window, now)
        if total < count:
            return
        recent = [e for e in track.entries if e[0] > now - window]
        self._activate(now, item, rule, track, out, total, recent[0][0], recent)

    def _ingest_level(
        self,
        now: float,
        item: Evidence,
        rule: dict[str, Any],
        track: _Track,
        out: list[Transition],
    ) -> None:
        if track.last_obs is not None and now <= track.last_obs:
            return  # one observation per poll: debounce counts polls
        value = float(item.value)  # type: ignore[arg-type]
        raise_at = float(rule["raise"])
        clear_at = float(rule.get("clear", raise_at))
        track.last_obs = now
        inc = self._live_incident(track)
        if value >= raise_at:
            track.streak += 1
            track.last_evidence = now
            if track.pending_since is None:
                track.pending_since = now
            if inc is not None:
                changed = self._absorb(inc, item, now, 1)
                changed = self._escalate(inc, rule, track, now, value) or changed
                self._finish_update(inc, changed, out)
                return
            assert track.entries is not None
            track.entries.append([now, 1, item.event_id, item.kind])
            del track.entries[:-MAX_EVIDENCE]
            if track.streak < int(rule.get("debounce", 1)):
                return
            hold = float(rule.get("hold", 0))
            if now - track.pending_since < hold:
                return
            self._activate(
                now,
                item,
                rule,
                track,
                out,
                track.streak,
                track.pending_since,
                track.entries,
                value,
            )
            track.entries = []
        elif value < clear_at:
            track.reset_streak()
            track.entries = []
            if inc is not None:
                self._resolve(track, inc, now, out, "cleared")
        elif inc is None:  # hysteresis band without an open incident
            track.reset_streak()
            track.entries = []

    def _window_params(self, rule: dict[str, Any]) -> tuple[int, float, float, int]:
        count = int(rule.get("count", 1))
        window = float(rule.get("window", 1))
        clear = float(rule.get("clear", self._auto_resolve()))
        return count, window, clear, int(rule.get("clear_below", 1))

    def _trim(self, track: _Track, rule: dict[str, Any], now: float) -> None:
        if rule["mode"] == "level":
            return
        _count, window, clear, _below = self._window_params(rule)
        esc = rule.get("escalate")
        esc_window = float(esc.get("window", 0)) if isinstance(esc, dict) else 0.0
        keep = max(window, clear, esc_window)
        track.entries = [e for e in track.entries or [] if e[0] > now - keep][
            -MAX_TRACK_ENTRIES:
        ]

    # -- incident changes -----------------------------------------------------------------

    def _activate(
        self,
        now: float,
        item: Evidence,
        rule: dict[str, Any],
        track: _Track,
        out: list[Transition],
        occurrences: int,
        first_seen: float,
        entries: list[list[Any]],
        value: float | None = None,
    ) -> None:
        prev = self._incidents.get(track.incident_id or "")
        base = _severity(rule.get("severity"))
        if prev is not None and self._reopens(prev, rule, now):
            assert prev.resolved_at is not None
            if rule["mode"] != "level":
                # only what came after the resolve counts for the reopen
                cut = prev.resolved_at
                entries = [e for e in entries if e[0] > cut] or entries[-1:]
                occurrences = sum(e[1] for e in entries)
            shorts = [_short(e) for e in entries][-MAX_EVIDENCE:]
            inc = prev
            state = TransitionState.REOPENED
            inc.resolved_at = None
            inc.reopen_count += 1
            inc.occurrences += occurrences
            inc.severity = base
            inc.evidence = (inc.evidence + shorts)[-MAX_EVIDENCE:]
            inc.last_seen = now
            if inc.ignore_until is not None and inc.ignore_until > now:
                inc.status = IncidentStatus.IGNORED
            else:
                inc.ignore_until = None
                inc.status = IncidentStatus.ACTIVE
        else:
            state = TransitionState.OPENED
            inc = Incident(
                id=self._next_id(),
                type=item.type,
                scope=item.scope,
                scope_key=item.scope_key,
                severity=base,
                confidence=_confidence(item),
                origin=item.origin,
                evidence=[_short(e) for e in entries][-MAX_EVIDENCE:],
                first_seen=first_seen,
                last_seen=now,
                occurrences=occurrences,
            )
            self._incidents[inc.id] = inc
        track.incident_id = inc.id
        track.live = True
        self._merge_meta(inc, item)
        self._escalate(inc, rule, track, now, value)
        if inc.status is not IncidentStatus.IGNORED:
            out.append(Transition(state, inc.copy()))

    @staticmethod
    def _reopens(prev: Incident, rule: dict[str, Any], now: float) -> bool:
        """Reopen ``prev`` instead of opening a new incident?

        Yes inside the cooldown after its resolve, and while an ignore of it
        is still running (silently, whatever the cooldown).
        """
        if prev.resolved_at is None:
            return False
        if (
            prev.status is IncidentStatus.IGNORED
            and prev.ignore_until is not None
            and prev.ignore_until > now
        ):
            return True
        cooldown = float(rule.get("cooldown", 0))
        return cooldown > 0 and now - prev.resolved_at < cooldown

    def _absorb(self, inc: Incident, item: Evidence, now: float, n: int) -> bool:
        """Add one evidence to an open incident; True if the severity rose."""
        inc.occurrences += n
        inc.last_seen = now
        if item.event_id is not None or item.kind:
            inc.evidence.append(_short([now, n, item.event_id, item.kind]))
            del inc.evidence[:-MAX_EVIDENCE]
        return self._merge_meta(inc, item)

    def _merge_meta(self, inc: Incident, item: Evidence) -> bool:
        """Merge routers, confidence, cause; True if the severity rose."""
        if item.router and item.router not in inc.routers:
            inc.routers = sorted([*inc.routers, item.router])
        inc.affected = max(inc.affected, item.affected)
        inc.confidence = max(inc.confidence, _confidence(item))
        if item.origin is Origin.OBSERVED:
            inc.origin = Origin.OBSERVED
        if item.cause and (
            inc.cause is None
            or (
                item.cause_status is CauseStatus.CONFIRMED
                and inc.cause_status is not CauseStatus.CONFIRMED
            )
        ):
            inc.cause = item.cause
            inc.cause_status = item.cause_status
        if item.severity is not None:
            return _raise_severity(inc, item.severity)
        return False

    def _escalate(
        self,
        inc: Incident,
        rule: dict[str, Any],
        track: _Track,
        now: float,
        value: float | None,
    ) -> bool:
        """Raise the severity per the rule's ``escalate`` entry; True if changed."""
        esc = rule.get("escalate")
        if (
            not isinstance(esc, dict)
            or esc.get("severity") not in Severity._value2member_map_
        ):
            return False
        hit = (
            _is_number(esc.get("value")) and value is not None and value >= esc["value"]
        )
        if _is_number(esc.get("count")):
            window = float(esc.get("window", rule.get("window", 0)))
            hit = hit or _sum_within(track, window, now) >= esc["count"]
        return hit and _raise_severity(inc, Severity(esc["severity"]))

    def _finish_update(
        self, inc: Incident, changed: bool, out: list[Transition]
    ) -> None:
        if changed and inc.status is IncidentStatus.ACTIVE:
            out.append(Transition(TransitionState.UPDATED, inc.copy(), "severity"))

    def _resolve(
        self,
        track: _Track,
        inc: Incident,
        at: float,
        out: list[Transition],
        reason: str,
    ) -> None:
        track.live = False
        track.reset_streak()
        inc.resolved_at = at
        if inc.status is IncidentStatus.IGNORED:
            return  # resolved silently; the status changes when the ignore ends
        inc.status = IncidentStatus.RESOLVED
        out.append(Transition(TransitionState.RESOLVED, inc.copy(), reason))


# --- small helpers ---------------------------------------------------------------------------


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _is_open(inc: Incident) -> bool:
    """Condition still present: active, acknowledged or ignored-not-resolved."""
    return inc.status in (IncidentStatus.ACTIVE, IncidentStatus.ACKNOWLEDGED) or (
        inc.status is IncidentStatus.IGNORED and inc.resolved_at is None
    )


def _evidence_count(value: Any) -> int:
    """An evidence count as int >= 1 (bad or non-positive counts count once)."""
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return 1


def _as_int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _shifted(value: float | None, delta: float) -> float | None:
    return None if value is None else value + delta


def _sum_within(track: _Track, window: float, now: float) -> int:
    return sum(e[1] for e in track.entries or [] if e[0] > now - window)


def _severity(value: Any) -> Severity:
    return Severity(value) if value in Severity._value2member_map_ else Severity.WARNING


def _confidence(item: Evidence) -> float:
    conf = min(1.0, max(0.0, item.confidence))
    if item.origin is Origin.INFERRED:
        conf = min(conf, INFERRED_CONFIDENCE_CAP)
    return conf


def _raise_severity(inc: Incident, severity: Severity) -> bool:
    if severity.rank > inc.severity.rank:
        inc.severity = severity
        return True
    return False


def _short(entry: list[Any]) -> dict[str, Any]:
    """Short evidence form for an incident: id, ts, kind."""
    short: dict[str, Any] = {"ts": entry[0]}
    if entry[2] is not None:
        short["id"] = entry[2]
    if entry[3]:
        short["kind"] = entry[3]
    return short
