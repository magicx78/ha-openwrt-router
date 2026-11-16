"""Rules for the network intelligence engine: default settings and alarm state machine.

Pure module, no Home Assistant imports. Time is never read from the clock:
every entry point takes ``now`` (epoch seconds). Later work packages add the
WLAN detectors (P4), correlation (P5) and health score (P6) to this module;
it holds

* ``DEFAULT_SETTINGS`` / ``merge_settings`` (plan c7 and c8),
* ``AlarmMachine``: turns evidence into ``Incident`` life cycles, and
* the infrastructure detectors (P3, system/LAN/WAN/DHCP):
  ``detect_infrastructure`` turns one poll into ``Finding``s.

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
import statistics
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .net_events import (
    CLOCK_SKEW_LIMIT,
    MAX_EVIDENCE,
    MAX_INCIDENTS,
    Category,
    CauseStatus,
    Incident,
    IncidentStatus,
    NetEvent,
    Origin,
    Scope,
    Severity,
    Source,
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
        # mirrors ram_high: RAM_PRESSURE_*_PCT, _HOLD_SECONDS, RAM_AVAILABLE_MIN_BYTES
        "system_ram_high": _level(85, 80, 1, 0, hold=900, min_available_mb=16),
        "system_reboot": _event(0),
        # services: the engine's own list (DEFAULT_SERVICES stays unchanged);
        # rpcd is left out on purpose, every ACL deployment restarts it
        "system_service_restart": _window(
            1,
            3600,
            600,
            900,
            escalate={"severity": "critical", "count": 3, "window": 3600},
            services=["dnsmasq", "odhcpd", "wpad", "hostapd", "network"],
        ),
        "system_clock_skew": _level(120, 30, 3, 3600),
        # value = count / median of the last ``window`` s (no conntrack max, F3)
        "system_conntrack_jump": _level(
            3.0, 1.5, 3, 3600, "info", min_count=5000, window=3600
        ),
        # LAN
        "lan_port_flap": _window(3, 600, 1800, 3600),
        # value 1 = speed below the highest of the last ``window`` s
        "lan_port_speed_drop": _level(1, 1, 2, 3600, window=86400),
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
    """Finite int or float (not bool); an int beyond float range is not."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


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
    opens an incident. Retention pruning pauses for one step after a
    forward jump: a step of more than ``CLOCK_SKEW_LIMIT`` beyond the
    elapsed monotonic time, or, without a monotonic reference, any step of
    more than ``CLOCK_SKEW_LIMIT`` that does not follow a held step. So
    slow polls (300 s plus the poll) never stop pruning.
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
        # Monotonic time of the last step that passed one (in memory only:
        # it has no meaning across a restart).
        self._last_mono: float | None = None
        self._prune_held = False

    # -- public ---------------------------------------------------------------

    @property
    def prune_held(self) -> bool:
        """True for the step right after a forward clock jump."""
        return self._prune_held

    @property
    def last_now(self) -> float | None:
        """The effective time of the previous step, None before the first."""
        return self._last_now

    def sync_clock(self, now: float, mono: float | None = None) -> ClockStep:
        """Advance the machine clock to ``now``; see the class doc on jumps.

        ``update`` calls this itself. A caller that stamps its own records
        (the engine) calls it first and uses ``ClockStep.now`` for them and
        for the following ``update``; ``ClockStep.shift`` tells it how far
        to move its own stored times. ``mono`` (``time.monotonic()``, if
        the caller has it) tells a forward jump of the wall clock from real
        elapsed time. Raises ``ValueError`` for a time that is not a finite
        number; an unusable ``mono`` is ignored.
        """
        if not _is_number(now):
            raise ValueError(f"invalid time: {now!r}")
        mono = float(mono) if _is_number(mono) else None
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
            elif step > 0:
                self._prune_held = self._is_jump(step, mono)
        if mono is not None:
            self._last_mono = mono
        self._last_now = now
        return ClockStep(now, shift)

    def _is_jump(self, step: float, mono: float | None) -> bool:
        """Is a forward ``step`` of the wall clock a jump (see class doc)?"""
        if step <= CLOCK_SKEW_LIMIT:
            return False
        last_mono = self._last_mono
        if mono is not None and last_mono is not None and mono >= last_mono:
            return step - (mono - last_mono) > CLOCK_SKEW_LIMIT
        return not self._prune_held  # no reference: hold one step at most

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
            if tail.isascii() and tail.isdigit():
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


# --- infrastructure detectors (P3) --------------------------------------------------
#
# Deterministic functions without I/O: each reads one poll (``InfraSnapshot``)
# and the router's previous state (``InfraState``, in memory only, owned by
# the engine) and appends ``Finding``s. A value that is missing or broken is
# "unknown": it produces nothing and leaves the stored state alone, so the
# next usable poll compares with the last usable one. Counter resets
# (delta < 0) and an uptime of 0 never produce an event.

# UTC offsets are whole quarter hours between -12:00 and +14:00.
_TZ_STEP = 900.0
_TZ_MAX = 14 * 3600.0 + _TZ_STEP
_CONNTRACK_MIN_SAMPLES = 10
_SPEED_BUCKET = 3600.0
# A port counts as an infrastructure link for this long after LLDP last
# showed a neighbour on it (the neighbour vanishes from LLDP once the link
# is down, but the down link is what lan_uplink_down is about).
INFRA_PORT_MEMORY = 86400.0
_MAX_PORTS = 64
_ARP_CONFIDENCE = 0.7
_DNS_CONFIDENCE = 0.5
_MAX_NAMES = 4

SERVICE_RESTART = "system.service_restart"
SERVICE_STOPPED = "system.service_stopped"
CRASH_LOOP_KIND = "system.service_crash_loop"
DECLINE_KIND = "dhcp.decline"

# Severity, cause, cause status and confidence of stored log event kinds that
# differ from the P2 default (info, no cause, 1.0).
LOG_EVENT_META: dict[str, tuple[Severity, str | None, CauseStatus | None, float]] = {
    CRASH_LOOP_KIND: (Severity.WARNING, None, None, 1.0),
    "system.oom_kill": (Severity.WARNING, None, None, 1.0),
    # The client probed the address and found it taken (RFC 2131 DHCPDECLINE).
    DECLINE_KIND: (Severity.INFO, "ip_conflict", CauseStatus.CONFIRMED, 1.0),
    # Only the dnsmasq line, no resolution test: a hypothesis (plan b 3.22).
    "dns.query_limit": (
        Severity.INFO,
        "dns_resolution",
        CauseStatus.HYPOTHESIS,
        _DNS_CONFIDENCE,
    ),
    "dns.no_servers": (
        Severity.WARNING,
        "dns_resolution",
        CauseStatus.HYPOTHESIS,
        _DNS_CONFIDENCE,
    ),
    "dns.send_failed": (
        Severity.INFO,
        "dns_resolution",
        CauseStatus.HYPOTHESIS,
        _DNS_CONFIDENCE,
    ),
}


@dataclass(frozen=True)
class InfraSnapshot:
    """The facts of one poll the infrastructure detectors read.

    Built by the engine from the coordinator data. ``None`` means "not
    measured in this poll" (missing field, failed call, missing ACL right).
    ``wan`` is only set for a router that has a WAN (``wan_found``).
    ``log_events`` are the new log lines of this poll (never the baseline
    of a first read), ``log_read`` tells whether the log was read at all.
    """

    uptime: float | None = None
    cpu_load: float | None = None
    memory_pressure: Mapping[str, Any] | None = None
    localtime: float | None = None
    localtime_at: float | None = None
    conntrack: int | None = None
    services: Mapping[str, Any] | None = None
    ports: tuple[Mapping[str, Any], ...] | None = None
    wan: Mapping[str, Any] | None = None
    wan_connected: bool | None = None
    dhcp_pools: tuple[Mapping[str, Any], ...] | None = None
    arp: Mapping[str, Any] | None = None
    lldp: tuple[Mapping[str, Any], ...] | None = None
    log_events: tuple[Any, ...] = ()
    log_read: bool = False


@dataclass(frozen=True)
class Finding:
    """One detector result.

    ``event`` True: store a ``NetEvent`` of ``kind`` (an observed change).
    ``rule`` set: feed evidence for that incident type (``value`` for level
    rules). Neither: only count ``kind``.
    """

    kind: str
    category: Category
    source: Source
    rule: str | None = None
    scope: Scope = Scope.ROUTER
    scope_key: str = ""
    value: float | None = None
    event: bool = False
    count: int = 1
    severity: Severity = Severity.INFO
    origin: Origin = Origin.OBSERVED
    confidence: float = 1.0
    cause: str | None = None
    cause_status: CauseStatus | None = None
    subject: dict[str, Any] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class _PortState:
    link: bool | None = None
    # downs seen by the poll since the last log read (dedup with log lines)
    poll_downs: int = 0
    # hour bucket -> highest link speed (Mbit/s) seen in it
    speeds: dict[int, int] = field(default_factory=dict)
    err_base: tuple[float, int, int] | None = None  # ts, errors, packets
    bytes_base: tuple[float, int, int] | None = None  # ts, rx, tx
    infra_seen: float | None = None  # last LLDP neighbour on this port
    last_seen: float | None = None


@dataclass
class InfraState:
    """Per-router comparison state of the detectors (memory only)."""

    uptime: float | None = None
    services: dict[tuple[str, str], tuple[int | None, bool]] | None = None
    # instances seen going from running to stopped (and not back yet)
    crashed: set[tuple[str, str]] = field(default_factory=set)
    conntrack: deque[tuple[float, int]] = field(
        default_factory=lambda: deque(maxlen=512)
    )
    ports: dict[str, _PortState] = field(default_factory=dict)
    wan_connected: bool | None = None
    wan_uptime: float | None = None
    wan_ip: str | None = None
    wan_poll_reconnects: int = 0
    arp_conflicts: frozenset[str] = frozenset()
    arp_reported: frozenset[str] = frozenset()
    lldp: dict[str, frozenset[tuple[str, str]]] | None = None
    lldp_candidate: dict[str, frozenset[tuple[str, str]]] | None = None
    lldp_since: float | None = None

    def after_reboot(self) -> None:
        """Forget what a reboot resets (PIDs, counters, the WAN session)."""
        self.services = None
        self.crashed.clear()
        self.conntrack.clear()
        for port in self.ports.values():
            port.err_base = None
            port.bytes_base = None
        self.wan_connected = None
        self.wan_uptime = None

    def shift(self, delta: float) -> None:
        """Move stored times by ``delta`` (large backward clock jump)."""
        self.conntrack = deque(
            ((ts + delta, n) for ts, n in self.conntrack), maxlen=512
        )
        for port in self.ports.values():
            if port.err_base is not None:
                port.err_base = (port.err_base[0] + delta, *port.err_base[1:])
            if port.bytes_base is not None:
                port.bytes_base = (port.bytes_base[0] + delta, *port.bytes_base[1:])
            port.infra_seen = _shifted(port.infra_seen, delta)
            port.last_seen = _shifted(port.last_seen, delta)
            port.speeds = {
                int((b * _SPEED_BUCKET + delta) // _SPEED_BUCKET): s
                for b, s in port.speeds.items()
            }
        self.lldp_since = _shifted(self.lldp_since, delta)


def port_key(router: str, port: str) -> str:
    """``scope_key`` of a port incident."""
    return f"{router}:port:{port}"


def service_key(router: str, service: str) -> str:
    """``scope_key`` of a service incident."""
    return f"{router}:service:{service}"


def pool_key(router: str, pool: str) -> str:
    """``scope_key`` of a DHCP pool incident."""
    return f"{router}:pool:{pool}"


def detect_infrastructure(
    state: InfraState,
    snap: InfraSnapshot,
    now: float,
    router: str,
    thresholds: Mapping[str, Any],
    *,
    lldp_interval: float = 600.0,
) -> list[Finding]:
    """Run all system, LAN, WAN and DHCP detectors for one poll of a router."""
    out: list[Finding] = []
    rules = _RuleSet(thresholds)
    rebooted = detect_reboot(state, snap, router, rules.get("system_reboot"), out)
    if rebooted:
        state.after_reboot()
    detect_cpu(snap, router, rules.get("system_cpu_high"), out)
    detect_ram(snap, router, rules.get("system_ram_high"), out)
    detect_clock_skew(snap, router, rules.get("system_clock_skew"), out)
    detect_conntrack(state, snap, now, router, rules.get("system_conntrack_jump"), out)
    detect_services(state, snap, router, rules.get("system_service_restart"), out)
    detect_lldp(
        state, snap, now, router, rules.get("lan_lldp_change"), out, lldp_interval
    )
    detect_ports(state, snap, now, router, rules, out)
    detect_wan(state, snap, router, rules, out)
    detect_dhcp(state, snap, router, rules, out)
    return out


class _RuleSet:
    """Threshold lookup that never fails (missing rule -> empty dict)."""

    def __init__(self, thresholds: Mapping[str, Any]) -> None:
        self._thresholds = thresholds if isinstance(thresholds, Mapping) else {}

    def get(self, name: str) -> Mapping[str, Any]:
        rule = self._thresholds.get(name)
        return rule if isinstance(rule, Mapping) else {}


def _num_or_none(value: Any) -> float | None:
    return float(value) if _is_number(value) else None


def _rule_num(rule: Mapping[str, Any], key: str, default: float) -> float:
    value = rule.get(key)
    return float(value) if _is_number(value) else default


# -- system ----------------------------------------------------------------------


def detect_reboot(
    state: InfraState,
    snap: InfraSnapshot,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> bool:
    """Uptime went down (both values > 0) -> ``system.reboot``; True if so."""
    uptime = snap.uptime
    if uptime is None or uptime <= 0:
        return False  # 0 = missing (coordinator default), never a reboot
    previous, state.uptime = state.uptime, uptime
    if previous is None or uptime >= previous:
        return False
    out.append(
        Finding(
            kind="system.reboot",
            category=Category.SYSTEM,
            source=Source.POLL,
            rule="system_reboot",
            scope_key=router,
            event=True,
            severity=_severity(rule.get("severity")),
            params={"uptime_s": int(uptime), "previous_uptime_s": int(previous)},
        )
    )
    return True


def detect_cpu(
    snap: InfraSnapshot, router: str, rule: Mapping[str, Any], out: list[Finding]
) -> None:
    """CPU load per core in % (level rule ``system_cpu_high``)."""
    if snap.cpu_load is None or snap.cpu_load < 0:
        return
    out.append(
        Finding(
            kind="system.cpu_load",
            category=Category.SYSTEM,
            source=Source.POLL,
            rule="system_cpu_high",
            scope_key=router,
            value=round(snap.cpu_load, 1),
        )
    )


def detect_ram(
    snap: InfraSnapshot, router: str, rule: Mapping[str, Any], out: list[Finding]
) -> None:
    """Mirror of the ``ram_high`` Repairs issue (same pressure formula).

    The value is the pressure in %; less available RAM than
    ``min_available_mb`` counts as at least the raise level, like the
    coordinator's "available below RAM_AVAILABLE_MIN_BYTES".
    """
    pressure = snap.memory_pressure
    if not isinstance(pressure, Mapping):
        return
    ratio = _num_or_none(pressure.get("pressure_ratio"))
    if ratio is None or not 0 <= ratio <= 1:
        return
    value = ratio * 100.0
    available = _num_or_none(pressure.get("available_bytes"))
    min_available = _rule_num(rule, "min_available_mb", 16.0) * 1024 * 1024
    if available is not None and available < min_available:
        value = max(value, _rule_num(rule, "raise", 85.0))
    out.append(
        Finding(
            kind="system.memory_pressure",
            category=Category.SYSTEM,
            source=Source.POLL,
            rule="system_ram_high",
            scope_key=router,
            value=round(value, 1),
        )
    )


def clock_skew(localtime: float, read_at: float) -> float:
    """Seconds between the router clock and HA, ignoring the UTC offset.

    procd's ``localtime`` is epoch seconds plus the router's UTC offset,
    which HA does not know. Within the range of real offsets (up to 14 h)
    the nearest whole quarter hour is taken as that offset; only the rest
    counts. A clock off by a whole quarter hour is therefore not seen.
    """
    diff = localtime - read_at
    if abs(diff) > _TZ_MAX:
        return abs(diff)
    return abs(diff - round(diff / _TZ_STEP) * _TZ_STEP)


def detect_clock_skew(
    snap: InfraSnapshot, router: str, rule: Mapping[str, Any], out: list[Finding]
) -> None:
    """Router clock against HA (level rule ``system_clock_skew``)."""
    if snap.localtime is None or snap.localtime_at is None:
        return
    out.append(
        Finding(
            kind="system.clock_skew",
            category=Category.SYSTEM,
            source=Source.POLL,
            rule="system_clock_skew",
            scope_key=router,
            value=round(clock_skew(snap.localtime, snap.localtime_at), 1),
        )
    )


def detect_conntrack(
    state: InfraState,
    snap: InfraSnapshot,
    now: float,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """Conntrack count against its median of the last ``window`` seconds.

    No percentage (``nf_conntrack_max`` is not readable, F3). The value is
    count / median above ``min_count``, else 0. It needs at least
    ``_CONNTRACK_MIN_SAMPLES`` samples spanning half the window.
    """
    count = snap.conntrack
    if count is None or count <= 0:
        return  # 0 = not readable (api default), not "no connections"
    window = _rule_num(rule, "window", 3600.0)
    history = state.conntrack
    while history and history[0][0] <= now - window:
        history.popleft()
    if len(history) >= _CONNTRACK_MIN_SAMPLES and now - history[0][0] >= window / 2:
        median = statistics.median(n for _ts, n in history)
        if median > 0:
            min_count = _rule_num(rule, "min_count", 5000.0)
            value = count / median if count > min_count else 0.0
            out.append(
                Finding(
                    kind="system.conntrack",
                    category=Category.SYSTEM,
                    source=Source.POLL,
                    rule="system_conntrack_jump",
                    scope_key=router,
                    value=round(value, 2),
                    params={"count": count, "median": median},
                )
            )
    history.append((now, count))


def _service_table(
    services: Mapping[str, Any], watched: Iterable[str]
) -> dict[tuple[str, str], tuple[int | None, bool]]:
    table: dict[tuple[str, str], tuple[int | None, bool]] = {}
    for name in watched:
        instances = services.get(name)
        if not isinstance(instances, Mapping):
            continue
        for inst, info in instances.items():
            if not isinstance(info, Mapping) or not isinstance(inst, str):
                continue
            pid = info.get("pid")
            pid = pid if isinstance(pid, int) and not isinstance(pid, bool) else None
            table[(name, inst)] = (
                pid if pid is not None and pid > 0 else None,
                info.get("running") is True,
            )
    return table


def detect_services(
    state: InfraState,
    snap: InfraSnapshot,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """Restart (PID change) or stop (running -> false) of a watched service.

    The watched services are the rule's ``services`` list (the engine's own
    list, ``DEFAULT_SERVICES`` is not involved). A service or instance that
    disappears from ``service list`` was stopped on purpose (init script)
    and is not reported. A service that stays stopped after a crash keeps
    feeding evidence, so its incident does not resolve as "stable".
    """
    if not isinstance(snap.services, Mapping):
        return  # not fetched in this poll: keep the last known state
    watched = [s for s in rule.get("services") or () if isinstance(s, str)]
    current = _service_table(snap.services, watched)
    previous, state.services = state.services, current
    state.crashed &= set(current)
    if previous is None:
        return  # first poll or right after a reboot: baseline only
    severity = _severity(rule.get("severity"))
    for (name, inst), (pid, running) in sorted(current.items()):
        before = previous.get((name, inst))
        if before is None:
            continue  # new instance: a start, not a restart
        old_pid, was_running = before
        base = {
            "category": Category.SYSTEM,
            "source": Source.PROCD,
            "rule": "system_service_restart",
            "scope_key": service_key(router, name),
            "severity": severity,
            "subject": {"service": name, "instance": inst},
        }
        if running:
            state.crashed.discard((name, inst))
        if was_running and running and pid and old_pid and pid != old_pid:
            out.append(Finding(kind=SERVICE_RESTART, event=True, **base))
        elif was_running and not running:
            state.crashed.add((name, inst))
            out.append(Finding(kind=SERVICE_STOPPED, event=True, **base))
        elif not running and (name, inst) in state.crashed:
            # still down after the crash: keep the incident open
            out.append(Finding(kind=SERVICE_STOPPED, **base))


# -- LAN --------------------------------------------------------------------------


def _port_state(state: InfraState, name: str) -> _PortState | None:
    port = state.ports.get(name)
    if port is None:
        if len(state.ports) >= _MAX_PORTS:
            return None
        port = state.ports[name] = _PortState()
    return port


def _lldp_table(
    neighbors: Iterable[Any],
) -> dict[str, frozenset[tuple[str, str]]]:
    table: dict[str, set[tuple[str, str]]] = {}
    for item in neighbors:
        if not isinstance(item, Mapping):
            continue
        port = item.get("local_interface")
        ident = item.get("chassis_id") or item.get("chassis_name")
        if not isinstance(port, str) or not port or not isinstance(ident, str):
            continue
        if not ident:
            continue
        remote = item.get("port_id")
        table.setdefault(port, set()).add(
            (ident, remote if isinstance(remote, str) else "")
        )
    return {port: frozenset(idents) for port, idents in table.items()}


def detect_lldp(
    state: InfraState,
    snap: InfraSnapshot,
    now: float,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
    interval: float,
) -> None:
    """A neighbour gone or replaced, confirmed by ``states`` LLDP states.

    LLDP is read every ``interval`` seconds and served from a cache in
    between, so a change counts once it has lasted ``states - 1`` reads
    plus half an interval. A new neighbour on a free port is not reported.
    Also marks every port with a neighbour as infrastructure link.
    """
    if snap.lldp is None:
        return  # LLDP unavailable or failed: unknown
    current = _lldp_table(snap.lldp)
    for name in current:
        port = _port_state(state, name)
        if port is not None:
            port.infra_seen = now
    if state.lldp is None:
        state.lldp = current
        return
    if current == state.lldp:
        state.lldp_candidate = None
        state.lldp_since = None
        return
    if state.lldp_candidate != current or state.lldp_since is None:
        state.lldp_candidate = current
        state.lldp_since = now
        return
    states = max(2, int(_rule_num(rule, "states", 2)))
    if now - state.lldp_since < (states - 1) * interval + interval / 2:
        return
    severity = _severity(rule.get("severity"))
    for name in sorted(state.lldp):
        before = state.lldp[name]
        after = current.get(name, frozenset())
        if not before - after:
            continue  # only additions
        out.append(
            Finding(
                kind="lan.lldp_change",
                category=Category.LAN,
                source=Source.LLDP,
                rule="lan_lldp_change",
                scope=Scope.PORT,
                scope_key=port_key(router, name),
                event=True,
                severity=severity,
                subject={"port": name},
                params={
                    "change": "changed" if after else "gone",
                    "before": sorted(i for i, _p in before)[:_MAX_NAMES],
                    "after": sorted(i for i, _p in after)[:_MAX_NAMES],
                },
            )
        )
    state.lldp = current
    state.lldp_candidate = None
    state.lldp_since = None


def _counter_value(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def detect_ports(
    state: InfraState,
    snap: InfraSnapshot,
    now: float,
    router: str,
    rules: _RuleSet,
    out: list[Finding],
) -> None:
    """Link flaps, uplink down, speed drop, error ratio and load per port."""
    if snap.ports is None:
        return  # port status not readable in this poll
    for raw in snap.ports:
        if not isinstance(raw, Mapping):
            continue
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            continue
        port = _port_state(state, name)
        if port is None:
            continue
        port.last_seen = now
        carrier, up = raw.get("carrier"), raw.get("up")
        link = carrier if isinstance(carrier, bool) else up
        link = link if isinstance(link, bool) else None
        speed = raw.get("speed_mbps")
        speed = (
            speed
            if isinstance(speed, int) and not isinstance(speed, bool) and speed > 0
            else None
        )
        _port_flap(port, name, link, router, out)
        _port_uplink(port, name, link, now, router, rules.get("lan_uplink_down"), out)
        if link and speed is not None:
            _port_speed(
                port,
                name,
                speed,
                now,
                router,
                rules.get("lan_port_speed_drop"),
                out,
            )
        _port_errors(port, name, raw, now, router, rules.get("lan_port_errors"), out)
        _port_load(port, name, raw, link, speed, now, router, out)
    _log_flaps(state, snap, router, out)
    # forget ports gone from the router for a day
    for name in [
        n
        for n, p in state.ports.items()
        if p.last_seen is not None and now - p.last_seen > INFRA_PORT_MEMORY
    ]:
        del state.ports[name]


def _port_flap(
    port: _PortState, name: str, link: bool | None, router: str, out: list[Finding]
) -> None:
    if link is None:
        return
    before, port.link = port.link, link
    if before is True and link is False:
        port.poll_downs += 1
        out.append(
            Finding(
                kind="lan.port_down",
                category=Category.LAN,
                source=Source.POLL,
                rule="lan_port_flap",
                scope=Scope.PORT,
                scope_key=port_key(router, name),
                event=True,
                subject={"port": name},
            )
        )
    elif before is False and link is True:
        out.append(
            Finding(
                kind="lan.port_up",
                category=Category.LAN,
                source=Source.POLL,
                subject={"port": name},
            )
        )


def _log_flaps(
    state: InfraState, snap: InfraSnapshot, router: str, out: list[Finding]
) -> None:
    """Link-down lines the poll did not see (flaps shorter than a poll).

    Kernel and netifd may both log the same down: per port the larger of
    the two counts is taken. Downs the poll already saw since the last log
    read are subtracted.
    """
    if not snap.log_read:
        return
    by_process: dict[str, dict[str, int]] = {}
    for event in snap.log_events:
        if (
            getattr(event, "category", None) != "link"
            or getattr(event, "kind", None) != "down"
            or not isinstance(getattr(event, "interface", None), str)
        ):
            continue
        counts = by_process.setdefault(event.interface, {})
        process = str(getattr(event, "process", None))
        counts[process] = counts.get(process, 0) + 1
    for name, counts in sorted(by_process.items()):
        port = state.ports.get(name)
        if port is None:
            continue  # not a port of this router (wifi, bridge, tunnel)
        extra = max(counts.values()) - port.poll_downs
        if extra > 0:
            source = Source.NETIFD if "netifd" in counts else Source.LOG
            out.append(
                Finding(
                    kind="lan.port_flap",
                    category=Category.LAN,
                    source=source,
                    rule="lan_port_flap",
                    scope=Scope.PORT,
                    scope_key=port_key(router, name),
                    event=True,
                    count=extra,
                    subject={"port": name},
                )
            )
    for port in state.ports.values():
        port.poll_downs = 0


def _port_uplink(
    port: _PortState,
    name: str,
    link: bool | None,
    now: float,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """Down state of a port LLDP showed a neighbour on (observed link)."""
    if (
        link is None
        or port.infra_seen is None
        or now - port.infra_seen > INFRA_PORT_MEMORY
    ):
        return
    out.append(
        Finding(
            kind="lan.uplink",
            category=Category.LAN,
            source=Source.POLL,
            rule="lan_uplink_down",
            scope=Scope.PORT,
            scope_key=port_key(router, name),
            value=0.0 if link else 1.0,
            subject={"port": name},
        )
    )


def _port_speed(
    port: _PortState,
    name: str,
    speed: int,
    now: float,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """Link speed below its highest value of the last ``window`` seconds.

    Judged only on infrastructure links (LLDP neighbour) and WAN ports: an
    access port changes its partner (a 100 Mbit/s printer after a laptop)
    and would raise false alarms. The history is kept for all ports.
    """
    window = _rule_num(rule, "window", 86400.0)
    bucket = int(now // _SPEED_BUCKET)
    oldest = bucket - max(1, int(window // _SPEED_BUCKET)) + 1
    port.speeds = {b: s for b, s in port.speeds.items() if oldest <= b <= bucket}
    port.speeds[bucket] = max(speed, port.speeds.get(bucket, 0))
    infra = port.infra_seen is not None and now - port.infra_seen <= INFRA_PORT_MEMORY
    if not infra and not name.startswith("wan"):
        return
    highest = max(port.speeds.values())
    out.append(
        Finding(
            kind="lan.port_speed",
            category=Category.LAN,
            source=Source.POLL,
            rule="lan_port_speed_drop",
            scope=Scope.PORT,
            scope_key=port_key(router, name),
            value=1.0 if speed < highest else 0.0,
            subject={"port": name},
            params={"speed_mbps": speed, "max_mbps": highest},
        )
    )


def _port_errors(
    port: _PortState,
    name: str,
    raw: Mapping[str, Any],
    now: float,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """RX+TX errors per packet in % over at least ``interval`` seconds."""
    values = [
        _counter_value(raw.get(key))
        for key in ("rx_errors", "tx_errors", "rx_packets", "tx_packets")
    ]
    if any(v is None for v in values):
        port.err_base = None  # counters not sent (older firmware, ACL)
        return
    rx_err, tx_err, rx_pkt, tx_pkt = values  # type: ignore[misc]
    errors, packets = rx_err + tx_err, rx_pkt + tx_pkt
    base = port.err_base
    if base is None:
        port.err_base = (now, errors, packets)
        return
    elapsed, d_err, d_pkt = now - base[0], errors - base[1], packets - base[2]
    if d_err < 0 or d_pkt < 0 or elapsed < 0:
        port.err_base = (now, errors, packets)  # counter reset: no event
        return
    interval = _rule_num(rule, "interval", 300.0)
    if elapsed < interval:
        return
    if d_pkt >= _rule_num(rule, "min_packets", 1000.0):
        port.err_base = (now, errors, packets)
        out.append(
            Finding(
                kind="lan.port_errors",
                category=Category.LAN,
                source=Source.POLL,
                rule="lan_port_errors",
                scope=Scope.PORT,
                scope_key=port_key(router, name),
                value=round(d_err / d_pkt * 100.0, 4),
                subject={"port": name},
                params={"errors": d_err, "packets": d_pkt},
            )
        )
    elif elapsed >= 4 * interval:
        port.err_base = (now, errors, packets)  # too little traffic: start over


def _port_load(
    port: _PortState,
    name: str,
    raw: Mapping[str, Any],
    link: bool | None,
    speed: int | None,
    now: float,
    router: str,
    out: list[Finding],
) -> None:
    """Busier direction in % of the link speed since the previous poll."""
    rx, tx = _counter_value(raw.get("rx_bytes")), _counter_value(raw.get("tx_bytes"))
    base, port.bytes_base = port.bytes_base, None
    if rx is None or tx is None:
        return
    port.bytes_base = (now, rx, tx)
    if base is None or not link or speed is None:
        return
    elapsed, d_rx, d_tx = now - base[0], rx - base[1], tx - base[2]
    if elapsed <= 0 or d_rx < 0 or d_tx < 0:
        return  # counter reset: no value
    load = max(d_rx, d_tx) * 8 / elapsed / (speed * 1_000_000) * 100.0
    out.append(
        Finding(
            kind="lan.port_load",
            category=Category.LAN,
            source=Source.POLL,
            rule="lan_port_load",
            scope=Scope.PORT,
            scope_key=port_key(router, name),
            value=round(load, 1),
            subject={"port": name},
        )
    )


# -- WAN --------------------------------------------------------------------------


def detect_wan(
    state: InfraState,
    snap: InfraSnapshot,
    router: str,
    rules: _RuleSet,
    out: list[Finding],
) -> None:
    """WAN down, reconnects and a new WAN IPv4 (gateway only).

    A reconnect is a down -> up between two polls, a WAN uptime that went
    down while connected in both, or an "Interface '<wan>' is now up" log
    line beyond those the poll saw since the last log read.
    """
    wan, connected = snap.wan, snap.wan_connected
    if not isinstance(wan, Mapping) or connected is None:
        return
    down_rule = rules.get("wan_down")
    out.append(
        Finding(
            kind="wan.status",
            category=Category.WAN,
            source=Source.NETIFD,
            rule="wan_down",
            scope_key=router,
            value=0.0 if connected else 1.0,
        )
    )
    uptime = _num_or_none(wan.get("uptime"))
    uptime = uptime if uptime is not None and uptime > 0 else None
    before, last_uptime = state.wan_connected, state.wan_uptime
    if before is True and not connected:
        out.append(
            Finding(
                kind="wan.down",
                category=Category.WAN,
                source=Source.NETIFD,
                scope_key=router,
                event=True,
                severity=_severity(down_rule.get("severity")),
            )
        )
    elif before is False and connected:
        state.wan_poll_reconnects += 1
        out.append(_wan_reconnect("wan.up", router, Source.NETIFD, 1))
    elif (
        before is True
        and connected
        and uptime is not None
        and last_uptime is not None
        and uptime < last_uptime
    ):
        state.wan_poll_reconnects += 1
        out.append(_wan_reconnect("wan.reconnect", router, Source.NETIFD, 1))
    state.wan_connected = connected
    state.wan_uptime = uptime if connected else None
    _wan_log_reconnects(state, snap, wan, router, out)
    _wan_ip(state, wan, connected, router, rules.get("wan_ip_changed"), out)


def _wan_reconnect(kind: str, router: str, source: Source, count: int) -> Finding:
    return Finding(
        kind=kind,
        category=Category.WAN,
        source=source,
        rule="wan_unstable",
        scope_key=router,
        event=True,
        count=count,
    )


def _wan_log_reconnects(
    state: InfraState,
    snap: InfraSnapshot,
    wan: Mapping[str, Any],
    router: str,
    out: list[Finding],
) -> None:
    if not snap.log_read:
        return
    iface = wan.get("interface")
    ups = (
        sum(
            1
            for e in snap.log_events
            if getattr(e, "category", None) == "iface"
            and getattr(e, "kind", None) == "up"
            and getattr(e, "interface", None) == iface
        )
        if isinstance(iface, str) and iface
        else 0
    )
    extra = ups - state.wan_poll_reconnects
    state.wan_poll_reconnects = 0
    if extra > 0:
        out.append(_wan_reconnect("wan.reconnect", router, Source.NETIFD, extra))


def _wan_ip(
    state: InfraState,
    wan: Mapping[str, Any],
    connected: bool,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    ip = wan.get("ipv4")
    if not connected or not isinstance(ip, str) or not ip:
        return  # no address while down: keep the last one
    before, state.wan_ip = state.wan_ip, ip
    if before is None or before == ip:
        return
    out.append(
        Finding(
            kind="wan.ip_changed",
            category=Category.WAN,
            source=Source.NETIFD,
            rule="wan_ip_changed",
            scope_key=router,
            event=True,
            severity=_severity(rule.get("severity")),
            subject={"ip": ip},
            params={"previous": before},
        )
    )


# -- DHCP -------------------------------------------------------------------------


def detect_dhcp(
    state: InfraState,
    snap: InfraSnapshot,
    router: str,
    rules: _RuleSet,
    out: list[Finding],
) -> None:
    """Pool usage (level) and one IPv4 with several MACs in the ARP table."""
    for pool in snap.dhcp_pools or ():
        if not isinstance(pool, Mapping):
            continue
        name, usage = pool.get("name"), _num_or_none(pool.get("usage_pct"))
        if not isinstance(name, str) or not name or usage is None:
            continue
        subject = {"pool": name}
        if isinstance(pool.get("interface"), str):
            subject["iface"] = pool["interface"]
        out.append(
            Finding(
                kind="dhcp.pool_usage",
                category=Category.DHCP,
                source=Source.POLL,
                rule="dhcp_pool_full",
                scope=Scope.SEGMENT,
                scope_key=pool_key(router, name),
                value=usage,
                subject=subject,
            )
        )
    _arp_conflicts(state, snap, router, rules.get("dhcp_conflict"), out)


def _arp_conflicts(
    state: InfraState,
    snap: InfraSnapshot,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """An IPv4 held by two MACs in two polls in a row (hypothesis).

    Also a device that switched from cable to Wi-Fi with a fixed address
    looks like this until its old ARP entry expires; hence two polls,
    confidence 0.7 and the cause only as hypothesis.
    """
    if not isinstance(snap.arp, Mapping):
        return
    macs_by_ip: dict[str, set[str]] = {}
    for mac, ip in snap.arp.items():
        if isinstance(mac, str) and isinstance(ip, str) and ip:
            macs_by_ip.setdefault(ip, set()).add(mac.upper())
    conflicts = frozenset(ip for ip, macs in macs_by_ip.items() if len(macs) > 1)
    confirmed = conflicts & state.arp_conflicts
    reported = state.arp_reported
    state.arp_conflicts, state.arp_reported = conflicts, confirmed
    for ip in sorted(confirmed):
        out.append(
            Finding(
                kind="dhcp.ip_conflict",
                category=Category.DHCP,
                source=Source.POLL,
                rule="dhcp_conflict",
                scope_key=router,
                event=ip not in reported,
                severity=_severity(rule.get("severity")),
                confidence=_ARP_CONFIDENCE,
                cause="ip_conflict",
                cause_status=CauseStatus.HYPOTHESIS,
                subject={"ip": ip},
                params={"macs": len(macs_by_ip[ip])},
            )
        )


def finding_evidence(
    finding: Finding, router: str, event: NetEvent | None = None
) -> Evidence | None:
    """Evidence for the alarm machine, or None for a finding without rule."""
    if not finding.rule:
        return None
    if event is not None:
        return Evidence.from_event(
            event, finding.rule, finding.scope, finding.scope_key, finding.value
        )
    return Evidence(
        type=finding.rule,
        scope_key=finding.scope_key,
        scope=finding.scope,
        kind=finding.kind,
        value=finding.value,
        count=finding.count,
        router=router,
        confidence=finding.confidence,
        origin=finding.origin,
        cause=finding.cause,
        cause_status=finding.cause_status,
    )


def log_event_evidence(event: NetEvent) -> Evidence | None:
    """Evidence from a stored log event (DHCPDECLINE, procd crash loop)."""
    if event.kind == DECLINE_KIND:
        return Evidence.from_event(event, "dhcp_conflict", Scope.ROUTER, event.router)
    if event.kind == CRASH_LOOP_KIND:
        service = event.subject.get("service")
        if isinstance(service, str) and service:
            return Evidence.from_event(
                event,
                "system_service_restart",
                Scope.ROUTER,
                service_key(event.router, service),
            )
    return None
