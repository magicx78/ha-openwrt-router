"""Rules for the network intelligence engine: default settings and alarm state machine.

Pure module, no Home Assistant imports. Time is never read from the clock:
every entry point takes ``now`` (epoch seconds). Later work packages add the
WLAN detectors (P4), correlation (P5) and health score (P6) to this module;
it holds

* ``DEFAULT_SETTINGS`` / ``merge_settings`` (plan c7 and c8),
* ``AlarmMachine``: turns evidence into ``Incident`` life cycles, and
* the infrastructure detectors (P3, system/LAN/WAN/DHCP):
  ``detect_infrastructure`` turns one poll into ``Finding``s, and
* the WLAN detectors (P4): ``detect_wifi`` (one router's poll against the
  fleet-wide ``WifiState``), ``wifi_log_meta`` and ``wifi_auth_evidence``
  for the stored Wi-Fi log lines.

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
from collections import Counter, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from .channel_plan import phy_of
from .client_stability import iface_band
from .dhcp_health import DHCP_MISSING, DHCP_PENDING, client_dhcp_status
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
        # max_gap: down -> up within this many s is a reconnect; a sleeping
        # IoT client comes back after minutes (P4 review M3, E3)
        "wifi_reconnect_storm": _window(5, 600, 1800, 3600, max_gap=30),
        "wifi_auth_failures": _window(3, 600, 1800, 3600),
        # count = distinct client MACs with a failed attempt (not attempts;
        # handshake timeouts excluded), P4 review M6
        "wifi_auth_wave": _window(5, 600, 1800, 3600, clear_below=2),
        # window: one tight cluster of AP-STA-DISCONNECTED lines (a radio or
        # hostapd going down drops all stations within about a second; 5 s
        # leaves room for whole-second log times). min_ratio only with
        # ratio_min_clients leaving (1 of 2 is no mass). P4 review M5.
        "wifi_mass_disconnect": _event(
            600, window=5, min_clients=5, min_ratio=0.5, ratio_min_clients=3
        ),
        # value 1 = no IP although connected (dhcp_missing), 0 = has a lease
        "wifi_no_ip": _level(
            1, 1, 2, 3600, "info", dhcp_missing_after=180, warn_clients_per_ap=3
        ),
        # ack_grace: a DHCPNAK followed by an ACK of the same MAC within this
        # many s is a normal INIT-REBOOT, no failure (P4 review M1, E4)
        "wifi_dhcp_after_connect": _window(1, 60, 1800, 3600, ack_grace=30),
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
    Evidence marked ``hold`` only keeps an open incident alive (a state
    that lasts, e.g. a crashed service still down): it never counts toward
    the threshold, the occurrences or an escalation.
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
    hold: bool = False

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
    # window rules: [ts, count, event_id, kind, router]; level rules: the
    # raising streak (router since P4; older stored entries lack it)
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
            [
                float(e[0]),
                int(e[1]),
                e[2] if isinstance(e[2], str) else None,
                str(e[3]),
                e[4] if len(e) > 4 and isinstance(e[4], str) else "",
            ]
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
        and len(entry) in (4, 5)
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

    def open_keys(
        self, types: Iterable[str], router: str
    ) -> list[tuple[str, Scope, str]]:
        """(type, scope, scope_key) of the open incidents of ``types`` that
        list ``router``, without copying the incidents."""
        wanted = frozenset(types)
        return [
            (inc.type, inc.scope, inc.scope_key)
            for inc in self._incidents.values()
            if inc.type in wanted and router in inc.routers and _is_open(inc)
        ]

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
        if item.hold:
            # Keeps an open incident from resolving as "stable"; never counts.
            track = self._tracks.get(key)
            inc = self._live_incident(track) if track is not None else None
            if track is not None and inc is not None:
                track.last_evidence = now
                inc.last_seen = now
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
        track.entries.append([now, n, item.event_id, item.kind, item.router or ""])
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
            track.entries.append([now, 1, item.event_id, item.kind, item.router or ""])
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
        # every router whose evidence counted, not just the last one (P4:
        # fleet rules such as the auth wave collect over several routers)
        counted = {e[4] for e in entries if len(e) > 4 and e[4]}
        if not counted <= set(inc.routers):
            inc.routers = sorted(counted | set(inc.routers))
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
_DNS_CONFIDENCE = 0.5
_MAX_NAMES = 4
# A DHCPDECLINE is the client's claim that the offered address answered
# ARP; confirmed only when the ARP table shows that address on another MAC.
_DECLINE_CONFIDENCE = 0.8
# PID changes this long after our own service action (HA button) are ours.
OWN_ACTION_WINDOW = 120.0
# Reboot from the boot time (read time - uptime): it must move later by more
# than this plus the poll interval (read jitter, slow polls).
_REBOOT_TOLERANCE = 60.0
_DEFAULT_POLL_INTERVAL = 60.0
# LLDP capabilities of a network device (live APs: Bridge and Router on,
# Wlan and Station off, so Wlan is no AP marker).
_INFRA_CAPABILITIES = frozenset({"bridge", "router"})
# IPv6-only WAN sections are not judged (wan6 is pending in normal
# operation on the live gateway; IPv6 stays open, plan A7).
_IPV6_WAN_PROTOS = frozenset({"dhcpv6"})

SERVICE_RESTART = "system.service_restart"
SERVICE_STOPPED = "system.service_stopped"
CRASH_LOOP_KIND = "system.service_crash_loop"
DECLINE_KIND = "dhcp.decline"
WAN_FAILOVER_KIND = "wan.failover"

# Severity, cause, cause status and confidence of stored log event kinds that
# differ from the P2 default (info, no cause, 1.0).
LOG_EVENT_META: dict[str, tuple[Severity, str | None, CauseStatus | None, float]] = {
    CRASH_LOOP_KIND: (Severity.WARNING, None, None, 1.0),
    "system.oom_kill": (Severity.WARNING, None, None, 1.0),
    # The client says the offered address is taken (RFC 2131 DHCPDECLINE):
    # a hypothesis until ARP shows a second MAC (``decline_cause``).
    DECLINE_KIND: (
        Severity.INFO,
        "ip_conflict",
        CauseStatus.HYPOTHESIS,
        _DECLINE_CONFIDENCE,
    ),
    # Only the dnsmasq line, no resolution test: a hypothesis (plan b 3.22).
    "dns.query_limit": (
        Severity.INFO,
        "dns_resolution",
        CauseStatus.HYPOTHESIS,
        _DNS_CONFIDENCE,
    ),
    "dns.no_servers": (
        Severity.INFO,
        "dns_resolution",
        CauseStatus.HYPOTHESIS,
        _DNS_CONFIDENCE,
    ),
    # "dns.send_failed" has no cause: dnsmasq logs it in send_from()
    # (src/forward.c), which sends replies to clients, not upstream queries.
}


@dataclass(frozen=True)
class InfraSnapshot:
    """The facts of one poll the infrastructure detectors read.

    Built by the engine from the coordinator data. ``None`` means "not
    measured in this poll" (missing field, failed call, missing ACL right).
    ``wan`` is only set for a router that has a WAN (``wan_found``),
    ``wan_at`` is the HA time of the WAN read. ``log_events`` are the new
    log lines of this poll (never the baseline of a first read),
    ``log_read`` tells whether the log was read at all, ``log_fetched_at``
    is the HA time of the log fetch and ``log_times`` the router times
    (epoch seconds, UTC) of new lines. ``service_actions`` maps a service
    to the HA time of our own last start/stop/restart.
    """

    uptime: float | None = None
    cpu_load: float | None = None
    memory_pressure: Mapping[str, Any] | None = None
    localtime: float | None = None
    localtime_at: float | None = None
    conntrack: int | None = None
    services: Mapping[str, Any] | None = None
    ports: tuple[Mapping[str, Any], ...] | None = None
    service_actions: Mapping[str, Any] | None = None
    wan: Mapping[str, Any] | None = None
    wan_connected: bool | None = None
    wan_at: float | None = None
    dhcp_pools: tuple[Mapping[str, Any], ...] | None = None
    lldp: tuple[Mapping[str, Any], ...] | None = None
    log_events: tuple[Any, ...] = ()
    log_read: bool = False
    log_fetched_at: float | None = None
    log_times: tuple[float, ...] = ()
    poll_interval: float | None = None


@dataclass(frozen=True)
class Finding:
    """One detector result.

    ``event`` True: store a ``NetEvent`` of ``kind`` (an observed change).
    ``rule`` set: feed evidence for that incident type (``value`` for level
    rules). Neither: only count ``kind``. ``hold``: evidence that only keeps
    an open incident alive (``Evidence.hold``).
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
    hold: bool = False
    # P4: measured client signal (dBm) of the event, clients affected, and a
    # severity the evidence raises the incident to (``Evidence.severity``).
    signal: int | None = None
    affected: int = 0
    escalate: Severity | None = None


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
    """Per-router comparison state of the detectors (memory only).

    Exception: ``wan_gateway`` is seeded by the engine from its store (a
    router whose IPv4 WAN was connected once stays a gateway).
    """

    uptime: float | None = None
    boot_at: float | None = None  # HA time of the last boot (read - uptime)
    tz_offset: float | None = None  # learned localtime - UTC (quarter hours)
    log_fetched_at: float | None = None  # HA time of the previous log fetch
    services: dict[tuple[str, str], tuple[int | None, bool]] | None = None
    services_at: float | None = None  # HA time of the previous service read
    # instances seen going from running to stopped (and not back yet)
    crashed: set[tuple[str, str]] = field(default_factory=set)
    conntrack: deque[tuple[float, int]] = field(
        default_factory=lambda: deque(maxlen=512)
    )
    ports: dict[str, _PortState] = field(default_factory=dict)
    wan_gateway: bool = False
    wan_iface: str | None = None
    wan_connected: bool | None = None
    wan_uptime: float | None = None
    wan_ip: str | None = None
    wan_poll_reconnects: int = 0
    # WAN up lines written after the WAN read of their poll (next poll's)
    wan_carry: int = 0
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
        self.wan_poll_reconnects = 0
        self.wan_carry = 0

    def clock_jumped(self) -> None:
        """HA's wall clock jumped ahead: the boot time is no reference."""
        self.boot_at = None

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
        self.boot_at = _shifted(self.boot_at, delta)
        self.services_at = _shifted(self.services_at, delta)
        self.log_fetched_at = _shifted(self.log_fetched_at, delta)


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
    fleet: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Run all system, LAN, WAN and DHCP detectors for one poll of a router.

    ``fleet`` holds the identities of the other routers (lower-case MACs and
    host IPs): an LLDP neighbour with one of them is infrastructure even
    without a Bridge/Router capability.
    """
    out: list[Finding] = []
    rules = _RuleSet(thresholds)
    rebooted = detect_reboot(state, snap, now, router, rules.get("system_reboot"), out)
    if rebooted:
        state.after_reboot()
    detect_cpu(snap, router, rules.get("system_cpu_high"), out)
    detect_ram(snap, router, rules.get("system_ram_high"), out)
    detect_clock_skew(state, snap, router, rules.get("system_clock_skew"), out)
    detect_conntrack(state, snap, now, router, rules.get("system_conntrack_jump"), out)
    detect_services(state, snap, now, router, rules.get("system_service_restart"), out)
    detect_lldp(
        state,
        snap,
        now,
        router,
        rules.get("lan_lldp_change"),
        out,
        lldp_interval,
        fleet,
    )
    detect_ports(state, snap, now, router, rules, out)
    detect_wan(state, snap, router, rules, out)
    detect_dhcp(snap, router, out)
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
    now: float,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> bool:
    """Router reboot (``system.reboot``); True if one was found.

    Either the uptime went down (both values > 0), or the boot time (HA
    time of the read minus the uptime) moved later by more than
    ``_REBOOT_TOLERANCE`` plus the poll interval: a reboot between two polls
    whose new uptime already passed the old one (router away longer than
    its old uptime). An uptime of 0 is "missing" (coordinator default),
    never a reboot. A forward jump of HA's clock clears the boot time
    first (``InfraState.clock_jumped``).
    """
    uptime = snap.uptime
    if uptime is None or uptime <= 0:
        return False
    read_at = snap.localtime_at if snap.localtime_at is not None else now
    boot = read_at - uptime
    previous, state.uptime = state.uptime, uptime
    last_boot, state.boot_at = state.boot_at, boot
    if previous is None:
        return False
    interval = snap.poll_interval
    if interval is None or not interval > 0:
        interval = _DEFAULT_POLL_INTERVAL
    dropped = uptime < previous
    moved = last_boot is not None and boot - last_boot > _REBOOT_TOLERANCE + interval
    if not dropped and not moved:
        return False
    params = {"uptime_s": int(uptime), "previous_uptime_s": int(previous)}
    if not dropped and last_boot is not None:
        params["boot_shift_s"] = round(boot - last_boot)
    out.append(
        Finding(
            kind="system.reboot",
            category=Category.SYSTEM,
            source=Source.POLL,
            rule="system_reboot",
            scope_key=router,
            event=True,
            severity=_severity(rule.get("severity")),
            params=params,
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
    state: InfraState,
    snap: InfraSnapshot,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """Router clock against HA (level rule ``system_clock_skew``).

    1. Log times (router UTC): every new line was written between the
       previous and this log fetch (HA times). The value is how far the
       newest/oldest new line lies outside that span (0 inside); the rule's
       ``raise`` (120 s) is the tolerance.
    2. ``localtime`` is UTC plus the router's UTC offset. While the log
       shows a good UTC clock (value below ``clear``) the offset is learned
       (rounded to quarter hours); later polls check ``localtime``
       absolutely against it. Without a log line in a poll, a deviation of
       whole quarter hours stays unknown (a DST/time zone change looks the
       same as a fault); the next line decides.
    3. Without any learned offset (no log data yet) the old modulo-900 s
       measure is the fallback; a fault of whole quarter hours is invisible
       there (blind spot, plan P3 review M1).
    """
    log_dev: float | None = None
    fetched = snap.log_fetched_at
    if fetched is not None and snap.log_times:
        lower = state.log_fetched_at
        dev = 0.0
        for ts in snap.log_times:
            dev = max(dev, ts - fetched)
            if lower is not None:
                dev = max(dev, lower - ts)
        log_dev = dev
    if fetched is not None:
        state.log_fetched_at = fetched
    local_dev: float | None = None
    if snap.localtime is not None and snap.localtime_at is not None:
        diff = snap.localtime - snap.localtime_at
        clear = _rule_num(rule, "clear", 30.0)
        if log_dev is not None and log_dev < clear and abs(diff) <= _TZ_MAX:
            state.tz_offset = round(diff / _TZ_STEP) * _TZ_STEP
        if state.tz_offset is None:
            local_dev = clock_skew(snap.localtime, snap.localtime_at)
        else:
            local_dev = abs(diff - state.tz_offset)
            steps = round(local_dev / _TZ_STEP)
            if (
                log_dev is None
                and steps >= 1
                and abs(local_dev - steps * _TZ_STEP) < clear
            ):
                local_dev = None  # offset change or whole-quarter fault: wait
    values = [v for v in (log_dev, local_dev) if v is not None]
    if not values:
        return
    out.append(
        Finding(
            kind="system.clock_skew",
            category=Category.SYSTEM,
            source=Source.LOG if log_dev is not None else Source.POLL,
            rule="system_clock_skew",
            scope_key=router,
            value=round(max(values), 1),
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
    now: float,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """Restart (PID change) or stop (running -> false) of a watched service.

    The watched services are the rule's ``services`` list (the engine's own
    list, ``DEFAULT_SERVICES`` is not involved). A service or instance that
    disappears from ``service list`` was stopped on purpose (init script)
    and is not reported. A change within ``OWN_ACTION_WINDOW`` of our own
    action on that service (HA button -> ``api.control_service``), or
    between the previous read and this one (slow polls), is ours and not
    reported; a LuCI apply cannot be told apart. A service that
    stays stopped after a crash keeps its incident open with ``hold``
    evidence, which never counts toward the escalation.
    """
    if not isinstance(snap.services, Mapping):
        return  # not fetched in this poll: keep the last known state
    watched = [s for s in rule.get("services") or () if isinstance(s, str)]
    current = _service_table(snap.services, watched)
    previous, state.services = state.services, current
    read_before, state.services_at = state.services_at, now
    state.crashed &= set(current)
    if previous is None:
        return  # first poll or right after a reboot: baseline only
    actions = snap.service_actions if isinstance(snap.service_actions, Mapping) else {}
    severity = _severity(rule.get("severity"))
    for (name, inst), (pid, running) in sorted(current.items()):
        before = previous.get((name, inst))
        if before is None:
            continue  # new instance: a start, not a restart
        old_pid, was_running = before
        if running:
            state.crashed.discard((name, inst))
        if _own_action(actions.get(name), read_before, now):
            continue  # our own start/stop/restart
        base = {
            "category": Category.SYSTEM,
            "source": Source.PROCD,
            "rule": "system_service_restart",
            "scope_key": service_key(router, name),
            "severity": severity,
            "subject": {"service": name, "instance": inst},
        }
        if was_running and running and pid and old_pid and pid != old_pid:
            out.append(Finding(kind=SERVICE_RESTART, event=True, **base))
        elif was_running and not running:
            state.crashed.add((name, inst))
            out.append(Finding(kind=SERVICE_STOPPED, event=True, **base))
        elif not running and (name, inst) in state.crashed:
            # still down after the crash: keep the incident open
            out.append(Finding(kind=SERVICE_STOPPED, hold=True, **base))


def _own_action(acted: Any, read_before: float | None, now: float) -> bool:
    """True if our own service action explains a change seen at ``now``."""
    if not _is_number(acted):
        return False
    acted = float(acted)
    if abs(now - acted) <= OWN_ACTION_WINDOW:
        return True
    return read_before is not None and read_before - OWN_ACTION_WINDOW <= acted <= now


# -- LAN --------------------------------------------------------------------------


def _port_state(state: InfraState, name: str) -> _PortState | None:
    port = state.ports.get(name)
    if port is None:
        if len(state.ports) >= _MAX_PORTS:
            return None
        port = state.ports[name] = _PortState()
    return port


def is_infra_neighbor(item: Mapping[str, Any], fleet: frozenset[str]) -> bool:
    """True for an LLDP neighbour that is a network device.

    A Bridge or Router capability (enabled; lldpd on the live APs sends
    both, Wlan off), or a chassis ID / management IP of a fleet router.
    A PC, NAS or phone with lldpd announces Station and is no uplink.
    """
    caps = item.get("capabilities")
    if isinstance(caps, (list, tuple)) and any(
        isinstance(cap, str) and cap.strip().lower() in _INFRA_CAPABILITIES
        for cap in caps
    ):
        return True
    for key in ("chassis_id", "management_ip"):
        value = item.get(key)
        if isinstance(value, str) and value.strip().lower() in fleet:
            return True
    return False


def _lldp_table(
    neighbors: Iterable[Any], fleet: frozenset[str]
) -> dict[str, frozenset[tuple[str, str]]]:
    """Infrastructure neighbours per local port (end devices left out)."""
    table: dict[str, set[tuple[str, str]]] = {}
    for item in neighbors:
        if not isinstance(item, Mapping) or not is_infra_neighbor(item, fleet):
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
    fleet: frozenset[str] = frozenset(),
) -> None:
    """An infrastructure neighbour gone or replaced, confirmed by ``states`` reads.

    LLDP is read every ``interval`` seconds and served from a cache in
    between, so a change counts once it has lasted ``states - 1`` reads
    plus half an interval. A new neighbour on a free port is not reported.
    Only network devices count (``is_infra_neighbor``); their ports are
    marked as infrastructure links.
    """
    if snap.lldp is None:
        return  # LLDP unavailable or failed: unknown
    current = _lldp_table(snap.lldp, fleet)
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
        _port_flap(port, name, link, now, router, out)
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
    _log_flaps(state, snap, now, router, out)
    # forget ports gone from the router for a day
    for name in [
        n
        for n, p in state.ports.items()
        if p.last_seen is not None and now - p.last_seen > INFRA_PORT_MEMORY
    ]:
        del state.ports[name]


def _infra_port(port: _PortState, name: str, now: float) -> bool:
    """A WAN port, or a port with an infrastructure LLDP neighbour lately."""
    if name.startswith("wan"):
        return True
    return port.infra_seen is not None and now - port.infra_seen <= INFRA_PORT_MEMORY


def _port_flap(
    port: _PortState,
    name: str,
    link: bool | None,
    now: float,
    router: str,
    out: list[Finding],
) -> None:
    """Link down/up per poll. Only infrastructure and WAN ports feed
    ``lan_port_flap``; on a client port (a PC rebooting) it is only counted.
    """
    if link is None:
        return
    before, port.link = port.link, link
    if before is True and link is False:
        port.poll_downs += 1
        infra = _infra_port(port, name, now)
        out.append(
            Finding(
                kind="lan.port_down",
                category=Category.LAN,
                source=Source.POLL,
                rule="lan_port_flap" if infra else None,
                scope=Scope.PORT,
                scope_key=port_key(router, name),
                event=infra,
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
    state: InfraState,
    snap: InfraSnapshot,
    now: float,
    router: str,
    out: list[Finding],
) -> None:
    """Link-down lines the poll did not see (flaps shorter than a poll).

    Kernel and netifd may both log the same down: per port the larger of
    the two counts is taken. Downs the poll already saw since the last log
    read are subtracted. Client ports are only counted (as in the poll).
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
            infra = _infra_port(port, name, now)
            source = Source.NETIFD if "netifd" in counts else Source.LOG
            out.append(
                Finding(
                    kind="lan.port_flap",
                    category=Category.LAN,
                    source=source,
                    rule="lan_port_flap" if infra else None,
                    scope=Scope.PORT,
                    scope_key=port_key(router, name),
                    event=infra,
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
    if not _infra_port(port, name, now):
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


def _ipv6_only_wan(wan: Mapping[str, Any]) -> bool:
    proto = wan.get("proto")
    iface = wan.get("interface")
    return (isinstance(proto, str) and proto.lower() in _IPV6_WAN_PROTOS) or (
        isinstance(iface, str) and iface.lower().endswith("6")
    )


def detect_wan(
    state: InfraState,
    snap: InfraSnapshot,
    router: str,
    rules: _RuleSet,
    out: list[Finding],
) -> None:
    """WAN down, reconnects, failover and a new WAN IPv4 (gateway only).

    Judged only on a gateway: a router whose IPv4 WAN was connected at
    least once while it carried the default route (``default_route`` not
    False). The engine keeps that role in its store
    (``InfraState.wan_gateway``). A dumb AP with OpenWrt's unplugged
    ``wan`` section is never judged; neither is an IPv6-only section
    (``wan6`` is pending in normal operation; IPv6 stays open, A7).

    The state is per WAN interface: a switch (mwan3 ``wan`` -> ``lte``)
    stores one info event ``wan.failover`` and starts a new baseline (no
    reconnect, no IP change). A reconnect is a down -> up between two polls,
    a WAN uptime that went down while connected in both, or an
    "Interface '<wan>' is now up" log line beyond those the poll saw.
    """
    wan, connected = snap.wan, snap.wan_connected
    if not isinstance(wan, Mapping) or connected is None or _ipv6_only_wan(wan):
        return
    if connected and wan.get("default_route") is not False:
        state.wan_gateway = True
    if not state.wan_gateway:
        return
    iface = wan.get("interface")
    iface = iface if isinstance(iface, str) and iface else None
    switched_from = (
        state.wan_iface
        if iface is not None and state.wan_iface not in (None, iface)
        else None
    )
    if iface is not None:
        state.wan_iface = iface
    if switched_from is not None:
        out.append(
            Finding(
                kind=WAN_FAILOVER_KIND,
                category=Category.WAN,
                source=Source.NETIFD,
                scope_key=router,
                event=True,
                severity=Severity.INFO,
                params={"from": switched_from, "to": iface},
            )
        )
        state.wan_connected = None
        state.wan_uptime = None
        state.wan_ip = None
        state.wan_poll_reconnects = 0
        state.wan_carry = 0
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
    _wan_log_reconnects(state, snap, wan, router, out, switched_from is not None)
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
    switched: bool,
) -> None:
    """Up lines of the WAN interface beyond the reconnects the polls saw.

    The WAN is read early in a poll, the log late. An up line written after
    the WAN read (router time > ``wan_at``) is seen by the next poll's WAN
    read, so it is carried over to the next log read instead of counted
    now. Router and HA clocks are compared directly (skew is a few seconds
    at most when NTP works; ``system_clock_skew`` flags larger ones).
    """
    if not snap.log_read:
        return
    iface = wan.get("interface")
    early = later = 0
    if isinstance(iface, str) and iface:
        for event in snap.log_events:
            if (
                getattr(event, "category", None) != "iface"
                or getattr(event, "kind", None) != "up"
                or getattr(event, "interface", None) != iface
            ):
                continue
            ts = getattr(event, "time_ms", 0)
            if (
                snap.wan_at is not None
                and isinstance(ts, int)
                and ts > 0
                and ts / 1000 > snap.wan_at
            ):
                later += 1
            else:
                early += 1
    extra = early + state.wan_carry - state.wan_poll_reconnects
    state.wan_poll_reconnects = 0
    state.wan_carry = 0 if switched else later
    if extra > 0 and not switched:
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


def detect_dhcp(snap: InfraSnapshot, router: str, out: list[Finding]) -> None:
    """Pool usage (level rule ``dhcp_pool_full``).

    No ARP-based conflict detector (P3 review K5): ``/proc/net/arp`` holds
    one entry per (IP, device), so two MACs for one IP in the merged map
    come from two devices or a stale ``getHostHints`` row, not from a
    conflict on one segment. Conflicts come from DHCPDECLINE only.
    """
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


def decline_cause(
    ip: str | None, mac: str | None, arp: Any
) -> tuple[CauseStatus, float]:
    """Cause status and confidence of a DHCPDECLINE (P3 review M3).

    Confirmed only when the router's ARP map shows the declined address on
    a MAC other than the declining client's; otherwise a hypothesis.
    """
    if isinstance(ip, str) and ip and isinstance(arp, Mapping):
        own = mac.lower() if isinstance(mac, str) else ""
        for other, addr in arp.items():
            if addr == ip and isinstance(other, str) and other.lower() != own:
                return CauseStatus.CONFIRMED, 1.0
    return CauseStatus.HYPOTHESIS, _DECLINE_CONFIDENCE


def finding_evidence(
    finding: Finding, router: str, event: NetEvent | None = None
) -> Evidence | None:
    """Evidence for the alarm machine, or None for a finding without rule."""
    if not finding.rule:
        return None
    if event is not None:
        return replace(
            Evidence.from_event(
                event, finding.rule, finding.scope, finding.scope_key, finding.value
            ),
            affected=finding.affected,
            severity=finding.escalate,
            hold=finding.hold,
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
        hold=finding.hold,
        affected=finding.affected,
        severity=finding.escalate,
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


# --- WLAN detectors (P4) ------------------------------------------------------------
#
# Deterministic like the infrastructure detectors. ``WifiState`` is one per
# engine and fleet-wide (roaming, DHCP after connect and the auth wave span
# routers), with a ``_WifiRouter`` part per router; ``WifiSnapshot`` is one
# router's poll. Log lines are ``observed``. Facts that only come from poll
# snapshots (band/AP change from client lists, no IP, weak clients, a client
# list that shrank) are ``inferred`` and capped at INFERRED_CONFIDENCE_CAP.
# Cause hypotheses go to ``params["causes"]`` as a list of {cause, status}
# (confirmed first); ``cause``/``cause_status`` carry the first one. A weak
# signal is ``confirmed`` only for a reconnect and a handshake timeout, by a
# signal at or below ``weak_dbm`` measured at most one poll after the line
# (P4 review E1); everywhere else it stays a hypothesis. ``exclusions.macs``
# keeps a client out of every WLAN detector (E3).
# Router log times (``time_ms``) pair lines; HA time (``now``) feeds the
# machine and the window counts.

WIFI_RECONNECT_KIND = "wifi.reconnect"
WIFI_MASS_DISCONNECT_KIND = "wifi.mass_disconnect"
WIFI_NO_IP_KIND = "wifi.no_ip"
WIFI_DHCP_AFTER_CONNECT_KIND = "wifi.dhcp_after_connect"
WIFI_BAND_CHANGE_KIND = "wifi.band_change"
WIFI_ROAM_KIND = "wifi.roam"
WIFI_WEAK_KIND = "wifi.weak_clients"
WIFI_ASSOC_REJECTED_KIND = "wifi.assoc_rejected"
WIFI_BACKHAUL_AUTH_KIND = "wifi.backhaul_auth_failed"
# Stored log lines that count as a failed authentication attempt.
WIFI_AUTH_KINDS = frozenset(
    {
        "wifi.psk_mismatch",
        "wifi.handshake_failed",
        "wifi.sae_failed",
        WIFI_BACKHAUL_AUTH_KIND,
    }
)
# Rules fed by log lines only: held open while the router's log cannot be
# read, so missing data never reads as "healthy". (The mass disconnect has
# a poll fallback without log, the auth wave resolves by count.)
WIFI_LOG_RULES = frozenset(
    {"wifi_reconnect_storm", "wifi_auth_failures", "wifi_dhcp_after_connect"}
)
WIFI_AUTH_WAVE_KEY = "fleet:wifi_auth_wave"

_DOWN_KINDS = frozenset({"disconnected", "deauth", "disassoc", "inactivity_timeout"})
_DHCP_FAIL_KINDS = frozenset({"nak", "no_address"})
# Lines of one failed attempt arrive together (hostapd writes the invalid
# MIC line and AP-STA-POSSIBLE-PSK-MISMATCH for the same 4-way handshake).
_AUTH_ATTEMPT_GAP_MS = 5000
# A deauth/disassoc line gives its reason to the AP-STA-DISCONNECTED line
# of the same station within this time.
_REASON_PAIR_MS = 5000
_WIFI_MEMORY = 3600.0
_DHCP_PAIR_KEEP_MS = 600_000
# A router's client list older than this is ignored for roaming decisions.
_PRESENT_MAX_AGE = 300.0
# usteer saw the client this recently: its fleet view decides AP changes.
_STEER_COVER = 300.0
_MAX_WIFI_KEYS = 4096
_LOG_QUALITY_BATCHES = 5
_MASS_PEAK_POLLS = 3
_SIGNAL_MIN = -120
_LOG_STATUS_OK = "ok"
_USTEER_OK = "ok"
_USTEER_UNAVAILABLE = "not_available"
# Router and HA clocks and whole-second log times: slack when a line is
# compared with the poll that measured the signal.
_SIGNAL_SLACK = 5.0
# A hostapd shutdown line (AP-DISABLED) this close to a disconnect cluster
# explains it.
_AP_DOWN_PAIR_MS = 10_000
# Log-based incidents are held at most this long after a router's log
# became unreadable (P4 review K3).
_WIFI_HOLD_MAX = 3600.0
_STEER_KINDS = frozenset({"usteer_connected", "usteer_disconnected"})

# cause keys (translation keys later, P6)
CAUSE_WEAK_SIGNAL = "weak_signal"


def _hyp(cause: str) -> tuple[str, CauseStatus]:
    return (cause, CauseStatus.HYPOTHESIS)


def _measured_signal(value: Any) -> int | None:
    """A plausible dBm value; hostapd's 0 means "unknown"."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if _SIGNAL_MIN <= value < 0 else None


def _weak_cause(
    signal: int | None, weak_dbm: float, fresh: bool
) -> tuple[str, CauseStatus]:
    """Weak signal as a cause: confirmed only by a measurement that fits the
    moment of the line (``fresh``), see ``_signal_fresh``."""
    if fresh and signal is not None and signal <= weak_dbm:
        return (CAUSE_WEAK_SIGNAL, CauseStatus.CONFIRMED)
    return _hyp(CAUSE_WEAK_SIGNAL)


def _signal_fresh(time_ms: int, now: float, poll_interval: float | None) -> bool:
    """True if the poll at ``now`` measured the signal at most one poll
    after the line at router time ``time_ms`` (P4 review E1)."""
    if time_ms <= 0:
        return False
    interval = poll_interval or _DEFAULT_POLL_INTERVAL
    age = now - time_ms / 1000
    return -_SIGNAL_SLACK <= age <= interval + _SIGNAL_SLACK


def cause_list(
    items: Iterable[tuple[str, CauseStatus]],
) -> tuple[str | None, CauseStatus | None, list[dict[str, str]]]:
    """Top cause, its status and the ordered list (confirmed first, no repeats)."""
    seen: dict[str, CauseStatus] = {}
    for cause, status in items:
        if cause not in seen or status is CauseStatus.CONFIRMED:
            seen[cause] = status
    ordered = sorted(seen.items(), key=lambda kv: kv[1] is not CauseStatus.CONFIRMED)
    if not ordered:
        return None, None, []
    listed = [{"cause": c, "status": s.value} for c, s in ordered]
    return ordered[0][0], ordered[0][1], listed


@dataclass(frozen=True)
class WifiContext:
    """One router's poll as lookup tables for the WLAN detectors.

    ``ifaces``: AP interface -> (band, ssid, phy). ``clients``: MAC (upper)
    -> client dict of this poll, None when no client list was read.
    """

    ifaces: Mapping[str, tuple[str | None, str | None, str]] = field(
        default_factory=dict
    )
    clients: Mapping[str, Mapping[str, Any]] | None = None

    def iface(self, name: str | None) -> tuple[str | None, str | None, str | None]:
        if not name:
            return None, None, None
        band, ssid, phy = self.ifaces.get(name, (None, None, phy_of(name)))
        return band, ssid, phy

    def describe(
        self, mac: str | None, iface: str | None = None
    ) -> tuple[dict[str, Any], int | None]:
        """Subject (mac, iface, ssid, band) and the client's measured signal."""
        client = (self.clients or {}).get(mac or "")
        if not iface and client is not None:
            radio = client.get("radio")
            iface = radio if isinstance(radio, str) else None
        band, ssid, _phy = self.iface(iface)
        subject = {
            key: value
            for key, value in (
                ("mac", mac),
                ("iface", iface),
                ("ssid", ssid),
                ("band", band),
            )
            if value
        }
        signal = _measured_signal(client.get("signal")) if client else None
        return subject, signal


def wifi_context(ap_interfaces: Any, clients: Any) -> WifiContext:
    """Build the lookup tables from coordinator data (broken entries skipped)."""
    ifaces: dict[str, tuple[str | None, str | None, str]] = {}
    for item in ap_interfaces if isinstance(ap_interfaces, list) else ():
        if not isinstance(item, dict):
            continue
        name = item.get("ifname")
        if not isinstance(name, str) or not name:
            continue
        ssid = item.get("ssid")
        phy = item.get("phy")
        ifaces[name] = (
            iface_band(item),
            ssid if isinstance(ssid, str) and ssid else None,
            phy if isinstance(phy, str) and phy else phy_of(name),
        )
    by_mac: dict[str, Mapping[str, Any]] | None = None
    if isinstance(clients, list):
        by_mac = {}
        for client in clients:
            if not isinstance(client, dict):
                continue
            mac = client.get("mac")
            if isinstance(mac, str) and mac:
                by_mac.setdefault(mac.upper(), client)
    return WifiContext(ifaces=ifaces, clients=by_mac)


@dataclass(frozen=True)
class WifiSnapshot:
    """The facts of one poll the WLAN detectors read.

    ``log_events`` are the new log lines of a fresh (non-baseline) fetch,
    ``log_lines``/``log_missed`` the cursor facts of a fetch in this poll
    (None: no fetch). ``dhcp`` is ``fleet.dhcp_context`` (lease, ARP and
    static MACs over the fleet; None = unknown). ``usteer`` maps a client
    MAC to the usteer nodes reporting it connected (this poll's usteer
    read, None if none). ``hosts`` maps a router address (lower case) to
    its entry id, for usteer's ``<ip>#hostapd.<if>`` node names.
    ``wifi_actions`` maps our own Wi-Fi action (``reload_wifi``,
    ``set_wifi_state``) to its HA time, ``exclude`` holds the MACs of
    ``exclusions.macs`` (upper case).
    """

    context: WifiContext = field(default_factory=WifiContext)
    has_aps: bool = False
    log_events: tuple[Any, ...] = ()
    log_status: str | None = None
    log_lines: int | None = None
    log_missed: int = 0
    dhcp: tuple[frozenset[str], frozenset[str], frozenset[str]] | None = None
    usteer: Mapping[str, tuple[str, ...]] | None = None
    usteer_status: str | None = None
    hosts: Mapping[str, str] = field(default_factory=dict)
    rebooted: bool = False
    poll_interval: float | None = None
    wifi_actions: Mapping[str, Any] | None = None
    exclude: frozenset[str] = frozenset()


@dataclass
class _Loc:
    router: str
    band: str | None
    iface: str | None


@dataclass
class _WifiRouter:
    """Per-router WLAN comparison state (memory only)."""

    # MAC -> (router time ms, iface, reason) of the last disconnect line
    last_down: dict[str, tuple[int, str | None, str | None]] = field(
        default_factory=dict
    )
    clients: frozenset[str] | None = None
    client_counts: deque[int] = field(
        default_factory=lambda: deque(maxlen=_MASS_PEAK_POLLS)
    )
    weak: set[str] = field(default_factory=set)
    no_ip: set[str] = field(default_factory=set)
    # AP-STA-DISCONNECTED lines not yet part of a mass disconnect:
    # (router time ms, MAC, iface, reason)
    downs: list[tuple[int, str, str | None, str | None]] = field(default_factory=list)
    mass_after_ms: int = 0
    # router time ms of the last hostapd shutdown line (AP-DISABLED)
    ap_down_ms: int = 0
    # poll fallback: clients missing on one poll and the count before (K4)
    mass_pending: tuple[frozenset[str], int] | None = None
    # HA time the log became unreadable (None: readable), and of the last poll
    log_lost_at: float | None = None
    last_now: float | None = None
    log_quality: deque[tuple[int, int]] = field(
        default_factory=lambda: deque(maxlen=_LOG_QUALITY_BATCHES)
    )
    log_status: str | None = None
    has_aps: bool = False
    clients_read: bool = False
    usteer: bool | None = None


@dataclass
class WifiState:
    """Fleet-wide WLAN state of the engine (memory only)."""

    routers: dict[str, _WifiRouter] = field(default_factory=dict)
    # router -> (HA time, MACs of its last client list)
    present: dict[str, tuple[float, frozenset[str]]] = field(default_factory=dict)
    loc: dict[str, _Loc] = field(default_factory=dict)
    steer_loc: dict[str, str] = field(default_factory=dict)
    steer_seen: dict[str, float] = field(default_factory=dict)
    # MAC -> recent connect lines (router time ms, router) over the fleet
    connects: dict[str, deque[tuple[int, str]]] = field(default_factory=dict)
    # MAC -> DHCP failures not yet paired (router time ms, router, kind)
    dhcp_fail: dict[str, list[tuple[int, str, str]]] = field(default_factory=dict)
    # MAC -> DHCPNAKs waiting for an ACK (router time ms, router, HA time read)
    nak_pending: dict[str, list[tuple[int, str, float]]] = field(default_factory=dict)
    # MAC -> router times ms of recent DHCPACKs
    dhcp_ack: dict[str, deque[int]] = field(default_factory=dict)
    # MAC -> usteer log lines (HA time read, kind, router of the node)
    steer_lines: dict[str, list[tuple[float, str, str | None]]] = field(
        default_factory=dict
    )
    # attempt key -> router time ms of its last failure line
    auth_last: dict[str, int] = field(default_factory=dict)
    # client MAC -> HA time it last counted for the auth wave (one per window)
    wave: dict[str, float] = field(default_factory=dict)
    # (rule, key) -> HA times of evidence, for the window count of events
    history: dict[tuple[str, str], deque[tuple[float, int]]] = field(
        default_factory=dict
    )

    def router(self, router: str) -> _WifiRouter:
        state = self.routers.get(router)
        if state is None:
            state = self.routers[router] = _WifiRouter()
        return state

    def forget(self, router: str) -> None:
        """Drop a router (unloaded or removed)."""
        self.routers.pop(router, None)
        self.present.pop(router, None)
        self.loc = {m: loc for m, loc in self.loc.items() if loc.router != router}
        self.steer_loc = {m: r for m, r in self.steer_loc.items() if r != router}

    def window_count(
        self, rule: str, key: str, now: float, n: int, window: float
    ) -> int:
        """Add ``n`` at ``now`` and return the sum within ``window`` s."""
        items = self.history.setdefault((rule, key), deque(maxlen=256))
        if n > 0:
            items.append((now, n))
        while items and items[0][0] <= now - max(window, _WIFI_MEMORY):
            items.popleft()
        return sum(c for ts, c in items if ts > now - window)

    def shift(self, delta: float) -> None:
        """Move stored HA times by ``delta`` (large backward clock jump)."""
        self.present = {r: (ts + delta, m) for r, (ts, m) in self.present.items()}
        self.steer_seen = {m: ts + delta for m, ts in self.steer_seen.items()}
        self.wave = {m: ts + delta for m, ts in self.wave.items()}
        self.steer_lines = {
            m: [(ts + delta, k, r) for ts, k, r in items]
            for m, items in self.steer_lines.items()
        }
        self.nak_pending = {
            m: [(t, r, seen + delta) for t, r, seen in items]
            for m, items in self.nak_pending.items()
        }
        for state in self.routers.values():
            if state.log_lost_at is not None:
                state.log_lost_at += delta
            if state.last_now is not None:
                state.last_now += delta
        self.history = {
            k: deque(((ts + delta, n) for ts, n in v), maxlen=256)
            for k, v in self.history.items()
        }

    def prune(self, now: float) -> None:
        """Forget old entries and keep every table bounded."""
        cutoff = now - _WIFI_MEMORY
        self.steer_seen = {m: t for m, t in self.steer_seen.items() if t > cutoff}
        self.steer_loc = {
            m: r for m, r in self.steer_loc.items() if m in self.steer_seen
        }
        self.wave = {m: t for m, t in self.wave.items() if t > cutoff}
        self.steer_lines = {
            m: kept
            for m, items in self.steer_lines.items()
            if (kept := [i for i in items if i[0] > cutoff][-8:])
        }
        self.nak_pending = {
            m: kept
            for m, items in self.nak_pending.items()
            if (kept := [n for n in items if n[2] > cutoff])
        }
        self.history = {
            k: v for k, v in self.history.items() if v and v[-1][0] > cutoff
        }
        for table in (
            self.loc,
            self.steer_loc,
            self.connects,
            self.dhcp_fail,
            self.dhcp_ack,
            self.nak_pending,
            self.steer_lines,
            self.auth_last,
            self.wave,
            self.history,
        ):
            _cap(table)
        for state in self.routers.values():
            _cap(state.last_down)

    def log_readable(self, router: str) -> bool:
        """True when the router's log could be read (lost lines only lower
        the coverage)."""
        state = self.routers.get(router)
        return state is not None and state.log_status == _LOG_STATUS_OK

    def may_hold(self, router: str, now: float) -> bool:
        """Hold the router's log-based incidents? Only while its log is
        unreadable, and at most _WIFI_HOLD_MAX after it became so (K3)."""
        state = self.routers.get(router)
        if state is None or state.log_status == _LOG_STATUS_OK:
            return False
        lost = state.log_lost_at
        return lost is None or now - lost < _WIFI_HOLD_MAX

    def coverage(self, router: str) -> dict[str, Any]:
        """WLAN data coverage of a router (diagnostics; the score is P6).

        ``log`` is the share of log lines read over the last fetches (0
        when the log is not readable), ``clients`` whether a client list
        was read. ``value`` averages both; missing data lowers it, it never
        reports a healthy WLAN on its own.
        """
        state = self.routers.get(router)
        if state is None or not state.has_aps:
            return {"applicable": state is not None and state.has_aps}
        log: float | None
        if state.log_status != _LOG_STATUS_OK:
            log = 0.0 if state.log_status is not None else None
        else:
            read = sum(lines for lines, _missed in state.log_quality)
            missed = sum(m for _lines, m in state.log_quality)
            log = read / (read + missed) if read + missed else 1.0
        clients = 1.0 if state.clients_read else 0.0
        parts = [clients, log if log is not None else 0.0]
        return {
            "applicable": True,
            "clients": state.clients_read,
            "log": None if log is None else round(log, 2),
            "log_missed_lines": sum(m for _lines, m in state.log_quality),
            "usteer": state.usteer,
            "value": round(sum(parts) / len(parts), 2),
        }


def _cap(table: dict[Any, Any]) -> None:
    """Keep the newest _MAX_WIFI_KEYS entries (dicts keep insertion order)."""
    excess = len(table) - _MAX_WIFI_KEYS
    for key in list(table)[: max(0, excess)]:
        del table[key]


def detect_wifi(
    state: WifiState,
    snap: WifiSnapshot,
    now: float,
    router: str,
    thresholds: Mapping[str, Any],
) -> list[Finding]:
    """Run the WLAN detectors for one poll of a router."""
    out: list[Finding] = []
    rules = _RuleSet(thresholds)
    state.prune(now)
    rstate = state.router(router)
    _wifi_bookkeeping(rstate, snap, now)
    read_before, rstate.last_now = rstate.last_now, now
    if snap.exclude:
        snap = _without_excluded(snap)
    lines = _unique_lines(snap.log_events)
    weak_dbm = _rule_num(rules.get("wifi_weak_clients"), "weak_dbm", -75)
    _record_steer_lines(state, snap, lines, now, router)
    _reconnects(
        state,
        rstate,
        snap,
        lines,
        now,
        router,
        rules.get("wifi_reconnect_storm"),
        weak_dbm,
        out,
    )
    _mass_disconnect_log(
        rstate,
        snap,
        lines,
        now,
        read_before,
        router,
        rules.get("wifi_mass_disconnect"),
        out,
    )
    _dhcp_after_connect(
        state, snap, lines, now, router, rules.get("wifi_dhcp_after_connect"), out
    )
    clients = snap.context.clients
    if clients is not None:
        _mass_disconnect_poll(
            state,
            rstate,
            snap,
            now,
            read_before,
            router,
            rules.get("wifi_mass_disconnect"),
            out,
        )
        _no_ip(rstate, snap, now, router, rules.get("wifi_no_ip"), out)
        _moves(state, snap, now, router, rules, out)
        _weak_clients(rstate, snap, router, rules.get("wifi_weak_clients"), out)
        rstate.clients = frozenset(clients)
        rstate.client_counts.append(len(clients))
    _steer_moves(state, snap, now, router, rules.get("wifi_roam_flapping"), out)
    return out


def _without_excluded(snap: WifiSnapshot) -> WifiSnapshot:
    """The snapshot without the excluded MACs (lines, clients, usteer)."""
    excl = snap.exclude
    clients = snap.context.clients
    return replace(
        snap,
        context=WifiContext(
            ifaces=snap.context.ifaces,
            clients=None
            if clients is None
            else {m: c for m, c in clients.items() if m not in excl},
        ),
        log_events=tuple(
            e
            for e in snap.log_events
            if not (isinstance(getattr(e, "mac", None), str) and e.mac.upper() in excl)
        ),
        usteer=None
        if snap.usteer is None
        else {
            m: n
            for m, n in snap.usteer.items()
            if not (isinstance(m, str) and m.upper() in excl)
        },
    )


def _wifi_bookkeeping(rstate: _WifiRouter, snap: WifiSnapshot, now: float) -> None:
    rstate.has_aps = snap.has_aps
    rstate.clients_read = snap.context.clients is not None
    if snap.log_status == _LOG_STATUS_OK:
        rstate.log_lost_at = None
    elif rstate.log_lost_at is None:
        rstate.log_lost_at = now
    rstate.log_status = snap.log_status
    if snap.log_lines is not None:
        rstate.log_quality.append((max(0, snap.log_lines), max(0, snap.log_missed)))
    if snap.usteer_status == _USTEER_OK:
        rstate.usteer = True
    elif snap.usteer_status == _USTEER_UNAVAILABLE:
        rstate.usteer = False


def _unique_lines(events: Iterable[Any]) -> list[Any]:
    """Wi-Fi and DHCP lines in router time order, exact duplicates dropped."""
    seen: set[tuple[Any, ...]] = set()
    out: list[Any] = []
    for event in events:
        if getattr(event, "category", None) not in ("wifi", "dhcp"):
            continue
        time_ms = getattr(event, "time_ms", 0)
        key = (
            event.category,
            event.kind,
            event.mac,
            event.interface,
            time_ms,
            getattr(event, "reason", None),
            event.log_id if not time_ms else None,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(event)
    out.sort(key=lambda e: (e.time_ms, e.log_id))
    return out


def _reconnects(
    state: WifiState,
    rstate: _WifiRouter,
    snap: WifiSnapshot,
    lines: list[Any],
    now: float,
    router: str,
    rule: Mapping[str, Any],
    weak_dbm: float,
    out: list[Finding],
) -> None:
    """A connect to the same interface within ``max_gap`` s (30) of a
    disconnect of the same client on this router. Another radio is band
    steering; a connect line of another router in between is roaming
    (ping-pong), so the pair is dropped. A longer gap is a client that slept
    (P4 review M3/M4)."""
    found: dict[str, list[str | None]] = {}
    ifaces: dict[str, str | None] = {}
    last_ms: dict[str, int] = {}
    limit = int(_rule_num(rule, "max_gap", 30) * 1000)
    for ev in lines:
        if ev.category != "wifi" or not ev.mac or ev.time_ms <= 0:
            continue
        if ev.kind in _DOWN_KINDS:
            if ev.reason == "prune":
                continue  # the station moved to another BSS of this hostapd
            prev = rstate.last_down.get(ev.mac)
            reason = ev.reason
            if (
                reason is None
                and prev is not None
                and abs(ev.time_ms - prev[0]) <= _REASON_PAIR_MS
            ):
                reason = prev[2]
            rstate.last_down.pop(ev.mac, None)
            rstate.last_down[ev.mac] = (ev.time_ms, ev.interface, reason)
        elif ev.kind == "connected":
            prev = rstate.last_down.pop(ev.mac, None)
            if (
                prev is not None
                and 0 <= ev.time_ms - prev[0] <= limit
                and (prev[1] is None or ev.interface is None or prev[1] == ev.interface)
                and not _connected_elsewhere(state, ev.mac, router, prev[0], ev.time_ms)
            ):
                found.setdefault(ev.mac, []).append(prev[2])
                ifaces[ev.mac] = ev.interface
                last_ms[ev.mac] = ev.time_ms
    window = _rule_num(rule, "window", 600)
    for mac, reasons in found.items():
        subject, signal = snap.context.describe(mac, ifaces.get(mac))
        fresh = _signal_fresh(last_ms[mac], now, snap.poll_interval)
        hyps = [_weak_cause(signal, weak_dbm, fresh)]
        if "local_request" in reasons:
            hyps.append(_hyp("steering"))
        if "inactivity" in reasons:
            hyps.append(_hyp("client_power_save"))
        hyps += [_hyp(c) for c in ("interference", "power_supply", "roaming", "auth")]
        cause, status, causes = cause_list(hyps)
        n = len(reasons)
        out.append(
            Finding(
                kind=WIFI_RECONNECT_KIND,
                category=Category.WIFI,
                source=Source.HOSTAPD,
                rule="wifi_reconnect_storm",
                scope=Scope.CLIENT,
                scope_key=mac,
                event=True,
                count=n,
                cause=cause,
                cause_status=status,
                subject=subject,
                signal=signal,
                params={
                    "window_count": state.window_count(
                        "wifi_reconnect_storm", mac, now, n, window
                    ),
                    "window_s": round(window),
                    "reasons": sorted({r or "none" for r in reasons}),
                    "causes": causes,
                },
            )
        )


def _connected_elsewhere(
    state: WifiState, mac: str, router: str, start_ms: int, end_ms: int
) -> bool:
    """A connect line of ``mac`` on another router between two times."""
    return any(
        other != router and start_ms <= t <= end_ms
        for t, other in state.connects.get(mac, ())
    )


def _record_steer_lines(
    state: WifiState, snap: WifiSnapshot, lines: list[Any], now: float, router: str
) -> None:
    """Keep usteer's connected/disconnected lines for the roam check (E2)."""
    for ev in lines:
        if ev.category != "wifi" or ev.kind not in _STEER_KINDS or not ev.mac:
            continue
        node = ev.interface or ""
        ap = _steer_node_router(node, router, snap.hosts) if node else None
        items = state.steer_lines.setdefault(ev.mac, [])
        items.append((now, ev.kind, ap))
        del items[:-8]


def _mass_trigger(
    rule: Mapping[str, Any], clients: int, base: int
) -> tuple[bool, float]:
    """(trigger, ratio). The ratio path needs ``ratio_min_clients`` too, so
    one client of two leaving is no mass disconnect."""
    ratio = clients / max(base, clients) if clients else 0.0
    if clients >= _rule_num(rule, "min_clients", 5):
        return True, ratio
    return (
        clients >= _rule_num(rule, "ratio_min_clients", 3)
        and ratio >= _rule_num(rule, "min_ratio", 0.5)
    ), ratio


def _own_wifi_action(snap: WifiSnapshot, read_before: float | None, now: float) -> bool:
    """Our own reload_wifi/set_wifi_state explains client drops now."""
    actions = snap.wifi_actions if isinstance(snap.wifi_actions, Mapping) else {}
    return any(_own_action(t, read_before, now) for t in actions.values())


def _down_reasons(lines: list[Any]) -> dict[int, str | None]:
    """Reason of each AP-STA-DISCONNECTED line (by log id): its own, or that
    of a deauth/disassoc line of the same station within _REASON_PAIR_MS."""
    told: dict[str, list[tuple[int, str]]] = {}
    for ev in lines:
        if ev.category == "wifi" and ev.kind in _DOWN_KINDS and ev.reason and ev.mac:
            told.setdefault(ev.mac, []).append((ev.time_ms, ev.reason))
    out: dict[int, str | None] = {}
    for ev in lines:
        if ev.category != "wifi" or ev.kind != "disconnected":
            continue
        reason = ev.reason
        if reason is None:
            near = [
                (abs(t - ev.time_ms), r)
                for t, r in told.get(ev.mac or "", ())
                if abs(t - ev.time_ms) <= _REASON_PAIR_MS
            ]
            reason = min(near)[1] if near else None
        out[ev.log_id] = reason
    return out


def _mass_disconnect_log(
    rstate: _WifiRouter,
    snap: WifiSnapshot,
    lines: list[Any],
    now: float,
    read_before: float | None,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """At least ``min_clients`` (or ``min_ratio`` of the clients) leaving
    within ``window`` s (5) of router time, from AP-STA-DISCONNECTED lines.
    Idle timeouts do not count. A reboot, a hostapd shutdown line or our own
    Wi-Fi action explains a cluster: then nothing is reported (P4 review M5)."""
    window_ms = int(_rule_num(rule, "window", 5) * 1000)
    reasons_of = _down_reasons(lines)
    for ev in lines:
        if ev.category == "wifi" and ev.kind == "ap_disabled" and ev.time_ms > 0:
            rstate.ap_down_ms = max(rstate.ap_down_ms, ev.time_ms)
        if (
            ev.category == "wifi"
            and ev.kind == "disconnected"
            and ev.mac
            and ev.time_ms > rstate.mass_after_ms
        ):
            reason = reasons_of.get(ev.log_id)
            if reason == "inactivity":
                continue  # the client went idle, the AP is fine
            rstate.downs.append((ev.time_ms, ev.mac, ev.interface, reason))
    if not rstate.downs:
        return
    if snap.rebooted:
        rstate.downs = []
        return
    rstate.downs.sort()
    newest = rstate.downs[-1][0]
    # keep what can still join a cluster with lines of the next read
    best: tuple[int, int, int] | None = None  # (clients, start, end)
    start = 0
    for end in range(len(rstate.downs)):
        while rstate.downs[end][0] - rstate.downs[start][0] > window_ms:
            start += 1
        macs = {d[1] for d in rstate.downs[start : end + 1]}
        if best is None or len(macs) > best[0]:
            best = (len(macs), start, end)
    assert best is not None
    clients, first, last = best
    base = max(rstate.client_counts, default=0)
    hit, ratio = _mass_trigger(rule, clients, base)
    if not hit:
        rstate.downs = [d for d in rstate.downs if d[0] > newest - window_ms]
        return
    cluster = rstate.downs[first : last + 1]
    end_ms = cluster[-1][0]
    rstate.mass_after_ms = end_ms
    rstate.downs = [d for d in rstate.downs if d[0] > end_ms]
    if (
        rstate.ap_down_ms
        and cluster[0][0] - _AP_DOWN_PAIR_MS <= rstate.ap_down_ms
        and rstate.ap_down_ms <= end_ms + _AP_DOWN_PAIR_MS
    ) or _own_wifi_action(snap, read_before, now):
        return  # hostapd went down or we reloaded the Wi-Fi ourselves
    reasons: Counter[str] = Counter(d[3] or "none" for d in cluster)
    ifaces = sorted({d[2] for d in cluster if d[2]})
    bands = sorted({b for i in ifaces if (b := snap.context.iface(i)[0])})
    hyps = [_hyp("radio_restart"), _hyp("interference"), _hyp("power_supply")]
    if reasons.get("local_request", 0) * 2 >= clients:
        hyps.insert(0, _hyp("steering"))
    cause, status, causes = cause_list(hyps)
    out.append(
        Finding(
            kind=WIFI_MASS_DISCONNECT_KIND,
            category=Category.WIFI,
            source=Source.HOSTAPD,
            rule="wifi_mass_disconnect",
            scope=Scope.ROUTER,
            scope_key=router,
            event=True,
            count=clients,
            affected=clients,
            severity=Severity.WARNING,
            cause=cause,
            cause_status=status,
            subject={"ifaces": ifaces, "bands": bands} if ifaces else {},
            params={
                "window_count": clients,
                "window_s": round(window_ms / 1000),
                "ratio": round(ratio, 2),
                "reasons": dict(sorted(reasons.items())),
                "causes": causes,
            },
        )
    )


def _fresh_elsewhere(state: WifiState, router: str, now: float) -> frozenset[str]:
    """MACs in the recent client lists of the other routers."""
    macs: set[str] = set()
    for other, (ts, listed) in state.present.items():
        if other != router and now - ts <= _PRESENT_MAX_AGE:
            macs |= listed
    return frozenset(macs)


def _mass_disconnect_poll(
    state: WifiState,
    rstate: _WifiRouter,
    snap: WifiSnapshot,
    now: float,
    read_before: float | None,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """Without a readable log: the client list shrank and stayed so on the
    next poll too (a short gap in one list is no mass disconnect, P4 review
    K4); clients now on another router excluded. ``inferred``; a reboot
    poll is left to the correlation (P5), our own Wi-Fi action explains it."""
    pending, rstate.mass_pending = rstate.mass_pending, None
    if (
        snap.log_status == _LOG_STATUS_OK
        or snap.rebooted
        or rstate.clients is None
        or snap.context.clients is None
        or _own_wifi_action(snap, read_before, now)
    ):
        return
    current = set(snap.context.clients)
    elsewhere = _fresh_elsewhere(state, router, now)
    if pending is not None:
        still = pending[0] - current - elsewhere
        hit, ratio = _mass_trigger(rule, len(still), pending[1])
        if hit:
            _poll_mass_finding(snap, router, len(still), ratio, out)
            return
    lost = rstate.clients - current - elsewhere
    hit, _ratio = _mass_trigger(rule, len(lost), len(rstate.clients))
    if hit:
        rstate.mass_pending = (frozenset(lost), len(rstate.clients))


def _poll_mass_finding(
    snap: WifiSnapshot, router: str, lost: int, ratio: float, out: list[Finding]
) -> None:
    cause, status, causes = cause_list(
        [_hyp("radio_restart"), _hyp("interference"), _hyp("power_supply")]
    )
    interval = snap.poll_interval or _DEFAULT_POLL_INTERVAL
    out.append(
        Finding(
            kind=WIFI_MASS_DISCONNECT_KIND,
            category=Category.WIFI,
            source=Source.POLL,
            rule="wifi_mass_disconnect",
            scope=Scope.ROUTER,
            scope_key=router,
            event=True,
            count=lost,
            affected=lost,
            severity=Severity.WARNING,
            origin=Origin.INFERRED,
            confidence=INFERRED_CONFIDENCE_CAP,
            cause=cause,
            cause_status=status,
            params={
                "window_count": lost,
                "window_s": round(interval * 2),
                "ratio": round(ratio, 2),
                "causes": causes,
            },
        )
    )


def _dhcp_after_connect(
    state: WifiState,
    snap: WifiSnapshot,
    lines: list[Any],
    now: float,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """DHCPNAK / "no address available" within ``window`` s (router time)
    after a connect of the same MAC anywhere in the fleet. Either side may
    be read first (staggered log reads), so both are kept for a while.
    A NAK counts only if no ACK of the same MAC follows within ``ack_grace``
    s (INIT-REBOOT asks for the old address first, P4 review M1/E4); it is
    decided once the DHCP router's log was read ``ack_grace`` s after it."""
    window_ms = int(_rule_num(rule, "window", 60) * 1000)
    grace = _rule_num(rule, "ack_grace", 30)
    grace_ms = int(grace * 1000)
    newest = _newest_ms(lines)
    for ev in lines:
        if not ev.mac or ev.time_ms <= 0:
            continue
        if ev.category == "wifi" and ev.kind == "connected":
            conns = state.connects.setdefault(ev.mac, deque(maxlen=8))
            conns.append((ev.time_ms, router))
            fails = state.dhcp_fail.get(ev.mac, [])
            for fail in list(fails):
                if 0 <= fail[0] - ev.time_ms <= window_ms:
                    fails.remove(fail)
                    out.append(
                        _dhcp_finding(
                            state, snap, now, rule, ev.mac, ev.time_ms, router, fail
                        )
                    )
            if not fails:
                state.dhcp_fail.pop(ev.mac, None)
        elif ev.category == "dhcp" and ev.kind == "ack":
            state.dhcp_ack.setdefault(ev.mac, deque(maxlen=8)).append(ev.time_ms)
        elif ev.category == "dhcp" and ev.kind == "nak":
            naks = state.nak_pending.setdefault(ev.mac, [])
            naks.append((ev.time_ms, router, now))
            del naks[:-8]
        elif ev.category == "dhcp" and ev.kind in _DHCP_FAIL_KINDS:
            _dhcp_fail_line(
                state, snap, now, rule, ev.mac, (ev.time_ms, router, ev.kind), out
            )
    if snap.log_lines is not None:  # this router's log was read now
        for mac in list(state.nak_pending):
            waiting: list[tuple[int, str, float]] = []
            for t, nak_router, seen in state.nak_pending[mac]:
                if any(t <= a <= t + grace_ms for a in state.dhcp_ack.get(mac, ())):
                    continue  # the client got its lease: normal INIT-REBOOT
                if nak_router == router and (
                    now - seen >= grace or newest >= t + grace_ms
                ):
                    _dhcp_fail_line(
                        state, snap, now, rule, mac, (t, nak_router, "nak"), out
                    )
                else:
                    waiting.append((t, nak_router, seen))
            if waiting:
                state.nak_pending[mac] = waiting
            else:
                del state.nak_pending[mac]
    for mac in list(state.dhcp_fail):
        state.dhcp_fail[mac] = [
            f for f in state.dhcp_fail[mac] if f[0] > newest - _DHCP_PAIR_KEEP_MS
        ]
        if not state.dhcp_fail[mac]:
            del state.dhcp_fail[mac]


def _dhcp_fail_line(
    state: WifiState,
    snap: WifiSnapshot,
    now: float,
    rule: Mapping[str, Any],
    mac: str,
    fail: tuple[int, str, str],
    out: list[Finding],
) -> None:
    """Pair a DHCP failure with an earlier connect, or keep it for a
    connect line read later."""
    window_ms = int(_rule_num(rule, "window", 60) * 1000)
    conn = next(
        (
            c
            for c in reversed(state.connects.get(mac, ()))
            if 0 <= fail[0] - c[0] <= window_ms
        ),
        None,
    )
    if conn is not None:
        out.append(_dhcp_finding(state, snap, now, rule, mac, conn[0], conn[1], fail))
        return
    kept = state.dhcp_fail.setdefault(mac, [])
    kept.append(fail)
    del kept[:-8]


def _newest_ms(lines: list[Any]) -> int:
    return max((ev.time_ms for ev in lines), default=0)


def _dhcp_finding(
    state: WifiState,
    snap: WifiSnapshot,
    now: float,
    rule: Mapping[str, Any],
    mac: str,
    connect_ms: int,
    ap_router: str,
    fail: tuple[int, str, str],
) -> Finding:
    subject, signal = snap.context.describe(mac)
    if fail[2] == "no_address":
        hyps = [_hyp("pool_exhausted"), _hyp("dhcp_server")]
    else:
        hyps = [_hyp("wrong_network"), _hyp("vlan")]
    cause, status, causes = cause_list(hyps)
    window = _rule_num(rule, "window", 60)
    return Finding(
        kind=WIFI_DHCP_AFTER_CONNECT_KIND,
        category=Category.WIFI,
        source=Source.LOG,
        rule="wifi_dhcp_after_connect",
        scope=Scope.CLIENT,
        scope_key=mac,
        event=True,
        severity=Severity.WARNING,
        cause=cause,
        cause_status=status,
        subject=subject,
        signal=signal,
        params={
            "dhcp": fail[2],
            "delay_s": round((fail[0] - connect_ms) / 1000),
            "ap_router": ap_router,
            "dhcp_router": fail[1],
            "window_count": state.window_count(
                "wifi_dhcp_after_connect", mac, now, 1, window
            ),
            "window_s": round(window),
            "causes": causes,
        },
    )


def _no_ip(
    rstate: _WifiRouter,
    snap: WifiSnapshot,
    now: float,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """``dhcp_health.client_dhcp_status`` per client (level 1 = no lease, no
    ARP entry, no static host after DHCP_MISSING_AFTER_SECONDS). Unknown
    without a usable fleet DHCP view (``fleet.dhcp_context`` None)."""
    clients = snap.context.clients or {}
    rstate.no_ip &= set(clients)
    if snap.dhcp is None:
        return
    leases, arp, static = snap.dhcp
    now_dt = datetime.fromtimestamp(now, UTC)
    status = {
        mac: client_dhcp_status(
            mac, client.get("connected_since"), now_dt, leases, arp, static
        )
        for mac, client in clients.items()
    }
    missing = [mac for mac, s in status.items() if s == DHCP_MISSING]
    warn = len(missing) >= _rule_num(rule, "warn_clients_per_ap", 3)
    cause, cause_status, causes = cause_list(
        [_hyp("dhcp_server"), _hyp("vlan"), _hyp("static_ip")]
    )
    for mac, value in status.items():
        if value == DHCP_PENDING:
            continue
        no_ip = value == DHCP_MISSING
        first = no_ip and mac not in rstate.no_ip
        if no_ip:
            rstate.no_ip.add(mac)
        else:
            rstate.no_ip.discard(mac)
        subject, signal = snap.context.describe(mac)
        out.append(
            Finding(
                kind=WIFI_NO_IP_KIND,
                category=Category.WIFI,
                source=Source.POLL,
                rule="wifi_no_ip",
                scope=Scope.CLIENT,
                scope_key=mac,
                value=1.0 if no_ip else 0.0,
                event=first,
                origin=Origin.INFERRED,
                confidence=INFERRED_CONFIDENCE_CAP,
                cause=cause if no_ip else None,
                cause_status=cause_status if no_ip else None,
                escalate=Severity.WARNING if no_ip and warn else None,
                subject=subject,
                signal=signal,
                params={"clients_without_ip": len(missing), "causes": causes}
                if first
                else {},
            )
        )


def _moves(
    state: WifiState,
    snap: WifiSnapshot,
    now: float,
    router: str,
    rules: _RuleSet,
    out: list[Finding],
) -> None:
    """Band change (same router) and AP change (other router) of a client
    between two client lists. A client listed by two routers at once (the
    old AP keeps a station until its inactivity timeout) is undecided until
    one list drops it; then the change counts once. ``inferred``."""
    clients = snap.context.clients or {}
    state.present[router] = (now, frozenset(clients))
    elsewhere = _fresh_elsewhere(state, router, now)
    for mac, client in clients.items():
        if mac in elsewhere:
            continue
        radio = client.get("radio")
        iface = radio if isinstance(radio, str) and radio else None
        band = snap.context.iface(iface)[0]
        prev = state.loc.get(mac)
        if prev is not None and prev.router == router and band is None:
            band = prev.band
        state.loc.pop(mac, None)
        state.loc[mac] = _Loc(router, band, iface)
        if prev is None:
            continue
        if prev.router != router:
            seen = state.steer_seen.get(mac)
            if seen is not None and now - seen <= _STEER_COVER:
                continue  # usteer's view decides (observed)
            out.append(
                _roam_finding(
                    state,
                    snap,
                    now,
                    rules.get("wifi_roam_flapping"),
                    mac,
                    prev.router,
                    router,
                    Source.POLL,
                )
            )
        elif prev.band and band and prev.band != band:
            out.append(
                _band_finding(
                    state,
                    snap,
                    now,
                    rules.get("wifi_band_flapping"),
                    mac,
                    prev.band,
                    band,
                )
            )


def _band_finding(
    state: WifiState,
    snap: WifiSnapshot,
    now: float,
    rule: Mapping[str, Any],
    mac: str,
    before: str,
    after: str,
) -> Finding:
    subject, signal = snap.context.describe(mac)
    cause, status, causes = cause_list(
        [_hyp("band_steering"), _hyp(CAUSE_WEAK_SIGNAL), _hyp("client_driver")]
    )
    window = _rule_num(rule, "window", 600)
    return Finding(
        kind=WIFI_BAND_CHANGE_KIND,
        category=Category.WIFI,
        source=Source.POLL,
        rule="wifi_band_flapping",
        scope=Scope.CLIENT,
        scope_key=mac,
        event=True,
        origin=Origin.INFERRED,
        confidence=INFERRED_CONFIDENCE_CAP,
        cause=cause,
        cause_status=status,
        subject=subject,
        signal=signal,
        params={
            "from_band": before,
            "to_band": after,
            "window_count": state.window_count(
                "wifi_band_flapping", mac, now, 1, window
            ),
            "window_s": round(window),
            "causes": causes,
        },
    )


def _roam_finding(
    state: WifiState,
    snap: WifiSnapshot,
    now: float,
    rule: Mapping[str, Any],
    mac: str,
    before: str,
    after: str,
    source: Source,
    observed: bool = False,
) -> Finding:
    """A roam; ``observed`` only with a usteer log line for it (E2)."""
    subject, signal = snap.context.describe(mac)
    cause, status, causes = cause_list(
        [
            _hyp(CAUSE_WEAK_SIGNAL),
            _hyp("overlapping_coverage"),
            _hyp("steering"),
        ]
    )
    window = _rule_num(rule, "window", 600)
    return Finding(
        kind=WIFI_ROAM_KIND,
        category=Category.WIFI,
        source=source,
        rule="wifi_roam_flapping",
        scope=Scope.CLIENT,
        scope_key=mac,
        event=True,
        origin=Origin.OBSERVED if observed else Origin.INFERRED,
        confidence=1.0 if observed else INFERRED_CONFIDENCE_CAP,
        cause=cause,
        cause_status=status,
        subject=subject,
        signal=signal,
        params={
            "from_router": before,
            "to_router": after,
            "window_count": state.window_count(
                "wifi_roam_flapping", mac, now, 1, window
            ),
            "window_s": round(window),
            "causes": causes,
        },
    )


def _steer_node_router(node: str, router: str, hosts: Mapping[str, str]) -> str | None:
    """Entry id of a usteer node: local nodes belong to the answering router,
    ``<ip>#hostapd.<if>`` to the router configured with that address."""
    if "#" not in node:
        return router
    return hosts.get(node.split("#", 1)[0].strip().lower())


def _steer_moves(
    state: WifiState,
    snap: WifiSnapshot,
    now: float,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """AP changes from usteer's fleet view. Only clients with exactly one
    connected node whose router is known take part; the views of several
    usteer routers share one location, so a change counts once. Comparing
    two snapshots is ``inferred``; a usteer log line of the move (connected
    to the new node or disconnected from the old one, read since the last
    snapshot) makes it ``observed`` (P4 review E2)."""
    for mac, nodes in (snap.usteer or {}).items():
        if not isinstance(mac, str) or len(nodes) != 1:
            continue
        ap = _steer_node_router(nodes[0], router, snap.hosts)
        if ap is None:
            continue
        mac = mac.upper()
        seen_before = state.steer_seen.get(mac)
        state.steer_seen[mac] = now
        prev = state.steer_loc.get(mac)
        state.steer_loc[mac] = ap
        if prev is not None and prev != ap:
            since = (seen_before if seen_before is not None else now) - _SIGNAL_SLACK
            observed = any(
                ts >= since
                and (
                    (kind == "usteer_connected" and node == ap)
                    or (kind == "usteer_disconnected" and node == prev)
                )
                for ts, kind, node in state.steer_lines.get(mac, ())
            )
            out.append(
                _roam_finding(
                    state, snap, now, rule, mac, prev, ap, Source.USTEER, observed
                )
            )


def _weak_clients(
    rstate: _WifiRouter,
    snap: WifiSnapshot,
    router: str,
    rule: Mapping[str, Any],
    out: list[Finding],
) -> None:
    """Level per radio: clients at or below ``weak_dbm``; a weak client
    counts until it is above ``clear_dbm`` again (hysteresis). The rule's
    ``hold`` keeps the count up for 600 s before an incident opens."""
    weak_dbm = _rule_num(rule, "weak_dbm", -75)
    clear_dbm = _rule_num(rule, "clear_dbm", -70)
    counts: dict[str, int] = {
        phy: 0 for _band, _ssid, phy in snap.context.ifaces.values()
    }
    bands: dict[str, set[str]] = {}
    weak: set[str] = set()
    for mac, client in (snap.context.clients or {}).items():
        signal = _measured_signal(client.get("signal"))
        radio = client.get("radio")
        band, _ssid, phy = snap.context.iface(radio if isinstance(radio, str) else None)
        if phy is None:
            continue
        counts.setdefault(phy, 0)
        if band:
            bands.setdefault(phy, set()).add(band)
        if signal is None:
            continue
        if signal <= weak_dbm or (mac in rstate.weak and signal <= clear_dbm):
            weak.add(mac)
            counts[phy] += 1
    rstate.weak = weak
    cause, status, _causes = cause_list([_hyp("coverage")])
    for phy, n in sorted(counts.items()):
        subject: dict[str, Any] = {"radio": phy}
        if bands.get(phy):
            subject["bands"] = sorted(bands[phy])
        out.append(
            Finding(
                kind=WIFI_WEAK_KIND,
                category=Category.WIFI,
                source=Source.POLL,
                rule="wifi_weak_clients",
                scope=Scope.RADIO,
                scope_key=f"{router}:radio:{phy}",
                value=float(n),
                origin=Origin.INFERRED,
                confidence=INFERRED_CONFIDENCE_CAP,
                cause=cause if n else None,
                cause_status=status if n else None,
                subject=subject,
            )
        )


@dataclass(frozen=True)
class WifiLogMeta:
    """Enrichment of a stored Wi-Fi log line (``NetEvent`` fields)."""

    subject: dict[str, Any]
    signal: int | None = None
    cause: str | None = None
    cause_status: CauseStatus | None = None
    params: dict[str, Any] = field(default_factory=dict)
    # failed authentication: a new attempt (not a second line of one)
    attempt: bool = False
    attempt_key: str | None = None


def wifi_log_meta(
    state: WifiState,
    context: WifiContext,
    event: Any,
    router: str,
    now: float,
    thresholds: Mapping[str, Any],
    poll_interval: float | None = None,
) -> WifiLogMeta:
    """SSID, band, signal, causes and window count of a stored Wi-Fi line
    (fresh lines only, not those of a log gap)."""
    rules = _RuleSet(thresholds)
    weak_dbm = _rule_num(rules.get("wifi_weak_clients"), "weak_dbm", -75)
    subject, signal = context.describe(event.mac, event.interface)
    fresh = _signal_fresh(event.time_ms, now, poll_interval)
    params: dict[str, Any] = {}
    if getattr(event, "reason", None):
        params["reason"] = event.reason
    key = f"{event.category}.{event.kind}"
    hyps: list[tuple[str, CauseStatus]] = []
    attempt = False
    attempt_key: str | None = None
    if key in WIFI_AUTH_KINDS:
        attempt_key = event.mac or f"{router}:backhaul:{event.interface or '?'}"
        last = state.auth_last.get(attempt_key)
        attempt = (
            event.time_ms <= 0
            or last is None
            or abs(event.time_ms - last) > _AUTH_ATTEMPT_GAP_MS
        )
        if event.time_ms > 0:
            state.auth_last.pop(attempt_key, None)
            state.auth_last[attempt_key] = event.time_ms
        window = _rule_num(rules.get("wifi_auth_failures"), "window", 600)
        params["window_count"] = state.window_count(
            "wifi_auth_failures", attempt_key, now, 1 if attempt else 0, window
        )
        params["window_s"] = round(window)
        hyps = _auth_hypotheses(key, event.reason, signal, weak_dbm, fresh)
    elif key == WIFI_ASSOC_REJECTED_KIND:
        if event.reason == "max_sta":
            hyps = [("ap_full", CauseStatus.CONFIRMED)]
        elif event.reason == "blocked":
            hyps = [("mac_filter", CauseStatus.CONFIRMED)]
        else:
            hyps = [_hyp("ap_full"), _hyp(CAUSE_WEAK_SIGNAL)]
    cause, status, causes = cause_list(hyps)
    if causes:
        params["causes"] = causes
    return WifiLogMeta(
        subject=subject,
        signal=signal,
        cause=cause,
        cause_status=status,
        params=params,
        attempt=attempt,
        attempt_key=attempt_key,
    )


def _auth_hypotheses(
    key: str, reason: str | None, signal: int | None, weak_dbm: float, fresh: bool
) -> list[tuple[str, CauseStatus]]:
    """Causes of a failed attempt. Only a handshake timeout can confirm a
    weak signal (E1): a wrong PSK or MIC is no signal problem."""
    if key == WIFI_BACKHAUL_AUTH_KIND:
        return [_hyp("psk_wrong"), _hyp("uplink_config")]
    if key == "wifi.sae_failed":
        return [_hyp("psk_wrong"), _hyp("sae_mismatch"), _hyp("client_driver")]
    if reason == "timeout":
        return [
            _weak_cause(signal, weak_dbm, fresh),
            _hyp("client_power_save"),
            _hyp("client_driver"),
        ]
    return [_hyp("psk_wrong"), _hyp("client_driver"), _hyp(CAUSE_WEAK_SIGNAL)]


def wifi_auth_evidence(
    state: WifiState,
    events: Iterable[NetEvent],
    attempts: Mapping[str, str],
    now: float,
    router: str,
    thresholds: Mapping[str, Any],
    exclude: frozenset[str] = frozenset(),
) -> list[Evidence]:
    """Evidence for ``wifi_auth_failures`` (per client, per uplink) and the
    fleet-wide ``wifi_auth_wave`` from the stored failure lines of a fresh
    log read. ``attempts`` maps the ids of events that start an attempt to
    their attempt key. The wave counts clients, not attempts: a MAC counts
    once per ``window`` (one device with an old PSK is no wave), handshake
    timeouts not at all (P4 review M6). Excluded MACs feed nothing."""
    out: list[Evidence] = []
    rule = _RuleSet(thresholds).get("wifi_auth_wave")
    window = _rule_num(rule, "window", 600)
    new_clients = 0
    for event in events:
        key = attempts.get(event.id)
        if key is None or event.kind not in WIFI_AUTH_KINDS:
            continue
        mac = event.subject.get("mac")
        if isinstance(mac, str) and mac.upper() in exclude:
            continue
        out.append(
            Evidence.from_event(
                event,
                "wifi_auth_failures",
                Scope.CLIENT if mac else Scope.ROUTER,
                key,
            )
        )
        if not isinstance(mac, str) or not mac:
            continue
        if event.params.get("reason") == "timeout":
            continue  # a timeout is no wrong password
        counted = state.wave.get(mac)
        if counted is not None and now - counted < window:
            continue
        state.wave.pop(mac, None)
        state.wave[mac] = now
        new_clients += 1
    if new_clients:
        clients = sum(1 for t in state.wave.values() if t > now - window)
        cause, status, _causes = cause_list([_hyp("psk_changed"), _hyp("attack")])
        out.append(
            Evidence(
                type="wifi_auth_wave",
                scope_key=WIFI_AUTH_WAVE_KEY,
                scope=Scope.FLEET,
                kind="wifi.auth_wave",
                count=new_clients,
                router=router,
                affected=clients,
                cause=cause,
                cause_status=status,
            )
        )
    return out
