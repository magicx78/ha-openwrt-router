"""Self-Healing: post-remediation verification (package H).

Developer document: ``docs/self-healing.md`` §7.3. Release 1.53.0 executes
nothing; here the verification watches whether an incident clears BY
ITSELF, the data the owner needs before any write is allowed. Nothing in
this module calls a router.

Two parts in one module:

* **The pure core** (no Home Assistant import, no clock read, no router
  call): :func:`verify` compares a before- and an after-snapshot
  (:class:`VerifySnapshot`, facts known or unknown with a reason code) for
  one action (id, catalog type, params, the call's result) at safety-clock
  times, and returns a frozen :class:`VerifyResult` with exactly one of the
  five result classes of order §11 (``heal_model.VerificationResult``), the
  per-criterion comparison (:class:`Criterion`) and reason codes.
* **The snapshot builder** (:func:`snapshot_from_sources`): builds a
  snapshot ONLY from objects already in memory (coordinator data, Network
  Intelligence), like ``heal_preflight.facts_from_sources``. It never
  raises, never polls, never refreshes, never calls the router; what it
  cannot read is unknown with a reason.

**The five classes** (order §11; the design doc uses the same five codes):

* ``resolved`` ("erfolgreich behoben"): the incident cleared with
  evidence, every state target of an executed write is good, its effect was
  measured, and every guard is known and not worse.
* ``partial`` ("teilweise behoben"): only for an executed write; something
  it targeted improved, but not everything; nothing worse, nothing unknown.
* ``not_resolved`` ("nicht behoben"): nothing targeted improved, nothing
  worse, nothing unknown.
* ``unknown`` ("Zustand unbekannt"): missing, stale, too early or too late
  evidence, any unknown criterion, or the effect of the action not seen.
* ``new_fault`` ("neue Störung verursacht"): a measured worsening on any
  criterion. It wins over every improvement and sets ``escalate``. The
  module only reports; it starts nothing.

**Hard rules.** Unknown never counts as success, on every criterion.
"Cleared by itself" is not a sixth class: it is ``resolved`` with
``attribution`` ``no_write`` (no write ran: no call, a call refused before
any change, or a read-only catalog action); then ``credited_to_action`` is
False and only incident and guards are compared, so ``partial`` cannot
occur. In 1.53.0 nothing writes, so this is the only good outcome.

**Time.** All times are safety-clock seconds (``heal_model.SafetyClock``):
nothing is judged before :data:`VERIFY_SETTLE_S` after the start; evidence
taken after :data:`VERIFY_MAX_WAIT_S` never counts; at the maximum wait a
class that could still change becomes final. A wall-clock jump does not
move the safety clock while HA runs, so it cannot shorten or stretch them.
One exception to the settle time (:data:`EARLY_LOSS`): a fresh, measured
loss of the management path or of WAN is a new fault at once.

**Fact ages** (review PR #83). A fact counts only if its measuring time
(``taken_at - age_s``) is known and fits: a before-fact in the
:data:`BEFORE_MAX_AGE_S` before the start, an after-fact after the settle
time (for an early loss: after the start). Otherwise it is unknown
(``<fact>_stale_<side>``). One unreadable row makes a whole fact unknown.
A clearing counts only once it has held :data:`VERIFY_CLEAR_HOLD_S`; the
wall-time resolve age counts only if wall and safety time moved alike
between the snapshots (else ``wall_clock_jump``).

**After the verdict.** :func:`planned_end` maps a final result by its
verdict key (never by class) onto heal_model's transition table; only
``repaired_by_action`` resolves a record (docs §7.3, for the wiring).

**Binding.** A result is bound to the action id, action type, params, the
call result, both snapshots and both times (``binding``, sha256). Every
derived field is ``init=False``; :meth:`VerifyResult.check_binding`
re-derives everything first. There is no secret: only INCONSISTENT edits
are caught; an edit of inputs and derived fields alike (a fully consistent
forgery) is not (same limit as ``heal_preflight``; docs §7.3).

**No names.** ``to_dict`` and ``to_verification`` carry counts, closed
codes and ids only; service and interface names stay inside the snapshot
and never reach a result.
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from . import heal_catalog as hc
from .core_models import REMEDIATION_ID_PREFIX, ROUTER_ID_PREFIX, is_valid_id
from .heal_model import (
    CLOCK_BACK_TOLERANCE_S,
    TIME_MAX,
    ActionState,
    CallResult,
    Check,
    CheckOutcome,
    Verification,
    VerificationResult,
    canonical_sha256,
)
from .heal_preflight import STALE_POLLS, Fact, FactSources, known, unknown

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pinned constants (docs §7.3)
# ---------------------------------------------------------------------------

# Nothing is judged before this many safety-clock seconds after the start:
# design §4 (service restart) asks that the NI root is not reopened within
# 10 minutes, that clients are back within 5 minutes and two polls passed.
VERIFY_SETTLE_S: Final = 600
# Evidence taken later than this after the start never counts (a later
# clearing is not the action's), and a class that could still change
# becomes final here.
VERIFY_MAX_WAIT_S: Final = 3600
# The before-snapshot must be taken at most this long before the start
# (the preflight is valid at most 300 s, heal_preflight VALID_FOR_BOUNDS_S).
BEFORE_MAX_AGE_S: Final = 300
# The after-snapshot must be at most this old when judged (three polls).
AFTER_MAX_AGE_S: Final = 180
# A clearing counts only once it has held this long (safety clock, from the
# clearing to the time Network Intelligence last confirmed it): a flap is
# not a success (review PR #83, P2-3).
VERIFY_CLEAR_HOLD_S: Final = 300
# Client tolerance (review PR #83, P2-6): a drop to 0 from any positive
# count is always worse; below CLIENT_SMALL_BELOW clients a loss of more
# than CLIENT_SMALL_DROP is worse; otherwise more than
# max(CLIENT_DROP_MIN, before * CLIENT_DROP_PCT // 100). The same rule per
# radio (AP interface), so a loss on one radio is not hidden by a gain on
# another.
CLIENT_DROP_PCT: Final = 30
CLIENT_DROP_MIN: Final = 2
CLIENT_SMALL_BELOW: Final = 7
CLIENT_SMALL_DROP: Final = 1
# Severities of a new incident that count as a worsening (order §11: "no
# new critical incidents"; info-level incidents do not count).
NOTICED_SEVERITIES: Final = ("warning", "critical")
# Network Intelligence's open incident states.
OPEN_STATES: Final = ("active", "acknowledged")
# How Network Intelligence resolved an incident, and what counts as
# evidence: ``cleared`` (a measured value back under its threshold) always,
# ``quiet`` (no new events for the clear window) only while the router's
# log ingest is ``ok``. ``no_data``, ``router_removed`` or anything else is
# no evidence.
RESOLVE_MEASURED: Final = "cleared"
RESOLVE_QUIET: Final = "quiet"
WAN_STATES: Final = ("up", "down", "absent")

# The snapshot's facts, in this order.
SNAPSHOT_FACTS: Final = (
    "management_path",
    "clients",
    "radio_clients",
    "services",
    "service_pids",
    "interfaces",
    "wan",
    "ap_interfaces",
    "uptime_s",
    "log_ok",
    "dependants_degraded",
    "incident_status",
    "incident_reopen_count",
    "incident_resolve_reason",
    "incident_resolved_age_s",
    "other_incidents",
)

_ID_RE: Final = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,63}")
_CODE_RE: Final = re.compile(r"[a-z][a-z0-9_.:|/-]{0,95}")
# Service, interface and AP interface names as the router has them (UCI
# section names may hold capitals and start with a digit: ``IoT``, ``4g``).
# They stay inside a snapshot and never reach a result.
_NAME_RE: Final = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
_REASON_RE: Final = re.compile(r"[a-z][a-z0-9_.]{0,63}")
_IPV4_RE: Final = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_MAC_RE: Final = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
_TUPLE_MAX: Final = 64
_INT_MAX: Final = 2**53


class VerifyError(ValueError):
    """Bad input to the verification (the message names the field only)."""


def _fail(what: str) -> VerifyError:
    return VerifyError(f"invalid {what}")


class Comparison(StrEnum):
    """Before against after, for one criterion."""

    IMPROVED = "improved"
    HELD = "held"  # good before, good after
    NOT_IMPROVED = "not_improved"  # bad after, not worse than before
    WORSE = "worse"
    UNKNOWN = "unknown"


class Role(StrEnum):
    """What a criterion says about the action."""

    PRIMARY = "primary"  # the incident itself
    STATE = "state"  # the state of the component an executed write targets
    EFFECT = "effect"  # proof that the executed write took effect at all
    GUARD = "guard"  # everything the action could reach: never worse


class Attribution(StrEnum):
    """Who may be credited with a change."""

    ACTION = "action"  # a write ran and returned ok
    ACTION_UNCONFIRMED = "action_unconfirmed"  # a write ran, outcome unknown
    NO_WRITE = "no_write"  # nothing that changes the router ran


class Binding(StrEnum):
    """Does a result still stand for these inputs? (:meth:`check_binding`)"""

    VALID = "valid"
    TAMPERED = "tampered"  # a derived field no longer follows from the inputs
    OTHER_ACTION = "other_action"
    OTHER_SNAPSHOT = "other_snapshot"


PRIMARY: Final = "incident_cleared"
GUARDS: Final = (
    "management_path",
    "clients_within_tolerance",
    "radio_clients_within_tolerance",
    "services_still_running",
    "interfaces_still_up",
    "wan_not_lost",
    "ap_interfaces_kept",
    "dependants_not_degraded",
    "no_new_incidents",
    "no_unplanned_reboot",
)
# What an EXECUTED write is checked for beyond incident and guards (state
# targets first, then the effect). Every writing catalog action must be
# here (checked at import); an effect that nothing in memory can measure is
# a criterion that is always unknown, so that action can never be credited.
WRITE_CRITERIA: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "service.restart": ("service_running", "service_restarted"),
        "wifi.radio_restart": ("radio_aps_present", "radio_restarted"),
        "interface.cycle": ("interface_up", "interface_cycled"),
        "router.reboot": ("router_rebooted",),
        "config.restore": ("config_matches_version",),
    }
)
# A guard an executed write replaces by its own state target.
REPLACED_GUARD: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "wifi.radio_restart": ("ap_interfaces_kept",),
        "router.reboot": ("no_unplanned_reboot",),
    }
)
ROLE_OF: Final[Mapping[str, Role]] = MappingProxyType(
    {
        PRIMARY: Role.PRIMARY,
        "service_running": Role.STATE,
        "interface_up": Role.STATE,
        "radio_aps_present": Role.STATE,
        "service_restarted": Role.EFFECT,
        "router_rebooted": Role.EFFECT,
        "radio_restarted": Role.EFFECT,
        "interface_cycled": Role.EFFECT,
        "config_matches_version": Role.EFFECT,
        **dict.fromkeys(GUARDS, Role.GUARD),
    }
)
CRITERIA: Final = tuple(ROLE_OF)
# Closed set of the string values a criterion may show (no router names).
VALUE_CODES: Final = frozenset(
    {"active", "acknowledged", "resolved", "ignored", "other", *WAN_STATES}
)
VERDICT_KEYS: Final = frozenset(
    {
        "repaired_by_action",
        "repaired_execution_unconfirmed",
        "cleared_by_itself",
        "partially_repaired",
        "action_did_not_help",
        "not_cleared",
        "worse_after_action",
        "worse_without_action",
        "cannot_tell",
    }
)


def _check_registry() -> None:
    """Every writing catalog action has its own criteria (import time)."""
    writes = {a for a, e in hc.CATALOG.items() if e.writes}
    if writes != set(WRITE_CRITERIA):
        raise VerifyError("write criteria do not match the catalog")
    for action, ids in WRITE_CRITERIA.items():
        roles = [ROLE_OF.get(i) for i in ids]
        if Role.EFFECT not in roles or any(
            r not in (Role.STATE, Role.EFFECT) for r in roles
        ):
            raise VerifyError(f"criteria of {action}")
    for action, guards in REPLACED_GUARD.items():
        if action not in WRITE_CRITERIA or not set(guards) <= set(GUARDS):
            raise VerifyError(f"replaced guard of {action}")


_check_registry()


# ---------------------------------------------------------------------------
# The snapshot
# ---------------------------------------------------------------------------


def _readable(value: Any, pattern: re.Pattern[str] = _CODE_RE) -> bool:
    return (
        type(value) is str
        and pattern.fullmatch(value) is not None
        and _IPV4_RE.search(value) is None
        and _MAC_RE.search(value) is None
        and "::" not in value
    )


def _is_count(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _INT_MAX


def _names_unique(rows: tuple[Any, ...]) -> bool:
    names = [r[0] for r in rows]
    return len(names) == len(set(names))


def _shape_ok(name: str, value: Any) -> bool:
    """``value`` (a known fact value) has the shape of fact ``name``."""
    if name in ("management_path", "log_ok"):
        return type(value) is bool
    if name in (
        "clients",
        "ap_interfaces",
        "uptime_s",
        "dependants_degraded",
        "incident_reopen_count",
    ):
        return _is_count(value)
    if name in ("services", "interfaces"):
        return (
            type(value) is tuple
            and all(
                type(r) is tuple
                and len(r) == 2
                and _readable(r[0], _NAME_RE)
                and type(r[1]) is bool
                for r in value
            )
            and _names_unique(value)
        )
    if name == "radio_clients":
        return (
            type(value) is tuple
            and all(
                type(r) is tuple
                and len(r) == 2
                and _readable(r[0], _NAME_RE)
                and _is_count(r[1])
                for r in value
            )
            and _names_unique(value)
        )
    if name == "service_pids":
        return type(value) is tuple and all(
            type(r) is tuple
            and len(r) == 2
            and _readable(r[0], _NAME_RE)
            and type(r[1]) is int
            and 0 < r[1] <= _INT_MAX
            for r in value
        )
    if name == "wan":
        return type(value) is str and value in WAN_STATES
    if name in ("incident_status", "incident_resolve_reason"):
        return _readable(value)
    if name == "incident_resolved_age_s":
        return (
            type(value) in (int, float)
            and math.isfinite(value)
            and 0 <= value <= TIME_MAX
        )
    if name == "other_incidents":
        return (
            type(value) is tuple
            and all(_readable(v, _ID_RE) for v in value)
            and len(value) == len(set(value))
        )
    return False


def _time(value: Any) -> float | None:
    if (
        type(value) not in (int, float)
        or not math.isfinite(value)
        or not 0 <= value <= TIME_MAX
    ):
        return None
    return float(value)


_NOT_COLLECTED: Final = unknown("not_collected")


def _nc() -> Fact:
    return _NOT_COLLECTED


@dataclass(frozen=True, kw_only=True, slots=True)
class VerifySnapshot:
    """The facts the verification compares, for one router and one incident.

    ``taken_at``: the safety-clock time of the snapshot; ``wall_at``: the
    wall time it was taken (None: unknown), only to see a wall-clock jump
    between two snapshots (the resolve age is wall time). Each fact is a
    ``heal_preflight.Fact`` (known, or unknown with a reason) whose
    ``age_s`` says how long before ``taken_at`` it was measured; a fact
    without an age never counts (docs §7.3). Shapes:
    ``services``/``interfaces`` ((name, running/up), ...) with unique names;
    ``radio_clients`` ((AP interface, clients), ...);
    ``service_pids`` ((service, pid), ...) of running instances; ``wan``
    one of :data:`WAN_STATES`; ``other_incidents`` the ids of the other
    open root incidents (warning or critical) on this router;
    ``incident_resolve_reason`` ``open`` while the incident is open;
    ``incident_resolved_age_s`` seconds since it resolved.
    """

    router_id: str
    incident_id: str
    taken_at: float
    wall_at: float | None = None
    management_path: Fact = field(default_factory=_nc)
    clients: Fact = field(default_factory=_nc)
    radio_clients: Fact = field(default_factory=_nc)
    services: Fact = field(default_factory=_nc)
    service_pids: Fact = field(default_factory=_nc)
    interfaces: Fact = field(default_factory=_nc)
    wan: Fact = field(default_factory=_nc)
    ap_interfaces: Fact = field(default_factory=_nc)
    uptime_s: Fact = field(default_factory=_nc)
    log_ok: Fact = field(default_factory=_nc)
    dependants_degraded: Fact = field(default_factory=_nc)
    incident_status: Fact = field(default_factory=_nc)
    incident_reopen_count: Fact = field(default_factory=_nc)
    incident_resolve_reason: Fact = field(default_factory=_nc)
    incident_resolved_age_s: Fact = field(default_factory=_nc)
    other_incidents: Fact = field(default_factory=_nc)

    def __post_init__(self) -> None:
        """Validate (exact types, shapes, bounds)."""
        if (
            not is_valid_id(self.router_id, ROUTER_ID_PREFIX)
            or type(self.router_id) is not str
        ):
            raise _fail("snapshot.router_id")
        if not _readable(self.incident_id, _ID_RE):
            raise _fail("snapshot.incident_id")
        taken = _time(self.taken_at)
        if taken is None:
            raise _fail("snapshot.taken_at")
        object.__setattr__(self, "taken_at", taken)
        if self.wall_at is not None:
            wall = _time(self.wall_at)
            if wall is None:
                raise _fail("snapshot.wall_at")
            object.__setattr__(self, "wall_at", wall)
        for name, fact in self.fact_items():
            if type(fact) is not Fact:
                raise _fail(f"snapshot.{name}")
            if fact.value is not None and not _shape_ok(name, fact.value):
                raise _fail(f"snapshot.{name}")

    def fact_items(self) -> Iterable[tuple[str, Fact]]:
        """(name, fact) of every fact field, in :data:`SNAPSHOT_FACTS` order."""
        for name in SNAPSHOT_FACTS:
            yield name, getattr(self, name)

    def to_dict(self) -> dict[str, Any]:
        """JSON form (holds router-supplied service and interface names:
        never put it into a result, a view or the audit)."""
        return {
            "router_id": self.router_id,
            "incident_id": self.incident_id,
            "taken_at": self.taken_at,
            "wall_at": self.wall_at,
            "facts": {name: fact.to_dict() for name, fact in self.fact_items()},
        }


if tuple(f.name for f in fields(VerifySnapshot))[4:] != SNAPSHOT_FACTS:
    raise VerifyError("snapshot fields do not match SNAPSHOT_FACTS")


# ---------------------------------------------------------------------------
# One criterion
# ---------------------------------------------------------------------------


def _value_ok(value: Any) -> bool:
    if value is None or type(value) is bool:
        return True
    if type(value) is int:
        return 0 <= value <= _INT_MAX
    return type(value) is str and value in VALUE_CODES


@dataclass(frozen=True, kw_only=True, slots=True)
class Criterion:
    """One compared criterion: counts, booleans and closed codes only."""

    criterion: str
    role: Role
    comparison: Comparison
    reason: str
    before: bool | int | str | None = None
    after: bool | int | str | None = None

    def __post_init__(self) -> None:
        """Validate (closed sets, exact types)."""
        if type(self.criterion) is not str or self.criterion not in ROLE_OF:
            raise _fail("criterion.criterion")
        if type(self.role) is not Role or self.role is not ROLE_OF[self.criterion]:
            raise _fail("criterion.role")
        if type(self.comparison) is not Comparison:
            raise _fail("criterion.comparison")
        if type(self.reason) is not str or _REASON_RE.fullmatch(self.reason) is None:
            raise _fail("criterion.reason")
        for name in ("before", "after"):
            if not _value_ok(getattr(self, name)):
                raise _fail(f"criterion.{name}")

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {
            "criterion": self.criterion,
            "role": self.role.value,
            "comparison": self.comparison.value,
            "reason": self.reason,
            "before": self.before,
            "after": self.after,
        }


def _c(
    cid: str,
    comparison: Comparison,
    reason: str,
    before: Any = None,
    after: Any = None,
) -> Criterion:
    return Criterion(
        criterion=cid,
        role=ROLE_OF[cid],
        comparison=comparison,
        reason=reason,
        before=before,
        after=after,
    )


_I, _H, _N, _W, _U = (
    Comparison.IMPROVED,
    Comparison.HELD,
    Comparison.NOT_IMPROVED,
    Comparison.WORSE,
    Comparison.UNKNOWN,
)


# Reasons the age rule gives a fact it turns unknown (``_aged``).
AGE_UNKNOWN: Final = "age_unknown"
MEASURED_TOO_EARLY: Final = "measured_too_early"
MEASURED_TOO_LATE: Final = "measured_too_late"
_AGE_REASONS: Final = frozenset({AGE_UNKNOWN, MEASURED_TOO_EARLY, MEASURED_TOO_LATE})


def _aged(
    snap: VerifySnapshot, earliest: float, latest: float | None
) -> VerifySnapshot:
    """``snap`` with every known fact whose measuring time is unknown or
    outside [earliest, latest] turned unknown (review PR #83, P1-1).

    The measuring time is ``taken_at - age_s``: a fresh snapshot of stale
    data is stale data.
    """
    over: dict[str, Fact] = {}
    for name, fact in snap.fact_items():
        if fact.value is None:
            continue
        age = fact.age_s
        if age is None or age < 0:
            over[name] = unknown(AGE_UNKNOWN, fact.source)
            continue
        measured = snap.taken_at - age
        if measured < earliest:
            over[name] = unknown(MEASURED_TOO_EARLY, fact.source)
        elif latest is not None and measured > latest:
            over[name] = unknown(MEASURED_TOO_LATE, fact.source)
    return replace(snap, **over) if over else snap


def _missing(
    cid: str, b: VerifySnapshot, a: VerifySnapshot, names: Iterable[str]
) -> Criterion | None:
    """UNKNOWN if a fact the criterion needs is unknown on either side
    (``<fact>_stale_<side>`` when the age rule made it unknown)."""
    for name in names:
        for side, snap in (("before", b), ("after", a)):
            gone = _gone(cid, name, getattr(snap, name), side)
            if gone is not None:
                return gone
    return None


def _missing_after(
    cid: str, a: VerifySnapshot, names: Iterable[str]
) -> Criterion | None:
    """UNKNOWN if a fact read on the after side only is unknown."""
    for name in names:
        gone = _gone(cid, name, getattr(a, name), "after")
        if gone is not None:
            return gone
    return None


def _gone(cid: str, name: str, fact: Fact, side: str) -> Criterion | None:
    if fact.value is not None:
        return None
    word = "stale" if fact.reason in _AGE_REASONS else "unknown"
    return _c(cid, _U, f"{name}_{word}_{side}")


def _status_code(value: Any) -> str:
    if value in ("active", "acknowledged", "resolved", "ignored"):
        return str(value)
    return "other"


def _with_codes(c: Criterion, before: Any, after: Any) -> Criterion:
    return replace(c, before=before, after=after)


def _wall_jump(b: VerifySnapshot, a: VerifySnapshot) -> str | None:
    """Why wall-time ages cannot be set against safety time, or None.

    The resolve age is wall time; between the two snapshots the wall clock
    must have moved like the safety clock (review PR #83, P2-5)."""
    if b.wall_at is None or a.wall_at is None:
        return "wall_time_unknown"
    drift = (a.wall_at - b.wall_at) - (a.taken_at - b.taken_at)
    if abs(drift) > CLOCK_BACK_TOLERANCE_S:
        return "wall_clock_jump"
    return None


def _incident(b: VerifySnapshot, a: VerifySnapshot, started: float) -> Criterion:
    cid = PRIMARY
    miss = _missing(cid, b, a, ("incident_status",))
    if miss is not None:
        return miss
    bs, as_ = b.incident_status.value, a.incident_status.value
    bc, ac = _status_code(bs), _status_code(as_)
    if bs == "ignored":
        return _c(cid, _U, "incident_ignored", bc, ac)
    if bs not in OPEN_STATES:
        return _c(cid, _U, "incident_not_open_before", bc, ac)
    miss = _missing(cid, b, a, ("incident_reopen_count",))
    if miss is not None:
        return _with_codes(miss, bc, ac)
    br, ar = b.incident_reopen_count.value, a.incident_reopen_count.value
    if ar < br:
        return _c(cid, _U, "incident_history_inconsistent", bc, ac)
    if ar > br:
        return _c(cid, _N, "incident_recurred", bc, ac)
    if as_ in OPEN_STATES:
        return _c(cid, _N, "incident_still_open", bc, ac)
    if as_ == "ignored":
        return _c(cid, _U, "incident_ignored", bc, ac)
    if as_ != "resolved":
        return _c(cid, _U, "incident_status_unrecognised", bc, ac)
    miss = _missing_after(
        cid, a, ("incident_resolve_reason", "incident_resolved_age_s")
    )
    if miss is not None:
        return _with_codes(miss, bc, ac)
    how = a.incident_resolve_reason.value
    age = a.incident_resolved_age_s.value
    jump = _wall_jump(b, a)
    if jump is not None:
        return _c(cid, _U, jump, bc, ac)
    if a.taken_at - age < started:
        return _c(cid, _U, "resolved_before_start", bc, ac)
    if how == RESOLVE_MEASURED:
        good = "incident_cleared_measured"
    elif how == RESOLVE_QUIET:
        miss = _missing_after(cid, a, ("log_ok",))
        if miss is not None:
            return _with_codes(miss, bc, ac)
        if a.log_ok.value is not True:
            return _c(cid, _U, "quiet_without_log_coverage", bc, ac)
        good = "incident_quiet_with_logs"
    else:
        return _c(cid, _U, "resolved_without_evidence", bc, ac)
    # held from the clearing to Network Intelligence's last look at it
    lag = a.incident_status.age_s
    if lag is None or age - lag < VERIFY_CLEAR_HOLD_S:
        return _c(cid, _U, "clearing_not_held_long_enough", bc, ac)
    return _c(cid, _I, good, bc, ac)


def _mgmt(b: VerifySnapshot, a: VerifySnapshot) -> Criterion:
    cid = "management_path"
    miss = _missing(cid, b, a, ("management_path",))
    if miss is not None:
        return miss
    bv, av = b.management_path.value, a.management_path.value
    if bv and not av:
        return _c(cid, _W, "management_path_lost", bv, av)
    if av and not bv:
        return _c(cid, _I, "management_path_back", bv, av)
    if bv:
        return _c(cid, _H, "management_path_held", bv, av)
    return _c(cid, _N, "management_path_still_down", bv, av)


def client_drop_allowed(before: int) -> int:
    """How many clients may go before it counts as a worsening (a drop to
    0 from a positive count is worse anyway, :func:`client_loss_worse`)."""
    if before < CLIENT_SMALL_BELOW:
        return CLIENT_SMALL_DROP
    return max(CLIENT_DROP_MIN, before * CLIENT_DROP_PCT // 100)


def client_loss_worse(before: int, after: int) -> bool:
    """A client count going from ``before`` to ``after`` is a worsening."""
    if before > 0 and after == 0:
        return True
    return before - after > client_drop_allowed(before)


def _clients(b: VerifySnapshot, a: VerifySnapshot) -> Criterion:
    cid = "clients_within_tolerance"
    miss = _missing(cid, b, a, ("clients",))
    if miss is not None:
        return miss
    bv, av = b.clients.value, a.clients.value
    if client_loss_worse(bv, av):
        return _c(cid, _W, "clients_dropped", bv, av)
    if av > bv:
        return _c(cid, _I, "clients_more", bv, av)
    return _c(cid, _H, "clients_within_tolerance", bv, av)


def _radio_clients(b: VerifySnapshot, a: VerifySnapshot) -> Criterion:
    """The client rule per radio (AP interface); a radio gone after has 0."""
    cid = "radio_clients_within_tolerance"
    miss = _missing(cid, b, a, ("radio_clients",))
    if miss is not None:
        return miss
    before = dict(b.radio_clients.value)
    after = dict(a.radio_clients.value)
    lost = [r for r, n in before.items() if client_loss_worse(n, after.get(r, 0))]
    if lost:
        return _c(cid, _W, "radio_clients_dropped", len(before), len(lost))
    if any(n > before.get(r, 0) for r, n in after.items()):
        return _c(cid, _I, "radio_clients_more", len(before), 0)
    return _c(cid, _H, "radio_clients_within_tolerance", len(before), 0)


def _flags_kept(
    cid: str,
    fact: str,
    b: VerifySnapshot,
    a: VerifySnapshot,
    exclude: str | None,
    words: tuple[str, str, str],
) -> Criterion:
    """Every name True before is True after (``exclude``: the target)."""
    miss = _missing(cid, b, a, (fact,))
    if miss is not None:
        return miss
    before = dict(getattr(b, fact).value)
    after = dict(getattr(a, fact).value)
    on = [n for n, v in before.items() if v and n != exclude]
    lost = [n for n in on if after.get(n) is not True]
    if lost:
        return _c(cid, _W, words[0], len(on), len(on) - len(lost))
    new = [
        n for n, v in after.items() if v and n != exclude and before.get(n) is not True
    ]
    if new:
        return _c(cid, _I, words[1], len(on), len(on))
    return _c(cid, _H, words[2], len(on), len(on))


def _wan(b: VerifySnapshot, a: VerifySnapshot) -> Criterion:
    cid = "wan_not_lost"
    miss = _missing(cid, b, a, ("wan",))
    if miss is not None:
        return miss
    bv, av = b.wan.value, a.wan.value
    if bv == "up":
        if av == "up":
            return _c(cid, _H, "wan_held", bv, av)
        return _c(cid, _W, "wan_lost", bv, av)
    if av == "up":
        return _c(cid, _I, "wan_back", bv, av)
    if bv == av == "absent":
        return _c(cid, _H, "no_wan", bv, av)
    if bv == av == "down":
        return _c(cid, _N, "wan_still_down", bv, av)
    return _c(cid, _U, "wan_changed_shape", bv, av)


def _count_kept(
    cid: str,
    fact: str,
    b: VerifySnapshot,
    a: VerifySnapshot,
    *,
    words: tuple[str, str, str],
) -> Criterion:
    """A count that must not go down (fewer is worse, more is better)."""
    miss = _missing(cid, b, a, (fact,))
    if miss is not None:
        return miss
    bv, av = getattr(b, fact).value, getattr(a, fact).value
    if av < bv:
        return _c(cid, _W, words[0], bv, av)
    if av > bv:
        return _c(cid, _I, words[1], bv, av)
    return _c(cid, _H, words[2], bv, av)


def _incidents(b: VerifySnapshot, a: VerifySnapshot) -> Criterion:
    """A new open incident is worse; one still open after is bad on both
    sides (never a success, review PR #83, P3-10)."""
    cid = "no_new_incidents"
    miss = _missing(cid, b, a, ("other_incidents",))
    if miss is not None:
        return miss
    bv, av = set(b.other_incidents.value), set(a.other_incidents.value)
    new = av - bv
    if new:
        return _c(cid, _W, "new_incident", len(bv), len(new))
    if av:
        return _c(cid, _N, "other_incidents_still_open", len(bv), len(av))
    if bv:
        return _c(cid, _I, "incidents_gone", len(bv), 0)
    return _c(cid, _H, "no_new_incidents", 0, 0)


def _dependants(b: VerifySnapshot, a: VerifySnapshot) -> Criterion:
    """More degraded dependants is worse; any still degraded after is bad
    on both sides (never a success)."""
    cid = "dependants_not_degraded"
    miss = _missing(cid, b, a, ("dependants_degraded",))
    if miss is not None:
        return miss
    bv, av = b.dependants_degraded.value, a.dependants_degraded.value
    if av > bv:
        return _c(cid, _W, "dependants_degraded", bv, av)
    if av > 0:
        return _c(cid, _N, "dependants_still_degraded", bv, av)
    if bv > 0:
        return _c(cid, _I, "dependants_recovered", bv, av)
    return _c(cid, _H, "dependants_held", bv, av)


def _target_flag(
    cid: str,
    fact: str,
    b: VerifySnapshot,
    a: VerifySnapshot,
    name: str,
    words: tuple[str, str, str, str, str],
) -> Criterion:
    """The target's flag (service running, interface up) before/after."""
    miss = _missing(cid, b, a, (fact,))
    if miss is not None:
        return miss
    before = dict(getattr(b, fact).value)
    after = dict(getattr(a, fact).value)
    if name not in before:
        return _c(cid, _U, words[0])
    bv, av = before[name], after.get(name) is True
    if bv and not av:
        return _c(cid, _W, words[1], bv, av)
    if av and not bv:
        return _c(cid, _I, words[2], bv, av)
    if bv:
        return _c(cid, _H, words[3], bv, av)
    return _c(cid, _N, words[4], bv, av)


def _restarted(b: VerifySnapshot, a: VerifySnapshot, name: str) -> Criterion:
    cid = "service_restarted"
    miss = _missing(cid, b, a, ("service_pids",))
    if miss is not None:
        return miss
    before = {p for n, p in b.service_pids.value if n == name}
    after = {p for n, p in a.service_pids.value if n == name}
    if not after:
        return _c(cid, _N, "no_running_instance", len(before), 0)
    if after & before:
        return _c(cid, _N, "restart_not_seen", len(before), len(after - before))
    return _c(cid, _I, "new_pid", len(before), len(after))


def _rebooted(b: VerifySnapshot, a: VerifySnapshot) -> Criterion:
    cid = "router_rebooted"
    miss = _missing(cid, b, a, ("uptime_s",))
    if miss is not None:
        return miss
    bv, av = b.uptime_s.value, a.uptime_s.value
    if av < bv:
        return _c(cid, _I, "uptime_reset", bv, av)
    return _c(cid, _N, "uptime_not_reset", bv, av)


def _no_reboot(b: VerifySnapshot, a: VerifySnapshot) -> Criterion:
    """A router whose uptime went back rebooted: an outage nobody planned
    (order test 23). Misses a reboot only if the router was up for less
    than the time between the snapshots before (docs §7.3)."""
    cid = "no_unplanned_reboot"
    miss = _missing(cid, b, a, ("uptime_s",))
    if miss is not None:
        return miss
    bv, av = b.uptime_s.value, a.uptime_s.value
    if av < bv:
        return _c(cid, _W, "router_rebooted_unplanned", bv, av)
    return _c(cid, _H, "no_reboot_seen", bv, av)


def _aps_present(b: VerifySnapshot, a: VerifySnapshot) -> Criterion:
    cid = "radio_aps_present"
    miss = _missing(cid, b, a, ("ap_interfaces",))
    if miss is not None:
        return miss
    bv, av = b.ap_interfaces.value, a.ap_interfaces.value
    if av < bv:
        return _c(cid, _W, "ap_interfaces_lost", bv, av)
    if av > bv:
        return _c(cid, _I, "ap_interfaces_back", bv, av)
    if av > 0:
        return _c(cid, _H, "ap_interfaces_held", bv, av)
    return _c(cid, _N, "no_ap_interfaces", bv, av)


_NOT_MEASURABLE: Final[Mapping[str, str]] = MappingProxyType(
    {
        "radio_restarted": "radio_restart_not_measurable",
        "interface_cycled": "interface_cycle_not_measurable",
        "config_matches_version": "config_version_not_tracked",
    }
)


def criteria_for(action_type: str, *, executed: bool) -> tuple[str, ...]:
    """The criterion ids for ``action_type``; ``executed``: a write ran."""
    if not executed or action_type not in WRITE_CRITERIA:
        return (PRIMARY, *GUARDS)
    replaced = REPLACED_GUARD.get(action_type, ())
    return (
        PRIMARY,
        *WRITE_CRITERIA[action_type],
        *(g for g in GUARDS if g not in replaced),
    )


def _criterion(
    cid: str,
    b: VerifySnapshot,
    a: VerifySnapshot,
    *,
    started: float,
    target: str,
    exclude_service: str | None,
    exclude_interface: str | None,
) -> Criterion:
    if cid == PRIMARY:
        return _incident(b, a, started)
    if cid == "management_path":
        return _mgmt(b, a)
    if cid == "clients_within_tolerance":
        return _clients(b, a)
    if cid == "services_still_running":
        return _flags_kept(
            cid,
            "services",
            b,
            a,
            exclude_service,
            ("service_stopped", "service_started", "services_held"),
        )
    if cid == "interfaces_still_up":
        return _flags_kept(
            cid,
            "interfaces",
            b,
            a,
            exclude_interface,
            ("interface_down", "interface_up_again", "interfaces_held"),
        )
    if cid == "wan_not_lost":
        return _wan(b, a)
    if cid == "ap_interfaces_kept":
        return _count_kept(
            cid,
            "ap_interfaces",
            b,
            a,
            words=("ap_interfaces_lost", "ap_interfaces_more", "ap_interfaces_held"),
        )
    if cid == "dependants_not_degraded":
        return _dependants(b, a)
    if cid == "radio_clients_within_tolerance":
        return _radio_clients(b, a)
    if cid == "no_new_incidents":
        return _incidents(b, a)
    if cid == "service_running":
        return _target_flag(
            cid,
            "services",
            b,
            a,
            target,
            (
                "service_not_in_before",
                "service_stopped",
                "service_running_again",
                "service_kept_running",
                "service_still_stopped",
            ),
        )
    if cid == "interface_up":
        return _target_flag(
            cid,
            "interfaces",
            b,
            a,
            target,
            (
                "interface_not_in_before",
                "interface_went_down",
                "interface_up_again",
                "interface_kept_up",
                "interface_still_down",
            ),
        )
    if cid == "service_restarted":
        return _restarted(b, a, target)
    if cid == "router_rebooted":
        return _rebooted(b, a)
    if cid == "no_unplanned_reboot":
        return _no_reboot(b, a)
    if cid == "radio_aps_present":
        return _aps_present(b, a)
    return _c(cid, _U, _NOT_MEASURABLE[cid])


# ---------------------------------------------------------------------------
# The result
# ---------------------------------------------------------------------------


def _frozen_params(params: Any) -> Mapping[str, Any]:
    """Read every value once into a read-only copy."""
    if params is None:
        return MappingProxyType({})
    if not isinstance(params, Mapping):
        raise _fail("params")
    return MappingProxyType(dict(list(params.items())))


def _snap_view(snap: VerifySnapshot | None) -> dict[str, Any] | None:
    return None if snap is None else snap.to_dict()


# The two guards whose fresh, measured loss is a new fault at once, before
# the settle time (review PR #83, P2-7): losing the way to the router or the
# uplink must never wait 10 minutes.
EARLY_LOSS: Final = ("management_path", "wan_not_lost")


def _gate(
    before: VerifySnapshot | None,
    after: VerifySnapshot | None,
    started: float,
    now: float,
    *,
    early_loss: bool,
) -> tuple[str, bool] | None:
    """(reason, final) when the evidence cannot be judged at all.

    ``early_loss``: a fresh, measured loss of an :data:`EARLY_LOSS` guard;
    then only a usable after-snapshot (not in the future, not beyond the
    maximum wait, not stale) is needed, not the settle time.
    """
    settle_until = started + VERIFY_SETTLE_S
    max_until = started + VERIFY_MAX_WAIT_S
    over = now >= max_until
    if now < started:
        return "judged_before_start", True
    if before is None:
        return "before_snapshot_missing", True
    if before.taken_at > started:
        return "before_snapshot_after_start", True
    if started - before.taken_at > BEFORE_MAX_AGE_S:
        return "before_snapshot_stale", True
    if not early_loss and now < settle_until:
        return "settle_time_not_reached", False
    if after is None:
        return "after_snapshot_missing", over
    if after.taken_at > now:
        # a later snapshot may still be usable: not final (P3-10)
        return "after_snapshot_in_future", over
    if after.taken_at > max_until:
        return "after_snapshot_beyond_max_wait", True
    if not early_loss and after.taken_at < settle_until:
        return "after_snapshot_too_early", over
    if now - after.taken_at > AFTER_MAX_AGE_S:
        return "after_snapshot_stale", over
    return None


def _decide(
    criteria: tuple[Criterion, ...], over: bool, *, executed: bool
) -> tuple[VerificationResult, tuple[str, ...], bool]:
    """(class, reasons, final) from the compared criteria."""

    def why(items: Iterable[Criterion]) -> tuple[str, ...]:
        return tuple(f"{c.criterion}.{c.comparison.value}" for c in items)

    worse = [c for c in criteria if c.comparison is _W]
    if worse:
        return VerificationResult.NEW_FAULT, why(worse), True
    unknown_ = [c for c in criteria if c.comparison is _U]
    if unknown_:
        return VerificationResult.UNKNOWN, why(unknown_), over
    primary = next(c for c in criteria if c.role is Role.PRIMARY)
    states = [c for c in criteria if c.role is Role.STATE]
    effects = [c for c in criteria if c.role is Role.EFFECT]
    unseen = [c for c in effects if c.comparison is not _I]
    if unseen:
        if primary.comparison is _I:
            # cleared, but the write is not seen: never credited, and it
            # cannot be told whether the action did anything
            return (
                VerificationResult.UNKNOWN,
                ("action_effect_not_seen", *why(unseen)),
                True,
            )
        return VerificationResult.NOT_RESOLVED, why([primary, *unseen]), over
    bad_guards = [c for c in criteria if c.role is Role.GUARD and c.comparison is _N]
    if primary.comparison is _I and bad_guards:
        # cleared, but the router is still unwell where the action could
        # reach (bad on both sides): never a success (P3-10)
        if executed:
            return VerificationResult.NOT_RESOLVED, why([primary, *bad_guards]), over
        return VerificationResult.UNKNOWN, why(bad_guards), over
    bad_states = [c for c in states if c.comparison not in (_I, _H)]
    if primary.comparison is _I and not bad_states:
        return VerificationResult.RESOLVED, why([primary, *states, *effects]), True
    if any(c.comparison is _I for c in (primary, *states)):
        return VerificationResult.PARTIAL, why([primary, *states]), over
    return VerificationResult.NOT_RESOLVED, why([primary, *states]), over


_VERDICTS: Final[Mapping[tuple[VerificationResult, Attribution], str]] = (
    MappingProxyType(
        {
            (VerificationResult.RESOLVED, Attribution.ACTION): "repaired_by_action",
            (
                VerificationResult.RESOLVED,
                Attribution.ACTION_UNCONFIRMED,
            ): "repaired_execution_unconfirmed",
            (VerificationResult.RESOLVED, Attribution.NO_WRITE): "cleared_by_itself",
            (VerificationResult.PARTIAL, Attribution.ACTION): "partially_repaired",
            (
                VerificationResult.PARTIAL,
                Attribution.ACTION_UNCONFIRMED,
            ): "partially_repaired",
            (
                VerificationResult.NOT_RESOLVED,
                Attribution.ACTION,
            ): "action_did_not_help",
            (
                VerificationResult.NOT_RESOLVED,
                Attribution.ACTION_UNCONFIRMED,
            ): "action_did_not_help",
            (VerificationResult.NOT_RESOLVED, Attribution.NO_WRITE): "not_cleared",
            (VerificationResult.NEW_FAULT, Attribution.ACTION): "worse_after_action",
            (
                VerificationResult.NEW_FAULT,
                Attribution.ACTION_UNCONFIRMED,
            ): "worse_after_action",
            (
                VerificationResult.NEW_FAULT,
                Attribution.NO_WRITE,
            ): "worse_without_action",
            (VerificationResult.UNKNOWN, Attribution.ACTION): "cannot_tell",
            (VerificationResult.UNKNOWN, Attribution.ACTION_UNCONFIRMED): "cannot_tell",
            (VerificationResult.UNKNOWN, Attribution.NO_WRITE): "cannot_tell",
        }
    )
)


def _attribution(entry: hc.CatalogEntry, call_result: CallResult | None) -> Attribution:
    """A read-only action changes nothing on the router; a refused call ran
    no change (``rejected``: refused before any change)."""
    if not entry.writes or call_result is None or call_result is CallResult.REJECTED:
        return Attribution.NO_WRITE
    if call_result is CallResult.OK:
        return Attribution.ACTION
    return Attribution.ACTION_UNCONFIRMED


def _derive(
    action_id: str,
    va: hc.ValidatedAction,
    call_result: CallResult | None,
    before: VerifySnapshot | None,
    after: VerifySnapshot | None,
    started: float,
    now: float,
) -> dict[str, Any]:
    """Every derived field of a result, from its inputs only."""
    attribution = _attribution(va.entry, call_result)
    executed = attribution is not Attribution.NO_WRITE
    ids = criteria_for(va.action_type, executed=executed)
    target = ""
    if executed and va.entry.target_param in ("service", "interface"):
        target = va.params[va.entry.target_param]
    settle_until = started + VERIFY_SETTLE_S
    criteria: tuple[Criterion, ...] = ()
    if before is not None and after is not None:
        # before-facts measured in the 300 s before the start; after-facts
        # measured after the settle time; for EARLY_LOSS also any after-fact
        # measured after the start, but only to see a loss (P1-1, P2-7)
        b_eff = _aged(before, started - BEFORE_MAX_AGE_S, started)
        a_eff = _aged(after, settle_until, None)
        a_fresh = _aged(after, started, None)

        def one(cid: str, a_snap: VerifySnapshot) -> Criterion:
            return _criterion(
                cid,
                b_eff,
                a_snap,
                started=started,
                target=target,
                exclude_service=target or None
                if va.action_type == "service.restart"
                else None,
                exclude_interface=target
                if va.action_type == "interface.cycle"
                else None,
            )

        rows = []
        for cid in ids:
            row = one(cid, a_eff)
            if cid in EARLY_LOSS:
                early = one(cid, a_fresh)
                if early.comparison is _W:
                    row = early
            rows.append(row)
        criteria = tuple(rows)
    early_loss = any(c.criterion in EARLY_LOSS and c.comparison is _W for c in criteria)
    over = now >= started + VERIFY_MAX_WAIT_S
    gate = _gate(before, after, started, now, early_loss=early_loss)
    if gate is not None:
        result, reasons, final = VerificationResult.UNKNOWN, (gate[0],), gate[1]
    else:
        result, reasons, final = _decide(criteria, over, executed=executed)
    known_snap = before if before is not None else after
    view = {
        "action_id": action_id,
        "action_type": va.action_type,
        "params": dict(va.params),
        "call_result": None if call_result is None else call_result.value,
        "before": _snap_view(before),
        "after": _snap_view(after),
        "started_at": started,
        "judged_at": now,
        "settle_s": VERIFY_SETTLE_S,
        "max_wait_s": VERIFY_MAX_WAIT_S,
        "clear_hold_s": VERIFY_CLEAR_HOLD_S,
        "before_max_age_s": BEFORE_MAX_AGE_S,
        "after_max_age_s": AFTER_MAX_AGE_S,
    }
    return {
        "router_id": None if known_snap is None else known_snap.router_id,
        "incident_id": None if known_snap is None else known_snap.incident_id,
        "attribution": attribution,
        "executed": executed,
        "criteria": criteria,
        "result": result,
        "reasons": reasons,
        "final": final,
        "escalate": result is VerificationResult.NEW_FAULT,
        "credited_to_action": result is VerificationResult.RESOLVED
        and attribution is Attribution.ACTION,
        "verdict_key": _VERDICTS[(result, attribution)],
        "settle_until": settle_until,
        "max_wait_until": started + VERIFY_MAX_WAIT_S,
        "binding": canonical_sha256(view),
    }


def _parts_exact(criteria: Any, reasons: Any) -> bool:
    """Exact types inside the derived tuples (review PR #83, P3-9)."""
    if not all(type(c) is Criterion for c in criteria):
        return False
    try:
        for c in criteria:
            replace(c)  # its own exact-type checks
    except (TypeError, ValueError):
        return False
    return all(type(r) is str for r in reasons)


_DERIVED: Final = (
    "router_id",
    "incident_id",
    "attribution",
    "executed",
    "criteria",
    "result",
    "reasons",
    "final",
    "escalate",
    "credited_to_action",
    "verdict_key",
    "settle_until",
    "max_wait_until",
    "binding",
)


@dataclass(frozen=True, kw_only=True, slots=True)
class VerifyResult:
    """The verdict of one verification; computed, never handed in.

    Inputs: ``action_id`` (``rem_`` id), ``action_type`` and ``params``
    (checked against the catalog), ``call_result`` (None: nothing was
    called; refused for a writing action, which always has a call
    result: ``rejected`` when the router refused it), ``before`` /
    ``after`` (exactly :class:`VerifySnapshot` or
    None, same router and incident), ``started_at`` (safety-clock time the
    call finished, or the observation started) and ``judged_at`` (safety
    time now). Everything else is derived in ``__post_init__``.
    """

    action_id: str
    action_type: str
    params: Any = None
    call_result: CallResult | None = None
    before: VerifySnapshot | None = None
    after: VerifySnapshot | None = None
    started_at: float
    judged_at: float
    router_id: str | None = field(init=False)
    incident_id: str | None = field(init=False)
    attribution: Attribution = field(init=False)
    executed: bool = field(init=False)
    criteria: tuple[Criterion, ...] = field(init=False)
    result: VerificationResult = field(init=False)
    reasons: tuple[str, ...] = field(init=False)
    final: bool = field(init=False)
    escalate: bool = field(init=False)
    credited_to_action: bool = field(init=False)
    verdict_key: str = field(init=False)
    settle_until: float = field(init=False)
    max_wait_until: float = field(init=False)
    binding: str = field(init=False)

    def __post_init__(self) -> None:
        """Validate the inputs and derive everything (raises VerifyError)."""
        set_ = object.__setattr__
        if type(self.action_id) is not str or not is_valid_id(
            self.action_id, REMEDIATION_ID_PREFIX
        ):
            raise _fail("action_id")
        va, refusal = hc.try_validate(self.action_type, _frozen_params(self.params))
        if va is None or refusal is not None:
            raise _fail("action")
        set_(self, "params", MappingProxyType(dict(va.params)))
        if self.call_result is not None and type(self.call_result) is not CallResult:
            raise _fail("call_result")
        if va.entry.writes and self.call_result is None:
            # never silently "cleared by itself" (review PR #83, P3-10)
            raise _fail("call_result")
        for name in ("before", "after"):
            snap = getattr(self, name)
            if snap is not None:
                if type(snap) is not VerifySnapshot:
                    raise _fail(name)
                # a re-validated copy (its Fact objects are shared and frozen)
                set_(self, name, replace(snap))
        if (
            self.before is not None
            and self.after is not None
            and (
                self.before.router_id != self.after.router_id
                or self.before.incident_id != self.after.incident_id
            )
        ):
            raise _fail("snapshots")
        for name in ("started_at", "judged_at"):
            value = _time(getattr(self, name))
            if value is None:
                raise _fail(name)
            set_(self, name, value)
        derived = _derive(
            self.action_id,
            va,
            self.call_result,
            self.before,
            self.after,
            self.started_at,
            self.judged_at,
        )
        for name in _DERIVED:
            set_(self, name, derived[name])

    def _untampered(self) -> bool:
        """The derived fields are what the stored inputs give again.

        Catches INCONSISTENT edits only (docs §7.3): an input or a derived
        field changed behind the frozen dataclass's back, a shared Fact
        changed in place, a pinned constant changed at run time. An edit of
        inputs and every derived field alike is consistent and not seen.
        """
        try:
            if type(self.params) is not MappingProxyType:
                return False
            va, refusal = hc.try_validate(self.action_type, self.params)
            if va is None or refusal is not None:
                return False
            for snap in (self.before, self.after):
                if snap is not None:
                    if type(snap) is not VerifySnapshot:
                        return False
                    replace(snap)  # still valid
            if (
                self.call_result is not None
                and type(self.call_result) is not CallResult
            ) or (va.entry.writes and self.call_result is None):
                return False
            derived = _derive(
                self.action_id,
                va,
                self.call_result,
                self.before,
                self.after,
                self.started_at,
                self.judged_at,
            )
        except Exception:  # noqa: BLE001 - anything odd is tampering
            return False
        return all(
            type(getattr(self, name)) is type(derived[name])
            and getattr(self, name) == derived[name]
            for name in _DERIVED
        ) and _parts_exact(self.criteria, self.reasons)

    def check_binding(
        self,
        *,
        action_id: Any,
        action_type: Any,
        params: Any,
        before: Any,
        after: Any,
    ) -> Binding:
        """May this result stand for these inputs? Re-derives first."""
        if not self._untampered():
            return Binding.TAMPERED
        try:
            frozen = _frozen_params(params)
        except VerifyError:
            return Binding.OTHER_ACTION
        va, _refusal = hc.try_validate(action_type, frozen)
        if (
            action_id != self.action_id
            or va is None
            or va.action_type != self.action_type
            or dict(va.params) != dict(self.params)
        ):
            return Binding.OTHER_ACTION
        for given, stored in ((before, self.before), (after, self.after)):
            if given is None or stored is None:
                if given is not stored:
                    return Binding.OTHER_SNAPSHOT
                continue
            if type(given) is not VerifySnapshot:
                return Binding.OTHER_SNAPSHOT
            if _snap_view(given) != _snap_view(stored):
                return Binding.OTHER_SNAPSHOT
        return Binding.VALID

    def criterion(self, criterion_id: str) -> Criterion:
        """One compared criterion by id (KeyError if not compared)."""
        for c in self.criteria:
            if c.criterion == criterion_id:
                return c
        raise KeyError(criterion_id)

    def to_dict(self) -> dict[str, Any]:
        """JSON form for a view: codes, counts and ids only (no names)."""
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "params": dict(self.params),
            "call_result": None if self.call_result is None else self.call_result.value,
            "router_id": self.router_id,
            "incident_id": self.incident_id,
            "result": self.result.value,
            "attribution": self.attribution.value,
            "executed": self.executed,
            "verdict_key": self.verdict_key,
            "credited_to_action": self.credited_to_action,
            "final": self.final,
            "escalate": self.escalate,
            "reasons": list(self.reasons),
            "criteria": [c.to_dict() for c in self.criteria],
            "started_at": self.started_at,
            "judged_at": self.judged_at,
            "settle_until": self.settle_until,
            "max_wait_until": self.max_wait_until,
            "before_taken_at": None if self.before is None else self.before.taken_at,
            "after_taken_at": None if self.after is None else self.after.taken_at,
            "binding": self.binding,
        }

    def to_verification(self) -> Verification:
        """The record's ``verification`` part (heal_model), as far as the
        model can hold it: class, before/after per criterion, checks.

        NOT in the model (docs §7.3, for package I / C2 to store): the
        attribution, ``final``, ``escalate``, ``credited_to_action``, the
        verdict key, the binding digest and the two safety times.
        """
        outcome = {
            _I: CheckOutcome.PASS,
            _H: CheckOutcome.PASS,
            _N: CheckOutcome.FAIL,
            _W: CheckOutcome.FAIL,
            _U: CheckOutcome.UNKNOWN,
        }
        return Verification(
            result=self.result,
            before={c.criterion: c.before for c in self.criteria},
            after={c.criterion: c.after for c in self.criteria},
            checks=tuple(
                Check(check=c.criterion, outcome=outcome[c.comparison], reason=c.reason)
                for c in self.criteria
            ),
        )


def verify(
    *,
    action_id: str,
    action_type: str,
    params: Any = None,
    call_result: CallResult | None = None,
    before: VerifySnapshot | None,
    after: VerifySnapshot | None,
    started_at: float,
    judged_at: float,
) -> VerifyResult:
    """Compare ``before`` with ``after`` for one action (see the module)."""
    return VerifyResult(
        action_id=action_id,
        action_type=action_type,
        params=params,
        call_result=call_result,
        before=before,
        after=after,
        started_at=started_at,
        judged_at=judged_at,
    )


# ---------------------------------------------------------------------------
# Where a record goes with a final result (for the later wiring, docs §7.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class PlannedEnd:
    """What the engine does with a FINAL result (review PR #83, P2-4).

    ``state``: the record's next state (None: no state change);
    ``counts_as_failure``: an outcome for the breaker and the fleet pause
    (``heal_policy.record_outcome``); ``credited``: the action repaired it;
    ``hold``: hold the router (docs §5.1), set for every new fault.
    """

    state: ActionState | None
    counts_as_failure: bool
    credited: bool
    hold: bool


_S = ActionState
# Record in VERIFYING (a write was called): by verdict key, never by class.
_AFTER_CALL: Final[Mapping[str, tuple[ActionState, bool, bool]]] = MappingProxyType(
    {
        # verdict -> (state, counts_as_failure, hold)
        "repaired_by_action": (_S.RESOLVED, False, False),
        "repaired_execution_unconfirmed": (_S.MANUAL_RECOVERY_REQUIRED, True, False),
        "partially_repaired": (_S.FAILED, True, False),
        "action_did_not_help": (_S.FAILED, True, False),
        # the router refused the call (no write ran): a failed action, and a
        # clearing meanwhile is never the action's
        "cleared_by_itself": (_S.FAILED, True, False),
        "not_cleared": (_S.FAILED, True, False),
        "worse_after_action": (_S.ESCALATED, True, True),
        "worse_without_action": (_S.ESCALATED, True, True),
        "cannot_tell": (_S.MANUAL_RECOVERY_REQUIRED, True, False),
    }
)


def planned_end(
    result: VerifyResult, *, from_state: ActionState, interrupted: bool
) -> PlannedEnd | None:
    """The record's planned end for a final ``result``; None while the
    result is not final (the record stays where it is).

    ``from_state`` VERIFYING (after a call): only ``repaired_by_action``
    resolves; an unconfirmed call or "cannot tell" needs a person; every
    other end counts as a failure; an interrupted record never becomes
    FAILED (that edge needs an uninterrupted action) but needs a person.
    ``from_state`` PROPOSED (Observe, nothing executed): "cleared by
    itself" cancels the proposal, never credited; a new fault holds the
    router without a state change (the engine may not escalate a
    proposal); anything else changes nothing.
    """
    if type(result) is not VerifyResult or not result._untampered():
        raise _fail("planned_end.result")
    if type(from_state) is not ActionState or type(interrupted) is not bool:
        raise _fail("planned_end.from_state")
    if not result.final:
        return None
    key = result.verdict_key
    if from_state is ActionState.VERIFYING:
        state, failure, hold = _AFTER_CALL[key]
        if interrupted and state is ActionState.FAILED:
            state = ActionState.MANUAL_RECOVERY_REQUIRED
        return PlannedEnd(
            state=state,
            counts_as_failure=failure,
            credited=key == "repaired_by_action",
            hold=hold,
        )
    if from_state is ActionState.PROPOSED and not result.executed:
        if key == "cleared_by_itself":
            return PlannedEnd(
                state=ActionState.CANCELLED,
                counts_as_failure=False,
                credited=False,
                hold=False,
            )
        if key == "worse_without_action":
            return PlannedEnd(
                state=None, counts_as_failure=False, credited=False, hold=True
            )
        return None
    raise _fail("planned_end.from_state")


# ---------------------------------------------------------------------------
# The snapshot builder (memory only)
# ---------------------------------------------------------------------------


def _value_of(raw: Any) -> Any:
    return getattr(raw, "value", raw)


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


def _count(value: Any) -> int | None:
    return int(value) if _is_count(value) else None


def _timestamp(value: Any) -> float | None:
    """Epoch seconds of an aware datetime (or a number), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value) if math.isfinite(value) else None
    ts = getattr(value, "timestamp", None)
    if callable(ts) and getattr(value, "tzinfo", None) is not None:
        try:
            out = float(ts())
        except (TypeError, ValueError, OverflowError):
            return None
        return out if math.isfinite(out) else None
    return None


def _interval(coord: Any) -> float | None:
    seconds = getattr(getattr(coord, "update_interval", None), "total_seconds", None)
    secs = _num(seconds()) if callable(seconds) else None
    return secs if secs is not None and secs > 0 else None


def _poll(src: FactSources, wall: float) -> tuple[Fact, float | None]:
    """The management path (HA reaches the router: the last poll is ok and
    fresh) and the poll interval."""
    s = "coordinator"
    coord = src.coordinator
    if coord is None:
        return unknown("router_not_loaded", s), None
    interval = _interval(coord)
    ok = getattr(coord, "last_update_success", None)
    if ok is False:
        # measured: the polls fail since the coordinator's first failure of
        # this outage (its age is the time since then; unknown without it)
        since = _timestamp(getattr(coord, "_failure_since", None))
        age = None if since is None or wall - since < 0 else wall - since
        return known(False, f"{s}.last_update_success", age), interval
    if ok is not True:
        return unknown("poll_state_unknown", s), interval
    data = getattr(coord, "data", None)
    last = _timestamp(getattr(data, "last_seen", None)) if data is not None else None
    if last is None:
        return unknown("no_successful_poll", f"{s}.data.last_seen"), interval
    if interval is None:
        return unknown("interval_unknown", f"{s}.update_interval"), None
    age = wall - last
    if age < -CLOCK_BACK_TOLERANCE_S:
        return unknown("wall_clock_behind_poll", f"{s}.data.last_seen"), interval
    if age > STALE_POLLS * interval:
        return unknown("poll_stale", f"{s}.data.last_seen"), interval
    return known(True, f"{s}.data.last_seen", max(age, 0.0)), interval


_STATE_FACTS: Final = (
    "clients",
    "radio_clients",
    "services",
    "service_pids",
    "interfaces",
    "wan",
    "ap_interfaces",
    "uptime_s",
    "log_ok",
)
_NI_FACTS: Final = (
    "dependants_degraded",
    "incident_status",
    "incident_reopen_count",
    "incident_resolve_reason",
    "incident_resolved_age_s",
    "other_incidents",
)


def _rows(
    rows: list[tuple[Any, ...]], source: str, age: float | None, ambiguous: str
) -> Fact:
    if len(rows) > _TUPLE_MAX:
        return unknown("too_many_entries", source)
    names = [r[0] for r in rows]
    if len(names) != len(set(names)):
        return unknown(ambiguous, source)
    return known(tuple(sorted(rows)), source, age)


def _name(value: Any) -> bool:
    return _readable(value, _NAME_RE)


def _services(data: Any, s: str, age: float | None) -> Fact:
    """Running flag per service; unknown unless THIS poll fetched them.

    The coordinator copies the last poll's services forward when fetching
    fails, while ``last_seen`` stays fresh (coordinator ``_async_poll``);
    only ``service_instances`` (None unless ``service list`` answered in
    this poll) proves they are this poll's. Every row must be readable,
    else the whole fact is unknown (review PR #83, P1-1, P1-2).
    """
    src = f"{s}.services"
    services = getattr(data, "services", None)
    if not isinstance(services, list) or not services:
        return unknown("services_not_polled", src)
    if not isinstance(getattr(data, "service_instances", None), Mapping):
        return unknown("services_freshness_unknown", src)
    rows = []
    for svc in services:
        if (
            not isinstance(svc, Mapping)
            or not _name(svc.get("name"))
            or type(svc.get("running")) is not bool
        ):
            return unknown("service_row_unreadable", src)
        rows.append((svc["name"], svc["running"]))
    return _rows(rows, src, age, "services_ambiguous")


def _service_pids(data: Any, s: str, age: float | None) -> Fact:
    src = f"{s}.service_instances"
    inst = getattr(data, "service_instances", None)
    if not isinstance(inst, Mapping):
        return unknown("service_instances_not_fetched", src)
    pids: list[tuple[Any, ...]] = []
    for name, instances in inst.items():
        if not _name(name) or not isinstance(instances, Mapping):
            return unknown("service_instance_unreadable", src)
        for one in instances.values():
            running = one.get("running") if isinstance(one, Mapping) else None
            if type(running) is not bool:
                return unknown("service_instance_unreadable", src)
            if not running:
                continue
            pid = one.get("pid")
            if type(pid) is not int or not 0 < pid <= _INT_MAX:
                return unknown("service_instance_unreadable", src)
            pids.append((name, pid))
    if len(pids) > _TUPLE_MAX:
        return unknown("too_many_entries", src)
    return known(tuple(sorted(pids)), src, age)


def _interfaces(data: Any, s: str, age: float | None) -> Fact:
    src = f"{s}.network_interfaces"
    ifaces = getattr(data, "network_interfaces", None)
    if getattr(data, "vlans_stale", False):
        return unknown("interfaces_stale", src)
    if not isinstance(ifaces, list) or not ifaces:
        return unknown("interfaces_not_polled", src)
    rows = []
    for i in ifaces:
        if not isinstance(i, Mapping) or not _name(i.get("logical_name")):
            return unknown("interface_row_unreadable", src)
        status = i.get("status")
        if status not in ("up", "down"):
            return unknown("interface_status_unreadable", src)
        rows.append((i["logical_name"], status == "up"))
    return _rows(rows, src, age, "interfaces_ambiguous")


def _radio_clients_fact(data: Any, s: str, age: float | None) -> Fact:
    """Clients per AP interface (every client of this poll comes from
    hostapd or iwinfo and names its AP interface in ``radio``)."""
    src = f"{s}.clients"
    clients = getattr(data, "clients", None)
    if not isinstance(clients, list):
        return unknown("clients_unknown", src)
    per: dict[str, int] = {}
    for c in clients:
        radio = c.get("radio") if isinstance(c, Mapping) else None
        if not _name(radio):
            return unknown("client_radio_unreadable", src)
        per[radio] = per.get(radio, 0) + 1
    if len(per) > _TUPLE_MAX:
        return unknown("too_many_entries", src)
    return known(tuple(sorted(per.items())), src, age)


def _state(src: FactSources, mgmt: Fact) -> dict[str, Fact]:
    """Facts of the last poll; unknown unless the poll is ok and fresh."""
    s = "coordinator.data"
    if mgmt.value is not True:
        reason = "poll_failed" if mgmt.value is False else (mgmt.reason or "poll")
        return {n: unknown(reason, s) for n in _STATE_FACTS}
    data = src.coordinator.data
    age = mgmt.age_s
    out: dict[str, Fact] = {}
    clients = _count(getattr(data, "client_count", None))
    out["clients"] = (
        known(clients, f"{s}.client_count", age)
        if clients is not None
        else unknown("clients_unknown", s)
    )
    out["radio_clients"] = _radio_clients_fact(data, s, age)
    out["services"] = _services(data, s, age)
    out["service_pids"] = _service_pids(data, s, age)
    out["interfaces"] = _interfaces(data, s, age)
    wan = getattr(data, "wan_status", None)
    found = wan.get("wan_found") if isinstance(wan, Mapping) else None
    connected = getattr(data, "wan_connected", None)
    if found is False:
        out["wan"] = known("absent", f"{s}.wan_status", age)
    elif found is True and type(connected) is bool:
        out["wan"] = known("up" if connected else "down", f"{s}.wan_connected", age)
    else:
        out["wan"] = unknown("wan_unknown", f"{s}.wan_status")
    aps = getattr(data, "ap_interfaces", None)
    if not isinstance(aps, list):
        out["ap_interfaces"] = unknown("ap_interfaces_unknown", f"{s}.ap_interfaces")
    elif not all(isinstance(x, Mapping) for x in aps):
        out["ap_interfaces"] = unknown("ap_interface_unreadable", f"{s}.ap_interfaces")
    else:
        out["ap_interfaces"] = known(len(aps), f"{s}.ap_interfaces", age)
    up = _count(getattr(data, "uptime", None))
    out["uptime_s"] = (
        known(up, f"{s}.uptime", age) if up else unknown("uptime_missing", s)
    )
    log = getattr(data, "log_status", None)
    out["log_ok"] = (
        known(log == "ok", f"{s}.log_status", age)
        if isinstance(log, str)
        else unknown("log_status_unknown", f"{s}.log_status")
    )
    return out


def _ni(
    src: FactSources, incident_id: str, wall: float, interval: float | None
) -> dict[str, Fact]:
    """Incident state, other incidents and dependants from Network
    Intelligence; unknown unless it ran within two poll intervals."""
    s = "network_intelligence"
    ni, entry_id = src.ni, src.entry_id
    if ni is None or getattr(ni, "loaded", False) is not True:
        return {n: unknown("ni_not_loaded", s) for n in _NI_FACTS}
    if entry_id is None:
        return {n: unknown("entry_unknown", s) for n in _NI_FACTS}
    last_now = _num(getattr(getattr(ni, "machine", None), "last_now", None))
    if last_now is None:
        return {n: unknown("ni_time_unknown", s) for n in _NI_FACTS}
    if interval is None:
        return {n: unknown("interval_unknown", s) for n in _NI_FACTS}
    lag = wall - last_now
    if lag < -CLOCK_BACK_TOLERANCE_S:
        return {n: unknown("wall_clock_behind_ni", s) for n in _NI_FACTS}
    if lag > STALE_POLLS * interval:
        return {n: unknown("ni_stale", s) for n in _NI_FACTS}
    age = max(lag, 0.0)
    out: dict[str, Fact] = {}
    incidents = list(ni.machine.peek())
    si = f"{s}.incidents"
    inc = next((i for i in incidents if getattr(i, "id", None) == incident_id), None)
    if inc is None:
        for n in _NI_FACTS[1:5]:
            out[n] = unknown("incident_unknown", si)
    else:
        status = _value_of(getattr(inc, "status", None))
        if not _readable(status):
            for n in _NI_FACTS[1:5]:
                out[n] = unknown("status_unknown", si)
        else:
            out["incident_status"] = known(status, si, age)
            reopen = _count(getattr(inc, "reopen_count", None))
            out["incident_reopen_count"] = (
                known(reopen, si, age)
                if reopen is not None
                else unknown("reopen_count_unknown", si)
            )
            if status != "resolved":
                out["incident_resolve_reason"] = known("open", si, age)
                out["incident_resolved_age_s"] = unknown("incident_not_resolved", si)
            else:
                how = getattr(inc, "resolve_reason", None)
                out["incident_resolve_reason"] = (
                    known(how, si, age)
                    if _readable(how)
                    else unknown("resolve_reason_unknown", si)
                )
                at = _num(getattr(inc, "resolved_at", None))
                if at is None:
                    out["incident_resolved_age_s"] = unknown("resolved_at_unknown", si)
                elif wall - at < -CLOCK_BACK_TOLERANCE_S:
                    out["incident_resolved_age_s"] = unknown("wall_clock_behind_ni", si)
                else:
                    out["incident_resolved_age_s"] = known(max(wall - at, 0.0), si, age)
    # open roots: active or acknowledged (an acknowledged incident is still
    # an outage, review PR #83, P3-10)
    active = [
        i
        for i in incidents
        if _value_of(getattr(i, "status", None)) in OPEN_STATES
        and getattr(i, "parent_id", None) is None
    ]
    others = []
    unreadable = False
    for i in active:
        if entry_id not in (getattr(i, "routers", None) or ()):
            continue
        if getattr(i, "id", None) == incident_id:
            continue
        if _value_of(getattr(i, "severity", None)) not in NOTICED_SEVERITIES:
            continue
        if not _readable(getattr(i, "id", None), _ID_RE):
            unreadable = True
            break
        others.append(i.id)
    if unreadable:
        out["other_incidents"] = unknown("incident_id_unreadable", si)
    elif len(set(others)) > _TUPLE_MAX:
        out["other_incidents"] = unknown("too_many_entries", si)
    else:
        out["other_incidents"] = known(tuple(sorted(set(others))), si, age)
    topo = getattr(ni, "topology", None)
    gateways = getattr(topo, "gateways", None)
    uplinks = getattr(topo, "uplinks", None)
    st = f"{s}.topology"
    if (
        topo is None
        or not isinstance(gateways, frozenset | set)
        or not isinstance(uplinks, Mapping)
        or (entry_id not in gateways and entry_id not in uplinks)
    ):
        out["dependants_degraded"] = unknown("router_not_in_topology", st)
    else:
        behind = list(topo.behind(entry_id))
        if not all(isinstance(e, str) for e in behind):
            out["dependants_degraded"] = unknown("topology_unreadable", st)
        else:
            down = set(behind)
            degraded = {
                r
                for i in active
                for r in (getattr(i, "routers", None) or ())
                if r in down
            }
            out["dependants_degraded"] = known(len(degraded), st, age)
    return out


def _sane(facts: Mapping[str, Fact]) -> dict[str, Fact]:
    """Every collected fact with a valid shape; anything else is unknown
    (``value_unreadable``) instead of an exception."""
    out: dict[str, Fact] = {}
    for name in SNAPSHOT_FACTS:
        fact = facts.get(name)
        if fact is None:
            continue
        if type(fact) is not Fact:
            out[name] = unknown("value_unreadable", "collector")
        elif fact.value is not None and not _shape_ok(name, fact.value):
            out[name] = unknown("value_unreadable", fact.source)
        else:
            out[name] = fact
    return out


def _guarded(
    facts: dict[str, Fact],
    names: Iterable[str],
    source: str,
    func: Callable[[], Mapping[str, Fact]],
) -> None:
    try:
        facts.update(func())
    except Exception as err:  # noqa: BLE001 - a broken source is "unknown"
        _LOGGER.debug("Verify: %s not collected (%s)", source, type(err).__name__)
        facts.update({n: unknown("collector_error", source) for n in names})


def snapshot_from_sources(
    src: FactSources,
    router_id: str,
    incident_id: str,
    *,
    safe_now: float,
    wall_now: float,
) -> VerifySnapshot | None:
    """The verification snapshot of ``router_id`` from memory only.

    ``src``: the ``heal_preflight.FactSources`` (only ``coordinator``,
    ``entry_id`` and ``ni`` are read; the store is not needed).
    ``safe_now``: the safety-clock time of the snapshot (the caller holds
    the store's clock); ``wall_now``: only to age the poll's and Network
    Intelligence's wall stamps. Reads attributes and memory-only methods;
    never awaits, never refreshes, never calls the router.

    Never raises: what it cannot read is unknown with a reason; if its own
    inputs are unusable (no ``FactSources``, a bad router or incident id, a
    time out of range) it returns None, which the verification treats as a
    missing snapshot ("cannot tell").
    """
    try:
        safe, wall = _time(safe_now), _time(wall_now)
        if (
            type(src) is not FactSources
            or type(router_id) is not str
            or not is_valid_id(router_id, ROUTER_ID_PREFIX)
            or not _readable(incident_id, _ID_RE)
            or safe is None
            or wall is None
        ):
            return None
        facts: dict[str, Fact] = {}
        poll: list[Any] = [unknown("collector_error", "coordinator"), None]

        def read_poll() -> Mapping[str, Fact]:
            poll[0], poll[1] = _poll(src, wall)
            return {"management_path": poll[0]}

        _guarded(facts, ("management_path",), "coordinator", read_poll)
        mgmt = facts["management_path"]
        _guarded(facts, _STATE_FACTS, "coordinator.data", lambda: _state(src, mgmt))
        _guarded(
            facts,
            _NI_FACTS,
            "network_intelligence",
            lambda: _ni(src, incident_id, wall, poll[1]),
        )
        return VerifySnapshot(
            router_id=router_id,
            incident_id=incident_id,
            taken_at=safe,
            wall_at=wall,
            **_sane(facts),
        )
    except Exception as err:  # noqa: BLE001 - the builder never raises
        _LOGGER.debug("Verify: no snapshot (%s)", type(err).__name__)
        return None


__all__ = [
    "AFTER_MAX_AGE_S",
    "BEFORE_MAX_AGE_S",
    "CLIENT_DROP_MIN",
    "CLIENT_DROP_PCT",
    "CLIENT_SMALL_BELOW",
    "CLIENT_SMALL_DROP",
    "CRITERIA",
    "EARLY_LOSS",
    "GUARDS",
    "SNAPSHOT_FACTS",
    "VERIFY_CLEAR_HOLD_S",
    "VERIFY_MAX_WAIT_S",
    "VERIFY_SETTLE_S",
    "WRITE_CRITERIA",
    "Attribution",
    "Binding",
    "Comparison",
    "Criterion",
    "PlannedEnd",
    "Role",
    "VerifyError",
    "VerifyResult",
    "VerifySnapshot",
    "client_drop_allowed",
    "client_loss_worse",
    "criteria_for",
    "planned_end",
    "snapshot_from_sources",
    "verify",
]
