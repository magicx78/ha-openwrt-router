"""Self-Healing (Phase 7), package B: the remediation record and its state machine.

Pure module (no Home Assistant import, no clock read, no router call): the
data model of one repair attempt (:class:`RemediationAction`), the ONE
transition table (:data:`TRANSITIONS`) that alone decides which state change
is allowed and who may trigger it, :func:`transition` (the only way to change
a state), the restart rule (:func:`restart_recovery`), the persisted
loop-protection state (:class:`LoopState`), the per-router settings
(:class:`HealSettings`) and the maintenance scopes of the module. The store
(``heal_store``) persists all of it; the deciding logic (risk, score,
breakers, cooldowns) comes in later packages and only reads and writes the
data defined here. Developer document: ``docs/self-healing.md``.

**States** (order §3): DETECTED, ANALYZED, PROPOSED, PREFLIGHT,
WAITING_APPROVAL, APPROVED, EXECUTING, VERIFYING, RESOLVED, REJECTED,
CANCELLED, FAILED, ROLLBACK_PENDING, ROLLING_BACK, ROLLED_BACK, ESCALATED,
MANUAL_RECOVERY_REQUIRED. Terminal: RESOLVED, REJECTED, CANCELLED,
ESCALATED, MANUAL_RECOVERY_REQUIRED, ROLLED_BACK; nothing leaves them.

**Actors** of a transition: ``engine`` (the remediation engine), ``admin``
(a verified HA administrator, through the module's routes) and ``recovery``
(the restart recovery of the store). Recovery never starts a write, an
approval or a preflight.

**No double execution.** EXECUTING is entered only from APPROVED, only by
the engine, only once per action (``first_entry``) and only through a
durable write (``durable``: the store persists the new state before the
caller may call the router). No edge leads from any state after EXECUTING
back to APPROVED or EXECUTING. An action found in EXECUTING, VERIFYING or
ROLLING_BACK after a restart moves to VERIFYING with ``interrupted`` set
("unknown, needs verification"); from there only RESOLVED, ESCALATED or
MANUAL_RECOVERY_REQUIRED follow (``not_interrupted`` guards FAILED, which
could lead to a rollback write).

**Strings.** Every string of the record is an id, a digest, a code
(``[a-z][a-z0-9_.]*``) or a short token (``[A-Za-z0-9][A-Za-z0-9_.:@-]*``,
at most 64 characters, never something that looks like key material);
mapping keys never name a secret (``core_masking.is_secret_key``).
Router-supplied names (services, radios, interfaces) are stored as such data
and never interpreted. Errors name the field, never the value.

**Fields.** Identity, the dedupe inputs and the flags never change after
creation; the planning fields change only while the action is planned;
approval, execution, verification and rollback change only together with
the transition they belong to, the approval binding never; ``audit_refs``
only grows; ``interrupted`` is set only by the restart rule (docs §3.1).

**Times.** Record times (history, ``created_at``, ``updated_at``) are UTC
wall-clock seconds passed in by the caller, kept to the millisecond and
recorded as given (also after a jump back). Every wait of the loop
protection (cooldowns, attempt windows, pauses, holds, retention of safety
state) runs on the :class:`SafetyClock`, which never runs backwards and
never jumps ahead by more than ``CLOCK_STEP_MAX_S`` at a time (docs §5.2).
"""

from __future__ import annotations

import hashlib
import itertools
import json
import logging
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields, replace
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any, Final, NoReturn, TypeVar

from .core_masking import is_secret_key, looks_like_key_material
from .core_models import (
    APPROVAL_ID_PREFIX,
    BACKUP_ID_PREFIX,
    EVENT_ID_PREFIX,
    REMEDIATION_ID_PREFIX,
    ROUTER_ID_PREFIX,
    is_sha256,
    is_valid_id,
    new_id,
)

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Limits of one record (docs/self-healing.md §3)
# ---------------------------------------------------------------------------

HISTORY_MAX: Final = 24  # the longest legal path has 13 entries
COMPONENTS_MAX: Final = 16
PARAMS_MAX: Final = 8
LIST_MAX: Final = 32  # items of a list in measurements and in a record
MEASUREMENTS_MAX: Final = 32  # keys of ``before`` / ``after``
CHECKS_MAX: Final = 32
FACTORS_MAX: Final = 16
REASONS_MAX: Final = 16
AUDIT_REFS_MAX: Final = 64
RECENT_FAILURES_MAX: Final = 10
EXTERNAL_WRITES_MAX: Final = 200
TOKEN_MAX: Final = 64
IDEMPOTENCY_RAW_MAX: Final = 128
PLAYBOOK_VERSION_MAX: Final = 10_000
CLIENTS_MAX: Final = 100_000
OUTAGE_MAX_S: Final = 86_400

# Digest-based ids of this module (module-internal: the core does not know
# them). Each is three letters + "_" + 32 hex, the core's id shape, so the
# masking never takes them for key material.
ACTION_DEDUPE_PREFIX: Final = "dda_"
INCIDENT_DEDUPE_PREFIX: Final = "ddi_"
COMPONENT_DEDUPE_PREFIX: Final = "ddc_"
COMPONENT_REF_PREFIX: Final = "cmp_"  # a component too long for a loop key
IDEMPOTENCY_PREFIX: Final = "idm_"
MAINTENANCE_ID_PREFIX: Final = "mtw_"
LOCK_ID_PREFIX: Final = "lck_"

# Safety clock (docs §5.2): the largest step one observation may add.
CLOCK_STEP_MAX_S: Final = 900
CLOCK_BACK_TOLERANCE_S: Final = 1.0  # smaller steps back are not counted
CLOCK_JUMPS_MAX: Final = 1_000_000

# Loop protection defaults and bounds (design §7; configurable within them).
COOLDOWN_DEFAULT_S: Final = 1800
COOLDOWN_BOUNDS_S: Final = (600, 86400)
MAX_ATTEMPTS_DEFAULT: Final = 2
MAX_ATTEMPTS_BOUNDS: Final = (1, 3)
BACKOFF_BASE_DEFAULT_S: Final = 1800
BACKOFF_BASE_BOUNDS_S: Final = (600, 86400)
BACKOFF_CAP_DEFAULT_S: Final = 86400
BACKOFF_CAP_BOUNDS_S: Final = (600, 86400)
FLEET_THRESHOLD_DEFAULT: Final = 3
FLEET_THRESHOLD_BOUNDS: Final = (1, 10)
FLEET_PAUSE_DEFAULT_S: Final = 86400
FLEET_PAUSE_BOUNDS_S: Final = (3600, 7 * 86400)
FLEET_CONCURRENCY_DEFAULT: Final = 1
FLEET_CONCURRENCY_BOUNDS: Final = (1, 1)
BACKOFF_STEP_MAX: Final = 16

_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,63}")
_CODE_RE: Final = re.compile(r"[a-z][a-z0-9_.]{0,63}")
_MKEY_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,47}")
_CORE_ID_RE: Final = re.compile(r"[a-z]{3}_[0-9a-f]{32}")
_IDEM_RAW_RE: Final = re.compile(r"[\x21-\x7e]{1,128}")
_SEGMENT_SPLIT_RE: Final = re.compile(r"[._:@-]")
# A name segment this long with mixed case and digits, or this long with
# many digits among letters, is more likely a key than a router name.
_MIXED_SEGMENT_MIN: Final = 12
_DIGIT_SEGMENT_MIN: Final = 16
_DIGIT_SEGMENT_DIGITS: Final = 4
_TS_MAX: Final = 1e11  # far beyond any wall time; above it is not a time


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class HealModelError(ValueError):
    """A record or a value is invalid. The message names the field only."""


class TransitionError(HealModelError):
    """A state change was refused; nothing changed."""

    code = "refused"

    def __init__(
        self,
        from_state: ActionState | None,
        to_state: Any,
        actor: Any,
        detail: str = "",
    ) -> None:
        """Keep the (validated) states and actor, never a free value."""
        self.from_state = from_state
        self.to_state = to_state if isinstance(to_state, ActionState) else None
        self.actor = actor if isinstance(actor, Actor) else None
        parts = [
            self.code,
            getattr(from_state, "value", "-"),
            getattr(self.to_state, "value", "?"),
            getattr(self.actor, "value", "?"),
        ]
        if detail:
            parts.append(detail)
        super().__init__(" ".join(parts))


class TerminalStateError(TransitionError):
    """The action is in a terminal state."""

    code = "terminal"


class IllegalTransitionError(TransitionError):
    """The pair (from, to) is not in the table (or the target is unknown)."""

    code = "illegal"


class ActorNotAllowedError(TransitionError):
    """The pair is in the table, but not for this actor."""

    code = "actor_not_allowed"


class PreconditionFailedError(TransitionError):
    """A precondition of the table row does not hold."""

    code = "precondition_failed"


class BadTransitionInputError(TransitionError):
    """Timestamp, reason or field changes of the transition are invalid."""

    code = "bad_input"


# ---------------------------------------------------------------------------
# Enums (persisted: a new value bumps the store's minor version)
# ---------------------------------------------------------------------------


class ActionState(StrEnum):
    """State of one remediation action (order §3)."""

    DETECTED = "detected"
    ANALYZED = "analyzed"
    PROPOSED = "proposed"
    PREFLIGHT = "preflight"
    WAITING_APPROVAL = "waiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    FAILED = "failed"
    ROLLBACK_PENDING = "rollback_pending"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    ESCALATED = "escalated"
    MANUAL_RECOVERY_REQUIRED = "manual_recovery_required"


class Actor(StrEnum):
    """Who triggers a transition (kinds only; who exactly is in the audit)."""

    ENGINE = "engine"
    ADMIN = "admin"
    RECOVERY = "recovery"


class Precondition(StrEnum):
    """Conditions a table row can demand beyond source, target and actor."""

    # the action was not interrupted by a restart (its outcome is known)
    NOT_INTERRUPTED = "not_interrupted"
    # the target state was never entered by this action before
    FIRST_ENTRY = "first_entry"


class RiskClass(IntEnum):
    """Binding risk classes (order §5)."""

    READ_ONLY = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class HealMode(StrEnum):
    """Operating mode of one router (order §4)."""

    OBSERVE = "observe"
    APPROVAL = "approval"
    AUTO_HEAL = "auto_heal"


class DecisionOutcome(StrEnum):
    """The five outcomes of the decision engine (order §7)."""

    RECOMMENDED = "recommended"
    REQUIRES_APPROVAL = "requires_approval"
    NOT_SAFE = "not_safe"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    UNSUPPORTED = "unsupported"


class VerificationResult(StrEnum):
    """The five verification results (order §11)."""

    RESOLVED = "resolved"
    PARTIAL = "partial"
    NOT_RESOLVED = "not_resolved"
    UNKNOWN = "unknown"
    NEW_FAULT = "new_fault"


class ApprovalStatus(StrEnum):
    """Approval of one action."""

    NOT_REQUIRED = "not_required"
    NOT_REQUESTED = "not_requested"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"  # the binding changed or the approval was lost


class CallResult(StrEnum):
    """What the one router call returned."""

    OK = "ok"
    REJECTED = "rejected"  # refused before any change (method, permission)
    INCONCLUSIVE = "inconclusive"  # timeout or connection loss: state unknown


class RollbackMechanism(StrEnum):
    """Verified rollback mechanisms independent of the management channel.

    Phase 7 has none (no confirmed commit, no watchdog, no out-of-band path
    on the platform); a new member needs a real, tested mechanism.
    """

    NONE = "none"


class RollbackStatus(StrEnum):
    """Rollback state of one action."""

    NOT_AVAILABLE = "not_available"
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    UNKNOWN = "unknown"  # a restart interrupted it


class CauseLevel(StrEnum):
    """Network Intelligence's derived cause level."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"


class CauseStatus(StrEnum):
    """Network Intelligence's cause status."""

    CONFIRMED = "confirmed"
    HYPOTHESIS = "hypothesis"


class ComponentKind(StrEnum):
    """Kind of an affected component."""

    ROUTER = "router"
    SERVICE = "service"
    RADIO = "radio"
    INTERFACE = "interface"
    CONFIG = "config"
    CLIENT = "client"  # a module pseudonym, never a MAC or a name


class CheckOutcome(StrEnum):
    """Outcome of one preflight or verification check."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class BreakerState(StrEnum):
    """Circuit breaker of one key (closes only by admin acknowledgement)."""

    CLOSED = "closed"
    OPEN = "open"


class LockHolder(StrEnum):
    """Who holds a router's repair lock."""

    ENGINE = "engine"  # a remediation action
    EXTERNAL = "external"  # a write from outside the engine (button, switch)


class HoldReason(StrEnum):
    """Why a router (or the fleet) is held (docs §5.1)."""

    # a call ran and its outcome is unknown (MANUAL_RECOVERY_REQUIRED)
    OUTCOME_UNKNOWN = "outcome_unknown"
    # a call ran and the action escalated to an admin
    OUTCOME_ESCALATED = "outcome_escalated"
    # a record of the store could not be read at load
    RECORD_UNREADABLE = "record_unreadable"
    # the store file was lost, unreadable or newer
    STORE_LOST = "store_lost"
    # an admin released an action stuck in a running state
    STUCK_RELEASED = "stuck_released"
    # an admin force-released a stuck external lock
    LOCK_FORCED = "lock_forced"


class MaintenanceScope(StrEnum):
    """Maintenance scopes kept by this module.

    Network- and router-wide maintenance is Network Intelligence's (one
    truth for both modules); an access point is a router whose role is AP.
    """

    INTERFACE = "interface"
    SERVICE = "service"


# ---------------------------------------------------------------------------
# State sets and the ONE transition table
# ---------------------------------------------------------------------------

S = ActionState
_E, _A, _R = Actor.ENGINE, Actor.ADMIN, Actor.RECOVERY

TERMINAL_STATES: Final = frozenset(
    {
        S.RESOLVED,
        S.REJECTED,
        S.CANCELLED,
        S.ESCALATED,
        S.MANUAL_RECOVERY_REQUIRED,
        S.ROLLED_BACK,
    }
)
# A router call may have happened or still run: unknown after a restart.
IN_FLIGHT_STATES: Final = frozenset({S.EXECUTING, S.VERIFYING, S.ROLLING_BACK})
# Entered only through a durable write (before the router call).
WRITE_AHEAD_STATES: Final = frozenset({S.EXECUTING, S.ROLLING_BACK})
# "A repair is active on this router": the repair lock is held.
LOCKING_STATES: Final = frozenset(
    {S.EXECUTING, S.VERIFYING, S.ROLLBACK_PENDING, S.ROLLING_BACK}
)


@dataclass(frozen=True, slots=True)
class Rule:
    """One row of the transition table."""

    actors: frozenset[Actor]
    requires: frozenset[Precondition] = frozenset()
    # the store must persist the new state before the caller goes on
    durable: bool = False
    # actors whose move marks the action as interrupted (restart recovery)
    interrupts: frozenset[Actor] = frozenset()


def _rule(
    *actors: Actor,
    requires: Iterable[Precondition] = (),
    durable: bool = False,
    interrupts: Iterable[Actor] = (),
) -> Rule:
    return Rule(frozenset(actors), frozenset(requires), durable, frozenset(interrupts))


_ONCE = (Precondition.FIRST_ENTRY,)
_KNOWN = (Precondition.NOT_INTERRUPTED,)

# (from, to) -> who may trigger it, under which conditions. The ONLY place
# that decides whether a state change is allowed (docs/self-healing.md §4).
TRANSITIONS: Final[Mapping[tuple[ActionState, ActionState], Rule]] = MappingProxyType(
    {
        (S.DETECTED, S.ANALYZED): _rule(_E),
        (S.DETECTED, S.CANCELLED): _rule(_E, _A),
        (S.ANALYZED, S.PROPOSED): _rule(_E),
        (S.ANALYZED, S.CANCELLED): _rule(_E, _A),
        (S.PROPOSED, S.PREFLIGHT): _rule(_E, _A),
        (S.PROPOSED, S.REJECTED): _rule(_A),
        (S.PROPOSED, S.CANCELLED): _rule(_E, _A),
        (S.PROPOSED, S.ESCALATED): _rule(_A),
        (S.PREFLIGHT, S.WAITING_APPROVAL): _rule(_E),
        (S.PREFLIGHT, S.APPROVED): _rule(_E),  # Auto-Heal, allowlisted
        (S.PREFLIGHT, S.CANCELLED): _rule(_E, _A, _R),
        (S.WAITING_APPROVAL, S.APPROVED): _rule(_A),
        (S.WAITING_APPROVAL, S.REJECTED): _rule(_A),
        (S.WAITING_APPROVAL, S.CANCELLED): _rule(_E, _A, _R),
        (S.WAITING_APPROVAL, S.ESCALATED): _rule(_A),
        (S.APPROVED, S.EXECUTING): _rule(_E, requires=_ONCE, durable=True),
        (S.APPROVED, S.CANCELLED): _rule(_E, _A, _R),
        (S.EXECUTING, S.VERIFYING): _rule(_E, _R, interrupts=(_R,)),
        (S.EXECUTING, S.FAILED): _rule(_E),  # the router refused the call
        (S.VERIFYING, S.VERIFYING): _rule(_R, requires=_KNOWN, interrupts=(_R,)),
        (S.VERIFYING, S.RESOLVED): _rule(_E),
        (S.VERIFYING, S.FAILED): _rule(_E, requires=_KNOWN),
        (S.VERIFYING, S.ESCALATED): _rule(_E, _A),
        (S.VERIFYING, S.MANUAL_RECOVERY_REQUIRED): _rule(_E, _R),
        (S.FAILED, S.ESCALATED): _rule(_E, _A, _R),
        (S.FAILED, S.ROLLBACK_PENDING): _rule(_E, requires=(*_ONCE, *_KNOWN)),
        (S.ROLLBACK_PENDING, S.ROLLING_BACK): _rule(_E, requires=_ONCE, durable=True),
        (S.ROLLBACK_PENDING, S.MANUAL_RECOVERY_REQUIRED): _rule(_E, _A, _R),
        (S.ROLLING_BACK, S.ROLLED_BACK): _rule(_E),
        (S.ROLLING_BACK, S.MANUAL_RECOVERY_REQUIRED): _rule(_E),
        (S.ROLLING_BACK, S.VERIFYING): _rule(_R, interrupts=(_R,)),
    }
)

# Restart rule (docs §5): state found at load -> (target, reason). States
# not listed (DETECTED, ANALYZED, PROPOSED, terminal ones) stay as they are;
# the engine re-checks open proposals against the current incidents.
_RESTART_RULES: Final[Mapping[ActionState, tuple[ActionState, str]]] = MappingProxyType(
    {
        S.EXECUTING: (S.VERIFYING, "interrupted_by_restart"),
        S.VERIFYING: (S.VERIFYING, "interrupted_by_restart"),
        S.ROLLING_BACK: (S.VERIFYING, "interrupted_by_restart"),
        S.ROLLBACK_PENDING: (
            S.MANUAL_RECOVERY_REQUIRED,
            "rollback_lost_on_restart",
        ),
        S.APPROVED: (S.CANCELLED, "approval_lost_on_restart"),
        S.WAITING_APPROVAL: (S.CANCELLED, "approval_lost_on_restart"),
        S.PREFLIGHT: (S.CANCELLED, "preflight_lost_on_restart"),
        S.FAILED: (S.ESCALATED, "failed_before_restart"),
    }
)


# ---------------------------------------------------------------------------
# Value checks (messages name the field, never the value)
# ---------------------------------------------------------------------------


def _fail(what: str) -> NoReturn:
    raise HealModelError(f"invalid {what}")


def _ts(value: Any, what: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or value < 0
        or value > _TS_MAX
    ):
        _fail(what)
    return round(float(value), 3)


def _opt_ts(value: Any, what: str) -> float | None:
    return None if value is None else _ts(value, what)


def _int(value: Any, what: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        _fail(what)
    return int(value)


def _opt_int(value: Any, what: str, lo: int, hi: int) -> int | None:
    return None if value is None else _int(value, what, lo, hi)


def _unit(value: Any, what: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not math.isfinite(value)
        or not 0.0 <= value <= 1.0
    ):
        _fail(what)
    return round(float(value), 4)


def _bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        _fail(what)
    return value


def _token_like_segment(segment: str) -> bool:
    """A segment shaped like an API key, a JWT part or a base64 run."""
    letters = sum(c.isalpha() for c in segment)
    digits = sum(c.isdigit() for c in segment)
    if (
        len(segment) >= _MIXED_SEGMENT_MIN
        and digits
        and any(c.isupper() for c in segment)
        and any(c.islower() for c in segment)
    ):
        return True
    return (
        len(segment) >= _DIGIT_SEGMENT_MIN
        and letters > 0
        and digits >= _DIGIT_SEGMENT_DIGITS
    )


def _token(value: Any, what: str) -> str:
    """A short router- or module-supplied name; never key material."""
    if not isinstance(value, str) or _TOKEN_RE.fullmatch(value) is None:
        _fail(what)
    if _CORE_ID_RE.fullmatch(value) is not None:
        return value
    if looks_like_key_material(value) or any(
        _token_like_segment(seg) for seg in _SEGMENT_SPLIT_RE.split(value)
    ):
        _fail(what)
    return value


def _opt_token(value: Any, what: str) -> str | None:
    return None if value is None else _token(value, what)


def _code(value: Any, what: str) -> str:
    """A machine code (reason, check id, action type, playbook id)."""
    if not isinstance(value, str) or _CODE_RE.fullmatch(value) is None:
        _fail(what)
    return value


def _opt_code(value: Any, what: str) -> str | None:
    return None if value is None else _code(value, what)


def _id(value: Any, prefix: str, what: str) -> str:
    if not is_valid_id(value, prefix):
        _fail(what)
    return str(value)


def _opt_id(value: Any, prefix: str, what: str) -> str | None:
    return None if value is None else _id(value, prefix, what)


def _digest(value: Any, what: str) -> str | None:
    if value is None:
        return None
    if not is_sha256(value):
        _fail(what)
    return str(value)


_EnumT = TypeVar("_EnumT", bound=StrEnum)


def _enum(cls: type[_EnumT], value: Any, what: str) -> _EnumT:
    try:
        return cls(value)
    except (ValueError, TypeError):
        _fail(what)


def _opt_enum(cls: type[_EnumT], value: Any, what: str) -> _EnumT | None:
    return None if value is None else _enum(cls, value, what)


def _risk(value: Any, what: str) -> RiskClass:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(what)
    try:
        return RiskClass(value)
    except ValueError:
        _fail(what)


def _tuple(
    value: Any, what: str, limit: int, item: Callable[[Any], Any]
) -> tuple[Any, ...]:
    if not isinstance(value, list | tuple) or len(value) > limit:
        _fail(what)
    return tuple(item(v) for v in value)


def _scalar(value: Any, what: str) -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > 2**53:
            _fail(what)
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail(what)
        return value
    return _token(value, what)


def _value(value: Any, what: str) -> Any:
    if isinstance(value, list | tuple):
        return _tuple(value, what, LIST_MAX, lambda v: _scalar(v, what))
    return _scalar(value, what)


def _mapping(value: Any, what: str, limit: int) -> Mapping[str, Any]:
    """Small flat mapping: plain keys that name no secret, scalar values."""
    if value is None:
        value = {}
    if not isinstance(value, Mapping) or len(value) > limit:
        _fail(what)
    out: dict[str, Any] = {}
    for key in sorted(value, key=str):
        if (
            not isinstance(key, str)
            or _MKEY_RE.fullmatch(key) is None
            or is_secret_key(key)
        ):
            _fail(what)
        out[key] = _value(value[key], what)
    return MappingProxyType(out)


def _plain(value: Any) -> Any:
    """JSON form of a value of the model."""
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, IntEnum):
        return int(value)
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    if hasattr(value, "to_dict"):
        return value.to_dict()
    return value


def _known(data: Any, cls: type, what: str) -> dict[str, Any]:
    """``data`` is a mapping with only field names of ``cls``."""
    if not isinstance(data, Mapping):
        _fail(what)
    names = {f.name for f in fields(cls)}
    if any(key not in names for key in data):
        _fail(what)
    return dict(data)


_T = TypeVar("_T")


def _build(cls: type[_T], data: Any, what: str) -> _T:
    """``cls(**data)`` with every construction error as HealModelError."""
    known = _known(data, cls, what)
    try:
        return cls(**known)
    except HealModelError:
        raise
    except (TypeError, ValueError, AttributeError) as err:
        raise HealModelError(f"invalid {what}") from err


def _part(value: Any, cls: type[_T], what: str) -> _T:
    return value if isinstance(value, cls) else _build(cls, value, what)


def _to_dict(obj: Any) -> dict[str, Any]:
    return {f.name: _plain(getattr(obj, f.name)) for f in fields(obj)}


def _set(obj: Any, name: str, value: Any) -> None:
    object.__setattr__(obj, name, value)


class _Record:
    """``to_dict`` / ``from_dict`` of the frozen parts."""

    __slots__ = ()
    _what = "record"

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return _to_dict(self)

    @classmethod
    def from_dict(cls, data: Any) -> Any:
        """From :meth:`to_dict`; raises :class:`HealModelError` on damage."""
        return _build(cls, data, cls._what)


# ---------------------------------------------------------------------------
# Parts of the record
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class Component(_Record):
    """One affected component (router-supplied name kept as a token)."""

    _what = "component"
    kind: ComponentKind
    name: str

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "kind", _enum(ComponentKind, self.kind, "component.kind"))
        _set(self, "name", _token(self.name, "component.name"))


@dataclass(frozen=True, kw_only=True, slots=True)
class Cause(_Record):
    """The cause as Network Intelligence reported it (never recomputed)."""

    _what = "cause"
    code: str
    status: CauseStatus = CauseStatus.HYPOTHESIS
    level: CauseLevel = CauseLevel.UNKNOWN
    confidence: float | None = None
    source_families: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "code", _code(self.code, "cause.code"))
        _set(self, "status", _enum(CauseStatus, self.status, "cause.status"))
        _set(self, "level", _enum(CauseLevel, self.level, "cause.level"))
        if self.confidence is not None:
            _set(self, "confidence", _unit(self.confidence, "cause.confidence"))
        _set(
            self,
            "source_families",
            _tuple(
                self.source_families,
                "cause.source_families",
                REASONS_MAX,
                lambda v: _code(v, "cause.source_families"),
            ),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class Factor(_Record):
    """One factor of the confidence score, with its reason code."""

    _what = "factor"
    factor: str
    value: float
    reason: str

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "factor", _code(self.factor, "factor.factor"))
        if (
            isinstance(self.value, bool)
            or not isinstance(self.value, int | float)
            or not math.isfinite(self.value)
            or abs(self.value) > 10
        ):
            _fail("factor.value")
        _set(self, "value", round(float(self.value), 4))
        _set(self, "reason", _code(self.reason, "factor.reason"))


@dataclass(frozen=True, kw_only=True, slots=True)
class Decision(_Record):
    """Outcome of the decision engine, explained (``why`` / ``why_not``)."""

    _what = "decision"
    outcome: DecisionOutcome
    score: float = 0.0
    factors: tuple[Factor, ...] = ()
    why: str | None = None
    why_not: str | None = None

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "outcome", _enum(DecisionOutcome, self.outcome, "decision.outcome"))
        _set(self, "score", _unit(self.score, "decision.score"))
        _set(
            self,
            "factors",
            _tuple(
                self.factors,
                "decision.factors",
                FACTORS_MAX,
                lambda v: _part(v, Factor, "factor"),
            ),
        )
        _set(self, "why", _opt_code(self.why, "decision.why"))
        _set(self, "why_not", _opt_code(self.why_not, "decision.why_not"))


@dataclass(frozen=True, kw_only=True, slots=True)
class Risk(_Record):
    """Risk class 0..3 with its reasons (never only from the action name).

    Unassessed means the highest class: a record without a risk assessment
    is never treated as read-only (holds and Auto-Heal check the class).
    """

    _what = "risk"
    risk_class: RiskClass = RiskClass.HIGH
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "risk_class", _risk(self.risk_class, "risk.risk_class"))
        _set(
            self,
            "reasons",
            _tuple(
                self.reasons,
                "risk.reasons",
                REASONS_MAX,
                lambda v: _code(v, "risk.reasons"),
            ),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class Impact(_Record):
    """Expected impact: counts and router ids only."""

    _what = "impact"
    clients_on_router: int | None = None
    clients_on_component: int | None = None
    dependants: tuple[str, ...] = ()  # router ids behind this router
    est_outage_s: int | None = None

    def __post_init__(self) -> None:
        """Validate."""
        for name in ("clients_on_router", "clients_on_component"):
            _set(
                self,
                name,
                _opt_int(getattr(self, name), f"impact.{name}", 0, CLIENTS_MAX),
            )
        _set(
            self,
            "dependants",
            _tuple(
                self.dependants,
                "impact.dependants",
                LIST_MAX,
                lambda v: _id(v, ROUTER_ID_PREFIX, "impact.dependants"),
            ),
        )
        _set(
            self,
            "est_outage_s",
            _opt_int(self.est_outage_s, "impact.est_outage_s", 0, OUTAGE_MAX_S),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class Change(_Record):
    """One planned change (typed; never a command)."""

    _what = "change"
    kind: str  # e.g. "service"
    target: str  # e.g. "dnsmasq"
    effect: str  # e.g. "restart"

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "kind", _code(self.kind, "change.kind"))
        _set(self, "target", _token(self.target, "change.target"))
        _set(self, "effect", _code(self.effect, "change.effect"))


@dataclass(frozen=True, kw_only=True, slots=True)
class Approval(_Record):
    """Approval status, bound to the guard approval and the binding hash."""

    _what = "approval"
    status: ApprovalStatus = ApprovalStatus.NOT_REQUESTED
    guard_approval_id: str | None = None
    binding_hash: str | None = None
    requested_by: Actor | None = None
    decided_by: Actor | None = None
    expires_at: float | None = None

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "status", _enum(ApprovalStatus, self.status, "approval.status"))
        _set(
            self,
            "guard_approval_id",
            _opt_id(self.guard_approval_id, APPROVAL_ID_PREFIX, "approval.id"),
        )
        _set(self, "binding_hash", _digest(self.binding_hash, "approval.binding_hash"))
        _set(
            self,
            "requested_by",
            _opt_enum(Actor, self.requested_by, "approval.requested_by"),
        )
        _set(
            self,
            "decided_by",
            _opt_enum(Actor, self.decided_by, "approval.decided_by"),
        )
        _set(self, "expires_at", _opt_ts(self.expires_at, "approval.expires_at"))


@dataclass(frozen=True, kw_only=True, slots=True)
class BackupRef(_Record):
    """Configuration backup reference (or why there is none)."""

    _what = "backup_ref"
    version_id: str | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        """Validate."""
        _set(
            self,
            "version_id",
            _opt_id(self.version_id, BACKUP_ID_PREFIX, "backup_ref.version_id"),
        )
        _set(self, "reason", _opt_code(self.reason, "backup_ref.reason"))


@dataclass(frozen=True, kw_only=True, slots=True)
class Execution(_Record):
    """The one router call of the action (times are wall-clock seconds)."""

    _what = "execution"
    attempt_no: int = 0  # attempt number of the loop key, from loop state
    intent_written_at: float | None = None
    call_started_at: float | None = None
    call_finished_at: float | None = None
    call_result: CallResult | None = None

    def __post_init__(self) -> None:
        """Validate."""
        _set(
            self,
            "attempt_no",
            _int(self.attempt_no, "execution.attempt_no", 0, 100),
        )
        for name in ("intent_written_at", "call_started_at", "call_finished_at"):
            _set(self, name, _opt_ts(getattr(self, name), f"execution.{name}"))
        _set(
            self,
            "call_result",
            _opt_enum(CallResult, self.call_result, "execution.call_result"),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class Check(_Record):
    """One preflight or verification check."""

    _what = "check"
    check: str
    outcome: CheckOutcome
    reason: str | None = None

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "check", _code(self.check, "check.check"))
        _set(self, "outcome", _enum(CheckOutcome, self.outcome, "check.outcome"))
        _set(self, "reason", _opt_code(self.reason, "check.reason"))


def _checks(value: Any, what: str) -> tuple[Check, ...]:
    return _tuple(value, what, CHECKS_MAX, lambda v: _part(v, Check, "check"))


@dataclass(frozen=True, kw_only=True, slots=True)
class Verification(_Record):
    """Verification result with before/after measurements (bounded)."""

    _what = "verification"
    result: VerificationResult | None = None
    before: Mapping[str, Any] = field(default_factory=dict)
    after: Mapping[str, Any] = field(default_factory=dict)
    checks: tuple[Check, ...] = ()

    def __post_init__(self) -> None:
        """Validate."""
        _set(
            self,
            "result",
            _opt_enum(VerificationResult, self.result, "verification.result"),
        )
        _set(
            self,
            "before",
            _mapping(self.before, "verification.before", MEASUREMENTS_MAX),
        )
        _set(
            self,
            "after",
            _mapping(self.after, "verification.after", MEASUREMENTS_MAX),
        )
        _set(self, "checks", _checks(self.checks, "verification.checks"))


@dataclass(frozen=True, kw_only=True, slots=True)
class Rollback(_Record):
    """Rollback statement and status (Phase 7: mechanism ``none``)."""

    _what = "rollback"
    mechanism: RollbackMechanism = RollbackMechanism.NONE
    statement: str | None = None
    status: RollbackStatus = RollbackStatus.NOT_AVAILABLE

    def __post_init__(self) -> None:
        """Validate."""
        _set(
            self,
            "mechanism",
            _enum(RollbackMechanism, self.mechanism, "rollback.mechanism"),
        )
        _set(self, "statement", _opt_code(self.statement, "rollback.statement"))
        _set(self, "status", _enum(RollbackStatus, self.status, "rollback.status"))


@dataclass(frozen=True, kw_only=True, slots=True)
class HistoryEntry(_Record):
    """One transition: from, to, the caller's time, the actor, a reason."""

    _what = "history"
    from_state: ActionState | None
    to_state: ActionState
    ts: float
    actor: Actor
    reason: str

    def __post_init__(self) -> None:
        """Validate."""
        _set(
            self,
            "from_state",
            _opt_enum(ActionState, self.from_state, "history.from_state"),
        )
        _set(self, "to_state", _enum(ActionState, self.to_state, "history.to_state"))
        _set(self, "ts", _ts(self.ts, "history.ts"))
        _set(self, "actor", _enum(Actor, self.actor, "history.actor"))
        _set(self, "reason", _code(self.reason, "history.reason"))


@dataclass(frozen=True, kw_only=True, slots=True)
class Flags(_Record):
    """Flags of a record (not states)."""

    _what = "flags"
    interrupted: bool = False  # a restart interrupted it: outcome unknown
    in_maintenance: bool = False
    acknowledged_by_admin: bool = False

    def __post_init__(self) -> None:
        """Validate."""
        for f in fields(self):
            _bool(getattr(self, f.name), f"flags.{f.name}")


# ---------------------------------------------------------------------------
# Digests and dedupe ids
# ---------------------------------------------------------------------------


def canonical_sha256(value: Any) -> str:
    """sha256 of the canonical JSON of ``value`` (sorted keys, no spaces)."""
    raw = json.dumps(
        _plain(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _digest_id(prefix: str, value: Any) -> str:
    return prefix + canonical_sha256(value)[:32]


def action_dedupe_id(
    router_id: str, action_type: str, params: Mapping[str, Any]
) -> str:
    """Same (router, action type, params) -> same id (order test 32)."""
    return _digest_id(
        ACTION_DEDUPE_PREFIX,
        {
            "r": _id(router_id, ROUTER_ID_PREFIX, "router_id"),
            "a": _code(action_type, "action_type"),
            "p": dict(_mapping(params, "params", PARAMS_MAX)),
        },
    )


def incident_dedupe_id(incident_id: str) -> str:
    """Same root incident -> same id, fleet-wide.

    Network Intelligence numbers incidents fleet-wide (``inc-N``), so one
    root incident has at most one open action in the whole fleet.
    """
    return _digest_id(INCIDENT_DEDUPE_PREFIX, {"i": _token(incident_id, "incident_id")})


ROUTER_COMPONENT: Final = Component(kind=ComponentKind.ROUTER, name="router")


def component_dedupe_id(router_id: str, component: Component) -> str:
    """Same (router, component) -> same id: one open action per component."""
    return _digest_id(
        COMPONENT_DEDUPE_PREFIX,
        {
            "r": _id(router_id, ROUTER_ID_PREFIX, "router_id"),
            "c": _part(component, Component, "component").to_dict(),
        },
    )


def component_ref(component: Component) -> str:
    """The ``ref`` of a loop key for one component: ``kind:name``.

    A name too long for a key is replaced by a digest id of the component.
    """
    ref = f"{component.kind.value}:{component.name}"
    if len(ref) <= TOKEN_MAX:
        return ref
    return _digest_id(COMPONENT_REF_PREFIX, component.to_dict())


def idempotency_id(raw: str) -> str:
    """Digest id of a caller's idempotency key; the raw value is not kept."""
    if not isinstance(raw, str) or _IDEM_RAW_RE.fullmatch(raw) is None:
        _fail("idempotency key")
    return _digest_id(IDEMPOTENCY_PREFIX, raw)


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------

# Fields nothing may change after creation (docs §3.1): identity and the
# history, the dedupe inputs, and the flags (``interrupted`` is set only by
# the restart rule, the others through ``with_flags``).
_IDENTITY_FIELDS: Final = frozenset(
    {"action_id", "router_id", "state", "history", "created_at", "updated_at"}
)
_FIXED_FIELDS: Final = _IDENTITY_FIELDS | frozenset(
    {"action_type", "params", "incident_id", "components", "idempotency_id", "flags"}
)
# States in which the action is still being planned (nothing approved yet).
PLANNING_STATES: Final = frozenset(
    {
        ActionState.DETECTED,
        ActionState.ANALYZED,
        ActionState.PROPOSED,
        ActionState.PREFLIGHT,
    }
)
# Change only while planning (``with_changes`` or a transition from there).
_PLAN_FIELDS: Final = frozenset(
    {
        "incident_type",
        "incident_reopen",
        "cause",
        "playbook_id",
        "playbook_version",
        "decision",
        "risk",
        "prerequisites",
        "planned_changes",
        "expected_impact",
        "backup_ref",
        "state_fingerprint",
    }
)
# Change only together with a transition from these source states.
_STEP_FIELD_SOURCES: Final[Mapping[str, frozenset[ActionState]]] = MappingProxyType(
    {
        "preflight": PLANNING_STATES | {ActionState.APPROVED},
        "approval": PLANNING_STATES
        | {ActionState.WAITING_APPROVAL, ActionState.APPROVED},
        "execution": frozenset(
            {ActionState.APPROVED, ActionState.EXECUTING, ActionState.VERIFYING}
        ),
        "verification": frozenset(
            {
                ActionState.PREFLIGHT,
                ActionState.APPROVED,
                ActionState.EXECUTING,
                ActionState.VERIFYING,
                ActionState.ROLLING_BACK,
            }
        ),
        "rollback": PLANNING_STATES
        | {
            ActionState.FAILED,
            ActionState.ROLLBACK_PENDING,
            ActionState.ROLLING_BACK,
        },
    }
)
# ``with_changes`` may set these step fields while planning (no transition).
_PLANNED_STEP_FIELDS: Final = frozenset({"preflight", "rollback"})
# A new record starts with these at their defaults.
_NEW_REFUSED: Final = _IDENTITY_FIELDS | frozenset(
    {"flags", "approval", "execution", "verification"}
)


@dataclass(frozen=True, kw_only=True, slots=True)
class RemediationAction(_Record):
    """One repair attempt (order §3 plus the design's additions).

    Change the state only with :func:`transition`; other fields with
    :meth:`with_changes`. Both return a new record.
    """

    _what = "action"
    action_id: str
    router_id: str
    state: ActionState
    history: tuple[HistoryEntry, ...]
    created_at: float
    updated_at: float
    action_type: str
    params: Mapping[str, Any] = field(default_factory=dict)
    incident_id: str | None = None
    incident_type: str | None = None
    incident_reopen: int = 0
    components: tuple[Component, ...] = ()
    cause: Cause | None = None
    playbook_id: str | None = None
    playbook_version: int | None = None
    decision: Decision | None = None
    risk: Risk = field(default_factory=Risk)
    prerequisites: tuple[str, ...] = ()
    planned_changes: tuple[Change, ...] = ()
    expected_impact: Impact = field(default_factory=Impact)
    preflight: tuple[Check, ...] = ()
    approval: Approval = field(default_factory=Approval)
    backup_ref: BackupRef = field(default_factory=BackupRef)
    execution: Execution = field(default_factory=Execution)
    verification: Verification = field(default_factory=Verification)
    rollback: Rollback = field(default_factory=Rollback)
    audit_refs: tuple[str, ...] = ()
    state_fingerprint: str | None = None
    idempotency_id: str | None = None
    flags: Flags = field(default_factory=Flags)

    def __post_init__(self) -> None:
        """Validate every field; the history must end in ``state``."""
        _set(self, "action_id", _id(self.action_id, REMEDIATION_ID_PREFIX, "action_id"))
        _set(self, "router_id", _id(self.router_id, ROUTER_ID_PREFIX, "router_id"))
        _set(self, "state", _enum(ActionState, self.state, "state"))
        history = _tuple(
            self.history,
            "history",
            HISTORY_MAX,
            lambda v: _part(v, HistoryEntry, "history"),
        )
        if (
            not history
            or history[-1].to_state is not self.state
            or history[0].from_state is not None
            or any(
                cur.from_state is not prev.to_state
                for prev, cur in itertools.pairwise(history)
            )
        ):
            _fail("history")
        _set(self, "history", history)
        _set(self, "created_at", _ts(self.created_at, "created_at"))
        _set(self, "updated_at", _ts(self.updated_at, "updated_at"))
        _set(self, "action_type", _code(self.action_type, "action_type"))
        _set(self, "params", _mapping(self.params, "params", PARAMS_MAX))
        _set(self, "incident_id", _opt_token(self.incident_id, "incident_id"))
        _set(self, "incident_type", _opt_code(self.incident_type, "incident_type"))
        _set(
            self,
            "incident_reopen",
            _int(self.incident_reopen, "incident_reopen", 0, 1_000_000),
        )
        _set(
            self,
            "components",
            _tuple(
                self.components,
                "components",
                COMPONENTS_MAX,
                lambda v: _part(v, Component, "component"),
            ),
        )
        for name, part_cls in (("cause", Cause), ("decision", Decision)):
            value = getattr(self, name)
            if value is not None:
                _set(self, name, _part(value, part_cls, name))
        _set(self, "playbook_id", _opt_code(self.playbook_id, "playbook_id"))
        _set(
            self,
            "playbook_version",
            _opt_int(
                self.playbook_version, "playbook_version", 0, PLAYBOOK_VERSION_MAX
            ),
        )
        for name, part_cls in (
            ("risk", Risk),
            ("expected_impact", Impact),
            ("approval", Approval),
            ("backup_ref", BackupRef),
            ("execution", Execution),
            ("verification", Verification),
            ("rollback", Rollback),
            ("flags", Flags),
        ):
            _set(self, name, _part(getattr(self, name), part_cls, name))
        _set(
            self,
            "prerequisites",
            _tuple(
                self.prerequisites,
                "prerequisites",
                CHECKS_MAX,
                lambda v: _code(v, "prerequisites"),
            ),
        )
        _set(
            self,
            "planned_changes",
            _tuple(
                self.planned_changes,
                "planned_changes",
                LIST_MAX,
                lambda v: _part(v, Change, "change"),
            ),
        )
        _set(self, "preflight", _checks(self.preflight, "preflight"))
        _set(
            self,
            "audit_refs",
            _tuple(
                self.audit_refs,
                "audit_refs",
                AUDIT_REFS_MAX,
                lambda v: _id(v, EVENT_ID_PREFIX, "audit_refs"),
            ),
        )
        _set(
            self,
            "state_fingerprint",
            _digest(self.state_fingerprint, "state_fingerprint"),
        )
        _set(
            self,
            "idempotency_id",
            _opt_id(self.idempotency_id, IDEMPOTENCY_PREFIX, "idempotency_id"),
        )

    # -- construction ------------------------------------------------------------------

    @classmethod
    def new(
        cls,
        *,
        router_id: str,
        action_type: str,
        ts: float,
        actor: Actor = Actor.ENGINE,
        reason: str = "detected",
        **values: Any,
    ) -> RemediationAction:
        """A new record in DETECTED (its first history entry has no source).

        Identity, flags, approval, execution and verification start at their
        defaults; the dedupe inputs (action type, params, incident,
        components, idempotency id) are given here and never change.
        """
        stamp = _ts(ts, "ts")
        if any(name in _NEW_REFUSED for name in values):
            _fail("fixed field")
        try:
            return cls(
                action_id=new_id(REMEDIATION_ID_PREFIX),
                router_id=router_id,
                state=ActionState.DETECTED,
                history=(
                    HistoryEntry(
                        from_state=None,
                        to_state=ActionState.DETECTED,
                        ts=stamp,
                        actor=actor,
                        reason=reason,
                    ),
                ),
                created_at=stamp,
                updated_at=stamp,
                action_type=action_type,
                **values,
            )
        except HealModelError:
            raise
        except (TypeError, ValueError, AttributeError) as err:
            raise HealModelError("invalid action") from err

    def with_changes(self, **changes: Any) -> RemediationAction:
        """A copy with other field values, outside a transition.

        Allowed: the planning fields (and planned preflight checks and the
        rollback statement) while the action is planned, and more
        ``audit_refs`` at any time. Everything else is fixed or changes only
        with its transition (:func:`transition`).
        """
        planning = self.state in PLANNING_STATES
        for name in changes:
            if name in _FIXED_FIELDS:
                _fail("fixed field")
            if name in _PLAN_FIELDS or name in _PLANNED_STEP_FIELDS:
                if not planning:
                    _fail("planning field")
            elif name in _STEP_FIELD_SOURCES:
                _fail("transition field")
        try:
            new = replace(self, **changes)
        except HealModelError:
            raise
        except (TypeError, ValueError, AttributeError) as err:
            raise HealModelError("invalid action") from err
        if not _audit_refs_grow(self, new):
            _fail("audit_refs")
        return new

    def with_flags(self, **flags: Any) -> RemediationAction:
        """A copy with ``in_maintenance`` or ``acknowledged_by_admin`` changed.

        ``interrupted`` is never set here (only the restart rule sets it) and
        an admin acknowledgement cannot be taken back.
        """
        allowed = {"in_maintenance", "acknowledged_by_admin"}
        if any(name not in allowed for name in flags):
            _fail("flags")
        new_flags = _build(Flags, {**self.flags.to_dict(), **flags}, "flags")
        if self.flags.acknowledged_by_admin and not new_flags.acknowledged_by_admin:
            _fail("flags.acknowledged_by_admin")
        return replace(self, flags=new_flags)

    # -- derived -----------------------------------------------------------------------

    @property
    def is_terminal(self) -> bool:
        """The action reached a terminal state."""
        return self.state in TERMINAL_STATES

    @property
    def holds_lock(self) -> bool:
        """A repair is active on the router while this action is here."""
        return self.state in LOCKING_STATES

    @property
    def action_dedupe(self) -> str:
        """Dedupe id of (router, action type, params)."""
        return action_dedupe_id(self.router_id, self.action_type, self.params)

    @property
    def incident_dedupe(self) -> str | None:
        """Dedupe id of the root incident (fleet-wide), None without one."""
        if self.incident_id is None:
            return None
        return incident_dedupe_id(self.incident_id)

    @property
    def target_components(self) -> tuple[Component, ...]:
        """The components the action acts on (the router if none is named)."""
        return self.components or (ROUTER_COMPONENT,)

    @property
    def component_dedupes(self) -> tuple[str, ...]:
        """Dedupe ids of (router, component) for every component."""
        return tuple(
            dict.fromkeys(
                component_dedupe_id(self.router_id, c) for c in self.target_components
            )
        )

    @property
    def loop_keys(self) -> tuple[tuple[str, str, str], ...]:
        """Attempt and breaker keys: (router, action type, component ref)."""
        return tuple(
            dict.fromkeys(
                (self.router_id, self.action_type, component_ref(c))
                for c in self.target_components
            )
        )

    @property
    def entered_executing(self) -> bool:
        """The action reached EXECUTING once (a router call may have run)."""
        return any(h.to_state is ActionState.EXECUTING for h in self.history)


def _audit_refs_grow(old: RemediationAction, new: RemediationAction) -> bool:
    """``audit_refs`` only grows: the old refs stay first, in order."""
    return new.audit_refs[: len(old.audit_refs)] == old.audit_refs


def binding_hash(action: RemediationAction, *, catalog_version: int) -> str:
    """The approval binding (design §3.2): changes when anything relevant does.

    Inputs: router, action type, params, catalog and playbook version, the
    action id, the root incident with its reopen count and the state
    fingerprint. Used as the guard checksum of the approval (later package).
    """
    return canonical_sha256(
        {
            "router_id": action.router_id,
            "action_type": action.action_type,
            "params": dict(action.params),
            "catalog_version": _int(catalog_version, "catalog_version", 0, 10_000),
            "playbook_version": action.playbook_version,
            "action_id": action.action_id,
            "incident_id": action.incident_id,
            "incident_reopen": action.incident_reopen,
            "state_fingerprint": action.state_fingerprint,
        }
    )


# ---------------------------------------------------------------------------
# Transitions
# ---------------------------------------------------------------------------


def can_transition(state: ActionState, to_state: ActionState, actor: Actor) -> bool:
    """Table check only (preconditions are judged against an action)."""
    rule = TRANSITIONS.get((state, to_state))
    return rule is not None and actor in rule.actors


def allowed_targets(state: ActionState, actor: Actor) -> frozenset[ActionState]:
    """States ``actor`` may move an action in ``state`` to (table only)."""
    return frozenset(
        dst
        for (src, dst), rule in TRANSITIONS.items()
        if src is state and actor in rule.actors
    )


def _precondition_holds(
    action: RemediationAction, to_state: ActionState, cond: Precondition
) -> bool:
    if cond is Precondition.NOT_INTERRUPTED:
        return not action.flags.interrupted
    return all(entry.to_state is not to_state for entry in action.history)


def transition(
    action: RemediationAction,
    to_state: ActionState | str,
    *,
    actor: Actor | str,
    ts: float,
    reason: str,
    changes: Mapping[str, Any] | None = None,
) -> RemediationAction:
    """Move ``action`` to ``to_state`` and return the new record.

    Validates against the table, appends the history entry (the caller's
    ``ts`` and ``actor``, a reason code) and applies ``changes`` (other
    fields, e.g. the verification result with VERIFYING -> RESOLVED) in the
    same step. Raises a :class:`TransitionError` subclass and changes
    nothing when the move is not allowed. Entering EXECUTING stamps
    ``execution.intent_written_at`` with ``ts``; the store makes that true
    by persisting the record before the caller goes on (``Rule.durable``).
    """
    src = action.state
    try:
        dst = ActionState(to_state)
    except (ValueError, TypeError):
        raise IllegalTransitionError(src, None, actor) from None
    try:
        who = Actor(actor)
    except (ValueError, TypeError):
        raise ActorNotAllowedError(src, dst, None) from None
    if src in TERMINAL_STATES:
        raise TerminalStateError(src, dst, who)
    rule = TRANSITIONS.get((src, dst))
    if rule is None:
        raise IllegalTransitionError(src, dst, who)
    if who not in rule.actors:
        raise ActorNotAllowedError(src, dst, who)
    for cond in sorted(rule.requires):
        if not _precondition_holds(action, dst, cond):
            raise PreconditionFailedError(src, dst, who, cond.value)
    try:
        entry = HistoryEntry(
            from_state=src, to_state=dst, ts=ts, actor=who, reason=reason
        )
    except HealModelError:
        raise BadTransitionInputError(src, dst, who, "entry") from None
    extra = dict(changes or {})
    detail = _refused_change(src, dst, extra)
    if detail is not None:
        raise BadTransitionInputError(src, dst, who, detail)
    try:
        if who in rule.interrupts:
            extra["flags"] = replace(action.flags, interrupted=True)
        if dst is ActionState.EXECUTING:
            execution = _part(
                extra.get("execution", action.execution), Execution, "execution"
            )
            extra["execution"] = replace(execution, intent_written_at=entry.ts)
        new = replace(
            action,
            state=dst,
            history=(*action.history, entry),
            updated_at=entry.ts,
            **extra,
        )
    except (HealModelError, TypeError, ValueError, AttributeError):
        raise BadTransitionInputError(src, dst, who, "changes") from None
    detail = _refused_result(action, new, dst)
    if detail is not None:
        raise BadTransitionInputError(src, dst, who, detail)
    return new


def _refused_change(
    src: ActionState, dst: ActionState, extra: Mapping[str, Any]
) -> str | None:
    """Which field of ``changes`` a transition src -> dst may not touch."""
    for name in extra:
        if name in _FIXED_FIELDS:
            return "fixed_field"
        if name in _PLAN_FIELDS and src not in PLANNING_STATES:
            return "planning_field"
        sources = _STEP_FIELD_SOURCES.get(name)
        if sources is not None and src not in sources:
            return "step_field"
        if (
            name == "approval"
            and src is ActionState.APPROVED
            and dst is not ActionState.CANCELLED
        ):
            return "step_field"
    return None


def _refused_result(
    old: RemediationAction, new: RemediationAction, dst: ActionState
) -> str | None:
    """Field rules that compare the old and the new record."""
    if not _audit_refs_grow(old, new):
        return "audit_refs"
    if old.state in (ActionState.WAITING_APPROVAL, ActionState.APPROVED) and (
        new.approval.guard_approval_id != old.approval.guard_approval_id
        or new.approval.binding_hash != old.approval.binding_hash
    ):
        return "approval_binding"
    if dst is not ActionState.EXECUTING and (
        new.execution.intent_written_at != old.execution.intent_written_at
        or new.execution.attempt_no != old.execution.attempt_no
    ):
        return "execution_intent"
    return None


def restart_recovery(action: RemediationAction) -> tuple[ActionState, str] | None:
    """What a restart does to an action found in this state, or None.

    In-flight actions (EXECUTING, VERIFYING, ROLLING_BACK) become "unknown,
    needs verification" (VERIFYING, interrupted); approvals and preflights
    are memory-only and lost; a pending rollback is never started after a
    restart; FAILED escalates. An action that is already interrupted is
    left alone (a second restart adds nothing).
    """
    step = _RESTART_RULES.get(action.state)
    if step is None:
        return None
    if action.state is ActionState.VERIFYING and action.flags.interrupted:
        return None
    return step


def apply_restart_recovery(
    action: RemediationAction, *, ts: float
) -> RemediationAction:
    """Apply :func:`restart_recovery` through the table (actor ``recovery``)."""
    step = restart_recovery(action)
    if step is None:
        return action
    target, reason = step
    changes: dict[str, Any] = {}
    if action.state is ActionState.ROLLING_BACK:
        changes["rollback"] = replace(action.rollback, status=RollbackStatus.UNKNOWN)
    if action.state in (ActionState.APPROVED, ActionState.WAITING_APPROVAL):
        changes["approval"] = replace(
            action.approval, status=ApprovalStatus.INVALIDATED
        )
    return transition(
        action, target, actor=Actor.RECOVERY, ts=ts, reason=reason, changes=changes
    )


def hold_reason_for(action: RemediationAction) -> HoldReason | None:
    """Whether the end of ``action`` holds its router, and why (docs §5.1).

    An action that reached EXECUTING (a router call may have run) and ended
    in MANUAL_RECOVERY_REQUIRED (outcome unknown) or ESCALATED holds the
    router until an admin releases it. Not held: a call the router refused
    cleanly (EXECUTING -> FAILED with ``call_result`` REJECTED, not
    interrupted), and every action that never reached EXECUTING.
    """
    if not action.entered_executing:
        return None
    if action.state is ActionState.MANUAL_RECOVERY_REQUIRED:
        return HoldReason.OUTCOME_UNKNOWN
    if action.state is not ActionState.ESCALATED:
        return None
    clean_refusal = (
        not action.flags.interrupted
        and action.execution.call_result is CallResult.REJECTED
        and any(
            h.from_state is ActionState.EXECUTING and h.to_state is ActionState.FAILED
            for h in action.history
        )
    )
    return None if clean_refusal else HoldReason.OUTCOME_ESCALATED


# ---------------------------------------------------------------------------
# Loop protection state (data only; packages D/I decide with it)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class LoopLimits(_Record):
    """Configurable limits of the loop protection (within fixed bounds)."""

    _what = "limits"
    cooldown_s: int = COOLDOWN_DEFAULT_S
    max_attempts_24h: int = MAX_ATTEMPTS_DEFAULT
    backoff_base_s: int = BACKOFF_BASE_DEFAULT_S
    backoff_cap_s: int = BACKOFF_CAP_DEFAULT_S
    fleet_failure_threshold: int = FLEET_THRESHOLD_DEFAULT
    fleet_pause_s: int = FLEET_PAUSE_DEFAULT_S
    fleet_concurrency: int = FLEET_CONCURRENCY_DEFAULT

    def __post_init__(self) -> None:
        """Validate against the bounds."""
        for name, (lo, hi) in (
            ("cooldown_s", COOLDOWN_BOUNDS_S),
            ("max_attempts_24h", MAX_ATTEMPTS_BOUNDS),
            ("backoff_base_s", BACKOFF_BASE_BOUNDS_S),
            ("backoff_cap_s", BACKOFF_CAP_BOUNDS_S),
            ("fleet_failure_threshold", FLEET_THRESHOLD_BOUNDS),
            ("fleet_pause_s", FLEET_PAUSE_BOUNDS_S),
            ("fleet_concurrency", FLEET_CONCURRENCY_BOUNDS),
        ):
            _int(getattr(self, name), f"limits.{name}", lo, hi)
        if self.backoff_cap_s < self.backoff_base_s:
            _fail("limits.backoff_cap_s")


@dataclass(frozen=True, kw_only=True, slots=True)
class AttemptRecord(_Record):
    """Attempts of one (router, action type, component ref) key.

    Times are safety-clock seconds (``SafetyClock.safe``).
    """

    _what = "attempt"
    count: int = 0
    window_start: float | None = None
    last_at: float | None = None
    cooldown_until: float | None = None
    backoff_step: int = 0
    last_result: str | None = None  # a CallResult or VerificationResult value

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "count", _int(self.count, "attempt.count", 0, 1000))
        for name in ("window_start", "last_at", "cooldown_until"):
            _set(self, name, _opt_ts(getattr(self, name), f"attempt.{name}"))
        _set(
            self,
            "backoff_step",
            _int(self.backoff_step, "attempt.backoff_step", 0, BACKOFF_STEP_MAX),
        )
        _set(self, "last_result", _opt_code(self.last_result, "attempt.last_result"))


@dataclass(frozen=True, kw_only=True, slots=True)
class BreakerRecord(_Record):
    """Circuit breaker of one (router, action type, target) key."""

    _what = "breaker"
    state: BreakerState = BreakerState.CLOSED
    opened_at: float | None = None
    reason: str | None = None
    failures: int = 0
    acknowledged_at: float | None = None

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "state", _enum(BreakerState, self.state, "breaker.state"))
        _set(self, "opened_at", _opt_ts(self.opened_at, "breaker.opened_at"))
        _set(self, "reason", _opt_code(self.reason, "breaker.reason"))
        _set(self, "failures", _int(self.failures, "breaker.failures", 0, 1000))
        _set(
            self,
            "acknowledged_at",
            _opt_ts(self.acknowledged_at, "breaker.acknowledged_at"),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class FleetPause(_Record):
    """Fleet-wide pause of Auto-Heal (fleet breaker, lost or damaged store)."""

    _what = "fleet"
    paused_until: float | None = None
    since: float | None = None
    reason: str | None = None
    recent_failures: tuple[float, ...] = ()

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "paused_until", _opt_ts(self.paused_until, "fleet.paused_until"))
        _set(self, "since", _opt_ts(self.since, "fleet.since"))
        _set(self, "reason", _opt_code(self.reason, "fleet.reason"))
        _set(
            self,
            "recent_failures",
            _tuple(
                self.recent_failures,
                "fleet.recent_failures",
                RECENT_FAILURES_MAX,
                lambda v: _ts(v, "fleet.recent_failures"),
            ),
        )

    def paused(self, now: float) -> bool:
        """Auto-Heal is paused fleet-wide at ``now``."""
        return self.paused_until is not None and now < self.paused_until


LOCK_SOURCE_ENGINE: Final = "self_healing"


def _new_lock_id() -> str:
    return new_id(LOCK_ID_PREFIX)


@dataclass(frozen=True, kw_only=True, slots=True)
class LockRecord(_Record):
    """Holder of a router's repair lock.

    Every holder has its own ``lock_id``: two writes from the same source
    are two holders, and only the id releases the lock.
    """

    _what = "lock"
    router_id: str
    holder: LockHolder
    since: float  # wall time (information only; a lock never expires)
    source: str  # "self_healing", "button.reboot", "switch.service" ...
    action_id: str | None = None
    lock_id: str = field(default_factory=_new_lock_id)

    def __post_init__(self) -> None:
        """Validate (an engine lock names its action, an external one none)."""
        _set(self, "router_id", _id(self.router_id, ROUTER_ID_PREFIX, "lock.router_id"))
        _set(self, "holder", _enum(LockHolder, self.holder, "lock.holder"))
        _set(self, "since", _ts(self.since, "lock.since"))
        _set(self, "source", _code(self.source, "lock.source"))
        _set(
            self,
            "action_id",
            _opt_id(self.action_id, REMEDIATION_ID_PREFIX, "lock.action_id"),
        )
        _set(self, "lock_id", _id(self.lock_id, LOCK_ID_PREFIX, "lock.lock_id"))
        if (self.holder is LockHolder.ENGINE) is (self.action_id is None):
            _fail("lock.action_id")

    @classmethod
    def external(cls, router_id: str, source: str, since: float) -> LockRecord:
        """A new holder for a write from outside the engine."""
        return cls(
            router_id=router_id, holder=LockHolder.EXTERNAL, since=since, source=source
        )

    @classmethod
    def engine(cls, action: RemediationAction, since: float) -> LockRecord:
        """The lock of a remediation action."""
        return cls(
            router_id=action.router_id,
            holder=LockHolder.ENGINE,
            action_id=action.action_id,
            since=since,
            source=LOCK_SOURCE_ENGINE,
        )

    def same_holder(self, other: LockRecord) -> bool:
        """The same holder: the same lock id."""
        return self.lock_id == other.lock_id


@dataclass(frozen=True, kw_only=True, slots=True)
class ExternalWrite(_Record):
    """A router write that came from outside the engine (button, switch)."""

    _what = "external"
    router_id: str
    source: str  # e.g. "button.service_restart"
    target: str  # e.g. "dnsmasq"
    ts: float
    audit_ref: str | None = None

    def __post_init__(self) -> None:
        """Validate."""
        _set(
            self,
            "router_id",
            _id(self.router_id, ROUTER_ID_PREFIX, "external.router_id"),
        )
        _set(self, "source", _code(self.source, "external.source"))
        _set(self, "target", _token(self.target, "external.target"))
        _set(self, "ts", _ts(self.ts, "external.ts"))
        _set(
            self,
            "audit_ref",
            _opt_id(self.audit_ref, EVENT_ID_PREFIX, "external.audit_ref"),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class IdempotencyRecord(_Record):
    """An idempotency id points at the action it created."""

    _what = "idempotency"
    action_id: str
    created_at: float

    def __post_init__(self) -> None:
        """Validate."""
        _set(
            self,
            "action_id",
            _id(self.action_id, REMEDIATION_ID_PREFIX, "idempotency.action_id"),
        )
        _set(self, "created_at", _ts(self.created_at, "idempotency.created_at"))


@dataclass(frozen=True, kw_only=True, slots=True)
class SafetyClock(_Record):
    """The clock every wait of the loop protection runs on (docs §5.2).

    ``observe(wall)`` moves ``safe`` on by the wall-clock step since the
    last observation, but never backwards (a jump back adds nothing) and by
    at most ``CLOCK_STEP_MAX_S`` (a jump ahead, or a long downtime, adds
    one step). So a wrong wall clock can only make waits longer, never
    shorter. The engine observes it at least every few minutes.
    """

    _what = "clock"
    wall: float | None = None  # the last wall time observed
    safe: float | None = None
    jumps_ahead: int = 0
    jumps_back: int = 0

    def __post_init__(self) -> None:
        """Validate (both times set, or neither)."""
        _set(self, "wall", _opt_ts(self.wall, "clock.wall"))
        _set(self, "safe", _opt_ts(self.safe, "clock.safe"))
        if (self.wall is None) is not (self.safe is None):
            _fail("clock.safe")
        for name in ("jumps_ahead", "jumps_back"):
            _set(
                self,
                name,
                _int(getattr(self, name), f"clock.{name}", 0, CLOCK_JUMPS_MAX),
            )

    def observe(self, now: float) -> SafetyClock:
        """The clock after observing the wall time ``now``."""
        wall = _ts(now, "clock.now")
        if self.wall is None or self.safe is None:
            return replace(self, wall=wall, safe=wall)
        delta = wall - self.wall
        ahead, back = self.jumps_ahead, self.jumps_back
        if delta < 0:
            step = 0.0
            if -delta > CLOCK_BACK_TOLERANCE_S:
                back = min(back + 1, CLOCK_JUMPS_MAX)
        elif delta > CLOCK_STEP_MAX_S:
            step = float(CLOCK_STEP_MAX_S)
            ahead = min(ahead + 1, CLOCK_JUMPS_MAX)
        else:
            step = delta
        return SafetyClock(
            wall=wall,
            safe=min(self.safe + step, _TS_MAX),
            jumps_ahead=ahead,
            jumps_back=back,
        )


FLEET_HOLD_KEY: Final = ""  # key of the fleet-wide hold in ``LoopState.holds``


@dataclass(frozen=True, kw_only=True, slots=True)
class RouterHold(_Record):
    """A router (or the whole fleet) held: Observe only (docs §5.1).

    While a hold is active the router's effective mode is Observe: no
    approval, no Auto-Heal, no write of Risk 1 or more. Read-only
    diagnostics (Risk 0) still run. ``until`` None: only an admin releases
    it. Times are safety-clock seconds.
    """

    _what = "hold"
    router_id: str | None  # None: the whole fleet
    reason: HoldReason
    since: float
    until: float | None = None
    action_id: str | None = None

    def __post_init__(self) -> None:
        """Validate."""
        _set(
            self,
            "router_id",
            _opt_id(self.router_id, ROUTER_ID_PREFIX, "hold.router_id"),
        )
        _set(self, "reason", _enum(HoldReason, self.reason, "hold.reason"))
        _set(self, "since", _ts(self.since, "hold.since"))
        _set(self, "until", _opt_ts(self.until, "hold.until"))
        if self.until is not None and self.until < self.since:
            _fail("hold.until")
        _set(
            self,
            "action_id",
            _opt_id(self.action_id, REMEDIATION_ID_PREFIX, "hold.action_id"),
        )

    @property
    def key(self) -> str:
        """Key in ``LoopState.holds`` (the router id, or the fleet key)."""
        return self.router_id or FLEET_HOLD_KEY

    def active(self, safe_now: float) -> bool:
        """The hold is in force at safety-clock time ``safe_now``."""
        return self.until is None or safe_now < self.until

    def outlasts(self, other: RouterHold) -> bool:
        """This hold ends later than ``other`` (no end is the latest)."""
        if other.until is None:
            return False
        return self.until is None or self.until > other.until


LoopKey = tuple[str, str, str]  # (router_id, action_type, component ref)
_KEY_FIELDS: Final = ("router_id", "action_type", "ref")


def _loop_key(raw: Any, what: str) -> LoopKey:
    if not isinstance(raw, Mapping):
        _fail(what)
    return (
        _id(raw.get("router_id"), ROUTER_ID_PREFIX, f"{what}.router_id"),
        _code(raw.get("action_type"), f"{what}.action_type"),
        _token(raw.get("ref"), f"{what}.ref"),
    )


def _loop_row(key: LoopKey, record: _Record) -> dict[str, Any]:
    return {**dict(zip(_KEY_FIELDS, key, strict=True)), **record.to_dict()}


def _list(data: Mapping[str, Any], name: str) -> list[Any]:
    rows = data.get(name) or []
    if not isinstance(rows, list):
        _fail(f"loop.{name}")
    return rows


def _map(data: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    raw = data.get(name) or {}
    if not isinstance(raw, Mapping):
        _fail(f"loop.{name}")
    return raw


@dataclass(slots=True)
class LoopState:
    """Every piece of loop-protection state that must survive a restart.

    ``attempts`` and ``breakers``: per (router, action type, component
    ref); ``fleet``: the fleet-wide pause; ``action_dedupe`` (router,
    action type, params), ``incident_dedupe`` (root incident, fleet-wide)
    and ``component_dedupe`` (router, component): dedupe id -> the
    non-terminal action holding it; ``idempotency``: idempotency id ->
    action; ``locks``: the repair lock holder per router; ``holds``: held
    routers (key: router id, ``""`` for the fleet); ``clock``: the safety
    clock; ``external_writes``: the newest writes from outside the engine
    (bounded).
    """

    attempts: dict[LoopKey, AttemptRecord] = field(default_factory=dict)
    breakers: dict[LoopKey, BreakerRecord] = field(default_factory=dict)
    fleet: FleetPause = field(default_factory=FleetPause)
    incident_dedupe: dict[str, str] = field(default_factory=dict)
    action_dedupe: dict[str, str] = field(default_factory=dict)
    component_dedupe: dict[str, str] = field(default_factory=dict)
    idempotency: dict[str, IdempotencyRecord] = field(default_factory=dict)
    locks: dict[str, LockRecord] = field(default_factory=dict)
    holds: dict[str, RouterHold] = field(default_factory=dict)
    clock: SafetyClock = field(default_factory=SafetyClock)
    external_writes: list[ExternalWrite] = field(default_factory=list)

    # -- locks -------------------------------------------------------------------------

    def lock_holder(self, router_id: str) -> LockRecord | None:
        """Who holds the router's repair lock (None: free)."""
        return self.locks.get(router_id)

    def repair_active(self, router_id: str) -> bool:
        """A remediation action holds the router's lock."""
        lock = self.locks.get(router_id)
        return lock is not None and lock.holder is LockHolder.ENGINE

    def try_lock(self, record: LockRecord) -> bool:
        """Take the lock if it is free; True again only for the same holder
        (the same ``lock_id``), never for another one of the same source."""
        held = self.locks.get(record.router_id)
        if held is not None:
            return held.same_holder(record)
        self.locks[record.router_id] = record
        return True

    def release_lock(self, router_id: str, lock_id: str) -> bool:
        """Release the lock; only its holder (its ``lock_id``) can."""
        held = self.locks.get(router_id)
        if held is None or held.lock_id != lock_id:
            return False
        del self.locks[router_id]
        return True

    # -- holds -------------------------------------------------------------------------

    def hold_on(self, router_id: str, safe_now: float) -> RouterHold | None:
        """The active hold on a router: its own, else the fleet's."""
        for key in (router_id, FLEET_HOLD_KEY):
            hold = self.holds.get(key)
            if hold is not None and hold.active(safe_now):
                return hold
        return None

    def place_hold(self, hold: RouterHold) -> RouterHold:
        """Hold a router (or the fleet); a hold in force that lasts longer
        stays. Returns the hold now in force for that key."""
        held = self.holds.get(hold.key)
        if held is None or hold.outlasts(held):
            self.holds[hold.key] = hold
            return hold
        return held

    def drop_expired_holds(self, safe_now: float) -> int:
        """Forget holds whose time is over (safety clock)."""
        gone = [k for k, h in self.holds.items() if not h.active(safe_now)]
        for key in gone:
            del self.holds[key]
        return len(gone)

    # -- external writes ---------------------------------------------------------------

    def record_external_write(self, write: ExternalWrite) -> None:
        """Remember a write from outside the engine (the newest are kept)."""
        self.external_writes.append(write)
        del self.external_writes[:-EXTERNAL_WRITES_MAX]

    # -- serialisation -----------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """JSON form (the keys of the maps become fields of a row)."""
        return {
            "attempts": [_loop_row(k, v) for k, v in sorted(self.attempts.items())],
            "breakers": [_loop_row(k, v) for k, v in sorted(self.breakers.items())],
            "fleet": self.fleet.to_dict(),
            "incident_dedupe": dict(sorted(self.incident_dedupe.items())),
            "action_dedupe": dict(sorted(self.action_dedupe.items())),
            "component_dedupe": dict(sorted(self.component_dedupe.items())),
            "idempotency": {
                k: v.to_dict() for k, v in sorted(self.idempotency.items())
            },
            "locks": [v.to_dict() for _k, v in sorted(self.locks.items())],
            "holds": [v.to_dict() for _k, v in sorted(self.holds.items())],
            "clock": self.clock.to_dict(),
            "external_writes": [w.to_dict() for w in self.external_writes],
        }

    @classmethod
    def from_dict(cls, data: Any) -> LoopState:
        """From :meth:`to_dict`; raises :class:`HealModelError` on any damage."""
        if not isinstance(data, Mapping):
            _fail("loop")
        state = cls()
        for row in _list(data, "attempts"):
            state.attempts[_loop_key(row, "loop.attempts")] = _build(
                AttemptRecord, _known_row(row, "attempts"), "loop.attempts"
            )
        for row in _list(data, "breakers"):
            state.breakers[_loop_key(row, "loop.breakers")] = _build(
                BreakerRecord, _known_row(row, "breakers"), "loop.breakers"
            )
        state.fleet = _build(FleetPause, data.get("fleet") or {}, "loop.fleet")
        for name, prefix, target in (
            ("incident_dedupe", INCIDENT_DEDUPE_PREFIX, state.incident_dedupe),
            ("action_dedupe", ACTION_DEDUPE_PREFIX, state.action_dedupe),
            ("component_dedupe", COMPONENT_DEDUPE_PREFIX, state.component_dedupe),
        ):
            for dedupe, action_id in _map(data, name).items():
                target[_id(dedupe, prefix, f"loop.{name}")] = _id(
                    action_id, REMEDIATION_ID_PREFIX, f"loop.{name}"
                )
        for idem, rec in _map(data, "idempotency").items():
            state.idempotency[_id(idem, IDEMPOTENCY_PREFIX, "loop.idempotency")] = (
                _build(IdempotencyRecord, rec, "loop.idempotency")
            )
        for row in _list(data, "locks"):
            lock = _build(LockRecord, row, "loop.locks")
            state.locks[lock.router_id] = lock
        for row in _list(data, "holds"):
            hold = _build(RouterHold, row, "loop.holds")
            if hold.key in state.holds:
                _fail("loop.holds")
            state.holds[hold.key] = hold
        state.clock = _build(SafetyClock, data.get("clock") or {}, "loop.clock")
        state.external_writes = [
            _build(ExternalWrite, row, "loop.external_writes")
            for row in _list(data, "external_writes")
        ][-EXTERNAL_WRITES_MAX:]
        return state


def _known_row(row: Any, name: str) -> dict[str, Any]:
    if not isinstance(row, Mapping):
        _fail(f"loop.{name}")
    return {k: v for k, v in row.items() if k not in _KEY_FIELDS}


# ---------------------------------------------------------------------------
# Settings and maintenance
# ---------------------------------------------------------------------------

# Owner decision (2026-11-27): after the update the module is ON for every
# router in Observe mode; Auto-Heal is never on by default, the allowlist is
# empty. Only an admin changes it (later package).
DEFAULT_MODULE_ENABLED: Final = True
DEFAULT_MODE: Final = HealMode.OBSERVE
# Highest risk an allowlist entry may carry (design OPEN Q7, stricter
# reading until the owner decides: Risk <= 1). Risk 3 can never be allowed.
AUTO_HEAL_MAX_RISK: Final = RiskClass.LOW
ALLOWLIST_MAX: Final = 16


@dataclass(frozen=True, kw_only=True, slots=True)
class AllowEntry(_Record):
    """One Auto-Heal allowlist entry of a router."""

    _what = "allow"
    action_type: str
    params: Mapping[str, Any] = field(default_factory=dict)  # a params subset
    max_risk: RiskClass = RiskClass.READ_ONLY

    def __post_init__(self) -> None:
        """Validate; nothing above ``AUTO_HEAL_MAX_RISK`` can be allowed."""
        _set(self, "action_type", _code(self.action_type, "allow.action_type"))
        _set(self, "params", _mapping(self.params, "allow.params", PARAMS_MAX))
        risk = _risk(self.max_risk, "allow.max_risk")
        if risk > AUTO_HEAL_MAX_RISK:
            _fail("allow.max_risk")
        _set(self, "max_risk", risk)


@dataclass(frozen=True, kw_only=True, slots=True)
class RouterSettings(_Record):
    """Mode and allowlist of one router."""

    _what = "router"
    mode: HealMode = DEFAULT_MODE
    allowlist: tuple[AllowEntry, ...] = ()

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "mode", _enum(HealMode, self.mode, "router.mode"))
        _set(
            self,
            "allowlist",
            _tuple(
                self.allowlist,
                "router.allowlist",
                ALLOWLIST_MAX,
                lambda v: _part(v, AllowEntry, "allow"),
            ),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class HealSettings(_Record):
    """Module switch, loop limits and the per-router settings."""

    _what = "settings"
    enabled: bool = DEFAULT_MODULE_ENABLED
    limits: LoopLimits = field(default_factory=LoopLimits)
    routers: Mapping[str, RouterSettings] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate."""
        _set(self, "enabled", _bool(self.enabled, "settings.enabled"))
        _set(self, "limits", _part(self.limits, LoopLimits, "limits"))
        if not isinstance(self.routers, Mapping):
            _fail("settings.routers")
        routers: dict[str, RouterSettings] = {}
        for rid in sorted(self.routers, key=str):
            routers[_id(rid, ROUTER_ID_PREFIX, "settings.routers")] = _part(
                self.routers[rid], RouterSettings, "router"
            )
        _set(self, "routers", MappingProxyType(routers))

    def router(self, router_id: str) -> RouterSettings:
        """Settings of a router; a router without an entry is in Observe."""
        return self.routers.get(router_id) or RouterSettings()

    @classmethod
    def from_dict(cls, data: Any) -> HealSettings:
        """From :meth:`to_dict`; absent fields take the defaults."""
        return _build(cls, data or {}, cls._what)


@dataclass(frozen=True, kw_only=True, slots=True)
class MaintenanceWindow(_Record):
    """An interface or service maintenance scope (manual or scheduled)."""

    _what = "maintenance"
    window_id: str
    scope: MaintenanceScope
    router_id: str
    target: str
    start: float
    end: float | None
    reason: str
    created_by: Actor

    def __post_init__(self) -> None:
        """Validate (only an admin or the engine creates one)."""
        _set(
            self,
            "window_id",
            _id(self.window_id, MAINTENANCE_ID_PREFIX, "maintenance.window_id"),
        )
        _set(self, "scope", _enum(MaintenanceScope, self.scope, "maintenance.scope"))
        _set(
            self,
            "router_id",
            _id(self.router_id, ROUTER_ID_PREFIX, "maintenance.router_id"),
        )
        _set(self, "target", _token(self.target, "maintenance.target"))
        _set(self, "start", _ts(self.start, "maintenance.start"))
        _set(self, "end", _opt_ts(self.end, "maintenance.end"))
        if self.end is not None and self.end < self.start:
            _fail("maintenance.end")
        _set(self, "reason", _code(self.reason, "maintenance.reason"))
        who = _enum(Actor, self.created_by, "maintenance.created_by")
        if who is Actor.RECOVERY:
            _fail("maintenance.created_by")
        _set(self, "created_by", who)

    def covers(self, now: float) -> bool:
        """The window covers the time ``now``."""
        return self.start <= now and (self.end is None or now <= self.end)

    def active(self, now: float, safe_now: float | None = None) -> bool:
        """The window covers the wall time ``now`` or the safety-clock time
        ``safe_now``: a clock jump can only make maintenance count longer
        (an alarm in maintenance is held back, never acted on)."""
        return self.covers(now) or (safe_now is not None and self.covers(safe_now))


__all__ = [
    "IN_FLIGHT_STATES",
    "LOCKING_STATES",
    "PLANNING_STATES",
    "TERMINAL_STATES",
    "TRANSITIONS",
    "WRITE_AHEAD_STATES",
    "ActionState",
    "Actor",
    "ActorNotAllowedError",
    "HealModelError",
    "HealSettings",
    "HoldReason",
    "IllegalTransitionError",
    "LockRecord",
    "LoopState",
    "PreconditionFailedError",
    "RemediationAction",
    "RouterHold",
    "SafetyClock",
    "TerminalStateError",
    "TransitionError",
    "allowed_targets",
    "apply_restart_recovery",
    "can_transition",
    "component_dedupe_id",
    "hold_reason_for",
    "incident_dedupe_id",
    "restart_recovery",
    "transition",
]
