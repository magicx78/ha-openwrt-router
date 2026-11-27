"""Self-Healing: the Preflight Safety Engine (package E).

Developer document: ``docs/self-healing.md`` §6 (the safety chain) and §7.1
(the checks). Release 1.53.0 executes nothing: the preflight is used
read-only to show "what would block". Nothing here calls a router.

Two parts in one module:

* **The pure core** (no Home Assistant import at module level, no clock
  read, no router call): :func:`run_preflight` runs the thirteen checks of
  :data:`PREFLIGHT_CHECK_IDS` (order §8, in that order) for a catalog action
  over a :class:`PreflightFacts` snapshot and returns a
  :class:`PreflightResult`. Every check reports ``pass``, ``fail``,
  ``unknown`` or ``not_applicable``, whether it is critical for this action,
  a reason code and the facts it used. An unknown fact never passes a
  critical check; any failed or unknown critical check blocks.
* **The collector** (:func:`collect_preflight_facts`,
  :func:`facts_from_sources`): builds the snapshot ONLY from data the
  integration already holds in memory after a poll (coordinator data, the
  core's Router Registry, version index and lock, Network Intelligence,
  the Security Center, the diagnostics module, the self-healing store). It
  triggers no poll, no refresh, no router call, no executor job and no
  Configuration Manager fetch. Every fact carries its source and age; what
  cannot be read today is unknown with a reason, never guessed. Modules
  bound to Home Assistant are imported inside the collector only.

**A result cannot be made green by a caller** (the discipline of
``heal_policy.gate``): :class:`PreflightResult` takes the facts, the action
and the optional approval record - never a verdict. Every derived field
(checks, verdict, fingerprint, validity window) is ``init=False`` and
computed in ``__post_init__``; ``dataclasses.replace`` can only swap inputs,
which runs the checks again. The action is validated against the closed
catalog again (``heal_catalog.try_validate``). :meth:`PreflightResult.validity`
recomputes everything from the stored facts before it says ``valid``, so a
derived field changed behind the frozen dataclass's back is caught
(``tampered``). There is no secret: only INCONSISTENT edits are caught; an
edit of inputs and derived fields alike is not (docs §7.1, with the
obligations of the package that wires this in, C2).

**Binding.** A result is bound to (router id, action type, params) and to
the safety-clock time of its facts (``heal_model.SafetyClock``); it is valid
only for ``PreflightLimits.valid_for_s`` seconds of safety time (default
120 s, 10-300 s). A wall-clock jump does not move the safety clock while HA
runs (docs §5.2), so it cannot extend a result. The state fingerprint
(sha256 over the facts that matter: no ages, no percentages, no client
counts, no addresses, no secrets) is what an approval is bound to; a change
of any relevant fact changes it, and the approval no longer matches.

**Policy facts.** :func:`risk_context_for` and :func:`incident_facts_for`
build ``heal_policy.RiskContext`` / ``IncidentFacts`` from the same
snapshot for the adapter package (the engine's ``DecisionContext`` lacks
them today).
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
from .const import RAM_AVAILABLE_MIN_BYTES, RAM_PRESSURE_HIGH_PCT
from .core_models import (
    APPROVAL_TTL,
    ROUTER_ID_PREFIX,
    is_valid_id,
    primary_identity_status,
)
from .heal_model import (
    CLOCK_BACK_TOLERANCE_S,
    FLEET_CONCURRENCY_DEFAULT,
    LOCKING_STATES,
    PLANNING_STATES,
    ROUTER_COMPONENT,
    TERMINAL_STATES,
    TIME_MAX,
    ActionState,
    ApprovalStatus,
    CauseLevel,
    CauseStatus,
    Check,
    CheckOutcome,
    ComponentKind,
    HealMode,
    LockHolder,
    RemediationAction,
    RiskClass,
    binding_hash,
    canonical_sha256,
    component_ref,
)
from .heal_policy import ROLES, SEVERITIES, IncidentFacts, RiskContext, TargetFact

_LOGGER = logging.getLogger(__name__)

# The thirteen checks of order §8, in that order. Package F (playbooks)
# refers to them by these names.
PREFLIGHT_CHECK_IDS: Final = (
    "router_reachable",
    "identity_unique",
    "action_supported",
    "permissions_present",
    "no_concurrent_repair",
    "maintenance_window_ok",
    "no_critical_state",
    "management_path_available",
    "components_known",
    "config_captured",
    "backup_present",
    "recovery_path_checked",
    "approval_valid",
)

# A result is valid for this long on the safety clock (configurable, only
# within these bounds: the preflight must be fresh at the last step).
VALID_FOR_DEFAULT_S: Final = 120
VALID_FOR_BOUNDS_S: Final = (10, 300)
# Poll data older than this many poll intervals is stale (unknown).
STALE_POLLS: Final = 2
# A router up for less than this is still settling after a (re)boot.
RECENT_REBOOT_DEFAULT_S: Final = 600
RECENT_REBOOT_BOUNDS_S: Final = (300, 3600)
# Run queue above the cores (the coordinator's throttling threshold).
CPU_OVERLOAD_PCT: Final = 100.0
# A snapshot or backup older than this is not "current".
SNAPSHOT_MAX_AGE_S: Final = 86400
# An approval of the Guard lives at most this long (core APPROVAL_TTL);
# an expiry further away is implausible (a wall clock set back, a forgery).
APPROVAL_TTL_MAX_S: Final = int(APPROVAL_TTL.total_seconds())

# Actions that change the router's configuration: they need a captured
# configuration and a validated backup, and their recovery is a restore.
# DECIDED (E): only ``config.restore`` in catalog v1.
CONFIG_CHANGING: Final = frozenset({"config.restore"})
# Actions that APPLY the saved configuration of their component: a service
# restart loads what is saved, so a saved change that is not running yet
# would go live with it. ``config_captured`` asks for the fact
# ``service_config_unapplied`` there (unknown until package G tracks the
# drift: unknown blocks). DECIDED (E, review of PR #80): only
# ``service.restart``; ``router.reboot`` applies all saved configuration too,
# but it is blocked by ``no_recovery_mechanism`` in catalog v1.
CONFIG_APPLYING: Final = frozenset({"service.restart"})

# The one state a record is in when its execution starts (APPROVED ->
# EXECUTING): an approval counts only on a record in that state.
EXECUTION_START_STATE: Final = ActionState.APPROVED
# incident families beyond this are clamped (``IncidentFacts`` bound)
_FAMILIES_MAX: Final = 64

# Core capabilities an action needs (``core_models.Capability`` values).
# Writes go over ubus only (never SSH); a restore needs the provider.
ACTION_CAPABILITIES: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "observe.evaluate": (),
        "diag.refresh": ("transport.ubus",),
        "diag.ha_probes": (),
        "service.restart": ("transport.ubus", "data.services"),
        "wifi.radio_restart": ("transport.ubus", "data.wireless"),
        "router.reboot": ("transport.ubus",),
        "config.restore": ("config.restore",),
        "interface.cycle": ("transport.ubus",),
    }
)
# Every capability the collector reads (the union of the above).
CAPABILITIES_READ: Final = tuple(
    sorted({c for caps in ACTION_CAPABILITIES.values() for c in caps})
)
_RESTORE_CAPABILITY: Final = "config.restore"

# Router-call objects/methods the catalog names (``rc/init`` ...), as the
# api's ACL-blocked cache would hold them.
ACL_METHODS: Final = tuple(
    sorted({m for e in hc.CATALOG.values() for m in e.required_acl if "/" in m})
)
_POLL_READS: Final = "existing_poll_reads"

RUN_PATHS: Final = ("auto", "approval", "observe")
LOCK_HOLDERS: Final = ("none", "engine", "external")

_CODE_RE: Final = re.compile(r"[a-z][a-z0-9_.:|/-]{0,95}")
_VALUE_RE: Final = re.compile(r"[A-Za-z0-9_.:|/-]{0,96}")
# Defence in depth: no fact value may look like an address.
_IPV4_RE: Final = re.compile(r"\d{1,3}(\.\d{1,3}){3}")
_MAC_RE: Final = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
_TUPLE_MAX: Final = 64


class PreflightError(ValueError):
    """Bad input to the preflight (the message names the field, never a value)."""


def _fail(what: str) -> PreflightError:
    return PreflightError(f"invalid {what}")


class CheckStatus(StrEnum):
    """Outcome of one check."""

    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class Verdict(StrEnum):
    """The overall verdict of one preflight."""

    CLEAR = "clear"  # every critical check passed
    BLOCKED = "blocked"  # a critical check failed or is unknown


class Validity(StrEnum):
    """Can this result be used now for this action? (:meth:`validity`)"""

    VALID = "valid"
    BLOCKED = "blocked"
    EXPIRED = "expired"
    NOT_YET = "not_yet"  # a safety time before the facts: refused
    OTHER_ROUTER = "other_router"
    OTHER_ACTION = "other_action"
    TAMPERED = "tampered"


# ---------------------------------------------------------------------------
# Facts
# ---------------------------------------------------------------------------


def _check_text(value: str, what: str) -> str:
    if _VALUE_RE.fullmatch(value) is None:
        raise _fail(what)
    if _IPV4_RE.search(value) or _MAC_RE.search(value) or "::" in value:
        raise _fail(what)
    return value


def _readable_code(value: Any) -> bool:
    """``value`` can be a code fact value (the collector's own check, so it
    reports unknown instead of raising in ``Fact``)."""
    return (
        isinstance(value, str)
        and _CODE_RE.fullmatch(value) is not None
        and _IPV4_RE.search(value) is None
        and _MAC_RE.search(value) is None
        and "::" not in value
    )


def _plain_value(value: Any, what: str, depth: int = 0) -> Any:
    """A fact value: bool, int, finite float, a short code, or tuples of them."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise _fail(what)
        return int(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _fail(what)
        return value
    if isinstance(value, str):
        return _check_text(str(value), what)
    if isinstance(value, list | tuple) and depth < 2 and len(value) <= _TUPLE_MAX:
        return tuple(_plain_value(v, what, depth + 1) for v in value)
    raise _fail(what)


@dataclass(frozen=True, kw_only=True, slots=True)
class Fact:
    """One fact with its source and age; ``value`` None means unknown.

    ``source``: where it was read (a code, e.g. ``coordinator.data.services``).
    ``age_s``: seconds since the source last changed it (None: not stamped).
    ``reason``: why it is unknown (required then), a code.
    """

    value: Any = None
    source: str = "none"
    age_s: float | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        """Validate (codes only; no address can be a value)."""
        object.__setattr__(self, "value", _plain_value(self.value, "fact.value"))
        if not isinstance(self.source, str) or _CODE_RE.fullmatch(self.source) is None:
            raise _fail("fact.source")
        if self.age_s is not None:
            if (
                isinstance(self.age_s, bool)
                or not isinstance(self.age_s, int | float)
                or not math.isfinite(self.age_s)
            ):
                raise _fail("fact.age_s")
            object.__setattr__(self, "age_s", float(self.age_s))
        if self.reason is not None and (
            not isinstance(self.reason, str) or _CODE_RE.fullmatch(self.reason) is None
        ):
            raise _fail("fact.reason")
        if self.value is None and self.reason is None:
            raise _fail("fact.reason")

    @property
    def known(self) -> bool:
        """The value is known."""
        return self.value is not None

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        value = self.value
        if isinstance(value, tuple):
            value = [list(v) if isinstance(v, tuple) else v for v in value]
        return {
            "value": value,
            "source": self.source,
            "age_s": None if self.age_s is None else round(self.age_s, 1),
            "reason": self.reason,
        }


def known(value: Any, source: str, age_s: float | None = None) -> Fact:
    """A known fact (``value`` must not be None)."""
    if value is None:
        raise _fail("fact.value")
    return Fact(value=value, source=source, age_s=age_s)


def unknown(reason: str, source: str = "none") -> Fact:
    """An unknown fact with its reason."""
    return Fact(value=None, source=source, reason=reason)


_NOT_COLLECTED: Final = Fact(value=None, source="none", reason="not_collected")


def _nc() -> Fact:
    return _NOT_COLLECTED


# Shapes of the fact fields (validated in PreflightFacts).
_BOOL, _COUNT, _NUM, _CODE, _CODES = "bool", "count", "num", "code", "codes"
_SERVICES, _BACKUPS = "services", "backups"


@dataclass(frozen=True, kw_only=True, slots=True)
class PreflightFacts:
    """Everything the checks read about one router (a snapshot).

    ``router_id``: the core router id. ``safe_at``: the safety-clock time
    of the snapshot (the binding time of a result). ``wall_at``: the wall
    time of the snapshot (only to age wall-clock stamps of other modules,
    never to bind or expire anything of this module).
    """

    router_id: str
    safe_at: float
    wall_at: float
    # the last poll
    poll_ok: Fact = field(default_factory=_nc)
    poll_age_s: Fact = field(default_factory=_nc)
    poll_interval_s: Fact = field(default_factory=_nc)
    # the wall clock is behind the highest wall time the store has seen
    # (set back): wall-clock ages and the approval expiry cannot be trusted
    wall_clock_behind: Fact = field(default_factory=_nc)
    # Unified Router Identity (core registry)
    record_active: Fact = field(default_factory=_nc)
    identity_status: Fact = field(default_factory=_nc)
    identity_bindings: Fact = field(default_factory=_nc)
    role: Fact = field(default_factory=_nc)
    # capability detection: ((name, state), ...)
    capabilities: Fact = field(default_factory=_nc)
    # rights
    login_is_root: Fact = field(default_factory=_nc)
    acl_blocked: Fact = field(default_factory=_nc)
    # concurrency (self-healing store, core lock)
    lock_holder: Fact = field(default_factory=_nc)
    router_repairs: Fact = field(default_factory=_nc)
    fleet_repairs: Fact = field(default_factory=_nc)
    related_repairs: Fact = field(default_factory=_nc)
    held: Fact = field(default_factory=_nc)
    fleet_paused: Fact = field(default_factory=_nc)
    loop_blocks: Fact = field(default_factory=_nc)
    config_manager_busy: Fact = field(default_factory=_nc)
    # maintenance and the path the action would take
    ni_maintenance: Fact = field(default_factory=_nc)
    component_windows: Fact = field(default_factory=_nc)
    run_path: Fact = field(default_factory=_nc)
    # the router's state (coordinator)
    memory_pressure_pct: Fact = field(default_factory=_nc)
    memory_available_bytes: Fact = field(default_factory=_nc)
    cpu_load_pct: Fact = field(default_factory=_nc)
    uptime_s: Fact = field(default_factory=_nc)
    # other modules
    security_findings: Fact = field(default_factory=_nc)
    uplink_incidents: Fact = field(default_factory=_nc)
    degraded_dependants: Fact = field(default_factory=_nc)
    # topology (Network Intelligence's router tree)
    dependants: Fact = field(default_factory=_nc)
    upstream_hops: Fact = field(default_factory=_nc)
    wireless_uplink: Fact = field(default_factory=_nc)
    # components in the last poll: ((name, running, enabled), ...)
    services: Fact = field(default_factory=_nc)
    # the saved configuration of the action's service differs from the
    # running one (package G tracks the drift; unknown until then)
    service_config_unapplied: Fact = field(default_factory=_nc)
    radios: Fact = field(default_factory=_nc)
    interfaces: Fact = field(default_factory=_nc)
    # impact counts (lower bounds where noted)
    clients_on_router: Fact = field(default_factory=_nc)
    lease_routers: Fact = field(default_factory=_nc)
    lease_clients: Fact = field(default_factory=_nc)
    # Configuration Manager: ((backup_id, created_wall, status, validation,
    # has_checksum), ...), newest first
    backups: Fact = field(default_factory=_nc)
    diag_enabled: Fact = field(default_factory=_nc)
    # the root incident (only for the policy facts, no check reads them;
    # its type, status, severity and cause enter the fingerprint)
    incident_type: Fact = field(default_factory=_nc)
    incident_status: Fact = field(default_factory=_nc)
    incident_severity: Fact = field(default_factory=_nc)
    incident_confidence: Fact = field(default_factory=_nc)
    incident_is_root: Fact = field(default_factory=_nc)
    incident_cause_status: Fact = field(default_factory=_nc)
    incident_cause_level: Fact = field(default_factory=_nc)
    incident_families: Fact = field(default_factory=_nc)
    incident_fresh: Fact = field(default_factory=_nc)

    def __post_init__(self) -> None:
        """Validate every field (exact types; shapes per field)."""
        if not is_valid_id(self.router_id, ROUTER_ID_PREFIX):
            raise _fail("facts.router_id")
        for name in ("safe_at", "wall_at"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int | float)
                or not math.isfinite(value)
                or not 0 <= value <= TIME_MAX
            ):
                raise _fail(f"facts.{name}")
            object.__setattr__(self, name, float(value))
        for f in fields(self):
            if f.name in ("router_id", "safe_at", "wall_at"):
                continue
            fact = getattr(self, f.name)
            if type(fact) is not Fact:
                raise _fail(f"facts.{f.name}")
            _check_shape(f.name, fact.value)

    def fact_items(self) -> Iterable[tuple[str, Fact]]:
        """(name, fact) of every fact field."""
        for f in fields(self):
            if f.name not in ("router_id", "safe_at", "wall_at"):
                yield f.name, getattr(self, f.name)

    def to_dict(self) -> dict[str, Any]:
        """JSON form (codes, counts and core ids only)."""
        return {
            "router_id": self.router_id,
            "safe_at": self.safe_at,
            "facts": {name: fact.to_dict() for name, fact in self.fact_items()},
        }


_SHAPES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "poll_ok": _BOOL,
        "poll_age_s": _NUM,
        "poll_interval_s": _NUM,
        "wall_clock_behind": _BOOL,
        "record_active": _BOOL,
        "identity_status": _CODE,
        "identity_bindings": _COUNT,
        "role": _CODE,
        "capabilities": "pairs",
        "login_is_root": _BOOL,
        "acl_blocked": _CODES,
        "lock_holder": _CODE,
        "router_repairs": _COUNT,
        "fleet_repairs": _COUNT,
        "related_repairs": _COUNT,
        "held": _BOOL,
        "fleet_paused": _BOOL,
        "loop_blocks": _CODES,
        "config_manager_busy": _BOOL,
        "ni_maintenance": _BOOL,
        "component_windows": _CODES,
        "run_path": _CODE,
        "memory_pressure_pct": _NUM,
        "memory_available_bytes": _COUNT,
        "cpu_load_pct": _NUM,
        "uptime_s": _COUNT,
        "security_findings": _COUNT,
        "uplink_incidents": _COUNT,
        "degraded_dependants": _COUNT,
        "dependants": _COUNT,
        "upstream_hops": _COUNT,
        "wireless_uplink": _BOOL,
        "services": _SERVICES,
        "service_config_unapplied": _BOOL,
        "radios": _CODES,
        "interfaces": _CODES,
        "clients_on_router": _COUNT,
        "lease_routers": _COUNT,
        "lease_clients": _COUNT,
        "backups": _BACKUPS,
        "diag_enabled": _BOOL,
        "incident_type": _CODE,
        "incident_status": _CODE,
        "incident_severity": _CODE,
        "incident_confidence": _NUM,
        "incident_is_root": _BOOL,
        "incident_cause_status": _CODE,
        "incident_cause_level": _CODE,
        "incident_families": _COUNT,
        "incident_fresh": _BOOL,
    }
)

# Facts that change all the time; the fingerprint takes the derived
# threshold flags instead (``_fingerprint_view``: poll freshness, which also
# reads ``wall_clock_behind``, memory, CPU, recent reboot). The routers
# holding a lease (``lease_routers``) and the incident's type, status,
# severity and cause DO enter it (review of PR #80): a new dependant router
# or a resolved incident is another state than the one approved.
VOLATILE_FACTS: Final = frozenset(
    {
        "poll_age_s",
        "poll_interval_s",
        "wall_clock_behind",
        "memory_pressure_pct",
        "memory_available_bytes",
        "cpu_load_pct",
        "uptime_s",
        "clients_on_router",
        "lease_clients",
        "incident_confidence",
        "incident_families",
        "incident_fresh",
    }
)
FINGERPRINT_FACTS: Final = tuple(n for n in _SHAPES if n not in VOLATILE_FACTS)


def _check_shape(name: str, value: Any) -> None:
    """``value`` (already plain) has the shape of field ``name``."""
    if value is None:
        return
    shape = _SHAPES[name]
    what = f"facts.{name}"
    ok = True
    if shape == _BOOL:
        ok = isinstance(value, bool)
    elif shape == _COUNT:
        ok = isinstance(value, int) and not isinstance(value, bool) and value >= 0
    elif shape == _NUM:
        ok = isinstance(value, int | float) and not isinstance(value, bool)
    elif shape == _CODE:
        ok = isinstance(value, str) and _CODE_RE.fullmatch(value) is not None
    elif shape == _CODES:
        ok = isinstance(value, tuple) and all(
            isinstance(v, str) and _CODE_RE.fullmatch(v) for v in value
        )
    elif shape == "pairs":
        ok = isinstance(value, tuple) and all(
            isinstance(v, tuple)
            and len(v) == 2
            and all(isinstance(x, str) and _CODE_RE.fullmatch(x) for x in v)
            for v in value
        )
    elif shape == _SERVICES:
        ok = isinstance(value, tuple) and all(
            isinstance(v, tuple)
            and len(v) == 3
            and isinstance(v[0], str)
            and _CODE_RE.fullmatch(v[0]) is not None
            and isinstance(v[1], bool)
            and (v[2] is None or isinstance(v[2], bool))
            for v in value
        )
    elif shape == _BACKUPS:
        ok = isinstance(value, tuple) and all(
            isinstance(v, tuple)
            and len(v) == 5
            and isinstance(v[0], str)
            and is_valid_id(v[0], hc.BACKUP_ID_PREFIX)
            and isinstance(v[1], int | float)
            and not isinstance(v[1], bool)
            and isinstance(v[2], str)
            and isinstance(v[3], str)
            and isinstance(v[4], bool)
            for v in value
        )
    if not ok:
        raise _fail(what)


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class PreflightLimits:
    """How long a result is valid, when a router counts as just rebooted."""

    valid_for_s: int = VALID_FOR_DEFAULT_S
    recent_reboot_s: int = RECENT_REBOOT_DEFAULT_S

    def __post_init__(self) -> None:
        """Validate against the bounds."""
        problem = _limits_problem(self, shared=False)
        if problem is not None:
            raise _fail(f"limits.{problem}")


def _limits_problem(limits: Any, *, shared: bool = True) -> str | None:
    """The first field of ``limits`` outside its bounds (None: all sound).

    Run again by every :class:`PreflightResult` and by its tamper check,
    because a frozen dataclass can still be changed behind its back.
    ``shared``: also hold the module's default instance to the defaults."""
    for name, (lo, hi) in (
        ("valid_for_s", VALID_FOR_BOUNDS_S),
        ("recent_reboot_s", RECENT_REBOOT_BOUNDS_S),
    ):
        value = getattr(limits, name, None)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not lo <= value <= hi
        ):
            return name
    if (
        shared
        and limits is DEFAULT_PREFLIGHT_LIMITS
        and (
            limits.valid_for_s != VALID_FOR_DEFAULT_S
            or limits.recent_reboot_s != RECENT_REBOOT_DEFAULT_S
        )
    ):
        # the shared default instance changed in place
        return "default"
    return None


DEFAULT_PREFLIGHT_LIMITS: Final = PreflightLimits()


# ---------------------------------------------------------------------------
# One check
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class CheckResult:
    """The result of one check (codes only)."""

    check: str
    status: CheckStatus
    critical: bool
    reason: str
    detail: tuple[str, ...] = ()
    facts_used: tuple[str, ...] = ()

    @property
    def blocks(self) -> bool:
        """A critical check that did not pass blocks (unknown never passes)."""
        return self.critical and self.status in (CheckStatus.FAIL, CheckStatus.UNKNOWN)

    def to_dict(self) -> dict[str, Any]:
        """JSON form."""
        return {
            "check": self.check,
            "status": self.status.value,
            "critical": self.critical,
            "blocks": self.blocks,
            "reason": self.reason,
            "detail": list(self.detail),
            "facts_used": list(self.facts_used),
        }

    def to_model(self) -> Check:
        """The model's ``Check`` (pass/fail/unknown).

        DECIDED (E, review of PR #80): ``heal_model.CheckOutcome`` has no
        ``not_applicable`` and this package does not change the model, so a
        not-applicable check has NO model form: it is never stored as a
        pass. :meth:`PreflightResult.to_model_checks` leaves it out and
        :attr:`PreflightResult.not_applicable` names it. Raises
        :class:`PreflightError` for such a check.
        """
        if self.status is CheckStatus.NOT_APPLICABLE:
            raise PreflightError(f"{self.check} is not_applicable: no model outcome")
        return Check(
            check=self.check,
            outcome=CheckOutcome(self.status.value),
            reason=self.reason,
        )


class _Ctx:
    """What every check reads (built once per run)."""

    __slots__ = ("approval", "entry", "f", "fingerprint", "limits", "va")

    def __init__(
        self,
        f: PreflightFacts,
        va: hc.ValidatedAction | None,
        limits: PreflightLimits,
        approval: RemediationAction | None,
        fingerprint: str,
    ) -> None:
        self.f = f
        self.va = va
        self.entry = va.entry if va is not None else None
        self.limits = limits
        self.approval = approval
        self.fingerprint = fingerprint


def _res(
    check: str,
    status: CheckStatus,
    critical: bool,
    reason: str,
    used: Iterable[str] = (),
    detail: Iterable[str] = (),
) -> CheckResult:
    return CheckResult(
        check=check,
        status=status,
        critical=critical,
        reason=reason,
        detail=tuple(dict.fromkeys(detail)),
        facts_used=tuple(dict.fromkeys(used)),
    )


def _na(check: str, reason: str, used: Iterable[str] = ()) -> CheckResult:
    return _res(check, CheckStatus.NOT_APPLICABLE, False, reason, used)


class _Tally:
    """Collects fails and unknowns of one check; fails win."""

    def __init__(self) -> None:
        self.fails: list[str] = []
        self.unknowns: list[str] = []
        self.used: list[str] = []

    def use(self, *names: str) -> None:
        self.used.extend(names)

    def fail(self, code: str) -> None:
        self.fails.append(code)

    def unk(self, code: str) -> None:
        self.unknowns.append(code)

    def result(self, check: str, critical: bool, pass_reason: str) -> CheckResult:
        if self.fails:
            return _res(
                check,
                CheckStatus.FAIL,
                critical,
                self.fails[0],
                self.used,
                [*self.fails, *self.unknowns],
            )
        if self.unknowns:
            return _res(
                check,
                CheckStatus.UNKNOWN,
                critical,
                self.unknowns[0],
                self.used,
                self.unknowns,
            )
        return _res(check, CheckStatus.PASS, critical, pass_reason, self.used)


def _poll_fresh(f: PreflightFacts) -> tuple[bool | None, str]:
    """(fresh, reason): True only for a successful poll of known, small age.

    False: the last poll failed (a known fact). None: unknown or stale.
    """
    ok = f.poll_ok.value
    if ok is False:
        return False, "last_poll_failed"
    if ok is None:
        return None, f.poll_ok.reason or "poll_unknown"
    behind = f.wall_clock_behind.value
    if behind is True:
        # the age is wall time minus a wall stamp: with the wall clock set
        # back, stale data would look fresh
        return None, "wall_clock_set_back"
    if behind is None:
        return None, f.wall_clock_behind.reason or "wall_clock_unknown"
    age, interval = f.poll_age_s.value, f.poll_interval_s.value
    if age is None:
        return None, f.poll_age_s.reason or "poll_age_unknown"
    if interval is None or interval <= 0:
        return None, f.poll_interval_s.reason or "poll_interval_unknown"
    if age < 0:
        return None, "poll_time_ahead"
    if age > STALE_POLLS * interval:
        return None, "poll_stale"
    return True, "last_poll_ok"


_POLL_FACTS: Final = ("poll_ok", "poll_age_s", "poll_interval_s", "wall_clock_behind")


def _risk(ctx: _Ctx) -> RiskClass:
    return ctx.entry.base_risk if ctx.entry is not None else RiskClass.HIGH


def _writes(ctx: _Ctx) -> bool:
    return ctx.entry is None or ctx.entry.writes


# -- the thirteen checks ---------------------------------------------------------


def _c_router_reachable(ctx: _Ctx) -> CheckResult:
    cid = "router_reachable"
    e = ctx.entry
    if e is not None and e.router_call is None and not e.writes:
        return _na(cid, "no_router_call")
    fresh, reason = _poll_fresh(ctx.f)
    # DECIDED (E): critical for every action with a router call, also a
    # read (a refresh of a router that is down or stale proves nothing)
    critical = True
    if fresh is True:
        return _res(cid, CheckStatus.PASS, critical, reason, _POLL_FACTS)
    status = CheckStatus.FAIL if fresh is False else CheckStatus.UNKNOWN
    return _res(cid, status, critical, reason, _POLL_FACTS)


def _c_identity_unique(ctx: _Ctx) -> CheckResult:
    cid = "identity_unique"
    e = ctx.entry
    if e is not None and e.router_call is None and not e.writes:
        return _na(cid, "no_router_call")
    f, t = ctx.f, _Tally()
    t.use("record_active", "identity_status", "identity_bindings")
    if f.record_active.value is False:
        t.fail("record_not_active")
    elif f.record_active.value is None:
        t.unk(f.record_active.reason or "record_unknown")
    status = f.identity_status.value
    if status is None:
        t.unk(f.identity_status.reason or "identity_unknown")
    elif status != "confirmed":
        t.fail(
            f"identity_{status}" if status != "unverified" else "identity_unverified"
        )
    bindings = f.identity_bindings.value
    if bindings is None:
        t.unk(f.identity_bindings.reason or "bindings_unknown")
    elif bindings != 1:
        t.fail("identity_shared" if bindings > 1 else "identity_unbound")
    return t.result(cid, _writes(ctx), "identity_confirmed_unique")


def _caps(f: PreflightFacts) -> dict[str, str] | None:
    value = f.capabilities.value
    return None if value is None else dict(value)


def _c_action_supported(ctx: _Ctx) -> CheckResult:
    cid = "action_supported"
    e, f = ctx.entry, ctx.f
    if e is None:
        return _res(cid, CheckStatus.FAIL, True, "not_in_catalog")
    t = _Tally()
    if e.status is hc.CatalogStatus.DISABLED:
        t.fail("action_disabled")
        t.fail(e.status_reason or "disabled")
    if "diag_enabled" in e.needs_facts:
        t.use("diag_enabled")
        if f.diag_enabled.value is False:
            t.fail("diagnostics_off")
        elif f.diag_enabled.value is None:
            t.unk(f.diag_enabled.reason or "diagnostics_unknown")
    needed = ACTION_CAPABILITIES.get(e.action_type, ())
    if needed:
        t.use("capabilities")
        caps = _caps(f)
        for cap in needed:
            state = None if caps is None else caps.get(cap)
            if state == "available":
                continue
            if state == "unavailable":
                t.fail(f"capability_unavailable:{cap}")
            else:
                t.unk(f"capability_unknown:{cap}")
    return t.result(cid, True, "catalog_ready_capabilities_present")


def _c_permissions_present(ctx: _Ctx) -> CheckResult:
    cid = "permissions_present"
    e, f = ctx.entry, ctx.f
    if e is None:
        return _res(cid, CheckStatus.UNKNOWN, True, "not_in_catalog")
    if e.router_call is None and not e.writes:
        return _na(cid, "no_router_call")
    critical = e.writes
    if e.router_call is None:
        return _res(cid, CheckStatus.FAIL, critical, "no_router_method")
    if not e.required_acl and not e.writes:
        # runs on the Home Assistant side (diag.ha_probes): no router right
        return _na(cid, "no_router_rights_needed")
    t = _Tally()
    if e.required_acl == (_POLL_READS,):
        fresh, reason = _poll_fresh(f)
        t.use(*_POLL_FACTS)
        if fresh is True:
            return t.result(cid, critical, "poll_reads_work")
        if fresh is False:
            t.unk("poll_rights_not_shown")
        else:
            t.unk(reason)
        return t.result(cid, critical, "poll_reads_work")
    methods = [m for m in e.required_acl if "/" in m]
    t.use("acl_blocked")
    blocked = f.acl_blocked.value
    if blocked is None:
        t.unk(f.acl_blocked.reason or "acl_cache_unknown")
    elif any(m in blocked for m in methods):
        t.fail("method_acl_blocked")
    t.use("login_is_root")
    root = f.login_is_root.value
    if not e.acl_granted:
        # the integration's ACL file does not grant it: only a root login
        # (rpcd's default root ACL, assumed, never verified here) has it
        if root is False:
            t.fail("acl_does_not_grant")
        elif root is True:
            t.unk("root_rights_not_verified")
        else:
            t.unk(f.login_is_root.reason or "login_unknown")
    else:
        # granted by the ACL file of the integration (v8); whether that file
        # is deployed on this router is not held in memory
        t.unk("deployed_acl_not_verified")
    return t.result(cid, critical, "rights_verified")


def _component_refs(ctx: _Ctx) -> tuple[str, ...]:
    va = ctx.va
    if va is None:
        return ()
    comps = va.components or (ROUTER_COMPONENT,)
    return tuple(f"{va.action_type}|{component_ref(c)}" for c in comps)


def _c_no_concurrent_repair(ctx: _Ctx) -> CheckResult:
    cid = "no_concurrent_repair"
    f = ctx.f
    risk = _risk(ctx)
    if risk < RiskClass.LOW and not _writes(ctx):
        return _na(cid, "read_only_risk_0")
    t = _Tally()
    t.use("held", "fleet_paused")
    for name, code in (("held", "router_held"), ("fleet_paused", "fleet_paused")):
        value = getattr(f, name).value
        if value is True:
            t.fail(code)
        elif value is None:
            t.unk(getattr(f, name).reason or f"{name}_unknown")
    if _writes(ctx):
        t.use("lock_holder", "router_repairs", "related_repairs", "fleet_repairs")
        holder = f.lock_holder.value
        if holder == "engine":
            t.fail("repair_running")
        elif holder == "external":
            t.fail("external_write_running")
        elif holder is None:
            t.unk(f.lock_holder.reason or "lock_unknown")
        for name, code, limit in (
            ("router_repairs", "repair_running", 0),
            ("related_repairs", "repair_on_related_router", 0),
            (
                "fleet_repairs",
                "fleet_concurrency_reached",
                FLEET_CONCURRENCY_DEFAULT - 1,
            ),
        ):
            value = getattr(f, name).value
            if value is None:
                t.unk(getattr(f, name).reason or f"{name}_unknown")
            elif value > limit:
                t.fail(code)
        t.use("loop_blocks")
        blocks = f.loop_blocks.value
        if blocks is None:
            t.unk(f.loop_blocks.reason or "loop_state_unknown")
        else:
            refs = _component_refs(ctx)
            for row in blocks:
                key, _sep, why = row.rpartition("|")
                if key in refs:
                    t.fail(why or "loop_blocked")
    return t.result(cid, True, "no_other_repair")


def _windows_for(ctx: _Ctx) -> list[str]:
    """Maintenance windows of the store that cover the action's target."""
    rows = ctx.f.component_windows.value or ()
    e, va = ctx.entry, ctx.va
    if e is None or va is None:
        return list(rows)
    if e.disruption is hc.Disruption.ROUTER:
        return list(rows)  # a router-wide action touches every scope
    wanted = {f"{c.kind.value}:{c.name}" for c in va.components}
    return [r for r in rows if r in wanted]


def _c_maintenance_window_ok(ctx: _Ctx) -> CheckResult:
    cid = "maintenance_window_ok"
    f = ctx.f
    if _risk(ctx) < RiskClass.LOW and not _writes(ctx):
        return _na(cid, "read_only_risk_0")
    path = f.run_path.value
    # a window blocks Auto-Heal; for an approval (and in Observe, where
    # nothing runs) it is reported, not blocking. Unknown path: blocking.
    critical = path not in ("approval", "observe")
    t = _Tally()
    t.use("ni_maintenance", "component_windows", "run_path")
    if f.ni_maintenance.value is True:
        t.fail("in_maintenance")
    elif f.ni_maintenance.value is None:
        t.unk(f.ni_maintenance.reason or "maintenance_unknown")
    if f.component_windows.value is None:
        t.unk(f.component_windows.reason or "windows_unknown")
    elif _windows_for(ctx):
        t.fail("component_in_maintenance")
    if path is None:
        t.unk(f.run_path.reason or "run_path_unknown")
    return t.result(cid, critical, "no_maintenance")


def _c_no_critical_state(ctx: _Ctx) -> CheckResult:
    cid = "no_critical_state"
    f = ctx.f
    if not _writes(ctx):
        return _na(cid, "read_only")
    t = _Tally()
    fresh, reason = _poll_fresh(f)
    t.use(*_POLL_FACTS, "memory_pressure_pct", "memory_available_bytes")
    t.use("cpu_load_pct", "uptime_s")
    if fresh is not True:
        # the router's own state is only as good as the last good poll
        t.unk("router_state_unknown" if fresh is False else reason)
    else:
        pct, avail = f.memory_pressure_pct.value, f.memory_available_bytes.value
        if pct is None or avail is None:
            t.unk("memory_unknown")
        elif pct > RAM_PRESSURE_HIGH_PCT or avail < RAM_AVAILABLE_MIN_BYTES:
            t.fail("memory_pressure_high")
        cpu = f.cpu_load_pct.value
        if cpu is None:
            t.unk("cpu_load_unknown")
        elif cpu > CPU_OVERLOAD_PCT:
            t.fail("router_overloaded")
        up = f.uptime_s.value
        if up is None:
            t.unk("uptime_unknown")
        elif up < ctx.limits.recent_reboot_s:
            t.fail("recent_reboot")
    t.use("config_manager_busy")
    if f.config_manager_busy.value is True:
        t.fail("config_operation_running")
    elif f.config_manager_busy.value is None:
        t.unk(f.config_manager_busy.reason or "config_lock_unknown")
    for name, code in (
        ("security_findings", "open_security_finding"),
        ("uplink_incidents", "incident_on_uplink"),
        ("degraded_dependants", "dependants_degraded"),
    ):
        t.use(name)
        value = getattr(f, name).value
        if value is None:
            t.unk(getattr(f, name).reason or f"{name}_unknown")
        elif value > 0:
            t.fail(code)
    return t.result(cid, True, "no_dangerous_state")


def _c_management_path(ctx: _Ctx) -> CheckResult:
    cid = "management_path_available"
    e, f = ctx.entry, ctx.f
    if e is None:
        return _res(cid, CheckStatus.UNKNOWN, True, "not_in_catalog")
    d = e.disruption
    if d is hc.Disruption.NONE:
        return _na(cid, "no_disruption")
    critical = e.writes
    t = _Tally()
    t.use("dependants")
    deps = f.dependants.value
    if d is hc.Disruption.SERVICE:
        # dnsmasq/odhcpd restart: no link, route or address goes away; the
        # paths of HA and of the routers behind stay up (leases are kept).
        # That holds only for a path that is up now (a fresh poll) and a
        # known tree behind the router (review of PR #80: never a pass on
        # nothing).
        fresh, reason = _poll_fresh(f)
        t.use(*_POLL_FACTS)
        if fresh is False:
            t.fail("router_unreachable")
        elif fresh is None:
            t.unk(reason)
        if deps is None:
            t.unk(f.dependants.reason or "topology_unknown")
        return t.result(cid, critical, "service_restart_keeps_paths")
    if d is hc.Disruption.ROUTER:
        t.fail("cuts_own_management_path")
        if deps is None:
            t.unk(f.dependants.reason or "topology_unknown")
        elif deps > 0:
            t.fail("cuts_dependants_path")
        return t.result(cid, critical, "path_kept")
    if d is hc.Disruption.RADIO:
        t.use("wireless_uplink")
        wl = f.wireless_uplink.value
        if wl is True:
            t.fail("own_uplink_wireless")
        elif wl is None:
            t.unk(f.wireless_uplink.reason or "uplink_medium_unknown")
        if deps is None:
            t.unk(f.dependants.reason or "topology_unknown")
        elif deps > 0:
            t.unk("dependant_uplink_medium_unknown")
        return t.result(cid, critical, "radio_carries_no_path")
    # INTERFACE
    name = ctx.va.params.get("interface") if ctx.va is not None else None
    if name == "lan":
        t.fail("interface_carries_management_path")
    elif deps is None:
        t.unk(f.dependants.reason or "topology_unknown")
    else:
        t.unk("interface_path_unknown")
    return t.result(cid, critical, "interface_carries_no_path")


def _service_row(f: PreflightFacts, name: str) -> tuple[Any, ...] | None:
    for row in f.services.value or ():
        if row[0] == name:
            return row
    return None


def _c_components_known(ctx: _Ctx) -> CheckResult:
    cid = "components_known"
    e, f, va = ctx.entry, ctx.f, ctx.va
    if e is None or va is None:
        return _res(cid, CheckStatus.UNKNOWN, True, "not_in_catalog")
    if e.target_kind is None and not e.writes:
        return _na(cid, "no_component")
    critical = e.writes
    t = _Tally()
    kind = e.target_kind
    if kind in (ComponentKind.SERVICE, ComponentKind.RADIO, ComponentKind.INTERFACE):
        fresh, reason = _poll_fresh(f)
        t.use(*_POLL_FACTS)
        if fresh is not True:
            t.unk("component_state_unknown" if fresh is False else reason)
            return t.result(cid, critical, "component_known")
    if kind is ComponentKind.SERVICE:
        name = va.params["service"]
        t.use("services")
        if f.services.value is None:
            t.unk(f.services.reason or "services_unknown")
        else:
            row = _service_row(f, name)
            if row is None:
                t.unk("service_not_in_poll")
            elif row[2] is None:
                t.unk("service_enabled_unknown")
            elif row[2] is False:
                # "not running" is the intended state there: not broken
                t.fail("service_disabled_on_purpose")
        return t.result(cid, critical, "service_known_enabled")
    if kind is ComponentKind.RADIO:
        t.use("radios")
        radios = f.radios.value
        if radios is None:
            t.unk(f.radios.reason or "radios_unknown")
        elif va.params["radio"] not in radios:
            # the naming differs between the iwinfo and the UCI path
            t.unk("radio_not_identified")
        return t.result(cid, critical, "radio_known")
    if kind is ComponentKind.INTERFACE:
        t.use("interfaces")
        names = f.interfaces.value
        if names is None:
            t.unk(f.interfaces.reason or "interfaces_unknown")
        elif va.params["interface"] not in names:
            t.fail("interface_absent")
        return t.result(cid, critical, "interface_known")
    if kind is ComponentKind.CONFIG:
        t.use("backups")
        rows = f.backups.value
        if rows is None:
            t.unk(f.backups.reason or "versions_unknown")
        elif va.params["version_id"] not in {r[0] for r in rows}:
            t.fail("backup_not_found")
        return t.result(cid, critical, "version_known")
    # the router itself (reboot)
    t.use("record_active")
    if f.record_active.value is False:
        t.fail("record_not_active")
    elif f.record_active.value is None:
        t.unk(f.record_active.reason or "record_unknown")
    return t.result(cid, critical, "router_is_component")


def _backup_rows(f: PreflightFacts) -> list[tuple[Any, ...]] | None:
    rows = f.backups.value
    if rows is None:
        return None
    return sorted(rows, key=lambda r: (r[1], r[0]), reverse=True)


def _c_config_captured(ctx: _Ctx) -> CheckResult:
    cid = "config_captured"
    e, f = ctx.entry, ctx.f
    if e is not None and e.action_type in CONFIG_APPLYING:
        # the restart puts the saved configuration live: it must be the
        # running one (review of PR #80; the preflight does not lean on
        # the policy for this)
        t = _Tally()
        t.use("service_config_unapplied")
        drift = f.service_config_unapplied.value
        if drift is True:
            t.fail("saved_config_not_running")
        elif drift is None:
            t.unk(f.service_config_unapplied.reason or "config_drift_unknown")
        return t.result(cid, True, "saved_config_is_running")
    if e is not None and e.action_type not in CONFIG_CHANGING:
        return _na(cid, "action_changes_no_config")
    t = _Tally()
    t.use("backups")
    rows = _backup_rows(f)
    if rows is None:
        t.unk(f.backups.reason or "versions_unknown")
        return t.result(cid, True, "current_snapshot")
    usable = [r for r in rows if r[2] in ("ok", "partial")]
    if not usable:
        t.fail("no_snapshot")
    else:
        age = f.wall_at - usable[0][1]
        if age < 0:
            t.unk("snapshot_time_ahead")
        elif age > SNAPSHOT_MAX_AGE_S:
            t.fail("snapshot_outdated")
    return t.result(cid, True, "current_snapshot")


def _valid_backup(f: PreflightFacts) -> tuple[str, str | None]:
    """('pass'|'fail'|'unknown', code) for "a current VALIDATED backup"."""
    rows = _backup_rows(f)
    if rows is None:
        return "unknown", f.backups.reason or "versions_unknown"
    valid = [r for r in rows if r[2] == "ok" and r[3] == "valid" and r[4] is True]
    if not valid:
        if any(r[2] == "ok" and r[3] == "unverified" for r in rows):
            return "fail", "backup_not_validated"
        return "fail", "no_backup"
    age = f.wall_at - valid[0][1]
    if age < 0:
        return "unknown", "backup_time_ahead"
    if age > SNAPSHOT_MAX_AGE_S:
        return "fail", "backup_outdated"
    return "pass", None


def _c_backup_present(ctx: _Ctx) -> CheckResult:
    cid = "backup_present"
    e = ctx.entry
    if e is not None and e.action_type not in CONFIG_CHANGING:
        return _na(cid, "action_changes_no_config")
    state, code = _valid_backup(ctx.f)
    status = {"pass": CheckStatus.PASS, "fail": CheckStatus.FAIL}.get(
        state, CheckStatus.UNKNOWN
    )
    return _res(cid, status, True, code or "validated_backup", ("backups",))


def _c_recovery_path_checked(ctx: _Ctx, mgmt: CheckResult) -> CheckResult:
    cid = "recovery_path_checked"
    e, f = ctx.entry, ctx.f
    if e is None:
        return _res(cid, CheckStatus.UNKNOWN, True, "not_in_catalog")
    if not e.writes:
        return _na(cid, "read_only_nothing_changes")
    statement = e.rollback_statement
    if e.action_type in CONFIG_CHANGING:
        # "a backup exists" is not "can be restored": a restore is a dry
        # run today (no executor), so recovery would be manual
        t = _Tally()
        t.use("capabilities", "backups")
        state = (_caps(f) or {}).get(_RESTORE_CAPABILITY)
        backup, code = _valid_backup(f)
        if state != "available":
            t.fail("restore_unavailable_dry_run_only")
            if backup == "pass":
                t.fail("backup_present_not_restorable")
        elif backup != "pass":
            t.fail(code or "no_backup")
        return t.result(cid, True, "restore_verified")
    if e.base_risk >= RiskClass.HIGH:
        return _res(
            cid,
            CheckStatus.FAIL,
            True,
            "no_recovery_mechanism",
            detail=(statement,),
        )
    if e.rollback is hc.RollbackKind.SECOND_CALL:
        used = ("dependants", "wireless_uplink")
        if mgmt.status is CheckStatus.PASS:
            return _res(
                cid,
                CheckStatus.PASS,
                True,
                "second_call_while_path_holds",
                used,
                (statement,),
            )
        status = (
            CheckStatus.FAIL if mgmt.status is CheckStatus.FAIL else CheckStatus.UNKNOWN
        )
        return _res(cid, status, True, "second_call_needs_path", used, (statement,))
    # a service restart: no rollback; the honest statement is manual
    # recovery if the service does not come back (accepted for Risk 2 with
    # an approval, catalog v1). DECIDED (review of PR #80): that is a pass
    # only while the management path itself passed (someone can still get
    # in) AND a person approves; otherwise unknown.
    used = mgmt.facts_used
    if mgmt.status is CheckStatus.PASS and _needs_approval(ctx):
        return _res(
            cid, CheckStatus.PASS, True, "manual_recovery_statement", used, (statement,)
        )
    reason = (
        "manual_recovery_needs_approval"
        if mgmt.status is CheckStatus.PASS
        else "manual_recovery_needs_path"
    )
    return _res(cid, CheckStatus.UNKNOWN, True, reason, used, (statement,))


def _needs_approval(ctx: _Ctx) -> bool:
    e = ctx.entry
    if e is None:
        return True
    risk = e.base_risk
    if e.writes and risk >= RiskClass.MEDIUM:
        return True
    return risk >= RiskClass.LOW and ctx.f.run_path.value != "auto"


def expected_binding(record: RemediationAction, fingerprint: str) -> str:
    """The binding an approval of ``record`` must carry for ``fingerprint``."""
    return binding_hash(
        replace(record, state_fingerprint=fingerprint),
        catalog_version=hc.CATALOG_VERSION,
    )


def _c_approval_valid(ctx: _Ctx) -> CheckResult:
    cid = "approval_valid"
    if not _needs_approval(ctx):
        return _na(cid, "no_approval_needed", ("run_path",))

    used = ("wall_clock_behind",)

    def fail(code: str) -> CheckResult:
        return _res(cid, CheckStatus.FAIL, True, code, used)

    f = ctx.f
    rec = ctx.approval
    if rec is None:
        return fail("no_approval")
    va = ctx.va
    if (
        va is None
        or rec.router_id != f.router_id
        or rec.action_type != va.action_type
        or dict(rec.params) != dict(va.params)
    ):
        return fail("approval_for_other_action")
    if rec.state is not EXECUTION_START_STATE:
        # proposed, waiting, cancelled, failed, resolved ...: an approval on
        # such a record does not allow the execution to start
        return fail("approval_record_state")
    ap = rec.approval
    if ap.status is not ApprovalStatus.APPROVED:
        if ap.status is ApprovalStatus.EXPIRED:
            return fail("approval_expired")
        return fail("approval_not_granted")
    if ap.guard_approval_id is None:
        return fail("approval_not_from_guard")
    if ap.binding_hash is None or ap.binding_hash != expected_binding(
        rec, ctx.fingerprint
    ):
        return fail("approval_bound_to_other_state")
    if ap.expires_at is None:
        return fail("approval_without_expiry")
    # The expiry is a wall time and the record carries no safety time of
    # the decision (heal_model unchanged in E). So: no pass while the wall
    # clock is behind the highest wall time seen (set back), nor before the
    # decision itself; the remaining obligation is C2's (docs §7.1).
    behind = f.wall_clock_behind.value
    if behind is True:
        return fail("wall_clock_set_back")
    if behind is None:
        return _res(
            cid,
            CheckStatus.UNKNOWN,
            True,
            f.wall_clock_behind.reason or "wall_clock_unknown",
            used,
        )
    decided = _approved_at(rec)
    if decided is None or f.wall_at < decided - CLOCK_BACK_TOLERANCE_S:
        return fail("wall_clock_before_decision")
    left = ap.expires_at - f.wall_at
    if left <= 0:
        return fail("approval_expired")
    if left > APPROVAL_TTL_MAX_S or ap.expires_at - decided > APPROVAL_TTL_MAX_S:
        return fail("approval_expiry_implausible")
    return _res(cid, CheckStatus.PASS, True, "approval_bound_and_current", used)


def _approved_at(rec: RemediationAction) -> float | None:
    """Wall time of the record's last step into APPROVED (the decision)."""
    for entry in reversed(rec.history):
        if entry.to_state is ActionState.APPROVED:
            return entry.ts
    return None


# ---------------------------------------------------------------------------
# Fingerprint and the run
# ---------------------------------------------------------------------------


def _fingerprint_view(f: PreflightFacts, limits: PreflightLimits) -> dict[str, Any]:
    """The facts that matter, without ages, percentages and counts of
    clients: those enter only as their threshold flags."""
    view: dict[str, Any] = {"router_id": f.router_id}
    for name in FINGERPRINT_FACTS:
        view[name] = getattr(f, name).value
    fresh, _reason = _poll_fresh(f)
    view["poll_fresh"] = fresh
    pct, avail = f.memory_pressure_pct.value, f.memory_available_bytes.value
    view["memory_high"] = (
        None
        if pct is None or avail is None
        else (pct > RAM_PRESSURE_HIGH_PCT or avail < RAM_AVAILABLE_MIN_BYTES)
    )
    cpu = f.cpu_load_pct.value
    view["cpu_overloaded"] = None if cpu is None else cpu > CPU_OVERLOAD_PCT
    up = f.uptime_s.value
    view["recent_reboot"] = None if up is None else up < limits.recent_reboot_s
    return view


def state_fingerprint(
    facts: PreflightFacts, limits: PreflightLimits = DEFAULT_PREFLIGHT_LIMITS
) -> str:
    """sha256 over the facts that matter (no secrets, no addresses)."""
    if type(facts) is not PreflightFacts:
        raise _fail("facts")
    if type(limits) is not PreflightLimits:
        raise _fail("limits")
    return canonical_sha256(_fingerprint_view(facts, limits))


def _derive(
    facts: PreflightFacts,
    action_type: Any,
    params: Mapping[str, Any],
    approval: RemediationAction | None,
    limits: PreflightLimits,
) -> tuple[tuple[CheckResult, ...], str, hc.ValidatedAction | None, str | None]:
    """(checks, fingerprint, validated action, catalog refusal)."""
    va, refusal = hc.try_validate(action_type, params)
    fingerprint = state_fingerprint(facts, limits)
    ctx = _Ctx(facts, va, limits, approval, fingerprint)
    mgmt = _c_management_path(ctx)
    checks = (
        _c_router_reachable(ctx),
        _c_identity_unique(ctx),
        _c_action_supported(ctx),
        _c_permissions_present(ctx),
        _c_no_concurrent_repair(ctx),
        _c_maintenance_window_ok(ctx),
        _c_no_critical_state(ctx),
        mgmt,
        _c_components_known(ctx),
        _c_config_captured(ctx),
        _c_backup_present(ctx),
        _c_recovery_path_checked(ctx, mgmt),
        _c_approval_valid(ctx),
    )
    if refusal is not None:
        checks = tuple(
            replace(c, reason=refusal, detail=("not_in_catalog",))
            if c.check == "action_supported"
            else c
            for c in checks
        )
    return checks, fingerprint, va, refusal


def _frozen_params(params: Any) -> Mapping[str, Any]:
    """Read every value once into a read-only copy (like ``DecisionInput``)."""
    if params is None:
        return MappingProxyType({})
    if not isinstance(params, Mapping):
        return MappingProxyType({"__invalid__": True})
    return MappingProxyType(dict(list(params.items())))


@dataclass(frozen=True, kw_only=True, slots=True)
class PreflightResult:
    """The verdict of one preflight; computed, never handed in.

    Inputs: ``facts`` (exactly :class:`PreflightFacts`), ``action_type``,
    ``params`` (read once, frozen), ``approval`` (the record carrying the
    approval, or None) and ``limits`` (exactly :class:`PreflightLimits`).
    Everything else is derived in ``__post_init__`` and cannot be passed in
    or replaced.
    """

    facts: PreflightFacts
    action_type: Any
    params: Any = None
    approval: RemediationAction | None = None
    limits: PreflightLimits = DEFAULT_PREFLIGHT_LIMITS
    router_id: str = field(init=False)
    safe_at: float = field(init=False)
    valid_until: float = field(init=False)
    checks: tuple[CheckResult, ...] = field(init=False)
    verdict: Verdict = field(init=False)
    blocking: tuple[str, ...] = field(init=False)
    fingerprint: str = field(init=False)
    catalog_refusal: str | None = field(init=False)
    in_release: bool = field(init=False)
    executable_now: bool = field(init=False)
    # the validity span as validated at creation (the tamper check compares
    # the stored limits and ``valid_until`` with it)
    _valid_for_s: int = field(init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate the inputs and derive everything (raises PreflightError)."""
        if type(self.facts) is not PreflightFacts:
            raise _fail("facts")
        if type(self.limits) is not PreflightLimits:
            raise _fail("limits")
        problem = _limits_problem(self.limits)
        if problem is not None:
            raise _fail(f"limits.{problem}")
        if self.approval is not None and type(self.approval) is not RemediationAction:
            raise _fail("approval")
        set_ = object.__setattr__
        # an own, re-validated copy: a later change of the caller's object
        # does not reach this result
        set_(self, "facts", replace(self.facts))
        params = _frozen_params(self.params)
        set_(self, "params", params)
        checks, fingerprint, va, refusal = _derive(
            self.facts, self.action_type, params, self.approval, self.limits
        )
        blocking = tuple(c.check for c in checks if c.blocks)
        set_(self, "_valid_for_s", self.limits.valid_for_s)
        set_(self, "router_id", self.facts.router_id)
        set_(self, "safe_at", self.facts.safe_at)
        set_(self, "valid_until", self.facts.safe_at + self._valid_for_s)
        set_(self, "checks", checks)
        set_(self, "blocking", blocking)
        set_(self, "verdict", Verdict.BLOCKED if blocking else Verdict.CLEAR)
        set_(self, "fingerprint", fingerprint)
        set_(self, "catalog_refusal", refusal)
        in_release = va is not None and va.action_type in hc.EXECUTABLE_IN_RELEASE
        set_(self, "in_release", in_release)
        set_(self, "executable_now", in_release and not blocking)

    @property
    def clear(self) -> bool:
        """Every critical check passed (says nothing about the time)."""
        return self.verdict is Verdict.CLEAR

    def check(self, check_id: str) -> CheckResult:
        """One check by id (KeyError if unknown)."""
        for c in self.checks:
            if c.check == check_id:
                return c
        raise KeyError(check_id)

    @property
    def not_applicable(self) -> tuple[str, ...]:
        """Ids of the checks that do not apply to this action (they have no
        model form and are not in :meth:`to_model_checks`)."""
        return tuple(
            c.check for c in self.checks if c.status is CheckStatus.NOT_APPLICABLE
        )

    def _untampered(self) -> bool:
        """The derived fields are what the stored inputs give again.

        What this can and cannot catch (docs §7.1): there is no secret, so
        it catches INCONSISTENT edits only - a derived field that no longer
        follows from the stored inputs, limits outside their bounds, the
        shared default limits changed. An edit of the inputs together with
        every derived field (e.g. ``facts.safe_at``, ``safe_at`` and
        ``valid_until`` moved forward alike) is consistent and is not seen;
        the caller (package C2) collects and runs again right before the
        router call instead of trusting a stored result.
        """
        try:
            if type(self.facts) is not PreflightFacts:
                return False
            if type(self.limits) is not PreflightLimits:
                return False
            if _limits_problem(self.limits) is not None:
                return False
            checks, fingerprint, va, refusal = _derive(
                self.facts, self.action_type, self.params, self.approval, self.limits
            )
        except Exception:  # noqa: BLE001 - anything odd is tampering
            return False
        blocking = tuple(c.check for c in checks if c.blocks)
        in_release = va is not None and va.action_type in hc.EXECUTABLE_IN_RELEASE
        return (
            checks == self.checks
            and fingerprint == self.fingerprint
            and refusal == self.catalog_refusal
            and blocking == self.blocking
            and self.verdict is (Verdict.BLOCKED if blocking else Verdict.CLEAR)
            and self.in_release is in_release
            and self.executable_now is (in_release and not blocking)
            and self.router_id == self.facts.router_id
            and self.safe_at == self.facts.safe_at
            and self._valid_for_s == self.limits.valid_for_s
            and self.valid_until == self.facts.safe_at + self._valid_for_s
        )

    def validity(
        self, *, router_id: str, action_type: Any, params: Any, safe_now: float
    ) -> Validity:
        """May this result stand for (router, action, params) at safety time
        ``safe_now``? Re-derives everything first (``tampered``)."""
        if not self._untampered():
            return Validity.TAMPERED
        if router_id != self.router_id:
            return Validity.OTHER_ROUTER
        va, _refusal = hc.try_validate(action_type, params)
        if (
            va is None
            or self.catalog_refusal is not None
            or va.action_type != self.action_type
            or dict(va.params) != dict(self.params)
        ):
            return Validity.OTHER_ACTION
        if (
            isinstance(safe_now, bool)
            or not isinstance(safe_now, int | float)
            or not math.isfinite(safe_now)
        ):
            return Validity.EXPIRED
        if safe_now < self.safe_at:
            return Validity.NOT_YET
        if safe_now >= self.valid_until:
            return Validity.EXPIRED
        if self.verdict is not Verdict.CLEAR:
            return Validity.BLOCKED
        return Validity.VALID

    def to_model_checks(self) -> tuple[Check, ...]:
        """The record's ``preflight`` list: the checks that apply, in order.

        A not-applicable check is left out (never stored as a pass; see
        :meth:`CheckResult.to_model` and :attr:`not_applicable`)."""
        return tuple(
            c.to_model()
            for c in self.checks
            if c.status is not CheckStatus.NOT_APPLICABLE
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON form for a view: codes, counts and ids only."""
        return {
            "router_id": self.router_id,
            "action_type": self.action_type
            if isinstance(self.action_type, str)
            else None,
            "params": dict(self.params) if self.catalog_refusal is None else {},
            "verdict": self.verdict.value,
            "blocking": list(self.blocking),
            "checks": [c.to_dict() for c in self.checks],
            "not_applicable": list(self.not_applicable),
            "fingerprint": self.fingerprint,
            "safe_at": self.safe_at,
            "valid_until": self.valid_until,
            "in_release": self.in_release,
            "executable_now": self.executable_now,
            "catalog_refusal": self.catalog_refusal,
            "facts": self.facts.to_dict()["facts"],
        }


def run_preflight(
    facts: PreflightFacts,
    action_type: Any,
    params: Any = None,
    *,
    approval: RemediationAction | None = None,
    limits: PreflightLimits = DEFAULT_PREFLIGHT_LIMITS,
) -> PreflightResult:
    """All thirteen checks for ``action_type`` with ``params`` over ``facts``."""
    return PreflightResult(
        facts=facts,
        action_type=action_type,
        params=params,
        approval=approval,
        limits=limits,
    )


# ---------------------------------------------------------------------------
# Facts for the policy (package D's RiskContext / IncidentFacts)
# ---------------------------------------------------------------------------


def _component_window(f: PreflightFacts, va: hc.ValidatedAction) -> bool | None:
    rows = f.component_windows.value
    if rows is None:
        return None
    if va.entry.disruption is hc.Disruption.ROUTER:
        return bool(rows)
    wanted = {f"{c.kind.value}:{c.name}" for c in va.components}
    return any(r in wanted for r in rows)


def risk_context_for(
    facts: PreflightFacts, action_type: Any, params: Any
) -> RiskContext:
    """``heal_policy.RiskContext`` for this action from the snapshot.

    Every field the snapshot cannot tell stays None (unknown); the policy
    reads None as "not known", never as harmless. Raises
    ``heal_catalog.CatalogError`` for an action outside the catalog.
    """
    if type(facts) is not PreflightFacts:
        raise _fail("facts")
    va = hc.validate(action_type, params)
    f, e = facts, va.entry
    fresh, _reason = _poll_fresh(f)

    def polled(fact: Fact) -> Any:
        return fact.value if fresh is True else None

    role = f.role.value if f.role.value in ROLES else None
    status, bindings = f.identity_status.value, f.identity_bindings.value
    identity: bool | None = None
    if status is not None and bindings is not None:
        identity = status == "confirmed" and bindings == 1
    reachable: bool | None = (
        True if fresh is True else (False if fresh is False else None)
    )
    deps = f.dependants.value
    target_on_path = target_wl = target_carries = None
    if e.disruption is hc.Disruption.RADIO:
        wl = f.wireless_uplink.value
        target_on_path = False if wl is False and deps == 0 else None
        target_wl = False if wl is False else None
        target_carries = False if deps == 0 else None
    elif e.disruption is hc.Disruption.INTERFACE:
        target_on_path = True if va.params.get("interface") == "lan" else None
        target_carries = False if deps == 0 else None
    service_enabled = None
    lease_routers = lease_clients = None
    if e.disruption is hc.Disruption.SERVICE and fresh is True:
        row = _service_row(f, va.params["service"])
        service_enabled = None if row is None else row[2]
        # lower bounds from this router's DHCP leases; none seen is unknown
        # (a router or client with a static address is not visible)
        lr, lc = f.lease_routers.value, f.lease_clients.value
        lease_routers = lr if isinstance(lr, int) and lr > 0 else None
        lease_clients = lc if isinstance(lc, int) and lc > 0 else None
    window = _component_window(f, va)
    ni = f.ni_maintenance.value
    in_maint: bool | None = None
    if ni is True or window is True:
        in_maint = True
    elif ni is False and window is False:
        in_maint = False
    concurrent: bool | None = None
    parts = (
        f.lock_holder.value,
        f.router_repairs.value,
        f.related_repairs.value,
        f.fleet_repairs.value,
    )
    if all(p is not None for p in parts):
        concurrent = (
            parts[0] != "none"
            or parts[1] > 0
            or parts[2] > 0
            or parts[3] >= FLEET_CONCURRENCY_DEFAULT
        )
    breaker: bool | None = None
    if f.loop_blocks.value is not None:
        refs = {
            f"{va.action_type}|{component_ref(c)}"
            for c in (va.components or (ROUTER_COMPONENT,))
        }
        breaker = any(
            row.rpartition("|")[0] in refs and row.rpartition("|")[2] == "breaker_open"
            for row in f.loop_blocks.value
        )
    return RiskContext(
        role=role,
        identity_confirmed=identity,
        reachable=reachable,
        dependants=deps,
        target_on_mgmt_path=target_on_path,
        target_is_wireless_uplink=target_wl,
        target_carries_dependants=target_carries,
        service_enabled=service_enabled,
        service_dependant_routers=lease_routers,
        service_dependant_clients=lease_clients,
        # package G tracks the drift; the collector reports it unknown
        service_config_unapplied=f.service_config_unapplied.value
        if e.disruption is hc.Disruption.SERVICE
        else None,
        clients_on_router=polled(f.clients_on_router),
        clients_on_target=None,  # clients per radio are not mapped yet
        open_security_findings=f.security_findings.value,
        in_maintenance=in_maint,
        concurrent_repair=concurrent,
        breaker_open=breaker,
        diag_enabled=f.diag_enabled.value,
    )


def incident_facts_for(
    facts: PreflightFacts, action_type: Any = None, params: Any = None
) -> IncidentFacts | None:
    """``heal_policy.IncidentFacts`` of the snapshot's incident (None: none).

    ``temporal_only`` and ``cause_outside_router`` stay unknown (package F,
    the playbooks, decides them). ``target_fact`` is DIRECT only when the
    action's service is enabled and not running in a fresh poll.
    """
    if type(facts) is not PreflightFacts:
        raise _fail("facts")
    f = facts
    if f.incident_type.value is None:
        return None
    severity = (
        f.incident_severity.value if f.incident_severity.value in SEVERITIES else None
    )
    level = f.incident_cause_level.value
    status = f.incident_cause_status.value
    conf = f.incident_confidence.value
    if conf is not None and not 0.0 <= conf <= 1.0:
        conf = None
    target_fact: TargetFact | None = None
    va, _refusal = hc.try_validate(action_type, params)
    fresh, _reason = _poll_fresh(f)
    if (
        va is not None
        and va.entry.disruption is hc.Disruption.SERVICE
        and fresh is True
    ):
        row = _service_row(f, va.params["service"])
        if row is not None and row[2] is True and row[1] is False:
            target_fact = TargetFact.DIRECT
    return IncidentFacts(
        incident_type=f.incident_type.value,
        severity=severity,
        cause_level=CauseLevel(level)
        if level in CauseLevel._value2member_map_
        else CauseLevel.UNKNOWN,
        cause_status=CauseStatus(status)
        if status in CauseStatus._value2member_map_
        else CauseStatus.HYPOTHESIS,
        confidence=conf,
        # clamped to the model's bound instead of raising (review of PR #80)
        source_families=min(f.incident_families.value or 0, _FAMILIES_MAX),
        is_root=f.incident_is_root.value,
        temporal_only=None,
        evidence_fresh=f.incident_fresh.value,
        target_fact=target_fact,
        cause_outside_router=None,
    )


# ---------------------------------------------------------------------------
# The collector: memory only
# ---------------------------------------------------------------------------

# Record states that count as a repair in progress (past planning, open).
_REPAIR_STATES: Final = frozenset(
    s for s in ActionState if s not in PLANNING_STATES and s not in TERMINAL_STATES
) | {ActionState.PREFLIGHT}
_ACTIVE_STATES: Final = frozenset(LOCKING_STATES) | {ActionState.APPROVED}


@dataclass(frozen=True, kw_only=True, slots=True)
class FactSources:
    """The in-memory objects the collector reads (any may be None).

    ``store``: the ``SelfHealingStore``; ``coordinator`` / ``api``: the
    router entry's runtime data; ``registry``: the core's registry (read
    side); ``versions``: the core's version index (``records()``);
    ``config_locked``: the Configuration Manager's ``locked``; ``ni``:
    Network Intelligence; ``security``: the Security Center; ``diag``: the
    network diagnostics module; ``entry_id``: the router's entry id (only to
    look the router up in Network Intelligence, never put into a fact).
    """

    store: Any
    entry_id: str | None = None
    coordinator: Any = None
    api: Any = None
    registry: Any = None
    versions: Any = None
    config_locked: Callable[[str], bool] | None = None
    ni: Any = None
    security: Any = None
    diag: Any = None


def _value_of(raw: Any) -> Any:
    return getattr(raw, "value", raw)


def _safe_call(func: Callable[[], Any], source: str) -> tuple[Any, str | None]:
    """(value, None) or (None, reason) - reading never raises."""
    try:
        return func(), None
    except Exception as err:  # noqa: BLE001 - a broken source is "unknown"
        _LOGGER.debug("Preflight: %s not readable (%s)", source, type(err).__name__)
        return None, "source_error"


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


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


def _poll_facts(src: FactSources, wall: float) -> dict[str, Fact]:
    coord = src.coordinator
    out: dict[str, Fact] = {}
    s = "coordinator"
    if coord is None:
        for name in ("poll_ok", "poll_age_s", "poll_interval_s"):
            out[name] = unknown("router_not_loaded", s)
        return out
    ok = getattr(coord, "last_update_success", None)
    out["poll_ok"] = (
        known(ok, f"{s}.last_update_success")
        if isinstance(ok, bool)
        else unknown("poll_state_unknown", s)
    )
    data = getattr(coord, "data", None)
    last = _timestamp(getattr(data, "last_seen", None)) if data is not None else None
    if last is None:
        out["poll_age_s"] = unknown("no_successful_poll", f"{s}.data.last_seen")
    else:
        out["poll_age_s"] = known(wall - last, f"{s}.data.last_seen", 0.0)
    interval = getattr(coord, "update_interval", None)
    seconds = getattr(interval, "total_seconds", None)
    secs = _num(seconds()) if callable(seconds) else None
    out["poll_interval_s"] = (
        known(secs, f"{s}.update_interval")
        if secs is not None and secs > 0
        else unknown("interval_unknown", f"{s}.update_interval")
    )
    return out


def _clock_fact(store: Any, wall: float) -> Fact:
    """Is the wall clock behind the highest wall time the store observed?

    The store's safety clock keeps that mark (``SafetyClock.high``, never
    lowered). A wall time below it means the clock was set back: every age
    computed from wall stamps (the poll's ``last_seen``) and every wall
    expiry (an approval's ``expires_at``) cannot be trusted then."""
    s = "heal_store.loop.clock"
    clock = getattr(getattr(store, "loop", None), "clock", None)
    high = _num(getattr(clock, "high", None))
    if high is None:
        return unknown("safety_clock_unknown", s)
    return known(wall < high - CLOCK_BACK_TOLERANCE_S, s, 0.0)


def _router_state_facts(
    src: FactSources, fresh: bool | None, age: float | None, why: str
) -> dict[str, Fact]:
    """Facts from the last poll's data; unknown unless the poll is fresh."""
    names = _STATE_NAMES
    data = (
        getattr(src.coordinator, "data", None) if src.coordinator is not None else None
    )
    if fresh is not True or data is None:
        reason = "poll_failed" if fresh is False else why
        return {n: unknown(reason, "coordinator.data") for n in names}
    s = "coordinator.data"
    out: dict[str, Fact] = {}
    mp = getattr(data, "memory_pressure", None) or {}
    pct = _num(mp.get("pressure_pct")) if isinstance(mp, Mapping) else None
    avail = _count(mp.get("available_bytes")) if isinstance(mp, Mapping) else None
    out["memory_pressure_pct"] = (
        known(pct, f"{s}.memory_pressure", age)
        if pct is not None
        else unknown("memory_stats_missing", s)
    )
    out["memory_available_bytes"] = (
        known(avail, f"{s}.memory_pressure", age)
        if avail is not None
        else unknown("memory_stats_missing", s)
    )
    # cpu_load is 0.0 until a load average was read: without the raw load
    # average it is not a measurement
    cpu = _num(getattr(data, "cpu_load", None))
    has_load = bool(getattr(data, "load_average", None))
    out["cpu_load_pct"] = (
        known(cpu, f"{s}.cpu_load", age)
        if cpu is not None and has_load
        else unknown("cpu_load_not_measured", s)
    )
    up = _count(getattr(data, "uptime", None))
    out["uptime_s"] = (
        known(up, f"{s}.uptime", age) if up else unknown("uptime_missing", s)
    )
    rows: list[tuple[str, bool, bool | None]] = []
    services = getattr(data, "services", None)
    if isinstance(services, list) and services:
        for svc in services:
            if not isinstance(svc, Mapping):
                continue
            name = svc.get("name")
            if not _readable_code(name):
                continue
            enabled = svc.get("enabled")
            rows.append(
                (
                    name,
                    svc.get("running") is True,
                    enabled if isinstance(enabled, bool) else None,
                )
            )
        out["services"] = known(tuple(sorted(rows)), f"{s}.services", age)
    else:
        out["services"] = unknown("services_not_polled", f"{s}.services")
    radios = getattr(data, "wifi_radios", None)
    if isinstance(radios, list) and radios:
        names = sorted(
            {
                r.get("phy")
                for r in radios
                if isinstance(r, Mapping) and _readable_code(r.get("phy"))
            }
        )
        out["radios"] = known(tuple(names), f"{s}.wifi_radios.phy", age)
    else:
        out["radios"] = unknown("radios_not_polled", f"{s}.wifi_radios")
    ifaces = getattr(data, "network_interfaces", None)
    if isinstance(ifaces, list) and ifaces and not getattr(data, "vlans_stale", False):
        names = sorted(
            {
                i.get("logical_name")
                for i in ifaces
                if isinstance(i, Mapping) and _readable_code(i.get("logical_name"))
            }
        )
        out["interfaces"] = known(tuple(names), f"{s}.network_interfaces", age)
    else:
        out["interfaces"] = unknown("interfaces_not_polled", f"{s}.network_interfaces")
    clients = _count(getattr(data, "client_count", None))
    out["clients_on_router"] = (
        known(clients, f"{s}.client_count", age)
        if clients is not None
        else unknown("clients_unknown", s)
    )
    sta = getattr(data, "sta_interfaces", None)
    if isinstance(sta, list) and sta:
        active = any(
            isinstance(x, Mapping)
            and (
                str(x.get("mode") or "").strip().lower() == "mesh"
                or (str(x.get("bssid") or "").strip() and x.get("signal") is not None)
            )
            for x in sta
        )
        out["wireless_uplink"] = (
            known(True, f"{s}.sta_interfaces", age)
            if active
            else unknown("sta_present_not_associated", f"{s}.sta_interfaces")
        )
    else:
        # an empty list is "no STA" or "detection failed" (api docstring)
        out["wireless_uplink"] = unknown(
            "sta_detection_inconclusive", f"{s}.sta_interfaces"
        )
    return out


def _registry_facts(src: FactSources, router_id: str) -> tuple[dict[str, Fact], Any]:
    names = (
        "record_active",
        "identity_status",
        "identity_bindings",
        "role",
        "capabilities",
    )
    reg = src.registry
    if reg is None:
        return {n: unknown("core_not_running", "core.registry") for n in names}, None
    record, err = _safe_call(lambda: reg.find(router_id), "registry")
    if err or record is None:
        reason = err or "router_not_registered"
        return {n: unknown(reason, "core.registry") for n in names}, None
    s = "core.registry"
    out: dict[str, Fact] = {}
    state = _value_of(getattr(record, "state", None))
    out["record_active"] = (
        known(state == "active", f"{s}.state")
        if isinstance(state, str)
        else unknown("state_unknown", s)
    )
    identity = getattr(record, "identity", None)
    status: Any = None
    flags = getattr(identity, "identity_flags", None)
    if flags is not None:
        status, _err = _safe_call(
            lambda: primary_identity_status(flags).value, "identity_flags"
        )
    out["identity_status"] = (
        known(status, f"{s}.identity")
        if _readable_code(status)
        else unknown("identity_unknown", s)
    )
    role = _value_of(getattr(identity, "role", None))
    out["role"] = (
        known(role, f"{s}.identity.role")
        if role in ROLES
        else unknown("role_unknown", s)
    )
    entry_id = getattr(identity, "entry_id", None)
    records, err = _safe_call(lambda: tuple(reg.list()), "registry.list")
    if err or records is None:
        out["identity_bindings"] = unknown(err or "registry_list_unknown", s)
    else:
        n = sum(
            1
            for r in records
            if getattr(r, "router_id", None) == router_id
            or (
                entry_id is not None
                and getattr(getattr(r, "identity", None), "entry_id", None) == entry_id
            )
        )
        out["identity_bindings"] = known(n, f"{s}.list")
    caps = getattr(record, "capabilities", None)
    if isinstance(caps, Mapping):
        pairs = []
        for name in CAPABILITIES_READ:
            st = caps.get(name)
            value = _value_of(getattr(st, "state", None)) if st is not None else None
            pairs.append(
                (name, value if value in ("available", "unavailable") else "unknown")
            )
        out["capabilities"] = known(tuple(pairs), f"{s}.capabilities")
    else:
        out["capabilities"] = unknown("capabilities_unknown", s)
    return out, record


def _rights_facts(src: FactSources) -> dict[str, Fact]:
    api = src.api
    if api is None:
        return {
            "login_is_root": unknown("router_not_loaded", "api"),
            "acl_blocked": unknown("router_not_loaded", "api"),
        }
    out: dict[str, Fact] = {}
    # the attribute lookup is inside the guarded call too (review of PR #80)
    is_root, err = _safe_call(lambda: api.config_ssh_user_is_root(), "api.login")
    out["login_is_root"] = (
        known(is_root, "api.config_ssh_user_is_root")
        if isinstance(is_root, bool)
        else unknown(err or "login_unknown", "api")
    )
    # The api's cache of methods rpcd denied in this session (memory). api.py
    # has no public accessor (only ``reset_acl_blocked``); the private set is
    # read behind ``_safe_call`` and its shape is checked: a changed shape is
    # unknown, never "nothing blocked". A later package adds the accessor.
    hits, err = _safe_call(lambda: _acl_hits(api), "api.acl_blocked")
    out["acl_blocked"] = (
        known(hits, "api.acl_blocked_cache")
        if isinstance(hits, tuple)
        else unknown(err or hits or "acl_cache_unknown", "api")
    )
    return out


def _acl_hits(api: Any) -> tuple[str, ...] | str:
    """The catalog's methods in the api's ACL-blocked cache, or the reason
    code why it cannot be read (missing, or no longer the set of
    (object, method) string tuples)."""
    blocked = getattr(api, "_acl_blocked", None)
    if not isinstance(blocked, set | frozenset):
        return "acl_cache_unknown"
    entries = tuple(blocked)
    if not all(
        isinstance(x, tuple) and x and all(isinstance(p, str) for p in x)
        for x in entries
    ):
        return "acl_cache_shape_changed"
    keys = set(entries)
    return tuple(sorted(m for m in ACL_METHODS if tuple(m.split("/", 1)) in keys))


def _store_facts(
    src: FactSources,
    router_id: str,
    safe: float,
    wall: float,
    exclude_action_id: str | None,
    related: Iterable[str] | None,
) -> dict[str, Fact]:
    store = src.store
    s = "heal_store"
    loop = store.loop
    out: dict[str, Fact] = {}
    lock = loop.lock_holder(router_id)
    holder = (
        "none"
        if lock is None
        else ("engine" if lock.holder is LockHolder.ENGINE else "external")
    )
    out["lock_holder"] = known(holder, f"{s}.loop.locks", 0.0)
    others = [a for a in store.actions.values() if a.action_id != exclude_action_id]
    out["router_repairs"] = known(
        sum(
            1 for a in others if a.router_id == router_id and a.state in _REPAIR_STATES
        ),
        f"{s}.actions",
        0.0,
    )
    out["fleet_repairs"] = known(
        sum(1 for a in others if a.state in _ACTIVE_STATES), f"{s}.actions", 0.0
    )
    if related is None:
        out["related_repairs"] = unknown(
            "topology_unknown", "network_intelligence.topology"
        )
    else:
        rel = set(related)
        busy = {
            a.router_id
            for a in others
            if a.router_id in rel and a.state in _REPAIR_STATES
        } | {rid for rid in rel if loop.lock_holder(rid) is not None}
        out["related_repairs"] = known(len(busy), f"{s}.actions_and_locks", 0.0)
    out["held"] = known(
        loop.hold_on(router_id, safe) is not None, f"{s}.loop.holds", 0.0
    )
    out["fleet_paused"] = known(loop.fleet.paused(safe), f"{s}.loop.fleet", 0.0)
    blocks: list[str] = []
    keys = {k for k in (*loop.attempts, *loop.breakers) if k[0] == router_id}
    limits = store.settings.limits
    from .heal_policy import loop_verdict  # pure; local to keep the import list short

    for key in sorted(keys):
        verdict = loop_verdict(
            (key,),
            attempts=loop.attempts,
            breakers=loop.breakers,
            fleet=type(loop.fleet)(),  # the pause is its own fact
            limits=limits,
            safe_now=safe,
        )
        if not verdict.allowed and verdict.reason:
            blocks.append(f"{key[1]}|{key[2]}|{verdict.reason}")
    out["loop_blocks"] = known(tuple(blocks), f"{s}.loop", 0.0)
    out["component_windows"] = _window_fact(store, router_id, safe, wall)
    return out


def _window_fact(store: Any, router_id: str, safe: float, wall: float) -> Fact:
    """Active maintenance windows of the router as ``scope:target`` codes.

    The model accepts targets a code cannot hold (upper case, ``@``, an
    address shape). Such a row is skipped and the whole fact is unknown
    (``window_target_unreadable``): the window might cover the action's
    target, so "no window" would be a guess."""
    s = "heal_store.maintenance"
    rows: set[str] = set()
    for w in store.maintenance:
        if w.router_id != router_id or not w.active(wall, safe):
            continue
        text = f"{_value_of(w.scope)}:{w.target}"
        if not _readable_code(text):
            return unknown("window_target_unreadable", s)
        rows.add(text)
    if len(rows) > _TUPLE_MAX:
        return unknown("too_many_windows", s)
    return known(tuple(sorted(rows)), s, 0.0)


def _run_path(store: Any, router_id: str) -> Fact:
    try:
        mode = store.effective_mode(router_id)
    except Exception as err:  # noqa: BLE001
        _LOGGER.debug("Preflight: no mode (%s)", type(err).__name__)
        return unknown("mode_unknown", "heal_store.settings")
    path = {
        HealMode.AUTO_HEAL: "auto",
        HealMode.APPROVAL: "approval",
        HealMode.OBSERVE: "observe",
    }.get(mode)
    return (
        known(path, "heal_store.effective_mode", 0.0)
        if path
        else unknown("mode_unknown", "heal_store")
    )


def _ni_facts(
    src: FactSources, router_id: str, wall: float, rid_of: Callable[[str], str | None]
) -> tuple[dict[str, Fact], list[str] | None]:
    """Maintenance, topology and incidents of Network Intelligence."""
    names = (
        "ni_maintenance",
        "dependants",
        "upstream_hops",
        "uplink_incidents",
        "degraded_dependants",
    )
    ni, entry_id = src.ni, src.entry_id
    s = "network_intelligence"
    if ni is None or not getattr(ni, "loaded", False):
        return {n: unknown("ni_not_loaded", s) for n in names}, None
    if entry_id is None:
        return {n: unknown("entry_unknown", s) for n in names}, None
    out: dict[str, Fact] = {}
    last_now = _num(getattr(getattr(ni, "machine", None), "last_now", None))
    age = wall - last_now if last_now is not None and wall >= last_now else None
    maint, err = _safe_call(lambda: ni.in_maintenance(entry_id), "ni.maintenance")
    out["ni_maintenance"] = (
        known(maint, f"{s}.in_maintenance", age)
        if isinstance(maint, bool)
        else unknown(err or "maintenance_unknown", s)
    )
    topo, err = _safe_call(lambda: ni.topology, "ni.topology")
    gateways = getattr(topo, "gateways", None)
    uplinks = getattr(topo, "uplinks", None)
    related: list[str] | None = None
    if (
        topo is None
        or not isinstance(gateways, frozenset | set)
        or not isinstance(uplinks, Mapping)
        or not gateways
        or (entry_id not in gateways and entry_id not in uplinks)
    ):
        reason = err or "router_not_in_topology"
        for n in (
            "dependants",
            "upstream_hops",
            "uplink_incidents",
            "degraded_dependants",
        ):
            out[n] = unknown(reason, f"{s}.topology")
        return out, None
    # the tree walks are guarded too (review of PR #80): a walk that raises
    # or yields something else than entry ids leaves the topology unknown
    behind, err_b = _safe_call(lambda: _entry_ids(topo.behind(entry_id)), "ni.behind")
    chain, err_c = _safe_call(lambda: _entry_ids(topo.chain(entry_id)), "ni.chain")
    if behind is None or chain is None:
        reason = err_b or err_c or "topology_unreadable"
        for n in (
            "dependants",
            "upstream_hops",
            "uplink_incidents",
            "degraded_dependants",
        ):
            out[n] = unknown(reason, f"{s}.topology")
        return out, None
    out["dependants"] = known(len(behind), f"{s}.topology", age)
    out["upstream_hops"] = known(len(chain), f"{s}.topology", age)
    incidents, err = _safe_call(lambda: list(ni.machine.peek()), "ni.incidents")
    if incidents is None:
        out["uplink_incidents"] = unknown(err or "incidents_unknown", s)
        out["degraded_dependants"] = unknown(err or "incidents_unknown", s)
    else:
        active = [
            i
            for i in incidents
            if _value_of(getattr(i, "status", None)) == "active"
            and getattr(i, "parent_id", None) is None
        ]
        up = set(chain)
        out["uplink_incidents"] = known(
            sum(1 for i in active if up.intersection(getattr(i, "routers", ()) or ())),
            f"{s}.incidents",
            age,
        )
        down = set(behind)
        degraded = {
            r for i in active for r in (getattr(i, "routers", ()) or ()) if r in down
        }
        out["degraded_dependants"] = known(len(degraded), f"{s}.incidents", age)
    related = []
    for e in (*behind, *chain):
        rid = rid_of(e)
        if rid is None:
            return out, None  # a related router without id: unknown
        related.append(rid)
    return out, related


def _entry_ids(values: Any) -> list[str] | None:
    """A topology walk as a list of entry ids (None: something else)."""
    out = list(values)
    return out if all(isinstance(v, str) for v in out) else None


def _security_fact(src: FactSources, router_id: str) -> Fact:
    sc = src.security
    s = "security_center"
    if sc is None:
        return unknown("security_center_not_running", s)
    if getattr(sc, "enabled", None) is not True:
        # a module that is off does not say "nothing found"
        return unknown("security_center_off", s)
    if getattr(sc, "ready", True) is not True:
        return unknown("security_center_not_ready", s)
    incidents = getattr(sc, "incidents", None)
    if not isinstance(incidents, Mapping):
        return unknown("findings_unknown", s)
    # a fleet-wide incident (no router id) counts for every router (review
    # of PR #80)
    n = sum(
        1
        for inc in incidents.values()
        if isinstance(inc, Mapping)
        and inc.get("router_id") in (router_id, None)
        and inc.get("status") in ("open", "confirmed")
    )
    return known(n, f"{s}.incidents")


def _lease_facts(
    src: FactSources,
    fresh: bool | None,
    age: float | None,
    registry_records: Any,
    router_id: str,
) -> dict[str, Fact]:
    """Routers and clients holding a DHCP lease from this router (lower
    bounds: a static address is not visible)."""
    data = (
        getattr(src.coordinator, "data", None) if src.coordinator is not None else None
    )
    s = "coordinator.data.dhcp_leases"
    if fresh is not True or data is None:
        return {
            "lease_routers": unknown("poll_not_fresh", s),
            "lease_clients": unknown("poll_not_fresh", s),
        }
    leases = getattr(data, "dhcp_leases", None)
    if not isinstance(leases, Mapping):
        return {
            "lease_routers": unknown("leases_unknown", s),
            "lease_clients": unknown("leases_unknown", s),
        }
    macs = {str(m).strip().lower() for m in leases}
    routers = 0
    router_macs: set[str] = set()
    if registry_records is not None:
        for r in registry_records:
            if getattr(r, "router_id", None) == router_id:
                continue
            own = {
                str(m).strip().lower()
                for m in getattr(getattr(r, "identity", None), "mac_addresses", ())
                or ()
            }
            if own & macs:
                routers += 1
                router_macs |= own & macs
        out_r = known(routers, s, age)
    else:
        out_r = unknown("registry_unknown", s)
    return {
        "lease_routers": out_r,
        "lease_clients": known(len(macs - router_macs), s, age),
    }


def _backup_facts(src: FactSources, router_id: str) -> Fact:
    s = "core.versions"
    versions = src.versions
    if versions is None:
        return unknown("core_not_running", s)
    if getattr(versions, "loaded", True) is not True:
        return unknown("versions_not_loaded", s)
    records, err = _safe_call(lambda: versions.records(router_id), "versions")
    if records is None:
        return unknown(err or "versions_unknown", s)
    rows = []
    for r in records:
        created = _timestamp(getattr(r, "created_at", None))
        bid = getattr(r, "backup_id", None)
        if created is None or not is_valid_id(bid, hc.BACKUP_ID_PREFIX):
            continue
        status = _value_of(getattr(r, "status", None))
        validation = _value_of(getattr(getattr(r, "validation", None), "status", None))
        sha = getattr(r, "sha256", None)
        # a status that is no code (e.g. with a space) is "unknown", never
        # a crash of the collector (review of PR #80)
        rows.append(
            (
                bid,
                int(created),
                status if _readable_code(status) else "unknown",
                validation if _readable_code(validation) else "unknown",
                isinstance(sha, str) and len(sha) == 64,
            )
        )
    rows.sort(key=lambda r: (r[1], r[0]), reverse=True)
    return known(tuple(rows[:_TUPLE_MAX]), f"{s}.records")


_INCIDENT_NAMES: Final = (
    "incident_type",
    "incident_status",
    "incident_severity",
    "incident_confidence",
    "incident_is_root",
    "incident_cause_status",
    "incident_cause_level",
    "incident_families",
    "incident_fresh",
)


def _incident_facts(
    src: FactSources, incident_id: str | None, interval: float | None
) -> dict[str, Fact]:
    names = _INCIDENT_NAMES
    s = "network_intelligence.incidents"
    if incident_id is None:
        return {n: unknown("no_incident", s) for n in names}
    ni = src.ni
    if ni is None or not getattr(ni, "loaded", False):
        return {n: unknown("ni_not_loaded", s) for n in names}
    incidents, err = _safe_call(lambda: list(ni.machine.peek()), "ni.incidents")
    inc = next(
        (i for i in incidents or () if getattr(i, "id", None) == incident_id), None
    )
    if inc is None:
        return {n: unknown(err or "incident_unknown", s) for n in names}
    out: dict[str, Fact] = {}
    itype = getattr(inc, "type", None)
    out["incident_type"] = (
        known(itype, s) if _readable_code(itype) else unknown("type_unknown", s)
    )
    istatus = _value_of(getattr(inc, "status", None))
    out["incident_status"] = (
        known(istatus, s) if _readable_code(istatus) else unknown("status_unknown", s)
    )
    sev = _value_of(getattr(inc, "severity", None))
    out["incident_severity"] = (
        known(sev, s) if sev in SEVERITIES else unknown("severity_unknown", s)
    )
    conf = _num(getattr(inc, "confidence", None))
    out["incident_confidence"] = (
        known(conf, s)
        if conf is not None and 0 <= conf <= 1
        else unknown("confidence_unknown", s)
    )
    out["incident_is_root"] = known(getattr(inc, "parent_id", None) is None, s)
    status = _value_of(getattr(inc, "cause_status", None))
    out["incident_cause_status"] = (
        known(status, s)
        if status in ("confirmed", "hypothesis")
        else unknown("cause_status_unknown", s)
    )
    level: str | None = None
    families: int | None = None
    try:
        from .net_rules import cause_families, events_by_id, incident_cause_level

        wanted = {e.get("id") for e in inc.evidence if isinstance(e, Mapping)}
        events = events_by_id(e for e in ni.ring if e.id in wanted)
        families = len(cause_families(inc, events))
        level = _value_of(incident_cause_level(inc, events))
    except Exception as err2:  # noqa: BLE001 - without them: unknown
        _LOGGER.debug("Preflight: no cause level (%s)", type(err2).__name__)
    out["incident_cause_level"] = (
        known(level, s) if isinstance(level, str) else unknown("cause_level_unknown", s)
    )
    out["incident_families"] = (
        known(families, s) if families is not None else unknown("families_unknown", s)
    )
    last_seen = _num(getattr(inc, "last_seen", None))
    last_now = _num(getattr(getattr(ni, "machine", None), "last_now", None))
    if last_seen is None or last_now is None or interval is None:
        out["incident_fresh"] = unknown("freshness_unknown", s)
    else:
        out["incident_fresh"] = known(
            0 <= last_now - last_seen <= STALE_POLLS * interval, s
        )
    return out


_STATE_NAMES: Final = (
    "memory_pressure_pct",
    "memory_available_bytes",
    "cpu_load_pct",
    "uptime_s",
    "services",
    "radios",
    "interfaces",
    "clients_on_router",
    "wireless_uplink",
)
_STORE_NAMES: Final = (
    "lock_holder",
    "router_repairs",
    "fleet_repairs",
    "related_repairs",
    "held",
    "fleet_paused",
    "loop_blocks",
    "component_windows",
)


def _guard(
    names: Iterable[str], source: str, func: Callable[[], tuple[Any, Any]]
) -> tuple[dict[str, Fact], Any]:
    """Run one part of the collector; if it raises, its facts are unknown
    (``collector_error``) - the collector itself never raises on data."""
    try:
        out, extra = func()
    except Exception as err:  # noqa: BLE001 - a broken source is "unknown"
        _LOGGER.debug("Preflight: %s not collected (%s)", source, type(err).__name__)
        return {n: unknown("collector_error", source) for n in names}, None
    return out, extra


def _sane(facts: dict[str, Fact]) -> dict[str, Fact]:
    """Every collected fact of a known name with a valid shape; anything
    else becomes unknown (``value_unreadable``) instead of an exception."""
    out: dict[str, Fact] = {}
    for name in _SHAPES:
        fact = facts.get(name)
        if fact is None:
            continue
        if type(fact) is not Fact:
            out[name] = unknown("value_unreadable", "collector")
            continue
        try:
            _check_shape(name, fact.value)
        except PreflightError:
            out[name] = unknown("value_unreadable", fact.source)
        else:
            out[name] = fact
    return out


def facts_from_sources(
    src: FactSources,
    router_id: str,
    *,
    wall_now: float,
    exclude_action_id: str | None = None,
    incident_id: str | None = None,
) -> PreflightFacts:
    """The snapshot of ``router_id`` from in-memory objects only.

    Reads attributes and memory-only methods; never awaits, never calls the
    router, the api's request methods, the coordinator's refresh or the
    Configuration Manager's provider. The safety-clock time is read from the
    store (``store.now()``, which observes the clocks in memory).

    Never raises on what it reads (review of PR #80): every part is guarded
    and reports unknown with a reason. It raises :class:`PreflightError`
    only for its own inputs - no store, a bad router id, a wall time out of
    range, a safety clock that cannot be read.
    """
    if src.store is None:
        raise PreflightError("no self-healing store")
    if not is_valid_id(router_id, ROUTER_ID_PREFIX):
        raise _fail("router_id")
    try:
        safe = float(src.store.now())
        wall = float(wall_now)
    except Exception as err:  # without the clocks: no snapshot
        raise PreflightError("safety clock not readable") from err
    facts: dict[str, Fact] = {}

    def part(
        names: Iterable[str], source: str, func: Callable[[], tuple[Any, Any]]
    ) -> Any:
        out, extra = _guard(names, source, func)
        facts.update(out)
        return extra

    part(_POLL_FACTS[:3], "coordinator", lambda: (_poll_facts(src, wall), None))
    part(
        ("wall_clock_behind",),
        "heal_store.loop.clock",
        lambda: ({"wall_clock_behind": _clock_fact(src.store, wall)}, None),
    )
    poll_f = PreflightFacts(
        router_id=router_id, safe_at=safe, wall_at=wall, **_sane(facts)
    )
    fresh, why = _poll_fresh(poll_f)
    age = poll_f.poll_age_s.value
    part(
        _STATE_NAMES,
        "coordinator.data",
        lambda: (_router_state_facts(src, fresh, age, why), None),
    )
    part(
        (
            "record_active",
            "identity_status",
            "identity_bindings",
            "role",
            "capabilities",
        ),
        "core.registry",
        lambda: _registry_facts(src, router_id),
    )
    records = None
    if src.registry is not None:
        records, _err = _safe_call(lambda: tuple(src.registry.list()), "registry.list")
    part(
        ("lease_routers", "lease_clients"),
        "coordinator.data.dhcp_leases",
        lambda: (_lease_facts(src, fresh, age, records, router_id), None),
    )
    part(("login_is_root", "acl_blocked"), "api", lambda: (_rights_facts(src), None))

    def rid_of(entry_id: str) -> str | None:
        for r in records or ():
            if getattr(getattr(r, "identity", None), "entry_id", None) == entry_id:
                rid = getattr(r, "router_id", None)
                return rid if is_valid_id(rid, ROUTER_ID_PREFIX) else None
        return None

    related = part(
        (
            "ni_maintenance",
            "dependants",
            "upstream_hops",
            "uplink_incidents",
            "degraded_dependants",
        ),
        "network_intelligence",
        lambda: _ni_facts(src, router_id, wall, rid_of),
    )
    part(
        _STORE_NAMES,
        "heal_store",
        lambda: (
            _store_facts(src, router_id, safe, wall, exclude_action_id, related),
            None,
        ),
    )
    part(
        ("run_path",),
        "heal_store.settings",
        lambda: ({"run_path": _run_path(src.store, router_id)}, None),
    )
    if src.config_locked is None:
        facts["config_manager_busy"] = unknown(
            "core_not_running", "core.config_manager"
        )
    else:
        busy, err = _safe_call(lambda: src.config_locked(router_id), "config.locked")
        facts["config_manager_busy"] = (
            known(busy, "core.config_manager.locked", 0.0)
            if isinstance(busy, bool)
            else unknown(err or "lock_unknown", "core.config_manager")
        )
    part(
        ("security_findings",),
        "security_center",
        lambda: ({"security_findings": _security_fact(src, router_id)}, None),
    )
    part(
        ("backups",),
        "core.versions",
        lambda: ({"backups": _backup_facts(src, router_id)}, None),
    )
    if src.diag is None:
        facts["diag_enabled"] = unknown("diagnostics_not_running", "net_diagnostics")
    else:
        enabled, _err = _safe_call(lambda: src.diag.enabled, "diag.enabled")
        facts["diag_enabled"] = (
            known(enabled, "net_diagnostics.enabled")
            if isinstance(enabled, bool)
            else unknown("diagnostics_unknown", "net_diagnostics")
        )
    # the drift of the saved against the running configuration is not
    # tracked yet (package G): unknown, which blocks a service restart
    facts["service_config_unapplied"] = unknown(
        "config_drift_not_tracked", "config_drift"
    )
    interval = facts["poll_interval_s"].value if "poll_interval_s" in facts else None
    part(
        _INCIDENT_NAMES,
        "network_intelligence.incidents",
        lambda: (_incident_facts(src, incident_id, interval), None),
    )
    return PreflightFacts(
        router_id=router_id, safe_at=safe, wall_at=wall, **_sane(facts)
    )


def collect_preflight_facts(
    hass: Any,
    router_id: str,
    *,
    exclude_action_id: str | None = None,
    incident_id: str | None = None,
) -> PreflightFacts:
    """The snapshot of ``router_id`` from what Home Assistant holds in memory.

    Needs the running self-healing engine (its store has the safety clock,
    holds, locks and maintenance windows); raises :class:`PreflightError`
    without it. Everything else that is missing becomes unknown facts.
    """
    from .diag_runtime import async_get_net_diagnostics
    from .enterprise_core import async_get_core
    from .heal_engine import async_get_self_healing
    from .net_engine import async_get_engine
    from .security_center import async_get_security_center

    engine = async_get_self_healing(hass)
    if engine is None or not getattr(engine, "loaded", False):
        raise PreflightError("self-healing engine not running")
    core = async_get_core(hass)
    registry = versions = config_locked = None
    if core is not None and getattr(core, "loaded", False) and not core.closed:
        registry = core.registry
        versions = core.versions
        config_locked = core.manager.locked
    entry_id = None
    if registry is not None:
        record, _err = _safe_call(lambda: registry.find(router_id), "registry")
        entry_id = getattr(getattr(record, "identity", None), "entry_id", None)
        if (
            getattr(record, "state", None) is not None
            and _value_of(record.state) != "active"
        ):
            entry_id = None
    coordinator = api = None
    if isinstance(entry_id, str):
        entry, _err = _safe_call(
            lambda: hass.config_entries.async_get_entry(entry_id), "config_entries"
        )
        runtime = getattr(entry, "runtime_data", None) if entry is not None else None
        coordinator = getattr(runtime, "coordinator", None)
        api = getattr(runtime, "api", None)
    ni = async_get_engine(hass)
    src = FactSources(
        store=engine.store,
        entry_id=entry_id if isinstance(entry_id, str) else None,
        coordinator=coordinator,
        api=api,
        registry=registry,
        versions=versions,
        config_locked=config_locked,
        ni=ni,
        security=async_get_security_center(hass),
        diag=async_get_net_diagnostics(hass),
    )
    return facts_from_sources(
        src,
        router_id,
        wall_now=engine.clock(),
        exclude_action_id=exclude_action_id,
        incident_id=incident_id,
    )


def preflight_for(
    hass: Any,
    router_id: str,
    action_type: Any,
    params: Any = None,
    *,
    record: RemediationAction | None = None,
    limits: PreflightLimits = DEFAULT_PREFLIGHT_LIMITS,
) -> PreflightResult:
    """Collect (memory only) and run: "what would block" for a view.

    ``record``: the action's record (excluded from the concurrency counts;
    its approval, if any, is checked). Nothing is stored, nothing runs.
    """
    facts = collect_preflight_facts(
        hass,
        router_id,
        exclude_action_id=None if record is None else record.action_id,
        incident_id=None if record is None else record.incident_id,
    )
    return run_preflight(facts, action_type, params, approval=record, limits=limits)


__all__ = [
    "ACTION_CAPABILITIES",
    "CONFIG_CHANGING",
    "DEFAULT_PREFLIGHT_LIMITS",
    "FINGERPRINT_FACTS",
    "PREFLIGHT_CHECK_IDS",
    "VOLATILE_FACTS",
    "CheckResult",
    "CheckStatus",
    "Fact",
    "FactSources",
    "PreflightError",
    "PreflightFacts",
    "PreflightLimits",
    "PreflightResult",
    "Validity",
    "Verdict",
    "collect_preflight_facts",
    "expected_binding",
    "facts_from_sources",
    "incident_facts_for",
    "known",
    "preflight_for",
    "risk_context_for",
    "run_preflight",
    "state_fingerprint",
    "unknown",
]
