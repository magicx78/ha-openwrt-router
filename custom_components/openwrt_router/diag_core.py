"""Thin adapter between the pure diag modules and the enterprise core.

The ``diag_*`` modules know opaque router keys, opaque target ids and their
own enums. This module is the only place that says "router key = core
router id" (``rtr_<32 hex>``) and maps diag results onto the Configuration
API v1 contract (docs/dev/configuration-api-v1.md, sections 4.1, 6, 12, 13,
14 and 17). It holds pure mapping functions plus small docking helpers that
call the core API (no network I/O, no scheduling, no entities); nothing runs
at import.

Identity
    The Home Assistant measurement point is keyed ``"ha"`` (``PointKind.HA``)
    in series keys and labels; that can never be a core router id, and every
    router key passing this adapter is checked with ``is_valid_id(.., rtr_)``
    (which also refuses the fleet id ``"-"``). In core events the HA point
    has ``router_id=None`` (no router); a cause that sits outside one router
    (WAN, resolver, segment) has ``FLEET_ROUTER_ID``. The guard knows only
    registry routers and the fleet id, so a guarded action for the HA point
    is decided under ``FLEET_ROUTER_ID`` (:func:`guard_subject`).

Events
    Module ``net_diagnostics``, event prefix ``net_diagnostics.``, capability
    prefix ``diag.`` (core tables MODULE_EVENT_PREFIXES /
    MODULE_CAPABILITY_NAMESPACES). Event data carries enum codes, counters,
    router ids and identifier pseudonyms only: never a target id, address,
    hostname, raw change value or user id. Manual runs and router probe
    changes are registered audit-mandatory types. No incidents are created.

Masking
    Every output (diagnostics, logs, event views) goes through
    ``core_masking.mask_for_output``; excluded probes and raw probe evidence
    are masked by key, change values are masked or replaced by identifier
    pseudonyms made with the module key, actors are pseudonymised with
    ``core_masking.pseudonymise_user_ids``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any, Final

from .core_errors import (
    ConfigApiError,
    ErrorClass,
    OperationInProgressError,
    RateLimitedError,
    SafetyRefusedError,
)
from .core_masking import (
    IDENTIFIER_INVALID,
    mask_for_output,
    pseudonymise_fields,
    pseudonymise_identifier,
    pseudonymise_user_ids,
)
from .core_models import (
    CORRELATION_ID_PREFIX,
    EVENT_CLASSIFICATION_PATTERN,
    FLEET_ROUTER_ID,
    MODULE_CAPABILITY_NAMESPACES,
    MODULE_EVENT_PREFIXES,
    ROUTER_ID_PREFIX,
    ActionClass,
    Actor,
    AuthorizationDecision,
    Capability,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    CoreEvent,
    CoreEventType,
    DecisionState,
    EventResult,
    RouterRecord,
    binding_checksum,
    is_valid_id,
    new_id,
    utcnow,
)
from .core_models import (
    RateLimit as CoreRateLimit,
)
from .core_models import (
    Severity as CoreSeverity,
)
from .diag_baseline import BaselineState
from .diag_causes import RouterDependencies
from .diag_model import (
    SEVERITY_RANK,
    Cause,
    CauseLink,
    Classification,
    CorrelationResult,
    Finding,
    Location,
    LocationKind,
    MeasurementPoint,
    PointKind,
    ProbeResult,
    Severity,
    plain,
)
from .diag_scheduler import RateLimit as SchedulerRateLimit
from .diag_scheduler import RequestStatus, RunRequest
from .diag_stats import SeriesKey
from .diag_targets import Refusal

_LOGGER = logging.getLogger(__name__)

# --- module identity ------------------------------------------------------------

MODULE: Final = "net_diagnostics"
EVENT_PREFIX: Final = MODULE_EVENT_PREFIXES[MODULE]  # "net_diagnostics."
CAPABILITY_PREFIX: Final = MODULE_CAPABILITY_NAMESPACES[MODULE]  # "diag."
HA_POINT_KEY: Final = PointKind.HA.value  # never a valid rtr_ id, never "-"
# Purpose of the module key (api.async_get_module_key) for identifier
# pseudonyms; another purpose would give unlinkable pseudonyms.
IDENTIFIER_KEY_PURPOSE: Final = "identifiers"

# --- capability / kind names ---------------------------------------------------------

KIND_DATA_INTERFACE_DUMP: Final = "diag.data.interface_dump"
KIND_DATA_ODHCPD: Final = "diag.data.odhcpd"  # ipv6leases / ipv6ra only
KIND_DATA_DNSMASQ: Final = "diag.data.dnsmasq_metrics"  # absent on a relay AP
KIND_DATA_DHCP_CONFIG: Final = "diag.data.dhcp_config"
KIND_HA_TCP: Final = "diag.probe.ha_tcp"
KIND_HA_DNS: Final = "diag.probe.ha_dns"
KIND_HA_HTTP: Final = "diag.probe.ha_http"
KIND_EXEC_PING: Final = "diag.exec.ping"
KIND_EXEC_NSLOOKUP: Final = "diag.exec.nslookup"
KIND_EXEC_TRACEROUTE: Final = "diag.exec.traceroute"

DATA_KINDS: Final = (
    KIND_DATA_INTERFACE_DUMP,
    KIND_DATA_ODHCPD,
    KIND_DATA_DNSMASQ,
    KIND_DATA_DHCP_CONFIG,
)
HA_PROBE_KINDS: Final = (KIND_HA_TCP, KIND_HA_DNS, KIND_HA_HTTP)
EXEC_KINDS: Final = (KIND_EXEC_PING, KIND_EXEC_NSLOOKUP, KIND_EXEC_TRACEROUTE)
ALL_KINDS: Final = DATA_KINDS + HA_PROBE_KINDS + EXEC_KINDS
ROUTER_CAPABILITIES: Final = DATA_KINDS + EXEC_KINDS  # what the detector reports

# Router tool behind each exec kind (looked up in DiagRouterFacts.tools).
EXEC_TOOLS: Final[Mapping[str, str]] = MappingProxyType(
    {
        KIND_EXEC_PING: "ping",
        KIND_EXEC_NSLOOKUP: "nslookup",
        KIND_EXEC_TRACEROUTE: "traceroute",
    }
)
# odhcpd methods the module uses; ipv4leases is never used (odhcpd_v4 off).
ODHCPD_METHODS: Final = ("ipv6leases", "ipv6ra")
_PERMISSIONS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        KIND_DATA_INTERFACE_DUMP: ("ubus:network.interface/dump",),
        KIND_DATA_ODHCPD: ("ubus:dhcp/ipv6leases", "ubus:dhcp/ipv6ra"),
        KIND_DATA_DNSMASQ: ("ubus:dnsmasq/metrics",),
        KIND_DATA_DHCP_CONFIG: ("ubus:uci/get",),
        # rpcd file exec on the tool; optional ACL tiers accept file "read"
        # only (OPTIONAL_TIER_FILE_READ_PREFIXES), so no tier grants it today.
        **{kind: ("file:exec",) for kind in EXEC_KINDS},
    }
)
# Free router memory below which no router-side exec probe may start.
DEFAULT_EXEC_MIN_FREE_KB: Final = 16 * 1024
_SOURCE_FACTS: Final = f"{MODULE}:facts"
_SOURCE_TRANSPORT: Final = f"core:{Capability.TRANSPORT_UBUS.value}"

# Reasons of kind_availability (stable codes).
REASON_OK: Final = "ok"
REASON_DISABLED: Final = "disabled"
REASON_NOT_ENABLED: Final = "not_enabled"
REASON_CAPABILITY_UNAVAILABLE: Final = "capability_unavailable"
REASON_CAPABILITY_UNKNOWN: Final = "capability_unknown"
REASON_MEMORY_LOW: Final = "memory_low"
REASON_MEMORY_UNKNOWN: Final = "memory_unknown"

# --- events ---------------------------------------------------------------------------

EVENT_FINDING: Final = f"{EVENT_PREFIX}finding"
EVENT_CAUSE: Final = f"{EVENT_PREFIX}cause"
EVENT_GATEWAY_CHANGED: Final = f"{EVENT_PREFIX}gateway_changed"
EVENT_DNS_SERVER_CHANGED: Final = f"{EVENT_PREFIX}dns_server_changed"
EVENT_MANUAL_RUN: Final = f"{EVENT_PREFIX}manual_run"
EVENT_ROUTER_PROBES_CHANGED: Final = f"{EVENT_PREFIX}router_probes_changed"
DIAG_EVENT_TYPES: Final = frozenset(
    {
        EVENT_FINDING,
        EVENT_CAUSE,
        EVENT_GATEWAY_CHANGED,
        EVENT_DNS_SERVER_CHANGED,
        EVENT_MANUAL_RUN,
        EVENT_ROUTER_PROBES_CHANGED,
    }
)
# Acts of a person: registered as audit-mandatory types (contract 12.5),
# so the core never deduplicates them (every one is stored and sent).
AUDIT_DUTY_EVENT_TYPES: Final = frozenset(
    {EVENT_MANUAL_RUN, EVENT_ROUTER_PROBES_CHANGED}
)
# Emitted with security_relevant=True: enabling router-side exec widens what
# HA may run on a router (security ring, contract 12.2).
SECURITY_EVENT_TYPES: Final = frozenset({EVENT_ROUTER_PROBES_CHANGED})
_CHANGE_EVENTS: Final[Mapping[Classification, str]] = MappingProxyType(
    {
        Classification.GATEWAY_CHANGED: EVENT_GATEWAY_CHANGED,
        Classification.DNS_SERVER_CHANGED: EVENT_DNS_SERVER_CHANGED,
    }
)
_SEVERITY: Final[Mapping[Severity, CoreSeverity]] = MappingProxyType(
    {
        Severity.OK: CoreSeverity.INFO,
        Severity.INFO: CoreSeverity.INFO,
        Severity.WARNING: CoreSeverity.WARNING,
        Severity.CRITICAL: CoreSeverity.CRITICAL,
    }
)

# --- outputs ------------------------------------------------------------------------

# Keys whose whole value is masked in diagnostics output: change values
# (unless replaced by pseudonyms) and probes excluded from a chain (their raw
# evidence may hold addresses).
OUTPUT_MASK_KEYS: Final = ("change", "excluded")
# Logs also mask raw probe evidence wherever it appears.
LOG_MASK_KEYS: Final = (*OUTPUT_MASK_KEYS, "evidence")
# Detail shown only after the core's sensitive read (ACTION_READ_DETAIL).
SENSITIVE_READS: Final = frozenset(
    {"chain", "evidence", "probe", "change", "reasons", "location"}
)
# core_masking treats ``*_key`` names (router_key, summary_key, ...) as
# secret; diag i18n keys and router keys are renamed so they stay readable.
_RENAMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "router_key": "router_id",
        "router_keys": "router_ids",
        "summary_key": "summary",
        "recommendation_key": "recommendation",
    }
)


# =============================================================================
# Identity
# =============================================================================


def check_router_id(router_id: object) -> str:
    """``router_id`` if it is a core router id, else ValueError."""
    if not is_valid_id(router_id, ROUTER_ID_PREFIX):
        raise ValueError("not a core router id")
    return router_id  # type: ignore[return-value]


def point_for(router_id: str | None) -> MeasurementPoint:
    """Measurement point of a router (by core id) or of HA (``None``)."""
    if router_id is None:
        return MeasurementPoint.ha()
    return MeasurementPoint.router(check_router_id(router_id))


def router_id_for(point: MeasurementPoint) -> str | None:
    """Core router id of a measurement point; ``None`` for the HA point."""
    if point.kind == PointKind.HA:
        return None
    return check_router_id(point.key)


def guard_subject(router_id: str | None) -> str:
    """``router_id`` the guard decides on: the router, or ``FLEET_ROUTER_ID``
    for the HA point (the guard knows only registry routers and ``-``)."""
    return FLEET_ROUTER_ID if router_id is None else check_router_id(router_id)


def series_point(router_id: str | None) -> str:
    """``SeriesKey.point`` of a router or of HA (``"ha"``)."""
    return HA_POINT_KEY if router_id is None else check_router_id(router_id)


def series_key(
    router_id: str | None, target_id: str, kind: Any, family: Any
) -> SeriesKey:
    """Series key of one (point, target, probe kind, family)."""
    return SeriesKey(
        series_point(router_id),
        target_id,
        str(getattr(kind, "value", kind)),
        str(getattr(family, "value", family)),
    )


def router_id_for_series(key: SeriesKey) -> str | None:
    """Core router id of a series key; ``None`` for an HA series."""
    if key.point == HA_POINT_KEY:
        return None
    return check_router_id(key.point)


def scheduler_key(router_id: str | None) -> str | None:
    """``DiagJob.router_key`` of a router (core id) or of HA (``None``)."""
    return None if router_id is None else check_router_id(router_id)


def dependencies_by_router(
    dependencies: Mapping[str, RouterDependencies],
) -> dict[str, RouterDependencies]:
    """``correlate`` input, checked: every router reference is a core id."""
    checked: dict[str, RouterDependencies] = {}
    for router_id, deps in dependencies.items():
        check_router_id(router_id)
        if deps.gateway is not None:
            check_router_id(deps.gateway)
        for upstream in deps.upstream:
            check_router_id(upstream)
        for host in deps.hosts:
            if host.kind == LocationKind.ROUTER:
                check_router_id(host.id)
        checked[router_id] = deps
    return checked


def location_router_id(location: Location) -> str | None:
    """Core ``router_id`` of a cause location: the router, ``None`` for HA,
    ``FLEET_ROUTER_ID`` for a place outside one router (WAN, resolver,
    segment)."""
    if location.kind == LocationKind.ROUTER:
        return check_router_id(location.id)
    if location.kind == LocationKind.HA:
        return None
    return FLEET_ROUTER_ID


# =============================================================================
# Capabilities
# =============================================================================


def _opt_set(value: Iterable[str] | None) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        raise TypeError("expected a collection of names, not a string")
    return frozenset(str(item) for item in value)


@dataclass(frozen=True)
class DiagRouterFacts:
    """What the poll found on one router (``None`` = not checked).

    Only per-device facts: never a device type, model or firmware version.
    ``mem_available_kb`` is a run-time precondition of exec probes, not part
    of any capability.
    """

    interface_dump: bool | None = None
    odhcpd_methods: frozenset[str] | None = None
    dnsmasq_ubus: bool | None = None
    dnsmasq_metric_keys: frozenset[str] | None = None
    dhcp_config: bool | None = None
    exec_permitted: bool | None = None
    tools: frozenset[str] | None = None
    mem_available_kb: int | None = None

    def __post_init__(self) -> None:
        for name in ("odhcpd_methods", "dnsmasq_metric_keys", "tools"):
            object.__setattr__(self, name, _opt_set(getattr(self, name)))
        mem = self.mem_available_kb
        if mem is not None and (isinstance(mem, bool) or not isinstance(mem, int)):
            raise TypeError("mem_available_kb must be an int or None")

    def signature(self) -> tuple[Any, ...]:
        """Everything a capability depends on (memory left out on purpose)."""
        return (
            self.interface_dump,
            None if self.odhcpd_methods is None else tuple(sorted(self.odhcpd_methods)),
            self.dnsmasq_ubus,
            None if self.dnsmasq_metric_keys is None else len(self.dnsmasq_metric_keys),
            self.dhcp_config,
            self.exec_permitted,
            None if self.tools is None else tuple(sorted(self.tools)),
        )


@dataclass(frozen=True)
class DiagSettings:
    """Per-router module settings. Exec kinds are off unless listed."""

    enabled_exec: frozenset[str] = frozenset()
    ha_probes: bool = True
    exec_min_free_kb: int = DEFAULT_EXEC_MIN_FREE_KB

    def __post_init__(self) -> None:
        enabled = frozenset(self.enabled_exec)
        unknown = enabled - set(EXEC_KINDS)
        if unknown:
            raise ValueError("only diag.exec.* kinds can be enabled")
        object.__setattr__(self, "enabled_exec", enabled)
        if not isinstance(self.exec_min_free_kb, int) or self.exec_min_free_kb < 0:
            raise ValueError("exec_min_free_kb must be a non-negative int")


def _cap(
    name: str,
    state: CapabilityState,
    reason: str,
    now: datetime,
    *,
    source: str = _SOURCE_FACTS,
    detail: Mapping[str, Any] | None = None,
) -> CapabilityStatus:
    return CapabilityStatus(
        capability=name,
        state=state,
        reason=reason,
        source=source,
        detected_at=now,
        required_permissions=_PERMISSIONS[name],
        detail=detail or {},
    )


def _from_flag(name: str, flag: bool | None, now: datetime) -> CapabilityStatus:
    if flag is None:
        return _cap(name, CapabilityState.UNKNOWN, CapabilityReason.NOT_CHECKED, now)
    if flag:
        return _cap(name, CapabilityState.AVAILABLE, CapabilityReason.OK, now)
    return _cap(name, CapabilityState.UNAVAILABLE, CapabilityReason.NOT_DETECTED, now)


def _odhcpd(facts: DiagRouterFacts, now: datetime) -> CapabilityStatus:
    methods = facts.odhcpd_methods
    if methods is None:
        return _from_flag(KIND_DATA_ODHCPD, None, now)
    detail = {method: method in methods for method in ODHCPD_METHODS}
    state, reason = (
        (CapabilityState.AVAILABLE, CapabilityReason.OK)
        if any(detail.values())
        else (CapabilityState.UNAVAILABLE, CapabilityReason.NOT_DETECTED)
    )
    return _cap(KIND_DATA_ODHCPD, state, reason, now, detail=detail)


def _dnsmasq(facts: DiagRouterFacts, now: datetime) -> CapabilityStatus:
    if facts.dnsmasq_ubus is not True or facts.dnsmasq_metric_keys is None:
        return _from_flag(
            KIND_DATA_DNSMASQ, None if facts.dnsmasq_ubus else facts.dnsmasq_ubus, now
        )
    count = len(facts.dnsmasq_metric_keys)
    status = _from_flag(KIND_DATA_DNSMASQ, count > 0, now)
    return _cap(
        KIND_DATA_DNSMASQ,
        status.state,
        status.reason,
        now,
        detail={"metric_count": count},
    )


def _exec(name: str, facts: DiagRouterFacts, now: datetime) -> CapabilityStatus:
    if facts.exec_permitted is False:
        return _cap(
            name, CapabilityState.UNAVAILABLE, CapabilityReason.PERMISSION_DENIED, now
        )
    if facts.exec_permitted is None or facts.tools is None:
        return _from_flag(name, None, now)
    return _from_flag(name, EXEC_TOOLS[name] in facts.tools, now)


def detect_capabilities(
    facts: DiagRouterFacts | None,
    *,
    transport: CapabilityStatus | None,
    now: datetime,
) -> dict[str, CapabilityStatus]:
    """``diag.data.*`` / ``diag.exec.*`` statuses of one router (pure).

    Derived from the core's ``transport.ubus`` status and per-device facts
    only, never from a device type or firmware version. HA-side probes are
    not router capabilities; see :func:`kind_availability`.
    """
    if transport is None or transport.state is CapabilityState.UNKNOWN:
        return {
            name: _cap(
                name,
                CapabilityState.UNKNOWN,
                CapabilityReason.NO_DATA_YET,
                now,
                source=_SOURCE_TRANSPORT,
            )
            for name in ROUTER_CAPABILITIES
        }
    if transport.state is CapabilityState.UNAVAILABLE:
        return {
            name: _cap(
                name,
                CapabilityState.UNAVAILABLE,
                CapabilityReason.TRANSPORT_UNSUPPORTED,
                now,
                source=_SOURCE_TRANSPORT,
            )
            for name in ROUTER_CAPABILITIES
        }
    if facts is None:
        return {
            name: _cap(name, CapabilityState.UNKNOWN, CapabilityReason.NO_DATA_YET, now)
            for name in ROUTER_CAPABILITIES
        }
    found = {
        KIND_DATA_INTERFACE_DUMP: _from_flag(
            KIND_DATA_INTERFACE_DUMP, facts.interface_dump, now
        ),
        KIND_DATA_ODHCPD: _odhcpd(facts, now),
        KIND_DATA_DNSMASQ: _dnsmasq(facts, now),
        KIND_DATA_DHCP_CONFIG: _from_flag(
            KIND_DATA_DHCP_CONFIG, facts.dhcp_config, now
        ),
    }
    found.update({name: _exec(name, facts, now) for name in EXEC_KINDS})
    return found


def _capability_reason(status: CapabilityStatus | None) -> str:
    if status is None or status.state is CapabilityState.UNKNOWN:
        return REASON_CAPABILITY_UNKNOWN
    if status.state is CapabilityState.UNAVAILABLE:
        return REASON_CAPABILITY_UNAVAILABLE
    return REASON_OK


def kind_availability(
    statuses: Mapping[str, CapabilityStatus],
    facts: DiagRouterFacts | None,
    settings: DiagSettings | None = None,
) -> dict[str, str]:
    """Per kind: ``REASON_OK`` if usable now, else why not (pure).

    ``statuses`` are the router's capability statuses (core record). An exec
    kind needs all of: listed in ``settings.enabled_exec`` (off by default),
    capability available, known free memory of at least
    ``settings.exec_min_free_kb``.
    """
    settings = settings or DiagSettings()
    reasons: dict[str, str] = {
        kind: _capability_reason(statuses.get(kind)) for kind in DATA_KINDS
    }
    for kind in HA_PROBE_KINDS:
        reasons[kind] = REASON_OK if settings.ha_probes else REASON_DISABLED
    mem = None if facts is None else facts.mem_available_kb
    for kind in EXEC_KINDS:
        if kind not in settings.enabled_exec:
            reasons[kind] = REASON_NOT_ENABLED
            continue
        reason = _capability_reason(statuses.get(kind))
        if reason == REASON_OK and mem is None:
            reason = REASON_MEMORY_UNKNOWN
        elif reason == REASON_OK and mem < settings.exec_min_free_kb:  # type: ignore[operator]
            reason = REASON_MEMORY_LOW
        reasons[kind] = reason
    return reasons


def available_kinds(
    statuses: Mapping[str, CapabilityStatus],
    facts: DiagRouterFacts | None,
    settings: DiagSettings | None = None,
) -> frozenset[str]:
    """Kinds usable on one router now (see :func:`kind_availability`)."""
    return frozenset(
        kind
        for kind, reason in kind_availability(statuses, facts, settings).items()
        if reason == REASON_OK
    )


FactsExtractor = Callable[[Any], "DiagRouterFacts | None"]


def make_detector(
    extract_facts: FactsExtractor,
    *,
    clock: Callable[[], datetime] = utcnow,
) -> Callable[[RouterRecord, Any], dict[str, CapabilityStatus]]:
    """Capability detector for ``register_capability_detector`` (sync, no I/O).

    The core passes the record as it was before this poll's evaluation, so
    the ``transport.ubus`` status seen here may be one poll old.
    """

    def detector(record: RouterRecord, data: Any) -> dict[str, CapabilityStatus]:
        return detect_capabilities(
            extract_facts(data),
            transport=record.capabilities.get(Capability.TRANSPORT_UBUS),
            now=clock(),
        )

    return detector


def make_signature(extract_facts: FactsExtractor) -> Callable[[Any], Any]:
    """Detector signature: re-run only when a capability fact changed."""

    def signature(data: Any) -> Any:
        facts = extract_facts(data)
        return None if facts is None else facts.signature()

    return signature


# =============================================================================
# Guard
# =============================================================================


@dataclass(frozen=True)
class DiagAction:
    """A guarded module action (``register_action`` arguments).

    ``agreed_name`` is the planned ``diag.*`` name, where there was one; the
    guard requires ``<module>.<action>``, so ``name`` is what is registered.
    """

    name: str
    action_class: ActionClass
    admin_user_only: bool = False
    sensitive_read: bool = False
    rate_limit: CoreRateLimit | None = None
    agreed_name: str | None = None


def guard_rate_limit(limit: SchedulerRateLimit | None = None) -> CoreRateLimit:
    """The guard's limit for manual runs, equal to the scheduler's limit.

    The two stack: the guard counts granted manual runs per (action,
    router), the scheduler counts every started run (manual, event,
    periodic) per router key and stays the limit that makes a manual run
    obey the same budget as automatic ones. ValueError for a scheduler
    window longer than one day (the core's maximum).
    """
    limit = limit or SchedulerRateLimit()
    return CoreRateLimit(max_calls=limit.max_runs, per=timedelta(seconds=limit.window))


# Active, not mutating: acts on the router or network (probe runs). Only a
# verified admin user starts one; rate limited per router like the scheduler.
ACTION_RUN_MANUAL: Final = DiagAction(
    name=f"{MODULE}.run_manual",
    action_class=ActionClass.ACTIVE,
    admin_user_only=True,
    rate_limit=guard_rate_limit(),
    agreed_name="diag.run_manual",
)
# Most restricted class: request + admin approval + single use.
ACTION_ENABLE_ROUTER_PROBES: Final = DiagAction(
    name=f"{MODULE}.enable_router_probes",
    action_class=ActionClass.CRITICAL,
    admin_user_only=True,
    agreed_name="diag.enable_router_probes",
)
# Reading diagnosis detail (SENSITIVE_READS): the core's sensitive read
# (a user must be a verified admin; module, system and automation read).
ACTION_READ_DETAIL: Final = DiagAction(
    name=f"{MODULE}.read_detail",
    action_class=ActionClass.READ,
    sensitive_read=True,
)
DIAG_ACTIONS: Final = (
    ACTION_RUN_MANUAL,
    ACTION_ENABLE_ROUTER_PROBES,
    ACTION_READ_DETAIL,
)


def diag_actions(
    scheduler_limit: SchedulerRateLimit | None = None,
) -> tuple[DiagAction, ...]:
    """The module actions; ``run_manual`` limited like ``scheduler_limit``."""
    run = replace(ACTION_RUN_MANUAL, rate_limit=guard_rate_limit(scheduler_limit))
    return (run, ACTION_ENABLE_ROUTER_PROBES, ACTION_READ_DETAIL)


def register_actions(
    guard: Any, *, scheduler_limit: SchedulerRateLimit | None = None
) -> tuple[str, ...]:
    """Register the module actions with ``guard`` (``api.guard`` or the core
    ActionGuard). Idempotent for the same limit; never called at import."""
    actions = diag_actions(scheduler_limit)
    for action in actions:
        guard.register_action(
            action.name,
            action.action_class,
            module=MODULE,
            admin_user_only=action.admin_user_only,
            sensitive_read=action.sensitive_read,
            rate_limit=action.rate_limit,
        )
    return tuple(action.name for action in actions)


def _exec_kinds(kinds: Iterable[str]) -> list[str]:
    if isinstance(kinds, str):
        raise TypeError("kinds must be a collection")
    found = sorted({str(kind) for kind in kinds})
    if set(found) - set(EXEC_KINDS):
        raise ValueError("only diag.exec.* kinds")
    return found


def enable_probes_checksum(router_id: str, kinds: Iterable[str]) -> str:
    """Binding checksum of ``enable_router_probes`` (router + exact kinds)."""
    return binding_checksum(check_router_id(router_id), _exec_kinds(kinds))


def authorize_manual_run(
    guard: Any,
    actor: Any,
    router_id: str | None,
    *,
    correlation_id: str | None = None,
) -> AuthorizationDecision:
    """Guard decision for one manual run (audited by the core).

    The HA point is decided under ``FLEET_ROUTER_ID``; an unknown router is
    refused by the core (``unknown_router``). On a denial raise
    ``core_guard.error_for_decision(decision)`` (``RateLimitedError`` when
    over the limit). An approved run still goes through the scheduler.
    """
    return guard.authorize(
        ACTION_RUN_MANUAL.name,
        guard_subject(router_id),
        actor,
        correlation_id=_check_correlation(correlation_id),
    )


def authorize_sensitive_read(
    guard: Any,
    reader: Any,
    router_id: str | None,
    *,
    correlation_id: str | None = None,
) -> bool:
    """True if ``reader`` may see the detail (``admin=True`` outputs).

    Decided by the core's sensitive read (``ACTION_READ_DETAIL``): grants
    and denials are audited on the security ring.
    """
    decision = guard.authorize(
        ACTION_READ_DETAIL.name,
        guard_subject(router_id),
        reader,
        correlation_id=_check_correlation(correlation_id),
    )
    return decision.state is DecisionState.APPROVED


# =============================================================================
# Errors (contract 14): refusals of the scheduler and the target checks
# =============================================================================

# Scheduler answers that are not a rate limit (the job id is never echoed).
_RUN_REFUSALS: Final[Mapping[RequestStatus, tuple[type[ConfigApiError], Any]]] = (
    MappingProxyType(
        {
            RequestStatus.REFUSED_ALREADY_QUEUED: (OperationInProgressError, None),
            RequestStatus.REFUSED_UNKNOWN_JOB: (ConfigApiError, ErrorClass.NOT_FOUND),
            RequestStatus.REFUSED_STOPPED: (ConfigApiError, ErrorClass.NOT_AVAILABLE),
        }
    )
)


def error_for_run_request(
    request: RunRequest | RequestStatus, *, router_id: str | None = None
) -> ConfigApiError | None:
    """Core error for a refused scheduler request; ``None`` if accepted.

    ``refused_rate_limit`` -> ``RateLimitedError`` with the scheduler's
    ``retry_after`` (0 if unknown); ``refused_already_queued`` ->
    ``OperationInProgressError``; ``refused_unknown_job`` -> ``not_found``;
    ``refused_stopped`` -> ``not_available``. ``details.reason`` is the
    scheduler status; the job id is never part of the error.
    """
    if isinstance(request, RunRequest):
        status, retry_after = request.status, request.retry_after
    else:
        status, retry_after = RequestStatus(request), None
    if status is RequestStatus.ACCEPTED:
        return None
    rid = None if router_id is None else check_router_id(router_id)
    details = {
        "reason": status.value,
        "action": ACTION_RUN_MANUAL.name,
        "limit_source": "scheduler",
    }
    if status is RequestStatus.REFUSED_RATE_LIMIT:
        return RateLimitedError(
            "Diagnosis run is rate limited",
            retry_after=max(0.0, float(retry_after or 0.0)),
            router_id=rid,
            details=details,
        )
    cls, error_class = _RUN_REFUSALS[status]
    message = f"Diagnosis run refused: {status.value}"
    if error_class is None:
        return cls(message, router_id=rid, details=details)
    return cls(message, router_id=rid, error_class=error_class, details=details)


# Refusals because probing there (or a host of that shape) is unsafe: a
# non-global or special address, a name outside the allowed scope, a shape
# that could inject options or URLs, an unconfirmed target, a resolver that
# answered oddly. Every other refusal is a plain input error.
SAFETY_REFUSALS: Final = frozenset(
    {
        Refusal.NOT_CONFIRMED,
        Refusal.NON_ASCII_HOST,
        Refusal.BAD_CHARACTER,
        Refusal.URL_NOT_ALLOWED,
        Refusal.LEADING_DASH,
        Refusal.PORT_IN_HOST,
        Refusal.NUMERIC_HOST,
        Refusal.BAD_PUNYCODE,
        Refusal.INTERNAL_NAME,
        Refusal.NOT_INTERNAL_NAME,
        Refusal.LOOPBACK,
        Refusal.LINK_LOCAL,
        Refusal.METADATA,
        Refusal.MULTICAST,
        Refusal.BROADCAST,
        Refusal.UNSPECIFIED,
        Refusal.RESERVED,
        Refusal.DOCUMENTATION,
        Refusal.TRANSLATED,
        Refusal.NOT_GLOBAL,
        Refusal.NOT_INTERNAL_NETWORK,
        Refusal.RESOLVED_INVALID,
        Refusal.TOO_MANY_ADDRESSES,
    }
)
_REFUSAL_ERROR_CLASSES: Final[Mapping[Refusal, ErrorClass]] = MappingProxyType(
    {
        Refusal.UNKNOWN_TARGET: ErrorClass.NOT_FOUND,
        Refusal.RESOLVED_EMPTY: ErrorClass.NOT_FOUND,
        Refusal.DUPLICATE_ID: ErrorClass.CONFLICT,
        Refusal.REGISTRY_FULL: ErrorClass.TOO_LARGE,
        **{
            refusal: ErrorClass.INVALID
            for refusal in (
                Refusal.INVALID_ID,
                Refusal.INVALID_TARGET,
                Refusal.INVALID_KIND,
                Refusal.INVALID_SCOPE,
                Refusal.INVALID_PORT,
                Refusal.PORT_REQUIRED,
                Refusal.EMPTY_HOST,
                Refusal.HOST_TOO_LONG,
                Refusal.INVALID_IP,
                Refusal.EMPTY_LABEL,
                Refusal.LABEL_TOO_LONG,
                Refusal.BAD_LABEL,
            )
        },
    }
)


def refusal_reason(refusal: Refusal) -> str:
    """Machine code of a target refusal (``target.<code>``)."""
    return f"target.{Refusal(refusal).value}"


def error_for_refusal(
    refusal: Refusal, *, router_id: str | None = None
) -> ConfigApiError:
    """Core error for a ``diag_targets.Refusal``; never holds the input.

    Safety refusals (:data:`SAFETY_REFUSALS`, and any refusal this table
    does not know: fail closed) -> ``SafetyRefusedError``; the rest ->
    ``ConfigApiError`` with ``invalid`` / ``not_found`` / ``conflict`` /
    ``too_large``. ``reason`` is ``target.<code>``.
    """
    refusal = Refusal(refusal)
    reason = refusal_reason(refusal)
    rid = None if router_id is None else check_router_id(router_id)
    error_class = _REFUSAL_ERROR_CLASSES.get(refusal)
    if refusal in SAFETY_REFUSALS or error_class is None:
        return SafetyRefusedError(
            f"Target refused for safety: {refusal.value}", reason=reason, router_id=rid
        )
    return ConfigApiError(
        f"Target refused: {refusal.value}",
        router_id=rid,
        error_class=error_class,
        details={"reason": reason},
    )


# =============================================================================
# Identifier pseudonyms (contract 11.5, 13)
# =============================================================================


async def async_identifier_key(api: Any) -> bytes:
    """The module key for identifier pseudonyms (``api.async_get_module_key``).

    Needs the module's event prefix registered first (core rule); never log
    or store the key.
    """
    return await api.async_get_module_key(MODULE, purpose=IDENTIFIER_KEY_PURPOSE)


def pseudonymise_address(value: Any, key: bytes) -> str:
    """``ipa_<16 hex>`` of an address (``IDENTIFIER_INVALID`` if it is none)."""
    try:
        return pseudonymise_identifier("ip", value, key)
    except (TypeError, ValueError):
        return IDENTIFIER_INVALID


def _addresses(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def _scalar(value: Any) -> str | None:
    """One address as text (None stays None) for ``pseudonymise_fields``."""
    return None if value is None else str(value)


_GATEWAY_FIELDS: Final[Mapping[str, str]] = MappingProxyType(
    {"previous_gateway": "ip", "current_gateway": "ip"}
)
_SERVER_FIELDS: Final[Mapping[str, str]] = MappingProxyType(
    {"previous": "ip", "current": "ip"}
)


def _change_pseudonyms(finding: Finding, key: bytes) -> dict[str, Any]:
    """Which pseudonymous gateway / servers changed (sorted, never raw).

    Built with the core's ``pseudonymise_fields`` (contract 13): a value
    that is no address becomes ``IDENTIFIER_INVALID``, never the raw value.
    """
    change = finding.change
    if change is None:
        return {}
    if finding.classification is Classification.GATEWAY_CHANGED:
        return pseudonymise_fields(
            {
                "previous_gateway": _scalar(change.previous),
                "current_gateway": _scalar(change.current),
            },
            key,
            _GATEWAY_FIELDS,
        )
    sides = pseudonymise_fields(
        {
            "previous": _addresses(change.previous),
            "current": _addresses(change.current),
        },
        key,
        _SERVER_FIELDS,
    )
    before, after = set(sides["previous"]), set(sides["current"])
    return {
        "previous_servers": sorted(before),
        "current_servers": sorted(after),
        "added_servers": sorted(after - before),
        "removed_servers": sorted(before - after),
    }


# =============================================================================
# Events
# =============================================================================


@dataclass(frozen=True)
class DiagEvent:
    """One module event, ready for ``api.emit(**event.emit_kwargs())``."""

    event_type: str
    severity: CoreSeverity
    result: EventResult
    router_id: str | None
    dedup_key: str | None
    data: Mapping[str, Any] = field(default_factory=dict)
    correlation_id: str | None = None
    actor: Actor | None = None
    security_relevant: bool = False
    # Typed CoreEvent field (contract 12.1, B8): the finding classification
    # or the cause rule, an enum code (EVENT_CLASSIFICATION_PATTERN).
    classification: str | None = None

    def __post_init__(self) -> None:
        if self.event_type not in DIAG_EVENT_TYPES:
            raise ValueError("unknown diag event type")
        if not isinstance(self.security_relevant, bool):
            raise TypeError("security_relevant must be a bool")
        if self.classification is not None and (
            not isinstance(self.classification, str)
            or EVENT_CLASSIFICATION_PATTERN.fullmatch(self.classification) is None
        ):
            raise ValueError("classification must be an event classification code")
        object.__setattr__(self, "data", MappingProxyType(plain(dict(self.data))))

    def emit_kwargs(self) -> dict[str, Any]:
        """Keyword arguments of ``ConfigurationApi.emit`` / ``AuditLog.emit``."""
        return {
            "event_type": self.event_type,
            "source": MODULE,
            "router_id": self.router_id,
            "severity": self.severity,
            "result": self.result,
            "actor": self.actor,
            "correlation_id": self.correlation_id,
            "dedup_key": self.dedup_key,
            "data": plain(dict(self.data)),
            "security_relevant": self.security_relevant,
            "classification": self.classification,
        }

    def to_dict(self) -> dict[str, Any]:
        """Plain form (NOT masked: use :func:`event_output` to show it)."""
        return {
            "type": self.event_type,
            "source": MODULE,
            "severity": self.severity.value,
            "result": self.result.value,
            "router_id": self.router_id,
            "correlation_id": self.correlation_id,
            "dedup_key": self.dedup_key,  # a SAFE_KEYS name: stays readable
            "security_relevant": self.security_relevant,
            "classification": self.classification,
            "actor": None if self.actor is None else self.actor.to_dict(),
            "data": plain(dict(self.data)),
        }


def register_event_prefix(target: Any) -> Callable[[], None]:
    """Allow the module's event types on ``target`` (api or AuditLog) and
    make :data:`AUDIT_DUTY_EVENT_TYPES` audit-mandatory there; returns one
    remover for both (the core's removers)."""
    remove_prefix = target.register_event_prefix(EVENT_PREFIX, module=MODULE)
    remove_types = target.register_audit_mandatory_types(
        sorted(AUDIT_DUTY_EVENT_TYPES), module=MODULE
    )

    def remove() -> None:
        remove_types()
        remove_prefix()

    return remove


def new_correlation_id() -> str:
    """A fresh ``cor_<32 hex>`` for one diagnosis round or manual run."""
    return new_id(CORRELATION_ID_PREFIX)


def _check_correlation(correlation_id: str | None) -> str | None:
    if correlation_id is not None and not is_valid_id(
        correlation_id, CORRELATION_ID_PREFIX
    ):
        raise ValueError("not a correlation id")
    return correlation_id


def core_severity(severity: Severity) -> CoreSeverity:
    """Diag severity -> core severity (OK has no core value: INFO)."""
    return _SEVERITY[Severity(severity)]


def _value(item: Any) -> Any:
    return None if item is None else getattr(item, "value", item)


def _count(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, str | bytes) or not isinstance(value, Iterable):
        return 1
    return sum(1 for _ in value)


def _change_event(
    finding: Finding,
    router_id: str | None,
    correlation_id: str | None,
    key: bytes | None,
) -> DiagEvent:
    change = finding.change
    data: dict[str, Any] = {
        "classification": finding.classification.value,
        "point_kind": finding.point.kind.value,
        "stage": _value(finding.cause_stage),
        "family": _value(finding.family),
        "previous_count": _count(None if change is None else change.previous),
        "current_count": _count(None if change is None else change.current),
    }
    if key is not None:
        data.update(_change_pseudonyms(finding, key))
    return DiagEvent(
        event_type=_CHANGE_EVENTS[finding.classification],
        severity=core_severity(finding.severity),
        result=EventResult.INFO,
        router_id=router_id,
        dedup_key=None,  # each observed change is a fact of its own
        correlation_id=correlation_id,
        data=data,
        classification=finding.classification.value,
    )


def finding_event(
    finding: Finding,
    *,
    links: Iterable[CauseLink] = (),
    correlation_id: str | None = None,
    key: bytes | None = None,
) -> DiagEvent | None:
    """Event of one finding; ``None`` for no fault / not enough data.

    With the module ``key`` (:func:`async_identifier_key`) a gateway or DNS
    server change also names WHICH pseudonymous address changed; without
    it only counts.
    """
    correlation_id = _check_correlation(correlation_id)
    router_id = router_id_for(finding.point)
    if finding.classification in _CHANGE_EVENTS:
        return _change_event(finding, router_id, correlation_id, key)
    if not finding.is_problem or finding.severity == Severity.OK:
        return None
    linked = tuple(links)
    family = _value(finding.family) or "any"
    stage = _value(finding.cause_stage) or "none"
    return DiagEvent(
        event_type=EVENT_FINDING,
        severity=core_severity(finding.severity),
        result=EventResult.FAILURE,
        router_id=router_id,
        dedup_key=f"{finding.classification.value}:{family}:{stage}",
        correlation_id=correlation_id,
        data={
            "classification": finding.classification.value,
            "severity": finding.severity.value,
            "cause_class": finding.cause_class.value,
            "stage": _value(finding.cause_stage),
            "family": _value(finding.family),
            "underlying": _value(finding.underlying),
            "point_kind": finding.point.kind.value,
            "evidence_count": len(finding.evidence),
            "contradiction_count": len(finding.contradictions),
            "also_count": len(finding.also),
            "unmeasured_count": len(finding.unmeasured),
            "link_count": len(linked),
            "link_rules": sorted({link.rule for link in linked}),
        },
        classification=finding.classification.value,
    )


def _cause_router_ids(cause: Cause) -> list[str]:
    return sorted(
        {check_router_id(key) for key in cause.router_keys if key != HA_POINT_KEY}
    )


def cause_event(
    cause: Cause,
    links: Iterable[CauseLink],
    *,
    severity: Severity = Severity.WARNING,
    correlation_id: str | None = None,
) -> DiagEvent:
    """Event of one cause; ``severity`` = worst linked finding's severity.

    ``router_id`` follows :func:`location_router_id` (fleet id for WAN,
    resolver and segment causes).
    """
    correlation_id = _check_correlation(correlation_id)
    location = cause.location
    linked = tuple(links)
    family = _value(cause.family) or "any"
    return DiagEvent(
        event_type=EVENT_CAUSE,
        severity=core_severity(severity),
        result=EventResult.FAILURE,
        router_id=location_router_id(location),
        dedup_key=(
            f"{location.kind.value}:{cause.rule}:{family}:{cause.cause_class.value}"
        ),
        correlation_id=correlation_id,
        data={
            "location_kind": location.kind.value,
            "cause_class": cause.cause_class.value,
            "rule": cause.rule,
            "family": _value(cause.family),
            "router_ids": _cause_router_ids(cause),
            "router_count": len(cause.router_keys),
            "link_count": len(linked),
            "evidence_count": len(cause.evidence),
        },
        classification=cause.rule,
    )


def correlation_events(
    result: CorrelationResult,
    *,
    correlation_id: str | None = None,
    key: bytes | None = None,
) -> tuple[DiagEvent, ...]:
    """Events of one correlated round: findings first, then causes."""
    correlation_id = _check_correlation(correlation_id)
    events: list[DiagEvent] = []
    for index, finding in enumerate(result.findings):
        event = finding_event(
            finding,
            links=result.links_for(index),
            correlation_id=correlation_id,
            key=key,
        )
        if event is not None:
            events.append(event)
    for cause in result.causes:
        links = [link for link in result.links if link.cause_id == cause.cause_id]
        severities = [result.findings[link.finding_index].severity for link in links]
        worst = max(severities, key=SEVERITY_RANK.__getitem__, default=Severity.INFO)
        events.append(
            cause_event(cause, links, severity=worst, correlation_id=correlation_id)
        )
    return tuple(events)


def _kinds(kinds: Iterable[str]) -> list[str]:
    if isinstance(kinds, str):
        raise TypeError("kinds must be a collection")
    found = sorted({str(kind) for kind in kinds})
    if not found or set(found) - set(ALL_KINDS):
        raise ValueError("kinds must be a non-empty set of diag kinds")
    return found


def _run_result(status: str) -> EventResult:
    if status == "accepted":
        return EventResult.SUCCESS
    if status.startswith(("refused", "denied")):
        return EventResult.DENIED
    return EventResult.FAILURE


def manual_run_event(
    router_id: str | None,
    *,
    actor: Actor,
    status: str,
    kinds: Iterable[str],
    correlation_id: str | None = None,
) -> DiagEvent:
    """Audit record of a manual run (an audit-mandatory type).

    ``status`` is a ``diag_scheduler.RequestStatus`` value or ``denied``
    (guard); it is also the ``dedup_key`` (the discriminator; the core never
    deduplicates a registered mandatory type). The actor is kept in
    ``CoreEvent.actor``; data has no user id.
    """
    status = str(getattr(status, "value", status))
    return DiagEvent(
        event_type=EVENT_MANUAL_RUN,
        severity=CoreSeverity.INFO,
        result=_run_result(status),
        router_id=scheduler_key(router_id),
        dedup_key=status,
        correlation_id=_check_correlation(correlation_id),
        actor=actor,
        data={"status": status, "kinds": _kinds(kinds)},
    )


def router_probes_event(
    router_id: str,
    *,
    actor: Actor,
    kinds: Iterable[str],
    result: EventResult,
    correlation_id: str | None = None,
) -> DiagEvent:
    """Audit record of enabling router-side exec probes (audit-mandatory,
    security ring). ``dedup_key`` is ``enabled`` or ``disabled``."""
    enabled = _exec_kinds(kinds)
    return DiagEvent(
        event_type=EVENT_ROUTER_PROBES_CHANGED,
        severity=CoreSeverity.WARNING if enabled else CoreSeverity.INFO,
        result=EventResult(result),
        router_id=check_router_id(router_id),
        dedup_key="enabled" if enabled else "disabled",
        correlation_id=_check_correlation(correlation_id),
        actor=actor,
        data={"enabled_kinds": enabled, "enabled_count": len(enabled)},
        security_relevant=True,
    )


# =============================================================================
# Outputs (diagnostics, logs, event views)
# =============================================================================


def _renamed(value: Any) -> Any:
    if isinstance(value, Mapping):
        if set(value) == {"kind", "key"}:  # a MeasurementPoint
            return {"kind": value["kind"], "router_id": value["key"]}
        return {_RENAMES.get(k, k): _renamed(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_renamed(item) for item in value]
    return value


def _masked(data: Any, keys: Iterable[str] = OUTPUT_MASK_KEYS) -> Any:
    return mask_for_output(_renamed(plain(data)), extra_keys=tuple(keys))


def _brief_finding(finding: Finding) -> dict[str, Any]:
    return {
        "point_kind": finding.point.kind.value,
        "router_id": router_id_for(finding.point),
        "classification": finding.classification.value,
        "severity": finding.severity.value,
        "cause_class": finding.cause_class.value,
        "stage": _value(finding.cause_stage),
        "family": _value(finding.family),
        "underlying": _value(finding.underlying),
        "summary": finding.summary_key,
        "recommendation": finding.recommendation_key,
        "unmeasured_count": len(finding.unmeasured),
        "is_change": finding.classification in _CHANGE_EVENTS,
    }


def finding_output(
    finding: Finding, *, admin: bool, key: bytes | None = None
) -> dict[str, Any]:
    """Masked view of a finding.

    Detail only for ``admin`` (the caller got it from
    :func:`authorize_sensitive_read`). Change values are masked, or with the
    module ``key`` replaced by their pseudonyms; never shown raw.
    """
    if not admin:
        return mask_for_output(_brief_finding(finding))
    data = finding.to_dict()
    data["router_id"] = router_id_for(finding.point)
    keys: tuple[str, ...] = OUTPUT_MASK_KEYS
    if key is not None and finding.change is not None:
        data["change"] = _change_pseudonyms(finding, key)
        keys = tuple(k for k in OUTPUT_MASK_KEYS if k != "change")
    return _masked(data, keys)


def _brief_cause(cause: Cause) -> dict[str, Any]:
    return {
        "location_kind": cause.location.kind.value,
        "cause_class": cause.cause_class.value,
        "rule": cause.rule,
        "summary": cause.summary_key,
        "reason": cause.reason,
        "family": _value(cause.family),
        "router_ids": _cause_router_ids(cause),
    }


def correlation_output(
    result: CorrelationResult, *, admin: bool, key: bytes | None = None
) -> dict[str, Any]:
    """Masked view of one correlated round (detail only for ``admin``)."""
    causes = (
        [_masked(cause.to_dict()) for cause in result.causes]
        if admin
        else [mask_for_output(_brief_cause(cause)) for cause in result.causes]
    )
    return {
        "findings": [finding_output(f, admin=admin, key=key) for f in result.findings],
        "causes": causes,
        "links": [_masked(link.to_dict()) for link in result.links],
    }


def probe_output(probe: ProbeResult) -> dict[str, Any]:
    """Masked view of one probe result; raw evidence is always masked
    (detail behind the sensitive read, see SENSITIVE_READS)."""
    return _masked(probe.to_dict(), LOG_MASK_KEYS)


def log_safe(data: Any) -> Any:
    """Masked copy of any diag data for a log line."""
    return _masked(data, LOG_MASK_KEYS)


def actor_output(actor: Any, salt: bytes) -> dict[str, Any]:
    """Masked actor (``Actor`` or ``VerifiedActor``) with the user id
    replaced by its ``usr_`` pseudonym."""
    return mask_for_output(pseudonymise_user_ids(actor.to_dict(), salt))


def event_output(event: DiagEvent, salt: bytes) -> dict[str, Any]:
    """Masked, pseudonymised view of a module event (diagnostics, logs)."""
    return mask_for_output(pseudonymise_user_ids(_renamed(event.to_dict()), salt))


# =============================================================================
# router.forgotten
# =============================================================================


@dataclass(frozen=True)
class ForgetPlan:
    """Diag state to drop when the core forgets a router."""

    router_id: str
    scheduler_key: str
    series_keys: frozenset[SeriesKey] = frozenset()
    baselines: frozenset[tuple[SeriesKey, str]] = frozenset()
    job_ids: frozenset[str] = frozenset()

    @property
    def is_empty(self) -> bool:
        """True if nothing is kept for the router."""
        return not (self.series_keys or self.baselines or self.job_ids)


def forget_plan(
    router_id: str,
    *,
    series_keys: Iterable[SeriesKey] = (),
    baselines: Iterable[BaselineState] = (),
    jobs: Iterable[Any] = (),
) -> ForgetPlan:
    """What to drop for ``router_id``: its series keys, baselines (key,
    metric) and scheduler jobs (``job_id`` / ``router_key``). HA state and
    other routers are never part of it. Cancel with
    ``DiagScheduler.async_cancel_router(plan.scheduler_key)``."""
    router_id = check_router_id(router_id)
    point = series_point(router_id)
    return ForgetPlan(
        router_id=router_id,
        scheduler_key=router_id,
        series_keys=frozenset(k for k in series_keys if k.point == point),
        baselines=frozenset(
            (state.key, state.metric) for state in baselines if state.key.point == point
        ),
        job_ids=frozenset(
            job.job_id for job in jobs if getattr(job, "router_key", None) == router_id
        ),
    )


def forgotten_router_id(event: object) -> str | None:
    """Router id of a ``router.forgotten`` core event (object or bus
    payload); ``None`` for any other event or an invalid id."""
    if isinstance(event, CoreEvent):
        event_type, router_id = event.type, event.router_id
    elif isinstance(event, Mapping):
        event_type, router_id = event.get("type"), event.get("router_id")
    else:
        return None
    if event_type != CoreEventType.ROUTER_FORGOTTEN.value:
        return None
    return router_id if is_valid_id(router_id, ROUTER_ID_PREFIX) else None


# =============================================================================
# Docking (called by the caller, never at import)
# =============================================================================


def register_with_core(
    api: Any,
    extract_facts: FactsExtractor,
    *,
    clock: Callable[[], datetime] = utcnow,
    scheduler_limit: SchedulerRateLimit | None = None,
) -> Callable[[], None]:
    """Event prefix + audit-mandatory types, guard actions and capability
    detector on a ConfigurationApi; returns one remover for the detector,
    the mandatory types and the prefix (guard actions cannot be removed)."""
    remove_events = register_event_prefix(api)
    register_actions(api.guard, scheduler_limit=scheduler_limit)
    remove_detector = api.register_capability_detector(
        MODULE,
        make_detector(extract_facts, clock=clock),
        prefix=CAPABILITY_PREFIX,
        signature=make_signature(extract_facts),
    )

    def remove() -> None:
        remove_detector()
        remove_events()

    return remove
