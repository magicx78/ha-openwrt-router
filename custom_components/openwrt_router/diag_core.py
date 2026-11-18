"""Thin adapter between the pure diag modules and the enterprise core.

The ``diag_*`` modules know opaque router keys, opaque target ids and their
own enums. This module is the only place that says "router key = core
router id" (``rtr_<32 hex>``) and maps diag results onto the Configuration
API v1 contract (docs/dev/configuration-api-v1.md, sections 6, 13 and 17).
It holds pure mapping functions only: no I/O, no scheduling, no entities,
nothing runs at import (the ``register_*`` helpers are called by the
caller).

Identity
    The Home Assistant measurement point is keyed ``"ha"`` (``PointKind.HA``)
    in series keys and labels; that can never be a core router id, and every
    router key passing this adapter is checked with ``is_valid_id(.., rtr_)``.
    In core events the HA point (and a fleet-wide cause) has
    ``router_id=None`` (dedup scope ``"-"``); the scheduler uses ``None``.

Events
    Module ``net_diagnostics``, event prefix ``net_diagnostics.``, capability
    prefix ``diag.`` (core tables MODULE_EVENT_PREFIXES /
    MODULE_CAPABILITY_NAMESPACES). Event data carries enum codes, counters
    and router ids only: never a target id, address, hostname, change value
    or user id. No incidents are created.

Masking
    Every output (diagnostics, logs, event views) goes through
    ``core_masking.mask_for_output``; change records, excluded probes and
    raw probe evidence are masked by key, actors are pseudonymised with
    ``core_masking.pseudonymise_user_ids``.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Final

from .core_masking import mask_for_output, pseudonymise_user_ids
from .core_models import (
    CORRELATION_ID_PREFIX,
    MODULE_CAPABILITY_NAMESPACES,
    MODULE_EVENT_PREFIXES,
    ROUTER_ID_PREFIX,
    ActionClass,
    Actor,
    ActorKind,
    Capability,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    CoreEvent,
    CoreEventType,
    EventResult,
    RouterRecord,
    VerifiedActor,
    binding_checksum,
    is_valid_id,
    new_id,
    utcnow,
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
    LocationKind,
    MeasurementPoint,
    PointKind,
    ProbeResult,
    Severity,
    plain,
)
from .diag_stats import SeriesKey

_LOGGER = logging.getLogger(__name__)

# --- module identity ------------------------------------------------------------

MODULE: Final = "net_diagnostics"
EVENT_PREFIX: Final = MODULE_EVENT_PREFIXES[MODULE]  # "net_diagnostics."
CAPABILITY_PREFIX: Final = MODULE_CAPABILITY_NAMESPACES[MODULE]  # "diag."
HA_POINT_KEY: Final = PointKind.HA.value  # never a valid rtr_ id

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
        # rpcd file exec on the tool; the core ACL tier registry refuses
        # file exec in optional tiers today (contract gap, see report).
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
# Acts of a person: always recorded, never deduplicated (dedup_key None).
# The core cannot mark module types audit-mandatory (contract gap).
AUDIT_DUTY_EVENT_TYPES: Final = frozenset(
    {EVENT_MANUAL_RUN, EVENT_ROUTER_PROBES_CHANGED}
)
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

# Keys whose whole value is masked in diagnostics output: change values and
# probes excluded from a chain (their raw evidence may hold addresses).
OUTPUT_MASK_KEYS: Final = ("change", "excluded")
# Logs also mask raw probe evidence wherever it appears.
LOG_MASK_KEYS: Final = (*OUTPUT_MASK_KEYS, "evidence")
# Detail only a verified admin user may read (contract: sensitive reads).
SENSITIVE_READS: Final = frozenset(
    {"chain", "evidence", "probe", "change", "reasons", "location"}
)
# core_masking treats ``*_key`` names as secret; diag i18n keys and router
# keys are renamed so they stay readable after masking.
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
    """Capability detector for ``register_capability_detector`` (sync, no I/O)."""

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
    """A guarded module action. ``agreed_name`` is the planned ``diag.*``
    name; the guard requires ``<module>.<action>``, so ``name`` is used."""

    name: str
    action_class: ActionClass
    admin_user_only: bool
    agreed_name: str


# Active but not mutating, admin only: no such class; READ + admin_user_only
# is the closest (immediate decision, verified admin users only, audited).
ACTION_RUN_MANUAL: Final = DiagAction(
    name=f"{MODULE}.run_manual",
    action_class=ActionClass.READ,
    admin_user_only=True,
    agreed_name="diag.run_manual",
)
# Most restricted class: request + admin approval + single use.
ACTION_ENABLE_ROUTER_PROBES: Final = DiagAction(
    name=f"{MODULE}.enable_router_probes",
    action_class=ActionClass.CRITICAL,
    admin_user_only=True,
    agreed_name="diag.enable_router_probes",
)
DIAG_ACTIONS: Final = (ACTION_RUN_MANUAL, ACTION_ENABLE_ROUTER_PROBES)


def register_actions(guard: Any) -> tuple[str, ...]:
    """Register the module actions with ``guard`` (``api.guard`` or the core
    ActionGuard). Idempotent; never called at import."""
    for action in DIAG_ACTIONS:
        guard.register_action(
            action.name,
            action.action_class,
            module=MODULE,
            admin_user_only=action.admin_user_only,
        )
    return tuple(action.name for action in DIAG_ACTIONS)


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


def may_read_sensitive(reader: object, *, now: datetime | None = None) -> bool:
    """Sensitive diag reads, by the core's content-read rule (contract 6.3):
    a user must be a freshly verified admin; module, system and automation
    actors read without admin rights. Anything unverified is refused."""
    if not isinstance(reader, VerifiedActor) or not reader.is_fresh(now):
        return False
    return reader.actor.kind is not ActorKind.USER or reader.is_admin


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

    def __post_init__(self) -> None:
        if self.event_type not in DIAG_EVENT_TYPES:
            raise ValueError("unknown diag event type")
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
            "actor": None if self.actor is None else self.actor.to_dict(),
            "data": plain(dict(self.data)),
        }


def register_event_prefix(target: Any) -> None:
    """Allow the module's event types on ``target`` (api or AuditLog)."""
    target.register_event_prefix(EVENT_PREFIX, module=MODULE)


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
    finding: Finding, router_id: str | None, correlation_id: str | None
) -> DiagEvent:
    change = finding.change
    return DiagEvent(
        event_type=_CHANGE_EVENTS[finding.classification],
        severity=core_severity(finding.severity),
        result=EventResult.INFO,
        router_id=router_id,
        dedup_key=None,  # each observed change is a fact of its own
        correlation_id=correlation_id,
        data={
            "classification": finding.classification.value,
            "point_kind": finding.point.kind.value,
            "stage": _value(finding.cause_stage),
            "family": _value(finding.family),
            "previous_count": _count(None if change is None else change.previous),
            "current_count": _count(None if change is None else change.current),
        },
    )


def finding_event(
    finding: Finding,
    *,
    links: Iterable[CauseLink] = (),
    correlation_id: str | None = None,
) -> DiagEvent | None:
    """Event of one finding; ``None`` for no fault / not enough data."""
    correlation_id = _check_correlation(correlation_id)
    router_id = router_id_for(finding.point)
    if finding.classification in _CHANGE_EVENTS:
        return _change_event(finding, router_id, correlation_id)
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
    """Event of one cause; ``severity`` = worst linked finding's severity."""
    correlation_id = _check_correlation(correlation_id)
    location = cause.location
    router_id = (
        check_router_id(location.id) if location.kind == LocationKind.ROUTER else None
    )
    linked = tuple(links)
    family = _value(cause.family) or "any"
    return DiagEvent(
        event_type=EVENT_CAUSE,
        severity=core_severity(severity),
        result=EventResult.FAILURE,
        router_id=router_id,
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
    )


def correlation_events(
    result: CorrelationResult, *, correlation_id: str | None = None
) -> tuple[DiagEvent, ...]:
    """Events of one correlated round: findings first, then causes."""
    correlation_id = _check_correlation(correlation_id)
    events: list[DiagEvent] = []
    for index, finding in enumerate(result.findings):
        event = finding_event(
            finding, links=result.links_for(index), correlation_id=correlation_id
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
    """Audit record of a manual run (audit duty: never deduplicated).

    ``status`` is a ``diag_scheduler.RequestStatus`` value or ``denied``
    (guard). The actor is kept in ``CoreEvent.actor``; data has no user id.
    """
    status = str(getattr(status, "value", status))
    return DiagEvent(
        event_type=EVENT_MANUAL_RUN,
        severity=CoreSeverity.INFO,
        result=_run_result(status),
        router_id=scheduler_key(router_id),
        dedup_key=None,
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
    """Audit record of enabling router-side exec probes (audit duty)."""
    enabled = _exec_kinds(kinds)
    return DiagEvent(
        event_type=EVENT_ROUTER_PROBES_CHANGED,
        severity=CoreSeverity.WARNING if enabled else CoreSeverity.INFO,
        result=EventResult(result),
        router_id=check_router_id(router_id),
        dedup_key=None,
        correlation_id=_check_correlation(correlation_id),
        actor=actor,
        data={"enabled_kinds": enabled, "enabled_count": len(enabled)},
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


def finding_output(finding: Finding, *, admin: bool) -> dict[str, Any]:
    """Masked view of a finding; detail only for ``admin`` (see
    :func:`may_read_sensitive`). Change values are masked even then."""
    if not admin:
        return mask_for_output(_brief_finding(finding))
    data = finding.to_dict()
    data["router_id"] = router_id_for(finding.point)
    return _masked(data)


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


def correlation_output(result: CorrelationResult, *, admin: bool) -> dict[str, Any]:
    """Masked view of one correlated round (detail only for ``admin``)."""
    causes = (
        [_masked(cause.to_dict()) for cause in result.causes]
        if admin
        else [mask_for_output(_brief_cause(cause)) for cause in result.causes]
    )
    return {
        "findings": [finding_output(f, admin=admin) for f in result.findings],
        "causes": causes,
        "links": [_masked(link.to_dict()) for link in result.links],
    }


def probe_output(probe: ProbeResult) -> dict[str, Any]:
    """Masked view of one probe result; raw evidence is always masked
    (admin-only read, see SENSITIVE_READS)."""
    return _masked(probe.to_dict(), LOG_MASK_KEYS)


def log_safe(data: Any) -> Any:
    """Masked copy of any diag data for a log line."""
    return _masked(data, LOG_MASK_KEYS)


def actor_output(actor: Actor | VerifiedActor, salt: bytes) -> dict[str, Any]:
    """Masked actor with the user id replaced by its ``usr_`` pseudonym."""
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
) -> Callable[[], None]:
    """Event prefix, guard actions and capability detector on a
    ConfigurationApi; returns the detector's remove callable."""
    register_event_prefix(api)
    register_actions(api.guard)
    return api.register_capability_detector(
        MODULE,
        make_detector(extract_facts, clock=clock),
        prefix=CAPABILITY_PREFIX,
        signature=make_signature(extract_facts),
    )
