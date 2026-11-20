"""Network diagnostics: run time and life cycle (release 1.47.0, part 1).

One fleet-wide :class:`NetDiagnostics` per Home Assistant instance, wired
like the Security Center: set up after the base setup of each entry,
released after its unload (``__init__.py``). It docks the pure ``diag_*``
modules onto the enterprise core (``diag_core``), the network intelligence
poll observer and the measurement block at the end of ``api.py``.

Defaults are OFF (``enabled`` False): only the store is read, nothing is
registered with the core, no observer, no scheduler, no packet and no router
call. Switched on:

* Passive: every poll the network intelligence engine ingests is handed to
  :meth:`NetDiagnostics.on_poll` (``net_engine.add_poll_observer``). The
  router's chain is evaluated from that poll's data only (WAN status and the
  ``diag_facts`` of the interface dump); no second coordinator listener, no
  extra router call. DHCP pool usage is taken over from the poll as is.
* Active, Home Assistant side only: a manual run by a verified admin through
  the core guard (``diag_core.authorize_manual_run``, rate limited), or
  periodic rounds when an admin turned ``periodic`` on AND at least one
  confirmed target exists. Probes come from ``api.py`` (TCP, DNS, HTTP;
  ICMP is not available on the HA side).
* Router exec probes: not available (no executor, no new ACL right).

Not ready / unknown: without the core, the module key, the registry's
router id or the interface dump a state is ``unknown`` or ``not_ready``
with a reason; never ``ok``. Events go through ``diag_core`` with
pseudonyms made with the module key; without the key no finding event is
sent (counted as ``events_not_ready``).

Failure isolation: no exception leaves a poll observer call, a setup or an
unload; each stage fails on its own (WARNING with the exception type only,
details at DEBUG). Logs above DEBUG carry no address, host or domain.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque
from collections.abc import Callable, Coroutine, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Final

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .api import (
    DIAG_DEFAULT_TRANSPORT,
    DIAG_HTTP_PATH,
    DIAG_PACKETS_PER_PROBE,
    DIAG_REASON_ICMP_NOT_ON_HA,
    DIAG_REASON_INTERNAL,
    DiagTransport,
    async_diag_probe,
    async_diag_resolve,
)
from .const import (
    DATA_NET_DIAGNOSTICS,
    DIAG_CONFIG_NOTES_MAX,
    DIAG_CONTEXT_CACHE_SECONDS,
    DIAG_CONTEXT_WINDOW_SECONDS,
    DIAG_DEFAULT_INTERVAL_SECONDS,
    DIAG_LOSS_ROUNDS,
    DIAG_MAX_INTERVAL_SECONDS,
    DIAG_MAX_TARGETS,
    DIAG_MIN_INTERVAL_SECONDS,
    DIAG_MODULE_KEY_RETRY_SECONDS,
    DIAG_SETTLE_SECONDS,
    SIGNAL_NET_DIAGNOSTICS,
)
from .core_errors import AuthorizationError, ConfigApiError, ErrorClass
from .core_guard import error_for_decision
from .core_models import (
    FLEET_ROUTER_ID,
    ROUTER_ID_PREFIX,
    ActionClass,
    Actor,
    CoreEventType,
    InstallationKeyState,
    VerifiedActor,
    is_valid_id,
)
from .diag_baseline import (
    LATENCY_CONFIG,
    LOSS_CONFIG,
    BaselineConfig,
    Observation,
    new_baseline,
    observe,
)
from .diag_causes import correlate
from .diag_chain import (
    ChainFacts,
    classify,
    dns_server_change,
    evaluate_chain,
    gateway_change,
)
from .diag_context import (
    ConfigChange,
    FindingContext,
    SecurityIncident,
    SourceState,
    SourceView,
    context_for,
)
from .diag_core import (
    ACTION_RUN_MANUAL,
    EXEC_KINDS,
    HA_POINT_KEY,
    HA_PROBE_KINDS,
    KIND_HA_DNS,
    KIND_HA_HTTP,
    KIND_HA_TCP,
    MODULE,
    DiagRouterFacts,
    async_identifier_key,
    authorize_manual_run,
    authorize_sensitive_read,
    correlation_events,
    error_for_refusal,
    error_for_run_request,
    finding_output,
    forget_plan,
    forgotten_router_id,
    manual_run_event,
    new_correlation_id,
    point_for,
    refusal_reason,
    register_with_core,
    series_key,
)
from .diag_model import (
    AddressFamily,
    Basis,
    Classification,
    Finding,
    MeasurementPoint,
    ProbeKind,
    ProbeOutcome,
    ProbeResult,
    Stage,
    StageState,
)
from .diag_scheduler import (
    DiagJob,
    DiagScheduler,
    RunResult,
    SchedulerConfig,
)
from .diag_score import COMP_WAN, Reading, ScoreInputs, compute_score
from .diag_stats import WINDOWS, Sample, SeriesKey
from .diag_store import (
    GAP_HA_RESTART,
    GAP_ROUTER_RESTART,
    DiagStore,
    async_final_flush,
)
from .diag_targets import (
    PendingTarget,
    PinnedTarget,
    Refusal,
    ScopePolicy,
    TargetKind,
    TargetRegistry,
    TargetScope,
    make_target,
    normalize_host,
)
from .net_events import Category as NiCategory
from .net_events import Severity as NiSeverity
from .net_events import Source as NiSource
from .net_rules import (
    DIAG_DNS_SERVER_CHANGED_KIND,
    DIAG_DNS_SERVER_CHANGED_TYPE,
    DIAG_GATEWAY_CHANGED_KIND,
    DIAG_GATEWAY_CHANGED_TYPE,
)
from .net_rules import Finding as NiFinding

_LOGGER = logging.getLogger(__name__)

# --- names and limits -------------------------------------------------------------

JOB_MANUAL: Final = "ha_manual"
JOB_PERIODIC: Final = "ha_periodic"
JOB_KIND: Final = "ha_probe"
# Worst case of one round: every target resolves (3 s) and probes (5 s).
RUN_TIMEOUT_SECONDS: Final = float(DIAG_MAX_TARGETS * 8 + 10)
# A router poll older than this many intervals (at least 10 min) is stale.
STALE_INTERVALS: Final = 3
STALE_MIN_SECONDS: Final = 600.0
DAY_SECONDS: Final = 86400.0

# Passive WAN series of a router (one per router, from the poll).
WAN_TARGET: Final = "wan_up"
WAN_KIND: Final = ProbeKind.FACT.value

# Guarded settings change (admin users only, audited by the guard). Kept out
# of ``diag_core.DIAG_ACTIONS`` (that tuple is the contract's action list).
ACTION_UPDATE_SETTINGS: Final = f"{MODULE}.update_settings"

# Module states and reasons (stable codes).
STATE_OFF: Final = "off"
STATE_NOT_READY: Final = "not_ready"
STATE_READY: Final = "ready"
R_STATE_UNKNOWN: Final = "unknown"
R_STATE_OK: Final = "ok"
R_STATE_PARTIAL: Final = "partial"
R_STATE_PROBLEM: Final = "problem"
R_STATE_SETTLING: Final = "settling"

REASON_DISABLED: Final = "disabled"
REASON_CLOSED: Final = "closed"
REASON_CORE_UNAVAILABLE: Final = "core_unavailable"
REASON_EVENTS_NOT_REGISTERED: Final = "events_not_registered"
REASON_MODULE_KEY_MISSING: Final = "module_key_missing"
REASON_ENGINE_UNAVAILABLE: Final = "engine_unavailable"
REASON_SCHEDULER_NOT_RUNNING: Final = "scheduler_not_running"
REASON_NO_DATA_YET: Final = "no_data_yet"
REASON_STALE: Final = "stale"
REASON_POLL_FAILED: Final = "poll_failed"
REASON_INTERFACE_DUMP_MISSING: Final = "interface_dump_missing"
REASON_NO_ROUTER_ID: Final = "router_id_unknown"
REASON_NO_CONFIRMED_TARGET: Final = "no_confirmed_target"
REASON_NO_MEASUREMENT: Final = "no_measurement_yet"
REASON_NO_EXECUTOR: Final = "no_executor"
REASON_ACTOR_REQUIRED: Final = "actor_required"
REASON_INVALID_SETTINGS: Final = "invalid_settings"

_COUNTERS: Final = (
    "errors",
    "polls",
    "polls_unmapped",
    "rounds",
    "probes",
    "probe_packets",
    "targets_refused",
    "events",
    "events_not_ready",
    "manual_runs",
    "manual_refused",
    "settings_changes",
    "router_restarts",
    "clock_shifts",
    "baselines_out_of_order",
)

_TARGET_KINDS: Final[Mapping[TargetKind, str]] = {
    TargetKind.TCP: KIND_HA_TCP,
    TargetKind.DNS: KIND_HA_DNS,
    TargetKind.HTTP: KIND_HA_HTTP,
}
_PATH_RE: Final = re.compile(r"/[A-Za-z0-9._~/-]{0,63}")
_SETTING_KEYS: Final = (
    "enabled",
    "periodic",
    "interval_s",
    "targets",
    "internal_networks",
    "local_domains",
    "dns_query_name",
    "http_path",
    "ha_resolver_internal",
)
_TARGET_KEYS: Final = frozenset(
    {"id", "kind", "scope", "host", "port", "confirmed", "stage"}
)


# =============================================================================
# Settings
# =============================================================================


class DiagSettingsError(ValueError):
    """An invalid settings value; ``reason`` is a code, never the input."""

    def __init__(self, reason: str) -> None:
        """Keep the reason code."""
        super().__init__(reason)
        self.reason = reason


def default_settings() -> dict[str, Any]:
    """Defaults: everything off, no target."""
    return {
        "enabled": False,
        "periodic": False,
        "interval_s": DIAG_DEFAULT_INTERVAL_SECONDS,
        "targets": [],
        "internal_networks": [],
        "local_domains": [],
        "dns_query_name": None,
        "http_path": DIAG_HTTP_PATH,
        "ha_resolver_internal": False,
    }


def _bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise DiagSettingsError(f"{name}.not_bool")
    return value


def _interval(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise DiagSettingsError("interval_s.not_int")
    if not DIAG_MIN_INTERVAL_SECONDS <= value <= DIAG_MAX_INTERVAL_SECONDS:
        raise DiagSettingsError("interval_s.out_of_range")
    return value


def _str_list(name: str, value: Any, limit: int = 32) -> list[str]:
    if not isinstance(value, list | tuple) or len(value) > limit:
        raise DiagSettingsError(f"{name}.not_list")
    if not all(isinstance(item, str) for item in value):
        raise DiagSettingsError(f"{name}.not_str")
    return list(value)


def _target(raw: Any) -> dict[str, Any]:
    """One configured target, normalised (``make_target`` checks the syntax)."""
    if not isinstance(raw, Mapping) or set(raw) - _TARGET_KEYS:
        raise DiagSettingsError("targets.invalid")
    confirmed = raw.get("confirmed", False)
    if not isinstance(confirmed, bool):
        raise DiagSettingsError("targets.confirmed.not_bool")
    port = raw.get("port")
    built = make_target(
        raw.get("id"),
        raw.get("kind"),
        raw.get("scope"),
        raw.get("host"),
        port=port,
        confirmed=confirmed,
    )
    if isinstance(built, Refusal):
        raise DiagSettingsError(refusal_reason(built))
    stage = raw.get("stage")
    if stage is not None:
        try:
            stage = Stage(stage).value
        except ValueError:
            raise DiagSettingsError("targets.stage.invalid") from None
    return {
        "id": built.target_id,
        "kind": built.kind.value,
        "scope": built.scope.value,
        "host": built.host,
        "port": built.port,
        "confirmed": built.confirmed,
        "stage": stage,
    }


def _targets(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list | tuple):
        raise DiagSettingsError("targets.not_list")
    if len(value) > DIAG_MAX_TARGETS:
        raise DiagSettingsError("targets.too_many")
    out = [_target(item) for item in value]
    if len({t["id"] for t in out}) != len(out):
        raise DiagSettingsError(refusal_reason(Refusal.DUPLICATE_ID))
    return out


def _query_name(value: Any) -> str | None:
    if value is None:
        return None
    name = normalize_host(value)
    if not isinstance(name, str) or re.fullmatch(r"[0-9.]+|.*:.*", name):
        raise DiagSettingsError("dns_query_name.invalid")
    return name


def _path(value: Any) -> str:
    if not isinstance(value, str) or not _PATH_RE.fullmatch(value):
        raise DiagSettingsError("http_path.invalid")
    return value


_CHECKS: Final[Mapping[str, Callable[[Any], Any]]] = {
    "enabled": lambda v: _bool("enabled", v),
    "periodic": lambda v: _bool("periodic", v),
    "interval_s": _interval,
    "targets": _targets,
    "internal_networks": lambda v: _str_list("internal_networks", v),
    "local_domains": lambda v: _str_list("local_domains", v),
    "dns_query_name": _query_name,
    "http_path": _path,
    "ha_resolver_internal": lambda v: _bool("ha_resolver_internal", v),
}


def _policy(settings: Mapping[str, Any]) -> ScopePolicy:
    try:
        return ScopePolicy.from_config(
            settings.get("internal_networks") or (),
            settings.get("local_domains") or (),
        )
    except (TypeError, ValueError):
        raise DiagSettingsError("scope_policy.invalid") from None


def parse_settings(raw: Any) -> dict[str, Any]:
    """Stored settings -> valid settings (tolerant: a bad field -> default).

    A damaged scope policy falls back to the empty one (fewer internal
    names, never more).
    """
    settings = default_settings()
    if not isinstance(raw, Mapping):
        return settings
    for name, check in _CHECKS.items():
        if name not in raw:
            continue
        try:
            settings[name] = check(raw[name])
        except DiagSettingsError:
            _LOGGER.warning(
                "Network diagnostics setting %s unreadable; default used", name
            )
    try:
        _policy(settings)
    except DiagSettingsError:
        settings["internal_networks"] = []
        settings["local_domains"] = []
    return settings


def merge_settings(current: Mapping[str, Any], update: Any) -> dict[str, Any]:
    """``current`` changed by ``update`` (strict: DiagSettingsError).

    A changed target list or scope policy must pass the target registry as
    a whole (address class, scope, registry limits); a stored setting that
    no longer does is kept by :func:`parse_settings` and shown as refused.
    """
    if not isinstance(update, Mapping):
        raise DiagSettingsError("settings.not_mapping")
    unknown = set(update) - set(_SETTING_KEYS)
    if unknown:
        raise DiagSettingsError("settings.unknown_key")
    merged = {**default_settings(), **dict(current)}
    for name, value in update.items():
        merged[name] = _CHECKS[name](value)
    _policy(merged)
    if {"targets", "internal_networks", "local_domains"} & set(update):
        _registry, refused = build_registry(merged)
        if refused:
            raise DiagSettingsError(refusal_reason(refused[0][1]))
    return merged


def build_registry(
    settings: Mapping[str, Any],
) -> tuple[TargetRegistry, list[tuple[str, Refusal]]]:
    """Target registry of the settings plus the refused targets (id, reason)."""
    try:
        policy = _policy(settings)
    except DiagSettingsError:
        policy = ScopePolicy()
    targets = []
    refused: list[tuple[str, Refusal]] = []
    for raw in settings.get("targets") or ():
        built = make_target(
            raw.get("id"),
            raw.get("kind"),
            raw.get("scope"),
            raw.get("host"),
            port=raw.get("port"),
            confirmed=raw.get("confirmed") is True,
        )
        if isinstance(built, Refusal):
            refused.append((str(raw.get("id")), built))
        else:
            targets.append(built)
    registry, more = TargetRegistry.build(policy, targets, max_targets=DIAG_MAX_TARGETS)
    return registry, refused + more


def extract_router_facts(data: Any) -> DiagRouterFacts | None:
    """Capability facts of one poll (``diag_core`` detector input).

    The interface dump counts as present when the poll carried the
    ``diag_facts`` of ``get_wan_status``; without them it is unknown (SSH
    fallback, empty dump). Router exec is never permitted (no executor).
    """
    wan = getattr(data, "wan_status", None)
    if not isinstance(wan, Mapping):
        return None
    dump = True if isinstance(wan.get("diag_facts"), Mapping) else None
    return DiagRouterFacts(interface_dump=dump, exec_permitted=False)


def chain_facts(wan: Mapping[str, Any], facts: Mapping[str, Any]) -> ChainFacts:
    """``ChainFacts`` of one router from its WAN status and ``diag_facts``."""
    total, up = facts.get("interfaces"), facts.get("interfaces_up")
    interface_up = None
    if isinstance(total, int) and isinstance(up, int) and total > 0:
        interface_up = up > 0
    # part 2: a LAN interface that should be up and is down fails the fact
    # (direct evidence); absent key: the part 1 rule above alone
    if interface_up and down_interfaces(facts):
        interface_up = False
    route4 = facts.get("ipv4_default_route")
    route6 = facts.get("ipv6_default_route")
    route4 = route4 if isinstance(route4, bool) else None
    route6 = route6 if isinstance(route6, bool) else None
    wan_found = wan.get("wan_found")
    wan_up_v4 = bool(wan.get("connected")) if wan_found is True else None
    return ChainFacts(
        management_reachable=True,
        interface_up=interface_up,
        default_route_v4=route4,
        default_route_v6=route6,
        wan_up_v4=wan_up_v4,
        wan_up_v6=None,  # no per-family WAN state in the poll
        ipv4_configured=True,
        ipv6_configured=facts.get("ipv6_global_address") is True or route6 is True,
    )


def down_interfaces(facts: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The ``down_interfaces`` of the facts (name and vlan flag only)."""
    raw = facts.get("down_interfaces")
    if not isinstance(raw, list):
        return []
    return [
        {"name": str(item.get("name"))[:32], "vlan": item.get("vlan") is True}
        for item in raw[:16]
        if isinstance(item, Mapping) and isinstance(item.get("name"), str)
    ]


def _address(value: Any) -> str | None:
    if isinstance(value, Mapping) and isinstance(value.get("address"), str):
        return value["address"]
    return None


def _servers(facts: Mapping[str, Any]) -> list[str] | None:
    raw = facts.get("dns_servers")
    if not isinstance(raw, list):
        return None
    return [a for a in (_address(item) for item in raw) if a is not None]


def probe_sample(probe: ProbeResult) -> Sample:
    """Statistics sample of one probe: answered, lost or a gap.

    Answered: OK, or NXDOMAIN (the resolver works), with an rtt. A gap:
    nothing measured (SKIPPED, an internal error). Everything else is lost.
    """
    ts = probe.timestamp
    if probe.outcome in (ProbeOutcome.OK, ProbeOutcome.NXDOMAIN) and (
        probe.rtt_ms is not None
    ):
        return Sample.answered(ts, probe.rtt_ms)
    if probe.outcome is ProbeOutcome.SKIPPED or (
        probe.outcome is ProbeOutcome.ERROR
        and probe.evidence.get("reason") == DIAG_REASON_INTERNAL
    ):
        return Sample.gap(ts)
    return Sample.lost(ts)


def _finding_brief(finding: Finding | None) -> dict[str, Any] | None:
    if finding is None:
        return None
    return {
        "classification": finding.classification.value,
        "severity": finding.severity.value,
        "cause_class": finding.cause_class.value,
        "stage": None if finding.cause_stage is None else finding.cause_stage.value,
        "family": None if finding.family is None else finding.family.value,
        "unmeasured": list(finding.unmeasured),
    }


def _finding_state(finding: Finding) -> tuple[str, str]:
    """(state, reason) of a chain finding: ``ok`` only for no fault."""
    if finding.classification is Classification.NO_FAULT_DETECTED:
        return R_STATE_OK, finding.classification.value
    if finding.classification is Classification.PARTIALLY_MEASURED:
        return R_STATE_PARTIAL, finding.classification.value
    if finding.classification is Classification.INSUFFICIENT_DATA:
        return R_STATE_UNKNOWN, finding.classification.value
    return R_STATE_PROBLEM, finding.classification.value


def _signature(finding: Finding) -> tuple[Any, ...]:
    return (finding.classification, finding.family, finding.cause_stage)


def _default_task_factory(hass: HomeAssistant) -> Any:
    """Background task factory for the scheduler loop (cancelled at HA stop)."""

    def factory(coro: Coroutine[Any, Any, None], name: str) -> asyncio.Task[None]:
        return hass.async_create_background_task(coro, name)

    return factory


# =============================================================================
# State
# =============================================================================


@dataclass
class _Binding:
    """What the module holds of the running core (released on deactivate)."""

    core: Any = None
    api: Any = None
    removers: list[Callable[[], None]] = field(default_factory=list)
    events_ok: bool = False
    actions_ok: bool = False


@dataclass
class _RouterState:
    """Memory-only state of one router (rebuilt from the next poll)."""

    last_poll: float | None = None
    prev_poll: float | None = None
    interval: float | None = None
    state: str = R_STATE_UNKNOWN
    reason: str = REASON_NO_DATA_YET
    finding: Finding | None = None
    sent: tuple[Any, ...] | None = None  # signature of the last finding event
    gateway: dict[AddressFamily, str] = field(default_factory=dict)
    dns: list[str] | None = None
    settling: bool = False
    wan_applicable: bool | None = None
    dhcp_pools: list[dict[str, Any]] = field(default_factory=list)
    # part 2: since when the current finding holds, the LAN interfaces that
    # are down, and the change findings the NI finding source computed for
    # this poll's data (taken over by the poll observer, never twice)
    finding_at: float | None = None
    down: list[dict[str, Any]] = field(default_factory=list)
    pending: tuple[Any, list[Finding]] | None = None


# =============================================================================
# Life cycle
# =============================================================================


@callback
def async_get_net_diagnostics(hass: HomeAssistant) -> NetDiagnostics | None:
    """The running module, or None."""
    diag = hass.data.get(DATA_NET_DIAGNOSTICS)
    return diag if isinstance(diag, NetDiagnostics) else None


async def async_setup_net_diagnostics(
    hass: HomeAssistant, entry: Any, coordinator: Any
) -> NetDiagnostics:
    """Create/load the per-HA module once and add this entry to it.

    Runs after the base setup (network intelligence, core, Security
    Center). Off by default: then only the store is read.
    """
    diag = async_get_net_diagnostics(hass)
    if diag is None:
        diag = NetDiagnostics(hass)
        hass.data[DATA_NET_DIAGNOSTICS] = diag
    await diag.async_load()
    diag.add_entry(entry.entry_id, coordinator)
    if diag.enabled:
        await diag.async_activate()
    # part 2: routes (registered once, answer "off" while off) and entities
    # (created while on, removed from the registry while off)
    try:
        from .diag_views import async_register_diag_views

        async_register_diag_views(hass)
    except Exception as err:  # noqa: BLE001 - the module works without them
        diag._fail("routes", err)
    await diag._async_sync_entities()
    return diag


async def async_release_net_diagnostics(hass: HomeAssistant, entry_id: str) -> None:
    """Drop the entry; after the last one stop everything and write the store."""
    diag = async_get_net_diagnostics(hass)
    if diag is None:
        return
    diag.remove_entry(entry_id)
    try:
        from .diag_entities import async_entry_released

        await async_entry_released(hass, entry_id, last=not diag.entry_count)
    except Exception as err:  # noqa: BLE001 - the release goes on
        diag._fail("entities", err)
    if diag.entry_count:
        return
    hass.data.pop(DATA_NET_DIAGNOSTICS, None)
    try:
        await diag.async_close()
    except Exception as err:  # noqa: BLE001 - the store is still written
        diag._fail("close", err)
    await async_final_flush(hass, diag.store)


class NetDiagnostics:
    """Fleet-wide network diagnostics: passive chains, HA probes, history."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Empty module; ``async_load`` reads the store."""
        self.hass = hass
        self.store = DiagStore(hass, parse_settings=parse_settings)
        self.active = False
        self._closed = False
        self.counters: dict[str, int] = dict.fromkeys(_COUNTERS, 0)
        self.registry, self.refused_targets = build_registry(default_settings())
        self._entries: dict[str, Any] = {}
        self._rid_cache: dict[str, str] = {}
        self._routers: dict[str, _RouterState] = {}
        self._rounds: dict[SeriesKey, deque[bool]] = {}
        self._binding = _Binding()
        self._module_key: bytes | None = None
        self._key_tried: float | None = None
        self._key_warned = False
        self._engine: Any = None
        self._engine_unsub: Callable[[], None] | None = None
        self.scheduler: DiagScheduler | None = None
        self._periodic_interval: float | None = None
        self._manual_plan: tuple[tuple[str, ...], str] | None = None
        self._ha_finding: Finding | None = None
        self._ha_sent: tuple[Any, ...] | None = None
        self._ha_last: dict[str, Any] | None = None
        # part 2: last HA round per probe, when the HA finding began, the
        # NI finding source, context sources, the entity view
        self._ha_probes: list[dict[str, Any]] = []
        self._ha_finding_at: float | None = None
        self._source_unsub: Callable[[], None] | None = None
        self._config_notes: dict[tuple[str, str], dict[str, Any]] = {}
        self._config_since: float | None = None
        self._drift_task: asyncio.Task[None] | None = None
        self._drift_again = False
        self._security_cache: dict[str, tuple[float, int, SourceView]] = {}
        self.view: dict[str, Any] | None = None
        self.loaded = False
        # Test seams: entry id -> core router id, probe transport, clocks,
        # scheduler limits and the factory of its loop task.
        self.router_id_of: Callable[[str], str | None] = self._registry_router_id
        # part 2 seams: context sources (read only) and the drift areas
        self.config_runtime_of: Callable[[], Any] = self._config_runtime
        self.security_center_of: Callable[[], Any] = self._security_center
        self.drift_areas_of: Callable[[dict[str, Any]], Any] = self._async_drift_areas
        self.transport: DiagTransport = DIAG_DEFAULT_TRANSPORT
        self.clock: Callable[[], float] = time.time
        self.scheduler_config = SchedulerConfig()
        self.task_factory: Any = _default_task_factory(hass)

    # -- properties ---------------------------------------------------------------

    @property
    def settings(self) -> dict[str, Any]:
        """The current settings (held by the store)."""
        return self.store.settings

    @property
    def enabled(self) -> bool:
        """The ``enabled`` setting."""
        return self.settings.get("enabled") is True

    @property
    def entry_count(self) -> int:
        """Number of entries using the module."""
        return len(self._entries)

    @property
    def module_key_available(self) -> bool:
        """True once the core handed out the module key."""
        return self._module_key is not None

    # -- entries --------------------------------------------------------------------

    @callback
    def add_entry(self, entry_id: str, coordinator: Any) -> None:
        """Remember the entry's coordinator (its data is read on a poll)."""
        self._entries[entry_id] = coordinator

    @callback
    def remove_entry(self, entry_id: str) -> None:
        """Forget the entry; its history stays until ``router.forgotten``."""
        rid = self._rid_cache.pop(entry_id, None)
        self._entries.pop(entry_id, None)
        if rid is not None and rid not in self._rid_cache.values():
            self._routers.pop(rid, None)

    def _registry_router_id(self, entry_id: str) -> str | None:
        api = self._binding.api
        if api is None:
            return None
        try:
            rid = api.registry.get_by_entry(entry_id).router_id
        except Exception:  # noqa: BLE001 - unknown entry: no router id yet
            return None
        return rid if is_valid_id(rid, ROUTER_ID_PREFIX) else None

    def _rid(self, entry_id: str) -> str | None:
        cached = self._rid_cache.get(entry_id)
        if cached is not None:
            return cached
        rid = self.router_id_of(entry_id)
        if not isinstance(rid, str) or not is_valid_id(rid, ROUTER_ID_PREFIX):
            return None
        self._rid_cache[entry_id] = rid
        return rid

    # -- errors ---------------------------------------------------------------------

    def _fail(self, stage: str, err: BaseException) -> None:
        """Log an error without identities; never raise."""
        self.counters["errors"] += 1
        _LOGGER.warning(
            "Network diagnostics: %s failed (%s); the routers keep working",
            stage,
            type(err).__name__,
        )
        _LOGGER.debug("Network diagnostics %s error", stage, exc_info=err)

    def _stage(self, name: str, func: Callable[..., Any], *args: Any) -> None:
        try:
            func(*args)
        except Exception as err:  # noqa: BLE001 - one stage, not the poll
            self._fail(name, err)

    # -- store ----------------------------------------------------------------------

    async def async_load(self) -> None:
        """Read the store once (tolerant) and build the target registry."""
        await self.store.async_load()
        self._rebuild_registry()
        self.loaded = True

    def _rebuild_registry(self) -> None:
        self.registry, self.refused_targets = build_registry(self.settings)

    def _save(self) -> None:
        self.store.schedule_save(enabled=self.enabled)

    # -- activation -----------------------------------------------------------------

    async def async_activate(self) -> None:
        """Bind core and engine, start the scheduler (enabled only)."""
        if self._closed or not self.enabled:
            return
        self.active = True
        try:
            await self._async_bind_core()
        except Exception as err:  # noqa: BLE001 - runs without the core
            self._fail("core binding", err)
        try:
            self._attach_engine()
        except Exception as err:  # noqa: BLE001 - runs without the engine
            self._fail("engine binding", err)
        try:
            await self._async_sync_jobs()
        except Exception as err:  # noqa: BLE001 - no HA probes then
            self._fail("scheduler", err)
        self._stage("restart gap", self._apply_ha_restart)
        self._save()
        self._publish()

    def _apply_ha_restart(self) -> None:
        """HA restart: the downtime since the last save is a gap (once)."""
        start = self.store.take_restart()
        if start is None:
            return
        self.store.history.mark_restart(
            start=start, end=self.clock(), reason=GAP_HA_RESTART
        )
        self._rounds.clear()

    async def async_deactivate(self) -> None:
        """Stop observing, probing and listening (data stays)."""
        self.active = False
        self._detach_engine()
        self._unbind_core()
        scheduler, self.scheduler = self.scheduler, None
        self._periodic_interval = None
        self._manual_plan = None
        drift, self._drift_task = self._drift_task, None
        if drift is not None and not drift.done():
            drift.cancel()
        self._config_notes.clear()
        self._config_since = None
        self._security_cache.clear()
        if scheduler is not None:
            await scheduler.async_stop()
        self._publish()

    async def async_close(self) -> None:
        """Stop for good; no delayed write is scheduled after this."""
        self._closed = True
        await self.async_deactivate()
        self.store.close()

    # -- core -------------------------------------------------------------------------

    async def _async_bind_core(self) -> None:
        from .config_api import async_get_configuration_api
        from .enterprise_core import async_get_core

        core = async_get_core(self.hass)
        if core is None or getattr(core, "closed", False):
            self._unbind_core()
            return
        if self._binding.core is core and self._binding.api is not None:
            await self._async_fetch_module_key()
            self._stage("forgotten routers", self._forget_unknown_routers)
            return
        self._unbind_core()
        api = await async_get_configuration_api(self.hass, 1)
        binding = _Binding(core=core, api=api)
        self._binding = binding
        self._rid_cache.clear()
        try:
            binding.removers.append(
                register_with_core(
                    api,
                    extract_router_facts,
                    scheduler_limit=self.scheduler_config.rate_limit,
                )
            )
            binding.events_ok = True
        except (TypeError, ValueError) as err:
            self._fail("core registration", err)
        binding.removers.append(api.subscribe(self._on_core_event))
        self._config_since = self.clock()
        await self._async_fetch_module_key()
        self._stage("forgotten routers", self._forget_unknown_routers)

    def _unbind_core(self) -> None:
        binding = self._binding
        self._binding = _Binding()
        self._module_key = None
        for remove in reversed(binding.removers):
            try:
                remove()
            except Exception:
                _LOGGER.debug("Network diagnostics: remover raised", exc_info=True)

    async def _async_fetch_module_key(self) -> None:
        binding = self._binding
        if self._module_key is not None or not binding.events_ok or not self.active:
            return
        self._key_tried = time.monotonic()
        try:
            state = binding.api.installation_key_state
            if state not in (
                InstallationKeyState.OK,
                InstallationKeyState.UNINITIALISED,
            ):
                self._key_missing(f"key state {getattr(state, 'value', state)}")
                return
            key = await async_identifier_key(binding.api)
            if not isinstance(key, bytes) or len(key) < 16:
                raise TypeError("module key")
            self._module_key = key
        except Exception as err:  # noqa: BLE001 - not ready then
            _LOGGER.debug("Network diagnostics: no module key (%s)", type(err).__name__)
            self._key_missing(type(err).__name__)
            return
        self._key_warned = False

    def _key_missing(self, reason: str) -> None:
        if self._key_warned:
            return
        self._key_warned = True
        _LOGGER.warning(
            "Network diagnostics not ready: no module key from the core (%s); "
            "no finding event is sent, retrying every %d s",
            reason[:64],
            DIAG_MODULE_KEY_RETRY_SECONDS,
        )

    def _maybe_retry_module_key(self) -> None:
        binding = self._binding
        if (
            self._module_key is not None
            or not self.active
            or self._closed
            or binding.api is None
            or not binding.events_ok
        ):
            return
        tried, clock = self._key_tried, time.monotonic()
        if tried is not None and 0 <= clock - tried < DIAG_MODULE_KEY_RETRY_SECONDS:
            return
        self._key_tried = clock
        self.hass.async_create_task(
            self._async_retry_module_key(), name="openwrt_router diag key"
        )

    async def _async_retry_module_key(self) -> None:
        try:
            await self._async_fetch_module_key()
        except Exception as err:  # noqa: BLE001 - never disturbs a poll
            self._key_missing(type(err).__name__)

    def _on_core_event(self, event: Any) -> None:
        """Core listener (sync, short); never raises."""
        if not self.active or self._closed:
            return
        try:
            if getattr(event, "source", None) == MODULE:
                return
            rid = forgotten_router_id(event)
            if rid is not None:
                self._forget_router(rid)
                return
            self._config_event(event)
        except Exception as err:  # noqa: BLE001 - the core isolates us too
            self._fail("core event", err)

    def _forget_unknown_routers(self) -> None:
        """Catch up on ``router.forgotten`` sent before we listened."""
        if not self.active or self._closed:
            return
        core, api = self._binding.core, self._binding.api
        if core is None or api is None or getattr(core, "loaded", False) is not True:
            return
        registry = getattr(core, "registry", None)
        if (
            getattr(registry, "loaded", False) is not True
            or getattr(registry, "load_failed", True) is not False
        ):
            return
        known = {
            r.router_id for r in api.registry.list(include_orphaned=True) if r.router_id
        }
        if not known:
            return
        for rid in sorted(self.store.history.router_ids() - known):
            if is_valid_id(rid, ROUTER_ID_PREFIX):  # never the HA point
                self._forget_router(rid)

    def _forget_router(self, rid: str) -> None:
        """``router.forgotten``: drop that router's history and memory."""
        history = self.store.history
        # No router-side job exists (no executor), so the plan has no job ids.
        plan = forget_plan(
            rid,
            series_keys=history.series_keys(),
            baselines=history.baseline_states(),
        )
        history.forget(plan)
        for key in plan.series_keys:
            self._rounds.pop(key, None)
        self._routers.pop(rid, None)
        for entry_id in [e for e, r in self._rid_cache.items() if r == rid]:
            del self._rid_cache[entry_id]
        for key in [k for k in self._config_notes if k[0] == rid]:
            del self._config_notes[key]
        self._security_cache.pop(rid, None)
        self.store.schedule_save(enabled=True, force=True)

    # -- engine -----------------------------------------------------------------------

    def _attach_engine(self) -> None:
        from .net_engine import async_get_engine

        engine = async_get_engine(self.hass)
        if engine is self._engine:
            return
        self._detach_engine()
        if engine is not None:
            self._engine = engine
            self._engine_unsub = engine.add_poll_observer(self)
            from .net_engine import add_finding_source

            self._source_unsub = add_finding_source(engine, self.ni_findings)

    def _detach_engine(self) -> None:
        source, self._source_unsub = self._source_unsub, None
        if source is not None:
            try:
                source()
            except Exception:
                _LOGGER.debug("Network diagnostics: source unsub raised", exc_info=True)
        unsub, self._engine_unsub = self._engine_unsub, None
        self._engine = None
        if unsub is not None:
            try:
                unsub()
            except Exception:
                _LOGGER.debug("Network diagnostics: unsub raised", exc_info=True)

    # -- poll observer (passive) ----------------------------------------------------

    def on_poll(self, facts: Any) -> None:
        """One NI poll of one router (read only); never raises."""
        if not self.active or self._closed:
            return
        try:
            self._on_poll(facts)
        except Exception as err:  # noqa: BLE001 - the poll goes on
            self._fail("poll", err)

    def _on_poll(self, facts: Any) -> None:
        self._stage("module key retry", self._maybe_retry_module_key)
        rid = self._rid(facts.router)
        if rid is None:
            self.counters["polls_unmapped"] += 1
            return
        coordinator = self._entries.get(facts.router)
        data = getattr(coordinator, "data", None)
        now = float(facts.now)
        state = self._routers.setdefault(rid, _RouterState())
        state.prev_poll, state.last_poll = state.last_poll, now
        state.interval = float(facts.interval) if facts.interval else None
        self.counters["polls"] += 1
        self._stage("restart", self._check_restart, rid, state, data, now)
        self._stage("wan series", self._record_wan, rid, state, data, now)
        self._stage("chain", self._evaluate_router, rid, state, coordinator, data)
        self._stage("dhcp", self._take_dhcp, state, data)
        self._stage("fold", self.store.history.fold, now)
        self._save()
        self._publish()

    def _check_restart(
        self, rid: str, state: _RouterState, data: Any, now: float
    ) -> None:
        """Router restart = uptime went down: a gap, streaks restart."""
        uptime = getattr(data, "uptime", None)
        if isinstance(uptime, bool) or not isinstance(uptime, int | float):
            return
        memory = self.store.history.router_memory(rid)
        last = memory.get("last_uptime")
        if uptime <= 0:
            return
        if isinstance(last, int | float) and uptime < last:
            start = state.prev_poll if state.prev_poll is not None else now - uptime
            self.store.history.mark_restart(
                start=start, end=now, reason=GAP_ROUTER_RESTART, point=rid
            )
            memory["restarts"] = int(memory.get("restarts") or 0) + 1
            memory["last_restart"] = now
            self.counters["router_restarts"] += 1
            for key in [k for k in self._rounds if k.point == rid]:
                del self._rounds[key]
        memory["last_uptime"] = uptime
        state.settling = uptime < DIAG_SETTLE_SECONDS

    def _record_wan(self, rid: str, state: _RouterState, data: Any, now: float) -> None:
        wan = getattr(data, "wan_status", None)
        wan = wan if isinstance(wan, Mapping) else {}
        found = wan.get("wan_found")
        if found is False:
            state.wan_applicable = False
            return
        state.wan_applicable = True if found is True else state.wan_applicable
        key = series_key(rid, WAN_TARGET, WAN_KIND, AddressFamily.IPV4)
        if found is None:
            sample = Sample.gap(now)
        elif wan.get("connected") is True:
            sample = Sample.answered(now, 0.0)
        else:
            sample = Sample.lost(now)
        self._record(key, sample, latency=False)

    def _record(self, key: SeriesKey, sample: Sample, *, latency: bool) -> None:
        """One sample plus its baselines (latency, rolling loss of 3 rounds).

        Baselines are kept only for a series the history admitted (quota).
        """
        history = self.store.history
        lat = None
        if latency and sample.rtt_ms is not None:
            lat = self._observation(key, LATENCY_CONFIG, sample.rtt_ms, sample.ts)
        outlier = lat is not None and lat.outlier
        if not history.record(key, sample, outlier=outlier):
            return
        if lat is not None:
            history.set_baseline(lat.state)
        if sample.outcome == "gap":
            return
        rounds = self._rounds.setdefault(key, deque(maxlen=DIAG_LOSS_ROUNDS))
        rounds.append(sample.outcome == "lost")
        loss = 100.0 * sum(rounds) / len(rounds)
        result = self._observation(key, LOSS_CONFIG, loss, sample.ts)
        if result is not None:
            history.set_baseline(result.state)

    def _observation(
        self, key: SeriesKey, config: BaselineConfig, value: float, ts: float
    ) -> Observation | None:
        """Feed one baseline round; None (counted) for an out-of-order round."""
        state = self.store.history.baseline(key, config.metric)
        if state is None:
            state = new_baseline(key, config)
        if state.last_ts is not None and ts < state.last_ts:
            self.counters["baselines_out_of_order"] += 1
            return None
        return observe(state, value, ts=ts, config=config, key=key)

    def _evaluate_router(
        self, rid: str, state: _RouterState, coordinator: Any, data: Any
    ) -> None:
        if getattr(coordinator, "last_update_success", True) is False:
            state.state, state.reason = R_STATE_UNKNOWN, REASON_POLL_FAILED
            return
        wan = getattr(data, "wan_status", None)
        facts = wan.get("diag_facts") if isinstance(wan, Mapping) else None
        if not isinstance(facts, Mapping):
            state.state, state.reason = R_STATE_UNKNOWN, REASON_INTERFACE_DUMP_MISSING
            state.finding = None
            return
        point = point_for(rid)
        finding = classify(evaluate_chain(point, (), chain_facts(wan, facts)))
        pending, state.pending = state.pending, None
        if pending is not None and pending[0] is data:
            changes = pending[1]  # already computed for NI (same poll)
        else:
            changes = self._changes(point, state, facts)
        if state.finding is None or _signature(state.finding) != _signature(finding):
            state.finding_at = state.last_poll
        state.finding = finding
        state.down = down_interfaces(facts)
        state.state, state.reason = _finding_state(finding)
        if state.settling and finding.is_problem:
            state.state = R_STATE_SETTLING
        # Only a problem finding (or a change) is an event; a settling router
        # sends its problem once it has settled.
        signature = _signature(finding)
        emit: list[Finding] = list(changes)
        send_finding = False
        if signature != state.sent:
            if not finding.is_problem:
                state.sent = signature
            elif not state.settling:
                send_finding = True
                emit.insert(0, finding)
        if emit and self._emit_findings(emit) and send_finding:
            state.sent = signature

    def _changes(
        self,
        point: MeasurementPoint,
        state: _RouterState,
        facts: Mapping[str, Any],
        *,
        settling: bool | None = None,
    ) -> list[Finding]:
        """Gateway / DNS server changes against the previous poll (memory).

        While the router settles after a restart nothing is compared and the
        memory keeps the values from before: a value that is back after the
        restart is no change, one that really changed is reported once.
        """
        found: list[Finding] = []
        if state.settling if settling is None else settling:
            return found
        for family, name in (
            (AddressFamily.IPV4, "ipv4_gateway"),
            (AddressFamily.IPV6, "ipv6_gateway"),
        ):
            current = _address(facts.get(name))
            if current is None:
                continue
            change = gateway_change(
                point, state.gateway.get(family), current, family=family
            )
            if change is not None:
                found.append(change)
            state.gateway[family] = current
        servers = _servers(facts)
        # part 2: no server at all (WAN down, its resolvers gone with it) is
        # no "change" of the servers: like a missing next hop the memory is
        # kept, a set that comes back the same is no change (case 27)
        if servers:
            change = dns_server_change(point, state.dns, servers)
            if change is not None:
                found.append(change)
            state.dns = servers
        return found

    def _take_dhcp(self, state: _RouterState, data: Any) -> None:
        """DHCP pool usage of the poll, taken over as is (no second count)."""
        pools = getattr(data, "dhcp_pools", None)
        state.dhcp_pools = [
            dict(pool) for pool in (pools or ()) if isinstance(pool, Mapping)
        ]

    def on_clock_shift(self, delta: float) -> None:
        """The NI clock jumped back: later samples are counted as out of order."""
        try:
            self.counters["clock_shifts"] += 1
            for state in self._routers.values():
                state.prev_poll = state.last_poll = None
        except Exception as err:  # noqa: BLE001 - never fatal
            self._fail("clock shift", err)

    def on_router_removed(self, router: str) -> None:
        """NI removed an entry's data: drop the memory of that router."""
        try:
            rid = self._rid_cache.get(router)
            if rid is not None:
                self._routers.pop(rid, None)
        except Exception as err:  # noqa: BLE001 - never fatal
            self._fail("router removed", err)

    # -- events -----------------------------------------------------------------------

    def _emit_findings(
        self, findings: Iterable[Finding], correlation_id: str | None = None
    ) -> bool:
        """Emit the events of one correlated round; False when not ready."""
        api, key = self._binding.api, self._module_key
        if api is None or key is None or not self._binding.events_ok:
            self.counters["events_not_ready"] += 1
            return False
        result = correlate(tuple(findings), {})
        cid = correlation_id or new_correlation_id()
        for event in correlation_events(result, correlation_id=cid, key=key):
            api.emit(**event.emit_kwargs())
            self.counters["events"] += 1
        return True

    def _emit_manual(
        self,
        actor: Any,
        status: str,
        kinds: Iterable[str],
        correlation_id: str,
    ) -> None:
        api = self._binding.api
        if api is None or not self._binding.events_ok:
            return
        plain = actor.actor if isinstance(actor, VerifiedActor) else actor
        if not isinstance(plain, Actor):
            return
        kinds = sorted(set(kinds)) or sorted(HA_PROBE_KINDS)
        event = manual_run_event(
            None,
            actor=plain,
            status=status,
            kinds=kinds,
            correlation_id=correlation_id,
        )
        try:
            api.emit(**event.emit_kwargs())
            self.counters["events"] += 1
        except Exception as err:  # noqa: BLE001 - the run result stands
            self._fail("manual run event", err)

    # -- scheduler and HA probes ----------------------------------------------------

    def _periodic_targets(self) -> list[str]:
        """Confirmed, non-ICMP targets of a periodic round."""
        return [
            t.target_id
            for t in self.registry.entries()
            if t.confirmed and t.kind is not TargetKind.ICMP
        ]

    def _wants_periodic(self) -> bool:
        return (
            self.active
            and self.enabled
            and self.settings.get("periodic") is True
            and bool(self._periodic_targets())
        )

    async def _async_sync_jobs(self) -> None:
        """Start the scheduler and add / change / drop the periodic job."""
        if not self.active or self._closed:
            return
        scheduler = self.scheduler
        if scheduler is None:
            scheduler = DiagScheduler(
                self.scheduler_config,
                on_result=self._on_result,
                task_factory=self.task_factory,
            )
            scheduler.add_job(
                DiagJob(
                    JOB_MANUAL,
                    JOB_KIND,
                    self._async_manual_job,
                    timeout=RUN_TIMEOUT_SECONDS,
                )
            )
            self.scheduler = scheduler
            scheduler.start()
        interval = float(self.settings.get("interval_s") or 0)
        want = self._wants_periodic()
        if self._periodic_interval is not None and (
            not want or self._periodic_interval != interval
        ):
            await scheduler.async_cancel_job(JOB_PERIODIC)
            self._periodic_interval = None
        if want and self._periodic_interval is None:
            scheduler.add_job(
                DiagJob(
                    JOB_PERIODIC,
                    JOB_KIND,
                    self._async_periodic_job,
                    interval=interval,
                    timeout=RUN_TIMEOUT_SECONDS,
                    first_delay=interval,
                )
            )
            self._periodic_interval = interval

    def _on_result(self, result: RunResult) -> None:
        if result.outcome.value != "success":
            _LOGGER.debug(
                "Network diagnostics run %s: %s", result.job_id, result.outcome
            )

    async def _async_periodic_job(self) -> dict[str, Any]:
        return await self._async_round(
            tuple(self._periodic_targets()), new_correlation_id()
        )

    async def _async_manual_job(self) -> dict[str, Any]:
        plan, self._manual_plan = self._manual_plan, None
        if plan is None:
            return {"probes": 0, "refused": [], "results": []}
        return await self._async_round(*plan)

    def _target_stage(self, target_id: str, kind: TargetKind) -> Stage:
        for raw in self.settings.get("targets") or ():
            if raw.get("id") == target_id and raw.get("stage"):
                return Stage(raw["stage"])
        return Stage.DNS if kind is TargetKind.DNS else Stage.INTERNET

    async def _async_round(
        self, target_ids: tuple[str, ...], correlation_id: str
    ) -> dict[str, Any]:
        """One HA-side probe round, sequential (never two packets at once)."""
        registry = self.registry
        scope = (
            TargetScope.INTERNAL
            if self.settings.get("ha_resolver_internal") is True
            else TargetScope.EXTERNAL
        )
        probes: list[ProbeResult] = []
        refused: list[dict[str, str]] = []
        for target_id in target_ids:
            pinned = await async_diag_resolve(
                registry, target_id, resolver_scope=scope, transport=self.transport
            )
            if isinstance(pinned, Refusal):
                self.counters["targets_refused"] += 1
                refused.append({"id": target_id, "reason": refusal_reason(pinned)})
                continue
            probe = await async_diag_probe(
                pinned,
                stage=self._target_stage(target_id, pinned.kind),
                may_query=registry.may_query,
                query_name=self.settings.get("dns_query_name"),
                http_path=self.settings.get("http_path") or DIAG_HTTP_PATH,
                transport=self.transport,
            )
            probes.append(probe)
            self.counters["probes"] += 1
            self.counters["probe_packets"] += DIAG_PACKETS_PER_PROBE.get(
                pinned.kind.value, 0
            )
        self.counters["rounds"] += 1
        self._stage("ha round", self._apply_ha_round, probes, correlation_id)
        return {
            "probes": len(probes),
            "refused": refused,
            "results": [
                {
                    "target_id": p.target_id,
                    "kind": p.kind.value,
                    "family": None if p.family is None else p.family.value,
                    "outcome": p.outcome.value,
                    "rtt_ms": p.rtt_ms,
                }
                for p in probes
            ],
        }

    def _apply_ha_round(self, probes: list[ProbeResult], correlation_id: str) -> None:
        for probe in probes:
            key = series_key(None, probe.target_id, probe.kind, probe.family or "any")
            self._record(key, probe_sample(probe), latency=True)
        now = max((p.timestamp for p in probes), default=self.clock())
        self.store.history.fold(now)
        self._ha_last = {"ts": now, "probes": len(probes)}
        self._ha_probes = [
            {
                "target_id": p.target_id,
                "kind": p.kind.value,
                "stage": p.stage.value,
                "outcome": p.outcome.value,
                "rtt_ms": p.rtt_ms,
                "ts": p.timestamp,
            }
            for p in probes
        ]
        if probes:
            finding = classify(evaluate_chain(MeasurementPoint.ha(), probes))
            if self._ha_finding is None or _signature(self._ha_finding) != _signature(
                finding
            ):
                self._ha_finding_at = now
            self._ha_finding = finding
            signature = _signature(finding)
            if signature != self._ha_sent and (
                not finding.is_problem or self._emit_findings([finding], correlation_id)
            ):
                self._ha_sent = signature
        self.store.schedule_save(enabled=self.enabled)
        self._publish()

    # -- guarded actions ----------------------------------------------------------------

    def _not_available(self, reason: str, message: str) -> ConfigApiError:
        return ConfigApiError(
            message, error_class=ErrorClass.NOT_AVAILABLE, details={"reason": reason}
        )

    async def _async_api(self) -> Any:
        if self._binding.api is None:
            try:
                await self._async_bind_core()
            except Exception as err:  # noqa: BLE001 - refused below
                self._fail("core binding", err)
        api = self._binding.api
        if api is None:
            raise self._not_available(
                REASON_CORE_UNAVAILABLE, "The enterprise core is not running"
            )
        return api

    async def _async_verify(self, api: Any, actor: Any) -> VerifiedActor:
        if isinstance(actor, VerifiedActor):
            return actor
        if isinstance(actor, Actor):
            return await api.guard.async_verify_actor(actor)
        raise AuthorizationError(
            "An actor is required", details={"reason": REASON_ACTOR_REQUIRED}
        )

    async def _async_authorize_settings(self, actor: Any) -> VerifiedActor:
        """Guard check of a settings change (admin users only, audited)."""
        api = await self._async_api()
        if not self._binding.actions_ok:
            api.guard.register_action(
                ACTION_UPDATE_SETTINGS,
                ActionClass.MUTATING,
                module=MODULE,
                admin_user_only=True,
            )
            self._binding.actions_ok = True
        verified = await self._async_verify(api, actor)
        decision = api.guard.authorize(
            ACTION_UPDATE_SETTINGS, FLEET_ROUTER_ID, verified
        )
        if not decision.approved:
            raise error_for_decision(decision)
        api.guard.consume(
            decision.authorization,
            action=ACTION_UPDATE_SETTINGS,
            router_id=FLEET_ROUTER_ID,
        )
        return verified

    async def async_update_settings(
        self, update: Mapping[str, Any], *, actor: Any
    ) -> dict[str, Any]:
        """Change settings (verified admin, audited); on/off (de)activates."""
        try:
            new = merge_settings(self.settings, update)
        except DiagSettingsError as err:
            raise ConfigApiError(
                "Invalid network diagnostics settings",
                error_class=ErrorClass.INVALID,
                details={"reason": err.reason},
            ) from None
        try:
            await self._async_authorize_settings(actor)
        except Exception:
            if not self.active:
                self._unbind_core()  # a refused change leaves nothing bound
            raise
        self.store.settings = new
        self._rebuild_registry()
        self.counters["settings_changes"] += 1
        if new["enabled"] and not self.active:
            await self.async_activate()
        elif not new["enabled"] and self.active:
            await self.async_deactivate()
        elif self.active:
            try:
                await self._async_sync_jobs()
            except Exception as err:  # noqa: BLE001 - settings are kept
                self._fail("scheduler", err)
        if not self.active:
            self._unbind_core()
        self.store.schedule_save(enabled=True, force=True)
        self._publish()
        await self._async_sync_entities()
        return self.settings_view()

    def _manual_targets(self, target_ids: Iterable[str] | None) -> list[str]:
        if target_ids is None:
            return [
                t.target_id
                for t in self.registry.entries()
                if t.kind is not TargetKind.ICMP
            ]
        if isinstance(target_ids, str):
            raise ConfigApiError(
                "target_ids must be a list",
                error_class=ErrorClass.INVALID,
                details={"reason": "target_ids.not_list"},
            )
        return list(dict.fromkeys(str(t) for t in target_ids))

    async def async_run_manual(
        self, *, actor: Any, target_ids: Iterable[str] | None = None
    ) -> dict[str, Any]:
        """One manual HA-side round (verified admin, guard rate limit).

        Order: module on -> actor verified by the core -> targets checked
        without any packet (a refusal, also "no confirmed target", raises
        ``SafetyRefusedError`` or another ``ConfigApiError``) -> guard
        decision and one-time use -> scheduler request -> audit event -> the
        round. Returns the round summary.
        """
        if not self.enabled or not self.active or self._closed:
            raise self._not_available(REASON_DISABLED, "Network diagnostics is off")
        cid = new_correlation_id()
        api = await self._async_api()
        ids = self._manual_targets(target_ids)
        verified = await self._async_verify(api, actor)
        kinds: set[str] = set()
        for target_id in ids or [None]:
            checked = (
                Refusal.NOT_CONFIRMED
                if target_id is None
                else self.registry.resolve(target_id)
            )
            if isinstance(checked, PinnedTarget | PendingTarget):
                if checked.target.kind is TargetKind.ICMP:
                    checked = Refusal.INVALID_KIND
                else:
                    kinds.add(_TARGET_KINDS[checked.target.kind])
            if isinstance(checked, Refusal):
                self.counters["manual_refused"] += 1
                self._emit_manual(verified, "refused_target", kinds, cid)
                raise error_for_refusal(checked)
        decision = authorize_manual_run(api.guard, verified, None, correlation_id=cid)
        if not decision.approved:
            self.counters["manual_refused"] += 1
            self._emit_manual(verified, "denied", kinds, cid)
            raise error_for_decision(decision)
        api.guard.consume(
            decision.authorization,
            action=ACTION_RUN_MANUAL.name,
            router_id=FLEET_ROUTER_ID,
        )
        scheduler = self.scheduler
        if scheduler is None:
            raise self._not_available(
                REASON_SCHEDULER_NOT_RUNNING, "The diagnosis scheduler is not running"
            )
        request = scheduler.request_run(JOB_MANUAL)
        error = error_for_run_request(request)
        if error is not None or request.completion is None:
            self.counters["manual_refused"] += 1
            self._emit_manual(verified, request.status.value, kinds, cid)
            raise error or self._not_available("no_completion", "No run")
        self._manual_plan = (tuple(ids), cid)
        self.counters["manual_runs"] += 1
        self._emit_manual(verified, request.status.value, kinds, cid)
        result = await request.completion
        value = result.value if isinstance(result.value, dict) else {}
        return {
            "status": result.outcome.value,
            "correlation_id": cid,
            "error": result.error,
            **value,
            "finding": _finding_brief(self._ha_finding),
        }

    # -- views ------------------------------------------------------------------------

    def settings_view(self) -> dict[str, Any]:
        """Settings for an admin view (targets without their host)."""
        out = {k: v for k, v in self.settings.items() if k != "targets"}
        out["targets"] = [
            {k: v for k, v in t.items() if k != "host"}
            for t in self.settings.get("targets") or ()
        ]
        return out

    def _module_state(self) -> tuple[str, list[str]]:
        if self._closed:
            return STATE_OFF, [REASON_CLOSED]
        if not self.enabled or not self.active:
            return STATE_OFF, [REASON_DISABLED]
        reasons: list[str] = []
        if self._binding.api is None:
            reasons.append(REASON_CORE_UNAVAILABLE)
        elif not self._binding.events_ok:
            reasons.append(REASON_EVENTS_NOT_REGISTERED)
        if self._module_key is None:
            reasons.append(REASON_MODULE_KEY_MISSING)
        if self._engine is None:
            reasons.append(REASON_ENGINE_UNAVAILABLE)
        if self.scheduler is None or not self.scheduler.running:
            reasons.append(REASON_SCHEDULER_NOT_RUNNING)
        return (STATE_NOT_READY if reasons else STATE_READY), reasons

    def _router_restarts(self, rid: str, now: float) -> int:
        return sum(
            1
            for gap in self.store.history.gaps
            if gap.get("point") == rid
            and gap.get("reason") == GAP_ROUTER_RESTART
            and isinstance(gap.get("end"), int | float)
            and gap["end"] >= now - DAY_SECONDS
        )

    def _router_score(self, rid: str, state: _RouterState, now: float) -> dict:
        history = self.store.history
        key = series_key(rid, WAN_TARGET, WAN_KIND, AddressFamily.IPV4)
        summaries = history.summaries(key, now=now, interval_s=state.interval)
        day = summaries.get("24h") if summaries else None
        wan = None
        if day is not None and day.loss_pct is not None:
            wan = Reading(100.0 - day.loss_pct, day.coverage)
        series = history.series.get(key)
        observed = 0.0 if series is None else max(0.0, now - series.since)
        result = compute_score(
            ScoreInputs(
                wan_availability=wan,
                router_restarts=Reading(float(self._router_restarts(rid, now))),
                observation_seconds=min(DAY_SECONDS, observed),
                not_applicable=(
                    frozenset({COMP_WAN})
                    if state.wan_applicable is False
                    else frozenset()
                ),
            )
        )
        return {
            "score": result.score,
            "coverage": result.coverage,
            "low_confidence": result.low_confidence,
            "observation_seconds": result.observation_seconds,
        }

    def _router_view(self, rid: str, state: _RouterState, wall: float) -> dict:
        view: dict[str, Any] = {"state": state.state, "reason": state.reason}
        last = state.last_poll
        limit = max(STALE_MIN_SECONDS, STALE_INTERVALS * (state.interval or 0.0))
        if last is None:
            view.update(state=R_STATE_UNKNOWN, reason=REASON_NO_DATA_YET)
        elif wall - last > limit:
            view.update(state=R_STATE_UNKNOWN, reason=REASON_STALE)
        view["finding"] = _finding_brief(state.finding)
        view["settling"] = state.settling
        view["dhcp_pools"] = [dict(p) for p in state.dhcp_pools]
        now = last if last is not None else wall
        view["restarts_24h"] = self._router_restarts(rid, now)
        try:
            view["score"] = self._router_score(rid, state, now)
        except Exception as err:  # noqa: BLE001 - the view stays
            self._fail("score", err)
            view["score"] = None
        return view

    def _ha_view(self, wall: float) -> dict[str, Any]:
        history = self.store.history
        series = []
        interval = (
            float(self.settings.get("interval_s") or 0)
            if self._periodic_interval is not None
            else None
        )
        for key in history.series_keys():
            if key.point != "ha":
                continue
            summaries = history.summaries(key, now=wall, interval_s=interval) or {}
            day = summaries.get("24h")
            baseline = history.baseline(key, LATENCY_CONFIG.metric)
            series.append(
                {
                    "target_id": key.target,
                    "kind": key.kind,
                    "family": key.family,
                    "24h": None
                    if day is None
                    else {
                        "answered": day.answered,
                        "lost": day.lost,
                        "gaps": day.gaps,
                        "loss_pct": day.loss_pct,
                        "mean_ms": day.mean_ms,
                        "jitter_ms": day.jitter_ms,
                        "coverage": day.coverage,
                    },
                    "baseline_phase": None if baseline is None else baseline.phase,
                }
            )
        usable = [
            t
            for t in self.registry.entries()
            if t.kind is not TargetKind.ICMP
            and (t.confirmed or t.scope is TargetScope.INTERNAL)
        ]
        if self._ha_finding is not None:
            state, reason = _finding_state(self._ha_finding)
        elif not usable:
            state, reason = R_STATE_UNKNOWN, REASON_NO_CONFIRMED_TARGET
        else:
            state, reason = R_STATE_UNKNOWN, REASON_NO_MEASUREMENT
        return {
            "state": state,
            "reason": reason,
            "finding": _finding_brief(self._ha_finding),
            "last_round": dict(self._ha_last) if self._ha_last else None,
            "series": series,
        }

    def load(self) -> dict[str, Any]:
        """What the module sends: per round, per day, HA and per router."""
        targets = [
            t
            for t in self.registry.entries()
            if t.target_id in self._periodic_targets()
        ]
        per_round = sum(DIAG_PACKETS_PER_PROBE.get(t.kind.value, 0) for t in targets)
        rounds = (
            DAY_SECONDS / self._periodic_interval if self._periodic_interval else 0.0
        )
        rate = self.scheduler_config.rate_limit
        return {
            "ha": {
                "periodic": self._periodic_interval is not None,
                "probes_per_round": len(targets) if self._periodic_interval else 0,
                "packets_per_round": per_round if self._periodic_interval else 0,
                "rounds_per_day": rounds,
                "packets_per_day": per_round * rounds,
                "resolver_queries_per_round": sum(1 for t in targets if not t.is_ip)
                if self._periodic_interval
                else 0,
                "run_limit": {"max_runs": rate.max_runs, "window_s": rate.window},
            },
            "router": {"extra_calls_per_poll": 0, "packets_per_round": 0},
        }

    def status(self) -> dict[str, Any]:
        """Module state with reasons, routers, HA, load and counters.

        No address, host or domain: router ids, target ids and codes only.
        """
        wall = self.clock()
        state, reasons = self._module_state()
        routers: dict[str, Any] = {}
        for rid, rstate in self._routers.items():
            routers[rid] = self._router_view(rid, rstate, wall)
        unmapped = [
            e for e in self._entries if e not in self._rid_cache and self.active
        ]
        refused = {tid: refusal_reason(r) for tid, r in self.refused_targets}
        targets = []
        for raw in self.settings.get("targets") or ():
            tid = str(raw.get("id"))
            usable = tid not in refused and (
                raw.get("scope") == TargetScope.INTERNAL.value
                or raw.get("confirmed") is True
            )
            reason = refused.get(tid)
            if reason is None and not usable:
                reason = refusal_reason(Refusal.NOT_CONFIRMED)
            if raw.get("kind") == TargetKind.ICMP.value:
                usable, reason = False, DIAG_REASON_ICMP_NOT_ON_HA
            targets.append(
                {
                    "id": tid,
                    "kind": raw.get("kind"),
                    "scope": raw.get("scope"),
                    "confirmed": raw.get("confirmed") is True,
                    "usable": usable,
                    "reason": reason or "ok",
                }
            )
        scheduler = self.scheduler
        return {
            "state": state,
            "reasons": reasons,
            "enabled": self.enabled,
            "periodic": self._periodic_interval is not None,
            "routers": routers,
            "routers_without_id": {
                "count": len(unmapped),
                "reason": REASON_NO_ROUTER_ID,
            },
            "ha": self._ha_view(wall) if self.active else None,
            "targets": targets,
            "router_probes": {
                "state": "not_available",
                "reason": REASON_NO_EXECUTOR,
                "kinds": list(EXEC_KINDS),
            },
            "load": self.load(),
            "scheduler": {
                "running": scheduler is not None and scheduler.running,
                "orphaned_tasks": 0 if scheduler is None else scheduler.orphaned_tasks,
            },
            "store": self.store.status(),
            "counters": dict(self.counters),
        }

    # =========================================================================
    # Part 2: NI change incidents, context sources, entity view, route views
    # =========================================================================

    # -- NI finding source (gateway / DNS server changed) -------------------------

    def ni_findings(self, entry_id: str, data: Any, now: float) -> list[Any]:
        """Change findings of this poll as NI findings; never raises.

        NI calls this in ``ingest`` before its machine step (the poll
        observer runs only after it). The changes are computed once here:
        the poll observer takes the same findings over for its core events.
        """
        if not self.active or self._closed:
            return []
        try:
            return self._ni_findings(entry_id, data)
        except Exception as err:  # noqa: BLE001 - the poll goes on
            self._fail("change incidents", err)
            return []

    def _ni_findings(self, entry_id: str, data: Any) -> list[Any]:
        rid = self._rid(entry_id)
        coordinator = self._entries.get(entry_id)
        if rid is None or getattr(coordinator, "last_update_success", True) is False:
            return []
        wan = getattr(data, "wan_status", None)
        facts = wan.get("diag_facts") if isinstance(wan, Mapping) else None
        if not isinstance(facts, Mapping):
            return []
        state = self._routers.setdefault(rid, _RouterState())
        uptime = getattr(data, "uptime", None)
        settling = state.settling
        if (
            isinstance(uptime, int | float)
            and not isinstance(uptime, bool)
            and uptime > 0
        ):
            settling = uptime < DIAG_SETTLE_SECONDS
        changes = self._changes(point_for(rid), state, facts, settling=settling)
        state.pending = (data, changes)
        return ni_change_findings(entry_id, changes)

    # -- context sources (read only) ----------------------------------------------

    def _config_runtime(self) -> Any:
        from .config_manager import async_get_runtime

        return async_get_runtime(self.hass)

    def _security_center(self) -> Any:
        from .security_center import async_get_security_center

        return async_get_security_center(self.hass)

    def _config_event(self, event: Any) -> None:
        """Drift / critical change / new version of the Configuration Manager."""
        kind = str(getattr(event, "type", ""))
        if kind not in _CONFIG_EVENT_TYPES:
            return
        rid = getattr(event, "router_id", None)
        if not isinstance(rid, str) or not is_valid_id(rid, ROUTER_ID_PREFIX):
            return
        if kind == CoreEventType.BACKUP_CREATED.value:
            if any(
                n["router_id"] == rid and n["state"] == "pending"
                for n in self._config_notes.values()
            ):
                self._schedule_drift_resolution()
            return
        data = getattr(event, "data", None)
        data = data if isinstance(data, Mapping) else {}
        drift_id = data.get("drift_id") or getattr(event, "dedup_key", None)
        if not isinstance(drift_id, str) or not drift_id:
            return
        ts = _event_ts(getattr(event, "ts", None))
        critical = kind == CoreEventType.CHANGE_CRITICAL.value or (
            isinstance(data.get("critical_count"), int) and data["critical_count"] > 0
        )
        key = (rid, drift_id[:128])
        note = self._config_notes.get(key)
        if note is None:
            baseline = data.get("baseline_version_id")
            self._config_notes[key] = {
                "router_id": rid,
                "ref": drift_id[:128],
                "ts": self.clock() if ts is None else ts,
                "baseline": baseline if isinstance(baseline, str) else None,
                "areas": None,
                "state": "pending",
                "critical": critical,
            }
            while len(self._config_notes) > DIAG_CONFIG_NOTES_MAX:
                notes = self._config_notes
                del notes[min(notes, key=lambda k: notes[k]["ts"])]
        elif critical:
            note["critical"] = True
        self._schedule_drift_resolution()

    def _schedule_drift_resolution(self) -> None:
        if self._drift_task is not None and not self._drift_task.done():
            self._drift_again = True
            return
        self._drift_again = False
        self._drift_task = self.hass.async_create_task(
            self._async_resolve_drifts(), name="openwrt_router diag drift areas"
        )

    async def _async_resolve_drifts(self) -> None:
        """Look up the configuration areas of pending drifts (no router call)."""
        await asyncio.sleep(0)  # never inside the core's emit
        try:
            while True:
                self._drift_again = False
                await self._async_resolve_pending()
                if not self._drift_again or not self.active:
                    break
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001 - never fails anything
            self._fail("drift areas", err)

    async def _async_resolve_pending(self) -> None:
        now = self.clock()
        pending = [n for n in self._config_notes.values() if n["state"] == "pending"]
        for note in pending[:8]:
            areas = None
            if note["baseline"] is not None:
                try:
                    areas = await self.drift_areas_of(note)
                except Exception as err:  # noqa: BLE001 - areas stay unknown
                    _LOGGER.debug(
                        "Network diagnostics: drift areas not readable (%s)",
                        type(err).__name__,
                    )
            if areas is not None:
                note["areas"] = sorted({str(a)[:32] for a in areas})
                note["state"] = "resolved"
            elif (
                note["baseline"] is None
                or now - note["ts"] > 2 * DIAG_CONTEXT_WINDOW_SECONDS
            ):
                note["state"] = "unknown"

    async def _async_drift_areas(self, note: Mapping[str, Any]) -> list[str] | None:
        """Areas of a drift from two stored versions (public core API only).

        Same reading as the Security Center: the drift's baseline version
        against the first version stored or last seen after it. None while
        there is none yet, or while a change has no area and none of the
        context areas is among them.
        """
        from .core_models import ConfigRef

        api = self._binding.api
        if api is None:
            return None
        records = list(await api.async_list_backups(note["router_id"], limit=20))
        base = next((r for r in records if r.backup_id == note["baseline"]), None)
        base_ts = _event_ts(getattr(base, "created_at", None)) if base else None
        if base_ts is None:
            return None
        candidates = []
        for record in records:
            stamps = (
                _event_ts(getattr(record, "created_at", None)),
                _event_ts(getattr(record, "last_seen_at", None)),
            )
            when = max((t for t in stamps if t is not None), default=None)
            if (
                when is None
                or when <= base_ts
                or record.backup_id == note["baseline"]
                or not getattr(record, "usable", True)
            ):
                continue
            candidates.append((when, record.backup_id))
        if not candidates:
            return None
        diff = await api.async_compare(
            ConfigRef.backup(str(note["baseline"])),
            ConfigRef.backup(min(candidates)[1]),
            actor=Actor.for_module(MODULE),
        )
        changes = getattr(diff, "comparable_changes", None)
        if changes is None:
            changes = getattr(diff, "changes", ())
        areas = {c.area for c in changes if isinstance(c.area, str) and c.area}
        unknown = any(not (isinstance(c.area, str) and c.area) for c in changes)
        if unknown and not areas & _CONTEXT_AREAS:
            return None
        return sorted(areas)

    def _config_view(self, rid: str) -> SourceView:
        try:
            runtime = self.config_runtime_of()
        except Exception:  # noqa: BLE001 - treated as missing
            runtime = None
        if runtime is None:
            return SourceView.unavailable(
                SourceState.MISSING, "configuration_manager_not_running"
            )
        try:
            on = runtime.drift_check_enabled(rid) is True
        except Exception:  # noqa: BLE001 - unknown router: not checked
            on = False
        if not on:
            return SourceView.unavailable(SourceState.DISABLED, "drift_check_off")
        if self._binding.api is None or self._config_since is None:
            return SourceView.unavailable(SourceState.NOT_READY, "core_unavailable")
        items = tuple(
            ConfigChange(
                router_id=note["router_id"],
                at=float(note["ts"]),
                ref=note["ref"],
                areas=tuple(note["areas"]) if note["state"] == "resolved" else None,
                critical=bool(note["critical"]),
            )
            for note in self._config_notes.values()
            if note["router_id"] == rid
        )
        return SourceView(SourceState.READY, since=self._config_since, items=items)

    def _security_view(self, rid: str, at: float) -> SourceView:
        try:
            center = self.security_center_of()
        except Exception:  # noqa: BLE001 - treated as missing
            center = None
        if center is None:
            return SourceView.unavailable(
                SourceState.MISSING, "security_center_not_running"
            )
        if getattr(center, "enabled", False) is not True:
            return SourceView.unavailable(SourceState.DISABLED, "security_center_off")
        if getattr(center, "ready", False) is not True:
            reason = getattr(center, "not_ready_reason", None)
            return SourceView.unavailable(
                SourceState.NOT_READY,
                reason if isinstance(reason, str) else "not_ready",
            )
        now = self.clock()
        cached = self._security_cache.get(rid)
        if (
            cached is not None
            and cached[1] == int(at)
            and 0 <= now - cached[0] < DIAG_CONTEXT_CACHE_SECONDS
        ):
            return cached[2]
        overview = center.overview(
            since=at - DIAG_CONTEXT_WINDOW_SECONDS, router_id=rid, limit=20
        )
        incidents = []
        for item in (overview or {}).get("incidents") or ():
            ts = item.get("last_seen") if isinstance(item, Mapping) else None
            if isinstance(ts, bool) or not isinstance(ts, int | float):
                continue
            incidents.append(
                SecurityIncident(
                    router_id=item.get("router_id"),
                    at=float(ts),
                    incident_id=str(item.get("id"))[:64],
                    type=str(item.get("type"))[:48],
                    category=str(item.get("category"))[:32],
                    severity=str(item.get("severity"))[:16],
                )
            )
        # DECIDED: the center keeps its incidents in its own store, so a
        # ready center covers the whole window.
        view = SourceView(
            SourceState.READY,
            since=at - DIAG_CONTEXT_WINDOW_SECONDS,
            items=tuple(incidents),
        )
        self._security_cache[rid] = (now, int(at), view)
        return view

    def router_context(self, rid: str) -> FindingContext | None:
        """Context of the router's current finding (None without a finding)."""
        state = self._routers.get(rid)
        if state is None or state.finding is None:
            return None
        at = state.finding_at or state.last_poll or self.clock()
        extra = ("interface_down_vlan",) if any(d["vlan"] for d in state.down) else ()
        return context_for(
            state.finding,
            rid,
            at,
            config=self._config_view(rid),
            security=self._security_view(rid, at),
            window=float(DIAG_CONTEXT_WINDOW_SECONDS),
            extra_evidence=extra,
        )

    # -- entity view ------------------------------------------------------------------

    def _publish(self) -> None:
        """Rebuild the entity view and tell the entities (never raises)."""
        try:
            on = self.enabled and self.active and not self._closed
            self.view = self._build_view() if on else None
        except Exception as err:  # noqa: BLE001 - the entities go unknown
            self._fail("entity view", err)
            self.view = None
        try:
            async_dispatcher_send(self.hass, SIGNAL_NET_DIAGNOSTICS)
        except Exception:
            _LOGGER.debug("Network diagnostics: dispatch failed", exc_info=True)

    def entries_by_router(self) -> dict[str, str]:
        """Core router id -> entry id of every mapped entry."""
        return {rid: entry for entry, rid in self._rid_cache.items()}

    def _gateway(self, state: _RouterState, router_state: str) -> dict[str, Any]:
        """Next-hop reachability from a DIRECT gateway-stage measurement only."""
        if router_state == R_STATE_UNKNOWN or state.finding is None:
            return {"state": None, "reason": REASON_NO_DATA_YET}
        chain = state.finding.chain
        if chain is not None:
            for family in (AddressFamily.IPV4, AddressFamily.IPV6):
                try:
                    stage = chain.stage(Stage.GATEWAY, family)
                except KeyError:
                    continue
                if stage.measured and stage.basis == Basis.DIRECT:
                    return {
                        "state": stage.state == StageState.HEALTHY,
                        "reason": stage.state.value,
                        "family": family.value,
                    }
        # passive facts know the next hop, not whether it answers
        return {
            "state": None,
            "reason": "not_measured",
            "next_hop_known": bool(state.gateway),
            "router_probes": REASON_NO_EXECUTOR,
        }

    def _ha_rtt(self, kinds: frozenset[str], wall: float) -> float | None:
        """Mean round trip of the last HA round (None if none or stale)."""
        last = self._ha_last
        if not last or not self._ha_probes:
            return None
        interval = float(self.settings.get("interval_s") or 0)
        if wall - float(last["ts"]) > max(3600.0, STALE_INTERVALS * interval):
            return None
        rtts = [
            float(p["rtt_ms"])
            for p in self._ha_probes
            if p["kind"] in kinds
            and p["outcome"] in _ANSWERED
            and isinstance(p["rtt_ms"], int | float)
            and not isinstance(p["rtt_ms"], bool)
        ]
        return round(sum(rtts) / len(rtts), 1) if rtts else None

    def _ha_loss(self, wall: float) -> float | None:
        """Loss of the HA internet series over 24 h (None without samples)."""
        answered = lost = 0
        history = self.store.history
        for key in history.series_keys():
            if key.point != HA_POINT_KEY or key.kind not in _INTERNET_KINDS:
                continue
            day = (history.summaries(key, now=wall) or {}).get("24h")
            if day is not None:
                answered += day.answered
                lost += day.lost
        total = answered + lost
        return None if total == 0 else round(100.0 * lost / total, 1)

    def _build_view(self) -> dict[str, Any]:
        wall = self.clock()
        scores: list[float] = []
        coverages: list[float] = []
        low = False
        known = 0
        problems: dict[str, int] = {}
        gateways: dict[str, dict[str, Any]] = {}
        for rid, state in self._routers.items():
            view = self._router_view(rid, state, wall)
            score = view.get("score") or {}
            unknown = view["state"] == R_STATE_UNKNOWN
            cov = score.get("coverage")
            usable_cov = isinstance(cov, int | float) and not unknown
            coverages.append(float(cov) if usable_cov else 0.0)
            if unknown:
                low = True
            else:
                known += 1
                value = score.get("score")
                if isinstance(value, int | float):
                    scores.append(float(value))
                else:
                    low = True
            low = low or score.get("low_confidence") is True
            if view["state"] == R_STATE_PROBLEM and state.finding is not None:
                name = state.finding.classification.value
                problems[name] = problems.get(name, 0) + 1
            gateways[rid] = self._gateway(state, view["state"])
        ha_state = self._ha_view(wall)["state"]
        if ha_state == R_STATE_PROBLEM and self._ha_finding is not None:
            name = self._ha_finding.classification.value
            problems[name] = problems.get(name, 0) + 1
        routers = len(self._routers)
        return {
            "score": min(scores) if scores else None,
            "score_coverage": round(sum(coverages) / routers, 2) if routers else None,
            "low_confidence": low or not scores,
            "routers": routers,
            "routers_scored": len(scores),
            "routers_unknown": routers - known,
            "coverage": round(100 * sum(coverages) / routers) if routers else None,
            "ha_state": ha_state,
            "findings_active": sum(problems.values())
            if known or ha_state != R_STATE_UNKNOWN
            else None,
            "findings_by_classification": dict(sorted(problems.items())),
            "ha_latency_ms": self._ha_rtt(_INTERNET_KINDS, wall),
            "ha_loss_pct": self._ha_loss(wall),
            "dns_ms": self._ha_rtt(_DNS_KINDS, wall),
            "ha_measured_at": None if not self._ha_last else self._ha_last["ts"],
            "gateways": gateways,
        }

    async def _async_sync_entities(self) -> None:
        try:
            from .diag_entities import async_sync_diag_entities

            await async_sync_diag_entities(self.hass)
        except Exception as err:  # noqa: BLE001 - the module works without them
            self._fail("entities", err)

    # -- route views (ids and codes only: no address, host or domain) ---------------

    @staticmethod
    def _chain(finding: Finding | None) -> list[dict[str, Any]] | None:
        chain = None if finding is None else finding.chain
        if chain is None:
            return None
        return [
            {
                "stage": s.stage.value,
                "family": s.family.value,
                "state": s.state.value,
                "basis": s.basis.value,
            }
            for s in chain.stages
        ]

    def overview(self) -> dict[str, Any]:
        """Score, coverage, active findings, chains, last run (brief, masked)."""
        state, reasons = self._module_state()
        if state == STATE_OFF:
            return {
                "state": STATE_OFF,
                "reasons": reasons,
                "enabled": self.enabled,
                "fleet": None,
                "routers": None,
                "ha": None,
                "last_run": None,
            }
        wall = self.clock()
        view = self.view if self.view is not None else self._build_view()
        routers: dict[str, Any] = {}
        for rid, rstate in self._routers.items():
            rv = self._router_view(rid, rstate, wall)
            routers[rid] = {
                "state": rv["state"],
                "reason": rv["reason"],
                "settling": rv["settling"],
                "score": rv["score"],
                "restarts_24h": rv["restarts_24h"],
                "finding": None
                if rstate.finding is None
                else finding_output(rstate.finding, admin=False),
                "chain": self._chain(rstate.finding),
                "down_interfaces": len(rstate.down),
                "gateway": view["gateways"].get(rid),
            }
        ha = self._ha_view(wall)
        return {
            "state": state,
            "reasons": reasons,
            "enabled": True,
            "fleet": {k: v for k, v in view.items() if k != "gateways"},
            "routers": routers,
            "ha": {
                "state": ha["state"],
                "reason": ha["reason"],
                "finding": None
                if self._ha_finding is None
                else finding_output(self._ha_finding, admin=False),
                "chain": self._chain(self._ha_finding),
            },
            "last_run": dict(self._ha_last) if self._ha_last else None,
        }

    def history_view(self) -> dict[str, Any]:
        """The four windows (1h/24h/7d/30d) of every series (ids only)."""
        state, reasons = self._module_state()
        if state == STATE_OFF:
            return {"state": STATE_OFF, "reasons": reasons, "series": None}
        wall = self.clock()
        history = self.store.history
        series = []
        for key in history.series_keys():
            interval = None
            if key.point != HA_POINT_KEY:
                router = self._routers.get(key.point)
                interval = router.interval if router is not None else None
            summaries = history.summaries(key, now=wall, interval_s=interval) or {}
            series.append(
                {
                    "point": key.point,
                    "target_id": key.target,
                    "kind": key.kind,
                    "family": key.family,
                    "windows": {
                        name: None if summary is None else asdict(summary)
                        for name, summary in summaries.items()
                    },
                }
            )
        return {
            "state": state,
            "reasons": reasons,
            "windows": list(WINDOWS),
            "series": series,
            "gaps": len(history.gaps),
        }

    async def async_detail(
        self, router_id: str | None, *, actor: Any, admin: bool
    ) -> dict[str, Any]:
        """One finding with its context; detail only after the sensitive read.

        Non-admins get the brief, masked finding and the context states; an
        admin gets the detail when the core's sensitive read approves it
        (granted and denied reads are audited by the core).
        """
        state, reasons = self._module_state()
        if state == STATE_OFF:
            return {"state": STATE_OFF, "reasons": reasons, "finding": None}
        if router_id is None:
            finding = self._ha_finding
            context = None
        else:
            rstate = self._routers.get(router_id)
            if rstate is None and router_id not in self.entries_by_router():
                raise ConfigApiError(
                    "Unknown router",
                    error_class=ErrorClass.NOT_FOUND,
                    details={"reason": "unknown_router"},
                )
            # a mapped router that was not polled yet has no finding
            finding = None if rstate is None else rstate.finding
            context = self.router_context(router_id)
        out: dict[str, Any] = {
            "state": state,
            "reasons": reasons,
            "router_id": router_id,
            "detail": "brief",
            "finding": None
            if finding is None
            else finding_output(finding, admin=False),
            "context": None if context is None else _brief_context(context.to_dict()),
        }
        if not admin:
            return out
        try:
            api = await self._async_api()
        except ConfigApiError:
            out["detail"] = REASON_CORE_UNAVAILABLE  # no sensitive read
            return out
        verified = await self._async_verify(api, actor)
        if not authorize_sensitive_read(api.guard, verified, router_id):
            out["detail"] = "denied"
            return out
        out["detail"] = "full"
        if finding is not None:
            out["finding"] = finding_output(finding, admin=True, key=self._module_key)
        if context is not None:
            out["context"] = context.to_dict()
        if router_id is not None:
            rstate = self._routers.get(router_id)
            down = () if rstate is None else rstate.down
            out["down_interfaces"] = [dict(d) for d in down]
        else:
            out["probes"] = [dict(p) for p in self._ha_probes]
        return out


# =============================================================================
# Part 2 helpers
# =============================================================================

_CONFIG_EVENT_TYPES: Final = frozenset(
    {
        CoreEventType.DRIFT_DETECTED.value,
        CoreEventType.CHANGE_CRITICAL.value,
        CoreEventType.BACKUP_CREATED.value,
    }
)
# areas a drift with partly unknown areas must name to count as known
_CONTEXT_AREAS: Final = frozenset(
    {"vlan", "interface", "routing", "firewall", "dns", "dhcp"}
)
_INTERNET_KINDS: Final = frozenset({ProbeKind.TCP.value, ProbeKind.HTTP.value})
_DNS_KINDS: Final = frozenset({ProbeKind.DNS.value})
# a DNS answer "no such name" is still an answer with a round trip
_ANSWERED: Final = frozenset({ProbeOutcome.OK.value, ProbeOutcome.NXDOMAIN.value})


def _event_ts(value: Any) -> float | None:
    """Epoch seconds of a core time value (datetime, ISO text or number)."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value).timestamp()
        except ValueError:
            return None
    stamp = getattr(value, "timestamp", None)
    if callable(stamp):
        try:
            return float(stamp())
        except (TypeError, ValueError, OverflowError):
            return None
    return None


def _brief_context(context: Mapping[str, Any]) -> dict[str, Any]:
    """Context for a non-admin: states and hypotheses, no change or
    incident ids."""

    def brief(links: Any) -> Any:
        if links is None:
            return None
        return [
            {
                "source": link["source"],
                "cause_class": link["cause_class"],
                "hypothesis": link["hypothesis"],
                "minutes_before": link["minutes_before"],
                "area": link["area"],
            }
            for link in links
        ]

    config, security = context["configuration"], context["security"]
    return {
        "classification": context["classification"],
        "cause_class": context["cause_class"],
        "configuration": {
            "state": config["state"],
            "reason": config["reason"],
            "changes": brief(config["changes"]),
        },
        "security": {
            "state": security["state"],
            "reason": security["reason"],
            "incidents": brief(security["incidents"]),
        },
        "hypotheses": list(context["hypotheses"]),
    }


def ni_change_findings(entry_id: str, changes: Iterable[Finding]) -> list[Any]:
    """NI findings (``net_rules`` DIAG_CHANGE_*) of the diag change findings.

    Scope: the entry's router (``scope_key`` = entry id, like
    ``wan_ip_changed``). No address: the family, and for DNS the number of
    servers only.
    """
    out: list[Any] = []
    for change in changes:
        family = "any" if change.family is None else change.family.value
        if change.classification is Classification.GATEWAY_CHANGED:
            out.append(
                NiFinding(
                    kind=DIAG_GATEWAY_CHANGED_KIND,
                    category=NiCategory.WAN,
                    source=NiSource.NETIFD,
                    rule=DIAG_GATEWAY_CHANGED_TYPE,
                    scope_key=entry_id,
                    event=True,
                    severity=NiSeverity.INFO,
                    params={"family": family},
                )
            )
        elif change.classification is Classification.DNS_SERVER_CHANGED:
            current = None if change.change is None else change.change.current
            count = len(current) if isinstance(current, tuple | list) else None
            out.append(
                NiFinding(
                    kind=DIAG_DNS_SERVER_CHANGED_KIND,
                    category=NiCategory.DNS,
                    source=NiSource.NETIFD,
                    rule=DIAG_DNS_SERVER_CHANGED_TYPE,
                    scope_key=entry_id,
                    event=True,
                    severity=NiSeverity.INFO,
                    params={"servers": count},
                )
            )
    return out
