"""Self-Healing: the remediation playbooks A-G as versioned data (package F).

Pure module (no Home Assistant import, no clock, no router call, no I/O).
Developer document: ``docs/self-healing.md`` §8.

What is here:

* :data:`PLAYBOOKS` - a closed, read-only registry of seven playbooks
  (:class:`Playbook`), built once at import and checked against the catalog
  (``heal_catalog``) and the preflight check ids of package E. Each one names
  its detection (the REAL incident type codes Network Intelligence emits, or
  "not available yet" with the missing detection), roles, capabilities,
  permissions (derived from the catalog), prerequisites, the preflight check
  ids, its typed read-only steps, verification probe names, abort
  conditions, escalation rules and its never-rules. Its risk class is
  derived from the catalog actions it names, never a number of its own.
* :func:`match` - incident -> at most one playbook, deterministically, only
  for root incidents, never on a link by time alone.
* :func:`assess` - match plus the playbook's analysis of an in-memory
  evidence snapshot (:class:`Evidence`): the classified cause, the steps with
  their results, the recommendation text codes, what the system will NOT do,
  and the proposed catalog action (params from closed sets only) or
  "recommendation only". It fills the :class:`heal_policy.IncidentFacts` the
  policy needs, including ``cause_outside_router`` (True / False / None).
* :func:`to_decision_input` - the finding as a ``heal_policy.DecisionInput``;
  a playbook never grants anything itself, the policy decides.

Release 1.53.0 is Observe only: nothing here executes anything, and the
steps "restart", "verify" and "document" are marked as later packages
(C2, H, K). Router-supplied strings are data: they are compared against
closed sets and never copied into a proposal or a text; a proposal's
parameter is always the catalog's own constant.
"""

from __future__ import annotations

import dataclasses
import logging
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from . import heal_catalog as hc
from . import heal_policy as hp
from .heal_model import CauseLevel, CauseStatus, RiskClass

_LOGGER = logging.getLogger(__name__)

REGISTRY_VERSION: Final = 1

# The preflight check ids of package E (heal_preflight.py); playbooks refer
# to checks by these ids only.
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

# The incident types Network Intelligence emits (net_rules DEFAULT_SETTINGS
# thresholds plus the two change types of network diagnostics); a test
# compares this set with net_rules.
KNOWN_INCIDENT_TYPES: Final = frozenset(
    {
        "wifi_reconnect_storm",
        "wifi_auth_failures",
        "wifi_auth_wave",
        "wifi_mass_disconnect",
        "wifi_no_ip",
        "wifi_dhcp_after_connect",
        "wifi_band_flapping",
        "wifi_roam_flapping",
        "wifi_weak_clients",
        "wifi_channel_busy",
        "wifi_radio_change",
        "system_cpu_high",
        "system_ram_high",
        "system_reboot",
        "router_unreachable",
        "lan_unreachable",
        "system_service_restart",
        "system_clock_skew",
        "system_conntrack_jump",
        "lan_port_flap",
        "lan_port_speed_drop",
        "lan_port_errors",
        "lan_port_load",
        "lan_uplink_down",
        "lan_lldp_change",
        "wan_down",
        "wan_unstable",
        "wan_ip_changed",
        "dhcp_pool_full",
        "dhcp_conflict",
        "wan_gateway_changed",
        "dns_server_changed",
    }
)
# The services ``system_service_restart`` watches (net_rules rule list).
WATCHED_SERVICES: Final = ("dnsmasq", "odhcpd", "wpad", "hostapd", "network")
# Causes Network Intelligence names (net_rules.RECOMMENDED_CAUSES).
KNOWN_CAUSES: Final = frozenset(
    {
        "lan_unreachable",
        "router_unreachable",
        "router_reboot",
        "wan_down",
        "radio_change",
        "uplink_down",
        "port_flap",
        "mass_disconnect",
        "ap_full",
        "attack",
        "auth",
        "band_steering",
        "client_driver",
        "client_power_save",
        "client_side",
        "coverage",
        "dhcp_server",
        "dns_resolution",
        "interference",
        "ip_conflict",
        "mac_filter",
        "overlapping_coverage",
        "pool_exhausted",
        "power_supply",
        "psk_changed",
        "psk_wrong",
        "radio_restart",
        "roaming",
        "sae_mismatch",
        "static_ip",
        "steering",
        "uplink_config",
        "vlan",
        "weak_signal",
        "wrong_network",
    }
)
SCOPES: Final = frozenset({"client", "radio", "port", "router", "segment", "fleet"})
# Network Intelligence's source families (net_rules._SOURCE_FAMILY and the
# two link families). ``correlation`` is a link to a root, not an
# observation of the fault: it is not counted for the policy.
SOURCE_FAMILIES: Final = frozenset(
    {"log", "poll", "usteer", "topology", "fleet", "correlation", "peers"}
)
LINK_FAMILIES: Final = frozenset({"correlation"})
# Configuration Manager areas (config_const.AREA_*); a test compares them.
CONFIG_AREAS: Final = frozenset(
    {
        "vlan",
        "interface",
        "mgmt_ip",
        "firewall",
        "dhcp",
        "dns",
        "wlan",
        "routing",
        "services",
        "ssh",
        "system",
        "other",
    }
)
# Areas whose default risk is high or critical (config_const): never an
# automatic rollback there, whatever the release.
CRITICAL_CONFIG_AREAS: Final = frozenset(
    {"vlan", "interface", "mgmt_ip", "firewall", "routing", "ssh"}
)
CHANGE_RISKS: Final = ("low", "medium", "high", "critical")
RESTORE_CHECKS: Final = ("compatible", "incompatible", "unknown")
# Network diagnostics chain stages and states (diag_model.Stage/StageState).
CHAIN_STAGES: Final = ("router", "gateway", "wan", "internet", "dns")
CHAIN_STATES: Final = ("healthy", "degraded", "failed", "unknown", "not_applicable")
INTERFACE_ROLES: Final = ("uplink", "management", "lan", "wan", "other")
ROLES: Final = hp.ROLES
SEVERITIES: Final = hp.SEVERITIES

_COUNT_MAX: Final = 1_000_000
_TS_MAX: Final = 1e11
# Restarts in 24 h from which a running service without an observed loop is
# "unclear" rather than healthy (never a fault on their own).
RESTARTS_UNCLEAR: Final = 2
_ITER_MAX: Final = 64


class PlaybookError(ValueError):
    """A playbook definition or an internal use outside the closed sets."""


# ---------------------------------------------------------------------------
# Lenient readers: data from routers and modules is untrusted
# ---------------------------------------------------------------------------


def _member(value: Any, choices: Iterable[str]) -> str | None:
    """The member of ``choices`` equal to ``value`` (a plain str), else None.

    Returns the closed set's own constant, never the caller's object.
    """
    if type(value) is not str:
        return None
    for choice in choices:
        if choice == value:
            return choice
    return None


def _bool(value: Any) -> bool | None:
    return value if type(value) is bool else None


def _count(value: Any, hi: int = _COUNT_MAX) -> int | None:
    if type(value) is int and 0 <= value <= hi:
        return value
    return None


def _fraction(value: Any) -> float | None:
    if (
        type(value) in (int, float)
        and math.isfinite(value)
        and 0.0 <= float(value) <= 1.0
    ):
        return float(value)
    return None


def _timestamp(value: Any) -> float | None:
    if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= _TS_MAX:
        return float(value)
    return None


def _percent(value: Any) -> float | None:
    if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 100:
        return float(value)
    return None


def _members(value: Any, choices: Iterable[str]) -> frozenset[str] | None:
    """A set of closed-set members (None: not an iterable of str at all)."""
    if value is None or isinstance(value, str | bytes):
        return None
    if not isinstance(value, Iterable):
        return None
    allowed = tuple(choices)
    out: set[str] = set()
    for index, item in enumerate(value):
        if index >= _ITER_MAX:
            break
        found = _member(item, allowed)
        if found is not None:
            out.add(found)
    return frozenset(out)


def _enum(value: Any, kind: type[StrEnum]) -> Any:
    if isinstance(value, kind):
        return value
    if type(value) is str:
        try:
            return kind(value)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# Inputs: the incident as Network Intelligence reports it, the evidence
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class IncidentInput:
    """A root incident of Network Intelligence, normalised.

    Every value is checked against a closed set; anything else becomes
    None ("unknown"), never an error and never a guess. ``service``: the
    service a ``system_service_restart`` names (its subject).
    ``temporal_only`` is True whenever no family other than the link to a
    root (``correlation``) is observed, whatever value was given (review of
    PR #79: a time-only link never becomes evidence by a ``False``).
    ``started_at``: when the incident started (seconds; compared with a
    configuration change time, never with a clock).
    """

    incident_type: Any = None
    scope: Any = None
    service: Any = None
    cause: Any = None
    cause_status: Any = None
    cause_level: Any = None
    confidence: Any = None
    severity: Any = None
    source_families: Any = ()
    is_root: Any = None
    temporal_only: Any = None
    evidence_fresh: Any = None
    affected_clients: Any = None
    occurrences: Any = None
    reopen_count: Any = None
    started_at: Any = None

    def __post_init__(self) -> None:
        """Normalise (never raises)."""
        put = object.__setattr__
        put(self, "incident_type", _member(self.incident_type, KNOWN_INCIDENT_TYPES))
        put(self, "scope", _member(self.scope, SCOPES))
        put(self, "service", _member(self.service, WATCHED_SERVICES))
        put(self, "cause", _member(self.cause, KNOWN_CAUSES))
        put(self, "cause_status", _enum(self.cause_status, CauseStatus))
        level = _enum(self.cause_level, CauseLevel)
        put(self, "cause_level", CauseLevel.UNKNOWN if level is None else level)
        put(self, "confidence", _fraction(self.confidence))
        put(self, "severity", _member(self.severity, SEVERITIES))
        families = _members(self.source_families, SOURCE_FAMILIES)
        put(self, "source_families", frozenset() if families is None else families)
        put(self, "is_root", _bool(self.is_root))
        put(self, "evidence_fresh", _bool(self.evidence_fresh))
        temporal = _bool(self.temporal_only)
        if not self.source_families - LINK_FAMILIES:
            temporal = True  # nothing but the link (or nothing) observed
        put(self, "temporal_only", temporal)
        put(self, "started_at", _timestamp(self.started_at))
        put(self, "affected_clients", _count(self.affected_clients))
        put(self, "occurrences", _count(self.occurrences))
        put(self, "reopen_count", _count(self.reopen_count))

    @property
    def observed_families(self) -> int:
        """Independent source families (the link to a root is not one)."""
        return len(self.source_families - LINK_FAMILIES)


@dataclass(frozen=True, kw_only=True, slots=True)
class ServiceFact:
    """One service from the poll (procd ``service list`` and ``rc list``)."""

    running: Any = None
    enabled: Any = None  # False: switched off on purpose (rc list)
    crash_loop: Any = None
    restarts_24h: Any = None

    def __post_init__(self) -> None:
        """Normalise."""
        put = object.__setattr__
        put(self, "running", _bool(self.running))
        put(self, "enabled", _bool(self.enabled))
        put(self, "crash_loop", _bool(self.crash_loop))
        put(self, "restarts_24h", _count(self.restarts_24h))

    @property
    def faulty(self) -> bool | None:
        """Enabled and down or in an observed restart loop (None: unclear).

        A restart count alone is not a fault fact (review of PR #79): a
        running service with :data:`RESTARTS_UNCLEAR` or more restarts in 24 h
        and no observed loop is unclear (None), fewer restarts are healthy.
        """
        if self.enabled is not True:
            return None if self.enabled is None else False
        if self.running is False or self.crash_loop is True:
            return True
        if self.running is True and self.crash_loop is False:
            if self.restarts_24h is not None and self.restarts_24h >= RESTARTS_UNCLEAR:
                return None
            return False
        return None


_UNKNOWN_SERVICE: Final = ServiceFact()


@dataclass(frozen=True, kw_only=True, slots=True)
class DnsFact:
    """DNS as seen from Home Assistant's side (network diagnostics)."""

    local_ok: Any = None  # the router's resolver answered an HA-side probe
    upstream_ok: Any = None  # the upstream resolver answered
    log_hint: Any = None  # dnsmasq lines (no servers, query limit)

    def __post_init__(self) -> None:
        """Normalise."""
        for name in ("local_ok", "upstream_ok", "log_hint"):
            object.__setattr__(self, name, _bool(getattr(self, name)))


@dataclass(frozen=True, kw_only=True, slots=True)
class DhcpFact:
    """Which daemons serve DHCP on this router, and the pool usage."""

    daemons: Any = None  # subset of hc.SERVICE_NAMES; None: unknown
    pool_usage_pct: Any = None

    def __post_init__(self) -> None:
        """Normalise."""
        object.__setattr__(self, "daemons", _members(self.daemons, hc.SERVICE_NAMES))
        object.__setattr__(self, "pool_usage_pct", _percent(self.pool_usage_pct))


@dataclass(frozen=True, kw_only=True, slots=True)
class RadioFact:
    """The radio of a radio incident (poll, STA detection, topology, RF)."""

    name: Any = None  # uci wifi-device name; only hc.RADIO_NAMES are kept
    up: Any = None
    wireless_uplink: Any = None  # a STA or mesh interface on this radio
    on_mgmt_path: Any = None
    carries_dependants: Any = None
    clients: Any = None
    failures_24h: Any = None
    interference: Any = None

    def __post_init__(self) -> None:
        """Normalise."""
        put = object.__setattr__
        put(self, "name", _member(self.name, hc.RADIO_NAMES))
        for name in (
            "up",
            "wireless_uplink",
            "on_mgmt_path",
            "carries_dependants",
            "interference",
        ):
            put(self, name, _bool(getattr(self, name)))
        put(self, "clients", _count(self.clients))
        put(self, "failures_24h", _count(self.failures_24h))


@dataclass(frozen=True, kw_only=True, slots=True)
class InterfaceFact:
    """The port or interface of an interface incident."""

    role: Any = None  # one of INTERFACE_ROLES
    link_up: Any = None
    errors_high: Any = None
    flapping: Any = None
    upstream_router_down: Any = None
    on_mgmt_path: Any = None
    carries_dependants: Any = None

    def __post_init__(self) -> None:
        """Normalise."""
        put = object.__setattr__
        put(self, "role", _member(self.role, INTERFACE_ROLES))
        for name in (
            "link_up",
            "errors_high",
            "flapping",
            "upstream_router_down",
            "on_mgmt_path",
            "carries_dependants",
        ):
            put(self, name, _bool(getattr(self, name)))


@dataclass(frozen=True, kw_only=True, slots=True)
class WanFact:
    """The WAN of the gateway as the poll shows it."""

    link_up: Any = None  # carrier
    interface_up: Any = None
    has_address: Any = None

    def __post_init__(self) -> None:
        """Normalise."""
        for name in ("link_up", "interface_up", "has_address"):
            object.__setattr__(self, name, _bool(getattr(self, name)))


@dataclass(frozen=True, kw_only=True, slots=True)
class ConfigFact:
    """What the Configuration Manager knows (versions, diff, dry run)."""

    version_known: Any = None
    version_id: Any = None  # bkp_ + 32 hex, checked by the catalog's spec
    diff_proven: Any = None  # the change is shown by a diff, not only a time
    changed_areas: Any = None  # CONFIG_AREAS changed since the last version
    change_risk: Any = None  # CHANGE_RISKS
    restore_check: Any = None  # RESTORE_CHECKS (dry run)
    backup_present: Any = None
    changed_at: Any = None  # when the change was seen (seconds; None: unknown)

    def __post_init__(self) -> None:
        """Normalise."""
        put = object.__setattr__
        put(self, "changed_at", _timestamp(self.changed_at))
        put(self, "version_known", _bool(self.version_known))
        spec = hc.CATALOG["config.restore"].params[0]
        put(
            self,
            "version_id",
            self.version_id
            if type(self.version_id) is str and spec.accepts(self.version_id)
            else None,
        )
        put(self, "diff_proven", _bool(self.diff_proven))
        put(self, "changed_areas", _members(self.changed_areas, CONFIG_AREAS))
        put(self, "change_risk", _member(self.change_risk, CHANGE_RISKS))
        put(self, "restore_check", _member(self.restore_check, RESTORE_CHECKS))
        put(self, "backup_present", _bool(self.backup_present))


@dataclass(frozen=True, kw_only=True, slots=True)
class ClientFact:
    """One client's history (client stability), as counts and flags only."""

    disconnects_24h: Any = None
    weak_signal: Any = None
    roam_flapping: Any = None
    ap_available: Any = None
    dhcp_dns_anomaly: Any = None
    peers_affected: Any = None

    def __post_init__(self) -> None:
        """Normalise."""
        put = object.__setattr__
        put(self, "disconnects_24h", _count(self.disconnects_24h))
        for name in (
            "weak_signal",
            "roam_flapping",
            "ap_available",
            "dhcp_dns_anomaly",
            "peers_affected",
        ):
            put(self, name, _bool(getattr(self, name)))


def _of(value: Any, kind: type) -> Any:
    return value if type(value) is kind else kind()


@dataclass(frozen=True, kw_only=True, slots=True)
class Evidence:
    """The in-memory evidence of one router (None everywhere: unknown).

    Filled later by the adapter from data that is polled anyway (coordinator
    data, Network Intelligence, network diagnostics, WiFi RF, client
    stability, Configuration Manager, topology). Nothing here is fetched.
    ``capabilities``: core capability names -> True (usable), False (not on
    this router), None (unknown). ``chain``: network diagnostics stage ->
    state. ``wan_up``: the router's WAN is up (gateway; None elsewhere).
    """

    role: Any = None
    reachable: Any = None
    capabilities: Any = None
    services: Any = None
    wan_up: Any = None
    dns: Any = None
    dhcp: Any = None
    radio: Any = None
    interface: Any = None
    wan: Any = None
    chain: Any = None
    config: Any = None
    client: Any = None

    def __post_init__(self) -> None:
        """Normalise (never raises)."""
        put = object.__setattr__
        put(self, "role", _member(self.role, ROLES))
        put(self, "reachable", _bool(self.reachable))
        put(self, "wan_up", _bool(self.wan_up))
        caps: dict[str, bool | None] = {}
        if isinstance(self.capabilities, Mapping):
            for index, (key, value) in enumerate(self.capabilities.items()):
                if index >= _ITER_MAX:
                    break
                if type(key) is str and len(key) <= 64:
                    caps[key] = _bool(value)
        put(self, "capabilities", MappingProxyType(caps))
        services: dict[str, ServiceFact] = {}
        if isinstance(self.services, Mapping):
            for name in WATCHED_SERVICES:
                fact = self.services.get(name)
                if type(fact) is ServiceFact:
                    services[name] = fact
        put(self, "services", MappingProxyType(services))
        chain: dict[str, str] = {}
        if isinstance(self.chain, Mapping):
            for stage in CHAIN_STAGES:
                state = _member(self.chain.get(stage), CHAIN_STATES)
                if state is not None:
                    chain[stage] = state
        put(self, "chain", MappingProxyType(chain))
        put(self, "dns", _of(self.dns, DnsFact))
        put(self, "dhcp", _of(self.dhcp, DhcpFact))
        put(self, "radio", _of(self.radio, RadioFact))
        put(self, "interface", _of(self.interface, InterfaceFact))
        put(self, "wan", _of(self.wan, WanFact))
        put(self, "config", _of(self.config, ConfigFact))
        put(self, "client", _of(self.client, ClientFact))

    def service(self, name: str) -> ServiceFact:
        """The poll facts of ``name`` (unknown when not in the poll)."""
        return self.services.get(name, _UNKNOWN_SERVICE)

    def stage(self, name: str) -> bool | None:
        """A chain stage as healthy (True), failed (False) or not known."""
        state = self.chain.get(name)
        if state == "healthy":
            return True
        if state == "failed":
            return False
        return None


# ---------------------------------------------------------------------------
# The playbook data
# ---------------------------------------------------------------------------


class Availability(StrEnum):
    """Whether Network Intelligence can detect what the playbook is for."""

    AVAILABLE = "available"
    PARTIAL = "partial"  # some incident types fit; the core detection is missing
    NOT_AVAILABLE = "not_available"


class Source(StrEnum):
    """In-memory data a step reads (all polled or computed anyway)."""

    NI_INCIDENT = "ni_incident"
    NI_EVENTS = "ni_events"
    POLL_SERVICES = "poll_services"
    POLL_DHCP_POOLS = "poll_dhcp_pools"
    POLL_WIRELESS = "poll_wireless"
    POLL_STA_INTERFACES = "poll_sta_interfaces"
    POLL_PORTS = "poll_ports"
    POLL_WAN = "poll_wan"
    DIAG_CHAIN = "diag_chain"
    DIAG_PROBES = "diag_probes"
    RF_CENTER = "rf_center"
    CLIENT_STABILITY = "client_stability"
    CONFIG_MANAGER = "config_manager"
    TOPOLOGY = "topology"
    CATALOG = "catalog"


class StepKind(StrEnum):
    """What a step does (only READ, CLASSIFY and PROPOSE run in 1.53.0)."""

    READ = "read"
    CLASSIFY = "classify"
    PROPOSE = "propose"
    DEFERRED = "deferred"  # a later package (execute, verify, document)


@dataclass(frozen=True, kw_only=True, slots=True)
class Step:
    """One typed step: what it reads, what it concludes, what it cannot know."""

    step_id: str
    kind: StepKind
    sources: tuple[Source, ...] = ()
    concludes: str | None = None
    cannot_know: tuple[str, ...] = ()
    deferred_to: str | None = None  # package letter for DEFERRED steps


@dataclass(frozen=True, kw_only=True, slots=True)
class Detection:
    """Which Network Intelligence incidents fit, and what is missing."""

    availability: Availability
    incident_types: tuple[str, ...] = ()
    services: tuple[str, ...] = ()  # for system_service_restart: these only
    missing: str | None = None


@dataclass(frozen=True, kw_only=True, slots=True)
class Playbook:
    """One remediation playbook as data (no code, no command, no free text).

    ``may_propose``: catalog actions it may put to the policy (with the
    closed ``service_choices``). ``modelled``: catalog actions it names but
    never proposes in this registry version (disabled in the catalog or
    recommendation only). ``excluded``: catalog actions it must never
    propose (its never-rules).
    """

    playbook_id: str
    letter: str
    version: int
    detection: Detection
    roles: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    prerequisites: tuple[str, ...]
    may_propose: tuple[str, ...]
    service_choices: tuple[str, ...]
    modelled: tuple[str, ...]
    excluded: tuple[str, ...]
    preflight: tuple[str, ...]
    steps: tuple[Step, ...]
    verification: tuple[str, ...]
    abort_conditions: tuple[str, ...]
    escalation: tuple[str, ...]
    never_rules: tuple[str, ...]

    @property
    def risk_class(self) -> RiskClass:
        """The highest catalog base risk of the actions it names (0 if none)."""
        risks = [hc.entry(a).base_risk for a in (*self.may_propose, *self.modelled)]
        return max(risks, default=hc.CATALOG["observe.evaluate"].base_risk)

    @property
    def required_permissions(self) -> tuple[str, ...]:
        """Read rights of the poll plus the catalog's ACL of its actions."""
        out = ["existing_poll_reads"]
        for action in (*self.may_propose, *self.modelled):
            for acl in hc.entry(action).required_acl:
                if acl not in out:
                    out.append(acl)
        return tuple(out)

    @property
    def rollback(self) -> Mapping[str, str]:
        """The catalog's honest rollback statement per named action."""
        return MappingProxyType(
            {
                a: hc.entry(a).rollback_statement
                for a in (*self.may_propose, *self.modelled)
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON (for a view or the docs)."""
        return {
            "playbook_id": self.playbook_id,
            "letter": self.letter,
            "version": self.version,
            "detection": {
                "availability": self.detection.availability.value,
                "incident_types": list(self.detection.incident_types),
                "services": list(self.detection.services),
                "missing": self.detection.missing,
            },
            "roles": list(self.roles),
            "required_capabilities": list(self.required_capabilities),
            "required_permissions": list(self.required_permissions),
            "prerequisites": list(self.prerequisites),
            "risk_class": int(self.risk_class),
            "may_propose": list(self.may_propose),
            "service_choices": list(self.service_choices),
            "modelled": list(self.modelled),
            "excluded": list(self.excluded),
            "preflight": list(self.preflight),
            "steps": [
                {
                    "step_id": s.step_id,
                    "kind": s.kind.value,
                    "sources": [x.value for x in s.sources],
                    "concludes": s.concludes,
                    "cannot_know": list(s.cannot_know),
                    "deferred_to": s.deferred_to,
                }
                for s in self.steps
            ],
            "verification": list(self.verification),
            "rollback": dict(self.rollback),
            "abort_conditions": list(self.abort_conditions),
            "escalation": list(self.escalation),
            "never_rules": list(self.never_rules),
        }


def _read(
    step_id: str,
    *sources: Source,
    concludes: str,
    cannot_know: tuple[str, ...] = (),
) -> Step:
    return Step(
        step_id=step_id,
        kind=StepKind.READ,
        sources=sources,
        concludes=concludes,
        cannot_know=cannot_know,
    )


def _classify(step_id: str, concludes: str = "cause_class") -> Step:
    return Step(step_id=step_id, kind=StepKind.CLASSIFY, concludes=concludes)


def _propose(step_id: str = "propose") -> Step:
    return Step(
        step_id=step_id,
        kind=StepKind.PROPOSE,
        sources=(Source.CATALOG,),
        concludes="proposal_or_recommendation",
    )


def _later(step_id: str, package: str) -> Step:
    return Step(step_id=step_id, kind=StepKind.DEFERRED, deferred_to=package)


_SERVICE_PREFLIGHT: Final = tuple(
    c for c in PREFLIGHT_CHECK_IDS if c != "backup_present"
)
_READ_PREFLIGHT: Final = ("router_reachable", "identity_unique", "components_known")
_WRITE_ABORTS: Final = (
    "router_unreachable",
    "concurrent_repair",
    "incident_resolved",
    "new_root_incident",
    "binding_changed",
)

_PLAYBOOKS: Final = (
    Playbook(
        playbook_id="dns_recovery",
        letter="A",
        version=1,
        detection=Detection(
            availability=Availability.PARTIAL,
            incident_types=("system_service_restart",),
            services=("dnsmasq",),
            missing="dns_resolution_probe",
        ),
        roles=("gateway", "access_point"),
        required_capabilities=("data.services",),
        prerequisites=("root_incident", "single_router", "dns_service_enabled"),
        may_propose=("service.restart",),
        service_choices=("dnsmasq",),
        modelled=(),
        excluded=("router.reboot",),
        preflight=_SERVICE_PREFLIGHT,
        steps=(
            _read(
                "dns_service_state",
                Source.POLL_SERVICES,
                concludes="service_state",
                cannot_know=("cause_of_stop",),
            ),
            _read(
                "local_resolver",
                Source.DIAG_PROBES,
                concludes="local_resolver_answers",
                cannot_know=("router_side_dns_probe",),
            ),
            _read(
                "upstream_resolver",
                Source.DIAG_CHAIN,
                Source.POLL_WAN,
                concludes="upstream_state",
                cannot_know=("upstream_from_router_itself",),
            ),
            _read(
                "config_and_logs",
                Source.NI_EVENTS,
                Source.CONFIG_MANAGER,
                concludes="log_and_config_hints",
                cannot_know=("running_vs_saved_config",),
            ),
            _read(
                "affected_clients",
                Source.NI_INCIDENT,
                Source.TOPOLOGY,
                concludes="affected_count",
            ),
            _propose(),
            _later("controlled_restart", "C2"),
            _later("recheck_dns", "H"),
            _later("document", "K"),
        ),
        verification=(
            *hc.CATALOG["service.restart"].verification_probes,
            "dns_incident_resolved",
        ),
        abort_conditions=(
            "cause_outside_router",
            "service_disabled_on_purpose",
            "service_config_unapplied",
            *_WRITE_ABORTS,
        ),
        escalation=(
            "restart_not_resolved_escalate",
            "cause_unknown_after_refresh_manual",
            "breaker_open_manual",
        ),
        never_rules=("never_restart_cause_outside", "never_restart_disabled_service"),
    ),
    Playbook(
        playbook_id="dhcp_recovery",
        letter="B",
        version=1,
        detection=Detection(
            availability=Availability.PARTIAL,
            incident_types=(
                "dhcp_pool_full",
                "dhcp_conflict",
                "wifi_no_ip",
                "wifi_dhcp_after_connect",
                "system_service_restart",
            ),
            services=("odhcpd",),
            missing="failed_lease_rate",
        ),
        roles=("gateway", "access_point"),
        required_capabilities=("data.services",),
        prerequisites=(
            "root_incident",
            "single_router",
            "dhcp_daemon_known",
            "dhcp_service_enabled",
        ),
        may_propose=("service.restart",),
        service_choices=("dnsmasq", "odhcpd"),
        modelled=(),
        excluded=("router.reboot",),
        preflight=_SERVICE_PREFLIGHT,
        steps=(
            _read(
                "dhcp_service_state",
                Source.POLL_SERVICES,
                concludes="service_state",
                cannot_know=("cause_of_stop",),
            ),
            _read(
                "pool_utilisation",
                Source.POLL_DHCP_POOLS,
                concludes="pool_usage",
            ),
            _read(
                "dhcp_logs",
                Source.NI_EVENTS,
                Source.NI_INCIDENT,
                concludes="lease_failures",
                cannot_know=("failed_lease_rate",),
            ),
            _read(
                "vlan_assignment",
                Source.CONFIG_MANAGER,
                Source.TOPOLOGY,
                concludes="vlan_hints",
                cannot_know=("client_vlan_assignment",),
            ),
            _read(
                "config_changes",
                Source.CONFIG_MANAGER,
                concludes="config_change_in_area",
                cannot_know=("running_vs_saved_config",),
            ),
            _propose(),
            _later("restart_after_approval", "C2"),
            _later("prove_function", "H"),
        ),
        verification=(
            *hc.CATALOG["service.restart"].verification_probes,
            "dhcp_leases_granted_again",
        ),
        abort_conditions=(
            "pool_exhausted",
            "service_disabled_on_purpose",
            "dhcp_daemon_unknown",
            "service_config_unapplied",
            *_WRITE_ABORTS,
        ),
        escalation=(
            "restart_not_resolved_escalate",
            "pool_exhausted_admin_config",
            "breaker_open_manual",
        ),
        never_rules=(
            "never_delete_leases",
            "never_restart_for_pool_exhaustion",
            "never_restart_unknown_daemon",
            "never_restart_disabled_service",
        ),
    ),
    Playbook(
        playbook_id="radio_recovery",
        letter="C",
        version=1,
        detection=Detection(
            availability=Availability.PARTIAL,
            incident_types=(
                "wifi_mass_disconnect",
                "wifi_radio_change",
                "system_service_restart",
            ),
            services=("hostapd", "wpad"),
            missing="radio_failure_counter",
        ),
        roles=("gateway", "access_point"),
        required_capabilities=("data.wireless",),
        prerequisites=("root_incident", "single_router", "radio_known"),
        may_propose=(),
        service_choices=(),
        modelled=("wifi.radio_restart",),
        excluded=("router.reboot",),
        preflight=_SERVICE_PREFLIGHT,
        steps=(
            _read("radio_state", Source.POLL_WIRELESS, concludes="radio_up"),
            _read(
                "hostapd_events",
                Source.NI_EVENTS,
                concludes="failure_pattern",
                cannot_know=("driver_internal_state",),
            ),
            _read(
                "rf_metrics",
                Source.RF_CENTER,
                concludes="interference",
                cannot_know=("rf_without_rf_module",),
            ),
            _read(
                "affected_clients",
                Source.NI_INCIDENT,
                Source.POLL_WIRELESS,
                concludes="clients_on_radio",
            ),
            _read(
                "uplink_and_router",
                Source.POLL_STA_INTERFACES,
                Source.TOPOLOGY,
                concludes="uplink_role",
            ),
            _propose(),
            _classify("client_impact", concludes="impact_counts"),
            _later("recovery_check", "H"),
        ),
        verification=hc.CATALOG["wifi.radio_restart"].verification_probes,
        abort_conditions=(
            "wireless_uplink",
            "radio_carries_dependants",
            "radio_on_management_path",
            *_WRITE_ABORTS,
        ),
        escalation=("recurring_failure_manual", "breaker_open_manual"),
        never_rules=(
            "never_restart_wireless_uplink",
            "never_restart_radio_carrying_dependants",
            "never_restart_radio_on_mgmt_path",
            "never_restart_wpad",
        ),
    ),
    Playbook(
        playbook_id="interface_recovery",
        letter="D",
        version=1,
        detection=Detection(
            availability=Availability.PARTIAL,
            incident_types=(
                "lan_uplink_down",
                "lan_port_flap",
                "lan_port_errors",
                "lan_port_speed_drop",
            ),
            missing="logical_interface_down",
        ),
        roles=("gateway", "access_point"),
        required_capabilities=(),
        prerequisites=("root_incident", "single_router", "port_known"),
        may_propose=(),
        service_choices=(),
        modelled=("interface.cycle",),
        excluded=("router.reboot",),
        preflight=_SERVICE_PREFLIGHT,
        steps=(
            _read(
                "physical_link",
                Source.POLL_PORTS,
                concludes="link_state",
                cannot_know=("cable_or_peer",),
            ),
            _read(
                "error_counters",
                Source.POLL_PORTS,
                Source.NI_INCIDENT,
                concludes="error_ratio",
            ),
            _read(
                "vlan_config",
                Source.CONFIG_MANAGER,
                concludes="config_change_in_area",
                cannot_know=("switch_side_vlan",),
            ),
            _read(
                "uplink_dependencies",
                Source.TOPOLOGY,
                concludes="uplink_role",
            ),
            _classify("narrow_cause"),
            _propose(),
        ),
        verification=hc.CATALOG["interface.cycle"].verification_probes,
        abort_conditions=(
            "uplink_or_management_interface",
            "upstream_router_down",
            *_WRITE_ABORTS,
        ),
        escalation=("physical_check_manual", "breaker_open_manual"),
        never_rules=("never_cycle_uplink_or_mgmt", "never_automatic_interface_change"),
    ),
    Playbook(
        playbook_id="wan_recovery",
        letter="E",
        version=1,
        detection=Detection(
            availability=Availability.AVAILABLE,
            incident_types=("wan_down", "wan_unstable"),
        ),
        roles=("gateway",),
        required_capabilities=(),
        prerequisites=("root_incident", "single_router", "wan_gateway"),
        may_propose=(),
        service_choices=(),
        modelled=(),
        excluded=("router.reboot",),
        preflight=_READ_PREFLIGHT,
        steps=(
            _read(
                "router_and_interfaces",
                Source.POLL_WAN,
                Source.POLL_PORTS,
                concludes="wan_link",
            ),
            _read(
                "gateway",
                Source.DIAG_CHAIN,
                concludes="gateway_reachable",
                cannot_know=("router_side_gateway_ping",),
            ),
            _read("external_ip", Source.DIAG_CHAIN, concludes="internet_reachable"),
            _read(
                "dns_independent",
                Source.DIAG_CHAIN,
                Source.DIAG_PROBES,
                concludes="dns_state",
            ),
            _read(
                "wan_state_and_logs",
                Source.POLL_WAN,
                Source.NI_EVENTS,
                concludes="wan_address",
                cannot_know=("isp_side_state",),
            ),
            _classify("isp_or_local"),
            _propose(),
        ),
        verification=("wan_up_two_polls", "root_incident_not_reopened"),
        abort_conditions=("isp_outage", *_WRITE_ABORTS),
        escalation=("isp_outage_contact_provider", "local_wan_fault_manual"),
        never_rules=("never_reboot_as_standard",),
    ),
    Playbook(
        playbook_id="drift_recovery",
        letter="F",
        version=1,
        detection=Detection(
            availability=Availability.NOT_AVAILABLE,
            missing="drift_incident",
        ),
        roles=("gateway", "access_point"),
        required_capabilities=("config.capture", "config.diff"),
        prerequisites=(
            "root_incident",
            "single_router",
            "diff_proven_change_in_area",
            "config_backup_enabled",
        ),
        may_propose=(),
        service_choices=(),
        modelled=("config.restore",),
        excluded=("router.reboot",),
        preflight=PREFLIGHT_CHECK_IDS,
        steps=(
            _read(
                "last_known_version",
                Source.CONFIG_MANAGER,
                concludes="version_known",
            ),
            _read("config_diff", Source.CONFIG_MANAGER, concludes="changed_areas"),
            _classify("relevant_changes", concludes="relevant_areas"),
            _read(
                "impact",
                Source.NI_INCIDENT,
                Source.TOPOLOGY,
                concludes="affected_count",
            ),
            _read(
                "restore_compatibility",
                Source.CONFIG_MANAGER,
                concludes="restore_check",
                cannot_know=("restore_executor",),
            ),
            _propose("rollback_plan"),
            _later("request_approval", "C2"),
            _later("secured_restore", "G"),
            _later("verify", "H"),
        ),
        verification=hc.CATALOG["config.restore"].verification_probes,
        abort_conditions=(
            "restore_incompatible",
            "no_backup",
            "critical_config_area",
            *_WRITE_ABORTS,
        ),
        escalation=("manual_restore_by_admin", "drift_acknowledge_or_restore"),
        never_rules=("never_automatic_restore", "never_automatic_rollback_critical"),
    ),
    Playbook(
        playbook_id="client_recovery",
        letter="G",
        version=1,
        detection=Detection(
            availability=Availability.AVAILABLE,
            incident_types=(
                "wifi_reconnect_storm",
                "wifi_auth_failures",
                "wifi_band_flapping",
                "wifi_roam_flapping",
            ),
        ),
        roles=("gateway", "access_point"),
        required_capabilities=("data.wireless",),
        prerequisites=("root_incident", "single_router", "single_client"),
        may_propose=(),
        service_choices=(),
        modelled=(),
        excluded=(),
        preflight=_READ_PREFLIGHT,
        steps=(
            _read(
                "stability_history",
                Source.CLIENT_STABILITY,
                concludes="disconnect_pattern",
            ),
            _read(
                "signal_quality",
                Source.POLL_WIRELESS,
                Source.RF_CENTER,
                concludes="signal",
            ),
            _read("roaming", Source.NI_EVENTS, concludes="roaming_pattern"),
            _read("ap_availability", Source.POLL_WIRELESS, concludes="ap_up"),
            _read(
                "dhcp_dns_anomalies",
                Source.NI_INCIDENT,
                concludes="dhcp_dns_hint",
                cannot_know=("client_device_state",),
            ),
            _classify("classify"),
            _propose("recommendations"),
        ),
        verification=("client_stable_24h", "root_incident_not_reopened"),
        abort_conditions=("client_gone",),
        escalation=("pattern_persists_manual",),
        never_rules=("never_client_action",),
    ),
)

PLAYBOOKS: Final[Mapping[str, Playbook]] = MappingProxyType(
    {p.playbook_id: p for p in _PLAYBOOKS}
)
PLAYBOOK_IDS: Final = tuple(p.playbook_id for p in _PLAYBOOKS)

# Incident types that fit no playbook, each with its reason.
NO_PLAYBOOK_REASONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "system_cpu_high": "load_not_repairable",
        "system_ram_high": "load_not_repairable",
        "system_conntrack_jump": "load_not_repairable",
        "lan_port_load": "load_not_repairable",
        "system_clock_skew": "clock_not_covered",
        "system_reboot": "event_not_a_fault",
        "wan_ip_changed": "event_not_a_fault",
        "wan_gateway_changed": "event_not_a_fault",
        "dns_server_changed": "event_not_a_fault",
        "lan_lldp_change": "event_not_a_fault",
        "router_unreachable": "router_unreachable_no_data",
        "lan_unreachable": "router_unreachable_no_data",
        "wifi_weak_clients": "coverage_not_a_fault",
        "wifi_channel_busy": "coverage_not_a_fault",
        "wifi_auth_wave": "security_domain",
    }
)
# Incident types -> playbook (system_service_restart goes by its service).
_TYPE_PLAYBOOK: Final[Mapping[str, str]] = MappingProxyType(
    {
        t: p.playbook_id
        for p in _PLAYBOOKS
        for t in p.detection.incident_types
        if t != "system_service_restart"
    }
)
_SERVICE_PLAYBOOK: Final[Mapping[str, str]] = MappingProxyType(
    {s: p.playbook_id for p in _PLAYBOOKS for s in p.detection.services}
)
# Configuration areas an incident type touches (drift overlay of F).
_TYPE_AREAS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "dhcp_pool_full": frozenset({"dhcp"}),
        "dhcp_conflict": frozenset({"dhcp"}),
        "wifi_no_ip": frozenset({"dhcp", "vlan", "wlan"}),
        "wifi_dhcp_after_connect": frozenset({"dhcp", "vlan", "wlan"}),
        "wifi_mass_disconnect": frozenset({"wlan"}),
        "wifi_radio_change": frozenset({"wlan"}),
        "lan_uplink_down": frozenset({"interface", "vlan"}),
        "lan_port_flap": frozenset({"interface", "vlan"}),
        "lan_port_errors": frozenset({"interface", "vlan"}),
        "lan_port_speed_drop": frozenset({"interface", "vlan"}),
        "wan_down": frozenset({"interface", "routing"}),
        "wan_unstable": frozenset({"interface", "routing"}),
        "wifi_reconnect_storm": frozenset({"wlan"}),
        "wifi_auth_failures": frozenset({"wlan"}),
        "wifi_band_flapping": frozenset({"wlan"}),
        "wifi_roam_flapping": frozenset({"wlan"}),
    }
)
_SERVICE_AREAS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "dnsmasq": frozenset({"dns", "dhcp", "services"}),
        "odhcpd": frozenset({"dhcp", "services"}),
        "hostapd": frozenset({"wlan"}),
        "wpad": frozenset({"wlan"}),
    }
)


# ---------------------------------------------------------------------------
# German texts (codes -> plain sentences; never interpolated)
# ---------------------------------------------------------------------------

TEXT_DE: Final[Mapping[str, str]] = MappingProxyType(
    {
        # playbooks
        "dns_recovery": "Playbook A: DNS wiederherstellen",
        "dhcp_recovery": "Playbook B: DHCP wiederherstellen",
        "radio_recovery": "Playbook C: WLAN-Funk wiederherstellen",
        "interface_recovery": "Playbook D: Schnittstelle wiederherstellen",
        "wan_recovery": "Playbook E: WAN wiederherstellen",
        "drift_recovery": "Playbook F: Konfigurationsabweichung beheben",
        "client_recovery": "Playbook G: Client-Verbindung wiederherstellen",
        # missing detections
        "dns_resolution_probe": (
            "Es gibt noch keine Prüfung, die eine fehlschlagende DNS-Auflösung bei "
            "funktionierender IP-Verbindung erkennt; dnsmasq-Logzeilen sind nur "
            "Ereignisse, kein Vorfall."
        ),
        "failed_lease_rate": (
            "Network Intelligence zählt fehlgeschlagene Lease-Vorgänge nur je Client, "
            "nicht als Häufung für den ganzen Router."
        ),
        "radio_failure_counter": (
            "Es gibt keinen Vorfall „Funk fällt wiederholt aus“; erkannt werden nur "
            "Massen-Trennungen, Kanalwechsel und Neustarts von hostapd/wpad."
        ),
        "logical_interface_down": (
            "Erkannt werden ausgefallene Ports und Uplinks, aber keine logische "
            "Schnittstelle, die unerwartet ausfällt."
        ),
        "drift_incident": (
            "Network Intelligence meldet keine Konfigurationsabweichung als Vorfall; "
            "Playbook F greift nur, wenn ein Vergleich eine Änderung im betroffenen "
            "Bereich belegt."
        ),
        # match results
        "matched": "Ein passendes Playbook wurde gefunden.",
        "unknown_incident_type": "Unbekannte Vorfallart: kein Playbook.",
        "not_root_incident": (
            "Folgevorfall: repariert wird nur der Wurzelvorfall, nicht seine Folgen."
        ),
        "root_unknown": "Ob es ein Wurzelvorfall ist, ist unbekannt: kein Playbook.",
        "temporal_correlation_only": (
            "Nur zeitliche Nähe verbindet den Vorfall mit einer Ursache: kein Playbook."
        ),
        "fleet_scope": "Vorfall der ganzen Flotte: kein Playbook für einen Router.",
        "service_not_covered": "Für diesen Dienst gibt es kein Playbook.",
        "load_not_repairable": "Hohe Last ist kein Fall für eine Reparatur.",
        "clock_not_covered": "Uhrzeitabweichungen deckt kein Playbook ab.",
        "event_not_a_fault": "Ein Ereignis, keine Störung: nichts zu reparieren.",
        "router_unreachable_no_data": (
            "Der Router ist nicht erreichbar; ohne Daten von ihm gibt es nichts zu "
            "analysieren."
        ),
        "coverage_not_a_fault": "Funkabdeckung ist keine Störung, die sich reparieren lässt.",
        "security_domain": (
            "Fall des Security Centers; Self-Healing sperrt und blockiert nichts."
        ),
        "drift_overlay": (
            "Ein Vergleich belegt eine Konfigurationsänderung im betroffenen Bereich: "
            "Playbook F statt des Playbooks der Vorfallart."
        ),
        "role_not_supported": "Das Playbook passt nicht zur Rolle dieses Routers.",
        "capability_missing": (
            "Diesem Router fehlt eine nötige Fähigkeit (etwa ein Repeater eines "
            "anderen Herstellers); das Playbook wird nicht angewendet."
        ),
        # cause classes
        "service_disabled_on_purpose": (
            "Der Dienst ist auf diesem Router absichtlich abgeschaltet; „läuft nicht“ "
            "ist hier der Sollzustand, keine Störung."
        ),
        "cause_outside_router": (
            "Die Ursache liegt außerhalb des Routers (WAN, Gateway oder vorgelagerter "
            "DNS-Server)."
        ),
        "dns_service_down": "dnsmasq ist eingeschaltet, läuft aber nicht oder startet ständig neu.",
        "local_resolver_failing": (
            "dnsmasq läuft, beantwortet aber keine Anfragen; der Grund ist nicht "
            "belegt."
        ),
        "cause_unknown": "Die Ursache lässt sich mit den vorhandenen Daten nicht bestimmen.",
        "dhcp_service_down": (
            "Der DHCP-Dienst ist eingeschaltet, läuft aber nicht oder startet "
            "ständig neu."
        ),
        "pool_exhausted": "Der DHCP-Adressbereich ist (fast) voll.",
        "address_conflict": "Ein Gerät belegt eine Adresse, die DHCP vergeben will.",
        "dhcp_daemon_unknown": "Unbekannt, welcher Dienst auf diesem Router DHCP vergibt.",
        "daemon_not_serving_dhcp": "Dieser Dienst vergibt auf diesem Router kein DHCP.",
        "client_side_dhcp": "Die Ursache liegt beim Client (feste Adresse, falsches Netz).",
        "radio_recurring_failure": "Der Funk fällt wiederholt aus.",
        "channel_change_normal": (
            "Ein Kanalwechsel (DFS, Radar) ist normales Verhalten, keine Störung."
        ),
        "single_drop": "Ein einzelner Ausfall, noch keine Wiederholung.",
        "rf_interference": "Störungen im Funkkanal (Interferenz) sind wahrscheinlich.",
        "radio_unknown": "Der betroffene Funk ist nicht eindeutig bekannt.",
        "uplink_unknown": "Unbekannt, ob dieser Funk einen Uplink trägt.",
        "upstream_router_down": "Der vorgelagerte Router ist ausgefallen.",
        "port_errors": "Der Port zeigt viele Fehler (Kabel, Stecker, Gegenstelle).",
        "port_flapping": "Der Port geht wiederholt aus und an.",
        "link_down": "Die Verbindung am Port ist unten.",
        "isp_outage": (
            "Störung beim Anbieter: der Router und seine WAN-Verbindung sind in "
            "Ordnung, dahinter ist das Internet nicht erreichbar."
        ),
        "wan_link_down": "Die WAN-Leitung ist physisch unten (Kabel, Modem, Anschluss).",
        "wan_no_address": "WAN ist verbunden, hat aber keine Adresse vom Anbieter.",
        "dns_only": "Das Internet ist erreichbar, nur DNS schlägt fehl.",
        "wan_interface_down": (
            "Die Leitung ist da, die WAN-Schnittstelle aber unten; ob der Router oder "
            "der Anbieter (Anmeldung, Adressvergabe) die Ursache ist, ist unbekannt."
        ),
        "pool_usage_unknown": (
            "Die Belegung des Adressbereichs ist unbekannt; ein voller Bereich ist "
            "nicht ausgeschlossen."
        ),
        "drift_hint": (
            "Eine Konfigurationsänderung im betroffenen Bereich ist belegt; ihr "
            "Zeitpunkt bindet sie aber nicht sicher an den Vorfall. Nur ein Hinweis."
        ),
        "drift_hint_outside_measured": (
            "Eine Konfigurationsänderung ist belegt, die Messung legt die Ursache "
            "aber außerhalb des Routers; das ursprüngliche Playbook bleibt."
        ),
        "drift_in_service_area": (
            "Eine belegte Konfigurationsänderung betrifft den Bereich dieses "
            "Dienstes; ein Neustart würde die gespeicherte, nicht geprüfte "
            "Änderung übernehmen."
        ),
        "wont_restart_unreviewed_change": (
            "Kein Neustart: er würde eine gespeicherte, nicht geprüfte "
            "Konfigurationsänderung dieses Dienstes übernehmen; zuerst den "
            "Vergleich prüfen."
        ),
        "drift_hint_outside_signal": (
            "Eine Konfigurationsänderung ist belegt, es gibt aber auch einen "
            "Hinweis auf eine Ursache außerhalb des Routers; das ursprüngliche "
            "Playbook bleibt, die Änderung ist nur ein Hinweis."
        ),
        "services_capability_unknown": (
            "Nicht bestätigt, dass dieser Router seine Dienste meldet."
        ),
        "drift_in_area": "Eine belegte Konfigurationsänderung betrifft den gestörten Bereich.",
        "weak_signal": "Das Signal des Clients ist schwach.",
        "roaming_flapping": "Der Client wechselt ständig den Access Point.",
        "ap_unavailable": "Der Access Point des Clients war nicht verfügbar.",
        "dhcp_dns_side": "Auffälligkeiten bei DHCP oder DNS betreffen den Client.",
        "client_side": "Die Ursache liegt wahrscheinlich am Client selbst.",
        # recommendations
        "rec_restart_dnsmasq_with_approval": (
            "Empfohlen: dnsmasq nach Freigabe gezielt neu starten."
        ),
        "rec_restart_dhcp_daemon_with_approval": (
            "Empfohlen: den DHCP-Dienst nach Freigabe gezielt neu starten."
        ),
        "rec_check_wan_and_upstream_dns": (
            "Empfohlen: WAN-Verbindung und vorgelagerte DNS-Server prüfen."
        ),
        "rec_refresh_and_diagnose": (
            "Empfohlen: Daten neu abfragen und die Netzwerkdiagnose laufen lassen."
        ),
        "rec_nothing_to_do": "Nichts zu tun.",
        "rec_enlarge_pool_or_shorten_lease": (
            "Empfohlen: den Adressbereich vergrößern oder die Lease-Zeit verkürzen "
            "(von Hand)."
        ),
        "rec_find_conflicting_device": (
            "Empfohlen: das Gerät mit der doppelten Adresse finden und umstellen."
        ),
        "rec_determine_dhcp_daemon": (
            "Empfohlen: festhalten, welcher Dienst auf diesem Router DHCP vergibt."
        ),
        "rec_check_client_network": (
            "Empfohlen: Netz und Adresseinstellung des Clients prüfen."
        ),
        "rec_radio_restart_manual_with_approval": (
            "Empfohlen: den Funk nach Freigabe von Hand und mit Blick auf die "
            "Clients neu starten."
        ),
        "rec_radio_carries_mgmt_path": (
            "Kein Neustart von Hand empfohlen: über diesen Funk läuft der Weg von "
            "Home Assistant zum Router; erst einen anderen Weg sichern."
        ),
        "rec_radio_mgmt_path_unknown": (
            "Kein Neustart von Hand empfohlen: unbekannt, ob der Weg von Home "
            "Assistant zum Router über diesen Funk läuft; das zuerst klären."
        ),
        "rec_identify_radio": (
            "Empfohlen: zuerst feststellen, welcher Funk betroffen ist."
        ),
        "rec_check_upstream_path": (
            "Empfohlen: den Weg nach oben prüfen (Uplink, vorgelagerter Router); ein "
            "Neustart auf diesem Router würde nichts beheben."
        ),
        "rec_review_diff": (
            "Hinweis: eine Konfigurationsänderung im betroffenen Bereich ist belegt; "
            "den Vergleich prüfen."
        ),
        "rec_check_channel_and_interference": (
            "Empfohlen: Kanalwahl und Störquellen prüfen (WiFi RF)."
        ),
        "rec_observe_radio": "Empfohlen: den Funk weiter beobachten.",
        "rec_check_uplink_by_hand": (
            "Empfohlen: von Hand prüfen, ob hier ein Uplink liegt oder andere Router "
            "daran hängen, bevor jemand eingreift."
        ),
        "rec_check_cable_and_peer": (
            "Empfohlen: Kabel, Stecker und Gegenstelle des Ports prüfen."
        ),
        "rec_check_upstream_router": "Empfohlen: den vorgelagerten Router prüfen.",
        "rec_wait_for_provider": (
            "Empfohlen: Störung beim Anbieter abwarten oder melden; am Router ist "
            "nichts zu reparieren."
        ),
        "rec_check_modem_and_cable": "Empfohlen: Modem, Kabel und Anschluss prüfen.",
        "rec_check_wan_settings": (
            "Empfohlen: WAN-Einstellungen und Anmeldung beim Anbieter prüfen."
        ),
        "rec_follow_dns_playbook": "Empfohlen: DNS getrennt prüfen (Playbook A).",
        "rec_review_diff_and_plan_restore": (
            "Empfohlen: die Änderung im Vergleich prüfen und eine Wiederherstellung "
            "planen (Probelauf)."
        ),
        "rec_restore_manually_after_review": (
            "Empfohlen: falls nötig von Hand wiederherstellen (LuCI oder sysupgrade), "
            "erst nach Prüfung und ausdrücklicher Freigabe."
        ),
        "rec_enable_config_backup": (
            "Empfohlen: Sicherungen im Configuration Manager einschalten."
        ),
        "rec_improve_coverage": (
            "Empfohlen: Abdeckung verbessern oder den Client näher an einen Access "
            "Point bringen."
        ),
        "rec_tune_roaming": "Empfohlen: Roaming-Einstellungen (Schwellen) prüfen.",
        "rec_check_ap": "Empfohlen: den Access Point prüfen.",
        "rec_check_client_device": (
            "Empfohlen: den Client prüfen (Treiber, Energiesparen, Passwort)."
        ),
        "rec_follow_dhcp_dns_playbooks": (
            "Empfohlen: DHCP und DNS prüfen (Playbooks A und B)."
        ),
        # what the system will not do
        "wont_execute_in_observe_release": (
            "Diese Version führt nichts aus: sie analysiert und empfiehlt nur."
        ),
        "wont_restart_cause_outside": (
            "Kein Neustart: die Ursache liegt außerhalb des Routers, ein Neustart "
            "würde nichts beheben."
        ),
        "wont_restart_disabled_service": (
            "Kein Neustart: der Dienst ist absichtlich aus; ein Start brächte einen "
            "zweiten DHCP-/DNS-Server ins Netz."
        ),
        "wont_restart_without_evidence": (
            "Kein Neustart vorgeschlagen: die Hinweise reichen nicht."
        ),
        "wont_delete_leases": (
            "Leases werden nie gelöscht; dafür gibt es keine Aktion."
        ),
        "wont_restart_for_pool": (
            "Kein Neustart: ein voller Adressbereich wird davon nicht leerer."
        ),
        "wont_restart_unknown_daemon": (
            "Kein Neustart: unklar, welcher Dienst DHCP vergibt."
        ),
        "wont_restart_wireless_uplink": (
            "Kein Funk-Neustart: dieser Funk trägt einen WLAN-Uplink; der Router "
            "wäre danach nicht mehr erreichbar."
        ),
        "wont_restart_radio_with_dependants": (
            "Kein Funk-Neustart: andere Router hängen an diesem Funk."
        ),
        "wont_restart_uplink_unknown": (
            "Kein Funk-Neustart: unbekannt, ob dieser Funk einen WLAN-Uplink trägt."
        ),
        "wont_restart_radio_dependants_unknown": (
            "Kein Funk-Neustart: unbekannt, ob andere Router an diesem Funk hängen."
        ),
        "wont_restart_radio_on_mgmt_path": (
            "Kein Funk-Neustart: über diesen Funk läuft der Weg von Home Assistant "
            "zum Router."
        ),
        "wont_restart_radio_mgmt_unknown": (
            "Kein Funk-Neustart: unbekannt, ob der Weg von Home Assistant zum Router "
            "über diesen Funk läuft."
        ),
        "wont_restart_capability_unknown": (
            "Kein Neustart vorgeschlagen: nicht bestätigt, dass dieser Router seine "
            "Dienste meldet (Fähigkeit unbekannt)."
        ),
        "wont_restart_pool_unknown": (
            "Kein Neustart vorgeschlagen: die Belegung des Adressbereichs ist "
            "unbekannt, ein voller Bereich ist nicht ausgeschlossen."
        ),
        "wont_restart_radio_disabled": (
            "Kein Funk-Neustart: die Aktion ist im Katalog gesperrt (auf der Flotte "
            "nicht geprüft)."
        ),
        "wont_restart_wpad": "Kein Neustart von wpad: davon hängt jeder WLAN-Client ab.",
        "wont_cycle_interface": (
            "Keine Schnittstelle wird ab- und angeschaltet; nur eine Empfehlung."
        ),
        "wont_cycle_uplink_or_mgmt": (
            "Kein Ab- und Anschalten: Uplink-, WAN- oder Management-Schnittstelle, "
            "oder andere Router hängen daran; der Router wäre danach vielleicht "
            "nicht mehr erreichbar."
        ),
        "wont_cycle_role_unknown": (
            "Kein Ab- und Anschalten: unbekannt, ob die Schnittstelle Uplink, WAN "
            "oder Management-Weg ist oder andere Router daran hängen."
        ),
        "wont_reboot": "Kein Router-Neustart als Standardlösung.",
        "wont_restore_automatically": (
            "Keine automatische Wiederherstellung: sie ist nur ein Probelauf und "
            "braucht eine ausdrückliche Freigabe."
        ),
        "wont_rollback_critical_config": (
            "Keine automatische Rücksetzung kritischer Konfiguration (Firewall, VLAN, "
            "Management, Routing, SSH, Schnittstellen)."
        ),
        "wont_touch_client": (
            "Kein Trennen, kein Sperren, kein erzwungenes Umlenken des Clients; dafür "
            "gibt es keine Aktion."
        ),
        # never-rules
        "never_restart_cause_outside": (
            "Nie ein Neustart, wenn die Ursache klar außerhalb des Routers liegt."
        ),
        "never_restart_disabled_service": (
            "Nie ein Neustart eines absichtlich abgeschalteten Dienstes."
        ),
        "never_delete_leases": "Nie DHCP-Leases löschen.",
        "never_restart_for_pool_exhaustion": (
            "Nie ein Neustart wegen eines vollen Adressbereichs."
        ),
        "never_restart_unknown_daemon": (
            "Nie ein Neustart, solange unklar ist, welcher Dienst DHCP vergibt."
        ),
        "never_restart_wireless_uplink": "Nie ein Funk-Neustart auf einem WLAN-Uplink.",
        "never_restart_radio_carrying_dependants": (
            "Nie ein Funk-Neustart, wenn andere Router daran hängen."
        ),
        "never_restart_radio_on_mgmt_path": (
            "Nie ein Funk-Neustart auf dem Weg von Home Assistant zum Router."
        ),
        "never_restart_wpad": "Nie ein Neustart von wpad.",
        "never_cycle_uplink_or_mgmt": (
            "Nie eine Uplink-, WAN- oder Management-Schnittstelle automatisch ab- "
            "und anschalten."
        ),
        "never_automatic_interface_change": (
            "Nie eine Schnittstelle automatisch ändern; nur Empfehlung."
        ),
        "never_reboot_as_standard": "Nie ein pauschaler Router-Neustart.",
        "never_automatic_restore": "Nie eine automatische Wiederherstellung.",
        "never_automatic_rollback_critical": (
            "Nie eine automatische Rücksetzung kritischer Konfiguration."
        ),
        "never_client_action": (
            "Nie Deauthentifizierung, Sperre oder erzwungenes Roaming eines Clients."
        ),
        # abort conditions
        "service_config_unapplied": (
            "Abbruch: die gespeicherte Konfiguration des Dienstes weicht von der "
            "laufenden ab."
        ),
        "router_unreachable": "Abbruch: der Router ist nicht erreichbar.",
        "concurrent_repair": "Abbruch: am Router läuft schon eine Reparatur.",
        "incident_resolved": "Abbruch: der Vorfall hat sich erledigt.",
        "new_root_incident": "Abbruch: ein neuer Wurzelvorfall ist aufgetreten.",
        "binding_changed": "Abbruch: der Zustand hat sich seit der Freigabe geändert.",
        "wireless_uplink": "Abbruch: der Funk trägt einen WLAN-Uplink.",
        "radio_carries_dependants": "Abbruch: andere Router hängen an diesem Funk.",
        "radio_on_management_path": "Abbruch: der Funk liegt auf dem Management-Weg.",
        "uplink_or_management_interface": (
            "Abbruch: Uplink- oder Management-Schnittstelle."
        ),
        "restore_incompatible": "Abbruch: die Sicherung passt nicht zu diesem Router.",
        "no_backup": "Abbruch: keine Sicherung vorhanden.",
        "critical_config_area": "Abbruch: kritischer Konfigurationsbereich.",
        "client_gone": "Abbruch: der Client ist nicht mehr da.",
        # escalation
        "restart_not_resolved_escalate": (
            "Hilft ein Neustart nicht, wird an den Administrator eskaliert; kein "
            "zweiter Versuch ohne Bestätigung."
        ),
        "cause_unknown_after_refresh_manual": (
            "Bleibt die Ursache nach neuer Abfrage unklar: Prüfung von Hand."
        ),
        "breaker_open_manual": (
            "Ist der Schutzschalter offen, entscheidet nur der Administrator."
        ),
        "pool_exhausted_admin_config": (
            "Voller Adressbereich: Änderung der Konfiguration durch den Administrator."
        ),
        "recurring_failure_manual": "Wiederkehrende Funkausfälle: Prüfung von Hand.",
        "physical_check_manual": "Kabel und Gegenstelle prüft ein Mensch.",
        "isp_outage_contact_provider": "Störung beim Anbieter: den Anbieter kontaktieren.",
        "local_wan_fault_manual": "Lokale WAN-Störung: Prüfung von Hand.",
        "manual_restore_by_admin": (
            "Wiederherstellen nur von Hand durch den Administrator."
        ),
        "drift_acknowledge_or_restore": (
            "Die Abweichung bestätigen oder von Hand zurücksetzen."
        ),
        "pattern_persists_manual": "Bleibt das Muster, prüft ein Mensch den Client.",
        # cannot know today
        "cause_of_stop": "Nicht bekannt: warum der Dienst angehalten hat.",
        "router_side_dns_probe": (
            "Nicht möglich: eine DNS-Prüfung auf dem Router selbst (nur von Home "
            "Assistant aus, wenn eingerichtet)."
        ),
        "upstream_from_router_itself": (
            "Nicht möglich: den vorgelagerten DNS-Server vom Router aus prüfen."
        ),
        "running_vs_saved_config": (
            "Nicht bekannt: ob die gespeicherte Konfiguration des Dienstes von der "
            "laufenden abweicht."
        ),
        "client_vlan_assignment": "Nicht bekannt: in welchem VLAN ein Client landet.",
        "driver_internal_state": "Nicht bekannt: der Zustand im WLAN-Treiber.",
        "rf_without_rf_module": "Ohne eingeschaltetes WiFi RF keine Funkmesswerte.",
        "cable_or_peer": "Nicht unterscheidbar: Kabel oder Gegenstelle.",
        "switch_side_vlan": "Nicht bekannt: VLAN-Einstellung am Switch.",
        "router_side_gateway_ping": "Nicht möglich: Ping zum Gateway vom Router aus.",
        "isp_side_state": "Nicht bekannt: der Zustand beim Anbieter.",
        "restore_executor": "Es gibt keinen Ausführer für eine Wiederherstellung.",
        "client_device_state": "Nicht bekannt: der Zustand im Client-Gerät.",
    }
)


# ---------------------------------------------------------------------------
# Registry check at import (a broken definition never loads)
# ---------------------------------------------------------------------------


def _check_registry() -> None:
    seen_types: set[tuple[str, str | None]] = set()
    for p in _PLAYBOOKS:
        if p.playbook_id not in TEXT_DE:
            raise PlaybookError("playbook_without_text")
        for action in (*p.may_propose, *p.modelled, *p.excluded):
            hc.entry(action)  # CatalogError if not in the catalog
        if set(p.may_propose) & set(p.excluded) or set(p.modelled) & set(p.excluded):
            raise PlaybookError("excluded_action_named")
        for name in p.service_choices:
            if name not in hc.SERVICE_NAMES:
                raise PlaybookError("service_not_in_catalog")
        for check in p.preflight:
            if check not in PREFLIGHT_CHECK_IDS:
                raise PlaybookError("unknown_preflight_check")
        for t in p.detection.incident_types:
            if t not in KNOWN_INCIDENT_TYPES:
                raise PlaybookError("unknown_incident_type")
            keys = (
                [(t, s) for s in p.detection.services]
                if t == "system_service_restart"
                else [(t, None)]
            )
            for key in keys:
                if key in seen_types:
                    raise PlaybookError("incident_type_twice")
                seen_types.add(key)
        for code in (
            *p.never_rules,
            *p.abort_conditions,
            *p.escalation,
            *(c for s in p.steps for c in s.cannot_know),
        ):
            if code not in TEXT_DE:
                raise PlaybookError("code_without_text")
        if p.detection.missing is not None and p.detection.missing not in TEXT_DE:
            raise PlaybookError("code_without_text")
    mapped = {t for t, _ in seen_types}
    if mapped & set(NO_PLAYBOOK_REASONS) or (mapped | set(NO_PLAYBOOK_REASONS)) != set(
        KNOWN_INCIDENT_TYPES
    ):
        raise PlaybookError("incident_types_not_partitioned")


_check_registry()


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------


class MatchStatus(StrEnum):
    """What the matcher found."""

    MATCHED = "matched"
    UNSUPPORTED = "unsupported"  # it would fit, but not on this router
    NO_PLAYBOOK = "no_playbook"


@dataclass(frozen=True, kw_only=True, slots=True)
class Match:
    """At most one playbook for an incident, with the reason as a code.

    ``drift_overlay``: Playbook F replaces ``original_playbook_id`` (a
    diff-proven change in the incident's area, made before the incident
    started); :func:`assess` still lets the original playbook keep the case
    when it measures the cause as outside. ``drift_hint``: such a change is
    proven, but its time does not tie it to the incident; it is a hint only.
    """

    status: MatchStatus
    playbook_id: str | None
    reason: str
    missing: tuple[str, ...] = ()  # capabilities this router lacks
    drift_overlay: bool = False
    drift_hint: bool = False
    original_playbook_id: str | None = None


def _no(reason: str) -> Match:
    return Match(status=MatchStatus.NO_PLAYBOOK, playbook_id=None, reason=reason)


def _areas_of(inc: IncidentInput) -> frozenset[str]:
    if inc.incident_type == "system_service_restart":
        return _SERVICE_AREAS.get(inc.service or "", frozenset())
    return _TYPE_AREAS.get(inc.incident_type or "", frozenset())


def _drift_in_area(inc: IncidentInput, ev: Evidence) -> bool:
    """A diff-proven change in an area this incident touches (not time only)."""
    cfg = ev.config
    return (
        cfg.diff_proven is True
        and cfg.changed_areas is not None
        and bool(cfg.changed_areas & _areas_of(inc))
    )


def _drift_before_incident(inc: IncidentInput, ev: Evidence) -> bool:
    """The proven change is known to predate the incident's start."""
    changed, started = ev.config.changed_at, inc.started_at
    return changed is not None and started is not None and changed < started


def _support(pb: Playbook, evidence: Evidence) -> tuple[str | None, tuple[str, ...]]:
    """Why ``pb`` does not fit this router (None: it fits), and what is missing."""
    if (
        evidence.role in ROLES
        and evidence.role != "unknown"
        and (evidence.role not in pb.roles)
    ):
        return "role_not_supported", ()
    missing = tuple(
        cap
        for cap in pb.required_capabilities
        if evidence.capabilities.get(cap) is False
    )
    if missing:
        return "capability_missing", missing
    return None, ()


def match(incident: IncidentInput, evidence: Evidence) -> Match:
    """At most one playbook for ``incident`` on the router of ``evidence``.

    Deterministic; the first rule that applies wins:

    1. not an :class:`IncidentInput` / :class:`Evidence`: ``PlaybookError``;
    2. an unknown incident type: no playbook;
    3. not a root (``is_root`` False), or root unknown (None): no playbook;
    4. a link by time only (``temporal_only`` True, always so when nothing
       but the link is observed): no playbook;
    5. a fleet-wide incident: no playbook (one router only);
    6. the type has no playbook (load, events, coverage, security): its
       reason; ``system_service_restart`` goes by its service (dnsmasq A,
       odhcpd B, hostapd/wpad C, else none);
    7. the playbook does not fit the router's known role, or the router
       lacks a required capability (False; unknown is not missing):
       UNSUPPORTED with the reason;
    8. a diff-proven configuration change in an area the incident touches,
       seen before the incident started, on a router Playbook F fits:
       Playbook F instead (the drift overlay) - unless the original playbook
       sees an outside signal (:func:`outside_signals`): then it keeps the
       case and the change is a hint (reason ``drift_hint_outside_measured``
       when the original playbook measures the cause outside, else
       ``drift_hint_outside_signal``; :func:`assess` returns exactly this
       match and puts the same reason in the finding). A proven change with
       an unknown or later time is a hint only.
    """
    if type(incident) is not IncidentInput or type(evidence) is not Evidence:
        raise PlaybookError("invalid input")
    inc = incident
    if inc.incident_type is None:
        return _no("unknown_incident_type")
    if inc.is_root is False:
        return _no("not_root_incident")
    if inc.is_root is not True:
        return _no("root_unknown")
    if inc.temporal_only is True:
        return _no("temporal_correlation_only")
    if inc.scope == "fleet":
        return _no("fleet_scope")
    if inc.incident_type in NO_PLAYBOOK_REASONS:
        return _no(NO_PLAYBOOK_REASONS[inc.incident_type])
    if inc.incident_type == "system_service_restart":
        found = _SERVICE_PLAYBOOK.get(inc.service or "")
    else:
        found = _TYPE_PLAYBOOK.get(inc.incident_type)
    if found is None:
        return _no("service_not_covered")
    reason, missing = _support(PLAYBOOKS[found], evidence)
    if reason is not None:
        return Match(
            status=MatchStatus.UNSUPPORTED,
            playbook_id=found,
            reason=reason,
            missing=missing,
        )
    drift = _drift_in_area(inc, evidence)
    if (
        drift
        and _drift_before_incident(inc, evidence)
        and _support(PLAYBOOKS["drift_recovery"], evidence)[0] is None
    ):
        if outside_signal(found, inc, evidence):
            # the original playbook sees a sign of an outside cause: it keeps
            # the case, the change is a hint; the reason says whether it
            # measured the cause outside (assess repeats this reason)
            return Match(
                status=MatchStatus.MATCHED,
                playbook_id=found,
                reason=(
                    "drift_hint_outside_measured"
                    if _measured_outside(found, inc, evidence)
                    else "drift_hint_outside_signal"
                ),
                drift_hint=True,
            )
        return Match(
            status=MatchStatus.MATCHED,
            playbook_id="drift_recovery",
            reason="drift_overlay",
            drift_overlay=True,
            original_playbook_id=found,
        )
    return Match(
        status=MatchStatus.MATCHED,
        playbook_id=found,
        reason="matched",
        drift_hint=drift,
    )


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class FindingStatus(StrEnum):
    """The playbook's result."""

    PROPOSAL = "proposal"  # a catalog action goes to the policy
    RECOMMENDATION_ONLY = "recommendation_only"
    NOTHING_TO_REPAIR = "nothing_to_repair"
    UNSUPPORTED = "unsupported"


class StepOutcome(StrEnum):
    """What a step could tell."""

    KNOWN = "known"
    UNKNOWN = "unknown"  # the evidence it reads is not there
    NOT_IN_RELEASE = "not_in_release"  # a later package
    NOT_RUN = "not_run"  # the playbook does not apply here


@dataclass(frozen=True, kw_only=True, slots=True)
class StepResult:
    """A step and its result (codes only)."""

    step_id: str
    outcome: StepOutcome
    conclusion: str | None = None


@dataclass(frozen=True, kw_only=True, slots=True)
class Withheld:
    """A catalog action the playbook considered and did not propose."""

    action_type: str
    reason: str


@dataclass(frozen=True, kw_only=True, slots=True)
class DriftPlan:
    """Playbook F's plan shape: a dry run and manual steps, never an execution.

    ``version_id``: the stored version a restore would use (package G: the
    newest restorable archive of the content before the change).
    ``changed_areas``: every area the stored comparison shows as changed;
    ``relevant_areas`` the ones the incident touches. ``restore_executable``
    is always False: there is no restore executor (the Configuration
    Manager's provider only runs a dry run), so a restore is by hand only.
    Every field is validated again on ``dataclasses.replace`` (package G).
    """

    version_id: str | None
    version_known: bool | None
    relevant_areas: tuple[str, ...]
    critical_areas: tuple[str, ...]
    change_risk: str | None
    restore_check: str | None
    backup_present: bool | None
    manual_steps: tuple[str, ...]
    changed_areas: tuple[str, ...] = ()
    requires_explicit_approval: bool = True
    executes: bool = False
    restore_executable: bool = False

    def __post_init__(self) -> None:
        """A plan never executes, never restores, always needs an approval."""
        if self.executes is not False or self.requires_explicit_approval is not True:
            raise PlaybookError("plan_must_not_execute")
        if self.restore_executable is not False:
            raise PlaybookError("restore_not_executable")
        if not _plan_sound(self):
            raise PlaybookError("invalid_plan")


def _areas_sound(value: Any) -> bool:
    """A sorted tuple of distinct configuration areas."""
    return (
        type(value) is tuple
        and all(type(a) is str and a in CONFIG_AREAS for a in value)
        and list(value) == sorted(set(value))
    )


def _plan_sound(plan: DriftPlan) -> bool:
    """Every field of ``plan`` inside its closed set (package G)."""
    spec = hc.CATALOG["config.restore"].params[0]
    if plan.version_id is not None and not spec.accepts(plan.version_id):
        return False
    for flag in (plan.version_known, plan.backup_present):
        if flag is not None and type(flag) is not bool:
            return False
    if not (_areas_sound(plan.changed_areas) and _areas_sound(plan.relevant_areas)):
        return False
    if not set(plan.relevant_areas) <= set(plan.changed_areas):
        return False
    if plan.critical_areas != tuple(
        a for a in plan.relevant_areas if a in CRITICAL_CONFIG_AREAS
    ):
        return False
    if plan.change_risk is not None and _member(plan.change_risk, CHANGE_RISKS) is None:
        return False
    if plan.restore_check is not None and (
        _member(plan.restore_check, RESTORE_CHECKS) is None
    ):
        return False
    return type(plan.manual_steps) is tuple and plan.manual_steps == DRIFT_MANUAL_STEPS


DRIFT_MANUAL_STEPS: Final = (
    "review_diff",
    "restore_dry_run",
    "request_explicit_approval",
    "restore_by_hand",
    "verify_after_restore",
)


@dataclass(frozen=True, kw_only=True, slots=True)
class PlaybookFinding:
    """What a playbook found and proposes (it grants nothing).

    ``incident_facts``: the policy's facts, including ``cause_outside_router``.
    ``context_facts``: ``heal_policy.RiskContext`` fields the playbook read
    (merged by :func:`to_decision_input`; a conflict becomes unknown).
    ``proposal``: a catalog-validated action or None (recommendation only).
    """

    playbook_id: str
    playbook_version: int
    registry_version: int
    status: FindingStatus
    cause_class: str
    incident_facts: hp.IncidentFacts
    context_facts: Mapping[str, Any]
    steps: tuple[StepResult, ...]
    recommendations: tuple[str, ...]
    will_not: tuple[str, ...]
    reasons: tuple[str, ...]
    proposal: hc.ValidatedAction | None = None
    withheld: tuple[Withheld, ...] = ()
    plan: DriftPlan | None = None

    def codes(self) -> tuple[str, ...]:
        """Every text code of the finding (for the German texts)."""
        return (
            self.playbook_id,
            self.cause_class,
            *self.recommendations,
            *self.will_not,
            *self.reasons,
        )

    def texts_de(self) -> list[str]:
        """The German sentences of the finding (fixed texts, no data)."""
        return [TEXT_DE[c] for c in self.codes() if c in TEXT_DE]

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON; strings are codes from this module or the catalog."""
        facts = self.incident_facts
        return {
            "playbook_id": self.playbook_id,
            "playbook_version": self.playbook_version,
            "registry_version": self.registry_version,
            "status": self.status.value,
            "cause_class": self.cause_class,
            "incident_facts": {
                "incident_type": facts.incident_type,
                "severity": facts.severity,
                "cause_level": facts.cause_level.value,
                "cause_status": facts.cause_status.value,
                "confidence": facts.confidence,
                "source_families": facts.source_families,
                "is_root": facts.is_root,
                "temporal_only": facts.temporal_only,
                "evidence_fresh": facts.evidence_fresh,
                "target_fact": None
                if facts.target_fact is None
                else facts.target_fact.value,
                "cause_outside_router": facts.cause_outside_router,
            },
            "context_facts": dict(self.context_facts),
            "steps": [
                {
                    "step_id": s.step_id,
                    "outcome": s.outcome.value,
                    "conclusion": s.conclusion,
                }
                for s in self.steps
            ],
            "recommendations": list(self.recommendations),
            "will_not": list(self.will_not),
            "reasons": list(self.reasons),
            "proposal": None
            if self.proposal is None
            else {
                "action_type": self.proposal.action_type,
                "params": dict(self.proposal.params),
            },
            "withheld": [
                {"action_type": w.action_type, "reason": w.reason}
                for w in self.withheld
            ],
            "plan": None
            if self.plan is None
            else {
                "version_id": self.plan.version_id,
                "version_known": self.plan.version_known,
                "changed_areas": list(self.plan.changed_areas),
                "relevant_areas": list(self.plan.relevant_areas),
                "critical_areas": list(self.plan.critical_areas),
                "change_risk": self.plan.change_risk,
                "restore_check": self.plan.restore_check,
                "backup_present": self.plan.backup_present,
                "manual_steps": list(self.plan.manual_steps),
                "requires_explicit_approval": self.plan.requires_explicit_approval,
                "executes": self.plan.executes,
                "restore_executable": self.plan.restore_executable,
            },
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class Assessment:
    """Match and finding (no finding when no playbook fits)."""

    match: Match
    finding: PlaybookFinding | None


@dataclass(kw_only=True)
class _Run:
    """The working state of one analysis (internal)."""

    pb: Playbook
    inc: IncidentInput
    ev: Evidence
    steps: dict[str, tuple[StepOutcome, str | None]] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)
    will_not: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    withheld: list[Withheld] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def step(self, step_id: str, known: bool, conclusion: str | None = None) -> None:
        if step_id not in {s.step_id for s in self.pb.steps}:
            raise PlaybookError("unknown_step")
        self.steps[step_id] = (
            StepOutcome.KNOWN if known else StepOutcome.UNKNOWN,
            conclusion if known else None,
        )

    def rec(self, *codes: str) -> None:
        for code in codes:
            if code not in self.recommendations:
                self.recommendations.append(code)

    def wont(self, *codes: str) -> None:
        for code in codes:
            if code not in self.will_not:
                self.will_not.append(code)

    def why(self, *codes: str) -> None:
        for code in codes:
            if code not in self.reasons:
                self.reasons.append(code)

    def propose(
        self, action_type: str, service: str | None
    ) -> hc.ValidatedAction | None:
        """A catalog action with a closed parameter, or None if withheld."""
        if action_type not in self.pb.may_propose:
            raise PlaybookError("action_not_in_playbook")
        params: dict[str, str] = {}
        if service is not None:
            member = _member(service, self.pb.service_choices)
            if member is None:
                raise PlaybookError("service_not_in_playbook")
            params["service"] = member
        va = hc.validate(action_type, params)
        if va.entry.status is not hc.CatalogStatus.READY:
            self.withheld.append(
                Withheld(action_type=action_type, reason="action_disabled")
            )
            return None
        return va

    def finding(
        self,
        *,
        status: FindingStatus,
        cause_class: str,
        target_fact: hp.TargetFact | None,
        outside: bool | None,
        proposal: hc.ValidatedAction | None = None,
        plan: DriftPlan | None = None,
    ) -> PlaybookFinding:
        if proposal is not None and status is not FindingStatus.PROPOSAL:
            raise PlaybookError("proposal_without_status")
        if status is FindingStatus.PROPOSAL and proposal is None:
            status = FindingStatus.RECOMMENDATION_ONLY
        self.wont("wont_execute_in_observe_release")
        steps: list[StepResult] = []
        for s in self.pb.steps:
            if s.kind is StepKind.DEFERRED:
                steps.append(
                    StepResult(step_id=s.step_id, outcome=StepOutcome.NOT_IN_RELEASE)
                )
                continue
            if s.kind in (StepKind.PROPOSE, StepKind.CLASSIFY) and (
                s.step_id not in self.steps
            ):
                conclusion = (
                    ("proposal" if proposal is not None else "recommendation_only")
                    if s.kind is StepKind.PROPOSE
                    else cause_class
                )
                steps.append(
                    StepResult(
                        step_id=s.step_id,
                        outcome=StepOutcome.KNOWN,
                        conclusion=conclusion,
                    )
                )
                continue
            outcome, conclusion = self.steps.get(s.step_id, (StepOutcome.UNKNOWN, None))
            steps.append(
                StepResult(step_id=s.step_id, outcome=outcome, conclusion=conclusion)
            )
        context = {"role": self.ev.role, "reachable": self.ev.reachable}
        context.update(self.context)
        facts = hp.IncidentFacts(
            incident_type=self.inc.incident_type,
            severity=self.inc.severity,
            cause_level=self.inc.cause_level,
            cause_status=self.inc.cause_status or CauseStatus.HYPOTHESIS,
            confidence=self.inc.confidence,
            source_families=min(self.inc.observed_families, 64),
            is_root=self.inc.is_root,
            temporal_only=self.inc.temporal_only,
            evidence_fresh=self.inc.evidence_fresh,
            target_fact=target_fact,
            cause_outside_router=outside,
        )
        return PlaybookFinding(
            playbook_id=self.pb.playbook_id,
            playbook_version=self.pb.version,
            registry_version=REGISTRY_VERSION,
            status=status,
            cause_class=cause_class,
            incident_facts=facts,
            context_facts=MappingProxyType(context),
            steps=tuple(steps),
            recommendations=tuple(self.recommendations),
            will_not=tuple(self.will_not),
            reasons=tuple(self.reasons),
            proposal=proposal,
            withheld=tuple(self.withheld),
            plan=plan,
        )


def _target_fact(svc: ServiceFact, log_hint: bool | None) -> hp.TargetFact | None:
    """A direct fault fact on the service, a log hint only, or unknown."""
    if svc.faulty is True:
        return hp.TargetFact.DIRECT
    if log_hint is True:
        return hp.TargetFact.LOG_ONLY
    if svc.faulty is False:
        return hp.TargetFact.NONE
    return None


def _service_steps(run: _Run, step_id: str, svc: ServiceFact) -> None:
    if svc.enabled is False:
        run.step(step_id, True, "disabled_on_purpose")
    elif svc.faulty is True:
        run.step(step_id, True, "enabled_and_faulty")
    elif svc.faulty is False:
        run.step(step_id, True, "running")
    else:
        run.step(step_id, False)


# --- Where the cause lies ----------------------------------------------------

# Causes under which a playbook may call the fault "on this router" (False).
# No cause at all is always allowed; any other cause Network Intelligence
# names (a root's cause inherited, a client-side cause, a configuration
# cause) never yields False: it gives True when it is clearly outside, else
# None (review of PR #79). Network Intelligence's own hypotheses for the
# incidents of B are ``dhcp_server``, ``pool_exhausted``, ``vlan``,
# ``static_ip`` and ``wrong_network``; ``system_service_restart`` carries no
# cause of its own.
INSIDE_CAUSES: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "dns_recovery": frozenset(),
        "dhcp_recovery": frozenset({"dhcp_server"}),
        "radio_recovery": frozenset({"radio_restart"}),
        "interface_recovery": frozenset(),
        "wan_recovery": frozenset(),
        "drift_recovery": frozenset(
            {"dhcp_server", "radio_restart", "vlan", "uplink_config"}
        ),
        "client_recovery": frozenset(),
    }
)
# A root on the far side: the router's upstream is gone.
UPSTREAM_CAUSES: Final = frozenset(
    {"uplink_down", "lan_unreachable", "router_unreachable"}
)
CLIENT_SIDE_CAUSES: Final = frozenset(
    {
        "client_side",
        "client_driver",
        "client_power_save",
        "psk_wrong",
        "sae_mismatch",
        "wrong_network",
        "static_ip",
        "mac_filter",
    }
)
RF_OUTSIDE_CAUSES: Final = frozenset({"interference", "power_supply"})
# Causes that put the fault outside this router, per playbook (True).
OUTSIDE_CAUSES: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "dns_recovery": UPSTREAM_CAUSES | {"wan_down"},
        "dhcp_recovery": UPSTREAM_CAUSES | CLIENT_SIDE_CAUSES | {"ip_conflict"},
        "radio_recovery": RF_OUTSIDE_CAUSES,
        "interface_recovery": frozenset(),
        "wan_recovery": frozenset(),
        "drift_recovery": frozenset(),
        "client_recovery": CLIENT_SIDE_CAUSES,
    }
)


def _type_playbook(inc: IncidentInput) -> str | None:
    """The playbook of the incident's type (or of its service)."""
    if inc.incident_type == "system_service_restart":
        return _SERVICE_PLAYBOOK.get(inc.service or "")
    return _TYPE_PLAYBOOK.get(inc.incident_type or "")


# Outside signals: evidence that the fault may lie outside the router. Defined
# ONCE as a shared set every playbook consults (decided by the master on PR
# #79, second review), plus a few playbook-specific ones. A playbook may only
# ignore a shared signal through an entry in SIGNAL_EXCEPTIONS (named and
# documented; today there is none).
SHARED_OUTSIDE_SIGNALS: Final = (
    "sig_wan_down",  # Evidence.wan_up is False
    "sig_wan_link_down",  # WanFact.link_up is False
    "sig_wan_interface_down",  # WanFact.interface_up is False
    "sig_wan_no_address",  # WanFact.has_address is False
    "sig_upstream_router_down",  # InterfaceFact.upstream_router_down is True
    "sig_uplink_port_down",  # InterfaceFact role "uplink" with link_up False
    "sig_chain_stage_not_healthy",  # gateway/wan/internet failed or degraded
    "sig_upstream_resolver_failing",  # DnsFact.upstream_ok is False
)
SPECIFIC_OUTSIDE_SIGNALS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        # dnsmasq "no servers" / "query limit" lines (net_rules: cause
        # dns_resolution, a hypothesis): an upstream or load problem as much
        # as a local one, so never proof of an inside fault
        "dns_recovery": ("sig_dns_log_hint",),
        "dhcp_recovery": ("sig_address_conflict",),
        "radio_recovery": ("sig_interference",),
        "interface_recovery": (),
        "wan_recovery": (),
        "drift_recovery": (),  # F takes the signals of the playbook it replaces
        "client_recovery": (),
    }
)
SIGNAL_EXCEPTIONS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {pid: frozenset() for pid in PLAYBOOK_IDS}
)
_NOT_HEALTHY: Final = ("failed", "degraded")
_OUTSIDE_CHAIN_STAGES: Final = ("gateway", "wan", "internet")


def _shared_signals(ev: Evidence) -> frozenset[str]:
    wan, itf = ev.wan, ev.interface
    found = {
        "sig_wan_down": ev.wan_up is False,
        "sig_wan_link_down": wan.link_up is False,
        "sig_wan_interface_down": wan.interface_up is False,
        "sig_wan_no_address": wan.has_address is False,
        "sig_upstream_router_down": itf.upstream_router_down is True,
        "sig_uplink_port_down": itf.role == "uplink" and itf.link_up is False,
        "sig_chain_stage_not_healthy": any(
            ev.chain.get(s) in _NOT_HEALTHY for s in _OUTSIDE_CHAIN_STAGES
        ),
        "sig_upstream_resolver_failing": ev.dns.upstream_ok is False,
    }
    return frozenset(name for name, on in found.items() if on)


def _specific_signals(
    playbook_id: str, inc: IncidentInput, ev: Evidence
) -> frozenset[str]:
    found = {
        "sig_dns_log_hint": ev.dns.log_hint is True,
        "sig_address_conflict": inc.incident_type == "dhcp_conflict",
        "sig_interference": ev.radio.interference is True,
        "sig_named_outside_cause": inc.cause is not None
        and inc.cause in OUTSIDE_CAUSES[playbook_id],
    }
    wanted = (*SPECIFIC_OUTSIDE_SIGNALS[playbook_id], "sig_named_outside_cause")
    return frozenset(name for name in wanted if found[name])


def outside_signals(
    playbook_id: str, inc: IncidentInput, ev: Evidence
) -> frozenset[str]:
    """Every sign, named or measured, that the fault may lie outside the router.

    A signal is not a verdict: an outside and an inside signal together give
    None, never False. ``cause_outside_router`` False never stands next to a
    signal (decided by the master on PR #79), and Playbook F never takes a
    case over from a playbook that saw one. The shared set
    (:data:`SHARED_OUTSIDE_SIGNALS`, minus :data:`SIGNAL_EXCEPTIONS`) plus
    the playbook's own (:data:`SPECIFIC_OUTSIDE_SIGNALS`, and a cause from
    :data:`OUTSIDE_CAUSES`); F uses those of the playbook of the incident's
    type, its exceptions included.
    """
    pid = playbook_id
    if pid == "drift_recovery":
        orig = _type_playbook(inc)
        if orig is not None and orig != pid:
            pid = orig
    shared = _shared_signals(ev) - SIGNAL_EXCEPTIONS[pid]
    return shared | _specific_signals(pid, inc, ev)


def outside_signal(playbook_id: str, inc: IncidentInput, ev: Evidence) -> bool:
    """Whether :func:`outside_signals` found anything."""
    return bool(outside_signals(playbook_id, inc, ev))


def _settle(
    playbook_id: str, inc: IncidentInput, ev: Evidence, raw: bool | None
) -> bool | None:
    """The derived location checked against the cause Network Intelligence
    names and every outside signal: an outside cause gives True; False only
    with no cause or one of the playbook's :data:`INSIDE_CAUSES` and no
    :func:`outside_signal`; otherwise unknown (None)."""
    cause = inc.cause
    if cause is not None and cause in OUTSIDE_CAUSES[playbook_id]:
        return True
    if raw is False and cause is not None and cause not in INSIDE_CAUSES[playbook_id]:
        return None
    if raw is False and outside_signal(playbook_id, inc, ev):
        return None
    return raw


def _may_restart(
    run: _Run, svc: ServiceFact, outside: bool | None, service: str
) -> bool:
    """Every fact a service-restart proposal needs is known and favourable.

    Enabled and down or in an observed loop; the cause on this router; not a
    link by time only and at least one observed family; and the router's
    ``data.services`` capability explicitly True (unknown: recommendation
    only, decided by the master on PR #79).
    """
    inc = run.inc
    if (
        svc.faulty is not True
        or outside is not False
        or inc.temporal_only is not False
        or inc.observed_families < 1
    ):
        return False
    cfg = run.ev.config
    if (
        cfg.diff_proven is True
        and cfg.changed_areas is not None
        and cfg.changed_areas & _SERVICE_AREAS.get(service, frozenset())
    ):
        # a restart would apply a saved, unreviewed change of this service
        # (decided by the master on PR #79, second review)
        run.why("drift_in_service_area")
        run.wont("wont_restart_unreviewed_change")
        run.rec("rec_review_diff")
        run.context["service_config_unapplied"] = None
        return False
    if run.ev.capabilities.get("data.services") is not True:
        run.why("services_capability_unknown")
        run.wont("wont_restart_capability_unknown")
        return False
    return True


# --- A: DNS -----------------------------------------------------------------


def dns_cause_outside(inc: IncidentInput, ev: Evidence) -> bool | None:
    """Where the DNS fault lies: outside the router (True), on it (False), or
    not to be told (None).

    Outside signals: the WAN of this router is down; a gateway, WAN or
    internet stage of the diagnostics chain failed; the local resolver
    answers while the upstream one does not; Network Intelligence names
    ``wan_down`` or a lost upstream as the cause. Inside signals: dnsmasq is
    enabled and down or in a loop; the local resolver fails while upstream
    answers. True needs an outside signal and no inside signal. False needs
    an inside signal, no outside signal, no cause other than those in
    :data:`INSIDE_CAUSES`, AND the outside measured healthy: the upstream
    resolver or the internet stage answering, no gateway/WAN/internet stage
    failed or degraded, the WAN not down (WAN up alone is not a measurement).
    Everything else is None.
    """
    svc = ev.service("dnsmasq")
    dns = ev.dns
    outside = (
        ev.wan_up is False
        or any(ev.stage(s) is False for s in _OUTSIDE_CHAIN_STAGES)
        or (dns.local_ok is True and dns.upstream_ok is False)
    )
    inside = svc.faulty is True or (dns.local_ok is False and dns.upstream_ok is True)
    outside_healthy = (
        (dns.upstream_ok is True or ev.stage("internet") is True)
        and not any(ev.chain.get(s) in _NOT_HEALTHY for s in _OUTSIDE_CHAIN_STAGES)
        and ev.wan_up is not False
    )
    raw: bool | None = None
    if outside and not inside:
        raw = True
    elif inside and not outside and outside_healthy:
        raw = False
    return _settle("dns_recovery", inc, ev, raw)


def _analyze_dns(run: _Run) -> PlaybookFinding:
    ev, inc = run.ev, run.inc
    svc = ev.service("dnsmasq")
    dns = ev.dns
    run.context["service_enabled"] = svc.enabled
    _service_steps(run, "dns_service_state", svc)
    run.step(
        "local_resolver",
        dns.local_ok is not None,
        None if dns.local_ok is None else ("answers" if dns.local_ok else "fails"),
    )
    upstream = dns.upstream_ok if dns.upstream_ok is not None else ev.stage("internet")
    run.step(
        "upstream_resolver",
        upstream is not None,
        None if upstream is None else ("healthy" if upstream else "failing"),
    )
    run.step(
        "config_and_logs",
        dns.log_hint is not None,
        None if dns.log_hint is None else ("log_hint" if dns.log_hint else "no_hint"),
    )
    run.step(
        "affected_clients",
        inc.affected_clients is not None,
        None if inc.affected_clients is None else "counted",
    )
    outside = dns_cause_outside(inc, ev)
    target = _target_fact(svc, dns.log_hint)
    if svc.enabled is False:
        # the smallest AP: switched off on purpose, the intended state
        run.why("never_restart_disabled_service")
        run.wont("wont_restart_disabled_service")
        run.rec("rec_nothing_to_do")
        return run.finding(
            status=FindingStatus.NOTHING_TO_REPAIR,
            cause_class="service_disabled_on_purpose",
            target_fact=hp.TargetFact.NONE,
            outside=outside,
        )
    if outside is True:
        run.why("never_restart_cause_outside")
        run.wont("wont_restart_cause_outside")
        run.rec("rec_check_wan_and_upstream_dns")
        return run.finding(
            status=FindingStatus.RECOMMENDATION_ONLY,
            cause_class="cause_outside_router",
            target_fact=target,
            outside=True,
        )
    if _may_restart(run, svc, outside, "dnsmasq"):
        proposal = run.propose("service.restart", "dnsmasq")
        run.rec("rec_restart_dnsmasq_with_approval")
        return run.finding(
            status=FindingStatus.PROPOSAL,
            cause_class="dns_service_down",
            target_fact=target,
            outside=False,
            proposal=proposal,
        )
    run.wont("wont_restart_without_evidence")
    run.rec("rec_refresh_and_diagnose")
    if outside is None:
        run.rec("rec_check_wan_and_upstream_dns")
    cause = (
        "dns_service_down"
        if svc.faulty is True
        else "local_resolver_failing"
        if dns.local_ok is False
        else "cause_unknown"
    )
    return run.finding(
        status=FindingStatus.RECOMMENDATION_ONLY,
        cause_class=cause,
        target_fact=target,
        outside=outside,
    )


# --- B: DHCP ----------------------------------------------------------------

POOL_FULL_PCT: Final = 90
# Types that can mean an exhausted pool: without a pool reading, no restart.
_POOL_SENSITIVE_TYPES: Final = frozenset({"wifi_no_ip", "wifi_dhcp_after_connect"})


def dhcp_cause_outside(
    inc: IncidentInput, ev: Evidence, daemon: str | None
) -> bool | None:
    """True: an address conflict, a client-side cause or a lost upstream
    (:data:`OUTSIDE_CAUSES`); False: the serving daemon is enabled and down or
    in a loop and no cause outside :data:`INSIDE_CAUSES` is named; else None."""
    raw: bool | None = None
    if inc.incident_type == "dhcp_conflict":
        raw = True
    elif daemon is not None and ev.service(daemon).faulty is True:
        raw = False
    return _settle("dhcp_recovery", inc, ev, raw)


def _dhcp_daemon(inc: IncidentInput, ev: Evidence) -> tuple[str | None, str | None]:
    """The daemon to look at and, if it is not usable, the reason code."""
    daemons = ev.dhcp.daemons
    if inc.incident_type == "system_service_restart":
        named = inc.service
        if daemons is None:
            return None, "dhcp_daemon_unknown"
        if named not in daemons:
            return None, "daemon_not_serving_dhcp"
        return named, None
    if daemons is None or len(daemons) != 1:
        return None, "dhcp_daemon_unknown"
    return next(iter(daemons)), None


def _dhcp_off_here(inc: IncidentInput, ev: Evidence) -> bool:
    """DHCP is switched off on purpose on this router (the smallest AP).

    A service-restart incident: its service is known disabled. Any other
    type: every daemon that could serve here is known disabled (the listed
    daemons, or both when the list is empty or unknown).
    """
    if inc.incident_type == "system_service_restart":
        return ev.service(inc.service or "").enabled is False
    daemons = ev.dhcp.daemons
    candidates = tuple(daemons) if daemons else hc.SERVICE_NAMES
    return all(ev.service(d).enabled is False for d in candidates)


def _analyze_dhcp(run: _Run) -> PlaybookFinding:
    ev, inc = run.ev, run.inc
    pool = ev.dhcp.pool_usage_pct
    run.step(
        "pool_utilisation",
        pool is not None,
        None if pool is None else ("full" if pool >= POOL_FULL_PCT else "room"),
    )
    run.step(
        "dhcp_logs",
        inc.occurrences is not None,
        None if inc.occurrences is None else "counted",
    )
    cfg = ev.config
    run.step(
        "config_changes",
        cfg.changed_areas is not None,
        None
        if cfg.changed_areas is None
        else ("changed" if "dhcp" in cfg.changed_areas else "unchanged"),
    )
    daemon, problem = _dhcp_daemon(inc, ev)
    svc = ev.service(daemon) if daemon is not None else _UNKNOWN_SERVICE
    if daemon is not None:
        run.context["service_enabled"] = svc.enabled
        _service_steps(run, "dhcp_service_state", svc)
    outside = dhcp_cause_outside(inc, ev, daemon)
    run.why("never_delete_leases")
    run.wont("wont_delete_leases")
    if _dhcp_off_here(inc, ev):
        run.why("never_restart_disabled_service")
        run.wont("wont_restart_disabled_service")
        run.rec("rec_nothing_to_do")
        return run.finding(
            status=FindingStatus.NOTHING_TO_REPAIR,
            cause_class="service_disabled_on_purpose",
            target_fact=hp.TargetFact.NONE,
            outside=outside,
        )
    if (
        inc.incident_type == "dhcp_pool_full"
        or inc.cause == "pool_exhausted"
        or (pool is not None and pool >= POOL_FULL_PCT)
    ):
        run.why("never_restart_for_pool_exhaustion")
        run.wont("wont_restart_for_pool")
        run.rec("rec_enlarge_pool_or_shorten_lease")
        return run.finding(
            status=FindingStatus.RECOMMENDATION_ONLY,
            cause_class="pool_exhausted",
            target_fact=_target_fact(svc, None),
            outside=outside,
        )
    if inc.incident_type == "dhcp_conflict" or inc.cause == "ip_conflict":
        run.rec("rec_find_conflicting_device")
        return run.finding(
            status=FindingStatus.RECOMMENDATION_ONLY,
            cause_class="address_conflict",
            target_fact=_target_fact(svc, None),
            outside=True,
        )
    if outside is True:
        run.why("never_restart_cause_outside")
        run.wont("wont_restart_cause_outside")
        if inc.cause in CLIENT_SIDE_CAUSES:
            run.rec("rec_check_client_network")
            cause = "client_side_dhcp"
        else:
            run.rec("rec_check_upstream_path")
            cause = "cause_outside_router"
        return run.finding(
            status=FindingStatus.RECOMMENDATION_ONLY,
            cause_class=cause,
            target_fact=_target_fact(svc, None),
            outside=True,
        )
    if daemon is None:
        run.why("never_restart_unknown_daemon")
        run.wont("wont_restart_unknown_daemon")
        run.rec("rec_determine_dhcp_daemon")
        return run.finding(
            status=FindingStatus.RECOMMENDATION_ONLY,
            cause_class=problem or "dhcp_daemon_unknown",
            target_fact=None,
            outside=outside,
        )
    if svc.enabled is False:
        run.why("never_restart_disabled_service")
        run.wont("wont_restart_disabled_service")
        run.rec("rec_nothing_to_do")
        return run.finding(
            status=FindingStatus.NOTHING_TO_REPAIR,
            cause_class="service_disabled_on_purpose",
            target_fact=hp.TargetFact.NONE,
            outside=outside,
        )
    if pool is None and inc.incident_type in _POOL_SENSITIVE_TYPES:
        run.why("never_restart_for_pool_exhaustion")
        run.wont("wont_restart_pool_unknown")
        run.rec("rec_refresh_and_diagnose")
        return run.finding(
            status=FindingStatus.RECOMMENDATION_ONLY,
            cause_class="pool_usage_unknown",
            target_fact=_target_fact(svc, None),
            outside=outside,
        )
    if _may_restart(run, svc, outside, daemon):
        proposal = run.propose("service.restart", daemon)
        run.rec("rec_restart_dhcp_daemon_with_approval")
        return run.finding(
            status=FindingStatus.PROPOSAL,
            cause_class="dhcp_service_down",
            target_fact=hp.TargetFact.DIRECT,
            outside=False,
            proposal=proposal,
        )
    run.wont("wont_restart_without_evidence")
    run.rec("rec_refresh_and_diagnose")
    return run.finding(
        status=FindingStatus.RECOMMENDATION_ONLY,
        cause_class="dhcp_service_down" if svc.faulty is True else "cause_unknown",
        target_fact=_target_fact(svc, None),
        outside=outside,
    )


# --- C: radio ---------------------------------------------------------------


def radio_cause_outside(inc: IncidentInput, ev: Evidence) -> bool | None:
    """True: interference or power supply named or measured; False: a radio
    or hostapd restart is the named cause (or the hostapd/wpad incident's
    service is down or in a loop) and no other cause is named; else None."""
    raw: bool | None = None
    if ev.radio.interference is True:
        raw = True
    elif inc.cause == "radio_restart" or (
        inc.incident_type == "system_service_restart"
        and ev.service(inc.service or "").faulty is True
    ):
        raw = False
    return _settle("radio_recovery", inc, ev, raw)


def _analyze_radio(run: _Run) -> PlaybookFinding:
    ev, inc = run.ev, run.inc
    radio = ev.radio
    run.context.update(
        target_is_wireless_uplink=radio.wireless_uplink,
        target_on_mgmt_path=radio.on_mgmt_path,
        target_carries_dependants=radio.carries_dependants,
        clients_on_target=radio.clients,
    )
    run.step(
        "radio_state",
        radio.up is not None,
        None if radio.up is None else ("up" if radio.up else "down"),
    )
    recurring: bool | None
    if radio.failures_24h is not None:
        recurring = radio.failures_24h >= 2
    elif inc.occurrences is not None or inc.reopen_count is not None:
        recurring = (inc.occurrences or 0) >= 2 or (inc.reopen_count or 0) >= 1
    else:
        recurring = None
    run.step(
        "hostapd_events",
        recurring is not None,
        None if recurring is None else ("recurring" if recurring else "single"),
    )
    run.step(
        "rf_metrics",
        radio.interference is not None,
        None
        if radio.interference is None
        else ("interference" if radio.interference else "clean"),
    )
    run.step(
        "affected_clients",
        radio.clients is not None,
        None if radio.clients is None else "counted",
    )
    uplink_known = radio.wireless_uplink is not None
    run.step(
        "uplink_and_router",
        uplink_known,
        None
        if not uplink_known
        else ("uplink" if radio.wireless_uplink else "no_uplink"),
    )
    outside = radio_cause_outside(inc, ev)
    run.why("never_restart_wpad")
    run.wont("wont_restart_wpad")
    if inc.incident_type == "wifi_radio_change" and recurring is not True:
        run.rec("rec_nothing_to_do")
        return run.finding(
            status=FindingStatus.NOTHING_TO_REPAIR,
            cause_class="channel_change_normal",
            target_fact=hp.TargetFact.NONE,
            outside=outside,
        )
    if outside is True:
        run.rec("rec_check_channel_and_interference")
        return run.finding(
            status=FindingStatus.RECOMMENDATION_ONLY,
            cause_class="rf_interference",
            target_fact=None,
            outside=True,
        )
    # never-rules first: they hold even the day the catalog enables the action
    # (each fact on its own; unknown is stated as unknown, never as fact)
    blocked = False
    if radio.wireless_uplink is not False:
        run.why("never_restart_wireless_uplink")
        run.wont(
            "wont_restart_wireless_uplink"
            if radio.wireless_uplink is True
            else "wont_restart_uplink_unknown"
        )
        blocked = True
    if radio.carries_dependants is not False:
        run.why("never_restart_radio_carrying_dependants")
        run.wont(
            "wont_restart_radio_with_dependants"
            if radio.carries_dependants is True
            else "wont_restart_radio_dependants_unknown"
        )
        blocked = True
    if radio.on_mgmt_path is not False:
        run.why("never_restart_radio_on_mgmt_path")
        run.wont(
            "wont_restart_radio_on_mgmt_path"
            if radio.on_mgmt_path is True
            else "wont_restart_radio_mgmt_unknown"
        )
        blocked = True
    if radio.name is None:
        blocked = True
    if recurring is not True:
        run.rec("rec_observe_radio")
        return run.finding(
            status=FindingStatus.RECOMMENDATION_ONLY,
            cause_class="single_drop" if recurring is False else "cause_unknown",
            target_fact=None,
            outside=outside,
        )
    if blocked:
        # never advise a manual restart of a radio that is (or may be) on
        # the management path, carries others or is not even identified
        if radio.wireless_uplink is not False or radio.carries_dependants is not False:
            run.rec("rec_check_uplink_by_hand")
        if radio.on_mgmt_path is True:
            run.rec("rec_radio_carries_mgmt_path")
        elif radio.on_mgmt_path is None:
            run.rec("rec_radio_mgmt_path_unknown")
        if radio.name is None:
            run.rec("rec_identify_radio")
        cause = (
            "radio_unknown"
            if radio.name is None
            else "uplink_unknown"
            if radio.wireless_uplink is None
            else "radio_recurring_failure"
        )
        return run.finding(
            status=FindingStatus.RECOMMENDATION_ONLY,
            cause_class=cause,
            target_fact=None,
            outside=outside,
        )
    # the radio restart is modelled only (disabled in the catalog)
    va = hc.validate("wifi.radio_restart", {"radio": radio.name})
    if va.entry.status is not hc.CatalogStatus.READY:
        run.withheld.append(
            Withheld(action_type="wifi.radio_restart", reason="action_disabled")
        )
        run.wont("wont_restart_radio_disabled")
    run.rec("rec_radio_restart_manual_with_approval")
    return run.finding(
        status=FindingStatus.RECOMMENDATION_ONLY,
        cause_class="radio_recurring_failure",
        target_fact=None,
        outside=outside,
    )


# --- D: interface -----------------------------------------------------------

_EDGE_ROLES: Final = ("lan", "other")
_CRITICAL_ROLES: Final = ("uplink", "management", "wan")


def interface_cause_outside(inc: IncidentInput, ev: Evidence) -> bool | None:
    """True only when the upstream router is known down; nothing on a port
    tells a cable from a peer, so False is never claimed."""
    raw = True if ev.interface.upstream_router_down is True else None
    return _settle("interface_recovery", inc, ev, raw)


def _analyze_interface(run: _Run) -> PlaybookFinding:
    ev = run.ev
    itf = ev.interface
    run.context.update(
        target_on_mgmt_path=itf.on_mgmt_path,
        target_carries_dependants=itf.carries_dependants,
    )
    run.step(
        "physical_link",
        itf.link_up is not None,
        None if itf.link_up is None else ("up" if itf.link_up else "down"),
    )
    run.step(
        "error_counters",
        itf.errors_high is not None,
        None if itf.errors_high is None else ("high" if itf.errors_high else "low"),
    )
    cfg = ev.config
    run.step(
        "vlan_config",
        cfg.changed_areas is not None,
        None
        if cfg.changed_areas is None
        else (
            "changed"
            if cfg.changed_areas & frozenset({"vlan", "interface"})
            else "unchanged"
        ),
    )
    # only a known LAN-side port may count as an edge: WAN, uplink,
    # management and unknown roles are critical, as is an unknown path
    critical = (
        itf.role not in _EDGE_ROLES
        or itf.on_mgmt_path is not False
        or itf.carries_dependants is not False
    )
    known_critical = (
        itf.role in _CRITICAL_ROLES
        or itf.on_mgmt_path is True
        or itf.carries_dependants is True
    )
    run.step(
        "uplink_dependencies",
        itf.role is not None or itf.carries_dependants is not None,
        "uplink_or_mgmt" if critical else "edge",
    )
    outside = interface_cause_outside(run.inc, ev)
    run.why("never_automatic_interface_change")
    run.wont("wont_cycle_interface")
    if critical:
        run.why("never_cycle_uplink_or_mgmt")
        run.wont(
            "wont_cycle_uplink_or_mgmt" if known_critical else "wont_cycle_role_unknown"
        )
    run.withheld.append(
        Withheld(action_type="interface.cycle", reason="recommendation_only")
    )
    if outside is True:
        cause = "upstream_router_down"
        run.rec("rec_check_upstream_router")
    elif itf.errors_high is True:
        cause = "port_errors"
        run.rec("rec_check_cable_and_peer")
    elif itf.flapping is True or run.inc.incident_type == "lan_port_flap":
        cause = "port_flapping"
        run.rec("rec_check_cable_and_peer")
    elif itf.link_up is False:
        cause = "link_down"
        run.rec("rec_check_cable_and_peer")
    else:
        cause = "cause_unknown"
        run.rec("rec_refresh_and_diagnose")
    if critical:
        run.rec("rec_check_uplink_by_hand")
    return run.finding(
        status=FindingStatus.RECOMMENDATION_ONLY,
        cause_class=cause,
        target_fact=hp.TargetFact.DIRECT if itf.link_up is False else None,
        outside=outside,
    )


# --- E: WAN -----------------------------------------------------------------


def wan_cause_outside(inc: IncidentInput, ev: Evidence) -> bool | None:
    """ISP outage (True): the WAN is up with an address but the gateway or
    the internet stage failed. Never False (review of PR #79): a carrier up
    with the WAN interface down and no address is what a provider-side
    PPPoE/DHCP failure looks like too, and a cable, modem or missing address
    cannot be told apart from the provider's side either: None."""
    wan = ev.wan
    raw: bool | None = None
    if (
        wan.interface_up is True
        and wan.has_address is True
        and (ev.stage("gateway") is False or ev.stage("internet") is False)
    ):
        raw = True
    return _settle("wan_recovery", inc, ev, raw)


def _analyze_wan(run: _Run) -> PlaybookFinding:
    ev = run.ev
    wan = ev.wan
    run.step(
        "router_and_interfaces",
        wan.link_up is not None,
        None if wan.link_up is None else ("link_up" if wan.link_up else "link_down"),
    )
    for step_id, stage in (
        ("gateway", "gateway"),
        ("external_ip", "internet"),
        ("dns_independent", "dns"),
    ):
        state = ev.stage(stage)
        run.step(
            step_id,
            state is not None,
            None if state is None else ("healthy" if state else "failed"),
        )
    run.step(
        "wan_state_and_logs",
        wan.has_address is not None,
        None
        if wan.has_address is None
        else ("address" if wan.has_address else "no_address"),
    )
    outside = wan_cause_outside(run.inc, ev)
    run.why("never_reboot_as_standard")
    run.wont("wont_reboot")
    if outside is True:
        run.rec("rec_wait_for_provider")
        return run.finding(
            status=FindingStatus.NOTHING_TO_REPAIR,
            cause_class="isp_outage",
            target_fact=hp.TargetFact.NONE,
            outside=True,
        )
    if wan.link_up is False:
        run.rec("rec_check_modem_and_cable")
        cause = "wan_link_down"
    elif wan.interface_up is True and wan.has_address is False:
        run.rec("rec_check_wan_settings")
        cause = "wan_no_address"
    elif wan.link_up is True and wan.interface_up is False:
        run.rec("rec_check_wan_settings")
        cause = "wan_interface_down"
    elif ev.stage("internet") is True and ev.stage("dns") is False:
        run.rec("rec_follow_dns_playbook")
        cause = "dns_only"
    else:
        run.rec("rec_refresh_and_diagnose")
        cause = "cause_unknown"
    return run.finding(
        status=FindingStatus.RECOMMENDATION_ONLY,
        cause_class=cause,
        target_fact=None,
        outside=outside,
    )


# --- F: drift ---------------------------------------------------------------


# The area a cause on the router lives in (Playbook F, second review of PR
# #79): F says False only when the named cause maps to an area that actually
# changed. Keys are exactly F's INSIDE_CAUSES.
DRIFT_CAUSE_AREAS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        "dhcp_server": frozenset({"dhcp"}),
        "radio_restart": frozenset({"wlan"}),
        "vlan": frozenset({"vlan"}),
        "uplink_config": frozenset({"interface", "wlan"}),
    }
)
# Playbooks that never say False: F never says it for their incidents either.
_NEVER_FALSE: Final = frozenset({"interface_recovery", "wan_recovery"})


def drift_cause_outside(inc: IncidentInput, ev: Evidence) -> bool | None:
    """False when a diff proves a change in the area the incident touches AND
    the named cause maps (:data:`DRIFT_CAUSE_AREAS`) to an area that changed;
    never for an incident of D or E; otherwise None."""
    raw: bool | None = None
    changed = ev.config.changed_areas
    areas = DRIFT_CAUSE_AREAS.get(inc.cause or "")
    if (
        _drift_in_area(inc, ev)
        and _type_playbook(inc) not in _NEVER_FALSE
        and areas is not None
        and changed is not None
        and areas & changed
    ):
        raw = False
    return _settle("drift_recovery", inc, ev, raw)


def _analyze_drift(run: _Run) -> PlaybookFinding:
    ev, inc = run.ev, run.inc
    cfg = ev.config
    run.step(
        "last_known_version",
        cfg.version_known is not None,
        None
        if cfg.version_known is None
        else ("known" if cfg.version_known else "none"),
    )
    run.step(
        "config_diff",
        cfg.changed_areas is not None,
        None if cfg.changed_areas is None else "areas",
    )
    relevant = tuple(sorted((cfg.changed_areas or frozenset()) & _areas_of(inc)))
    critical = tuple(a for a in relevant if a in CRITICAL_CONFIG_AREAS)
    run.step("relevant_changes", True, "relevant" if relevant else "none")
    run.step(
        "impact",
        inc.affected_clients is not None,
        None if inc.affected_clients is None else "counted",
    )
    run.step(
        "restore_compatibility",
        cfg.restore_check is not None,
        cfg.restore_check,
    )
    plan = DriftPlan(
        version_id=cfg.version_id,
        version_known=cfg.version_known,
        changed_areas=tuple(sorted(cfg.changed_areas or frozenset())),
        relevant_areas=relevant,
        critical_areas=critical,
        change_risk=cfg.change_risk,
        restore_check=cfg.restore_check,
        backup_present=cfg.backup_present,
        manual_steps=DRIFT_MANUAL_STEPS,
    )
    run.why("never_automatic_restore")
    run.wont("wont_restore_automatically")
    if critical or cfg.change_risk in ("high", "critical"):
        run.why("never_automatic_rollback_critical")
        run.wont("wont_rollback_critical_config")
    run.withheld.append(
        Withheld(action_type="config.restore", reason="restore_dry_run_only")
    )
    run.rec("rec_review_diff_and_plan_restore", "rec_restore_manually_after_review")
    if cfg.backup_present is not True:
        run.rec("rec_enable_config_backup")
    return run.finding(
        status=FindingStatus.RECOMMENDATION_ONLY,
        cause_class="drift_in_area" if relevant else "cause_unknown",
        target_fact=None,
        outside=drift_cause_outside(inc, ev),
        plan=plan,
    )


# --- G: client --------------------------------------------------------------


def client_cause_outside(inc: IncidentInput, ev: Evidence) -> bool | None:
    """True: a client-side cause; False: the client's AP was not available
    and no cause is named; a full AP, weak signal, roaming or steering can be
    either: None."""
    raw = False if ev.client.ap_available is False else None
    return _settle("client_recovery", inc, ev, raw)


def _analyze_client(run: _Run) -> PlaybookFinding:
    ev, inc = run.ev, run.inc
    cl = ev.client
    run.step(
        "stability_history",
        cl.disconnects_24h is not None,
        None if cl.disconnects_24h is None else "counted",
    )
    run.step(
        "signal_quality",
        cl.weak_signal is not None,
        None if cl.weak_signal is None else ("weak" if cl.weak_signal else "good"),
    )
    run.step(
        "roaming",
        cl.roam_flapping is not None,
        None
        if cl.roam_flapping is None
        else ("flapping" if cl.roam_flapping else "calm"),
    )
    run.step(
        "ap_availability",
        cl.ap_available is not None,
        None if cl.ap_available is None else ("up" if cl.ap_available else "down"),
    )
    run.step(
        "dhcp_dns_anomalies",
        cl.dhcp_dns_anomaly is not None,
        None
        if cl.dhcp_dns_anomaly is None
        else ("anomaly" if cl.dhcp_dns_anomaly else "none"),
    )
    outside = client_cause_outside(inc, ev)
    run.why("never_client_action")
    run.wont("wont_touch_client")
    if outside is True:
        cause, rec = "client_side", "rec_check_client_device"
    elif outside is False:
        cause, rec = "ap_unavailable", "rec_check_ap"
    elif cl.dhcp_dns_anomaly is True:
        cause, rec = "dhcp_dns_side", "rec_follow_dhcp_dns_playbooks"
    elif cl.roam_flapping is True or inc.incident_type == "wifi_roam_flapping":
        cause, rec = "roaming_flapping", "rec_tune_roaming"
    elif cl.weak_signal is True or inc.cause == "weak_signal":
        cause, rec = "weak_signal", "rec_improve_coverage"
    else:
        cause, rec = "cause_unknown", "rec_refresh_and_diagnose"
    run.rec(rec)
    return run.finding(
        status=FindingStatus.RECOMMENDATION_ONLY,
        cause_class=cause,
        target_fact=None,
        outside=outside,
    )


_ANALYZERS: Final = MappingProxyType(
    {
        "dns_recovery": _analyze_dns,
        "dhcp_recovery": _analyze_dhcp,
        "radio_recovery": _analyze_radio,
        "interface_recovery": _analyze_interface,
        "wan_recovery": _analyze_wan,
        "drift_recovery": _analyze_drift,
        "client_recovery": _analyze_client,
    }
)

_HAND_BACK_REASONS: Final = frozenset(
    {"drift_hint_outside_measured", "drift_hint_outside_signal"}
)


def _measured_outside(playbook_id: str, inc: IncidentInput, ev: Evidence) -> bool:
    """Whether the playbook's own analysis puts the cause outside (True)."""
    probe = _ANALYZERS[playbook_id](_Run(pb=PLAYBOOKS[playbook_id], inc=inc, ev=ev))
    return probe.incident_facts.cause_outside_router is True


def _unsupported(run: _Run, m: Match) -> PlaybookFinding:
    run.why(m.reason)
    run.rec("rec_nothing_to_do")
    steps = run.finding(
        status=FindingStatus.UNSUPPORTED,
        cause_class=m.reason,
        target_fact=None,
        outside=None,
    )
    return dataclasses.replace(
        steps,
        steps=tuple(
            StepResult(step_id=s.step_id, outcome=StepOutcome.NOT_RUN)
            for s in run.pb.steps
        ),
    )


def assess(incident: IncidentInput, evidence: Evidence) -> Assessment:
    """Match ``incident`` and, if a playbook fits, run its analysis.

    The only way to a finding: a playbook is never analysed for an incident
    the matcher did not give it.
    """
    m = match(incident, evidence)
    if m.playbook_id is None:
        return Assessment(match=m, finding=None)
    run = _Run(pb=PLAYBOOKS[m.playbook_id], inc=incident, ev=evidence)
    if m.status is MatchStatus.UNSUPPORTED:
        return Assessment(match=m, finding=_unsupported(run, m))
    if m.reason in _HAND_BACK_REASONS:
        # match() handed the case back: the original playbook saw a sign of an
        # outside cause, the drift is only a hint and the original finding,
        # with its value, stays (decided by the master on PR #79). The finding
        # carries match()'s reason: measured outside, or only a signal.
        run.why(m.reason)
        run.rec("rec_review_diff")
        finding = _ANALYZERS[m.playbook_id](run)
    elif m.drift_overlay:
        run.why("drift_overlay")
        finding = _ANALYZERS[m.playbook_id](run)
    else:
        if m.drift_hint:
            run.why("drift_hint")
            run.rec("rec_review_diff")
        finding = _ANALYZERS[m.playbook_id](run)
    if finding.proposal is not None:
        # a proposal is always a catalog action this playbook may propose,
        # with its closed parameters (checked again, independently)
        p = finding.proposal
        if p.action_type not in run.pb.may_propose or any(
            _member(v, run.pb.service_choices) is not v for v in p.params.values()
        ):
            raise PlaybookError("proposal_outside_playbook")
    return Assessment(match=m, finding=finding)


# ---------------------------------------------------------------------------
# To the policy
# ---------------------------------------------------------------------------


def merge_context(context: hp.RiskContext, facts: Mapping[str, Any]) -> hp.RiskContext:
    """``context`` with the playbook's facts where it knows nothing; a fact
    both know with different values becomes unknown (None)."""
    if type(context) is not hp.RiskContext:
        raise PlaybookError("invalid context")
    names = {f.name for f in dataclasses.fields(hp.RiskContext)}
    merged: dict[str, Any] = {}
    for name, value in facts.items():
        if name not in names:
            continue
        given = getattr(context, name)
        if given is None:
            merged[name] = value
        elif value is not None and value != given:
            merged[name] = None
    return dataclasses.replace(context, **merged) if merged else context


def to_decision_input(
    finding: PlaybookFinding,
    *,
    context: hp.RiskContext,
    prior_failed_attempts: int | None = None,
    config_change_24h: bool | None = None,
) -> hp.DecisionInput | None:
    """The finding's proposal as the policy's input; None without a proposal.

    A recommendation-only finding has nothing for the policy to decide; the
    playbook never grants anything, the policy (``heal_policy.gate``)
    decides about every proposal.
    """
    if type(finding) is not PlaybookFinding:
        raise PlaybookError("invalid finding")
    if finding.proposal is None:
        return None
    merged = merge_context(context, finding.context_facts)
    if "drift_in_service_area" in finding.reasons:
        # an unreviewed change of the service is saved: never "applied"
        merged = dataclasses.replace(merged, service_config_unapplied=None)
    return hp.DecisionInput(
        action_type=finding.proposal.action_type,
        params=dict(finding.proposal.params),
        incident=finding.incident_facts,
        context=merged,
        prior_failed_attempts=prior_failed_attempts,
        config_change_24h=config_change_24h,
    )


def registry_table() -> list[dict[str, Any]]:
    """The registry as plain JSON rows (for a view or the docs)."""
    return [p.to_dict() for p in _PLAYBOOKS]


__all__ = [
    "KNOWN_INCIDENT_TYPES",
    "NO_PLAYBOOK_REASONS",
    "PLAYBOOKS",
    "PLAYBOOK_IDS",
    "PREFLIGHT_CHECK_IDS",
    "REGISTRY_VERSION",
    "TEXT_DE",
    "Assessment",
    "Availability",
    "ClientFact",
    "ConfigFact",
    "DhcpFact",
    "DnsFact",
    "DriftPlan",
    "Evidence",
    "FindingStatus",
    "IncidentInput",
    "InterfaceFact",
    "Match",
    "MatchStatus",
    "Playbook",
    "PlaybookError",
    "PlaybookFinding",
    "RadioFact",
    "ServiceFact",
    "Source",
    "Step",
    "StepKind",
    "StepOutcome",
    "WanFact",
    "Withheld",
    "assess",
    "client_cause_outside",
    "dhcp_cause_outside",
    "dns_cause_outside",
    "drift_cause_outside",
    "interface_cause_outside",
    "match",
    "merge_context",
    "radio_cause_outside",
    "registry_table",
    "to_decision_input",
    "wan_cause_outside",
]
