"""Security Center wiring (release 1.46.0, part 1; plan 2026-11-17).

One fleet-wide center per Home Assistant instance. It connects the pure
``security_*`` modules to data the integration already has; it makes no
router call of its own and adds none to a poll.

Inputs (all read-only):

* Network intelligence: the center is a ``PollObserver`` of the engine
  (like client stability). Per poll it feeds the Wi-Fi lines and the
  inferred NI events to the detectors, the router uptime (restart guard),
  and the clients of the poll (with the live state of client stability) to
  the trust book. NI incidents are read with ``machine.peek()`` and only
  ever *linked* by their id (``correlate``), never changed or suppressed.
* Enterprise core: core events through ``api.subscribe`` (drift,
  ``router.forgotten``, new backup versions), capabilities through the
  registry and ``api.capability``, the module key through
  ``api.async_get_module_key``. The configuration areas of a drift come
  from comparing two *stored* versions (``api.async_compare`` with the
  module actor): no router contact.

Outputs: own ``sec_*`` incidents (own counters, cap 100), a timeline,
events on the core bus only through ``api.emit`` (security ring), and a
masked overview. Manual actions go through the core guard (admin users
only) and are audited.

Default off: without ``enabled`` the center only reads its store. It
registers no observer and no listener, writes nothing and emits nothing.
Every entry point catches its own errors (logged without identities) so a
poll, a core event or a setup never fails because of the center.

Part 2: the syslog receiver (``security_syslog``) runs only while the center
is on and ``log_path`` is ``syslog``; its records pass the ``Deduper`` (one
for all paths, marks kept across path changes) before the detectors see
them, and ``Liveness`` turns them into the firewall/DNS log source states.
The sender allowlist comes from the core's router registry. After each poll
the center publishes a counts-only ``fleet_view`` for the fleet sensors
(``security_entities``) and signals ``SIGNAL_SECURITY_CENTER``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import math
import secrets
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import voluptuous as vol
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.json import prepare_save_json
from homeassistant.helpers.storage import Store

from .const import (
    DATA_SECURITY_CENTER,
    SEC_COUNT_WINDOW_SECONDS,
    SEC_DEFAULT_SYSLOG_PORT,
    SEC_DRIFT_HINT_WINDOW_SECONDS,
    SEC_DRIFT_RESOLVE_WINDOW_SECONDS,
    SEC_DRIFT_RETRY_SECONDS,
    SEC_INCIDENT_AUTO_RESOLVE_SECONDS,
    SEC_INCIDENT_CAP,
    SEC_SAVE_DELAY_SECONDS,
    SEC_STORE_KEY,
    SEC_STORE_MAX_BYTES,
    SEC_STORE_MINOR_VERSION,
    SEC_STORE_VERSION,
    SEC_SYSLOG_BUFFER_MAX,
    SEC_SYSLOG_RETRY_SECONDS,
    SEC_TIMELINE_DAYS,
    SEC_TIMELINE_MAX,
    SIGNAL_SECURITY_CENTER,
)
from .core_masking import MASK, pseudonymise_fields
from .core_models import (
    FLEET_ROUTER_ID,
    ActionClass,
    Actor,
    ActorKind,
    Capability,
    CoreEvent,
    CoreEventType,
    EventResult,
    InstallationKeyState,
    Severity,
    VerifiedActor,
)
from .security_baseline import BaselineBook
from .security_logfmt import FMT_DNS_QUERY, FMT_DNS_REPLY, FMT_FW4, FORMAT_CONFIRMED
from .security_logsrc import KIND_SOURCES, Deduper, Liveness, NullLogSource
from .security_model import (
    AUDIT_MANDATORY_TYPES,
    EVENT_PREFIX,
    IDENTITY_KEY_PURPOSE,
    INCIDENT_PREFIX,
    MODULE_SOURCE,
    Assessment,
    Availability,
    DataSource,
    LogPath,
    SecurityEvent,
    SourceStatus,
    check_module_key,
    client_ref,
    event_actor,
    event_type,
    forget_router,
    forgotten_router_id,
    keyed_id,
    mask_identities,
    normalize_mac,
    sealed_event,
    source_status,
    status_from_capability,
    valid_router_id,
)
from .security_rules import (
    AUTH_FAIL_KINDS,
    DRIFT_KIND,
    DetectorResult,
    DetectorSet,
    IncidentRef,
    check_sources,
    correlate,
    default_detectors,
    results_events,
)
from .security_score import (
    FACTOR_ACTIVITY,
    FACTOR_AUTH,
    FACTOR_CONFIG,
    FACTOR_INCIDENTS,
    FACTOR_SEGMENTATION,
    FACTOR_UNKNOWN,
    compute_score,
    incident_load,
)
from .security_syslog import (
    REASON_NOT_STARTED,
    SyslogReceiver,
    sender_address,
)
from .security_trust import Indicator, NoticeKind, TrustBook, TrustNotice, TrustState

_LOGGER = logging.getLogger(__name__)

_FLUSH_KEY = f"{DATA_SECURITY_CENTER}_flush"
_DAY = 86400.0

# --- incidents and statuses ----------------------------------------------------------

STATUS_OPEN = "open"
STATUS_RESOLVED = "resolved"
STATUS_CONFIRMED = "confirmed"
INCIDENT_STATUSES = (STATUS_OPEN, STATUS_RESOLVED, STATUS_CONFIRMED)
_ACTIVE_STATUSES = frozenset({STATUS_OPEN, STATUS_CONFIRMED})

# Full store (review 2, M3): open and confirmed hints are never evicted for
# new ones; a new hint that finds no room is dropped and counted, with at
# most one timeline note per window. Core events of new hints are limited
# to SEC_EVENT_BURST per SEC_EVENT_BURST_WINDOW_SECONDS (the rest counted),
# so a flood of findings cannot fill the core's security ring.
SEC_CAP_NOTE_WINDOW_SECONDS = 3600.0
SEC_EVENT_BURST = 20
SEC_EVENT_BURST_WINDOW_SECONDS = 600.0
TEXT_CAP_REACHED = (
    "Obergrenze erreicht: neue Hinweise werden nicht gespeichert, bis "
    "erledigte Hinweise Platz machen (offene und bestätigte bleiben)"
)

# Availability of one detection in the overview.
DETECTION_AVAILABLE = "available"
DETECTION_NOT_AVAILABLE = "not_available"
DETECTION_LIMITED = "limited"

# Reasons of the off-router log path. The syslog receiver adds its own
# (``security_syslog.REASON_*``: port in use, permission denied, ...).
REASON_COLLECTOR = "collector_not_available"
# The router's management address is no IP literal, or no router sends from
# it: its lines cannot be told apart from foreign ones, so none are taken.
REASON_SENDER_UNKNOWN = "sender_not_allowed"
REASON_NO_CORE = "no_core"
REASON_NO_ENGINE = "no_engine"

# Guard actions (registered on first use; admin users only).
ACTION_CONFIRM_DEVICE = f"{MODULE_SOURCE}.confirm_device"
ACTION_SET_DEVICE_NAME = f"{MODULE_SOURCE}.set_device_name"
ACTION_SET_INCIDENT_STATUS = f"{MODULE_SOURCE}.set_incident_status"
ACTION_UPDATE_SETTINGS = f"{MODULE_SOURCE}.update_settings"
_ACTIONS = (
    ACTION_CONFIRM_DEVICE,
    ACTION_SET_DEVICE_NAME,
    ACTION_SET_INCIDENT_STATUS,
    ACTION_UPDATE_SETTINGS,
)
EVENT_INCIDENT_STATUS = event_type("incident_status_changed")
EVENT_SETTINGS = event_type("settings_changed")

# Detector -> trust indicator of the client it names.
INDICATOR_OF: Mapping[str, Indicator] = {
    "wifi_auth_repeat": Indicator.LOGIN_FAILURES,
    "wifi_multi_ap_auth": Indicator.MULTI_AP_AUTH,
    "wifi_assoc_burst": Indicator.ASSOC_BURST,
    "fw_port_scan_hint": Indicator.PORT_SCAN,
    "fw_mgmt_access": Indicator.MGMT_ACCESS,
    "fw_inter_vlan": Indicator.INTER_VLAN,
    "dns_rate": Indicator.DNS_ANOMALY,
    "dns_nxdomain_cluster": Indicator.DNS_ANOMALY,
    "dns_many_domains": Indicator.DNS_ANOMALY,
    "dns_tunnel_hint": Indicator.DNS_ANOMALY,
}
# Plan D-REUSE: NI incident types that already cover a finding. With an
# open linked NI incident of the counterpart type no sec_* incident is
# opened; the finding is linked in the timeline instead.
REUSED_NI_TYPES: frozenset[str] = frozenset(
    {
        "system_reboot",
        "wifi_auth_failures",
        "wifi_auth_wave",
        "wifi_mass_disconnect",
        "dhcp_conflict",
        "system_conntrack_jump",
    }
)
NI_COUNTERPART: Mapping[str, str] = {
    "wifi_auth_repeat": "wifi_auth_failures",
    "wifi_auth_many_clients": "wifi_auth_wave",
    "wifi_deauth_cluster": "wifi_mass_disconnect",
}
_NI_OPEN = frozenset({"active", "acknowledged"})

# Score factor -> detectors whose limitations make it partial.
_FACTOR_DETECTORS: Mapping[str, tuple[str, ...]] = {
    FACTOR_AUTH: ("wifi_auth_repeat", "wifi_multi_ap_auth"),
    FACTOR_ACTIVITY: (
        "fw_blocked",
        "fw_port_scan_hint",
        "fw_mgmt_access",
        "dns_rate",
        "dns_nxdomain_cluster",
        "dns_many_domains",
        "dns_tunnel_hint",
    ),
    FACTOR_SEGMENTATION: ("vlan_segmentation_drift", "fw_inter_vlan"),
}

# German texts (plan D-WORDING: "Hinweis" / "Hypothese"; a configuration
# change is never called an attack).
TITLES: Mapping[str, str] = {
    "wifi_auth_repeat": "Wiederholte WLAN-Anmeldefehler eines Geräts",
    "wifi_auth_many_clients": "Anmeldefehler vieler Geräte an einem Zugangspunkt",
    "wifi_assoc_burst": "Auffällig viele WLAN-Verbindungsversuche",
    "wifi_deauth_cluster": "Gehäufte WLAN-Abmeldungen",
    "wifi_multi_ap_auth": "Anmeldefehler eines Geräts an mehreren Zugangspunkten",
    "fw_blocked": "Ungewöhnlich viele blockierte Verbindungen",
    "fw_port_scan_hint": "Hinweis auf eine Port-Abfrage",
    "fw_mgmt_access": "Zugriffsversuche auf die Router-Verwaltung",
    "fw_inter_vlan": "Verbindungsversuche zwischen Netzsegmenten",
    "vlan_segmentation_drift": "Segmentierungsrelevante Konfigurationsänderung",
    "dns_rate": "Ungewöhnlich viele DNS-Anfragen",
    "dns_nxdomain_cluster": "Gehäufte DNS-Anfragen an nicht vorhandene Namen",
    "dns_many_domains": "Auffällig viele verschiedene DNS-Namen",
    "dns_tunnel_hint": "Hinweis auf ungewöhnliche DNS-Namen",
    "trust_suspicious": "Gerät mit mehreren Auffälligkeiten",
}
HINT_DEFAULT = "Hinweis zur Prüfung; kein Beleg für eine Ursache."
HINT_DRIFT = (
    "Konfigurationsänderung in einem segmentierungsrelevanten Bereich ({areas}). "
    "Bitte prüfen, ob die Änderung geplant war."
)
HINT_DRIFT_BEFORE = (
    "Kurz vorher gab es eine Konfigurationsänderung an diesem Router "
    "(zeitlicher Zusammenhang, keine belegte Ursache)."
)
TEXT_DRIFT_SEEN = "Konfigurationsänderung erkannt"
TEXT_REUSED = "Bereits durch einen vorhandenen Netzwerk-Vorfall abgedeckt"
NOTICE_TEXTS: Mapping[str, str] = {
    NoticeKind.NEW_DEVICE: "Neues Gerät",
    NoticeKind.PRIVATE_MAC: "Neues Gerät mit privater MAC-Adresse",
    NoticeKind.INCOMPLETE: "Gerät ohne Verlaufsdaten",
    NoticeKind.IP_CHURN: "Gerät wechselt häufig die IP-Adresse",
    NoticeKind.SUSPICIOUS: "Gerät mit mehreren Auffälligkeiten",
    NoticeKind.CAPACITY: "Geräteliste voll",
}

_COUNTERS = (
    "polls",
    "polls_unmapped",
    "findings",
    "incidents_opened",
    "incidents_merged",
    "incidents_reopened",
    "incidents_resolved",
    "incidents_dropped",
    "incidents_cap_dropped",
    "incidents_reused",
    "notices",
    "drifts_seen",
    "drifts_resolved",
    "drifts_area_unknown",
    "events_emitted",
    "events_failed",
    "events_throttled",
    "actions",
    "actions_denied",
    "routers_forgotten",
    "errors",
    "load_errors",
    "store_trimmed",
    "log_records",
    "syslog_starts",
)


class _HourCount:
    """Count per minute over the last ``SEC_COUNT_WINDOW_SECONDS`` (memory only).

    At most one bucket per minute of the window, so the size stays bounded
    whatever the input rate; times outside the window are not counted.
    """

    __slots__ = ("_buckets",)

    def __init__(self) -> None:
        self._buckets: dict[int, int] = {}

    def add(self, ts: float, now: float, n: int = 1) -> None:
        if (
            n <= 0
            or not math.isfinite(ts)
            or not 0 <= now - ts < SEC_COUNT_WINDOW_SECONDS
        ):
            return
        minute = int(ts // 60)
        self._buckets[minute] = self._buckets.get(minute, 0) + n
        self._prune(now)

    def total(self, now: float) -> int:
        self._prune(now)
        return sum(self._buckets.values())

    def _prune(self, now: float) -> None:
        oldest = int((now - SEC_COUNT_WINDOW_SECONDS) // 60)
        newest = int(now // 60)
        for minute in [m for m in self._buckets if m <= oldest or m > newest]:
            del self._buckets[minute]

    def clear(self) -> None:
        self._buckets.clear()


class SecurityCenterError(HomeAssistantError):
    """A refused or impossible Security Center action (``reason`` says why)."""

    def __init__(self, reason: str, message: str | None = None) -> None:
        """Error with a machine reason."""
        super().__init__(message or f"Security Center: {reason}")
        self.reason = reason


# --- settings --------------------------------------------------------------------------


def default_settings() -> dict[str, Any]:
    """Every option off (plan D-OFF)."""
    return {
        "enabled": False,
        "log_path": LogPath.OFF.value,
        "syslog_port": SEC_DEFAULT_SYSLOG_PORT,
        "keep_dns_names": False,
        "thresholds": {},
        "subnet_zones": {},
    }


_DETECTOR_IDS = frozenset(d.id for d in default_detectors().detectors)


def _threshold_map(value: Any) -> dict[str, float]:
    if not isinstance(value, Mapping):
        raise vol.Invalid("thresholds must be a mapping")
    out: dict[str, float] = {}
    for key, number in value.items():
        if key not in _DETECTOR_IDS:
            raise vol.Invalid("unknown detector")
        if (
            isinstance(number, bool)
            or not isinstance(number, int | float)
            or not 1 <= number <= 100000
        ):
            raise vol.Invalid("threshold must be a number from 1 to 100000")
        out[str(key)] = number
    return out


def _zone_map(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise vol.Invalid("subnet_zones must be a mapping")
    if len(value) > 64:
        raise vol.Invalid("at most 64 subnets")
    out: dict[str, str] = {}
    for cidr, zone in value.items():
        try:
            net = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError as err:
            raise vol.Invalid("invalid subnet") from err
        if (
            not isinstance(zone, str)
            or not 1 <= len(zone) <= 32
            or not all(c.isalnum() or c in "_-" for c in zone)
        ):
            raise vol.Invalid("invalid zone name")
        out[str(net)] = zone.lower()
    return out


SETTINGS_SCHEMA = vol.Schema(
    {
        vol.Required("enabled"): bool,
        vol.Required("log_path"): vol.In([p.value for p in LogPath]),
        vol.Required("syslog_port"): vol.All(
            vol.Coerce(int), vol.Range(min=1024, max=65535)
        ),
        vol.Required("keep_dns_names"): bool,
        vol.Required("thresholds"): _threshold_map,
        vol.Required("subnet_zones"): _zone_map,
    },
    extra=vol.PREVENT_EXTRA,
)


def merge_settings(current: Mapping[str, Any], update: Any) -> dict[str, Any]:
    """``current`` with ``update`` applied; vol.Invalid if the result is bad."""
    if not isinstance(update, Mapping):
        raise vol.Invalid("settings update must be a mapping")
    return SETTINGS_SCHEMA({**current, **update})


def settings_from_store(raw: Any) -> dict[str, Any]:
    """Stored settings, every unusable value back at its default."""
    settings = default_settings()
    if not isinstance(raw, Mapping):
        return settings
    for key in settings:
        if key not in raw:
            continue
        try:
            settings = SETTINGS_SCHEMA({**settings, key: raw[key]})
        except vol.Invalid:
            continue
    return settings


# --- small helpers -----------------------------------------------------------------------


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _severity(value: Any) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.WARNING


def _evidence_value(event: SecurityEvent, name: str) -> str | None:
    prefix = f"{name}="
    for item in event.evidence:
        if item.startswith(prefix):
            return item[len(prefix) :]
    return None


def _ts(value: Any) -> float | None:
    """Epoch seconds of a datetime (or a number), else None."""
    stamp = getattr(value, "timestamp", None)
    if callable(stamp):
        try:
            return float(stamp())
        except (TypeError, ValueError, OverflowError):
            return None
    return _num(value)


def _is_admin(actor: Any) -> bool:
    """A verified, fresh admin user (the only one who sees plain identities)."""
    if not isinstance(actor, VerifiedActor):
        return False
    try:
        return (
            actor.actor.kind is ActorKind.USER and actor.is_admin and actor.is_fresh()
        )
    except Exception:  # noqa: BLE001 - a broken actor is no admin
        return False


@dataclass(slots=True)
class DriftNote:
    """One drift of one router as the core reported it (no values inside)."""

    router_id: str
    drift_id: str
    ts: float
    baseline: str | None
    critical: bool = False
    areas: list[str] | None = None
    state: str = "pending"  # pending | resolved | unknown
    fed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Store form."""
        return {
            "router_id": self.router_id,
            "drift_id": self.drift_id,
            "ts": self.ts,
            "baseline": self.baseline,
            "critical": self.critical,
            "areas": self.areas,
            "state": self.state,
            "fed": self.fed,
        }

    @classmethod
    def from_dict(cls, data: Any) -> DriftNote | None:
        """Lenient inverse of :meth:`to_dict`."""
        if not isinstance(data, Mapping):
            return None
        rid = valid_router_id(data.get("router_id"))
        drift_id = data.get("drift_id")
        ts = _num(data.get("ts"))
        if rid is None or not isinstance(drift_id, str) or not drift_id or ts is None:
            return None
        areas = data.get("areas")
        baseline = data.get("baseline")
        state = data.get("state")
        return cls(
            router_id=rid,
            drift_id=drift_id[:128],
            ts=ts,
            baseline=baseline if isinstance(baseline, str) else None,
            critical=data.get("critical") is True,
            areas=[str(a)[:32] for a in areas] if isinstance(areas, list) else None,
            state=state if state in ("pending", "resolved", "unknown") else "pending",
            fed=data.get("fed") is True,
        )


@dataclass(slots=True)
class _Binding:
    """What the center holds of the running core (released on deactivate)."""

    core: Any = None
    api: Any = None
    removers: list[Callable[[], None]] = field(default_factory=list)
    events_ok: bool = False
    actions_ok: bool = False


# --- life cycle --------------------------------------------------------------------------


@callback
def async_get_security_center(hass: HomeAssistant) -> SecurityCenter | None:
    """The running Security Center, or None."""
    center = hass.data.get(DATA_SECURITY_CENTER)
    return center if isinstance(center, SecurityCenter) else None


async def async_setup_security_center(
    hass: HomeAssistant, entry: Any, coordinator: Any
) -> SecurityCenter:
    """Create/load the per-HA center once and add this entry to it.

    Runs after network intelligence, client stability and the configuration
    manager are set up for the entry. Off by default: then only the store
    is read.
    """
    center = async_get_security_center(hass)
    if center is None:
        center = SecurityCenter(hass)
        hass.data[DATA_SECURITY_CENTER] = center
    await center.async_load()
    center.add_entry(entry.entry_id, coordinator)
    if center.enabled:
        await center.async_activate()
        center._stage("publish", center._publish, center._now())
    # part 2: HTTP routes (once per HA run) and the fleet sensors
    center._stage("http routes", _register_views, hass)
    center._sync_entities()
    return center


def _register_views(hass: HomeAssistant) -> None:
    from .security_views import async_register_security_views

    async_register_security_views(hass)


async def async_release_security_center(hass: HomeAssistant, entry_id: str) -> None:
    """Drop the entry; after the last one stop and write the store now."""
    center = async_get_security_center(hass)
    if center is None:
        return
    center.remove_entry(entry_id)
    try:
        from .security_entities import async_entry_unloaded

        # the fleet sensors move to another entry if this one hosted them
        async_entry_unloaded(hass, entry_id, last=not center.entry_count)
    except Exception as err:  # noqa: BLE001 - the unload goes on
        center._fail("sensor release", err)
    if center.entry_count:
        if center.syslog is not None:
            center._stage("log senders", center._refresh_senders)
        return
    hass.data.pop(DATA_SECURITY_CENTER, None)
    center.close()
    claim: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    hass.data[_FLUSH_KEY] = claim
    try:
        if center.dirty:
            await center.async_flush()
    finally:
        claim.set_result(None)
        if hass.data.get(_FLUSH_KEY) is claim:
            hass.data.pop(_FLUSH_KEY, None)


def _store_size(payload: dict[str, Any]) -> int:
    """Bytes of the store file exactly as HA's ``Store`` writes it."""
    wrapped = {
        "version": SEC_STORE_VERSION,
        "minor_version": SEC_STORE_MINOR_VERSION,
        "key": SEC_STORE_KEY,
        "data": payload,
    }
    _mode, data = prepare_save_json(wrapped)
    return len(data.encode("utf-8") if isinstance(data, str) else data)


def _backup_file(path: Any) -> bool:
    from .net_engine import _backup_file as backup

    return backup(path)


class SecurityCenter:
    """Fleet-wide Security Center: detectors, trust book, incidents, store."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Empty center; ``async_load`` reads the store."""
        self.hass = hass
        self._store: Store[dict[str, Any]] = Store(
            hass,
            SEC_STORE_VERSION,
            SEC_STORE_KEY,
            minor_version=SEC_STORE_MINOR_VERSION,
            private=True,
        )
        self._lock = asyncio.Lock()
        self.loaded = False
        self.load_failed = False
        self.dirty = False
        self._save_pending = False
        self._closed = False
        self.settings: dict[str, Any] = default_settings()
        self.trust = TrustBook()
        self.baseline = BaselineBook()
        self.detectors: DetectorSet = default_detectors(baseline=self.baseline)
        self.log_source = NullLogSource()
        self.deduper = Deduper()
        # part 2: syslog receiver (None unless on and log_path "syslog")
        self.liveness = Liveness()
        self.syslog: SyslogReceiver | None = None
        self._syslog_port: int | None = None
        self._syslog_tried: float | None = None  # monotonic
        self._fw_events = _HourCount()
        self._auth_failures = _HourCount()
        self.fleet_view: dict[str, Any] | None = None
        self.incidents: dict[str, dict[str, Any]] = {}
        self._by_scope: dict[str, str] = {}
        self.timeline: list[dict[str, Any]] = []
        self.drifts: dict[tuple[str, str], DriftNote] = {}
        self.counters: dict[str, int] = dict.fromkeys(_COUNTERS, 0)
        self.last_now: float | None = None
        self._cap_noted: float | None = None  # memory only
        self._emit_times: deque[float] = deque()  # monotonic, memory only
        self.last_save_bytes: int | None = None
        # memory only
        self._entries: dict[str, Any] = {}  # entry id -> coordinator
        self._rid_cache: dict[str, str] = {}
        self._seen: dict[str, dict[str, float]] = {}  # router id -> source -> time
        self._results: dict[tuple[str, str], DetectorResult] = {}
        self._statuses: dict[str, dict[str, SourceStatus]] = {}
        self._ni_refs: list[IncidentRef] = []
        self._ni_open: dict[str, tuple[str, str | None]] = {}  # id -> (type, sev)
        self._binding = _Binding()
        self._engine: Any = None
        self._engine_unsub: Callable[[], None] | None = None
        self._module_key: bytes | None = None
        # Key of the ids while the core hands out no module key: random per
        # run, never stored (review 2, M2).
        self._run_key = secrets.token_bytes(32)
        self._drift_task: asyncio.Task[Any] | None = None
        self._drift_again = False
        self._drift_tried: float | None = None
        self._core_now: float | None = None
        self.active = False
        # Test seams: entry id -> contract router id; drift note -> areas;
        # management address -> router id (allowlist); receiver factory.
        self.router_id_of: Callable[[str], str | None] = self._registry_router_id
        self.drift_areas_of: Callable[[DriftNote], Any] = self._async_drift_areas
        self.senders_of: Callable[[], Mapping[str, str]] = self._registry_senders
        self.syslog_factory: Callable[..., SyslogReceiver] = SyslogReceiver

    # -- properties ---------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """The ``enabled`` setting."""
        return self.settings.get("enabled") is True

    @property
    def entry_count(self) -> int:
        """Number of entries using the center."""
        return len(self._entries)

    @property
    def module_key_available(self) -> bool:
        """True once the core handed out the module key."""
        return self._module_key is not None

    def _now(self) -> float:
        """Time of actions and views: never behind the wall clock.

        ``last_now`` is the time of the newest poll (NI's clock) or, after a
        restart, of the last save; actions and views before the first poll
        must not get that old time (review 2, N2). A poll clock ahead of the
        wall clock is kept. Detectors use the poll's own time, not this, so
        the clock-shift handling (``on_clock_shift``) is unchanged.
        """
        wall = time.time()
        return wall if self.last_now is None else max(wall, self.last_now)

    # -- entries ------------------------------------------------------------------------

    @callback
    def add_entry(self, entry_id: str, coordinator: Any) -> None:
        """Remember the entry's coordinator (uptime is read from its data)."""
        self._entries[entry_id] = coordinator

    @callback
    def remove_entry(self, entry_id: str) -> None:
        """Forget the entry (its router data stays until router.forgotten).

        The router leaves the source statuses, the score and the coverage at
        once (review 2, H1); its hints, timeline and baselines stay.
        """
        rid = self._rid_cache.get(entry_id) if entry_id in self._entries else None
        if rid is None and entry_id in self._entries:
            try:
                rid = self._rid(entry_id)
            except Exception:  # noqa: BLE001 - unknown router: nothing to drop
                rid = None
        self._entries.pop(entry_id, None)
        self._rid_cache.pop(entry_id, None)
        if rid is not None and rid not in self._rid_cache.values():
            self._drop_router_memory(rid)

    def _drop_router_memory(self, rid: str) -> None:
        """Statuses and results of a router without a loaded entry (memory)."""
        self._seen.pop(rid, None)
        self._statuses.pop(rid, None)
        for key in [k for k in self._results if k[1] == rid]:
            del self._results[key]

    def _registry_router_id(self, entry_id: str) -> str | None:
        api = self._binding.api
        if api is None:
            return None
        try:
            return valid_router_id(api.registry.get_by_entry(entry_id).router_id)
        except Exception:  # noqa: BLE001 - unknown entry: no router id yet
            return None

    def _registry_senders(self) -> dict[str, str]:
        """Allowlist of the syslog receiver: management address -> router id.

        Only routers of loaded entries whose management host is an IP
        literal (no DNS lookup); without the core the list is empty.
        """
        api = self._binding.api
        if api is None:
            return {}
        out: dict[str, str] = {}
        ambiguous: set[str] = set()
        for record in api.registry.list():
            if record.entry_id not in self._entries:
                continue
            rid = valid_router_id(record.router_id)
            address = sender_address(getattr(record.connection, "host", None))
            if rid is None or address is None:
                continue
            if out.get(address, rid) != rid:
                ambiguous.add(address)  # two routers, one address: neither
            out[address] = rid
        for address in ambiguous:
            del out[address]
        return out

    def _rid(self, entry_id: str) -> str | None:
        rid = self._rid_cache.get(entry_id)
        if rid is None:
            rid = valid_router_id(self.router_id_of(entry_id))
            if rid is not None:
                self._rid_cache[entry_id] = rid
        return rid

    # -- errors -----------------------------------------------------------------------

    def _fail(self, stage: str, err: BaseException) -> None:
        """Log an error of the center without identities; never raise."""
        self.counters["errors"] += 1
        _LOGGER.warning(
            "Security Center: %s failed (%s); the routers keep working",
            stage,
            type(err).__name__,
        )
        _LOGGER.debug("Security Center %s error", stage, exc_info=err)

    # -- store ----------------------------------------------------------------------------

    async def async_load(self) -> None:
        """Read the store once; a damaged store is kept as ``.bak``."""
        async with self._lock:
            if self.loaded:
                return
            pending = self.hass.data.get(_FLUSH_KEY)
            if isinstance(pending, asyncio.Future) and not pending.done():
                await pending
            try:
                stored = await self._store.async_load()
            except Exception as err:  # noqa: BLE001 - start empty, keep a copy
                self._fail("store load", err)
                stored = None
                self.load_failed = True
            if stored is not None and not isinstance(stored, dict):
                _LOGGER.warning("Security Center store has an unknown format")
                stored = None
                self.load_failed = True
            if stored:
                self._restore(stored)
            if self.load_failed:
                await self._async_backup()
            self.loaded = True

    def _restore(self, stored: Mapping[str, Any]) -> None:
        """Every section on its own: a broken one starts empty."""
        sections: tuple[tuple[str, Callable[[Any], None]], ...] = (
            ("settings", self._restore_settings),
            ("trust", self._restore_trust),
            ("baseline", self._restore_baseline),
            ("incidents", self._restore_incidents),
            ("timeline", self._restore_timeline),
            ("drifts", self._restore_drifts),
            ("log_marks", self._restore_marks),
            ("counters", self._restore_counters),
        )
        for name, restore in sections:
            try:
                restore(stored.get(name))
            except Exception as err:  # noqa: BLE001 - tolerant per section
                self.counters["load_errors"] += 1
                _LOGGER.warning(
                    "Security Center store section %s unreadable (%s); empty",
                    name,
                    type(err).__name__,
                )
        saved = _num(stored.get("saved_at"))
        if saved is not None:
            self.last_now = saved

    def _restore_settings(self, raw: Any) -> None:
        self.settings = settings_from_store(raw)
        self._rebuild_detectors()

    def _restore_trust(self, raw: Any) -> None:
        if raw is not None:
            self.trust = TrustBook.from_dict(raw)

    def _restore_baseline(self, raw: Any) -> None:
        if raw is not None:
            self.baseline = BaselineBook.from_dict(raw)
            self._rebuild_detectors()

    def _restore_incidents(self, raw: Any) -> None:
        for item in raw if isinstance(raw, list) else ():
            inc = _incident_from_store(item)
            if inc is None or inc["id"] in self.incidents:
                continue
            self.incidents[inc["id"]] = inc
            self._by_scope[inc["scope"]] = inc["id"]
        self._enforce_cap()

    def _restore_timeline(self, raw: Any) -> None:
        rows = [
            dict(row)
            for row in (raw if isinstance(raw, list) else ())
            if isinstance(row, Mapping) and _num(row.get("ts")) is not None
        ]
        self.timeline = rows[-SEC_TIMELINE_MAX:]

    def _restore_drifts(self, raw: Any) -> None:
        for item in raw if isinstance(raw, list) else ():
            note = DriftNote.from_dict(item)
            if note is not None:
                self.drifts[(note.router_id, note.drift_id)] = note

    def _restore_marks(self, raw: Any) -> None:
        self.deduper = Deduper.from_dict(raw)

    def _restore_counters(self, raw: Any) -> None:
        if not isinstance(raw, Mapping):
            return
        for key in _COUNTERS:
            value = raw.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                self.counters[key] = value

    async def _async_backup(self) -> None:
        path = getattr(self._store, "path", None)
        try:
            copied = await self.hass.async_add_executor_job(_backup_file, path)
        except Exception as err:  # noqa: BLE001 - the next save replaces it
            self._fail("store backup", err)
            return
        if copied:
            _LOGGER.warning("Security Center kept a copy of its unreadable store")

    @callback
    def schedule_save(self) -> None:
        """Mark a change; write at most ``SEC_SAVE_DELAY_SECONDS`` from now."""
        if not self.enabled and not self._save_pending:
            # Off: nothing is written (plan D-OFF); settings changes call
            # _schedule_save_now themselves.
            return
        self._schedule_save_now()

    def _schedule_save_now(self) -> None:
        self.dirty = True
        if self._save_pending or self._closed:
            return
        self._save_pending = True
        self._store.async_delay_save(self._data_to_save, SEC_SAVE_DELAY_SECONDS)

    async def async_flush(self) -> None:
        """Write the store now."""
        await self._store.async_save(self._data_to_save())

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        """Store payload, trimmed to ``SEC_STORE_MAX_BYTES``."""
        self._save_pending = False
        self.dirty = False
        payload = self._payload()
        size = _store_size(payload)
        if size > SEC_STORE_MAX_BYTES:
            payload, size = self._trimmed_payload(payload, size)
            self.counters["store_trimmed"] += 1
            _LOGGER.warning(
                "Security Center store trimmed to %d bytes (limit %d)",
                size,
                SEC_STORE_MAX_BYTES,
            )
        self.last_save_bytes = size
        return payload

    def _payload(self) -> dict[str, Any]:
        now = self._now()
        return {
            "settings": dict(self.settings),
            "trust": self.trust.to_dict(),
            "baseline": self.baseline.to_dict(),
            "incidents": list(self.incidents.values()),
            "timeline": list(self.timeline),
            "drifts": [n.to_dict() for n in self.drifts.values() if now - n.ts <= _DAY],
            "log_marks": self.deduper.to_dict(),
            "counters": dict(self.counters),
            "saved_at": self.last_now,
        }

    def _trimmed_payload(
        self, payload: dict[str, Any], size: int
    ) -> tuple[dict[str, Any], int]:
        """Order: timeline, resolved incidents, baselines, oldest devices."""
        limit = SEC_STORE_MAX_BYTES
        timeline = payload["timeline"]
        while size > limit and timeline:
            timeline = timeline[len(timeline) // 2 + 1 :] if len(timeline) > 1 else []
            payload["timeline"] = timeline
            size = _store_size(payload)
        if size > limit:
            payload["incidents"] = [
                i for i in payload["incidents"] if i.get("status") != STATUS_RESOLVED
            ]
            size = _store_size(payload)
        if size > limit:
            payload["baseline"] = BaselineBook().to_dict()
            size = _store_size(payload)
        records = list(payload["trust"].get("records", []))
        fixed = [r for r in records if r.get("confirmed_at") is not None]
        rest = [r for r in records if r.get("confirmed_at") is None]
        while size > limit and rest:
            rest = rest[len(rest) // 4 + 1 :]
            payload["trust"] = {**payload["trust"], "records": [*fixed, *rest]}
            size = _store_size(payload)
        return payload, size

    # -- activation -------------------------------------------------------------------------

    async def async_activate(self) -> None:
        """Bind the core and the engine (enabled only); errors stay here."""
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
        await self.async_sync_log_source()

    # -- syslog receiver (part 2) -------------------------------------------------------

    def _wants_syslog(self) -> bool:
        return (
            self.active
            and not self._closed
            and self.enabled
            and self.settings.get("log_path") == LogPath.SYSLOG.value
        )

    async def async_sync_log_source(self) -> None:
        """Start, keep, restart or stop the receiver to match the settings.

        Binds only while the center is on and ``log_path`` is ``syslog``;
        otherwise no socket exists. Never raises: a bind error leaves a
        receiver that is not listening and says why.
        """
        try:
            await self._async_sync_log_source()
        except Exception as err:  # noqa: BLE001 - never fails a setup
            self._fail("syslog receiver", err)

    async def _async_sync_log_source(self) -> None:
        want = self._wants_syslog()
        port = self.settings.get("syslog_port", SEC_DEFAULT_SYSLOG_PORT)
        receiver = self.syslog
        if receiver is not None and (
            not want or self._syslog_port != port or not receiver.listening
        ):
            self._stop_syslog()
            receiver = None
        if not want:
            return
        if receiver is not None:
            self._refresh_senders()
            return
        receiver = self.syslog_factory(port=port, on_backlog=self._on_log_backlog)
        self.syslog = receiver
        self._syslog_port = port
        self._syslog_tried = time.monotonic()
        self.counters["syslog_starts"] += 1
        self._refresh_senders()
        await receiver.async_start()
        if self.syslog is not receiver:  # stopped while binding
            receiver.close()

    def _stop_syslog(self) -> None:
        """Take what is buffered, then close the socket (no socket stays)."""
        receiver = self.syslog
        self.syslog = None
        self._syslog_port = None
        if receiver is None:
            return
        try:
            self._drain_from(receiver)
        except Exception as err:  # noqa: BLE001 - closing goes on
            self._fail("log drain", err)
        receiver.close()

    def _refresh_senders(self) -> None:
        receiver = self.syslog
        if receiver is not None:
            receiver.set_senders(self.senders_of())

    def _on_log_backlog(self) -> None:
        """The receiver's buffer fills up: drain before the next poll."""
        if self.active and not self._closed:
            self._stage("log drain", self._drain_logs)

    def _drain_logs(self) -> None:
        receiver = self.syslog
        if receiver is not None:
            self._drain_from(receiver)

    def _drain_from(self, receiver: SyslogReceiver) -> None:
        """Receiver -> Deduper -> Liveness, detectors and the hour counts."""
        records = receiver.drain(SEC_SYSLOG_BUFFER_MAX)
        now = receiver.now()
        fresh = self.deduper.filter(records, now)  # also releases held runs
        if not fresh:
            return
        self.liveness.observe(fresh)
        self.detectors.feed_records(fresh)
        self.counters["log_records"] += len(fresh)
        blocked = sum(
            1
            for r in fresh
            if r.kind in KIND_SOURCES
            and KIND_SOURCES[r.kind] == DataSource.FIREWALL_LOG.value
            and r.fields.get("ts_future") is not True
        )
        self._fw_events.add(now, now, blocked)

    def _maybe_retry_syslog(self) -> None:
        """A receiver that could not bind is tried again now and then."""
        receiver = self.syslog
        if receiver is None or receiver.listening or not self._wants_syslog():
            return
        tried = self._syslog_tried
        if tried is not None and time.monotonic() - tried < SEC_SYSLOG_RETRY_SECONDS:
            return
        self._syslog_tried = time.monotonic()
        self.hass.async_create_task(
            self.async_sync_log_source(), name="openwrt_router security syslog"
        )

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
                api.register_event_prefix(EVENT_PREFIX, module=MODULE_SOURCE)
            )
            binding.removers.append(
                api.register_audit_mandatory_types(
                    sorted(AUDIT_MANDATORY_TYPES), module=MODULE_SOURCE
                )
            )
            binding.events_ok = True
        except (TypeError, ValueError) as err:
            self._fail("event registration", err)
        binding.removers.append(api.subscribe(self._on_core_event))
        await self._async_fetch_module_key()
        self._stage("forgotten routers", self._forget_unknown_routers)

    def _stored_router_ids(self) -> set[str]:
        """Router ids the center keeps state of (store sections)."""
        rids = {i.get("router_id") for i in self.incidents.values()}
        rids |= {t.get("router_id") for t in self.timeline}
        rids |= {rid for rid, _drift in self.drifts}
        rids |= set(self.deduper.to_dict().get("hwm", {}))
        return {r for r in rids if isinstance(r, str) and valid_router_id(r)}

    def _forget_unknown_routers(self) -> None:
        """Catch up on ``router.forgotten`` the core sent before we listened.

        The core forgets aged orphans while it loads (``prune_orphans``),
        before any center subscribes, and the bus keeps nothing (review 2,
        M1). On every bind of an active center the stored router ids are
        compared with the registry (read only, orphaned records included);
        what the registry no longer knows is forgotten here. Unknown is not
        forgotten: without a loaded registry (not loaded, load failed, empty)
        nothing is dropped.
        """
        if not self.active or self._closed:
            return
        binding = self._binding
        core, api = binding.core, binding.api
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
        for rid in sorted(self._stored_router_ids() - known):
            self._forget_router(rid)

    async def _async_fetch_module_key(self) -> None:
        binding = self._binding
        if self._module_key is not None or not binding.events_ok:
            return
        if not self.active:
            # Off (e.g. an admin changes a setting): never create the
            # installation key for it (review 2, N6).
            return
        try:
            state = binding.api.installation_key_state
            if state not in (
                InstallationKeyState.OK,
                InstallationKeyState.UNINITIALISED,
            ):
                return
            key = await binding.api.async_get_module_key(
                MODULE_SOURCE, purpose=IDENTITY_KEY_PURPOSE
            )
            self._module_key = check_module_key(key)
        except Exception as err:  # noqa: BLE001 - pseudonyms then become MASK
            _LOGGER.debug("Security Center: no module key (%s)", type(err).__name__)

    def _unbind_core(self) -> None:
        binding = self._binding
        self._binding = _Binding()
        self._module_key = None
        for remove in reversed(binding.removers):
            try:
                remove()
            except Exception:
                _LOGGER.debug("Security Center: remover raised", exc_info=True)

    def _attach_engine(self) -> None:
        from .net_engine import async_get_engine

        engine = async_get_engine(self.hass)
        if engine is self._engine:
            return
        self._detach_engine()
        if engine is not None:
            self._engine = engine
            self._engine_unsub = engine.add_poll_observer(self)

    def _detach_engine(self) -> None:
        if self._engine_unsub is not None:
            self._engine_unsub()
        self._engine_unsub = None
        self._engine = None

    @callback
    def deactivate(self) -> None:
        """Stop observing and listening (data stays); no socket stays bound."""
        self.active = False
        try:
            self._stop_syslog()
        except Exception as err:  # noqa: BLE001 - deactivation goes on
            self._fail("syslog stop", err)
        self._detach_engine()
        self._unbind_core()
        if self._drift_task is not None and not self._drift_task.done():
            self._drift_task.cancel()
        self._drift_task = None
        if self.fleet_view is not None:
            self.fleet_view = None
            self._signal()

    @callback
    def close(self) -> None:
        """Stop for good; no writes are scheduled after this."""
        self.deactivate()
        self._closed = True

    # -- core events ------------------------------------------------------------------------

    def _on_core_event(self, event: CoreEvent) -> None:
        """Core listener (sync, short); never raises."""
        if not self.active or self._closed:
            return
        try:
            if event.source == MODULE_SOURCE:
                return
            ts = _ts(event.ts)
            if ts is not None:
                self._core_now = max(self._core_now or ts, ts)
            forgotten = forgotten_router_id(event)
            if forgotten is not None:
                self._forget_router(forgotten)
                return
            kind = str(event.type)
            if kind in (
                CoreEventType.DRIFT_DETECTED.value,
                CoreEventType.CHANGE_CRITICAL.value,
            ):
                self._note_drift(event, kind, ts)
            elif kind == CoreEventType.BACKUP_CREATED.value:
                rid = valid_router_id(event.router_id)
                if rid is not None and any(
                    n.router_id == rid and n.state == "pending"
                    for n in self.drifts.values()
                ):
                    self._schedule_drift_resolution()
        except Exception as err:  # noqa: BLE001 - the core isolates us too
            self._fail("core event", err)

    def _note_drift(self, event: CoreEvent, kind: str, ts: float | None) -> None:
        rid = valid_router_id(event.router_id)
        data = event.data if isinstance(event.data, Mapping) else {}
        drift_id = data.get("drift_id") or event.dedup_key
        if rid is None or ts is None or not isinstance(drift_id, str) or not drift_id:
            return
        critical = kind == CoreEventType.CHANGE_CRITICAL.value or (
            isinstance(data.get("critical_count"), int) and data["critical_count"] > 0
        )
        key = (rid, drift_id[:128])
        note = self.drifts.get(key)
        if note is None:
            baseline = data.get("baseline_version_id")
            note = DriftNote(
                router_id=rid,
                drift_id=drift_id[:128],
                ts=ts,
                baseline=baseline if isinstance(baseline, str) else None,
                critical=critical,
            )
            self.drifts[key] = note
            self.counters["drifts_seen"] += 1
            self._timeline(
                ts,
                "drift",
                category="config",
                severity=Severity.WARNING if critical else Severity.INFO,
                router_id=rid,
                text=TEXT_DRIFT_SEEN,
                drift_id=note.drift_id,
            )
            self.schedule_save()
        elif critical and not note.critical:
            note.critical = True
        self._schedule_drift_resolution()

    def _schedule_drift_resolution(self) -> None:
        if self._drift_task is not None and not self._drift_task.done():
            self._drift_again = True
            return
        self._drift_again = False
        self._drift_task = self.hass.async_create_task(
            self._async_resolve_drifts(), name="openwrt_router security drift areas"
        )

    async def _async_resolve_drifts(self) -> None:
        """Look up the areas of pending drifts, feed them, evaluate."""
        await asyncio.sleep(0)  # never inside the core's emit
        try:
            while True:
                self._drift_again = False
                fed = await self._async_resolve_pending()
                if fed:
                    self._evaluate_drift(fed)
                if not self._drift_again or not self.active:
                    break
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001 - never fails anything
            self._fail("drift areas", err)

    async def _async_resolve_pending(self) -> list[DriftNote]:
        now = self._core_now if self._core_now is not None else self._now()
        self._drift_tried = now
        fed: list[DriftNote] = []
        for note in list(self.drifts.values()):
            if note.fed or note.state != "pending":
                continue
            areas = None
            if note.baseline is not None:
                try:
                    areas = await self.drift_areas_of(note)
                except Exception as err:  # noqa: BLE001 - areas stay unknown
                    _LOGGER.debug(
                        "Security Center: drift areas not readable (%s)",
                        type(err).__name__,
                    )
                    areas = None
            if areas is not None:
                note.areas = sorted({str(a)[:32] for a in areas})
                note.state = "resolved"
                self.counters["drifts_resolved"] += 1
            elif (
                note.baseline is None
                or now - note.ts > SEC_DRIFT_RESOLVE_WINDOW_SECONDS
            ):
                note.state = "unknown"
                self.counters["drifts_area_unknown"] += 1
            else:
                continue
            fed.append(note)
        return fed

    async def _async_drift_areas(self, note: DriftNote) -> list[str] | None:
        """Areas of a drift from two stored versions (no router contact).

        The comparison runs between the drift's baseline version and the
        first version the store saw after the baseline (the configuration
        manager stores one per new drift id; a dedup hit moves the
        ``last_seen_at`` of an existing one). None while there is none yet,
        or while a change carries no area and no known segmentation area is
        among them (then the areas are not known).
        """
        from .core_models import ConfigRef

        api = self._binding.api
        if api is None:
            return None
        records = list(await api.async_list_backups(note.router_id, limit=20))
        base = next((r for r in records if r.backup_id == note.baseline), None)
        base_ts = _ts(getattr(base, "created_at", None)) if base else None
        if base_ts is None:
            return None
        candidates = []
        for record in records:
            # Times of the version store only (one clock): a version first
            # stored or last seen after the baseline shows the drifted state.
            when = max(
                (
                    t
                    for t in (
                        _ts(getattr(record, "created_at", None)),
                        _ts(getattr(record, "last_seen_at", None)),
                    )
                    if t is not None
                ),
                default=None,
            )
            if (
                when is None
                or when <= base_ts
                or record.backup_id == note.baseline
                or not getattr(record, "usable", True)
            ):
                continue
            candidates.append((when, record.backup_id))
        if not candidates:
            return None
        other = min(candidates)[1]
        diff = await api.async_compare(
            ConfigRef.backup(str(note.baseline)),
            ConfigRef.backup(other),
            actor=Actor.for_module(MODULE_SOURCE),
        )
        changes = getattr(diff, "comparable_changes", None)
        if changes is None:
            changes = getattr(diff, "changes", ())
        areas = {c.area for c in changes if isinstance(c.area, str) and c.area}
        unknown = any(not (isinstance(c.area, str) and c.area) for c in changes)
        relevant = areas & {"vlan", "firewall", "interface"}
        if unknown and not relevant:
            return None
        return sorted(areas)

    def _evaluate_drift(self, notes: list[DriftNote]) -> None:
        """Feed resolved drifts and evaluate the drift detector only."""
        records = []
        for note in notes:
            note.fed = True
            records.append(
                {
                    "router": note.router_id,
                    "ts": note.ts,
                    "recv": note.ts,
                    "kind": DRIFT_KIND,
                    "fields": {
                        "drift_id": note.drift_id,
                        "areas": note.areas if note.state == "resolved" else None,
                        "critical": note.critical,
                    },
                }
            )
        self.detectors.feed_drift(records)
        now = max(
            [n.ts for n in notes]
            + ([self._core_now] if self._core_now is not None else [])
        )
        routers = sorted({n.router_id for n in notes} | set(self._seen))
        statuses = {rid: self._router_statuses(rid, now) for rid in routers}
        results: list[DetectorResult] = []
        for det in self.detectors.detectors:
            if det.input_kind == "drift":
                results.extend(det.evaluate(now, statuses))
        self._keep_results(results)
        self._apply_results(results, now)
        self.schedule_save()

    # -- poll observer ----------------------------------------------------------------------

    def on_poll(self, facts: Any) -> None:
        """One NI poll of one router (read only); never raises."""
        if not self.active or self._closed:
            return
        try:
            self._on_poll(facts)
        except Exception as err:  # noqa: BLE001 - the poll goes on
            self._fail("poll", err)

    def _on_poll(self, facts: Any) -> None:
        rid = self._rid(facts.router)
        if rid is None:
            self.counters["polls_unmapped"] += 1
            return
        now = float(facts.now)
        self.last_now = now
        self.counters["polls"] += 1
        self._stage("sources", self._note_sources, rid, facts, now)
        self._stage("wifi feed", self._feed_wifi, rid, facts)
        self._stage("trust", self._observe_clients, rid, facts, now)
        self._stage("ni incidents", self._read_ni, now)
        self._stage("log senders", self._refresh_senders)
        self._stage("log drain", self._drain_logs)
        self._stage("syslog retry", self._maybe_retry_syslog)
        self._stage("evaluate", self._evaluate, now)
        self._stage("housekeeping", self._housekeeping, now)
        self._stage("publish", self._publish, now)
        if any(n.state == "pending" for n in self.drifts.values()) and (
            self._drift_tried is None
            or now - self._drift_tried >= SEC_DRIFT_RETRY_SECONDS
            or now < self._drift_tried
        ):
            self._drift_tried = now
            self._core_now = max(self._core_now or now, now)
            self._stage("drift retry", self._schedule_drift_resolution)
        self.schedule_save()

    def _stage(self, name: str, func: Callable[..., Any], *args: Any) -> None:
        try:
            func(*args)
        except Exception as err:  # noqa: BLE001 - one stage, not the poll
            self._fail(name, err)

    def _note_sources(self, rid: str, facts: Any, now: float) -> None:
        seen = self._seen.setdefault(rid, {})
        seen[DataSource.NI_INCIDENTS] = now
        if facts.log_ok:
            seen[DataSource.WIFI_EVENTS] = now
        if facts.fresh_clients:
            seen[DataSource.HOSTAPD_CLIENTS] = now
            if self._client_stability() is not None:
                seen[DataSource.CLIENT_HISTORY] = now
        coordinator = self._entries.get(facts.router)
        data = getattr(coordinator, "data", None)
        uptime = _num(getattr(data, "uptime", None))
        if uptime is not None and uptime > 0:
            seen[DataSource.ROUTER_UPTIME] = now
            self.detectors.note_uptime(rid, uptime)

    def _feed_wifi(self, rid: str, facts: Any) -> None:
        excluded = {normalize_mac(m) for m in facts.exclude}
        items = [*facts.wifi_lines]
        for event in facts.stored_events:
            origin = getattr(event.origin, "value", event.origin)
            source = getattr(event.source, "value", event.source)
            if origin == "observed" and source == "log":
                continue  # the same line is in wifi_lines already
            items.append(event)

        def wanted(item: Any) -> bool:
            mac = getattr(item, "mac", None)
            if mac is None:
                subject = getattr(item, "subject", None)
                mac = subject.get("mac") if isinstance(subject, Mapping) else None
            return mac is None or normalize_mac(mac) not in excluded

        self.detectors.feed_wifi([i for i in items if wanted(i)], router_id=rid)
        # Fleet sensor: failed Wi-Fi authentications of the fresh lines only
        # (each line is in exactly one poll; stored events would repeat).
        now = float(facts.now)
        failures = sum(
            1
            for line in facts.wifi_lines
            if f"{getattr(line, 'category', '')}.{getattr(line, 'kind', '')}"
            in AUTH_FAIL_KINDS
            and wanted(line)
        )
        self._auth_failures.add(now, now, failures)

    def _client_stability(self) -> Any:
        from .client_engine import async_get_client_engine

        cs = async_get_client_engine(self.hass)
        if cs is None or not cs.settings.get("enabled", False):
            return None
        return cs

    def _observe_clients(self, rid: str, facts: Any, now: float) -> None:
        clients = facts.context.clients
        if not clients:
            return
        excluded = {normalize_mac(m) for m in facts.exclude}
        cs = self._client_stability()
        notices: list[TrustNotice] = []
        for mac, row in clients.items():
            if normalize_mac(mac) in excluded:
                continue
            obs = cs.history.live(mac) if cs is not None else None
            if obs is None:
                row = row if isinstance(row, Mapping) else {}
                obs = SimpleNamespace(
                    mac=mac,
                    private_mac=None,
                    first_seen=None,
                    last_seen=now,
                    ip=row.get("ip") if isinstance(row.get("ip"), str) else None,
                    hostname=row.get("hostname")
                    if isinstance(row.get("hostname"), str)
                    else None,
                )
            notices.extend(self.trust.observe(obs, now))
        self._apply_notices(notices, rid, now)

    def _read_ni(self, now: float) -> None:
        """Open NI incidents of the reused types, as references (read only)."""
        self._ni_refs = []
        self._ni_open = {}
        engine = self._engine
        if engine is None:
            return
        for inc in engine.machine.peek():
            status = getattr(inc.status, "value", inc.status)
            if inc.type not in REUSED_NI_TYPES or status not in _NI_OPEN:
                continue
            routers = tuple(
                r for r in (self._rid(str(x)) for x in inc.routers) if r is not None
            )
            scope = getattr(inc.scope, "value", inc.scope)
            mac = normalize_mac(inc.scope_key) if scope == "client" else None
            self._ni_open[inc.id] = (
                inc.type,
                getattr(inc.severity, "value", inc.severity),
            )
            self._ni_refs.append(
                IncidentRef(
                    incident_id=inc.id,
                    start=float(inc.first_seen or inc.last_seen or now),
                    end=None,
                    router_ids=routers,
                    clients=(mac,) if mac else (),
                )
            )

    # -- statuses ---------------------------------------------------------------------------

    def _router_statuses(self, rid: str, now: float) -> dict[str, SourceStatus]:
        seen = self._seen.get(rid, {})
        out: dict[str, SourceStatus] = {}
        for source in (
            DataSource.WIFI_EVENTS,
            DataSource.NI_INCIDENTS,
            DataSource.ROUTER_UPTIME,
        ):
            out[source] = source_status(
                source,
                now=now,
                last_ok=seen.get(source),
                enabled=self._engine is not None,
            )
        cs_on = self._client_stability() is not None
        out[DataSource.CLIENT_HISTORY] = source_status(
            DataSource.CLIENT_HISTORY,
            now=now,
            last_ok=seen.get(DataSource.CLIENT_HISTORY),
            enabled=cs_on,
        )
        out[DataSource.HOSTAPD_CLIENTS] = self._hostapd_status(rid, now, seen)
        out[DataSource.CONFIG_DRIFT] = self._drift_status(rid, now)
        for source in (DataSource.FIREWALL_LOG, DataSource.DNS_QUERY_LOG):
            out[source] = self._path_status(source, now, rid)
        self._statuses[rid] = out
        return out

    def _hostapd_status(
        self, rid: str, now: float, seen: Mapping[str, float]
    ) -> SourceStatus:
        last_ok = seen.get(DataSource.HOSTAPD_CLIENTS)
        api = self._binding.api
        if api is not None:
            try:
                caps = api.registry.capabilities(rid)
                cap = caps.get(DataSource.HOSTAPD_CLIENTS)
                if cap is not None:
                    return status_from_capability(cap, now=now, last_ok=last_ok)
            except Exception:  # noqa: BLE001 - unknown router: by deliveries
                _LOGGER.debug("Security Center: capabilities not readable")
        return source_status(DataSource.HOSTAPD_CLIENTS, now=now, last_ok=last_ok)

    def _drift_status(self, rid: str, now: float) -> SourceStatus:
        api = self._binding.api
        if api is None:
            return SourceStatus(
                source=DataSource.CONFIG_DRIFT,
                availability=Availability.NOT_AVAILABLE,
                reason=REASON_NO_CORE,
            )
        try:
            cap = api.capability(rid, Capability.CONFIG_DRIFT)
        except Exception:  # noqa: BLE001 - unknown router
            return SourceStatus(
                source=DataSource.CONFIG_DRIFT,
                availability=Availability.NOT_AVAILABLE,
                reason="not_reported",
            )
        status = status_from_capability(cap, now=now, last_ok=now)
        if not status.usable:
            return status
        from .config_manager import async_get_runtime

        runtime = async_get_runtime(self.hass)
        try:
            checking = runtime is not None and runtime.drift_check_enabled(rid)
        except Exception:  # noqa: BLE001 - unknown router in the runtime
            checking = False
        return source_status(
            DataSource.CONFIG_DRIFT, now=now, last_ok=now, enabled=checking
        )

    def _path_status(
        self, source: str, now: float, rid: str | None = None
    ) -> SourceStatus:
        """Status of a log-path source of one router (``rid``) or the fleet.

        Syslog: not available while the receiver does not listen (with its
        reason) or the router is not on the allowlist; otherwise by the
        receive time of the newest record of that source (never "fine" by
        silence: ``no_data_yet`` until one arrived, ``stale`` later).
        """
        path = self.settings.get("log_path", LogPath.OFF.value)
        if path == LogPath.COLLECTOR.value:
            return self._not_available(source, REASON_COLLECTOR)
        if path != LogPath.SYSLOG.value:
            return self.log_source.status(source, now=now)
        receiver = self.syslog
        if receiver is None and not self.active:
            return self.log_source.status(source, now=now)  # off: "disabled"
        if receiver is None or not receiver.listening:
            reason = receiver.reason if receiver is not None else None
            return self._not_available(source, reason or REASON_NOT_STARTED)
        if rid is not None:
            if rid not in receiver.router_ids:
                return self._not_available(source, REASON_SENDER_UNKNOWN)
            return self.liveness.status(rid, source, now=now)
        times = [
            t
            for r in receiver.router_ids
            if (t := self.liveness.last_ok(r, source)) is not None
        ]
        return source_status(
            source,
            now=now,
            last_ok=max(times) if times else None,
            stale_after_s=self.liveness.stale_after_s,
        )

    @staticmethod
    def _not_available(source: str, reason: str) -> SourceStatus:
        return SourceStatus(
            source=source, availability=Availability.NOT_AVAILABLE, reason=reason
        )

    def _current_routers(self) -> set[str]:
        """Router ids of the loaded entries (the fleet the score is about)."""
        return {rid for rid in (self._rid(e) for e in list(self._entries)) if rid}

    def _all_statuses(self, now: float) -> dict[str, dict[str, SourceStatus]]:
        # Only routers of loaded entries count (review 2, H1): an unloaded or
        # removed router must not keep the coverage low or the score capped.
        routers = self._current_routers()
        for rid in [r for r in self._statuses if r not in routers]:
            del self._statuses[rid]
        return {rid: self._router_statuses(rid, now) for rid in sorted(routers)}

    @staticmethod
    def _flat(statuses: Mapping[str, Mapping[str, SourceStatus]]) -> dict[str, Any]:
        """Worst status of every source over all routers (for the score)."""
        rank = {
            Availability.AVAILABLE: 0,
            Availability.STALE: 1,
            Availability.NOT_AVAILABLE: 2,
        }
        out: dict[str, SourceStatus] = {}
        for per_router in statuses.values():
            for source, status in per_router.items():
                old = out.get(source)
                if old is None or rank[status.availability] > rank[old.availability]:
                    out[source] = status
        return out

    # -- evaluation -------------------------------------------------------------------------

    def _evaluate(self, now: float) -> None:
        statuses = self._all_statuses(now)
        results = self.detectors.evaluate(now, statuses)
        self._keep_results(results)
        self._apply_results(results, now)

    def _keep_results(self, results: Iterable[DetectorResult]) -> None:
        for result in results:
            self._results[(result.detector_id, result.router_id or "-")] = result

    def _apply_results(self, results: Iterable[DetectorResult], now: float) -> None:
        events = results_events(results)
        self.counters["findings"] += len(events)
        extra: list[SecurityEvent] = []
        for event in events:
            indicator = INDICATOR_OF.get(event.name)
            if indicator is not None and event.client:
                notices = self.trust.add_indicator(event.client, indicator, now)
                extra.extend(self._apply_notices(notices, event.router_id, now))
        groups = correlate([*events, *extra], incidents=self._ni_refs)
        for group in groups:
            for event in group.events:
                self._record(event, now)

    def _apply_notices(
        self, notices: Iterable[TrustNotice], rid: str | None, now: float
    ) -> list[SecurityEvent]:
        """Timeline entries; a suspicious device becomes an event to record."""
        out: list[SecurityEvent] = []
        for notice in notices:
            self.counters["notices"] += 1
            self._timeline(
                notice.at,
                "notice",
                category="device",
                severity=notice.severity,
                router_id=rid,
                client=notice.mac,
                text=NOTICE_TEXTS.get(notice.kind, notice.kind.value),
                type_=f"trust_{notice.kind.value}",
            )
            if notice.kind is NoticeKind.SUSPICIOUS and notice.mac:
                out.append(notice.to_event(router_id=None))
        return out

    # -- incidents --------------------------------------------------------------------------

    @property
    def _id_key(self) -> bytes:
        return self._module_key if self._module_key is not None else self._run_key

    def _record(self, event: SecurityEvent, now: float) -> None:
        event = sealed_event(event, self._id_key)
        counterpart = NI_COUNTERPART.get(event.name)
        if counterpart is not None:
            reused = [
                link
                for link in event.linked_incident_ids
                if self._ni_open.get(link, ("", None))[0] == counterpart
            ]
            if reused:
                self.counters["incidents_reused"] += 1
                self._timeline(
                    event.ts,
                    "reused",
                    category=event.category.value,
                    severity=event.severity,
                    router_id=event.router_id,
                    client=event.client,
                    text=TEXT_REUSED,
                    type_=event.name,
                    linked=reused,
                )
                return
        scope = "|".join(event.dedup_scope)
        inc_id = self._by_scope.get(scope)
        inc = self.incidents.get(inc_id) if inc_id else None
        if inc is not None and inc["status"] in _ACTIVE_STATUSES:
            self._merge(inc, event)
            self.counters["incidents_merged"] += 1
            return
        if inc is not None:
            self._merge(inc, event)
            inc["status"] = STATUS_OPEN
            inc["resolved_at"] = None
            self.counters["incidents_reopened"] += 1
            self._timeline(
                event.ts,
                "incident_reopened",
                category=inc["category"],
                severity=event.severity,
                router_id=event.router_id,
                client=event.client,
                text=inc["title"],
                incident_id=inc["id"],
            )
            self._emit_event(event, inc["id"], limited=True)
            return
        if not self._make_room():
            self._cap_reached(now)
            return
        inc = self._new_incident(event, scope)
        self.counters["incidents_opened"] += 1
        self._timeline(
            event.ts,
            "incident_opened",
            category=inc["category"],
            severity=event.severity,
            router_id=event.router_id,
            client=event.client,
            text=inc["title"],
            incident_id=inc["id"],
            linked=list(inc["linked_incident_ids"]),
        )
        self._emit_event(event, inc["id"], limited=True)

    def _new_incident(self, event: SecurityEvent, scope: str) -> dict[str, Any]:
        inc_id = INCIDENT_PREFIX + keyed_id(self._id_key, "incident", scope, 8)
        name = event.name
        drift_refs: list[str] = []
        hints: list[str] = []
        if name == "vlan_segmentation_drift":
            drift_id = _evidence_value(event, "drift_id")
            if drift_id:
                drift_refs.append(drift_id)
            areas = (_evidence_value(event, "areas") or "").replace("+", ", ")
            hints.append(HINT_DRIFT.format(areas=areas or "unbekannt"))
        else:
            hints.append(HINT_DEFAULT)
            if event.router_id is not None:
                before = self._drifts_before(event.router_id, event.ts)
                if before:
                    drift_refs.extend(before)
                    hints.append(HINT_DRIFT_BEFORE)
        inc: dict[str, Any] = {
            "id": inc_id,
            "type": event.incident_type,
            "detector": name,
            "event_id": event.event_id,
            "scope": scope,
            "category": event.category.value,
            "severity": event.severity.value,
            "assessment": event.assessment.value,
            "status": STATUS_OPEN,
            "router_id": event.router_id,
            "client_ref": self._client_ref(event.client),
            "has_client": event.client is not None,
            "first_seen": event.ts,
            "last_seen": event.last_ts or event.ts,
            "count": event.count,
            "evidence": mask_identities(list(event.evidence)),
            "linked_incident_ids": list(event.linked_incident_ids),
            "drift_refs": drift_refs,
            "correlation_id": event.correlation_id,
            "title": TITLES.get(name, name),
            "hint": " ".join(hints),
            "resolved_at": None,
        }
        self.incidents[inc_id] = inc
        self._by_scope[scope] = inc_id
        return inc

    def _drifts_before(self, rid: str, ts: float) -> list[str]:
        """Example E: drifts of the router shortly before ``ts`` (link only)."""
        return sorted(
            n.drift_id
            for n in self.drifts.values()
            if n.router_id == rid and 0 <= ts - n.ts <= SEC_DRIFT_HINT_WINDOW_SECONDS
        )

    @staticmethod
    def _merge(inc: dict[str, Any], event: SecurityEvent) -> None:
        inc["last_seen"] = max(inc["last_seen"], event.last_ts or event.ts)
        inc["count"] = int(inc.get("count", 1)) + event.count
        if event.severity.rank > _severity(inc["severity"]).rank:
            inc["severity"] = event.severity.value
        try:
            rank = Assessment(inc["assessment"]).rank
        except ValueError:
            rank = -1
        if event.assessment.rank > rank:
            inc["assessment"] = event.assessment.value
        links = list(inc.get("linked_incident_ids", []))
        for link in event.linked_incident_ids:
            if link not in links:
                links.append(link)
        inc["linked_incident_ids"] = links[:16]

    def _make_room(self) -> bool:
        """Room for one new hint: evict resolved ones, oldest first.

        False if the store is full of open and confirmed hints: those are
        never evicted for a new one (review 2, M3).
        """
        while len(self.incidents) >= SEC_INCIDENT_CAP:
            resolved = [
                i for i in self.incidents.values() if i["status"] == STATUS_RESOLVED
            ]
            if not resolved:
                return False
            victim = min(resolved, key=lambda i: i["last_seen"])
            self._drop_incident(victim["id"])
            self.counters["incidents_dropped"] += 1
        return True

    def _cap_reached(self, now: float) -> None:
        """A new hint found no room: count it, note it once per window."""
        self.counters["incidents_cap_dropped"] += 1
        last = self._cap_noted
        if last is not None and abs(now - last) < SEC_CAP_NOTE_WINDOW_SECONDS:
            return
        self._cap_noted = now
        self._timeline(
            now,
            "cap_reached",
            category="system",
            severity=Severity.WARNING,
            router_id=None,
            text=TEXT_CAP_REACHED,
        )
        self.schedule_save()

    def _enforce_cap(self) -> None:
        """A loaded store above ``SEC_INCIDENT_CAP`` (cap lowered, edited file).

        Resolved go first, then open, confirmed last (an administrator's
        confirmation is kept longest); oldest first within each.
        """
        order = {STATUS_RESOLVED: 0, STATUS_OPEN: 1, STATUS_CONFIRMED: 2}
        while len(self.incidents) > SEC_INCIDENT_CAP:
            victim = min(
                self.incidents.values(),
                key=lambda i: (order.get(i["status"], 0), i["last_seen"]),
            )
            self._drop_incident(victim["id"])
            self.counters["incidents_dropped"] += 1

    def _drop_incident(self, inc_id: str) -> None:
        inc = self.incidents.pop(inc_id, None)
        if inc is not None and self._by_scope.get(inc["scope"]) == inc_id:
            del self._by_scope[inc["scope"]]

    def _housekeeping(self, now: float) -> None:
        for inc in self.incidents.values():
            if (
                inc["status"] == STATUS_OPEN
                and now - inc["last_seen"] > SEC_INCIDENT_AUTO_RESOLVE_SECONDS
            ):
                inc["status"] = STATUS_RESOLVED
                inc["resolved_at"] = now
                self.counters["incidents_resolved"] += 1
                self._timeline(
                    now,
                    "incident_resolved",
                    category=inc["category"],
                    severity=Severity.INFO,
                    router_id=inc["router_id"],
                    text=inc["title"],
                    incident_id=inc["id"],
                    client_ref=inc.get("client_ref"),
                )
        cut = now - SEC_TIMELINE_DAYS * _DAY
        self.timeline = [t for t in self.timeline if t["ts"] >= cut][-SEC_TIMELINE_MAX:]
        for key in [k for k, n in self.drifts.items() if now - n.ts > 2 * _DAY]:
            del self.drifts[key]

    # -- timeline ---------------------------------------------------------------------------

    def _client_ref(self, mac: str | None) -> str | None:
        if mac is None or self._module_key is None:
            return None
        return client_ref(mac, self._module_key)

    def _timeline(
        self,
        ts: float,
        kind: str,
        *,
        category: str,
        severity: Severity | str,
        router_id: str | None,
        text: str,
        client: str | None = None,
        client_ref: str | None = None,
        incident_id: str | None = None,
        type_: str | None = None,
        drift_id: str | None = None,
        linked: Iterable[str] = (),
    ) -> None:
        entry = {
            "ts": ts,
            "kind": kind,
            "category": category,
            "severity": _severity(severity).value,
            "router_id": router_id,
            "client_ref": client_ref or self._client_ref(client),
            "has_client": client is not None or client_ref is not None,
            "incident_id": incident_id,
            "type": type_,
            "drift_id": drift_id,
            "linked": list(linked)[:16],
            "text": text,
        }
        self.timeline.append(entry)
        if len(self.timeline) > SEC_TIMELINE_MAX:
            del self.timeline[: len(self.timeline) - SEC_TIMELINE_MAX]

    # -- events ---------------------------------------------------------------------------

    def _emit_budget(self) -> bool:
        """True while fewer than SEC_EVENT_BURST hint events left in the window."""
        clock = time.monotonic()
        times = self._emit_times
        while times and clock - times[0] >= SEC_EVENT_BURST_WINDOW_SECONDS:
            times.popleft()
        if len(times) >= SEC_EVENT_BURST:
            return False
        times.append(clock)
        return True

    def _emit_event(
        self, event: SecurityEvent, incident_id: str | None, *, limited: bool = False
    ) -> None:
        """One security event on the core bus (security ring), never raises.

        ``limited``: an event of a new or reopened hint (rate limited, the
        rest counted as ``events_throttled``); manual actions are not.
        """
        binding = self._binding
        if not self.active or binding.api is None or not binding.events_ok:
            return
        if limited and not self._emit_budget():
            self.counters["events_throttled"] += 1
            return
        try:
            core = event.to_core_event(module_key=self._module_key)
            binding.api.emit(
                core.type,
                source=MODULE_SOURCE,
                router_id=core.router_id,
                entry_id=core.entry_id,
                severity=core.severity,
                result=core.result,
                actor=core.actor,
                correlation_id=core.correlation_id,
                dedup_key=core.dedup_key,
                data=core.data,
                security_relevant=True,
                client_ref=core.client_ref,
                confidence=core.confidence,
                classification=core.classification,
                incident_ref=incident_id or core.incident_ref,
            )
            self.counters["events_emitted"] += 1
        except Exception as err:  # noqa: BLE001 - counted, never fatal
            self.counters["events_failed"] += 1
            _LOGGER.debug("Security Center event not emitted (%s)", type(err).__name__)

    def _emit_plain(
        self,
        name: str,
        *,
        router_id: str | None,
        actor: Actor | None,
        data: Mapping[str, Any],
        incident_id: str | None = None,
    ) -> None:
        binding = self._binding
        if binding.api is None or not binding.events_ok:
            return
        try:
            binding.api.emit(
                name,
                source=MODULE_SOURCE,
                router_id=router_id,
                severity=Severity.INFO,
                result=EventResult.SUCCESS,
                actor=event_actor(actor),
                data=dict(data),
                security_relevant=True,
                incident_ref=incident_id,
            )
            self.counters["events_emitted"] += 1
        except Exception as err:  # noqa: BLE001 - counted, never fatal
            self.counters["events_failed"] += 1
            _LOGGER.debug("Security Center event not emitted (%s)", type(err).__name__)

    # -- forgetting, clock --------------------------------------------------------------

    def _forget_router(self, rid: str) -> None:
        """Core ``router.forgotten``: drop every piece of that router's state."""
        holders: list[Any] = [self.detectors, self.deduper, self.liveness]
        if self.syslog is not None:
            holders.append(self.syslog)
        forget_router(rid, tuple(holders))
        for key in [k for k in self.drifts if k[0] == rid]:
            del self.drifts[key]
        for inc_id in [
            i for i, inc in self.incidents.items() if inc["router_id"] == rid
        ]:
            self._drop_incident(inc_id)
        self.timeline = [t for t in self.timeline if t.get("router_id") != rid]
        self._seen.pop(rid, None)
        self._statuses.pop(rid, None)
        for key in [k for k in self._results if k[1] == rid]:
            del self._results[key]
        for entry_id in [e for e, r in self._rid_cache.items() if r == rid]:
            del self._rid_cache[entry_id]
        self.counters["routers_forgotten"] += 1
        self.schedule_save()

    def on_clock_shift(self, delta: float) -> None:
        """The NI clock jumped back: move stored times, restart the windows."""
        if not self.active or self._closed:
            return
        try:
            for inc in self.incidents.values():
                for key in ("first_seen", "last_seen", "resolved_at"):
                    if _num(inc.get(key)) is not None:
                        inc[key] = inc[key] + delta
            for entry in self.timeline:
                entry["ts"] = entry["ts"] + delta
            for note in self.drifts.values():
                note.ts += delta
            for rid in list(self._seen):
                self.detectors.reset_router(rid)
            self._seen.clear()
            self.last_now = None
            self.schedule_save()
        except Exception as err:  # noqa: BLE001 - never fatal
            self._fail("clock shift", err)

    def on_router_removed(self, router: str) -> None:
        """NI removes an entry's data: drop the memory of its sources."""
        try:
            rid = self._rid_cache.get(router)
            if rid is not None:
                self._drop_router_memory(rid)
        except Exception as err:  # noqa: BLE001 - never fatal
            self._fail("router removed", err)

    # -- settings ---------------------------------------------------------------------------

    def _rebuild_detectors(self) -> None:
        """New detector set from the settings; the baseline book stays."""
        dest = self.settings.get("subnet_zones") or None
        detectors = default_detectors(
            keep_names=self.settings.get("keep_dns_names") is True,
            dest_subnets=dest,
            baseline=self.baseline,
        )
        for det in detectors.detectors:
            value = self.settings.get("thresholds", {}).get(det.id)
            if value is not None:
                det.threshold = (
                    max(2, value) if det.id == "wifi_multi_ap_auth" else value
                )
        self.detectors = detectors
        self._results.clear()

    # -- manual actions -----------------------------------------------------------------

    def _require_api(self) -> Any:
        api = self._binding.api
        if api is None:
            raise SecurityCenterError(
                REASON_NO_CORE, "The enterprise core is not running"
            )
        return api

    async def _async_api(self) -> Any:
        if self._binding.api is None:
            try:
                await self._async_bind_core()
            except Exception as err:  # noqa: BLE001 - refused below
                self._fail("core binding", err)
        return self._require_api()

    async def _async_authorize(
        self, action: str, router_id: str, actor: Any
    ) -> VerifiedActor:
        """Guard check (admin users only, audited) and one-time use."""
        api = await self._async_api()
        if not self._binding.actions_ok:
            for name in _ACTIONS:
                api.guard.register_action(
                    name,
                    ActionClass.MUTATING,
                    module=MODULE_SOURCE,
                    admin_user_only=True,
                )
            self._binding.actions_ok = True
        if isinstance(actor, VerifiedActor):
            verified = actor
        elif isinstance(actor, Actor):
            verified = await api.guard.async_verify_actor(actor)
        else:
            raise SecurityCenterError("actor_required", "An actor is required")
        decision = api.guard.authorize(action, router_id, verified)
        if not decision.approved:
            self.counters["actions_denied"] += 1
            raise SecurityCenterError(str(decision.reason or "denied"))
        api.guard.consume(decision.authorization, action=action, router_id=router_id)
        self.counters["actions"] += 1
        return verified

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise SecurityCenterError("disabled", "The Security Center is off")

    async def async_confirm_device(
        self,
        mac: str,
        *,
        actor: Any,
        name: str | None = None,
        now: float | None = None,
    ) -> None:
        """Mark a device as known (trust book), audited; no quarantine."""
        self._require_enabled()
        key = normalize_mac(mac)
        if key is None:
            raise SecurityCenterError("invalid_mac")
        verified = await self._async_authorize(
            ACTION_CONFIRM_DEVICE, FLEET_ROUTER_ID, actor
        )
        when = self._now() if now is None else now
        action = self.trust.confirm(key, when, name=name, actor=verified.actor)
        if action is None:
            raise SecurityCenterError("refused")
        self._action_done(action.to_event(router_id=None), "confirmed", when)

    async def async_set_device_name(
        self, mac: str, name: str | None, *, actor: Any, now: float | None = None
    ) -> None:
        """Give a tracked device a display name (None clears it), audited."""
        self._require_enabled()
        key = normalize_mac(mac)
        if key is None:
            raise SecurityCenterError("invalid_mac")
        if self.trust.get(key) is None:
            raise SecurityCenterError("unknown_device")
        verified = await self._async_authorize(
            ACTION_SET_DEVICE_NAME, FLEET_ROUTER_ID, actor
        )
        when = self._now() if now is None else now
        action = self.trust.set_name(key, name, actor=verified.actor, now=when)
        if action is None:
            raise SecurityCenterError("unknown_device")
        self._action_done(action.to_event(router_id=None), "renamed", when)

    def _action_done(self, event: SecurityEvent, what: str, when: float) -> None:
        event = sealed_event(event, self._id_key)
        self._timeline(
            when,
            "action",
            category="device",
            severity=Severity.INFO,
            router_id=None,
            client=event.client,
            text=f"Gerät {'bestätigt' if what == 'confirmed' else 'benannt'}",
            type_=event.name,
        )
        self._emit_event(event, None)
        self.schedule_save()
        self._stage("publish", self._publish, when)

    async def async_set_incident_status(
        self, incident_id: str, status: str, *, actor: Any, now: float | None = None
    ) -> dict[str, Any]:
        """Set open / resolved / confirmed of an own incident, audited."""
        self._require_enabled()
        if status not in INCIDENT_STATUSES:
            raise SecurityCenterError("invalid_status")
        inc = self.incidents.get(incident_id)
        if inc is None:
            raise SecurityCenterError("unknown_incident")
        router = inc.get("router_id") or FLEET_ROUTER_ID
        verified = await self._async_authorize(
            ACTION_SET_INCIDENT_STATUS, router, actor
        )
        when = self._now() if now is None else now
        previous = inc["status"]
        inc["status"] = status
        inc["resolved_at"] = when if status == STATUS_RESOLVED else None
        if status != STATUS_RESOLVED:
            inc["last_seen"] = max(inc["last_seen"], when)
        self._timeline(
            when,
            "status",
            category=inc["category"],
            severity=Severity.INFO,
            router_id=inc.get("router_id"),
            client_ref=inc.get("client_ref"),
            text=f"Status: {status}",
            incident_id=incident_id,
        )
        self._emit_plain(
            EVENT_INCIDENT_STATUS,
            router_id=inc.get("router_id"),
            actor=verified.actor,
            data={"incident_id": incident_id, "status": status, "previous": previous},
            incident_id=incident_id,
        )
        self.schedule_save()
        self._stage("publish", self._publish, when)
        return self._incident_view(inc, admin=True, macs=None)

    async def async_update_settings(
        self, update: Mapping[str, Any], *, actor: Any
    ) -> dict[str, Any]:
        """Change settings (admin, audited); turning on activates the center."""
        try:
            new = merge_settings(self.settings, update)
        except vol.Invalid as err:
            raise SecurityCenterError("invalid_settings", str(err)) from None
        try:
            verified = await self._async_authorize(
                ACTION_UPDATE_SETTINGS, FLEET_ROUTER_ID, actor
            )
        except Exception:
            if not self.active:
                self._unbind_core()  # a refused change leaves nothing bound
            raise
        old = self.settings
        self.settings = new
        changed = sorted(k for k in new if new[k] != old.get(k))
        if any(k in changed for k in ("thresholds", "subnet_zones", "keep_dns_names")):
            self._rebuild_detectors()
        if new["enabled"] and not self.active:
            await self.async_activate()
        if new["enabled"] or old.get("enabled"):
            self._emit_plain(
                EVENT_SETTINGS,
                router_id=None,
                actor=verified.actor,
                data={
                    "enabled": new["enabled"],
                    "log_path": new["log_path"],
                    "changed": changed,
                },
            )
        if not new["enabled"]:
            # off again (or still off): no listener, no observer stays bound
            self.deactivate()
        else:
            # log path or port changed: (re)bind or close the receiver
            await self.async_sync_log_source()
            self._stage("publish", self._publish, self._now())
        self._schedule_save_now()
        self._sync_entities()
        return dict(self.settings)

    # -- overview -----------------------------------------------------------------------

    def _macs_by_ref(self) -> dict[str, str]:
        key = self._module_key
        if key is None:
            return {}
        out: dict[str, str] = {}
        for row in self.trust.to_dict()["records"]:
            ref = client_ref(row["mac"], key)
            if ref is not None:
                out[ref] = row["mac"]
        return out

    def _device_view(self, row: Mapping[str, Any], *, admin: bool, now: float) -> dict:
        state = self.trust.state(row["mac"], now).value
        indicators = sorted(
            {k for k, ts in row.get("indicators", []) if now - ts <= _DAY}
        )
        view = {
            "mac": row["mac"],
            "ip": row.get("ip"),
            "hostname": row.get("hostname"),
            "name": row.get("name"),
            "state": state,
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "private_mac": row.get("private_mac") is True,
            "confirmed": row.get("confirmed_at") is not None,
            "observed": row.get("observed") is not False,
            "indicators": indicators,
        }
        if admin:
            return view
        view["name_set"] = view["name"] is not None
        view["name"] = None
        if self._module_key is not None:
            return pseudonymise_fields(
                view,
                self._module_key,
                {"mac": "client", "ip": "ip", "hostname": "hostname"},
            )
        for name in ("mac", "ip", "hostname"):
            if view[name] is not None:
                view[name] = MASK
        return view

    def _incident_view(
        self, inc: Mapping[str, Any], *, admin: bool, macs: Mapping[str, str] | None
    ) -> dict[str, Any]:
        view = {k: v for k, v in inc.items() if k != "scope"}
        view["linked_incident_ids"] = list(inc.get("linked_incident_ids", []))
        view["drift_refs"] = list(inc.get("drift_refs", []))
        view["evidence"] = list(inc.get("evidence", []))
        if admin and macs is not None:
            mac = macs.get(inc.get("client_ref") or "")
            view["client"] = mac
            record = self.trust.get(mac) if mac else None
            view["client_name"] = record.name if record else None
        elif inc.get("has_client") and not inc.get("client_ref"):
            view["client_ref"] = MASK
        return view

    def overview(
        self,
        *,
        actor: Any = None,
        since: float | None = None,
        until: float | None = None,
        router_id: str | None = None,
        client: str | None = None,
        category: str | None = None,
        severity: str | None = None,
        limit: int = 200,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Masked overview; plain device data only for a verified admin user."""
        admin = _is_admin(actor)
        when = self._now() if now is None else now
        statuses = self._all_statuses(when)
        flat = self._flat(statuses)
        macs = self._macs_by_ref() if admin else None
        ref = self._client_filter(client, admin)
        min_rank = _severity(severity).rank if severity else None

        def keep(item: Mapping[str, Any], ts_key: str) -> bool:
            ts = _num(item.get(ts_key))
            if since is not None and (ts is None or ts < since):
                return False
            if until is not None and (ts is None or ts > until):
                return False
            if router_id is not None and item.get("router_id") != router_id:
                return False
            if client is not None and (ref is None or item.get("client_ref") != ref):
                return False
            if category is not None and item.get("category") != category:
                return False
            return min_rank is None or _severity(item.get("severity")).rank >= min_rank

        incidents = [
            self._incident_view(i, admin=admin, macs=macs)
            for i in sorted(
                self.incidents.values(), key=lambda i: i["last_seen"], reverse=True
            )
            if keep(i, "last_seen")
        ][: max(0, limit)]
        timeline = [
            self._timeline_view(t, admin=admin, macs=macs)
            for t in reversed(self.timeline)
            if keep(t, "ts")
        ][: max(0, limit)]
        devices = [
            self._device_view(row, admin=admin, now=when)
            for row in self.trust.to_dict()["records"]
        ]
        score = self._score(when, statuses, flat)
        return {
            "enabled": self.enabled,
            "active": self.active,
            "admin_view": admin,
            "score": score,
            "coverage": {
                "value": score["coverage"],
                "available": sorted(
                    s
                    for s, st in flat.items()
                    if st.availability is Availability.AVAILABLE
                ),
                "stale": sorted(
                    s for s, st in flat.items() if st.availability is Availability.STALE
                ),
                "missing": sorted(
                    s
                    for s, st in flat.items()
                    if st.availability is Availability.NOT_AVAILABLE
                ),
            },
            "incidents": incidents,
            "timeline": timeline,
            "devices": devices,
            "device_counts": self.trust.counts(when),
            "detections": self._detections(),
            "log_path": self._log_path_view(when),
            "subnet_map": (
                {"state": "configured", "subnets": len(self.settings["subnet_zones"])}
                if self.settings.get("subnet_zones")
                else {"state": "omitted", "subnets": 0}
            ),
            "module_key": self._module_key is not None,
            "limits": {
                "incident_cap": SEC_INCIDENT_CAP,
                "incidents_cap_dropped": self.counters["incidents_cap_dropped"],
                "events_throttled": self.counters["events_throttled"],
            },
        }

    def _client_filter(self, client: str | None, admin: bool) -> str | None:
        if client is None:
            return None
        if client.startswith("cli_"):
            return client
        if not admin or self._module_key is None:
            return None  # a non-admin filters by pseudonym only
        return client_ref(client, self._module_key)

    def _timeline_view(
        self, entry: Mapping[str, Any], *, admin: bool, macs: Mapping[str, str] | None
    ) -> dict[str, Any]:
        view = dict(entry)
        view["linked"] = list(entry.get("linked", []))
        if admin and macs is not None:
            view["client"] = macs.get(entry.get("client_ref") or "")
        elif entry.get("has_client") and not entry.get("client_ref"):
            view["client_ref"] = MASK
        return view

    def _detections(self) -> list[dict[str, Any]]:
        out = []
        for det in self.detectors.detectors:
            results = [r for (d, _r), r in self._results.items() if d == det.id]
            available = [r for r in results if r.available]
            limitations = sorted({x for r in available for x in r.limitations})
            missing = sorted({m for r in results if not r.available for m in r.missing})
            reasons = sorted(
                {
                    st.reason
                    for per in self._statuses.values()
                    for s, st in per.items()
                    if s in det.sources and not st.usable
                }
            )
            if not results:
                availability, reason, missing = self._unevaluated(det)
            elif available and (limitations or len(available) < len(results)):
                availability, reason = (
                    DETECTION_LIMITED,
                    ",".join(limitations or reasons),
                )
            elif available:
                availability, reason = DETECTION_AVAILABLE, ""
            else:
                availability, reason = DETECTION_NOT_AVAILABLE, ",".join(reasons)
            if det.id.startswith("fw_"):
                unconfirmed = not FORMAT_CONFIRMED[FMT_FW4]
            elif det.id.startswith("dns_"):
                unconfirmed = not (
                    FORMAT_CONFIRMED[FMT_DNS_QUERY] and FORMAT_CONFIRMED[FMT_DNS_REPLY]
                )
            else:
                unconfirmed = False
            out.append(
                {
                    "id": det.id,
                    "description": det.describe(),
                    "availability": availability,
                    "reason": reason,
                    "missing": missing,
                    "limitations": limitations,
                    "learning": any(r.learning for r in available),
                    "format_unconfirmed": unconfirmed,
                }
            )
        return out

    def _unevaluated(self, det: Any) -> tuple[str, str, list[str]]:
        """Availability of a detector that has not run yet (from statuses)."""
        if not self._statuses:
            return DETECTION_NOT_AVAILABLE, "no_router", []
        missing: set[str] = set()
        reasons: set[str] = set()
        for per_router in self._statuses.values():
            status, lacking = check_sources(det.sources, per_router)
            if status is Availability.AVAILABLE:
                return DETECTION_AVAILABLE, "", []
            missing.update(lacking)
            reasons.update(per_router[s].reason for s in lacking if s in per_router)
        return DETECTION_NOT_AVAILABLE, ",".join(sorted(reasons)), sorted(missing)

    def _score(
        self,
        now: float,
        statuses: Mapping[str, Mapping[str, SourceStatus]],
        flat: Mapping[str, SourceStatus],
    ) -> dict[str, Any]:
        active = [i for i in self.incidents.values() if i["status"] in _ACTIVE_STATUSES]
        severities = [i["severity"] for i in active]
        severities += [sev for _type, sev in self._ni_open.values() if sev]
        values: dict[str, float | None] = {
            FACTOR_INCIDENTS: incident_load(severities),
            FACTOR_CONFIG: float(
                sum(
                    1
                    for n in self.drifts.values()
                    if n.critical and 0 <= now - n.ts <= _DAY
                )
            ),
            FACTOR_AUTH: float(
                sum(
                    1
                    for i in active
                    if i["detector"] == "wifi_auth_repeat"
                    and now - i["last_seen"] <= 3600
                )
            ),
            FACTOR_ACTIVITY: float(
                sum(1 for i in active if i["category"] in ("firewall", "dns"))
            ),
            FACTOR_UNKNOWN: float(
                sum(
                    count
                    for state, count in self.trust.counts(now).items()
                    if state in ("unrecognized", "suspicious")
                )
            ),
            FACTOR_SEGMENTATION: float(
                sum(1 for i in active if i["category"] == "vlan")
            ),
        }
        limitations = {
            factor: sorted(
                {
                    x
                    for (d, _r), r in self._results.items()
                    if d in detectors and r.available
                    for x in r.limitations
                }
            )
            for factor, detectors in _FACTOR_DETECTORS.items()
        }
        result = compute_score(values, flat, limitations=limitations)
        out = result.to_dict()
        out["routers"] = len(statuses)
        return out

    def _log_path_view(self, now: float) -> dict[str, Any]:
        """Setting, fleet status of the log sources, receiver counters."""
        receiver = self.syslog
        return {
            "setting": self.settings.get("log_path"),
            "status": [
                self._path_status(s, now).to_dict()
                for s in (DataSource.FIREWALL_LOG, DataSource.DNS_QUERY_LOG)
            ],
            "receiver": receiver.status() if receiver is not None else None,
            "dedup": self.deduper.stats().to_dict(),
        }

    # -- views of the HTTP routes (part 2) ------------------------------------------

    async def async_viewer(self, actor: Any) -> Any:
        """The actor for reading: verified by the core guard while on.

        Plain identities need a fresh verified admin user; without the core
        (or while off: nothing is bound then) the unverified actor is
        returned and the output stays pseudonymised.
        """
        if not self.active or self._binding.api is None:
            return actor
        try:
            return await self._binding.api.guard.async_verify_actor(actor)
        except Exception as err:  # noqa: BLE001 - unverified: pseudonyms
            _LOGGER.debug(
                "Security Center: viewer not verified (%s)", type(err).__name__
            )
            return actor

    def incident_detail(
        self, incident_id: str, *, actor: Any = None, now: float | None = None
    ) -> dict[str, Any] | None:
        """One own incident with its timeline entries; None if unknown."""
        inc = self.incidents.get(incident_id)
        if inc is None:
            return None
        admin = _is_admin(actor)
        macs = self._macs_by_ref() if admin else None
        when = self._now() if now is None else now
        return {
            "admin_view": admin,
            "incident": self._incident_view(inc, admin=admin, macs=macs),
            "timeline": [
                self._timeline_view(t, admin=admin, macs=macs)
                for t in reversed(self.timeline)
                if t.get("incident_id") == incident_id
            ][:200],
            "now": when,
        }

    def detections_view(self, now: float | None = None) -> dict[str, Any]:
        """Availability of every detection and of the log path (no identities)."""
        when = self._now() if now is None else now
        statuses = self._all_statuses(when)
        return {
            "enabled": self.enabled,
            "active": self.active,
            "detections": self._detections(),
            "sources": {
                rid: {s: st.to_dict() for s, st in sorted(per.items())}
                for rid, per in statuses.items()
            },
            "log_path": self._log_path_view(when),
        }

    def settings_view(self, *, admin: bool) -> dict[str, Any]:
        """Settings; for non-admins the subnet map only as a count."""
        settings = dict(self.settings)
        settings["thresholds"] = dict(settings.get("thresholds") or {})
        zones = dict(settings.get("subnet_zones") or {})
        settings["subnet_zones"] = zones if admin else {}
        receiver = self.syslog
        return {
            "settings": settings,
            "subnet_zone_count": len(zones),
            "active": self.active,
            "can_edit": admin,
            "receiver": receiver.status() if receiver is not None else None,
        }

    # -- fleet sensors (part 2) -----------------------------------------------------

    def _publish(self, now: float) -> None:
        """Rebuild ``fleet_view`` and tell the sensors."""
        self.fleet_view = self._fleet_view(now) if self.active else None
        self._signal()

    def _signal(self) -> None:
        try:
            from homeassistant.helpers.dispatcher import async_dispatcher_send

            async_dispatcher_send(self.hass, SIGNAL_SECURITY_CENTER)
        except Exception as err:  # noqa: BLE001 - the sensors catch up later
            _LOGGER.debug("Security Center: no sensor update (%s)", type(err).__name__)

    def _sync_entities(self) -> None:
        """Create or remove the fleet sensors to match ``enabled``."""
        try:
            from .security_entities import async_sync_security_entities

            async_sync_security_entities(self.hass)
        except Exception as err:  # noqa: BLE001 - never fails a setup or action
            self._fail("sensor sync", err)

    def _fleet_view(self, now: float) -> dict[str, Any] | None:
        """Counts for the fleet sensors; None (unknown) before any router.

        A count whose source no router delivers is None, never 0: no data
        is not "nothing happened".
        """
        statuses = self._all_statuses(now)
        if not statuses:
            return None

        def delivered(*sources: str) -> bool:
            return any(
                st.usable
                for per in statuses.values()
                for s, st in per.items()
                if s in sources
            )

        flat = self._flat(statuses)
        score = self._score(now, statuses, flat)
        active = [i for i in self.incidents.values() if i["status"] in _ACTIVE_STATUSES]
        # No usable source anywhere (coverage 0): the hint counts are not
        # known either (review 2, N1); "keine Daten", never 0.
        any_source = any(st.usable for per in statuses.values() for st in per.values())
        counts = self.trust.counts(now)
        unknown = sum(
            counts.get(s.value, 0)
            for s in (TrustState.NEW, TrustState.UNRECOGNIZED, TrustState.SUSPICIOUS)
        )
        return {
            "score": score["score"],
            "score_cap": score.get("cap"),
            "score_reason": score.get("reason"),
            "coverage": score["coverage"],
            "routers": len(statuses),
            "missing": sorted(
                s
                for s, st in flat.items()
                if st.availability is Availability.NOT_AVAILABLE
            ),
            "stale": sorted(
                s for s, st in flat.items() if st.availability is Availability.STALE
            ),
            "hints_active": len(active) if any_source else None,
            "hints_critical": sum(
                1 for i in active if i["severity"] == Severity.CRITICAL.value
            )
            if any_source
            else None,
            "unknown_devices": unknown
            if delivered(DataSource.HOSTAPD_CLIENTS, DataSource.CLIENT_HISTORY)
            else None,
            "device_counts": counts,
            "firewall_events_1h": self._fw_events.total(self.syslog.now())
            if self.syslog is not None and delivered(DataSource.FIREWALL_LOG)
            else None,
            "wifi_auth_failures_1h": self._auth_failures.total(now)
            if delivered(DataSource.WIFI_EVENTS)
            else None,
        }

    def diagnostics(self) -> dict[str, Any]:
        """Counts only (no identities)."""
        return {
            "enabled": self.enabled,
            "active": self.active,
            "loaded": self.loaded,
            "load_failed": self.load_failed,
            "entries": len(self._entries),
            "routers": len(self._seen),
            "incidents": len(self.incidents),
            "open_incidents": sum(
                1 for i in self.incidents.values() if i["status"] in _ACTIVE_STATUSES
            ),
            "timeline": len(self.timeline),
            "devices": len(self.trust),
            "baselines": len(self.baseline),
            "drifts": len(self.drifts),
            "detector_state": self.detectors.state_size(),
            "module_key": self._module_key is not None,
            "events_registered": self._binding.events_ok,
            "last_save_bytes": self.last_save_bytes,
            "counters": dict(self.counters),
            "log_path": self.settings.get("log_path"),
            "syslog": (
                {
                    k: v
                    for k, v in self.syslog.status().items()
                    if k in ("listening", "reason", "port", "senders", "buffered")
                }
                | {
                    "stats": self.syslog.stats().to_dict(),
                    "footprint": self.syslog.footprint(),
                }
                if self.syslog is not None
                else None
            ),
            "dedup": self.deduper.stats().to_dict() | self.deduper.footprint(),
            "fleet_view": self.fleet_view is not None,
        }


def _incident_from_store(item: Any) -> dict[str, Any] | None:
    """A stored incident with checked types, else None."""
    if not isinstance(item, Mapping):
        return None
    inc_id = item.get("id")
    scope = item.get("scope")
    first = _num(item.get("first_seen"))
    last = _num(item.get("last_seen"))
    if (
        not isinstance(inc_id, str)
        or not inc_id.startswith(INCIDENT_PREFIX)
        or not isinstance(scope, str)
        or first is None
        or last is None
        or item.get("status") not in INCIDENT_STATUSES
    ):
        return None
    router = item.get("router_id")
    if router is not None and valid_router_id(router) is None:
        return None
    inc = {
        "id": inc_id[:64],
        "type": str(item.get("type") or "")[:96],
        "detector": str(item.get("detector") or "")[:64],
        "event_id": str(item.get("event_id") or "")[:96],
        "scope": scope[:400],
        "category": str(item.get("category") or "system")[:16],
        "severity": _severity(item.get("severity")).value,
        "assessment": str(item.get("assessment") or "noticeable")[:16],
        "status": item["status"],
        "router_id": router,
        "client_ref": item.get("client_ref")
        if isinstance(item.get("client_ref"), str)
        else None,
        "has_client": item.get("has_client") is True,
        "first_seen": first,
        "last_seen": last,
        "count": max(1, int(_num(item.get("count")) or 1)),
        "evidence": mask_identities(
            [str(x) for x in item.get("evidence", []) if isinstance(x, str)][:8]
        ),
        "linked_incident_ids": [
            str(x)[:96]
            for x in item.get("linked_incident_ids", [])
            if isinstance(x, str)
        ][:16],
        "drift_refs": [
            str(x)[:128] for x in item.get("drift_refs", []) if isinstance(x, str)
        ][:8],
        "correlation_id": item.get("correlation_id")
        if isinstance(item.get("correlation_id"), str)
        else None,
        "title": mask_identities(str(item.get("title") or "")),
        "hint": mask_identities(str(item.get("hint") or "")),
        "resolved_at": _num(item.get("resolved_at")),
    }
    return inc


__all__ = [
    "DriftNote",
    "SecurityCenter",
    "SecurityCenterError",
    "async_get_security_center",
    "async_release_security_center",
    "async_setup_security_center",
    "default_settings",
    "merge_settings",
    "settings_from_store",
]
