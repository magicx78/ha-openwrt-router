"""Network Time Machine: one read adapter per source.

Plan ``docs/plans/2026-11-21-network-time-machine.md`` §4 variant (b).
Phase A: a pure read layer over modules that already keep history; every
adapter reads the source's public read function once per request and turns
its entries into timeline marks (§5.1). Phases B/C add three sources that
read the Time Machine's own index (``tm_engine`` / ``tm_store``; no router
call either): ``tm_index`` (outages, gaps, radios, topology, configuration
fingerprint, own marks), ``tm_refs`` (references to audit entries,
administrators only) and ``tm_clients`` (client sessions, administrators
only, only while the client switch is on). They are read whole (the index
holds at most 15000 marks), so they are never cut.

Sources and their read functions:

* ``core_audit``: ``ConfigurationApi.events`` per audit ring (oldest first,
  ``limit`` keeps the newest, no ``until``). Each ring is read whole (the
  read limit is above the ring's capacity) and cut to the window here, so
  every entry of the window is reachable page by page.
* ``config_versions``: ``ConfigurationApi.async_list_backups`` (newest
  first, no ``until`` either; read limit 500).
* ``ni_events`` / ``ni_incidents``: ``net_query.events_page`` and
  ``net_query.incidents_page``, the functions behind the Network
  Intelligence routes. Events with a limit above the ring's capacity.
  Incidents come in status/severity order without a time filter: they are
  all read (the limit is the number stored plus one: active and
  acknowledged incidents are never pruned, so the store can hold more than
  ``MAX_INCIDENTS``) and filtered by time here.
* ``security_timeline``: ``SecurityCenter.overview`` with the masked
  (non-admin) view; only its ``timeline`` is used (read limit above its
  capacity).

Times are on a millisecond grid: a mark's ``ts`` is its source time
rounded *down* to the millisecond (``ms_floor``), the window check uses
that value and ``tm_query`` puts the query's bounds on the same grid, so a
mark lies in exactly one page window. A read that hit its limit reports
its ``edge`` (the oldest read entry of the window, client entries
included): above it the source is complete.

Privacy (plan §6, F3/F4/F5): a mark carries no MAC, IP, host name, SSID or
WLAN netdev name. Routers appear only as the contract ``router_id`` plus the
entry title the sister modules show (dropped when it is an address). An
entry of a Phase A source that concerns a client is left out and only
counted (``omitted_client``). Client marks exist only in ``tm_clients``:
the pseudonym ``tmc_…`` and, for administrators, the current host name
while Client Stability still knows the client. Source texts (Security
Center only) go through the core masking and the identity masking; all
other marks carry fixed codes (``title_key``) and numbers only.

Phase E (1.52.0): for administrators with the client switch on, an entry
of the Security Center, Traffic Analytics or WiFi RF that names a client
(``client_ref`` with that module's own key) is attributed to the Time
Machine's client (``client`` ``tmc_…``) by :class:`ClientResolver`: each
module's in-process "pseudonym for MAC" function is applied to the MACs the
client recorder knows right now, never by comparing ``cli_…`` values of two
modules. Nothing of it is cached between requests (a forgotten client is
gone at once). An entry that cannot be attributed stays left out and
counted.

Phase F (1.52.0): :func:`jump_target` says which Enterprise tab (and which
object) a mark's ``ref`` leads to; ``JUMP_TARGETS`` lists every
``ref.module`` / ``ref.type`` the backend produces (the target of
``core_audit`` / ``event`` depends on the mark's kind, ``KIND_TABS``).

Every failure of a source stays inside its own result: a source that
raises, takes too long or answers in an unexpected shape reports
``unreadable`` with a fixed reason and never breaks the answer.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import math
import re
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from homeassistant.core import HomeAssistant

from .const import DOMAIN, SEC_TIMELINE_MAX
from .core_errors import ConfigApiError
from .core_masking import redact_text
from .core_models import (
    AUDIT_MAX_EVENTS,
    MAX_LIST_LIMIT,
    OPTION_CONFIG_BACKUP_ENABLED,
    SECURITY_AUDIT_MAX_EVENTS,
    AuditRing,
    BackupRecord,
    CoreEvent,
    VersionStatus,
)
from .net_events import MAX_EVENTS as NI_MAX_EVENTS
from .net_events import MAX_INCIDENTS as NI_MAX_INCIDENTS

_LOGGER = logging.getLogger(__name__)

# --- fixed vocabulary (stable; additive changes only) -----------------------------------

SOURCE_CORE_AUDIT: Final = "core_audit"
SOURCE_CONFIG_VERSIONS: Final = "config_versions"
SOURCE_NI_EVENTS: Final = "ni_events"
SOURCE_NI_INCIDENTS: Final = "ni_incidents"
SOURCE_SECURITY_TIMELINE: Final = "security_timeline"
SOURCE_IDS: Final = (
    SOURCE_CORE_AUDIT,
    SOURCE_CONFIG_VERSIONS,
    SOURCE_NI_EVENTS,
    SOURCE_NI_INCIDENTS,
    SOURCE_SECURITY_TIMELINE,
)
# Phases B/C: the own index (ids as in ``tm_marks``).
SOURCE_TM_INDEX: Final = "tm_index"
SOURCE_TM_REFS: Final = "tm_refs"
SOURCE_TM_CLIENTS: Final = "tm_clients"
INDEX_SOURCE_IDS: Final = (SOURCE_TM_INDEX, SOURCE_TM_REFS, SOURCE_TM_CLIENTS)
ALL_SOURCE_IDS: Final = SOURCE_IDS + INDEX_SOURCE_IDS

STATE_OK: Final = "ok"
STATE_EMPTY: Final = "empty"
STATE_OFF: Final = "off"
STATE_UNREADABLE: Final = "unreadable"

# ``reason`` of a source: None for ok/empty, one of these otherwise.
REASON_NOT_RUNNING: Final = "not_running"  # the source module is not set up
REASON_NOT_LOADED: Final = "not_loaded"  # set up, its store not read yet
REASON_TIMEOUT: Final = "timeout"  # over the time budget of a source
REASON_ERROR: Final = "error"  # the read function raised
REASON_BAD_FORMAT: Final = "bad_format"  # an answer of an unexpected shape
REASON_MODULE_OFF: Final = "module_off"  # the source module is switched off
REASON_ADMIN_ONLY: Final = "admin_only"  # not shown to this (non-admin) user
REASON_CLIENTS_OFF: Final = "clients_off"  # the client switch is off (tm_clients)
REASONS: Final = (
    REASON_NOT_RUNNING,
    REASON_NOT_LOADED,
    REASON_TIMEOUT,
    REASON_ERROR,
    REASON_BAD_FORMAT,
    REASON_MODULE_OFF,
    REASON_ADMIN_ONLY,
)
# Phases B/C (the panel of 1.50.0 has texts for REASONS only).
INDEX_REASONS: Final = (REASON_CLIENTS_OFF,)
ALL_REASONS: Final = REASONS + INDEX_REASONS

SEVERITIES: Final = ("info", "warning", "critical")
SEVERITY_RANK: Final = {name: rank for rank, name in enumerate(SEVERITIES)}

GROUP_INFRASTRUCTURE: Final = "infrastructure"
GROUP_RADIO: Final = "radio"
GROUP_TOPOLOGY: Final = "topology"
GROUP_CONFIGURATION: Final = "configuration"
GROUP_DISRUPTION: Final = "disruption"
GROUP_SECURITY: Final = "security"
GROUP_ADMINISTRATION: Final = "administration"
GROUP_CLIENTS: Final = "clients"
GROUP_TIME_MACHINE: Final = "time_machine"

# kind -> group (plan §5.2 plus the catch-all kinds of Phase A). Kinds that
# Phase A never produces are listed so the filter accepts them already.
KIND_GROUP: Final[Mapping[str, str]] = {
    # infrastructure
    "router_down": GROUP_INFRASTRUCTURE,
    "router_up": GROUP_INFRASTRUCTURE,
    "lan_down": GROUP_INFRASTRUCTURE,
    "lan_up": GROUP_INFRASTRUCTURE,
    "ha_gap": GROUP_INFRASTRUCTURE,  # Phase B
    "observation_gap": GROUP_INFRASTRUCTURE,
    "wan_event": GROUP_INFRASTRUCTURE,
    "port_event": GROUP_INFRASTRUCTURE,
    "system_event": GROUP_INFRASTRUCTURE,
    # radio
    "channel_changed": GROUP_RADIO,
    "dfs_event": GROUP_RADIO,
    "radio_down": GROUP_RADIO,  # Phase B
    "radio_up": GROUP_RADIO,  # Phase B
    "rf_event": GROUP_RADIO,
    # topology
    "uplink_changed": GROUP_TOPOLOGY,
    "router_role_changed": GROUP_TOPOLOGY,  # Phase B
    # configuration (administrators only)
    "config_fingerprint_changed": GROUP_CONFIGURATION,  # Phase B
    "config_version": GROUP_CONFIGURATION,
    "config_drift": GROUP_CONFIGURATION,
    "config_event": GROUP_CONFIGURATION,
    # disruption
    "incident_opened": GROUP_DISRUPTION,
    "incident_resolved": GROUP_DISRUPTION,
    "security_incident": GROUP_DISRUPTION,
    "diag_finding": GROUP_DISRUPTION,
    "traffic_anomaly": GROUP_DISRUPTION,
    "net_event": GROUP_DISRUPTION,
    # security and administration (administrators only)
    "security_event": GROUP_SECURITY,
    "registry_event": GROUP_ADMINISTRATION,
    "core_event": GROUP_ADMINISTRATION,
    "audit_event": GROUP_ADMINISTRATION,
    # clients (Phase C; never produced in Phase A)
    "client_session": GROUP_CLIENTS,
    "client_roam": GROUP_CLIENTS,
    "client_disconnect": GROUP_CLIENTS,
    # the time machine's own marks (Phase B)
    "tm_started": GROUP_TIME_MACHINE,
    "tm_disabled": GROUP_TIME_MACHINE,
    "tm_store_recovered": GROUP_TIME_MACHINE,
    "tm_forgot_client": GROUP_TIME_MACHINE,
    "tm_exported": GROUP_TIME_MACHINE,
    # added in Phase B/C (additive): a jump of the system clock, and the
    # summary of one client's marks over its daily cap
    "clock_shift": GROUP_TIME_MACHINE,
    "client_flapping": GROUP_CLIENTS,
    "tm_cleared": GROUP_TIME_MACHINE,  # the history was cleared (action)
}
KINDS: Final = tuple(KIND_GROUP)
# What a non-admin sees while the panel is open to all users (F4):
# infrastructure (with radio and topology) and disruptions, no clients.
NON_ADMIN_GROUPS: Final = frozenset(
    {GROUP_INFRASTRUCTURE, GROUP_RADIO, GROUP_TOPOLOGY, GROUP_DISRUPTION}
)

# --- limits -----------------------------------------------------------------------------

# Read limits per source. Above the capacity of the source's store (1.50.0
# review S1-S3), so a read is whole and client entries or another ring can
# never use it up; a read that still hits its limit is cut (``truncated``,
# ``edge``). Only the configuration versions keep the core's list maximum.
AUDIT_READ_LIMIT: Final = max(AUDIT_MAX_EVENTS, SECURITY_AUDIT_MAX_EVENTS) + 1
VERSIONS_READ_LIMIT: Final = MAX_LIST_LIMIT
NI_EVENTS_READ_LIMIT: Final = NI_MAX_EVENTS + 1
NI_INCIDENTS_READ_LIMIT: Final = NI_MAX_INCIDENTS + 1
SECURITY_READ_LIMIT: Final = SEC_TIMELINE_MAX + 1
# Time budget of one source (seconds): an asyncio timeout around its awaits
# plus a monotonic deadline checked inside its own loops. A synchronous read
# function of a source module is not interrupted; the deadline is checked
# after it returns.
SOURCE_BUDGET_S: Final = 2.0
MS: Final = 0.001  # the time grid of marks and page bounds
PARAMS_MAX: Final = 8
TEXT_MAX: Final = 120
NAME_MAX: Final = 64

_TOKEN = re.compile(r"[a-z0-9_]{1,40}(?:\.[a-z0-9_]{1,40}){0,3}")
_REF_ID = re.compile(r"[A-Za-z0-9_:.-]{1,80}")
_VERSION_ID = re.compile(r"bkp_[0-9a-f]{32}")
_MAC_LIKE = re.compile(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
_CLIENT_KEYS: Final = frozenset({"mac", "client", "client_ref", "station", "sta"})

ReadFn = Callable[
    [HomeAssistant, "ReadRequest", "RouterMap", float], Awaitable["SourceResult"]
]


# --- request, router map, result -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReadRequest:
    """One read: the half-open window ``[since, until)`` in epoch seconds."""

    since: float
    until: float
    admin: bool
    now: float


# 1.52.2: the config entry of a router now (``entry`` of a router in
# ``/state`` and in the blocks of ``/compare``); null: no config entry, only
# history.
ENTRY_ENABLED: Final = "enabled"
ENTRY_DISABLED: Final = "disabled"  # ``disabled_by`` is set (never set up)


@dataclass(frozen=True, slots=True)
class RouterMap:
    """``entry_id`` -> contract ``router_id`` and ``router_id`` -> display name."""

    by_entry: Mapping[str, str] = field(default_factory=dict)
    names: Mapping[str, str | None] = field(default_factory=dict)
    # 1.52.2: router ids whose config entry is disabled (``disabled_by`` set;
    # ConfigEntryDisabler has only USER: a user disabled it)
    disabled: frozenset[str] = frozenset()

    def entry_of(self, router_id: str | None) -> str | None:
        """``enabled`` / ``disabled`` for a router with a config entry, else None."""
        if router_id is None or router_id not in self.names:
            return None
        return ENTRY_DISABLED if router_id in self.disabled else ENTRY_ENABLED

    def router_of_entry(self, entry_id: Any) -> str | None:
        """The router id of a config entry (None if unknown)."""
        return self.by_entry.get(entry_id) if isinstance(entry_id, str) else None

    def name_of(self, router_id: str | None) -> str | None:
        """The display name of a router (None if unknown or an address)."""
        return None if router_id is None else self.names.get(router_id)


@dataclass(slots=True)
class SourceResult:
    """What one adapter read for the window."""

    source: str
    state: str
    reason: str | None = None
    marks: list[dict[str, Any]] = field(default_factory=list)
    omitted_client: int = 0
    truncated: bool = False
    oldest: float | None = None
    # A cut read (``truncated``): the oldest read entry of the window, client
    # entries included; the source is complete above it. None when the cut
    # leaves no entry of the window (``unreachable``).
    edge: float | None = None
    # Older entries of the window cannot be read at all (no ``until`` in the
    # read function, or a read without time order).
    unreachable: bool = False
    # Marks dropped as doubles of another source (``tm_query.merge``).
    duplicates: int = 0
    # ``tm_index`` only: when the own index was live ([start, end] pairs).
    coverage: list[tuple[float, float]] = field(default_factory=list)
    # Own index only (1.51.0, review S4): intervals that began before the
    # window and reach into it; never part of ``marks`` (``tm_query`` shows
    # them in ``spanning`` with ``spans=1`` only, and uses them for doubles).
    spanning: list[dict[str, Any]] = field(default_factory=list)
    # ``tm_index`` on a later page only (review K-a): its marks just after
    # the cursor (already on the page before), read only to find doubles.
    lookahead: list[dict[str, Any]] = field(default_factory=list)


class SourceOff(Exception):
    """The source is switched off or not shown to this user (no error)."""

    def __init__(self, reason: str) -> None:
        """Remember the fixed reason code."""
        super().__init__(reason)
        self.reason = reason


class SourceUnreadable(Exception):
    """The source cannot be read now (fixed reason code)."""

    def __init__(self, reason: str) -> None:
        """Remember the fixed reason code."""
        super().__init__(reason)
        self.reason = reason


# --- helpers ----------------------------------------------------------------------------


def domain_entries(hass: HomeAssistant) -> list[Any]:
    """Config entries of the integration; never raises."""
    try:
        entries = hass.config_entries.async_entries(DOMAIN)
    except Exception:  # noqa: BLE001 - a broken registry is "no entries"
        return []
    return list(entries) if isinstance(entries, list) else []


def display_name(title: Any) -> str | None:
    """The entry title as router name; None when empty, too long or an address."""
    if not isinstance(title, str):
        return None
    name = title.strip()
    if not name or len(name) > NAME_MAX or _MAC_LIKE.search(name):
        return None
    try:
        ipaddress.ip_address(name.strip("[]"))
    except ValueError:
        return name
    return None


def build_router_map(hass: HomeAssistant) -> RouterMap:
    """Map every entry through ``RouterRegistry.router_id_for_entry``."""
    from .enterprise_core import async_get_core

    core = async_get_core(hass)
    registry = getattr(core, "registry", None)
    if registry is None:
        return RouterMap()
    by_entry: dict[str, str] = {}
    names: dict[str, str | None] = {}
    disabled: set[str] = set()
    for entry in domain_entries(hass):
        entry_id = getattr(entry, "entry_id", None)
        if not isinstance(entry_id, str):
            continue
        try:
            router_id = registry.router_id_for_entry(entry_id)
        except Exception:  # noqa: BLE001 - an unknown entry has no router id
            router_id = None
        if isinstance(router_id, str):
            by_entry[entry_id] = router_id
            names[router_id] = display_name(getattr(entry, "title", None))
            if getattr(entry, "disabled_by", None) is not None:
                disabled.add(router_id)
    return RouterMap(by_entry, names, frozenset(disabled))


def ms_floor(value: float) -> float:
    """``value`` rounded down to the millisecond grid (``k / 1000``)."""
    k = math.floor(value * 1000)
    if k / 1000 > value:
        k -= 1
    elif (k + 1) / 1000 <= value:
        k += 1
    return k / 1000


def ms_ceil(value: float) -> float:
    """``value`` rounded up to the millisecond grid (``k / 1000``)."""
    k = math.ceil(value * 1000)
    if (k - 1) / 1000 >= value:
        k -= 1
    elif k / 1000 < value:
        k += 1
    return k / 1000


def ms_next(value: float) -> float:
    """The grid point after ``value`` (a grid value)."""
    return (round(value * 1000) + 1) / 1000


def epoch(value: datetime) -> float:
    """Epoch seconds (UTC) of an aware datetime."""
    return value.timestamp()


def to_utc(value: float) -> datetime:
    """An aware UTC datetime of epoch seconds."""
    return datetime.fromtimestamp(value, UTC)


def mark_id(source: str, source_id: str, variant: str = "") -> str:
    """Stable mark id ``tmm_<16 hex>`` from source, source id and variant."""
    digest = hashlib.sha256(
        f"{source}\0{source_id}\0{variant}".encode(), usedforsecurity=False
    ).hexdigest()
    return f"tmm_{digest[:16]}"


def token(value: Any) -> str | None:
    """A fixed code of a source (lower-case dotted token), else None."""
    if isinstance(value, str) and _TOKEN.fullmatch(value):
        return value
    return None


def severity_of(value: Any) -> str:
    """One of SEVERITIES (unknown values count as ``info``)."""
    raw = getattr(value, "value", value)
    return raw if isinstance(raw, str) and raw in SEVERITY_RANK else "info"


def number(value: Any) -> float | int | None:
    """A finite number (bool is no number); lists count as their length."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return round(value, 3) if math.isfinite(value) else None
    if isinstance(value, list | tuple):
        return len(value)
    return None


def params_of(source: Mapping[str, Any] | None, keys: Iterable[str]) -> dict[str, Any]:
    """Numeric values of the listed keys only (at most PARAMS_MAX)."""
    out: dict[str, Any] = {}
    if not isinstance(source, Mapping):
        return out
    for key in keys:
        value = number(source.get(key))
        if value is not None:
            out[key] = value
        if len(out) >= PARAMS_MAX:
            break
    return out


def masked_text(value: Any) -> str | None:
    """Short source text through the core masking (secrets, MACs) and the
    identity masking (IPs, domains, keyed identities), capped."""
    if not isinstance(value, str) or not value.strip():
        return None
    from .security_model import clean_text, mask_identities

    text = mask_identities(redact_text(value))
    if not isinstance(text, str):
        return None
    return clean_text(text, TEXT_MAX) or None


def ref_of(
    module: str,
    type_: str | None,
    ref_id: Any = None,
    version_id: Any = None,
) -> dict[str, Any]:
    """Reference to the source record (``module``, ``type``, ``id``, ``version_id``)."""
    return {
        "module": module,
        "type": type_,
        "id": ref_id if isinstance(ref_id, str) and _REF_ID.fullmatch(ref_id) else None,
        "version_id": version_id
        if isinstance(version_id, str) and _VERSION_ID.fullmatch(version_id)
        else None,
    }


def make_mark(
    *,
    source: str,
    source_id: str,
    variant: str = "",
    ts: float,
    kind: str,
    severity: Any,
    router_id: str | None,
    routers: RouterMap,
    fleet: bool,
    code: str | None,
    text: str | None = None,
    params: Mapping[str, Any] | None = None,
    ref: Mapping[str, Any],
) -> dict[str, Any]:
    """One timeline mark (plan §5.1); see ``docs/time-machine.md``."""
    return {
        "id": mark_id(source, source_id, variant),
        "ts": ms_floor(float(ts)),
        "source": source,
        "kind": kind,
        "group": KIND_GROUP[kind],
        "severity": severity_of(severity),
        "router_id": router_id,
        "router_name": routers.name_of(router_id),
        "fleet": fleet,
        "title_key": f"{source}.{code or 'unknown'}",
        "text": text,
        "params": dict(params or {}),
        "ref": dict(ref),
        "derived": False,
        # additive (Phases B/C); set on marks of the own index only
        "code": code,
        "end": None,
        "end_state": None,
        "client": None,
        "client_name": None,
        "peers": None,
        # additive (1.51.0): an interval of the own index that began before
        # the window and reaches into it (only in ``spanning``, with
        # ``spans=1``; review S4)
        "spans_in": False,
    }


def _check(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise SourceUnreadable(REASON_TIMEOUT)


def _finish(
    source: str,
    marks: list[dict[str, Any]],
    omitted: int,
    truncated: bool,
    read: Iterable[float] = (),
    *,
    unreachable: bool = False,
) -> SourceResult:
    """The result of one read. ``read`` holds the grid times of every entry
    of the window that was read (client entries included): a cut read ends
    at the oldest of them (``edge``). All marks stay; rights, filters and
    the page size are applied by ``tm_query.merge``."""
    marks.sort(key=lambda m: (-m["ts"], m["id"]))
    times = list(read)
    edge = min(times) if truncated and times and not unreachable else None
    return SourceResult(
        source,
        STATE_OK if marks or truncated else STATE_EMPTY,
        None,
        marks,
        omitted,
        truncated,
        marks[-1]["ts"] if marks else None,
        edge,
        truncated and edge is None,
    )


def _in_window(ts: Any, req: ReadRequest) -> bool:
    """On the grid: ``since <= ms_floor(ts) < until`` (see the module doc)."""
    return (
        isinstance(ts, int | float)
        and not isinstance(ts, bool)
        and math.isfinite(ts)
        and req.since <= ms_floor(float(ts)) < req.until
    )


async def _config_api(hass: HomeAssistant) -> Any:
    """The Configuration API of a running, loaded core (never loads it)."""
    from .config_api import async_get_configuration_api
    from .enterprise_core import async_get_core

    core = async_get_core(hass)
    if core is None or getattr(core, "closed", False):
        raise SourceUnreadable(REASON_NOT_RUNNING)
    if getattr(core, "loaded", False) is not True:
        raise SourceUnreadable(REASON_NOT_LOADED)
    try:
        return await async_get_configuration_api(hass, 1)
    except ConfigApiError as err:
        reason = (getattr(err, "details", None) or {}).get("reason")
        raise SourceUnreadable(
            REASON_NOT_RUNNING if reason == "core_not_running" else REASON_ERROR
        ) from None


# --- core audit -------------------------------------------------------------------------

_DRIFT_TYPES: Final = frozenset(
    {
        "configuration.drift_detected",
        "configuration.drift_incomplete",
        "configuration.drift_acknowledged",
        "configuration.change_critical",
        "configuration.change_unknown",
    }
)
_MODULE_KINDS: Final = (
    ("wifi_rf.", "rf_event"),
    ("net_diagnostics.", "diag_finding"),
    ("traffic_analytics.", "traffic_anomaly"),
    ("security_center.", "security_incident"),
    ("config_manager.", "config_event"),
    ("configuration.", "config_event"),
    ("router.", "registry_event"),
    ("security.", "security_event"),
    ("core.", "core_event"),
)
_AUDIT_PARAMS: Final = (
    "changes",
    "critical_count",
    "unknown_count",
    "not_compared_count",
)


def audit_kind(event_type: str) -> str:
    """Timeline kind of an audit event type."""
    if event_type in _DRIFT_TYPES:
        return "config_drift"
    for prefix, kind in _MODULE_KINDS:
        if event_type.startswith(prefix):
            return kind
    return "audit_event"


def _audit_concerns_client(event: CoreEvent) -> bool:
    data = event.data if isinstance(event.data, Mapping) else {}
    return event.client_ref is not None or any(k in data for k in _CLIENT_KEYS)


# --- client attribution across modules (Phase E, 1.52.0) --------------------------------

# Modules whose entries carry a ``client_ref`` made with their own key, and
# the ``CoreEvent.source`` they write.
CLIENT_MODULES: Final = ("security_center", "traffic_analytics", "wifi_rf")


def module_pseudonym(hass: HomeAssistant, module: str) -> Callable[[Any], Any] | None:
    """The in-process "pseudonym for MAC" function of a running module."""
    if module == "security_center":
        from .security_center import async_get_security_center

        center = async_get_security_center(hass)
        return None if center is None else center.client_ref_for_mac
    if module == "traffic_analytics":
        from .traffic_correlate import async_get_traffic_read_api

        api = async_get_traffic_read_api(hass)
        return None if api is None else api.client_ref_for_mac
    if module == "wifi_rf":
        from .rf_center import async_get_rf_center

        center = async_get_rf_center(hass)
        return None if center is None else center.client_ref_for_mac
    return None


_AMBIGUOUS: Final = ""


class ClientResolver:
    """``client_ref`` of a module -> the Time Machine client (16 hex).

    Built for one request from the MACs the client recorder holds in memory
    (open sessions plus the recently seen, ``tm_clients.MACS_RECENT_MAX``):
    per module one table ``module pseudonym -> tmc``, made with that
    module's own function. Two MACs with the same module pseudonym are
    ambiguous and resolve to nothing. Never stored, never logged.
    """

    def __init__(self, hass: HomeAssistant, recorder: Any) -> None:
        """Take the recorder's MACs now (a copy; nothing is kept after)."""
        self._hass = hass
        self._recorder = recorder
        self._macs = list(getattr(recorder, "_macs", {}).items())
        self._tables: dict[str, dict[str, str]] = {}

    def _table(self, module: str) -> dict[str, str]:
        table = self._tables.get(module)
        if table is not None:
            return table
        table = {}
        func = module_pseudonym(self._hass, module)
        for hexed, mac in self._macs if func is not None else ():
            try:
                value = func(mac)
            except Exception:  # noqa: BLE001 - a module that fails resolves nothing
                value = None
            if not isinstance(value, str) or not value:
                continue
            if table.get(value, hexed) != hexed:
                table[value] = _AMBIGUOUS
            else:
                table[value] = hexed
        self._tables[module] = table
        return table

    def resolve(self, module: Any, client_ref: Any) -> str | None:
        """The client (16 hex) or None (unknown module, not attributable)."""
        if module not in CLIENT_MODULES or not isinstance(client_ref, str):
            return None
        hexed = self._table(module).get(client_ref)
        return hexed or None

    def name(self, hexed: str) -> str | None:
        """The current host name, exactly as on the own client marks."""
        return self._recorder.name_of(hexed)


def client_resolver(hass: HomeAssistant, req: ReadRequest) -> ClientResolver | None:
    """A resolver for administrators while client histories are recorded."""
    if not req.admin:
        return None
    from .tm_engine import async_get_time_machine

    engine = async_get_time_machine(hass)
    recorder = getattr(engine, "recorder", None) if engine is not None else None
    if (
        engine is None
        or engine.loaded is not True
        or not engine.clients_wanted
        or recorder is None
        or not recorder.attached
    ):
        return None
    return ClientResolver(hass, recorder)


def _attribute(mark: dict[str, Any], resolver: ClientResolver, hexed: str) -> None:
    mark["client"] = f"tmc_{hexed}"
    mark["client_name"] = resolver.name(hexed)


# --- jump targets (Phase F, 1.52.0) ---------------------------------------------------

TAB_CONFIG: Final = "config"
TAB_SECURITY: Final = "security"
TAB_DIAGNOSTICS: Final = "diagnostics"
TAB_TRAFFIC: Final = "traffic"
TAB_WIFI: Final = "wifi"
TAB_TIME_MACHINE: Final = "timemachine"
# Kind of a ``core_audit`` / ``event`` mark -> tab (kinds of no tab: none).
KIND_TABS: Final[Mapping[str, str]] = {
    "config_event": TAB_CONFIG,
    "config_drift": TAB_CONFIG,
    "security_incident": TAB_SECURITY,
    "rf_event": TAB_WIFI,
    "diag_finding": TAB_DIAGNOSTICS,
    "traffic_anomaly": TAB_TRAFFIC,
}
# Kinds of audit entries that no Enterprise tab shows (explicitly none): the
# core's own entries (registry, authorizations, store) and unknown types.
KIND_NO_TAB: Final = frozenset(
    {"registry_event", "security_event", "core_event", "audit_event"}
)
_BY_KIND: Final = "by_kind"
# Every (ref.module, ref.type) the backend produces -> tab, ``by_kind``
# (``KIND_TABS``) or None: no Enterprise tab shows it (Network Intelligence
# lives in the panel's own views, outside the Enterprise tabs).
JUMP_TARGETS: Final[Mapping[tuple[str, str | None], str | None]] = {
    ("core_audit", "event"): _BY_KIND,
    ("core_audit", "drift"): TAB_CONFIG,
    ("config_manager", "version"): TAB_CONFIG,
    ("network_intelligence", "event"): None,
    ("network_intelligence", "incident"): None,
    ("security_center", "incident"): TAB_SECURITY,
    ("security_center", "drift"): TAB_SECURITY,
    ("security_center", "timeline"): TAB_SECURITY,
    ("time_machine", "mark"): TAB_TIME_MACHINE,
}
# What the object id of a target names (None: the tab itself).
_OBJECT: Final[Mapping[tuple[str, str | None], str | None]] = {
    ("core_audit", "event"): "audit_event",
    ("core_audit", "drift"): "audit_event",
    ("config_manager", "version"): "version",
    ("security_center", "incident"): "incident",
    ("security_center", "drift"): "drift",
    ("security_center", "timeline"): None,
    ("time_machine", "mark"): None,
}


def jump_target(
    ref: Mapping[str, Any] | None, kind: str | None = None
) -> dict[str, Any] | None:
    """Where a mark's ``ref`` leads: ``{"tab", "object_type", "object_id",
    "version_id"}``, or None (no Enterprise tab, or an unknown ref)."""
    if not isinstance(ref, Mapping):
        return None
    key = (ref.get("module"), ref.get("type"))
    tab = JUMP_TARGETS.get(key)  # type: ignore[call-overload]
    if tab == _BY_KIND:
        tab = KIND_TABS.get(kind or "")
    if tab is None:
        return None
    object_type = _OBJECT.get(key)  # type: ignore[call-overload]
    object_id = ref.get("id") if object_type is not None else None
    if key == ("config_manager", "version"):
        object_id = ref.get("version_id")
    return {
        "tab": tab,
        "object_type": object_type if object_id is not None else None,
        "object_id": object_id,
        "version_id": ref.get("version_id"),
    }


async def read_core_audit(
    hass: HomeAssistant, req: ReadRequest, routers: RouterMap, deadline: float
) -> SourceResult:
    """Audit entries of both rings (administrators only)."""
    if not req.admin:
        raise SourceOff(REASON_ADMIN_ONLY)
    api = await _config_api(hass)
    since = to_utc(req.since)
    limit = AUDIT_READ_LIMIT
    events: dict[str, CoreEvent] = {}
    truncated = unreachable = False
    edges: list[float] = []
    for ring in (AuditRing.GENERAL, AuditRing.SECURITY):
        # ``events`` has no ``until`` and sorts oldest first; ``limit`` keeps
        # the newest. The limit is above the ring's capacity: the ring is
        # read whole and cut to the window here.
        batch = api.events(since=since, ring=ring, limit=limit)
        if not isinstance(batch, tuple | list):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        times: list[float] = []
        for event in batch:
            if not isinstance(event, CoreEvent):
                raise SourceUnreadable(REASON_BAD_FORMAT)
            events.setdefault(event.event_id, event)
            if _in_window(epoch(event.ts), req):
                times.append(ms_floor(epoch(event.ts)))
        if len(batch) >= limit:
            # A cut ring is complete above its oldest read entry; the edge
            # of the source is the newest of these edges (review S2). With
            # no entry of the window read, the older ones of this ring are
            # out of reach (no ``until``).
            truncated = True
            if times:
                edges.append(min(times))
            else:
                unreachable = True
    marks: list[dict[str, Any]] = []
    omitted = 0
    resolver = client_resolver(hass, req)
    for event in events.values():
        _check(deadline)
        ts = epoch(event.ts)
        if not _in_window(ts, req):
            continue
        hexed: str | None = None
        if _audit_concerns_client(event):
            # Phase E: attributed through the module's own pseudonym
            # function, else left out and counted
            hexed = (
                resolver.resolve(event.source, event.client_ref)
                if resolver is not None
                else None
            )
            if hexed is None:
                omitted += 1
                continue
        kind = audit_kind(str(event.type))
        data = event.data if isinstance(event.data, Mapping) else {}
        params = params_of(data, _AUDIT_PARAMS)
        if event.repeat_count:
            params["repeat_count"] = int(event.repeat_count)
        version_id = data.get("baseline_version_id") or data.get("version_id")
        mark = make_mark(
            source=SOURCE_CORE_AUDIT,
            source_id=event.event_id,
            ts=ts,
            kind=kind,
            severity=event.severity,
            router_id=event.router_id,
            routers=routers,
            fleet=event.router_id is None,
            code=token(str(event.type)),
            params=params,
            ref=ref_of(
                "core_audit",
                "drift" if kind == "config_drift" else "event",
                event.event_id,
                version_id,
            ),
        )
        if hexed is not None and resolver is not None:
            _attribute(mark, resolver, hexed)
        marks.append(mark)
    result = _finish(SOURCE_CORE_AUDIT, marks, omitted, truncated)
    result.edge = max(edges) if edges else None
    result.unreachable = unreachable
    return result


# --- configuration versions --------------------------------------------------------------

_VERSION_SEVERITY: Final = {
    VersionStatus.OK: "info",
    VersionStatus.PARTIAL: "warning",
    VersionStatus.FAILED: "warning",
}


async def read_config_versions(
    hass: HomeAssistant, req: ReadRequest, routers: RouterMap, deadline: float
) -> SourceResult:
    """Configuration versions (administrators only, like the Config Manager)."""
    if not req.admin:
        raise SourceOff(REASON_ADMIN_ONLY)
    if not any(
        getattr(e, "options", {}).get(OPTION_CONFIG_BACKUP_ENABLED) is True
        for e in domain_entries(hass)
    ):
        raise SourceOff(REASON_MODULE_OFF)
    api = await _config_api(hass)
    records = await api.async_list_backups(
        since=to_utc(req.since), limit=VERSIONS_READ_LIMIT
    )
    if not isinstance(records, tuple | list):
        raise SourceUnreadable(REASON_BAD_FORMAT)
    marks: list[dict[str, Any]] = []
    read: list[float] = []
    for record in records:
        _check(deadline)
        if not isinstance(record, BackupRecord):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        ts = epoch(record.created_at)
        if not _in_window(ts, req):
            continue
        read.append(ms_floor(ts))
        marks.append(
            make_mark(
                source=SOURCE_CONFIG_VERSIONS,
                source_id=record.backup_id,
                ts=ts,
                kind="config_version",
                severity=_VERSION_SEVERITY.get(record.status, "warning"),
                router_id=record.router_id,
                routers=routers,
                fleet=False,
                code=token(f"{record.reason.value}.{record.status.value}"),
                ref=ref_of(
                    "config_manager", "version", record.backup_id, record.backup_id
                ),
            )
        )
    return _finish(
        SOURCE_CONFIG_VERSIONS, marks, 0, len(records) >= VERSIONS_READ_LIMIT, read
    )


# --- network intelligence ---------------------------------------------------------------

_NI_FLEET: Final = "fleet"
_NI_EXACT: Final[Mapping[str, str]] = {
    "system.router_unreachable": "router_down",
    "system.router_reachable": "router_up",
    "system.lan_unreachable": "lan_down",
    "system.lan_reachable": "lan_up",
    "system.log_gap": "observation_gap",
    "lan.uplink": "uplink_changed",
    "dfs.new_channel": "channel_changed",
}
_NI_PREFIX: Final = (
    ("system.", "system_event"),
    ("wan.", "wan_event"),
    ("lan.", "port_event"),
    ("dfs.", "dfs_event"),
    ("wifi.", "rf_event"),
)
_NI_EVENT_PARAMS: Final = (
    "channel",
    "frequency",
    "gap_s",
    "missed",
    "count",
    "routers",
)
_NI_INCIDENT_PARAMS: Final = ("affected", "occurrences", "reopen_count", "children")


def ni_kind(kind: str) -> str:
    """Timeline kind of a Network Intelligence event kind."""
    exact = _NI_EXACT.get(kind)
    if exact is not None:
        return exact
    for prefix, mapped in _NI_PREFIX:
        if kind.startswith(prefix):
            return mapped
    return "net_event"


def _no_name(_router: str) -> None:
    """Router names come from the RouterMap, never from the source."""


def _ni_engine(hass: HomeAssistant) -> Any:
    from .net_engine import async_get_engine

    engine = async_get_engine(hass)
    if engine is None:
        raise SourceUnreadable(REASON_NOT_RUNNING)
    if getattr(engine, "loaded", False) is not True:
        raise SourceUnreadable(REASON_NOT_LOADED)
    return engine


def _ni_router(raw: Any, routers: RouterMap) -> tuple[str | None, bool]:
    if raw == _NI_FLEET:
        return None, True
    return routers.router_of_entry(raw), False


async def read_ni_events(
    hass: HomeAssistant, req: ReadRequest, routers: RouterMap, deadline: float
) -> SourceResult:
    """Network Intelligence events of the window (newest stored first)."""
    from .net_query import events_page

    engine = _ni_engine(hass)
    page = events_page(
        engine,
        _no_name,
        {"limit": NI_EVENTS_READ_LIMIT, "since": req.since, "until": req.until},
    )
    events = page.get("events") if isinstance(page, Mapping) else None
    if not isinstance(events, list):
        raise SourceUnreadable(REASON_BAD_FORMAT)
    marks: list[dict[str, Any]] = []
    read: list[float] = []
    omitted = 0
    for event in events:
        _check(deadline)
        if not isinstance(event, Mapping):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        event_id, ts, kind = event.get("id"), event.get("ts"), event.get("kind")
        subject = event.get("subject")
        if not isinstance(event_id, str) or not isinstance(kind, str):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        if not _in_window(ts, req):
            continue
        read.append(ms_floor(float(ts)))
        if isinstance(subject, Mapping) and any(k in subject for k in _CLIENT_KEYS):
            omitted += 1
            continue
        router_id, fleet = _ni_router(event.get("router"), routers)
        params = params_of(event.get("params"), _NI_EVENT_PARAMS)
        count = number(event.get("count"))
        if count is not None and count > 1 and len(params) < PARAMS_MAX:
            params.setdefault("count", count)
        marks.append(
            make_mark(
                source=SOURCE_NI_EVENTS,
                source_id=event_id,
                ts=ts,
                kind=ni_kind(kind),
                severity=event.get("severity"),
                router_id=router_id,
                routers=routers,
                fleet=fleet,
                code=token(kind),
                params=params,
                # the NI event id carries the HA entry id: not handed out
                ref=ref_of("network_intelligence", "event"),
            )
        )
    return _finish(
        SOURCE_NI_EVENTS, marks, omitted, page.get("next_before") is not None, read
    )


async def read_ni_incidents(
    hass: HomeAssistant, req: ReadRequest, routers: RouterMap, deadline: float
) -> SourceResult:
    """Opening, reopening and resolving of NI incidents inside the window.

    ``incidents_page`` sorts by status, severity and ``last_seen`` and has no
    time filter: every stored incident is read (the limit is above the
    store's capacity) and the steps are filtered by time here (review S3).
    """
    from .net_query import engine_now, incidents_page

    engine = _ni_engine(hass)
    # Active and acknowledged incidents are never pruned (``prune_incidents``),
    # so the store may hold more than MAX_INCIDENTS: the limit follows the
    # number stored, one above it (1.51.0, review N1).
    try:
        stored = len(engine.machine.peek())
    except Exception:  # noqa: BLE001 - a broken machine is a bad answer
        raise SourceUnreadable(REASON_BAD_FORMAT) from None
    page = incidents_page(
        engine,
        _no_name,
        {"limit": max(NI_INCIDENTS_READ_LIMIT, stored + 1)},
        engine_now(engine, req.now),
    )
    incidents = page.get("incidents") if isinstance(page, Mapping) else None
    total = page.get("total") if isinstance(page, Mapping) else None
    if not isinstance(incidents, list) or not isinstance(total, int):
        raise SourceUnreadable(REASON_BAD_FORMAT)
    marks: list[dict[str, Any]] = []
    omitted = 0
    for inc in incidents:
        _check(deadline)
        if not isinstance(inc, Mapping):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        inc_id, inc_type = inc.get("id"), inc.get("type")
        first_seen, raw_routers = inc.get("first_seen"), inc.get("routers")
        if (
            not isinstance(inc_id, str)
            or not isinstance(inc_type, str)
            or not isinstance(first_seen, int | float)
            or not isinstance(raw_routers, list)
        ):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        steps = [
            ("opened", first_seen, "incident_opened"),
            ("reopened", inc.get("reopened_at"), "incident_opened"),
            ("resolved", inc.get("resolved_at"), "incident_resolved"),
        ]
        steps = [s for s in steps if _in_window(s[1], req)]
        if not steps:
            continue
        if inc.get("scope") == "client":
            omitted += len(steps)
            continue
        if inc.get("scope") == "fleet" or len(raw_routers) > 1:
            router_id, fleet = None, True
        elif raw_routers:
            router_id, fleet = routers.router_of_entry(raw_routers[0]), False
        else:
            router_id, fleet = None, False
        params = params_of(inc, _NI_INCIDENT_PARAMS)
        source_id = f"{inc_id}@{first_seen}"
        for variant, ts, kind in steps:
            marks.append(
                make_mark(
                    source=SOURCE_NI_INCIDENTS,
                    source_id=source_id,
                    variant=f"{variant}@{ts}",
                    ts=ts,
                    kind=kind,
                    severity=inc.get("severity"),
                    router_id=router_id,
                    routers=routers,
                    fleet=fleet,
                    code=token(inc_type),
                    params=params,
                    ref=ref_of("network_intelligence", "incident", inc_id),
                )
            )
    # Not in time order: a cut read gives no edge; older steps are out of
    # reach (the store holds at most its capacity, so this does not happen).
    cut = total > len(incidents)
    return _finish(SOURCE_NI_INCIDENTS, marks, omitted, cut, unreachable=cut)


# --- security center --------------------------------------------------------------------

_SEC_INCIDENT_KINDS: Final = frozenset(
    {
        "incident_opened",
        "incident_reopened",
        "incident_seen_again",
        "incident_resolved",
        "status",
        "reused",
    }
)


def security_kind(kind: str) -> str:
    """Timeline kind of a Security Center timeline entry."""
    if kind in _SEC_INCIDENT_KINDS:
        return "security_incident"
    if kind == "drift":
        return "config_drift"
    if kind == "traffic_indicator":
        return "traffic_anomaly"
    return "security_event"


async def read_security_timeline(
    hass: HomeAssistant, req: ReadRequest, routers: RouterMap, deadline: float
) -> SourceResult:
    """Security Center timeline, the masked (non-admin) view for everyone."""
    from .security_center import async_get_security_center

    center = async_get_security_center(hass)
    if center is None:
        raise SourceUnreadable(REASON_NOT_RUNNING)
    if center.enabled is not True:
        raise SourceOff(REASON_MODULE_OFF)
    view = center.overview(
        actor=None, since=req.since, until=req.until, limit=SECURITY_READ_LIMIT
    )
    rows = view.get("timeline") if isinstance(view, Mapping) else None
    if not isinstance(rows, list):
        raise SourceUnreadable(REASON_BAD_FORMAT)
    marks: list[dict[str, Any]] = []
    read: list[float] = []
    omitted = 0
    occurrences: dict[str, int] = {}
    resolver = client_resolver(hass, req)
    for row in reversed(rows):  # oldest first: stable occurrence numbers
        _check(deadline)
        if not isinstance(row, Mapping):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        ts, kind = row.get("ts"), row.get("kind")
        if not isinstance(kind, str):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        if not _in_window(ts, req):
            continue
        read.append(ms_floor(float(ts)))
        hexed: str | None = None
        if row.get("has_client") or row.get("client_ref"):
            # Phase E: the row's client_ref is the Security Center's own
            hexed = (
                resolver.resolve("security_center", row.get("client_ref"))
                if resolver is not None
                else None
            )
            if hexed is None:
                omitted += 1
                continue
        router_id = row.get("router_id")
        router_id = router_id if isinstance(router_id, str) else None
        incident_id, drift_id = row.get("incident_id"), row.get("drift_id")
        sec_type = token(row.get("type"))
        base = "\0".join(
            str(x) for x in (ts, kind, router_id, incident_id, drift_id, sec_type)
        )
        nth = occurrences.get(base, 0)
        occurrences[base] = nth + 1
        mapped = security_kind(kind)
        code = token(f"{kind}.{sec_type}" if sec_type else kind)
        if incident_id:
            ref = ref_of("security_center", "incident", incident_id)
        elif drift_id:
            ref = ref_of("security_center", "drift", drift_id)
        else:
            ref = ref_of("security_center", "timeline")
        mark = make_mark(
            source=SOURCE_SECURITY_TIMELINE,
            source_id=base,
            variant=str(nth),
            ts=ts,
            kind=mapped,
            severity=row.get("severity"),
            router_id=router_id,
            routers=routers,
            fleet=router_id is None,
            code=code,
            text=masked_text(row.get("text")),
            ref=ref,
        )
        if hexed is not None and resolver is not None:
            _attribute(mark, resolver, hexed)
        marks.append(mark)
    return _finish(
        SOURCE_SECURITY_TIMELINE,
        marks,
        omitted,
        len(rows) >= SECURITY_READ_LIMIT,
        read,
    )


# --- runner -----------------------------------------------------------------------------

# --- the own index (Phases B/C) ---------------------------------------------------------


def _tm_engine(hass: HomeAssistant) -> Any:
    from .tm_engine import async_get_time_machine

    engine = async_get_time_machine(hass)
    if engine is None:
        raise SourceUnreadable(REASON_NOT_RUNNING)
    if engine.loaded is not True:
        raise SourceUnreadable(REASON_NOT_LOADED)
    return engine


def _peer(router_id: str | None, routers: RouterMap) -> dict[str, Any] | None:
    if router_id is None:
        return None
    return {"router_id": router_id, "router_name": routers.name_of(router_id)}


def _stored_source_id(mark: Any) -> str:
    if mark.ref is not None:
        return f"{mark.ref[0]}:{mark.ref[1]}"
    return f"m{mark.seq}"


def stored_mark_id(mark: Any) -> str:
    """The timeline ``id`` of a stored mark (what :func:`index_mark` gives)."""
    return mark_id(mark.source, _stored_source_id(mark))


def index_mark(
    mark: Any, routers: RouterMap, *, client_name: str | None = None
) -> dict[str, Any]:
    """One stored mark (``tm_marks.Mark``) as a timeline mark.

    ``title_key`` is ``<source>.<kind>`` (the code, e.g. the error type of an
    outage, is the extra field ``code``); a reference mark keeps the key of
    the audit entry it points to (``core_audit.<event type>``) and its
    ``ref``, so it reads like the original.
    """
    source = mark.source
    source_id = _stored_source_id(mark)
    if mark.ref is not None:
        ref = ref_of(
            "core_audit",
            "drift" if mark.kind == "config_drift" else "event",
            mark.ref[1],
        )
        title_key = f"core_audit.{mark.code or 'unknown'}"
    else:
        ref = ref_of("time_machine", "mark", source_id)
        title_key = f"{source}.{mark.kind}"
    out = make_mark(
        source=source,
        source_id=source_id,
        ts=mark.ts,
        kind=mark.kind,
        severity=mark.severity,
        router_id=mark.router,
        routers=routers,
        fleet=mark.router is None,
        code=mark.code,
        params=mark.params,
        ref=ref,
    )
    out["title_key"] = title_key
    out["derived"] = bool(mark.derived)
    out["end"] = mark.end
    out["end_state"] = mark.end_state
    if mark.client is not None:
        out["client"] = f"tmc_{mark.client}"
        out["client_name"] = client_name
    if mark.peers is not None:
        out["peers"] = {
            "before": _peer(mark.peers[0], routers),
            "after": _peer(mark.peers[1], routers),
        }
    return out


# Marks turned into timeline marks between two yields to the event loop
# (review K6: a full client quota is ~10000 marks, ~30 ms in one piece).
INDEX_YIELD_EVERY: Final = 1000


async def _index_marks(
    engine: Any,
    source: str,
    req: ReadRequest,
    routers: RouterMap,
    deadline: float,
    names: Callable[[str | None], str | None] | None = None,
) -> SourceResult:
    """Marks of the window plus the intervals reaching into it (apart)."""
    index = engine.index
    parts: list[list[dict[str, Any]]] = [[], []]
    found = [(m, 0) for m in index.window(source, req.since, req.until)]
    found += [(m, 1) for m in index.spanning_in(source, req.since)]
    for i, (mark, part) in enumerate(found):
        if i % 500 == 0:
            _check(deadline)
        if i and i % INDEX_YIELD_EVERY == 0:
            # the list is taken: a mark added or closed meanwhile does not
            # change this answer's set (a closed one may show its end)
            await asyncio.sleep(0)
        name = names(mark.client) if names is not None and mark.client else None
        item = index_mark(mark, routers, client_name=name)
        item["spans_in"] = part == 1
        parts[part].append(item)
    result = _finish(source, parts[0], 0, False)
    result.spanning = parts[1]
    return result


async def read_tm_index(
    hass: HomeAssistant, req: ReadRequest, routers: RouterMap, deadline: float
) -> SourceResult:
    """Own marks of the window (rights per group in ``tm_query``)."""
    engine = _tm_engine(hass)
    result = await _index_marks(engine, SOURCE_TM_INDEX, req, routers, deadline)
    result.coverage = [
        (float(start), float(end) if end is not None else req.now)
        for start, end in engine.store.coverage
        if start is not None
    ]
    return result


async def read_tm_refs(
    hass: HomeAssistant, req: ReadRequest, routers: RouterMap, deadline: float
) -> SourceResult:
    """Reference marks of audit entries (administrators only, like the audit)."""
    if not req.admin:
        raise SourceOff(REASON_ADMIN_ONLY)
    engine = _tm_engine(hass)
    return await _index_marks(engine, SOURCE_TM_REFS, req, routers, deadline)


async def read_tm_clients(
    hass: HomeAssistant, req: ReadRequest, routers: RouterMap, deadline: float
) -> SourceResult:
    """Client marks (administrators only, only with the client switch on)."""
    if not req.admin:
        raise SourceOff(REASON_ADMIN_ONLY)
    engine = _tm_engine(hass)
    if not engine.clients_wanted:
        raise SourceOff(REASON_CLIENTS_OFF)
    recorder = engine.recorder
    names = recorder.name_of if recorder is not None else None
    return await _index_marks(engine, SOURCE_TM_CLIENTS, req, routers, deadline, names)


READERS: Final[Mapping[str, ReadFn]] = {
    SOURCE_CORE_AUDIT: read_core_audit,
    SOURCE_CONFIG_VERSIONS: read_config_versions,
    SOURCE_NI_EVENTS: read_ni_events,
    SOURCE_NI_INCIDENTS: read_ni_incidents,
    SOURCE_SECURITY_TIMELINE: read_security_timeline,
    SOURCE_TM_INDEX: read_tm_index,
    SOURCE_TM_REFS: read_tm_refs,
    SOURCE_TM_CLIENTS: read_tm_clients,
}


async def async_read_source(
    hass: HomeAssistant,
    source: str,
    req: ReadRequest,
    routers: RouterMap,
    *,
    budget: float = SOURCE_BUDGET_S,
    readers: Mapping[str, ReadFn] | None = None,
) -> SourceResult:
    """Read one source; every failure becomes ``unreadable`` with a fixed reason."""
    reader = (readers or {}).get(source) or READERS[source]
    deadline = time.monotonic() + budget
    try:
        async with asyncio.timeout(budget):
            result = await reader(hass, req, routers, deadline)
    except SourceOff as off:
        return SourceResult(source, STATE_OFF, off.reason)
    except SourceUnreadable as err:
        return SourceResult(source, STATE_UNREADABLE, err.reason)
    except TimeoutError:
        return SourceResult(source, STATE_UNREADABLE, REASON_TIMEOUT)
    except Exception as err:  # noqa: BLE001 - one source never breaks the answer
        _LOGGER.debug(
            "Time Machine: source %s not readable: %s", source, type(err).__name__
        )
        return SourceResult(source, STATE_UNREADABLE, REASON_ERROR)
    if not isinstance(result, SourceResult) or result.source != source:
        return SourceResult(source, STATE_UNREADABLE, REASON_BAD_FORMAT)
    return result
