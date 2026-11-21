"""Network Time Machine, Phase A: one read adapter per source.

Plan ``docs/plans/2026-11-21-network-time-machine.md`` §4 variant (b),
Phase A: a pure read layer over modules that already keep history. No own
store, no router call, no listener, no background task: every adapter reads
the source's public read function once per request and turns its entries
into timeline marks (§5.1).

Sources and their read functions:

* ``core_audit``: ``ConfigurationApi.events`` per audit ring (it has no
  ``until`` and returns oldest first although its docstring says "newest
  first"; both are handled here, the core is not changed).
* ``config_versions``: ``ConfigurationApi.async_list_backups`` (newest
  first, no ``until`` either).
* ``ni_events`` / ``ni_incidents``: ``net_query.events_page`` and
  ``net_query.incidents_page``, the functions behind the Network
  Intelligence routes.
* ``security_timeline``: ``SecurityCenter.overview`` with the masked
  (non-admin) view; only its ``timeline`` is used.

Privacy (plan §6, F3/F4/F5): a mark carries no MAC, IP, host name, SSID or
WLAN netdev name. Routers appear only as the contract ``router_id`` plus the
entry title the sister modules show (dropped when it is an address). An
entry that concerns a client is left out and only counted
(``omitted_client``): Phase A has no client switch. Source texts (Security
Center only) go through the core masking and the identity masking; all
other marks carry fixed codes (``title_key``) and numbers only.

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

from .const import DOMAIN
from .core_errors import ConfigApiError
from .core_masking import redact_text
from .core_models import (
    MAX_LIST_LIMIT,
    OPTION_CONFIG_BACKUP_ENABLED,
    AuditRing,
    BackupRecord,
    CoreEvent,
    VersionStatus,
)

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
REASONS: Final = (
    REASON_NOT_RUNNING,
    REASON_NOT_LOADED,
    REASON_TIMEOUT,
    REASON_ERROR,
    REASON_BAD_FORMAT,
    REASON_MODULE_OFF,
    REASON_ADMIN_ONLY,
)

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
}
KINDS: Final = tuple(KIND_GROUP)
# What a non-admin sees while the panel is open to all users (F4):
# infrastructure (with radio and topology) and disruptions, no clients.
NON_ADMIN_GROUPS: Final = frozenset(
    {GROUP_INFRASTRUCTURE, GROUP_RADIO, GROUP_TOPOLOGY, GROUP_DISRUPTION}
)

# --- limits -----------------------------------------------------------------------------

# Hard caps per source when reading (the source's own list maximum).
AUDIT_READ_LIMIT: Final = MAX_LIST_LIMIT  # per audit ring
VERSIONS_READ_LIMIT: Final = MAX_LIST_LIMIT
NI_EVENTS_READ_LIMIT: Final = 500  # net_query.EVENTS_LIMIT_MAX
NI_INCIDENTS_READ_LIMIT: Final = 200  # net_query.INCIDENTS_LIMIT_MAX
SECURITY_READ_LIMIT: Final = 500
# Marks one source contributes to an answer at most (newest kept).
SOURCE_MARK_CAP: Final = 500
# Time budget of one source (seconds): asyncio timeout around its awaits
# plus a monotonic deadline checked inside its loops.
SOURCE_BUDGET_S: Final = 2.0
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


@dataclass(frozen=True, slots=True)
class RouterMap:
    """``entry_id`` -> contract ``router_id`` and ``router_id`` -> display name."""

    by_entry: Mapping[str, str] = field(default_factory=dict)
    names: Mapping[str, str | None] = field(default_factory=dict)

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
    return RouterMap(by_entry, names)


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
        "ts": round(float(ts), 3),
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
    }


def _check(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise SourceUnreadable(REASON_TIMEOUT)


def _finish(
    source: str, marks: list[dict[str, Any]], omitted: int, truncated: bool
) -> SourceResult:
    marks.sort(key=lambda m: (-m["ts"], m["id"]))
    if len(marks) > SOURCE_MARK_CAP:
        del marks[SOURCE_MARK_CAP:]
        truncated = True
    return SourceResult(
        source,
        STATE_OK if marks else STATE_EMPTY,
        None,
        marks,
        omitted,
        truncated,
        marks[-1]["ts"] if marks else None,
    )


def _in_window(ts: Any, req: ReadRequest) -> bool:
    return (
        isinstance(ts, int | float)
        and not isinstance(ts, bool)
        and req.since <= ts < req.until
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


async def read_core_audit(
    hass: HomeAssistant, req: ReadRequest, routers: RouterMap, deadline: float
) -> SourceResult:
    """Audit entries of both rings (administrators only)."""
    if not req.admin:
        raise SourceOff(REASON_ADMIN_ONLY)
    api = await _config_api(hass)
    since = to_utc(req.since)
    events: dict[str, CoreEvent] = {}
    truncated = False
    for ring in (AuditRing.GENERAL, AuditRing.SECURITY):
        # ``events`` has no ``until`` and sorts oldest first; both rings are
        # read with the list maximum and cut to the window here.
        batch = api.events(since=since, ring=ring, limit=AUDIT_READ_LIMIT)
        if not isinstance(batch, tuple | list):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        truncated = truncated or len(batch) >= AUDIT_READ_LIMIT
        for event in batch:
            if not isinstance(event, CoreEvent):
                raise SourceUnreadable(REASON_BAD_FORMAT)
            events.setdefault(event.event_id, event)
    marks: list[dict[str, Any]] = []
    omitted = 0
    for event in events.values():
        _check(deadline)
        ts = epoch(event.ts)
        if not _in_window(ts, req):
            continue
        if _audit_concerns_client(event):
            omitted += 1
            continue
        kind = audit_kind(str(event.type))
        data = event.data if isinstance(event.data, Mapping) else {}
        params = params_of(data, _AUDIT_PARAMS)
        if event.repeat_count:
            params["repeat_count"] = int(event.repeat_count)
        version_id = data.get("baseline_version_id") or data.get("version_id")
        marks.append(
            make_mark(
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
        )
    return _finish(SOURCE_CORE_AUDIT, marks, omitted, truncated)


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
    for record in records:
        _check(deadline)
        if not isinstance(record, BackupRecord):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        ts = epoch(record.created_at)
        if not _in_window(ts, req):
            continue
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
        SOURCE_CONFIG_VERSIONS, marks, 0, len(records) >= VERSIONS_READ_LIMIT
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
        SOURCE_NI_EVENTS, marks, omitted, page.get("next_before") is not None
    )


async def read_ni_incidents(
    hass: HomeAssistant, req: ReadRequest, routers: RouterMap, deadline: float
) -> SourceResult:
    """Opening, reopening and resolving of NI incidents inside the window."""
    from .net_query import engine_now, incidents_page

    engine = _ni_engine(hass)
    page = incidents_page(
        engine,
        _no_name,
        {"limit": NI_INCIDENTS_READ_LIMIT},
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
    return _finish(SOURCE_NI_INCIDENTS, marks, omitted, total > len(incidents))


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
    omitted = 0
    occurrences: dict[str, int] = {}
    for row in reversed(rows):  # oldest first: stable occurrence numbers
        _check(deadline)
        if not isinstance(row, Mapping):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        ts, kind = row.get("ts"), row.get("kind")
        if not isinstance(kind, str):
            raise SourceUnreadable(REASON_BAD_FORMAT)
        if not _in_window(ts, req):
            continue
        if row.get("has_client") or row.get("client_ref"):
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
        marks.append(
            make_mark(
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
        )
    return _finish(
        SOURCE_SECURITY_TIMELINE, marks, omitted, len(rows) >= SECURITY_READ_LIMIT
    )


# --- runner -----------------------------------------------------------------------------

READERS: Final[Mapping[str, ReadFn]] = {
    SOURCE_CORE_AUDIT: read_core_audit,
    SOURCE_CONFIG_VERSIONS: read_config_versions,
    SOURCE_NI_EVENTS: read_ni_events,
    SOURCE_NI_INCIDENTS: read_ni_incidents,
    SOURCE_SECURITY_TIMELINE: read_security_timeline,
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
    reader = (readers or READERS)[source]
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
