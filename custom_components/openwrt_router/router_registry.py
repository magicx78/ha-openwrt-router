"""Fleet-wide router registry of the enterprise core (contract §4/§5).

One :class:`RouterRegistry` per HA instance keeps a :class:`RouterRecord`
per router, keyed by the stable ``router_id`` (``rtr_…``), with a mapping
config entry -> router id.

* :meth:`RouterRegistry.async_ensure_entry` assigns the id at setup, BEFORE
  the router is contacted (an entry stuck in setup_retry still has its id
  and an ``unverified`` record).
* :meth:`RouterRegistry.attach` registers ONE coordinator listener per
  entry. After every finished poll it reads what the coordinator already
  has (``coordinator.data``, ``coordinator.api.uses_ssh_fallback``,
  ``last_update_success``): reachability, identity, role, firmware and
  capabilities. It makes NO router call. Identity and capabilities are
  recomputed only when a cheap signature of their inputs changes.
* A failed poll keeps the last known identity and capabilities and only
  sets the reachability to offline.
* Removing an entry orphans its record (history stays). Nothing is ever
  merged: shared hardware MACs flag both records ``duplicate_suspected``.
* Adoption (binding an orphaned record to a new entry) is core-internal
  and needs a single-use :class:`WriteAuthorization`.

Store ``openwrt_router.router_registry`` v1.1. An unreadable store is kept
as ``.bak`` and rebuilt: router ids are deterministic per entry, so only
adoption links can be lost; that loss is logged and audited
(``core.store_recovered``).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr

from . import core_store
from .capabilities import (
    ConfigCapabilityProvider,
    capability_signature,
    evaluate,
    merge,
)
from .const import (
    CONF_HOST,
    CONF_PORT,
    CONF_PROTOCOL,
    DOMAIN,
    ROUTER_REGISTRY_SAVE_DELAY_SECONDS,
    ROUTER_REGISTRY_STORE_MINOR_VERSION,
)
from .core_audit import AuditLog
from .core_errors import (
    AuthorizationError,
    CapabilityUnavailableError,
    RouterIdentityError,
    RouterNotFoundError,
)
from .core_models import (
    CONFIG_CAPABILITIES,
    CONFIG_CAPABILITY_NAMESPACE,
    CORE_CAPABILITY_NAMESPACES,
    CORE_OWNED_MODULE_CAPABILITIES,
    CORE_STORE_VERSION,
    MODULE_CAPABILITY_NAMESPACES,
    OPTION_CONFIG_BACKUP_ENABLED,
    ROUTER_ID_PREFIX,
    ROUTER_REGISTRY_STORE_KEY,
    AccessPointInfo,
    Actor,
    AdoptionCandidate,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    ConnectionInfo,
    CoreEventType,
    DeployedAclObservation,
    EmitResult,
    EventResult,
    FirmwareInfo,
    GuardedAction,
    HardwareFingerprint,
    IdentityFlag,
    InterfaceInfo,
    ReachabilityState,
    RecordState,
    RouterIdentity,
    RouterReachability,
    RouterRecord,
    RouterRole,
    Severity,
    Transport,
    WriteAuthorization,
    binding_checksum,
    canonical_checksum,
    is_fleet_router_id,
    is_valid_id,
    normalize_mac,
    utcnow,
)
from .router_identity import (
    alternate_router_id,
    assess,
    derive_role,
    duplicate_groups,
    identity_signature,
    merge_reference,
    observe,
    router_id_for_entry,
)

_LOGGER = logging.getLogger(__name__)

# (authorization, entry_id, orphan_router_id) -> None or AuthorizationError.
# Default: WriteAuthorization._consume; part 2 plugs in guard.consume.
AuthorizationConsumer = Callable[[WriteAuthorization, str, str], None]
# (entry_id, orphan_router_id, actor) -> authorization (part 2: the guard).
AdoptAuthorizer = Callable[[str, str, Actor], Awaitable[WriteAuthorization]]
# (entry_id, router_id, reason) -> None; reason "setup" or "firmware_changed".
# Called from the poll listener (sync, must not block); part 2 probes then.
ProbeListener = Callable[[str, str, str], None]

PROBE_REASON_SETUP = "setup"
PROBE_REASON_FIRMWARE = "firmware_changed"

ORPHAN_ENTRY_REMOVED = "entry_removed"
ORPHAN_ENTRY_MISSING = "entry_missing_at_load"
ORPHAN_REPLACED = "replaced_by_adoption"
ORPHAN_DUPLICATE_BINDING = "duplicate_entry_binding"
_MAX_ID_ATTEMPTS = 16

# Orphaned records are kept for adoption and as history, but not forever
# (review PR #55, finding 6). Applied once per core load, only when the
# config entries AND the version store are known:
# * an orphan WITHOUT versions is forgotten this many days after it was
#   orphaned (adoption happens when a router is re-added, i.e. days, not
#   months, later);
# * above this many orphans the oldest go, those without versions first,
#   so an orphan with (archived) versions always outlives one without.
# A record bound to (or earlier bound to) an existing entry is never dropped.
ORPHAN_RETENTION_DAYS = 90
MAX_ORPHANED_RECORDS = 64
FORGET_AGED = "aged"
FORGET_CAPPED = "capped"


def migrate_registry_store(
    old_major: int, old_minor: int, old_data: Any
) -> dict[str, Any]:
    """Store migration. v1.x: additive minors, fill the routers map."""
    if old_major != CORE_STORE_VERSION or not isinstance(old_data, dict):
        # A newer or foreign major: the loader keeps a .bak and rebuilds.
        raise NotImplementedError(f"registry store version {old_major} unknown")
    data = dict(old_data)
    if not isinstance(data.get("routers"), dict):
        data["routers"] = {}
    return data


def default_consume(
    authorization: WriteAuthorization, entry_id: str, orphan_router_id: str
) -> None:
    """Consume an adopt authorization bound to (entry_id, orphan_router_id)."""
    # core-internal by contract §6.5 (part 2: the guard consumes)
    authorization._consume(
        action=GuardedAction.ADOPT,
        router_id=orphan_router_id,
        checksum=binding_checksum(entry_id, orphan_router_id),
    )


# -- (de)serialisation --------------------------------------------------------------


def _dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("naive timestamp in registry store")
    return parsed


def _s(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value) if value is not None and value != "" else None
    except (TypeError, ValueError):
        return None


def _macs(values: Any) -> frozenset[str]:
    if not isinstance(values, list | tuple):
        return frozenset()
    return frozenset(m for m in (normalize_mac(v) for v in values) if m is not None)


def _flags(values: Any) -> frozenset[IdentityFlag]:
    out: set[IdentityFlag] = set()
    for value in values if isinstance(values, list | tuple) else ():
        try:
            out.add(IdentityFlag(value))
        except ValueError:
            continue  # flag of a newer minor version
    return frozenset(out)


def _enum(enum_cls: Any, value: Any, default: Any) -> Any:
    try:
        return enum_cls(value)
    except ValueError:
        return default


def _identity_from_dict(data: Mapping[str, Any]) -> RouterIdentity:
    fp = data.get("fingerprint") or {}
    return RouterIdentity(
        router_id=data["router_id"],
        entry_id=_s(data.get("entry_id")),
        device_id=_s(data.get("device_id")),
        hostname=_s(data.get("hostname")),
        management_host=_s(data.get("management_host")),
        management_port=_int(data.get("management_port")),
        management_protocol=_s(data.get("management_protocol")),
        mac_addresses=_macs(data.get("mac_addresses")),
        model=_s(data.get("model")),
        board_name=_s(data.get("board_name")),
        architecture=_s(data.get("architecture")),
        openwrt_version=_s(data.get("openwrt_version")),
        openwrt_revision=_s(data.get("openwrt_revision")),
        serial=_s(data.get("serial")),
        role=_enum(RouterRole, data.get("role"), RouterRole.UNKNOWN),
        access_points=tuple(
            AccessPointInfo(
                ifname=str(ap["ifname"]),
                ssid=_s(ap.get("ssid")),
                bssid=normalize_mac(ap.get("bssid")),
                band=_s(ap.get("band")),
            )
            for ap in data.get("access_points") or ()
            if isinstance(ap, Mapping) and ap.get("ifname")
        ),
        interfaces=tuple(
            InterfaceInfo(
                name=str(i["name"]),
                device=_s(i.get("device")),
                mac=normalize_mac(i.get("mac")),
                proto=_s(i.get("proto")),
                up=i.get("up") if isinstance(i.get("up"), bool) else None,
            )
            for i in data.get("interfaces") or ()
            if isinstance(i, Mapping) and i.get("name")
        ),
        first_seen=_dt(data.get("first_seen")),
        last_seen=_dt(data.get("last_seen")),
        fingerprint=HardwareFingerprint.build(
            board_name=_s(fp.get("board_name")),
            model=_s(fp.get("model")),
            macs=fp.get("macs") or (),
        ),
        identity_flags=_flags(data.get("identity_flags")),
    )


def _capability_from_dict(name: str, data: Mapping[str, Any]) -> CapabilityStatus:
    detected = _dt(data.get("detected_at"))
    if detected is None:
        raise ValueError("capability without detected_at")
    detail = data.get("detail")
    return CapabilityStatus(
        capability=name,
        state=CapabilityState(data["state"]),
        reason=str(data.get("reason") or CapabilityReason.NOT_CHECKED),
        source=str(data.get("source") or "store"),
        detected_at=detected,
        reason_text=_s(data.get("reason_text")),
        required_permissions=tuple(
            str(p) for p in data.get("required_permissions") or ()
        ),
        detail=dict(detail) if isinstance(detail, Mapping) else {},
    )


def record_from_dict(data: Mapping[str, Any]) -> RouterRecord:
    """Inverse of ``RouterRecord.to_dict`` (store form)."""
    conn = data.get("connection") or {}
    reach = data.get("reachability") or {}
    fw = data.get("firmware") or {}
    caps = data.get("capabilities") or {}
    capabilities: dict[str, CapabilityStatus] = {}
    for name, raw in caps.items() if isinstance(caps, Mapping) else ():
        if isinstance(raw, Mapping):
            try:
                capabilities[str(name)] = _capability_from_dict(str(name), raw)
            except (ValueError, TypeError, KeyError):
                continue  # re-derived on the next poll
    return RouterRecord(
        identity=_identity_from_dict(data["identity"]),
        state=RecordState(data.get("state", RecordState.ACTIVE)),
        connection=ConnectionInfo(
            host=_s(conn.get("host")),
            port=_int(conn.get("port")),
            protocol=_s(conn.get("protocol")),
            transport=_enum(Transport, conn.get("transport"), Transport.UNKNOWN),
        ),
        reachability=RouterReachability(
            state=_enum(
                ReachabilityState, reach.get("state"), ReachabilityState.UNKNOWN
            ),
            last_success=_dt(reach.get("last_success")),
            last_attempt=_dt(reach.get("last_attempt")),
        ),
        firmware=FirmwareInfo(
            **{
                key: _s(fw.get(key))
                for key in (
                    "distribution",
                    "version",
                    "revision",
                    "target",
                    "kernel",
                    "architecture",
                    "board_name",
                    "package_manager",
                )
            }
        ),
        capabilities=capabilities,
        registered_at=_dt(data.get("registered_at")),
        orphaned_at=_dt(data.get("orphaned_at")),
        adopted_at=_dt(data.get("adopted_at")),
        previous_entry_ids=tuple(
            str(e) for e in data.get("previous_entry_ids") or () if e
        ),
    )


# -- runtime state per loaded entry ---------------------------------------------------


@dataclass(slots=True)
class _Runtime:
    """In-memory state of one attached entry (never stored)."""

    entry_id: str
    host: str | None = None
    port: int | None = None
    protocol: str | None = None
    # Option config_backup_enabled; default OFF since 1.44.0.
    config_enabled: bool = False
    # Deployed rpcd ACL seen at entry setup (rf.* capabilities); None = not yet.
    acl: DeployedAclObservation | None = None
    coordinator: Any = None
    remove_listener: Callable[[], None] | None = None
    identity_sig: tuple[Any, ...] | None = None
    cap_sig: tuple[Any, ...] | None = None
    ssh_seen: bool = False
    observed_macs: frozenset[str] | None = None
    polls: int = 0
    failed_polls: int = 0
    # (router_id, firmware version) of the last probe trigger; None = attach.
    probe_sig: tuple[str, str | None] | None = None
    stats: dict[str, int] = field(default_factory=dict)


# Module capability detector: (record, coordinator data) -> {name: status}.
CapabilityDetector = Callable[[RouterRecord, Any], Mapping[str, CapabilityStatus]]
DetectorSignature = Callable[[Any], Any]


@dataclass(frozen=True, slots=True)
class _Detector:
    """One registered module capability detector."""

    module: str
    prefix: str
    run: CapabilityDetector
    signature: DetectorSignature | None


@dataclass(frozen=True, slots=True)
class AttachedRouter:
    """Live handles of an attached entry (core-internal, never stored)."""

    router_id: str
    entry_id: str
    coordinator: Any
    config_enabled: bool


class RouterRegistry:
    """Router records of all config entries (implements RouterRegistryProtocol)."""

    def __init__(self, hass: HomeAssistant, audit: AuditLog) -> None:
        """Create an empty registry; call :meth:`async_load` before use."""
        self.hass = hass
        self.audit = audit
        self._store: Any = core_store.create_store(
            hass,
            CORE_STORE_VERSION,
            ROUTER_REGISTRY_STORE_KEY,
            minor_version=ROUTER_REGISTRY_STORE_MINOR_VERSION,
            migrate=migrate_registry_store,
        )
        self._lock = asyncio.Lock()
        self._records: dict[str, RouterRecord] = {}
        self._entry_map: dict[str, str] = {}
        self._runtime: dict[str, _Runtime] = {}
        # last KNOWN state per router and capability (merge, finding 16)
        self._last_known_caps: dict[str, dict[str, Any]] = {}
        self._config_provider: ConfigCapabilityProvider | None = None
        self._provider_revision = 0
        # Module capability detectors (1.44.0): module -> detector. Sync, no
        # I/O; they run only when the capability signature changes.
        self._detectors: dict[str, _Detector] = {}
        self._adopt_authorizer: AdoptAuthorizer | None = None
        self._consume: AuthorizationConsumer = default_consume
        self._probe_listener: ProbeListener | None = None
        self.loaded = False
        self.load_failed = False
        self.backed_up = False
        self.dirty = False
        self._save_pending = False
        self._closed = False
        self._listener_error_logged = False
        self.stats: dict[str, int] = {
            "polls": 0,
            "failed_polls": 0,
            "identity_evaluations": 0,
            "capability_evaluations": 0,
            "capability_changes": 0,
            "capability_first_detections": 0,
            "capability_kept_stale": 0,
            "listener_errors": 0,
            "polls_without_record": 0,
            "store_saves_scheduled": 0,
            "store_saves_immediate": 0,
            "records_skipped_on_load": 0,
            "orphaned_at_load": 0,
            "fingerprint_macs_dropped": 0,
            "ignored_local_macs": 0,
            "id_collisions": 0,
            "device_lookups": 0,
            "device_lookup_errors": 0,
            "probe_triggers": 0,
            "probe_listener_errors": 0,
            "config_option_changes": 0,
            "acl_observations": 0,
            "detectors_registered": 0,
            "detector_runs": 0,
            "detector_errors": 0,
            "detector_entries_refused": 0,
            "runtimes_released": 0,
            "orphans_forgotten_aged": 0,
            "orphans_forgotten_capped": 0,
            "orphan_prune_skipped": 0,
        }
        self.timing: dict[str, float] = {"runs": 0, "total_s": 0.0, "max_s": 0.0}

    # -- load / save -------------------------------------------------------------------

    async def async_load(self, known_entry_ids: Iterable[str] | None = None) -> None:
        """Read the store once (idempotent) and reconcile with known entries.

        ``known_entry_ids``: ids of ALL config entries of the domain (also
        disabled ones). Active records of entries that no longer exist are
        orphaned; with no known entries nothing is orphaned (a half-started
        HA must not orphan the fleet).
        """
        async with self._lock:
            if self.loaded:
                return
            result = await core_store.async_load_store(
                self.hass, self._store, ROUTER_REGISTRY_STORE_KEY
            )
            self.load_failed = result.failed
            self.backed_up = result.backed_up
            routers = (result.data or {}).get("routers")
            if isinstance(routers, Mapping):
                self._restore(routers)
            self._rebuild_entry_map()
            self.loaded = True
        if self.load_failed:
            self._report_store_recovered()
        elif self.stats["records_skipped_on_load"]:
            self._emit(
                CoreEventType.STORE_RECOVERED,
                severity=Severity.WARNING,
                result=EventResult.FAILURE,
                data={
                    "store": ROUTER_REGISTRY_STORE_KEY,
                    "backup_written": False,
                    "records_skipped": self.stats["records_skipped_on_load"],
                },
            )
        known = {e for e in (known_entry_ids or ()) if isinstance(e, str) and e}
        if known:
            for record in list(self._records.values()):
                entry_id = record.entry_id
                if entry_id is not None and entry_id not in known:
                    self.stats["orphaned_at_load"] += 1
                    self._orphan(record.router_id, ORPHAN_ENTRY_MISSING)
            if self.stats["orphaned_at_load"]:
                self.schedule_save()

    def _restore(self, routers: Mapping[str, Any]) -> None:
        for key, raw in routers.items():
            try:
                record = record_from_dict(raw)
            except (ValueError, TypeError, KeyError, AttributeError):
                self.stats["records_skipped_on_load"] += 1
                _LOGGER.warning(
                    "Router registry: record %s unreadable, skipped (its id comes "
                    "back on the next setup; an adoption link of it is lost)",
                    key,
                    exc_info=True,
                )
                continue
            self._records[record.router_id] = record

    def _rebuild_entry_map(self) -> None:
        """entry_id -> router id from ACTIVE records; never two per entry."""
        self._entry_map.clear()
        by_entry: dict[str, list[RouterRecord]] = {}
        for record in self._records.values():
            if record.entry_id is not None:
                by_entry.setdefault(record.entry_id, []).append(record)
        for entry_id, records in by_entry.items():
            records.sort(
                key=lambda r: (
                    r.adopted_at is None,
                    r.registered_at or utcnow(),
                    r.router_id,
                )
            )
            self._entry_map[entry_id] = records[0].router_id
            for extra in records[1:]:
                _LOGGER.warning(
                    "Router registry: %s and %s were both bound to one entry; "
                    "%s is orphaned (nothing merged)",
                    records[0].router_id,
                    extra.router_id,
                    extra.router_id,
                )
                self._orphan(extra.router_id, ORPHAN_DUPLICATE_BINDING)

    def _report_store_recovered(self) -> None:
        """Audit the rebuild and name the adoption links that were lost."""
        lost: list[str] = []
        try:
            for event in self.audit.events(types=[CoreEventType.ROUTER_ADOPTED]):
                if event.router_id and event.router_id not in lost:
                    lost.append(event.router_id)
        except Exception:
            _LOGGER.warning(
                "Could not read adoptions from the audit log", exc_info=True
            )
        _LOGGER.warning(
            "Router registry store was rebuilt (backup kept: %s). Router ids "
            "are recreated per entry; %d adoption link(s) known from the audit "
            "log are lost and must be adopted again: %s",
            self.backed_up,
            len(lost),
            ", ".join(lost) or "-",
        )
        self._emit(
            CoreEventType.STORE_RECOVERED,
            severity=Severity.WARNING,
            result=EventResult.FAILURE,
            data={
                "store": ROUTER_REGISTRY_STORE_KEY,
                "backup_written": self.backed_up,
                "adoption_links_lost": len(lost),
                "lost_router_ids": lost,
            },
        )

    @callback
    def schedule_save(self, *, immediate: bool = False) -> None:
        """Mark the registry dirty and write it after the save delay."""
        self.dirty = True
        if self._closed:
            return
        if immediate:
            self.stats["store_saves_immediate"] += 1
            self.hass.async_create_task(self.async_flush())
            return
        if self._save_pending:
            return
        self._save_pending = True
        self.stats["store_saves_scheduled"] += 1
        self._store.async_delay_save(
            self._data_to_save, ROUTER_REGISTRY_SAVE_DELAY_SECONDS
        )

    async def async_flush(self) -> None:
        """Write the store now."""
        await self._store.async_save(self._data_to_save())

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        self._save_pending = False
        self.dirty = False
        return {
            "routers": {
                rid: record.to_dict() for rid, record in sorted(self._records.items())
            }
        }

    @callback
    def close(self) -> None:
        """Detach every coordinator listener; no further writes are scheduled."""
        for entry_id in list(self._runtime):
            self.detach(entry_id)
        self._runtime.clear()
        self._probe_listener = None
        self._closed = True

    # -- entries ------------------------------------------------------------------------

    @callback
    def ensure_entry(self, entry: ConfigEntry) -> RouterRecord:
        """Return the entry's record; create it (unverified) if needed.

        Works without any router contact. Idempotent. Never merges: if the
        entry's default id is taken by another record, it gets an alternate
        deterministic id (logged and counted).
        """
        entry_id = entry.entry_id
        data = entry.data if isinstance(entry.data, Mapping) else {}
        options = entry.options if isinstance(entry.options, Mapping) else {}
        host = _s(data.get(CONF_HOST))
        port = _int(data.get(CONF_PORT))
        protocol = _s(data.get(CONF_PROTOCOL))
        runtime = self._runtime.setdefault(entry_id, _Runtime(entry_id))
        runtime.host, runtime.port, runtime.protocol = host, port, protocol
        runtime.config_enabled = options.get(OPTION_CONFIG_BACKUP_ENABLED) is True

        rid = self._entry_map.get(entry_id)
        if rid is not None:
            record = self._records[rid]
            if (record.connection.host, record.connection.port) != (host, port) or (
                record.connection.protocol != protocol
            ):
                record = replace(
                    record,
                    connection=replace(
                        record.connection, host=host, port=port, protocol=protocol
                    ),
                )
                self._records[rid] = record
                self.schedule_save()
            return record

        now = utcnow()
        connection = ConnectionInfo(host=host, port=port, protocol=protocol)
        restored = self._orphan_of_entry(entry_id)
        if restored is not None:
            # The entry came back (HA backup restore): reactivate its record.
            record = replace(
                restored,
                state=RecordState.ACTIVE,
                orphaned_at=None,
                connection=connection,
            )
            self._records[record.router_id] = record
            self._entry_map[entry_id] = record.router_id
            self._emit(
                CoreEventType.ROUTER_REGISTERED,
                router_id=record.router_id,
                entry_id=entry_id,
                data={"reactivated": True},
            )
            self.schedule_save(immediate=True)
            return record

        rid = router_id_for_entry(entry_id)
        attempt = 0
        while rid in self._records and attempt < _MAX_ID_ATTEMPTS:
            attempt += 1
            self.stats["id_collisions"] += 1
            rid = alternate_router_id(entry_id, attempt)
        if rid in self._records:
            raise RouterIdentityError(
                "no free router id for the entry", details={"attempts": attempt}
            )
        if attempt:
            _LOGGER.warning(
                "Router id of entry %s was taken by another record; using %s "
                "(nothing merged)",
                entry_id,
                rid,
            )
        record = RouterRecord(
            identity=RouterIdentity(
                router_id=rid,
                entry_id=entry_id,
                management_host=host,
                management_port=port,
                management_protocol=protocol,
            ),
            connection=connection,
            registered_at=now,
        )
        self._records[rid] = record
        self._entry_map[entry_id] = rid
        self._emit(
            CoreEventType.ROUTER_REGISTERED,
            router_id=rid,
            entry_id=entry_id,
            data={"id_attempts": attempt},
        )
        self.schedule_save()
        return record

    async def async_ensure_entry(self, entry: ConfigEntry) -> RouterRecord:
        """Load if needed, then :meth:`ensure_entry`."""
        await self.async_load()
        return self.ensure_entry(entry)

    def _orphan_of_entry(self, entry_id: str) -> RouterRecord | None:
        candidates = [
            r
            for r in self._records.values()
            if r.state is RecordState.ORPHANED and r.identity.entry_id == entry_id
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda r: r.orphaned_at or utcnow(), reverse=True)
        return candidates[0]

    @callback
    def attach(self, entry: ConfigEntry, coordinator: Any) -> Callable[[], None]:
        """Listen to the entry's coordinator; returns an idempotent remover.

        The remover is also registered with ``entry.async_on_unload``.
        """
        entry_id = entry.entry_id
        if entry_id not in self._entry_map:
            self.ensure_entry(entry)
        self.detach(entry_id)
        runtime = self._runtime.setdefault(entry_id, _Runtime(entry_id))
        runtime.coordinator = coordinator
        runtime.identity_sig = None
        runtime.cap_sig = None
        runtime.probe_sig = None

        @callback
        def _on_update() -> None:
            self._on_poll(entry_id)

        remove = coordinator.async_add_listener(_on_update)
        removed = False

        @callback
        def _remove_once() -> None:
            nonlocal removed
            if removed:
                return
            removed = True
            if runtime.remove_listener is _remove_once:
                runtime.remove_listener = None
                runtime.coordinator = None
            remove()

        runtime.remove_listener = _remove_once
        entry.async_on_unload(_remove_once)
        # The first refresh already ran before the attach: use its data now.
        self._on_poll(entry_id)
        return _remove_once

    @callback
    def detach(self, entry_id: str) -> None:
        """Remove the coordinator listener of ``entry_id`` (idempotent)."""
        runtime = self._runtime.get(entry_id)
        if runtime is not None and runtime.remove_listener is not None:
            runtime.remove_listener()

    @callback
    def release_entry(self, entry_id: str) -> None:
        """Detach and drop the entry's runtime state (unload; idempotent).

        The record stays; the next setup creates the runtime again. Until
        then :meth:`config_enabled` reads the option from the config entry.
        """
        self.detach(entry_id)
        if self._runtime.pop(entry_id, None) is not None:
            self.stats["runtimes_released"] += 1

    @property
    def attached_entry_ids(self) -> frozenset[str]:
        """Entries with a live coordinator listener."""
        return frozenset(
            e for e, rt in self._runtime.items() if rt.remove_listener is not None
        )

    # -- the poll listener ------------------------------------------------------------------

    @callback
    def _on_poll(self, entry_id: str) -> None:
        """One finished poll of ``entry_id``. Never raises, never calls the router."""
        started = time.perf_counter()
        try:
            self._process_poll(entry_id)
        except Exception:
            self.stats["listener_errors"] += 1
            if not self._listener_error_logged:
                self._listener_error_logged = True
                _LOGGER.warning(
                    "Enterprise core: processing a poll of %s failed (poll and "
                    "entities are not affected; further errors are counted)",
                    entry_id,
                    exc_info=True,
                )
            else:
                _LOGGER.debug(
                    "Enterprise core poll error for %s", entry_id, exc_info=True
                )
        finally:
            elapsed = time.perf_counter() - started
            self.timing["runs"] += 1
            self.timing["total_s"] += elapsed
            self.timing["max_s"] = max(self.timing["max_s"], elapsed)

    def _process_poll(self, entry_id: str) -> None:
        runtime = self._runtime.get(entry_id)
        rid = self._entry_map.get(entry_id)
        if runtime is None or rid is None or self._closed:
            self.stats["polls_without_record"] += 1
            return
        coordinator = runtime.coordinator
        if coordinator is None:
            return
        record = self._records[rid]
        now = utcnow()
        success = coordinator.last_update_success is True
        data = getattr(coordinator, "data", None)
        if success and data is None:
            return  # no poll finished yet
        self.stats["polls"] += 1
        runtime.polls += 1
        old_state = record.reachability.state
        if success:
            reach = RouterReachability(
                state=ReachabilityState.ONLINE, last_success=now, last_attempt=now
            )
        else:
            self.stats["failed_polls"] += 1
            runtime.failed_polls += 1
            reach = RouterReachability(
                state=ReachabilityState.OFFLINE,
                last_success=record.reachability.last_success,
                last_attempt=now,
            )
        record = replace(record, reachability=reach)
        self._records[rid] = record
        if reach.state is not old_state:
            self.schedule_save()
        if not success:
            return  # keep the last known identity and capabilities

        api = getattr(coordinator, "api", None)
        uses_ssh = getattr(api, "uses_ssh_fallback", False) is True
        if uses_ssh:
            runtime.ssh_seen = True
        transport = Transport.SSH_FALLBACK if uses_ssh else Transport.UBUS
        if record.connection.transport is not transport:
            record = replace(
                record, connection=replace(record.connection, transport=transport)
            )
            self._records[rid] = record
            self.schedule_save()

        signature = identity_signature(data, runtime.host)
        if signature != runtime.identity_sig:
            runtime.identity_sig = signature
            self._update_identity(rid, runtime, data, now)
        else:
            identity = replace(self._records[rid].identity, last_seen=now)
            self._records[rid] = replace(self._records[rid], identity=identity)

        cap_sig = capability_signature(
            data,
            uses_ssh_fallback=uses_ssh,
            ssh_seen=runtime.ssh_seen,
            config_enabled=runtime.config_enabled,
            provider_token=self._provider_revision,
            acl=runtime.acl,
        ) + self._detector_signature(data)
        if cap_sig != runtime.cap_sig:
            runtime.cap_sig = cap_sig
            self._update_capabilities(rid, runtime, data, uses_ssh, now)

        if self._records[rid].identity.device_id is None:
            self._update_device_id(rid, entry_id)
        self._check_probe_trigger(entry_id, rid, runtime)

    def _check_probe_trigger(self, entry_id: str, rid: str, runtime: _Runtime) -> None:
        """Tell the probe listener about a new attach or a firmware change.

        Tracked with or without a listener, so registering a provider later
        does not look like a new attach; the provider side probes all
        attached routers itself when it registers.
        """
        signature = (rid, self._records[rid].firmware.version)
        previous = runtime.probe_sig
        if signature == previous:
            return
        runtime.probe_sig = signature
        reason = (
            PROBE_REASON_FIRMWARE
            if previous is not None and previous[0] == rid
            else PROBE_REASON_SETUP
        )
        listener = self._probe_listener
        if listener is None:
            return
        self.stats["probe_triggers"] += 1
        try:
            listener(entry_id, rid, reason)
        except Exception:
            self.stats["probe_listener_errors"] += 1
            _LOGGER.warning("Probe trigger for %s failed", rid, exc_info=True)

    def _update_device_id(self, rid: str, entry_id: str) -> None:
        """device_id of the entry's device ``(DOMAIN, entry_id)``; read only.

        Same lookup as the coordinator: ``async_get_device_by_identifier``
        (HA 2026.8+) in the entry's own devices; older cores (floor 2026.2)
        only have ``async_get_device`` (deprecated, removed in 2027.8).
        """
        self.stats["device_lookups"] += 1
        identifier = (DOMAIN, entry_id)
        try:
            dev_reg = dr.async_get(self.hass)
            get_by_identifier = getattr(dev_reg, "async_get_device_by_identifier", None)
            if get_by_identifier is not None:
                device = get_by_identifier(identifier, entry_id)
            else:
                device = dev_reg.async_get_device(identifiers={identifier})
        except Exception:
            self.stats["device_lookup_errors"] += 1
            _LOGGER.debug(
                "Device registry lookup failed for %s", entry_id, exc_info=True
            )
            return
        if device is None:
            return
        record = self._records[rid]
        self._records[rid] = replace(
            record, identity=replace(record.identity, device_id=device.id)
        )
        self.schedule_save()

    def _update_identity(
        self, rid: str, runtime: _Runtime, data: Any, now: datetime
    ) -> None:
        self.stats["identity_evaluations"] += 1
        record = self._records[rid]
        identity = record.identity
        obs = observe(data, management_host=runtime.host)
        self.stats["ignored_local_macs"] += obs.ignored_local_macs
        result = assess(
            flags=identity.identity_flags,
            reference=identity.fingerprint,
            previous_hostname=identity.hostname,
            previous_version=identity.openwrt_version,
            previous_host=identity.management_host,
            observation=obs,
            management_host=runtime.host,
        )
        reference = identity.fingerprint
        if result.update_reference:
            reference, dropped = merge_reference(reference, obs.fingerprint)
            self.stats["fingerprint_macs_dropped"] += dropped
        if obs.identifying:
            runtime.observed_macs = obs.fingerprint.macs
        new_identity = replace(
            identity,
            hostname=obs.hostname or identity.hostname,
            management_host=runtime.host,
            management_port=runtime.port,
            management_protocol=runtime.protocol,
            mac_addresses=obs.fingerprint.macs or identity.mac_addresses,
            model=obs.model or identity.model,
            board_name=obs.board_name or identity.board_name,
            architecture=obs.architecture or identity.architecture,
            openwrt_version=obs.openwrt_version or identity.openwrt_version,
            openwrt_revision=obs.openwrt_revision or identity.openwrt_revision,
            role=derive_role(data, runtime.host, identity.role),
            access_points=obs.access_points or identity.access_points,
            interfaces=obs.interfaces or identity.interfaces,
            first_seen=identity.first_seen or (now if obs.has_data else None),
            last_seen=now,
            fingerprint=reference,
            identity_flags=result.flags,
        )
        firmware = replace(
            record.firmware,
            distribution=obs.distribution or record.firmware.distribution,
            version=obs.openwrt_version or record.firmware.version,
            revision=obs.openwrt_revision or record.firmware.revision,
            target=obs.target or record.firmware.target,
            kernel=obs.kernel or record.firmware.kernel,
            architecture=obs.architecture or record.firmware.architecture,
            board_name=obs.board_name or record.firmware.board_name,
        )
        self._records[rid] = replace(record, identity=new_identity, firmware=firmware)
        if _stored_identity(new_identity) != _stored_identity(identity) or (
            firmware != record.firmware
        ):
            self.schedule_save()

        entry_id = runtime.entry_id
        if result.hardware_changed:
            _LOGGER.warning(
                "Router %s (entry %s): the hardware does not match the known "
                "device (swap suspected); id kept, flagged 'changed'",
                rid,
                entry_id,
            )
            self._emit(
                CoreEventType.ROUTER_IDENTITY_CHANGED,
                router_id=rid,
                entry_id=entry_id,
                severity=Severity.WARNING,
                dedup_key="hardware_changed",
                data={
                    "change": "hardware_changed",
                    "shared_mac_count": result.shared_mac_count,
                    "board_changed": bool(
                        identity.fingerprint.board_name
                        and obs.board_name
                        and identity.fingerprint.board_name != obs.board_name
                    ),
                },
            )
        if result.hardware_restored:
            self._emit(
                CoreEventType.ROUTER_IDENTITY_CHANGED,
                router_id=rid,
                entry_id=entry_id,
                dedup_key="hardware_restored",
                data={
                    "change": "hardware_restored",
                    "shared_mac_count": result.shared_mac_count,
                },
            )
        if result.changed_fields:
            self._emit(
                CoreEventType.ROUTER_IDENTITY_CHANGED,
                router_id=rid,
                entry_id=entry_id,
                data={
                    "change": "attributes",
                    "changed_fields": list(result.changed_fields),
                    "factory_reset_suspected": result.factory_reset_suspected,
                },
            )
        if result.flags != identity.identity_flags or obs.identifying:
            self._check_duplicates()

    def _update_capabilities(
        self, rid: str, runtime: _Runtime, data: Any, uses_ssh: bool, now: datetime
    ) -> None:
        self.stats["capability_evaluations"] += 1
        record = self._records[rid]
        fresh = evaluate(
            data,
            uses_ssh_fallback=uses_ssh,
            ssh_seen=runtime.ssh_seen,
            now=now,
            record=record,
            config_enabled=runtime.config_enabled,
            provider=self._config_provider,
            acl=runtime.acl,
        )
        fresh.update(self._run_detectors(record, data))
        result = merge(
            record.capabilities,
            fresh,
            last_known=self._last_known_caps.setdefault(rid, {}),
        )
        self.stats["capability_kept_stale"] += result.kept_stale
        self.stats["capability_first_detections"] += result.first_detections
        updates = getattr(data, "updates_available", None)
        manager = (
            updates.get("package_manager") if isinstance(updates, Mapping) else None
        )
        firmware = record.firmware
        if manager in ("apk", "opkg") and firmware.package_manager != manager:
            firmware = replace(firmware, package_manager=manager)
        if result.stored_changed or firmware != record.firmware:
            self._records[rid] = replace(
                record, capabilities=result.capabilities, firmware=firmware
            )
            self.schedule_save()
        if result.changes:
            self.stats["capability_changes"] += len(result.changes)
            self._emit(
                CoreEventType.ROUTER_CAPABILITIES_CHANGED,
                router_id=rid,
                entry_id=runtime.entry_id,
                dedup_key=canonical_checksum(result.changes)[:16],
                data={"changes": result.changes, "changed_count": len(result.changes)},
            )

    def _check_duplicates(self) -> None:
        """Flag every ACTIVE router that shares hardware MACs with another."""
        mac_sets: dict[str, frozenset[str]] = {}
        for entry_id, rid in self._entry_map.items():
            runtime = self._runtime.get(entry_id)
            observed = runtime.observed_macs if runtime is not None else None
            macs = (
                observed
                if observed is not None
                else self._records[rid].identity.fingerprint.macs
            )
            if macs:
                mac_sets[rid] = macs
        groups = duplicate_groups(mac_sets)
        for rid in list(self._entry_map.values()):
            record = self._records[rid]
            flags = record.identity.identity_flags
            others = groups.get(rid)
            flagged = IdentityFlag.DUPLICATE_SUSPECTED in flags
            if others and not flagged:
                self._set_flags(rid, flags | {IdentityFlag.DUPLICATE_SUSPECTED})
                _LOGGER.warning(
                    "Router %s shares hardware MACs with %s: duplicate suspected "
                    "(nothing merged)",
                    rid,
                    ", ".join(sorted(others)),
                )
                self._emit(
                    CoreEventType.ROUTER_DUPLICATE_SUSPECTED,
                    router_id=rid,
                    entry_id=record.entry_id,
                    severity=Severity.WARNING,
                    dedup_key="|".join(sorted(others)),
                    data={
                        "other_router_ids": sorted(others),
                        "shared_mac_count": sum(others.values()),
                    },
                )
            elif not others and flagged:
                self._set_flags(rid, flags - {IdentityFlag.DUPLICATE_SUSPECTED})
                self._emit(
                    CoreEventType.ROUTER_IDENTITY_CHANGED,
                    router_id=rid,
                    entry_id=record.entry_id,
                    dedup_key="duplicate_cleared",
                    data={"change": "duplicate_cleared"},
                )

    def _set_flags(self, rid: str, flags: frozenset[IdentityFlag]) -> None:
        record = self._records[rid]
        self._records[rid] = replace(
            record, identity=replace(record.identity, identity_flags=flags)
        )
        self.schedule_save()

    # -- orphaning / adoption ----------------------------------------------------------------

    def _orphan(self, rid: str, reason: str) -> RouterRecord:
        record = self._records[rid]
        if record.state is RecordState.ORPHANED:
            return record
        entry_id = record.entry_id
        record = replace(record, state=RecordState.ORPHANED, orphaned_at=utcnow())
        self._records[rid] = record
        if entry_id is not None and self._entry_map.get(entry_id) == rid:
            del self._entry_map[entry_id]
        self._emit(
            CoreEventType.ROUTER_ORPHANED,
            router_id=rid,
            entry_id=entry_id,
            data={"reason": reason},
        )
        return record

    async def async_orphan_entry(
        self, entry_id: str, *, reason: str = ORPHAN_ENTRY_REMOVED
    ) -> RouterRecord | None:
        """Orphan the entry's record (history stays); saved right away."""
        await self.async_load()
        self.detach(entry_id)
        self._runtime.pop(entry_id, None)
        rid = self._entry_map.get(entry_id)
        if rid is None:
            return None
        record = self._orphan(rid, reason)
        self._check_duplicates()
        self.stats["store_saves_immediate"] += 1
        await self.async_flush()
        return record

    @callback
    def prune_orphans(
        self,
        known_entry_ids: Iterable[str],
        versioned_router_ids: Iterable[str] | None,
        *,
        now: datetime | None = None,
    ) -> tuple[str, ...]:
        """Forget aged orphans and the oldest above the cap; returns dropped ids.

        ``known_entry_ids``: ALL config entries of the domain. Empty means a
        half-started HA: nothing is dropped. ``versioned_router_ids``: routers
        with versions in the version store (archived ones included); None
        (store not loaded) drops nothing. Both skips are counted. Every drop
        is counted, logged and audited (``router.forgotten``).
        """
        known = {e for e in known_entry_ids if isinstance(e, str) and e}
        if not known or versioned_router_ids is None:
            self.stats["orphan_prune_skipped"] += 1
            return ()
        versioned = set(versioned_router_ids)
        now = now or utcnow()
        cutoff = now - timedelta(days=ORPHAN_RETENTION_DAYS)
        orphans = [r for r in self._records.values() if r.state is RecordState.ORPHANED]
        droppable: list[RouterRecord] = []
        for record in orphans:
            bound = {record.identity.entry_id, *record.previous_entry_ids}
            if not bound & known:
                droppable.append(record)
        drops: list[tuple[RouterRecord, str]] = []
        kept: list[RouterRecord] = []
        for record in droppable:
            if (
                record.router_id not in versioned
                and record.orphaned_at is not None
                and record.orphaned_at < cutoff
            ):
                drops.append((record, FORGET_AGED))
            else:
                kept.append(record)
        excess = len(orphans) - len(drops) - MAX_ORPHANED_RECORDS
        if excess > 0:
            # versionless first, then oldest first (unknown age = oldest)
            kept.sort(
                key=lambda r: (
                    r.router_id in versioned,
                    r.orphaned_at or datetime.min.replace(tzinfo=UTC),
                    r.router_id,
                )
            )
            drops.extend((record, FORGET_CAPPED) for record in kept[:excess])
        for record, reason in drops:
            self._forget(record, reason, has_versions=record.router_id in versioned)
        if drops:
            _LOGGER.info(
                "Router registry: forgot %d orphaned record(s): %d without "
                "versions orphaned more than %d days ago, %d over the cap of %d "
                "orphans (see router.forgotten in the audit log)",
                len(drops),
                sum(1 for _, reason in drops if reason == FORGET_AGED),
                ORPHAN_RETENTION_DAYS,
                sum(1 for _, reason in drops if reason == FORGET_CAPPED),
                MAX_ORPHANED_RECORDS,
            )
            self.schedule_save()
        return tuple(record.router_id for record, _ in drops)

    def _forget(self, record: RouterRecord, reason: str, *, has_versions: bool) -> None:
        rid = record.router_id
        del self._records[rid]
        self._last_known_caps.pop(rid, None)
        self.stats[f"orphans_forgotten_{reason}"] += 1
        self._emit(
            CoreEventType.ROUTER_FORGOTTEN,
            router_id=rid,
            data={
                "reason": reason,
                "orphaned_at": (
                    record.orphaned_at.isoformat() if record.orphaned_at else None
                ),
                "has_versions": has_versions,
                "last_entry_id": record.identity.entry_id,
                "retention_days": ORPHAN_RETENTION_DAYS,
                "max_orphans": MAX_ORPHANED_RECORDS,
            },
        )

    def adoption_candidates(self, entry_id: str) -> tuple[AdoptionCandidate, ...]:
        """Orphaned records sharing hardware MACs with the entry's router."""
        record = self.get_by_entry(entry_id)
        runtime = self._runtime.get(entry_id)
        macs = (
            runtime.observed_macs
            if runtime is not None and runtime.observed_macs is not None
            else record.identity.fingerprint.macs
        )
        current = record.identity.fingerprint
        out: list[AdoptionCandidate] = []
        for orphan in self._records.values():
            if orphan.state is not RecordState.ORPHANED:
                continue
            fp = orphan.identity.fingerprint
            shared = macs & fp.macs
            if not shared:
                continue
            out.append(
                AdoptionCandidate(
                    router_id=orphan.router_id,
                    identity=orphan.identity,
                    matched_macs=shared,
                    board_match=bool(
                        fp.board_name and fp.board_name == current.board_name
                    ),
                    model_match=bool(fp.model and fp.model == current.model),
                    orphaned_at=orphan.orphaned_at,
                )
            )
        out.sort(key=lambda c: (-len(c.matched_macs), c.router_id))
        return tuple(out)

    async def async_adopt(
        self, entry_id: str, orphan_router_id: str, *, actor: Actor
    ) -> RouterRecord:
        """Protocol entry point: needs the guard (part 2) to authorize."""
        if self._adopt_authorizer is None:
            error = AuthorizationError(
                "Adoption needs the action guard, which is not available yet",
                router_id=orphan_router_id,
                details={"reason": "guard_unavailable"},
            )
            self._emit(
                CoreEventType.AUTHORIZATION_DENIED,
                router_id=orphan_router_id,
                entry_id=entry_id,
                actor=actor,
                severity=Severity.WARNING,
                result=EventResult.DENIED,
                data={
                    "action": GuardedAction.ADOPT.value,
                    "reason": "guard_unavailable",
                },
            )
            raise error
        authorization = await self._adopt_authorizer(entry_id, orphan_router_id, actor)
        return await self.async_adopt_authorized(
            entry_id, orphan_router_id, authorization=authorization
        )

    async def async_adopt_authorized(
        self,
        entry_id: str,
        orphan_router_id: str,
        *,
        authorization: WriteAuthorization,
    ) -> RouterRecord:
        """Bind the orphaned record to ``entry_id`` (core-internal).

        The entry's current record becomes orphaned (never merged); the
        adopted record takes over the live identity, connection and
        capabilities. Saved right away; ``router.adopted`` is audited.
        """
        await self.async_load()
        orphan = self._records.get(orphan_router_id)
        if orphan is None:
            raise RouterNotFoundError(
                "No such router record", router_id=orphan_router_id
            )
        current_rid = self._entry_map.get(entry_id)
        if current_rid is None:
            raise RouterNotFoundError("The entry has no router record")
        if orphan.state is not RecordState.ORPHANED:
            raise RouterIdentityError(
                "Only an orphaned record can be adopted",
                router_id=orphan_router_id,
                details={"state": orphan.state.value},
            )
        try:
            self._consume(authorization, entry_id, orphan_router_id)
        except AuthorizationError as err:
            self._emit(
                CoreEventType.AUTHORIZATION_DENIED,
                router_id=orphan_router_id,
                entry_id=entry_id,
                actor=authorization.actor,
                correlation_id=authorization.correlation_id,
                severity=Severity.WARNING,
                result=EventResult.DENIED,
                data={
                    "action": GuardedAction.ADOPT.value,
                    "reason": str(err.details.get("reason", "denied")),
                    "authorization_id": authorization.authorization_id,
                },
            )
            raise
        now = utcnow()
        current = self._records[current_rid]
        live = current.identity
        previous = list(orphan.previous_entry_ids)
        if orphan.identity.entry_id and orphan.identity.entry_id not in previous:
            previous.append(orphan.identity.entry_id)
        adopted = replace(
            orphan,
            identity=replace(
                live,
                router_id=orphan_router_id,
                first_seen=orphan.identity.first_seen or live.first_seen,
            ),
            state=RecordState.ACTIVE,
            connection=current.connection,
            reachability=current.reachability,
            firmware=current.firmware,
            capabilities=current.capabilities,
            orphaned_at=None,
            adopted_at=now,
            previous_entry_ids=tuple(previous),
        )
        self._orphan(current_rid, ORPHAN_REPLACED)
        self._records[orphan_router_id] = adopted
        self._entry_map[entry_id] = orphan_router_id
        runtime = self._runtime.get(entry_id)
        if runtime is not None:
            runtime.identity_sig = None
            runtime.cap_sig = None
        self._emit(
            CoreEventType.ROUTER_ADOPTED,
            router_id=orphan_router_id,
            entry_id=entry_id,
            actor=authorization.actor,
            correlation_id=authorization.correlation_id,
            result=EventResult.SUCCESS,
            data={
                "replaced_router_id": current_rid,
                "previous_entry_ids": list(previous),
                "authorization_id": authorization.authorization_id,
            },
        )
        self._check_duplicates()
        self.stats["store_saves_immediate"] += 1
        await self.async_flush()
        return adopted

    # -- part 2 seams ------------------------------------------------------------------------

    @callback
    def set_config_capability_provider(
        self, provider: ConfigCapabilityProvider | None
    ) -> Callable[[], None]:
        """Install the hook deciding ``config.*``; returns an uninstaller."""
        self._config_provider = provider
        self.invalidate_capabilities()

        @callback
        def _remove() -> None:
            if self._config_provider is provider:
                self._config_provider = None
                self.invalidate_capabilities()

        return _remove

    @callback
    def invalidate_capabilities(self) -> None:
        """Re-evaluate capabilities with the next poll (e.g. after a probe).

        The provider revision is part of the capability signature, so the
        next finished poll of every router evaluates again.
        """
        self._provider_revision += 1

    # -- 1.44.0: option, deployed ACL, module detectors ----------------------------

    @callback
    def set_config_enabled(self, entry_id: str, enabled: bool) -> bool:
        """Apply the option ``config_backup_enabled`` live (options flow).

        Returns True if it changed. ``config.*`` are re-evaluated right away
        from the last poll's data (no router call).
        """
        runtime = self._runtime.get(entry_id)
        if runtime is None or runtime.config_enabled is bool(enabled):
            return False
        runtime.config_enabled = bool(enabled)
        self.stats["config_option_changes"] += 1
        _LOGGER.info(
            "Configuration backup %s for entry %s",
            "enabled" if enabled else "disabled",
            entry_id,
        )
        self._recheck(entry_id)
        return True

    def config_enabled(self, router_id: str) -> bool:
        """Option ``config_backup_enabled`` of the router's entry (default OFF).

        Entries without runtime state are read from the config entry; an
        orphaned record or an unknown entry counts as OFF.
        """
        record = self._records.get(router_id)
        if record is None or record.state is not RecordState.ACTIVE:
            return False
        entry_id = record.entry_id
        if entry_id is None:
            return False
        runtime = self._runtime.get(entry_id)
        if runtime is not None:
            return runtime.config_enabled
        try:
            entry = self.hass.config_entries.async_get_entry(entry_id)
        except Exception:
            _LOGGER.debug("Config entry %s not readable", entry_id, exc_info=True)
            return False
        options = getattr(entry, "options", None)
        return isinstance(options, Mapping) and (
            options.get(OPTION_CONFIG_BACKUP_ENABLED) is True
        )

    @callback
    def note_deployed_acl(
        self, entry_id: str, observation: DeployedAclObservation
    ) -> None:
        """Remember what ensure_acl / an offer deploy saw (no store write).

        Re-evaluates the rf.* capabilities from the last poll's data, if any.
        """
        runtime = self._runtime.setdefault(entry_id, _Runtime(entry_id))
        runtime.acl = observation
        self.stats["acl_observations"] += 1
        self._recheck(entry_id)

    def deployed_acl(self, router_id: str) -> DeployedAclObservation | None:
        """The deployed-ACL observation of the router's entry, if any."""
        for entry_id, rid in self._entry_map.items():
            if rid == router_id:
                runtime = self._runtime.get(entry_id)
                return None if runtime is None else runtime.acl
        return None

    @callback
    def _recheck(self, entry_id: str) -> None:
        """Run the capability part of a poll again on the last data."""
        runtime = self._runtime.get(entry_id)
        rid = self._entry_map.get(entry_id)
        if runtime is None or rid is None or self._closed:
            return
        runtime.cap_sig = None
        coordinator = runtime.coordinator
        data = getattr(coordinator, "data", None) if coordinator is not None else None
        if (
            data is None
            or getattr(coordinator, "last_update_success", None) is not True
        ):
            return  # the next finished poll evaluates
        try:
            api = getattr(coordinator, "api", None)
            uses_ssh = getattr(api, "uses_ssh_fallback", False) is True
            self._update_capabilities(rid, runtime, data, uses_ssh, utcnow())
        except Exception:
            self.stats["listener_errors"] += 1
            _LOGGER.warning(
                "Enterprise core: capability re-check of %s failed",
                entry_id,
                exc_info=True,
            )

    @callback
    def register_capability_detector(
        self,
        module: str,
        detector: CapabilityDetector,
        *,
        prefix: str,
        signature: DetectorSignature | None = None,
    ) -> Callable[[], None]:
        """Let ``module`` report capabilities below ``prefix`` (contract §17).

        ``detector(record, data)`` is sync and does NO I/O: it reads the poll
        data the core already has and returns ``{name: CapabilityStatus}``.
        It runs only when the core's capability signature or its own
        ``signature(data)`` changes. A known module may use its own namespace
        (``security.``, ``diag.``, ``rf.``) or the shared ``log.``; nobody
        may use a core or ``config.`` namespace, another module's namespace
        or a core-owned name (rf.txpowerlist/survey/scan). Such names and
        non-status values are dropped and counted
        (``detector_entries_refused``); an exception is counted
        (``detector_errors``) and never breaks the poll.
        """
        if not isinstance(module, str) or not module:
            raise ValueError("module must be a non-empty string")
        if not isinstance(prefix, str) or not prefix.endswith("."):
            raise ValueError("capability prefix must end with '.'")
        if prefix.startswith(
            (*CORE_CAPABILITY_NAMESPACES, CONFIG_CAPABILITY_NAMESPACE)
        ):
            raise ValueError(f"{prefix} is a core capability namespace")
        own = MODULE_CAPABILITY_NAMESPACES.get(module)
        if own is not None and not (prefix.startswith(own) or prefix == "log."):
            raise ValueError(f"module {module} reports below {own} or log. only")
        for other, other_ns in MODULE_CAPABILITY_NAMESPACES.items():
            if other != module and prefix.startswith(other_ns):
                raise ValueError(f"capability namespace {prefix} belongs to {other}")
        if module in self._detectors:
            raise ValueError(f"module {module} already has a capability detector")
        if not callable(detector) or (
            signature is not None and not callable(signature)
        ):
            raise TypeError("detector and signature must be callables")
        entry = _Detector(
            module=module, prefix=prefix, run=detector, signature=signature
        )
        self._detectors[module] = entry
        self.stats["detectors_registered"] += 1
        self.invalidate_capabilities()

        @callback
        def _remove() -> None:
            if self._detectors.get(module) is entry:
                del self._detectors[module]
                self.invalidate_capabilities()

        return _remove

    def _detector_signature(self, data: Any) -> tuple[Any, ...]:
        out: list[Any] = []
        for module, det in sorted(self._detectors.items()):
            if det.signature is None:
                out.append((module, None))
                continue
            try:
                out.append((module, det.signature(data)))
            except Exception:
                self.stats["detector_errors"] += 1
                _LOGGER.debug("Signature of detector %s failed", module, exc_info=True)
                out.append((module, "error"))
        return tuple(out)

    def _run_detectors(
        self, record: RouterRecord, data: Any
    ) -> dict[str, CapabilityStatus]:
        found: dict[str, CapabilityStatus] = {}
        for module, det in sorted(self._detectors.items()):
            self.stats["detector_runs"] += 1
            try:
                reported = dict(det.run(record, data) or {})
            except Exception:
                self.stats["detector_errors"] += 1
                _LOGGER.warning(
                    "Capability detector of %s failed for %s (poll not affected)",
                    module,
                    record.router_id,
                    exc_info=True,
                )
                continue
            refused = 0
            for raw_name, status in reported.items():
                name = str(raw_name)
                if (
                    not name.startswith(det.prefix)
                    or name in CORE_OWNED_MODULE_CAPABILITIES
                    or not isinstance(status, CapabilityStatus)
                    or status.capability != name
                ):
                    refused += 1
                    continue
                found[name] = status
            if refused:
                self.stats["detector_entries_refused"] += refused
                _LOGGER.warning(
                    "Capability detector of %s reported %d entries outside %s or "
                    "core-owned; dropped",
                    module,
                    refused,
                    det.prefix,
                )
        return found

    @callback
    def set_probe_listener(self, listener: ProbeListener | None) -> None:
        """Part 2: called on attach and firmware change (never per poll)."""
        self._probe_listener = listener

    def attached(self, router_id: str) -> AttachedRouter | None:
        """Live handles of the entry bound to ``router_id`` (core-internal)."""
        record = self._records.get(router_id)
        if record is None or record.state is not RecordState.ACTIVE:
            return None
        for entry_id, rid in self._entry_map.items():
            if rid != router_id:
                continue
            runtime = self._runtime.get(entry_id)
            if runtime is None or runtime.coordinator is None:
                return None
            return AttachedRouter(
                router_id=router_id,
                entry_id=entry_id,
                coordinator=runtime.coordinator,
                config_enabled=runtime.config_enabled,
            )
        return None

    def attached_router_ids(self) -> tuple[str, ...]:
        """Router ids of all entries with a live coordinator."""
        out = []
        for entry_id, runtime in sorted(self._runtime.items()):
            rid = self._entry_map.get(entry_id)
            if rid is not None and runtime.coordinator is not None:
                out.append(rid)
        return tuple(out)

    @callback
    def set_adopt_authorizer(self, authorizer: AdoptAuthorizer | None) -> None:
        """Part 2: the guard authorizes ``async_adopt``."""
        self._adopt_authorizer = authorizer

    @callback
    def set_authorization_consumer(
        self, consumer: AuthorizationConsumer | None
    ) -> None:
        """Part 2: the guard's ``consume`` replaces the default check."""
        self._consume = consumer or default_consume

    # -- read side (RouterRegistryProtocol) ------------------------------------------------

    def get(self, router_id: str) -> RouterRecord:
        """Record by router id; RouterNotFoundError if unknown.

        A malformed id (path parts, NUL, oversized, wrong type) is refused
        without being echoed into the error. The fleet id ``"-"``
        (``FLEET_ROUTER_ID``) is never a router: same refusal, plus
        ``details["fleet"] = True``.
        """
        if not is_valid_id(router_id, ROUTER_ID_PREFIX):
            details: dict[str, Any] = {"reason": "invalid_router_id"}
            if is_fleet_router_id(router_id):
                details["fleet"] = True
            raise RouterNotFoundError("Unknown router id", details=details)
        record = self._records.get(router_id)
        if record is None:
            raise RouterNotFoundError("Unknown router id", router_id=router_id)
        return record

    def get_by_entry(self, entry_id: str) -> RouterRecord:
        """Active record of a config entry; RouterNotFoundError if none."""
        rid = self._entry_map.get(entry_id)
        if rid is None:
            raise RouterNotFoundError("No router record for the entry")
        return self._records[rid]

    def find(self, router_id: str) -> RouterRecord | None:
        """Record by router id or None."""
        return self._records.get(router_id)

    def router_id_for_entry(self, entry_id: str) -> str | None:
        """The router id currently bound to ``entry_id``."""
        return self._entry_map.get(entry_id)

    def list(self, *, include_orphaned: bool = False) -> tuple[RouterRecord, ...]:
        """All active (and optionally orphaned) records, sorted by id."""
        return tuple(
            record
            for _, record in sorted(self._records.items())
            if include_orphaned or record.state is RecordState.ACTIVE
        )

    def capabilities(self, router_id: str) -> Mapping[str, CapabilityStatus]:
        """Read-only capability map of a router."""
        return self.get(router_id).capabilities

    def has_capability(self, router_id: str, capability: str) -> bool:
        """True if available now (never for an orphaned record)."""
        record = self.find(router_id)
        if record is None or record.state is not RecordState.ACTIVE:
            return False
        status = record.capabilities.get(str(capability))
        return status is not None and status.available

    def require_capability(self, router_id: str, capability: str) -> None:
        """Raise CapabilityUnavailableError unless available.

        A ``config.*`` capability in ``unknown`` + ``determined_on_first_use``
        may be tried (a probe could not tell safely); the first real use
        settles its status.
        """
        record = self.get(router_id)
        name = str(capability)
        if record.state is not RecordState.ACTIVE:
            raise CapabilityUnavailableError(
                capability=name,
                reason=CapabilityReason.ENTRY_NOT_LOADED.value,
                router_id=router_id,
            )
        status = record.capabilities.get(name)
        if status is None:
            raise CapabilityUnavailableError(
                capability=name,
                reason=CapabilityReason.NOT_CHECKED.value,
                router_id=router_id,
            )
        if status.available or (
            name in CONFIG_CAPABILITIES
            and status.state is CapabilityState.UNKNOWN
            and str(status.reason) == CapabilityReason.DETERMINED_ON_FIRST_USE.value
        ):
            return
        raise CapabilityUnavailableError(
            capability=name, reason=str(status.reason), router_id=router_id
        )

    def summary(self) -> dict[str, Any]:
        """Counts for diagnostics (no MACs, hosts or hostnames)."""
        status: dict[str, int] = {}
        reach: dict[str, int] = {}
        for record in self._records.values():
            if record.state is RecordState.ACTIVE:
                key = record.identity.status.value
                status[key] = status.get(key, 0) + 1
                state = record.reachability.state.value
                reach[state] = reach.get(state, 0) + 1
        runs = int(self.timing["runs"])
        return {
            "loaded": self.loaded,
            "load_failed": self.load_failed,
            "active": sum(
                1 for r in self._records.values() if r.state is RecordState.ACTIVE
            ),
            "orphaned": sum(
                1 for r in self._records.values() if r.state is RecordState.ORPHANED
            ),
            "attached": len(self.attached_entry_ids),
            "identity_status": status,
            "reachability": reach,
            "listener_runs": runs,
            "listener_avg_us": round(self.timing["total_s"] / runs * 1e6, 1)
            if runs
            else 0.0,
            "listener_max_us": round(self.timing["max_s"] * 1e6, 1),
            **self.stats,
        }

    def record_summary(self, router_id: str) -> dict[str, Any]:
        """One record without MACs, hosts, hostnames, SSIDs or interfaces."""
        record = self.get(router_id)
        ident = record.identity
        return {
            "router_id": record.router_id,
            "state": record.state.value,
            "status": ident.status.value,
            "identity_flags": sorted(f.value for f in ident.identity_flags),
            "role": ident.role.value,
            "transport": record.connection.transport.value,
            "reachability": record.reachability.state.value,
            "has_device": ident.device_id is not None,
            "fingerprint_mac_count": len(ident.fingerprint.macs),
            "access_point_count": len(ident.access_points),
            "openwrt_version": ident.openwrt_version,
            "registered_at": record.to_dict()["registered_at"],
            "adopted": record.adopted_at is not None,
            "previous_entry_count": len(record.previous_entry_ids),
            "capabilities": {
                name: status.state.value
                for name, status in sorted(record.capabilities.items())
            },
        }

    # -- helpers --------------------------------------------------------------------------------

    def _emit(self, event_type: CoreEventType, **kwargs: Any) -> EmitResult | None:
        """Emit through the audit log; an audit failure never breaks the caller."""
        try:
            return self.audit.emit(event_type, **kwargs)
        except Exception:
            _LOGGER.warning(
                "Core event %s could not be recorded", event_type, exc_info=True
            )
            return None


def _stored_identity(identity: RouterIdentity) -> dict[str, Any]:
    """Identity without the per-poll timestamp (decides whether to save)."""
    data = identity.to_dict()
    data.pop("last_seen", None)
    return data


def is_router_id(value: object) -> bool:
    """True for ``rtr_<32 hex>``."""
    return is_valid_id(value, ROUTER_ID_PREFIX)
