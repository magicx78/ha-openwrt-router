"""Data types of the enterprise core and the Configuration API v1.

Plan: docs/plans/2026-11-17-enterprise-core.md, contract:
docs/dev/configuration-api-v1.md.

This module holds constants, enums, frozen dataclasses, a few pure helpers
and the service interfaces (Protocols) at the end of the file. It holds no state, makes no router call and does not touch ``hass``
except in :func:`async_actor_from_context`.

Rules for changes within API v1: additive only (new optional fields with a
default, new enum members, new event types, new capability names).
Dataclasses are ``kw_only`` so a new field never shifts positional arguments.

Naming: a "backup" and a "version" are the same thing. The id is
``backup_id`` (``bkp_<32 hex>``); ``BackupRecord.version_id`` is an alias.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

from .const import (
    DOMAIN,
    FEATURE_DHCP_LEASES,
    FEATURE_HAS_IWINFO,
    FEATURE_HAS_SERVICES,
    FEATURE_UCI_AVAILABLE,
)
from .core_errors import (
    ApiVersionError,
    AuthorizationError,
    BackupMetadataError,
    ErrorClass,
    UnsupportedStorageFormatError,
)
from .core_masking import is_secret_key, mask_secrets, mask_value
from .mac_utils import is_mac
from .net_events import Severity

if TYPE_CHECKING:
    from homeassistant.core import Context, HomeAssistant

    from .api import OpenWrtAPI
    from .coordinator import OpenWrtCoordinator

_LOGGER = logging.getLogger(__name__)

__all__ = ["ErrorClass", "Severity"]  # re-exported for consumers

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CONFIGURATION_API_VERSION: Final = 1
CONFIGURATION_API_MIN_VERSION: Final = 1
SUPPORTED_API_VERSIONS: Final = tuple(
    range(CONFIGURATION_API_MIN_VERSION, CONFIGURATION_API_VERSION + 1)
)
# Version of the ConfigBackupProvider protocol a provider implements.
PROVIDER_API_VERSION: Final = 1
SUPPORTED_PROVIDER_API_VERSIONS: Final = (1,)
BACKUP_METADATA_VERSION: Final = 1

# Fixed namespace of the deterministic default router id. NEVER change it:
# every router id ever issued is derived from it.
ROUTER_ID_NAMESPACE: Final = uuid.UUID("5fc97c09-217a-4ccb-af32-d954b049fecf")

ROUTER_ID_PREFIX: Final = "rtr_"
BACKUP_ID_PREFIX: Final = "bkp_"
EVENT_ID_PREFIX: Final = "evt_"
APPROVAL_ID_PREFIX: Final = "apr_"
PLAN_ID_PREFIX: Final = "pln_"
AUTHORIZATION_ID_PREFIX: Final = "wau_"
CORRELATION_ID_PREFIX: Final = "cor_"

# HA bus event of the audit log (payload = CoreEvent.to_dict(), masked).
# Deliberately separate from EVENT_INCIDENT: net_rules and logbook stay as is.
EVENT_CORE: Final = f"{DOMAIN}_core_event"
# hass.data key of the fleet-wide core object (enterprise_core.py, later step).
DATA_ENTERPRISE_CORE: Final = f"{DOMAIN}_enterprise_core"

# Stores (later step); each version 1 with a migrate function from day one.
ROUTER_REGISTRY_STORE_KEY: Final = f"{DOMAIN}.router_registry"
# Version index (BackupRecord metadata) and drift acknowledgements.
CONFIG_CATALOG_STORE_KEY: Final = f"{DOMAIN}.config_catalog"
AUDIT_STORE_KEY: Final = f"{DOMAIN}.audit"
# 32 random bytes for HMAC secret digests; never in audit, bus or diagnostics.
INSTALLATION_KEY_STORE_KEY: Final = f"{DOMAIN}.installation_key"
INSTALLATION_KEY_BYTES: Final = 32
CORE_STORE_VERSION: Final = 1

# Version store on disk: hass.config.path(*CONFIG_BACKUP_PATH, <router_id>).
CONFIG_BACKUP_PATH: Final = ("openwrt_router", "config_backups")
CONFIG_BACKUP_ORPHANED_DIR: Final = "orphaned"
CONFIG_BACKUP_REMOVED_DIR: Final = "removed"
PARTIAL_SUFFIX: Final = ".partial"
STORAGE_DIR_MODE: Final = 0o700
STORAGE_FILE_MODE: Final = 0o600
ORPHAN_SWEEP_MIN_AGE: Final = timedelta(hours=1)
DEFAULT_ROUTER_STORAGE_LIMIT_BYTES: Final = 50 * 1024 * 1024
DEFAULT_TOTAL_STORAGE_LIMIT_BYTES: Final = 250 * 1024 * 1024
STORAGE_FORMAT_PLAIN_V1: Final = "plain-v1"
SUPPORTED_STORAGE_FORMATS: Final = frozenset({STORAGE_FORMAT_PLAIN_V1})
NOTE_MAX_LENGTH: Final = 500

# Options-flow switch that gates all config.* capabilities and the matching
# ACL tier (the option itself is added to const.py/config_flow.py later).
OPTION_CONFIG_BACKUP_ENABLED: Final = "config_backup_enabled"

# Capability / event namespaces reserved for later modules (security-center,
# net-diagnostics). Module-defined names live below a registered prefix.
RESERVED_NAMESPACES: Final = ("security.", "diag.", "log.")

APPROVAL_TTL: Final = timedelta(minutes=15)
WRITE_AUTHORIZATION_TTL: Final = timedelta(minutes=5)
# Mutating operations wait at most this long for the per-router lock.
ROUTER_LOCK_TIMEOUT: Final = timedelta(minutes=5)
# Same dedup key again within the cooldown: not stored, not fired.
FAILURE_EVENT_COOLDOWN: Final = timedelta(hours=24)
AUDIT_MAX_EVENTS: Final = 1000
AUDIT_RETENTION_DAYS: Final = 90
DEFAULT_LIST_LIMIT: Final = 50
MAX_LIST_LIMIT: Final = 500

_ID_HEX = re.compile(r"[0-9a-f]{32}")
_SHA256 = re.compile(r"[0-9a-f]{64}")

# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def utcnow() -> datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.now(UTC)


def default_router_id(entry_id: str) -> str:
    """Return the deterministic default router id of a config entry."""
    if not isinstance(entry_id, str) or not entry_id:
        raise ValueError("entry_id must be a non-empty string")
    return ROUTER_ID_PREFIX + uuid.uuid5(ROUTER_ID_NAMESPACE, entry_id).hex


def new_id(prefix: str) -> str:
    """Return a new random id ``<prefix><32 hex>``."""
    return prefix + uuid.uuid4().hex


def is_valid_id(value: object, prefix: str) -> bool:
    """Return True if ``value`` is ``<prefix><32 lower-case hex>``."""
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and _ID_HEX.fullmatch(value[len(prefix) :]) is not None
    )


def is_sha256(value: object) -> bool:
    """Return True for 64 lower-case hex characters."""
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def normalize_mac(value: object) -> str | None:
    """Return ``aa:bb:cc:dd:ee:ff`` for any MAC form, else None."""
    if not is_mac(value):
        return None
    hexdigits = re.sub(r"[^0-9a-f]", "", str(value).strip().lower())
    return ":".join(hexdigits[i : i + 2] for i in range(0, 12, 2))


def _is_universal_unicast(mac: str) -> bool:
    """True for a normalised, universally administered unicast MAC."""
    first = int(mac[:2], 16)
    return not first & 0x03 and mac != "00:00:00:00:00:00"


def _json_default(value: Any) -> Any:
    """JSON encoder fallback for canonical checksums."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, set | frozenset):
        return sorted(value, key=str)
    if isinstance(value, bytes):
        return hashlib.sha256(value).hexdigest()
    return str(value)


def canonical_checksum(data: Any) -> str:
    """Return the sha256 hex digest of the canonical JSON form of ``data``."""
    text = json.dumps(
        data, sort_keys=True, separators=(",", ":"), default=_json_default
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def binding_checksum(*parts: Any) -> str:
    """Checksum a WriteAuthorization / approval is bound to (see contract §6)."""
    return canonical_checksum(list(parts))


def dedup_key(router_id: str | None, discriminator: str) -> str:
    """Event dedup key, e.g. ``(router_id, drift_id)`` or ``(router_id, error_class)``."""
    return f"{router_id or '-'}:{discriminator}"


def ensure_supported_api_version(version: int) -> int:
    """Return ``version`` if supported, else raise :class:`ApiVersionError`."""
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version not in SUPPORTED_API_VERSIONS
    ):
        raise ApiVersionError(
            requested=version, supported_versions=SUPPORTED_API_VERSIONS
        )
    return version


def ensure_supported_storage_format(storage_format: str) -> str:
    """Return the format if readable, else UnsupportedStorageFormatError."""
    if storage_format not in SUPPORTED_STORAGE_FORMATS:
        raise UnsupportedStorageFormatError(
            f"Storage format {storage_format!r} is not supported",
            details={
                "storage_format": str(storage_format),
                "supported": sorted(SUPPORTED_STORAGE_FORMATS),
            },
        )
    return storage_format


def _iso(value: datetime | None) -> str | None:
    """ISO 8601 string of an aware datetime, or None."""
    return None if value is None else value.isoformat()


def _require_aware(value: datetime | None, name: str) -> None:
    """Raise ValueError unless ``value`` is None or an aware datetime."""
    if value is None:
        return
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{name} must be an aware datetime")


def _parse_dt(value: Any, name: str) -> datetime | None:
    """Parse an ISO 8601 string (or datetime); naive values are taken as UTC."""
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value)
    else:
        raise TypeError(f"{name} is not a timestamp")
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _opt_str(data: Mapping[str, Any], key: str) -> str | None:
    """``data[key]`` if it is a string, else None."""
    value = data.get(key)
    return value if isinstance(value, str) else None


def _opt_hash(data: Mapping[str, Any], key: str) -> str | None:
    """``data[key]`` if it is a sha256 hex string; None if absent."""
    value = data.get(key)
    if value is None:
        return None
    if not is_sha256(value):
        raise ValueError(f"{key} must be 64 lower-case hex characters")
    return value


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RouterRole(StrEnum):
    """Role of a router in the fleet."""

    GATEWAY = "gateway"
    ACCESS_POINT = "access_point"
    UNKNOWN = "unknown"


class IdentityStatus(StrEnum):
    """How sure the core is that a record still describes the same hardware."""

    UNVERIFIED = "unverified"  # no data seen yet (e.g. entry in setup_retry)
    CONFIRMED = "confirmed"
    CHANGED = "changed"  # board/model changed or no MAC overlap: swap suspected
    DUPLICATE_SUSPECTED = "duplicate_suspected"  # another entry shares MACs


class RecordState(StrEnum):
    """Lifecycle of a router record."""

    ACTIVE = "active"
    ORPHANED = "orphaned"  # config entry removed; history and backups stay


class ReachabilityState(StrEnum):
    """Reachability from coordinator.last_update_success."""

    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class Transport(StrEnum):
    """How the integration currently talks to the router."""

    UBUS = "ubus"
    SSH_FALLBACK = "ssh_fallback"
    UNKNOWN = "unknown"


class Capability(StrEnum):
    """Core capability names (dotted). Modules may add names below a
    registered namespace (see RESERVED_NAMESPACES); APIs therefore take
    capability names as ``str``."""

    TRANSPORT_UBUS = "transport.ubus"
    TRANSPORT_SSH = "transport.ssh"
    DATA_SYSTEM_BOARD = "data.system_board"
    DATA_WIRELESS = "data.wireless"
    DATA_HOSTAPD_CLIENTS = "data.hostapd_clients"
    DATA_DHCP_LEASES = "data.dhcp_leases"
    DATA_LLDP = "data.lldp"
    DATA_LOGS = "data.logs"
    DATA_IWINFO = "data.iwinfo"
    DATA_SERVICES = "data.services"
    DATA_UCI = "data.uci"
    STREAM_UBUS = "stream.ubus"
    PKG_APK = "pkg.apk"
    PKG_OPKG = "pkg.opkg"
    CONFIG_CAPTURE = "config.capture"
    CONFIG_BACKUP = "config.backup"
    CONFIG_VALIDATE = "config.validate"
    CONFIG_DIFF = "config.diff"
    CONFIG_DRIFT = "config.drift"
    CONFIG_RESTORE_DRY_RUN = "config.restore_dry_run"
    CONFIG_RESTORE = "config.restore"
    CONFIG_EXPORT = "config.export"
    # Router-side probes of the provider (async_probe), never in the poll.
    CONFIG_CGI_BACKUP = "config.cgi_backup"
    CONFIG_SSH_ROOT = "config.ssh_root"
    CONFIG_UCI_READ = "config.uci_read"  # detail: {config_name: bool}
    CONFIG_PACKAGELIST = "config.packagelist"


# Capabilities the configuration provider decides (no provider: unavailable).
CONFIG_CAPABILITIES: Final = frozenset(
    c for c in Capability if c.value.startswith("config.")
)
# Of these, the ones found by the provider's router probe (async_probe).
PROBED_CAPABILITIES: Final = frozenset(
    {
        Capability.CONFIG_CGI_BACKUP,
        Capability.CONFIG_SSH_ROOT,
        Capability.CONFIG_UCI_READ,
        Capability.CONFIG_PACKAGELIST,
    }
)
# coordinator.data.features keys (const.FEATURE_*) mapped 1:1 to a capability.
FEATURE_CAPABILITIES: Final[Mapping[str, Capability]] = MappingProxyType(
    {
        FEATURE_HAS_IWINFO: Capability.DATA_IWINFO,
        FEATURE_DHCP_LEASES: Capability.DATA_DHCP_LEASES,
        FEATURE_HAS_SERVICES: Capability.DATA_SERVICES,
        FEATURE_UCI_AVAILABLE: Capability.DATA_UCI,
    }
)


class CapabilityState(StrEnum):
    """State of one capability for one router."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class CapabilityReason(StrEnum):
    """Standard reason codes of a CapabilityStatus (providers may add own)."""

    OK = "ok"
    NO_DATA_YET = "no_data_yet"
    NOT_CHECKED = "not_checked"
    NOT_PROBED = "not_probed"
    NOT_DETECTED = "not_detected"
    PERMISSION_DENIED = "permission_denied"
    TRANSPORT_UNSUPPORTED = "transport_unsupported"
    UNSUPPORTED_FIRMWARE = "unsupported_firmware"
    ROUTER_OFFLINE = "router_offline"
    ENTRY_NOT_LOADED = "entry_not_loaded"
    DISABLED = "disabled"  # option config_backup_enabled is off
    NO_PROVIDER = "no_provider"
    PROVIDER_DECLINED = "provider_declined"


class ActorKind(StrEnum):
    """Who triggered an operation."""

    USER = "user"
    AUTOMATION = "automation"
    SYSTEM = "system"
    MODULE = "module"


class ActionClass(StrEnum):
    """Guard class of an action.

    CRITICAL means "needs request + admin approval", not "writes": export
    only reads but is critical because it discloses secrets.
    """

    READ = "read"
    MUTATING = "mutating"
    CRITICAL = "critical"


class GuardedAction(StrEnum):
    """Actions known to the guard in v1.

    Later modules register further actions as ``<module>.<action>`` (e.g.
    ``router_settings.change``, ``service.restart``) with
    ``ActionGuardProtocol.register_action``; APIs take actions as ``str``.
    """

    BACKUP = "backup"
    PROTECT = "protect"
    DRIFT_ACK = "drift_ack"
    EXPORT = "export"
    DELETE = "delete"
    PRUNE = "prune"  # retention; system/module only, never protected versions
    RESTORE = "restore"
    ADOPT = "adopt"
    ACL_DEPLOY = "acl_deploy"


ACTION_CLASSES: Final[Mapping[str, ActionClass]] = MappingProxyType(
    {
        GuardedAction.BACKUP: ActionClass.MUTATING,
        GuardedAction.PROTECT: ActionClass.MUTATING,
        GuardedAction.DRIFT_ACK: ActionClass.MUTATING,
        GuardedAction.EXPORT: ActionClass.CRITICAL,
        GuardedAction.DELETE: ActionClass.CRITICAL,
        GuardedAction.PRUNE: ActionClass.MUTATING,
        GuardedAction.RESTORE: ActionClass.CRITICAL,
        GuardedAction.ADOPT: ActionClass.MUTATING,
        GuardedAction.ACL_DEPLOY: ActionClass.CRITICAL,
    }
)
# Only an admin USER may perform (and approve) these.
ADMIN_USER_ONLY_ACTIONS: Final = frozenset(
    {
        GuardedAction.PROTECT,
        GuardedAction.DRIFT_ACK,
        GuardedAction.EXPORT,
        GuardedAction.ADOPT,
    }
)
# Only the integration itself (system) or a module may perform these.
SYSTEM_ONLY_ACTIONS: Final = frozenset({GuardedAction.PRUNE})


class DecisionState(StrEnum):
    """Synchronous answer of ActionGuard.authorize()."""

    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"  # approval request created, waiting for an admin


class ApprovalStatus(StrEnum):
    """Lifecycle of an approval request for a critical action."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    USED = "used"


class BackupType(StrEnum):
    """Kind of backup artifact set."""

    FULL_ARCHIVE = "full_archive"  # sysupgrade -b style archive (+ uci, inventory)
    UCI_SNAPSHOT = "uci_snapshot"
    PARTIAL = "partial"


class BackupReason(StrEnum):
    """Why a version was taken (config-manager calls this ``kind``)."""

    MANUAL = "manual"
    SCHEDULED = "scheduled"
    PRE_FIRMWARE_UPDATE = "pre_firmware_update"
    RELEASE_CHANGE = "release_change"
    PRE_RESTORE = "pre_restore"
    PRE_CHANGE = "pre_change"
    DRIFT = "drift"
    INCIDENT = "incident"
    MIGRATION = "migration"
    IMPORT = "import"


class VersionStatus(StrEnum):
    """Collection result of a version."""

    OK = "ok"
    PARTIAL = "partial"  # some artifacts missing (error_class says why)
    FAILED = "failed"  # nothing usable; kept for history and dedup of errors


class ArtifactKind(StrEnum):
    """Artifacts of a version; artifact maps are keyed by ``str``."""

    ARCHIVE = "archive"
    UCI = "uci"
    INVENTORY = "inventory"


class ValidationStatus(StrEnum):
    """Integrity state of a stored version."""

    UNVERIFIED = "unverified"
    VALID = "valid"
    INVALID = "invalid"  # readable but not a usable backup
    CORRUPT = "corrupt"  # checksum or size mismatch
    MISSING = "missing"  # file gone (sweep marks index entries without file)


class DriftAckState(StrEnum):
    """User decision about one drift."""

    ACKNOWLEDGED = "acknowledged"  # seen, baseline stays
    KNOWN = "known"  # this drift_id is the new baseline


class ConfigRefKind(StrEnum):
    """What a ConfigRef points at."""

    BACKUP = "backup"
    LIVE = "live"


class ChangeKind(StrEnum):
    """Kind of one configuration change in a diff."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"  # config-manager: "changed"
    REORDERED = "reordered"


class RestoreStatus(StrEnum):
    """Outcome of a restore execution."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class EventResult(StrEnum):
    """Result field of a CoreEvent."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    PENDING = "pending"
    INFO = "info"


class CoreEventType(StrEnum):
    """Audit / bus event types; new types are an additive change.

    Modules add own types below a registered prefix; ``CoreEvent.type``
    is therefore a ``str``.
    """

    ROUTER_REGISTERED = "router.registered"
    ROUTER_IDENTITY_CHANGED = "router.identity_changed"
    ROUTER_DUPLICATE_SUSPECTED = "router.duplicate_suspected"
    ROUTER_CAPABILITIES_CHANGED = "router.capabilities_changed"
    ROUTER_ORPHANED = "router.orphaned"
    ROUTER_ADOPTED = "router.adopted"
    BACKUP_CREATED = "configuration.backup_created"
    BACKUP_FAILED = "configuration.backup_failed"
    BACKUP_RECOVERED = "configuration.backup_recovered"
    BACKUP_VALIDATED = "configuration.backup_validated"
    BACKUP_PROTECTION_CHANGED = "configuration.backup_protection_changed"
    BACKUP_EXPORTED = "configuration.backup_exported"
    BACKUP_DELETED = "configuration.backup_deleted"
    DRIFT_DETECTED = "configuration.drift_detected"
    DRIFT_ACKNOWLEDGED = "configuration.drift_acknowledged"
    RESTORE_CHECKED = "configuration.restore_checked"  # dry run / compatibility
    RESTORE_REQUESTED = "configuration.restore_requested"
    RESTORE_APPROVED = "configuration.restore_approved"
    RESTORE_REJECTED = "configuration.restore_rejected"
    RESTORE_COMPLETED = "configuration.restore_completed"
    RESTORE_FAILED = "configuration.restore_failed"
    STORAGE_SWEPT = "configuration.storage_swept"
    AUTHORIZATION_DENIED = "security.authorization_denied"
    APPROVAL_REQUESTED = "security.approval_requested"
    APPROVAL_APPROVED = "security.approval_approved"
    APPROVAL_REJECTED = "security.approval_rejected"
    APPROVAL_EXPIRED = "security.approval_expired"


# ---------------------------------------------------------------------------
# Actor
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class Actor:
    """Who performs an operation; only a USER can be admin."""

    kind: ActorKind
    user_id: str | None = None
    context_id: str | None = None
    parent_context_id: str | None = None
    module: str | None = None
    is_admin: bool = False

    def __post_init__(self) -> None:
        """Coerce the kind and drop admin rights of non-user actors."""
        object.__setattr__(self, "kind", ActorKind(self.kind))
        if self.kind is not ActorKind.USER and self.is_admin:
            object.__setattr__(self, "is_admin", False)

    @classmethod
    def system(cls, module: str | None = None) -> Actor:
        """The integration itself (startup, retention, migrations)."""
        return cls(kind=ActorKind.SYSTEM, module=module)

    @classmethod
    def for_module(cls, module: str, *, context_id: str | None = None) -> Actor:
        """Another enterprise module acting on its own."""
        return cls(kind=ActorKind.MODULE, module=module, context_id=context_id)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "kind": self.kind.value,
            "user_id": self.user_id,
            "context_id": self.context_id,
            "parent_context_id": self.parent_context_id,
            "module": self.module,
            "is_admin": self.is_admin,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Actor:
        """Inverse of :meth:`to_dict`; ValueError/TypeError/KeyError on bad data."""
        return cls(
            kind=ActorKind(data["kind"]),
            user_id=_opt_str(data, "user_id"),
            context_id=_opt_str(data, "context_id"),
            parent_context_id=_opt_str(data, "parent_context_id"),
            module=_opt_str(data, "module"),
            is_admin=data.get("is_admin") is True,
        )


async def async_actor_from_context(
    hass: HomeAssistant, context: Context | None, module: str | None = None
) -> Actor:
    """Build an Actor from an HA ``Context``.

    Order: a ``user_id`` makes a USER (admin only if the user exists, is
    active and is admin); else a given ``module`` makes a MODULE; else a
    ``parent_id`` makes an AUTOMATION; else SYSTEM.
    """
    context_id = context.id if context is not None else None
    parent_id = context.parent_id if context is not None else None
    if context is not None and context.user_id:
        user = await hass.auth.async_get_user(context.user_id)
        is_admin = bool(
            user is not None
            and getattr(user, "is_active", True)
            and getattr(user, "is_admin", False)
        )
        return Actor(
            kind=ActorKind.USER,
            user_id=context.user_id,
            context_id=context_id,
            parent_context_id=parent_id,
            module=module,
            is_admin=is_admin,
        )
    if module:
        kind = ActorKind.MODULE
    elif parent_id:
        kind = ActorKind.AUTOMATION
    else:
        kind = ActorKind.SYSTEM
    return Actor(
        kind=kind, context_id=context_id, parent_context_id=parent_id, module=module
    )


# ---------------------------------------------------------------------------
# Identity and registry types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class AccessPointInfo:
    """One AP interface of the router (from coordinator.data.ap_interfaces)."""

    ifname: str
    ssid: str | None = None
    bssid: str | None = None
    band: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "ifname": self.ifname,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "band": self.band,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class InterfaceInfo:
    """One network interface (from coordinator.data.network_interfaces)."""

    name: str
    device: str | None = None
    mac: str | None = None
    proto: str | None = None
    up: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "name": self.name,
            "device": self.device,
            "mac": self.mac,
            "proto": self.proto,
            "up": self.up,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class HardwareFingerprint:
    """Board, model and universally administered MACs of one device."""

    board_name: str | None = None
    model: str | None = None
    macs: frozenset[str] = frozenset()

    @classmethod
    def build(
        cls,
        *,
        board_name: str | None,
        model: str | None,
        macs: Iterable[object],
    ) -> HardwareFingerprint:
        """Normalise MACs and keep only universally administered unicast ones."""
        kept = frozenset(
            mac
            for mac in (normalize_mac(m) for m in macs)
            if mac is not None and _is_universal_unicast(mac)
        )
        return cls(board_name=board_name or None, model=model or None, macs=kept)

    @property
    def is_empty(self) -> bool:
        """True if nothing identifying is known."""
        return not (self.board_name or self.model or self.macs)

    def mac_overlap(self, other: HardwareFingerprint) -> frozenset[str]:
        """MACs both fingerprints share."""
        return self.macs & other.macs

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "board_name": self.board_name,
            "model": self.model,
            "macs": sorted(self.macs),
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class RouterIdentity:
    """Identity snapshot of one router. router_id never follows host/hostname."""

    router_id: str
    entry_id: str | None
    device_id: str | None = None
    hostname: str | None = None
    management_host: str | None = None
    management_port: int | None = None
    management_protocol: str | None = None
    mac_addresses: frozenset[str] = frozenset()
    model: str | None = None
    board_name: str | None = None
    architecture: str | None = None
    openwrt_version: str | None = None
    openwrt_revision: str | None = None
    serial: str | None = None  # not fetched today
    role: RouterRole = RouterRole.UNKNOWN
    access_points: tuple[AccessPointInfo, ...] = ()
    interfaces: tuple[InterfaceInfo, ...] = ()
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    fingerprint: HardwareFingerprint = HardwareFingerprint()
    status: IdentityStatus = IdentityStatus.UNVERIFIED

    def __post_init__(self) -> None:
        """Validate the id and timestamps."""
        if not is_valid_id(self.router_id, ROUTER_ID_PREFIX):
            raise ValueError("router_id must be rtr_<32 hex>")
        _require_aware(self.first_seen, "first_seen")
        _require_aware(self.last_seen, "last_seen")

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (not masked: holds no secrets, but MACs/hostnames)."""
        return {
            "router_id": self.router_id,
            "entry_id": self.entry_id,
            "device_id": self.device_id,
            "hostname": self.hostname,
            "management_host": self.management_host,
            "management_port": self.management_port,
            "management_protocol": self.management_protocol,
            "mac_addresses": sorted(self.mac_addresses),
            "model": self.model,
            "board_name": self.board_name,
            "architecture": self.architecture,
            "openwrt_version": self.openwrt_version,
            "openwrt_revision": self.openwrt_revision,
            "serial": self.serial,
            "role": self.role.value,
            "access_points": [ap.to_dict() for ap in self.access_points],
            "interfaces": [i.to_dict() for i in self.interfaces],
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "fingerprint": self.fingerprint.to_dict(),
            "status": self.status.value,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class RouterReachability:
    """Reachability derived from the entry's coordinator."""

    state: ReachabilityState = ReachabilityState.UNKNOWN
    last_success: datetime | None = None
    last_attempt: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "state": self.state.value,
            "last_success": _iso(self.last_success),
            "last_attempt": _iso(self.last_attempt),
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class ConnectionInfo:
    """Management connection properties of a router (no credentials)."""

    host: str | None = None
    port: int | None = None
    protocol: str | None = None  # "http" | "https"
    transport: Transport = Transport.UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "transport": self.transport.value,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class FirmwareInfo:
    """Firmware facts from router_info / updates_available."""

    distribution: str | None = None
    version: str | None = None
    revision: str | None = None
    target: str | None = None
    kernel: str | None = None
    architecture: str | None = None
    board_name: str | None = None
    package_manager: str | None = None  # "apk" | "opkg" | None (not checked)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "distribution": self.distribution,
            "version": self.version,
            "revision": self.revision,
            "target": self.target,
            "kernel": self.kernel,
            "architecture": self.architecture,
            "board_name": self.board_name,
            "package_manager": self.package_manager,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class DiagnosticSource:
    """One data source the integration has for a router (e.g. ``log_status``)."""

    name: str
    available: bool
    detail: str | None = None
    updated_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "name": self.name,
            "available": self.available,
            "detail": self.detail,
            "updated_at": _iso(self.updated_at),
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class CapabilityStatus:
    """State of one capability for one router.

    ``capability`` is a Capability value or a module name below a registered
    namespace. ``reason`` is a CapabilityReason value or ``provider:<code>``;
    ``source`` names what it was derived from, e.g. ``features.has_iwinfo``,
    ``api.uses_ssh_fallback`` or ``probe:<provider_id>``. ``detail`` carries
    per-item results, e.g. ``{"wireless": True, "firewall": False}`` for
    ``config.uci_read``.
    """

    capability: str
    state: CapabilityState
    reason: str
    source: str
    detected_at: datetime
    reason_text: str | None = None
    required_permissions: tuple[str, ...] = ()
    detail: Mapping[str, Any] = field(default_factory=dict)

    @property
    def available(self) -> bool:
        """True if the capability can be used now."""
        return self.state is CapabilityState.AVAILABLE

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "capability": str(self.capability),
            "state": self.state.value,
            "reason": str(self.reason),
            "reason_text": self.reason_text,
            "source": self.source,
            "required_permissions": list(self.required_permissions),
            "detected_at": _iso(self.detected_at),
            "detail": mask_secrets(dict(self.detail)),
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class RouterRecord:
    """Registry entry of one router (active or orphaned)."""

    identity: RouterIdentity
    state: RecordState = RecordState.ACTIVE
    connection: ConnectionInfo = ConnectionInfo()
    reachability: RouterReachability = RouterReachability()
    firmware: FirmwareInfo = FirmwareInfo()
    capabilities: Mapping[str, CapabilityStatus] = field(default_factory=dict)
    registered_at: datetime | None = None
    orphaned_at: datetime | None = None
    adopted_at: datetime | None = None
    previous_entry_ids: tuple[str, ...] = ()

    @property
    def router_id(self) -> str:
        """The stable router id."""
        return self.identity.router_id

    @property
    def entry_id(self) -> str | None:
        """The bound config entry; None while orphaned."""
        return None if self.state is RecordState.ORPHANED else self.identity.entry_id

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "router_id": self.router_id,
            "entry_id": self.entry_id,
            "state": self.state.value,
            "identity": self.identity.to_dict(),
            "connection": self.connection.to_dict(),
            "reachability": self.reachability.to_dict(),
            "firmware": self.firmware.to_dict(),
            "capabilities": {
                str(cap): status.to_dict()
                for cap, status in sorted(self.capabilities.items())
            },
            "registered_at": _iso(self.registered_at),
            "orphaned_at": _iso(self.orphaned_at),
            "adopted_at": _iso(self.adopted_at),
            "previous_entry_ids": list(self.previous_entry_ids),
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class AdoptionCandidate:
    """An orphaned record whose fingerprint matches a new entry."""

    router_id: str
    identity: RouterIdentity
    matched_macs: frozenset[str] = frozenset()
    board_match: bool = False
    model_match: bool = False
    orphaned_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "router_id": self.router_id,
            "identity": self.identity.to_dict(),
            "matched_macs": sorted(self.matched_macs),
            "board_match": self.board_match,
            "model_match": self.model_match,
            "orphaned_at": _iso(self.orphaned_at),
        }


@dataclass(frozen=True, kw_only=True, slots=True, eq=False)
class RouterConnection:
    """Live handles of a loaded entry, handed to providers by the core.

    ``api`` is the entry's EXISTING OpenWrtAPI (all router I/O stays in
    api.py); ``coordinator`` is its OpenWrtCoordinator. Never stored.
    """

    router_id: str
    entry_id: str
    api: OpenWrtAPI = field(repr=False)
    coordinator: OpenWrtCoordinator = field(repr=False)
    transport: Transport = Transport.UNKNOWN


# ---------------------------------------------------------------------------
# Version store: storage references and artifacts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class StorageRef:
    """Where the core keeps one artifact; ``locator`` is opaque to modules.

    ``storage_format`` names the on-disk encoding (phase 1: ``plain-v1``,
    private folder, mode 0600, no own encryption). Reading an unknown format
    raises UnsupportedStorageFormatError.
    """

    locator: str  # path relative to the router's folder, e.g. "<bkp>.tar.gz"
    kind: str = "file"
    storage_format: str = STORAGE_FORMAT_PLAIN_V1
    encrypted: bool = False

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "locator": self.locator,
            "kind": self.kind,
            "storage_format": self.storage_format,
            "encrypted": self.encrypted,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StorageRef:
        """Inverse of :meth:`to_dict`."""
        locator = data["locator"]
        kind = data.get("kind", "file")
        storage_format = data.get("storage_format", STORAGE_FORMAT_PLAIN_V1)
        if not all(isinstance(v, str) and v for v in (locator, kind, storage_format)):
            raise ValueError("storage fields must be non-empty strings")
        return cls(
            locator=locator,
            kind=kind,
            storage_format=storage_format,
            encrypted=data.get("encrypted") is True,
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class ArtifactRef:
    """One stored artifact of a version."""

    storage: StorageRef
    sha256: str
    size_bytes: int
    content_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        """Validate checksum and size."""
        if not is_sha256(self.sha256):
            raise ValueError("artifact sha256 must be 64 lower-case hex characters")
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes < 0
        ):
            raise ValueError("artifact size_bytes must be a non-negative int")

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "storage": self.storage.to_dict(),
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "content_type": self.content_type,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ArtifactRef:
        """Inverse of :meth:`to_dict`."""
        return cls(
            storage=StorageRef.from_dict(data["storage"]),
            sha256=data["sha256"],
            size_bytes=data["size_bytes"],
            content_type=_opt_str(data, "content_type") or "application/octet-stream",
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class ArtifactPayload:
    """Bytes of one artifact handed to ``async_put_version``.

    The store recomputes sha256 and refuses a mismatch (checksum_mismatch).
    """

    data: bytes = field(repr=False)
    sha256: str
    content_type: str = "application/octet-stream"

    @property
    def size_bytes(self) -> int:
        """Length of ``data``."""
        return len(self.data)


# ---------------------------------------------------------------------------
# Version metadata (index owned by the core, bytes stored by the core)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class ValidationInfo:
    """Result of the last integrity check of a version."""

    status: ValidationStatus = ValidationStatus.UNVERIFIED
    checked_at: datetime | None = None
    details: str | None = None

    def __post_init__(self) -> None:
        """Coerce and validate."""
        object.__setattr__(self, "status", ValidationStatus(self.status))
        _require_aware(self.checked_at, "checked_at")

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "status": self.status.value,
            "checked_at": _iso(self.checked_at),
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidationInfo:
        """Inverse of :meth:`to_dict`."""
        return cls(
            status=ValidationStatus(data.get("status", ValidationStatus.UNVERIFIED)),
            checked_at=_parse_dt(data.get("checked_at"), "checked_at"),
            details=_opt_str(data, "details"),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class CompatibilityInfo:
    """What a version was taken from; used for restore compatibility checks."""

    format: str  # provider format name, e.g. "sysupgrade_tar_gz", "uci_json"
    format_version: int = 1
    openwrt_version: str | None = None
    target: str | None = None
    board_name: str | None = None
    model: str | None = None
    architecture: str | None = None
    package_manager: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "format": self.format,
            "format_version": self.format_version,
            "openwrt_version": self.openwrt_version,
            "target": self.target,
            "board_name": self.board_name,
            "model": self.model,
            "architecture": self.architecture,
            "package_manager": self.package_manager,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CompatibilityInfo:
        """Inverse of :meth:`to_dict`."""
        fmt = data["format"]
        version = data.get("format_version", 1)
        if not isinstance(fmt, str) or not fmt:
            raise ValueError("compatibility.format must be a non-empty string")
        if not isinstance(version, int) or isinstance(version, bool):
            raise TypeError("compatibility.format_version must be an int")
        return cls(
            format=fmt,
            format_version=version,
            openwrt_version=_opt_str(data, "openwrt_version"),
            target=_opt_str(data, "target"),
            board_name=_opt_str(data, "board_name"),
            model=_opt_str(data, "model"),
            architecture=_opt_str(data, "architecture"),
            package_manager=_opt_str(data, "package_manager"),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class BackupLinks:
    """Cross references of a version to other modules."""

    incident_id: str | None = None
    change_id: str | None = None
    correlation_id: str | None = None
    parent_backup_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "incident_id": self.incident_id,
            "change_id": self.change_id,
            "correlation_id": self.correlation_id,
            "parent_backup_id": self.parent_backup_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> BackupLinks:
        """Inverse of :meth:`to_dict`."""
        data = data or {}
        return cls(
            incident_id=_opt_str(data, "incident_id"),
            change_id=_opt_str(data, "change_id"),
            correlation_id=_opt_str(data, "correlation_id"),
            parent_backup_id=_opt_str(data, "parent_backup_id"),
        )


MetadataMigration = Callable[[dict[str, Any]], dict[str, Any]]
# from_version -> function returning the dict at a higher metadata_version.
# Empty in v1; a future metadata version 2 registers {1: _v1_to_v2}.
METADATA_MIGRATIONS: dict[int, MetadataMigration] = {}


def migrate_backup_metadata(data: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``data`` upgraded to :data:`BACKUP_METADATA_VERSION`.

    Raises :class:`BackupMetadataError` for a missing, invalid or newer
    version, or when no migration step exists.
    """
    version = data.get("metadata_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise BackupMetadataError("Backup metadata has no valid metadata_version")
    if version > BACKUP_METADATA_VERSION:
        raise BackupMetadataError(
            f"Backup metadata version {version} is newer than supported "
            f"{BACKUP_METADATA_VERSION}",
            details={"metadata_version": version},
        )
    current = dict(data)
    while version < BACKUP_METADATA_VERSION:
        step = METADATA_MIGRATIONS.get(version)
        if step is None:
            raise BackupMetadataError(
                f"No migration from backup metadata version {version}",
                details={"metadata_version": version},
            )
        current = step(dict(current))
        new_version = current.get("metadata_version")
        if not isinstance(new_version, int) or new_version <= version:
            raise BackupMetadataError("Backup metadata migration did not advance")
        version = new_version
    return current


def _check_note(note: str | None) -> None:
    """Raise ValueError for a non-string or too long note."""
    if note is not None and (not isinstance(note, str) or len(note) > NOTE_MAX_LENGTH):
        raise ValueError(f"note must be a string of at most {NOTE_MAX_LENGTH} chars")


@dataclass(frozen=True, kw_only=True, slots=True)
class BackupRecord:
    """Index entry of one version (metadata format BACKUP_METADATA_VERSION).

    ``sha256`` is the archive's sha256 and ``size_bytes`` the sum over all
    artifacts (both derived). A FAILED version may have no artifacts.
    """

    backup_id: str
    router_id: str
    created_at: datetime
    backup_type: BackupType
    reason: BackupReason
    created_by: Actor
    status: VersionStatus = VersionStatus.OK
    error_class: ErrorClass | None = None
    last_seen_at: datetime | None = None  # dedup hits only move this
    fetch_method: str | None = None  # e.g. "cgi", "ssh"; provider-defined
    content_hash: str | None = None  # dedup fingerprint of the archive members
    uci_hash: str | None = None  # content hash of the UCI snapshot
    openwrt_version: str | None = None
    hardware_model: str | None = None
    board_name: str | None = None
    compatibility: CompatibilityInfo | None = None
    artifacts: Mapping[str, ArtifactRef] = field(default_factory=dict)
    validation: ValidationInfo = ValidationInfo()
    links: BackupLinks = BackupLinks()
    contains_secrets: bool = True
    protected: bool = False
    note: str | None = None
    metadata_version: int = BACKUP_METADATA_VERSION

    def __post_init__(self) -> None:
        """Validate ids, hashes, enums, note and timestamps."""
        if not is_valid_id(self.backup_id, BACKUP_ID_PREFIX):
            raise ValueError("backup_id must be bkp_<32 hex>")
        if not is_valid_id(self.router_id, ROUTER_ID_PREFIX):
            raise ValueError("router_id must be rtr_<32 hex>")
        if not isinstance(self.created_at, datetime):
            raise TypeError("created_at must be a datetime")
        _require_aware(self.created_at, "created_at")
        _require_aware(self.last_seen_at, "last_seen_at")
        for name in ("content_hash", "uci_hash"):
            value = getattr(self, name)
            if value is not None and not is_sha256(value):
                raise ValueError(f"{name} must be 64 lower-case hex characters")
        _check_note(self.note)
        object.__setattr__(self, "backup_type", BackupType(self.backup_type))
        object.__setattr__(self, "reason", BackupReason(self.reason))
        object.__setattr__(self, "status", VersionStatus(self.status))
        if self.error_class is not None:
            object.__setattr__(self, "error_class", ErrorClass(self.error_class))
        if self.metadata_version != BACKUP_METADATA_VERSION:
            raise ValueError("metadata_version must be the current version")

    @property
    def version_id(self) -> str:
        """Alias of ``backup_id`` (a backup is a version)."""
        return self.backup_id

    @property
    def sha256(self) -> str | None:
        """sha256 of the archive artifact, None without archive."""
        archive = self.artifacts.get(ArtifactKind.ARCHIVE)
        return None if archive is None else archive.sha256

    @property
    def size_bytes(self) -> int:
        """Total size of all artifacts."""
        return sum(a.size_bytes for a in self.artifacts.values())

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (metadata only, never the bytes)."""
        return {
            "metadata_version": self.metadata_version,
            "backup_id": self.backup_id,
            "router_id": self.router_id,
            "created_at": _iso(self.created_at),
            "last_seen_at": _iso(self.last_seen_at),
            "backup_type": self.backup_type.value,
            "reason": self.reason.value,
            "status": self.status.value,
            "error_class": None if self.error_class is None else self.error_class.value,
            "fetch_method": self.fetch_method,
            "content_hash": self.content_hash,
            "uci_hash": self.uci_hash,
            "openwrt_version": self.openwrt_version,
            "hardware_model": self.hardware_model,
            "board_name": self.board_name,
            "compatibility": (
                None if self.compatibility is None else self.compatibility.to_dict()
            ),
            "artifacts": {
                str(kind): ref.to_dict() for kind, ref in sorted(self.artifacts.items())
            },
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "validation": self.validation.to_dict(),
            "links": self.links.to_dict(),
            "created_by": self.created_by.to_dict(),
            "contains_secrets": self.contains_secrets,
            "protected": self.protected,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BackupRecord:
        """Parse (and migrate) index metadata; raises BackupMetadataError."""
        if not isinstance(data, Mapping):
            raise BackupMetadataError("Backup metadata must be a mapping")
        current = migrate_backup_metadata(data)
        try:
            return cls._from_current(current)
        except (KeyError, TypeError, ValueError) as err:
            raise BackupMetadataError(
                f"Invalid backup metadata: {type(err).__name__}: {err}"
            ) from err

    @classmethod
    def _from_current(cls, data: Mapping[str, Any]) -> BackupRecord:
        """Parse metadata already at the current version."""
        created_at = _parse_dt(data["created_at"], "created_at")
        if created_at is None:
            raise ValueError("created_at is required")
        raw_artifacts = data.get("artifacts") or {}
        if not isinstance(raw_artifacts, Mapping):
            raise TypeError("artifacts must be a mapping")
        compat = data.get("compatibility")
        error_class = data.get("error_class")
        return cls(
            backup_id=data["backup_id"],
            router_id=data["router_id"],
            created_at=created_at,
            last_seen_at=_parse_dt(data.get("last_seen_at"), "last_seen_at"),
            backup_type=BackupType(data["backup_type"]),
            reason=BackupReason(data["reason"]),
            status=VersionStatus(data.get("status", VersionStatus.OK)),
            error_class=None if error_class is None else ErrorClass(error_class),
            fetch_method=_opt_str(data, "fetch_method"),
            content_hash=_opt_hash(data, "content_hash"),
            uci_hash=_opt_hash(data, "uci_hash"),
            openwrt_version=_opt_str(data, "openwrt_version"),
            hardware_model=_opt_str(data, "hardware_model"),
            board_name=_opt_str(data, "board_name"),
            compatibility=(
                None if compat is None else CompatibilityInfo.from_dict(compat)
            ),
            artifacts={
                str(kind): ArtifactRef.from_dict(ref)
                for kind, ref in raw_artifacts.items()
            },
            validation=ValidationInfo.from_dict(data.get("validation") or {}),
            links=BackupLinks.from_dict(data.get("links")),
            created_by=Actor.from_dict(data["created_by"]),
            contains_secrets=data.get("contains_secrets", True) is not False,
            protected=data.get("protected") is True,
            note=_opt_str(data, "note"),
            metadata_version=data["metadata_version"],
        )


# Alias: "version" and "backup" name the same record.
VersionRecord = BackupRecord


@dataclass(frozen=True, kw_only=True, slots=True)
class VersionMeta:
    """Metadata handed to ``async_put_version`` together with the artifacts."""

    backup_type: BackupType
    reason: BackupReason
    created_by: Actor
    status: VersionStatus = VersionStatus.OK
    error_class: ErrorClass | None = None
    fetch_method: str | None = None
    content_hash: str | None = None
    uci_hash: str | None = None
    openwrt_version: str | None = None
    hardware_model: str | None = None
    board_name: str | None = None
    compatibility: CompatibilityInfo | None = None
    contains_secrets: bool = True
    note: str | None = None
    links: BackupLinks = BackupLinks()
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        """Validate hashes and the note."""
        for name in ("content_hash", "uci_hash"):
            value = getattr(self, name)
            if value is not None and not is_sha256(value):
                raise ValueError(f"{name} must be 64 lower-case hex characters")
        _check_note(self.note)


@dataclass(frozen=True, kw_only=True, slots=True)
class PutVersionResult:
    """Result of ``async_put_version``: dedup hit means ``created=False``."""

    record: BackupRecord
    created: bool

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {"record": self.record.to_dict(), "created": self.created}


@dataclass(frozen=True, kw_only=True, slots=True)
class SweepReport:
    """What the startup sweep of the version store did."""

    checked_at: datetime
    partial_deleted: int = 0
    orphaned_moved: int = 0
    marked_missing: int = 0

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "checked_at": _iso(self.checked_at),
            "partial_deleted": self.partial_deleted,
            "orphaned_moved": self.orphaned_moved,
            "marked_missing": self.marked_missing,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class DriftAck:
    """User decision about one drift (stored in the core's catalog store)."""

    router_id: str
    drift_id: str
    state: DriftAckState
    actor: Actor
    ts: datetime
    note: str | None = None

    def __post_init__(self) -> None:
        """Validate."""
        object.__setattr__(self, "state", DriftAckState(self.state))
        _require_aware(self.ts, "ts")
        _check_note(self.note)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "router_id": self.router_id,
            "drift_id": self.drift_id,
            "state": self.state.value,
            "actor": self.actor.to_dict(),
            "ts": _iso(self.ts),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DriftAck:
        """Inverse of :meth:`to_dict`; ValueError/TypeError/KeyError on bad data."""
        ts = _parse_dt(data["ts"], "ts")
        if ts is None:
            raise ValueError("ts is required")
        return cls(
            router_id=data["router_id"],
            drift_id=data["drift_id"],
            state=DriftAckState(data["state"]),
            actor=Actor.from_dict(data["actor"]),
            ts=ts,
            note=_opt_str(data, "note"),
        )


# ---------------------------------------------------------------------------
# Provider requests and results
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class CaptureRequest:
    """Read the live configuration (no write on the router)."""

    router_id: str
    actor: Actor
    correlation_id: str | None = None
    configs: tuple[str, ...] | None = None  # UCI config names; None = all


@dataclass(frozen=True, kw_only=True, slots=True)
class ConfigSnapshot:
    """Structured live configuration: ``configs[config][section][option]``."""

    router_id: str
    captured_at: datetime
    configs: Mapping[str, Mapping[str, Any]]
    openwrt_version: str | None = None
    board_name: str | None = None
    format: str = "uci_json"
    format_version: int = 1
    contains_secrets: bool = True

    @property
    def checksum(self) -> str:
        """sha256 of the canonical (unmasked) configuration content."""
        return canonical_checksum(self.configs)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form with secrets masked."""
        return {
            "router_id": self.router_id,
            "captured_at": _iso(self.captured_at),
            "configs": mask_secrets(self.configs),
            "openwrt_version": self.openwrt_version,
            "board_name": self.board_name,
            "format": self.format,
            "format_version": self.format_version,
            "contains_secrets": self.contains_secrets,
            "checksum": self.checksum,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class CollectRequest:
    """Ask the provider to fetch a version from the router (read only)."""

    router_id: str
    backup_type: BackupType
    reason: BackupReason
    actor: Actor
    correlation_id: str | None = None
    note: str | None = None
    links: BackupLinks = BackupLinks()
    fetch_method: str | None = None  # preferred path; None = provider's chain


@dataclass(frozen=True, kw_only=True, slots=True)
class CollectedVersion:
    """What a provider fetched: artifact bytes plus metadata. Not stored yet."""

    artifacts: Mapping[str, ArtifactPayload]
    meta: VersionMeta
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True, slots=True)
class ConfigRef:
    """A stored version (``backup_id``) or the LIVE configuration of a router."""

    backup_id: str | None = None
    router_id: str | None = None

    def __post_init__(self) -> None:
        """Exactly one of backup_id / router_id."""
        if (self.backup_id is None) == (self.router_id is None):
            raise ValueError("ConfigRef needs exactly one of backup_id, router_id")

    @classmethod
    def backup(cls, backup_id: str) -> ConfigRef:
        """Reference to a stored version."""
        return cls(backup_id=backup_id)

    @classmethod
    def live(cls, router_id: str) -> ConfigRef:
        """Reference to the live configuration of a router."""
        return cls(router_id=router_id)

    @property
    def kind(self) -> ConfigRefKind:
        """BACKUP or LIVE."""
        return ConfigRefKind.LIVE if self.router_id else ConfigRefKind.BACKUP

    @property
    def is_live(self) -> bool:
        """True for a LIVE reference."""
        return self.kind is ConfigRefKind.LIVE

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "kind": self.kind.value,
            "backup_id": self.backup_id,
            "router_id": self.router_id,
        }


# What a provider compares: a stored version or a live snapshot.
ConfigSource = BackupRecord | ConfigSnapshot
# Reads stored artifact bytes (the core's VersionStore.async_read_artifact).
ArtifactReader = Callable[[StorageRef], Awaitable[bytes]]


@dataclass(frozen=True, kw_only=True, slots=True)
class ConfigChange:
    """One UCI-level change; secret options are masked in to_dict().

    ``area``/``risk`` are provider classifications (config-manager: Area,
    Risk), kept as strings.
    """

    kind: ChangeKind
    config: str
    section: str
    option: str | None = None  # None = whole section added/removed
    section_type: str | None = None
    before: Any = None
    after: Any = None
    area: str | None = None
    risk: str | None = None

    @property
    def secret(self) -> bool:
        """True if the option names a secret (values are masked)."""
        return self.option is not None and is_secret_key(self.option)

    def _raw(self) -> dict[str, Any]:
        """Unmasked content, only for checksums."""
        return {
            "kind": self.kind,
            "config": self.config,
            "section": self.section,
            "option": self.option,
            "section_type": self.section_type,
            "before": self.before,
            "after": self.after,
            "area": self.area,
            "risk": self.risk,
        }

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form with secrets masked."""
        data = self._raw()
        data["kind"] = self.kind.value
        if self.secret:
            data["before"] = mask_value(self.before)
            data["after"] = mask_value(self.after)
        else:
            data["before"] = mask_secrets(self.before)
            data["after"] = mask_secrets(self.after)
        data["secret"] = self.secret
        return data


@dataclass(frozen=True, kw_only=True, slots=True)
class ConfigDiff:
    """Difference between two configuration sources."""

    base: ConfigRef
    other: ConfigRef
    compared_at: datetime
    changes: tuple[ConfigChange, ...] = ()
    truncated: bool = False

    @property
    def has_changes(self) -> bool:
        """True if anything differs."""
        return bool(self.changes)

    def _raw(self) -> dict[str, Any]:
        """Unmasked content, only for checksums."""
        return {
            "base": self.base.to_dict(),
            "other": self.other.to_dict(),
            "changes": [c._raw() for c in self.changes],
            "truncated": self.truncated,
        }

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form with secrets masked."""
        counts = {kind.value: 0 for kind in ChangeKind}
        for change in self.changes:
            counts[change.kind.value] += 1
        return {
            "base": self.base.to_dict(),
            "other": self.other.to_dict(),
            "compared_at": _iso(self.compared_at),
            "changes": [c.to_dict() for c in self.changes],
            "counts": counts,
            "truncated": self.truncated,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class DriftReport:
    """Live configuration compared with a baseline version."""

    router_id: str
    baseline_backup_id: str
    checked_at: datetime
    drifted: bool
    diff: ConfigDiff
    drift_id: str | None = None  # stable id of this drift (dedup, acks)
    ack_state: DriftAckState | None = None
    ignored_paths: tuple[str, ...] = ()  # volatile options left out

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form with secrets masked."""
        return {
            "router_id": self.router_id,
            "baseline_backup_id": self.baseline_backup_id,
            "checked_at": _iso(self.checked_at),
            "drifted": self.drifted,
            "drift_id": self.drift_id,
            "ack_state": None if self.ack_state is None else self.ack_state.value,
            "diff": self.diff.to_dict(),
            "ignored_paths": list(self.ignored_paths),
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class CompatibilityIssue:
    """One finding of a restore compatibility check."""

    code: str  # e.g. "board_mismatch", "major_version_mismatch"
    message: str
    blocking: bool = True

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {"code": self.code, "message": self.message, "blocking": self.blocking}


@dataclass(frozen=True, kw_only=True, slots=True)
class CompatibilityCheck:
    """Can this version be restored to that router?"""

    compatible: bool
    issues: tuple[CompatibilityIssue, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "compatible": self.compatible,
            "issues": [i.to_dict() for i in self.issues],
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class RestoreStep:
    """One planned write of a restore."""

    order: int
    action: str  # e.g. "uci_set", "uci_delete", "archive_restore", "reboot"
    target: str  # e.g. "wireless.default_radio0.key" or a service name
    description: str | None = None
    detail: Mapping[str, Any] = field(default_factory=dict)

    def _raw(self) -> dict[str, Any]:
        """Unmasked content, only for checksums."""
        return {
            "order": self.order,
            "action": self.action,
            "target": self.target,
            "description": self.description,
            "detail": dict(self.detail),
        }

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form with secrets masked."""
        data = self._raw()
        data["detail"] = mask_secrets(self.detail)
        return data


@dataclass(frozen=True, kw_only=True, slots=True)
class RestorePlan:
    """Dry-run result: what a restore would do. Building it never writes.

    ``checksum`` is computed from the unmasked content; an approval is bound
    to it, so any change of the plan invalidates the approval.
    """

    plan_id: str
    backup_id: str
    source_router_id: str
    target_router_id: str
    provider_id: str
    created_at: datetime
    compatibility: CompatibilityCheck
    steps: tuple[RestoreStep, ...] = ()
    diff: ConfigDiff | None = None
    live_checksum: str | None = None  # ConfigSnapshot.checksum the plan used
    requires_reboot: bool = False
    warnings: tuple[str, ...] = ()
    instructions: tuple[str, ...] = ()  # i18n keys for a manual restore

    def _raw(self) -> dict[str, Any]:
        """Unmasked content, only for the checksum."""
        return {
            "plan_id": self.plan_id,
            "backup_id": self.backup_id,
            "source_router_id": self.source_router_id,
            "target_router_id": self.target_router_id,
            "provider_id": self.provider_id,
            "created_at": _iso(self.created_at),
            "compatibility": self.compatibility.to_dict(),
            "steps": [s._raw() for s in self.steps],
            "diff": None if self.diff is None else self.diff._raw(),
            "live_checksum": self.live_checksum,
            "requires_reboot": self.requires_reboot,
            "warnings": list(self.warnings),
            "instructions": list(self.instructions),
        }

    @property
    def checksum(self) -> str:
        """sha256 over the canonical unmasked plan content."""
        return canonical_checksum(self._raw())

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form with secrets masked."""
        return {
            "plan_id": self.plan_id,
            "backup_id": self.backup_id,
            "source_router_id": self.source_router_id,
            "target_router_id": self.target_router_id,
            "provider_id": self.provider_id,
            "created_at": _iso(self.created_at),
            "compatibility": self.compatibility.to_dict(),
            "steps": [s.to_dict() for s in self.steps],
            "diff": None if self.diff is None else self.diff.to_dict(),
            "live_checksum": self.live_checksum,
            "requires_reboot": self.requires_reboot,
            "warnings": list(self.warnings),
            "instructions": list(self.instructions),
            "checksum": self.checksum,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class RestoreResult:
    """Outcome of an executed restore."""

    approval_id: str
    plan_id: str
    router_id: str
    status: RestoreStatus
    started_at: datetime
    finished_at: datetime
    pre_restore_backup_id: str | None = None
    applied_steps: int = 0
    failed_step: int | None = None
    message: str | None = None
    reboot_required: bool = False
    rolled_back: bool = False
    correlation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "approval_id": self.approval_id,
            "plan_id": self.plan_id,
            "router_id": self.router_id,
            "status": self.status.value,
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at),
            "pre_restore_backup_id": self.pre_restore_backup_id,
            "applied_steps": self.applied_steps,
            "failed_step": self.failed_step,
            "message": self.message,
            "reboot_required": self.reboot_required,
            "rolled_back": self.rolled_back,
            "correlation_id": self.correlation_id,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class ExportHandle:
    """Download handle of an exported version; ``reader`` returns the bytes."""

    backup_id: str
    artifact: str  # ArtifactKind value
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    contains_secrets: bool
    reader: Callable[[], Awaitable[bytes]] = field(repr=False, compare=False)
    expires_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (without the reader)."""
        return {
            "backup_id": self.backup_id,
            "artifact": self.artifact,
            "filename": self.filename,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "contains_secrets": self.contains_secrets,
            "expires_at": _iso(self.expires_at),
        }


# ---------------------------------------------------------------------------
# Guard: approvals, decisions and write authorizations
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class ApprovalRequest:
    """Two-step approval of a critical action, bound to ``checksum``.

    ``subject_id`` is the plan_id (restore), backup_id (export) or a list
    key (delete); ``checksum`` is the binding checksum of the action.
    """

    approval_id: str
    action: str
    router_id: str
    subject_id: str
    checksum: str
    requested_by: Actor
    requested_at: datetime
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: Actor | None = None
    decided_at: datetime | None = None
    reason: str | None = None
    correlation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "approval_id": self.approval_id,
            "action": str(self.action),
            "router_id": self.router_id,
            "subject_id": self.subject_id,
            "checksum": self.checksum,
            "requested_by": self.requested_by.to_dict(),
            "requested_at": _iso(self.requested_at),
            "expires_at": _iso(self.expires_at),
            "status": self.status.value,
            "decided_by": (
                None if self.decided_by is None else self.decided_by.to_dict()
            ),
            "decided_at": _iso(self.decided_at),
            "reason": self.reason,
            "correlation_id": self.correlation_id,
        }


# Module-private mint sentinel: only the ActionGuard (core_guard.py) may call
# _mint_write_authorization(). Python cannot enforce this; tests and review do.
_MINT_SENTINEL: Final = object()


class WriteAuthorization:
    """Single-use permission for one guarded action, minted only by the guard.

    Bound to action, router_id and (optionally) a binding checksum. The
    component that performs the action (version store, provider) calls
    :meth:`consume` right before it acts. Every consume attempt uses the
    authorization up, also a failed one (fail closed).
    """

    __slots__ = (
        "_action",
        "_actor",
        "_approval_id",
        "_authorization_id",
        "_checksum",
        "_consumed",
        "_correlation_id",
        "_expires_at",
        "_issued_at",
        "_router_id",
    )

    def __init__(
        self,
        *,
        authorization_id: str,
        action: str,
        router_id: str,
        actor: Actor,
        issued_at: datetime,
        expires_at: datetime,
        checksum: str | None = None,
        approval_id: str | None = None,
        correlation_id: str | None = None,
        _sentinel: object = None,
    ) -> None:
        """Refuse construction outside the guard."""
        if _sentinel is not _MINT_SENTINEL:
            raise TypeError("WriteAuthorization can only be minted by the ActionGuard")
        _require_aware(issued_at, "issued_at")
        _require_aware(expires_at, "expires_at")
        self._authorization_id = authorization_id
        self._action = str(action)
        self._router_id = router_id
        self._actor = actor
        self._issued_at = issued_at
        self._expires_at = expires_at
        self._checksum = checksum
        self._approval_id = approval_id
        self._correlation_id = correlation_id
        self._consumed = False

    @property
    def authorization_id(self) -> str:
        """``wau_<32 hex>``."""
        return self._authorization_id

    @property
    def action(self) -> str:
        """The one action this authorizes (GuardedAction value or extension)."""
        return self._action

    @property
    def router_id(self) -> str:
        """The one router this authorizes."""
        return self._router_id

    @property
    def actor(self) -> Actor:
        """Who the action is performed for."""
        return self._actor

    @property
    def checksum(self) -> str | None:
        """Binding checksum (plan checksum, binding_checksum(...))."""
        return self._checksum

    @property
    def approval_id(self) -> str | None:
        """Approval this was minted from (critical actions)."""
        return self._approval_id

    @property
    def correlation_id(self) -> str | None:
        """Correlation id of the operation."""
        return self._correlation_id

    @property
    def issued_at(self) -> datetime:
        """Mint time."""
        return self._issued_at

    @property
    def expires_at(self) -> datetime:
        """After this, consume() fails."""
        return self._expires_at

    @property
    def consumed(self) -> bool:
        """True once consume() was called (successfully or not)."""
        return self._consumed

    def is_expired(self, now: datetime | None = None) -> bool:
        """True if past ``expires_at``."""
        return (now or utcnow()) >= self._expires_at

    def _deny(self, reason: str) -> AuthorizationError:
        """Build the error for a failed consume."""
        return AuthorizationError(
            f"WriteAuthorization rejected: {reason}",
            router_id=self._router_id,
            details={
                "reason": reason,
                "authorization_id": self._authorization_id,
                "action": self._action,
            },
        )

    def consume(
        self,
        *,
        action: str,
        router_id: str,
        checksum: str | None = None,
        now: datetime | None = None,
    ) -> None:
        """Use the authorization once or raise AuthorizationError.

        ``checksum`` is required (and must match) when the authorization is
        bound to one. Reasons: already_used, expired, action_mismatch,
        router_mismatch, checksum_mismatch.
        """
        if self._consumed:
            raise self._deny("already_used")
        self._consumed = True
        if self.is_expired(now):
            raise self._deny("expired")
        if str(action) != self._action:
            raise self._deny("action_mismatch")
        if router_id != self._router_id:
            raise self._deny("router_mismatch")
        if self._checksum is not None and checksum != self._checksum:
            raise self._deny("checksum_mismatch")

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form for audit."""
        return {
            "authorization_id": self._authorization_id,
            "action": self._action,
            "router_id": self._router_id,
            "actor": self._actor.to_dict(),
            "checksum": self._checksum,
            "approval_id": self._approval_id,
            "correlation_id": self._correlation_id,
            "issued_at": _iso(self._issued_at),
            "expires_at": _iso(self._expires_at),
            "consumed": self._consumed,
        }

    def __repr__(self) -> str:
        """Short representation."""
        return (
            f"WriteAuthorization({self._authorization_id}, {self._action}, "
            f"{self._router_id}, consumed={self._consumed})"
        )


def _mint_write_authorization(
    *,
    action: str,
    router_id: str,
    actor: Actor,
    checksum: str | None = None,
    approval_id: str | None = None,
    correlation_id: str | None = None,
    ttl: timedelta = WRITE_AUTHORIZATION_TTL,
    now: datetime | None = None,
) -> WriteAuthorization:
    """Mint a WriteAuthorization. PRIVATE: only core_guard.ActionGuard calls it."""
    issued = now or utcnow()
    return WriteAuthorization(
        authorization_id=new_id(AUTHORIZATION_ID_PREFIX),
        action=action,
        router_id=router_id,
        actor=actor,
        issued_at=issued,
        expires_at=issued + ttl,
        checksum=checksum,
        approval_id=approval_id,
        correlation_id=correlation_id,
        _sentinel=_MINT_SENTINEL,
    )


@dataclass(frozen=True, kw_only=True, slots=True)
class AuthorizationDecision:
    """Synchronous answer of ``ActionGuardProtocol.authorize``.

    APPROVED carries ``authorization``; PENDING carries ``approval_request``;
    DENIED carries ``reason``. ``audit_id`` is the event_id of the audit
    entry written for this decision.
    """

    state: DecisionState
    action: str
    router_id: str
    audit_id: str
    authorization: WriteAuthorization | None = field(default=None, repr=False)
    approval_request: ApprovalRequest | None = None
    reason: str | None = None

    @property
    def approved(self) -> bool:
        """True if an authorization was minted."""
        return self.state is DecisionState.APPROVED

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "state": self.state.value,
            "action": str(self.action),
            "router_id": self.router_id,
            "audit_id": self.audit_id,
            "authorization": (
                None if self.authorization is None else self.authorization.to_dict()
            ),
            "approval_request": (
                None
                if self.approval_request is None
                else self.approval_request.to_dict()
            ),
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class CoreEvent:
    """One audit / bus event.

    ``type`` is a CoreEventType value or a module type below a registered
    prefix (kept as str when it comes from a newer version). ``data`` must
    carry ids and counters, never configuration values; it is masked on
    output as a second safety net. Events with the same ``dedup_key`` within
    the cooldown are neither stored nor fired.
    """

    event_id: str
    ts: datetime
    type: str
    source: str
    severity: Severity = Severity.INFO
    result: EventResult = EventResult.INFO
    router_id: str | None = None
    entry_id: str | None = None
    actor: Actor | None = None
    correlation_id: str | None = None
    dedup_key: str | None = None
    data: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate the timestamp."""
        _require_aware(self.ts, "ts")

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form with ``data`` masked."""
        return {
            "event_id": self.event_id,
            "ts": _iso(self.ts),
            "type": str(self.type),
            "source": self.source,
            "severity": self.severity.value,
            "result": self.result.value,
            "router_id": self.router_id,
            "entry_id": self.entry_id,
            "actor": None if self.actor is None else self.actor.to_dict(),
            "correlation_id": self.correlation_id,
            "dedup_key": self.dedup_key,
            "data": mask_secrets(dict(self.data)),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> CoreEvent:
        """Inverse of :meth:`to_dict`; ValueError/TypeError/KeyError on bad data."""
        raw_type = data["type"]
        if not isinstance(raw_type, str) or not raw_type:
            raise ValueError("event type must be a non-empty string")
        try:
            event_type: str = CoreEventType(raw_type)
        except ValueError:
            event_type = raw_type
        ts = _parse_dt(data["ts"], "ts")
        if ts is None:
            raise ValueError("ts is required")
        actor = data.get("actor")
        payload = data.get("data")
        return cls(
            event_id=data["event_id"],
            ts=ts,
            type=event_type,
            source=data["source"],
            severity=Severity(data.get("severity", Severity.INFO)),
            result=EventResult(data.get("result", EventResult.INFO)),
            router_id=_opt_str(data, "router_id"),
            entry_id=_opt_str(data, "entry_id"),
            actor=Actor.from_dict(actor) if isinstance(actor, Mapping) else None,
            correlation_id=_opt_str(data, "correlation_id"),
            dedup_key=_opt_str(data, "dedup_key"),
            data=dict(payload) if isinstance(payload, Mapping) else {},
        )


CoreEventListener = Callable[[CoreEvent], None]


# ---------------------------------------------------------------------------
# Service interfaces (implemented in later steps; contract only)
# ---------------------------------------------------------------------------


@runtime_checkable
class ConfigBackupProvider(Protocol):
    """The one configuration provider (config-manager).

    Produces and analyses artifacts only: it reads from the router through
    the entry's existing OpenWrtAPI and never stores, exports or deletes
    bytes itself (the core's VersionStore does). Stored bytes come in
    through ``read``. Exactly one provider can be registered.
    """

    @property
    def provider_id(self) -> str:
        """Stable id, e.g. ``config_manager``."""

    @property
    def provider_api_version(self) -> int:
        """Version of this protocol the provider implements."""

    def supported(self, router: RouterRecord) -> bool:
        """Cheap, synchronous pre-check (no router call)."""

    async def async_probe(
        self, conn: RouterConnection
    ) -> Mapping[str, CapabilityStatus]:
        """Probe config.* capabilities on the router (setup, ACL redeploy,
        firmware change; never in the poll)."""

    async def async_capture(
        self, conn: RouterConnection, request: CaptureRequest
    ) -> ConfigSnapshot:
        """Read the live configuration."""

    async def async_collect(
        self, conn: RouterConnection, request: CollectRequest
    ) -> CollectedVersion:
        """Fetch a version (archive, uci, inventory) from the router."""

    async def async_validate(
        self, record: BackupRecord, read: ArtifactReader
    ) -> ValidationInfo:
        """Check a stored version beyond checksums (format, members)."""

    async def async_compare(
        self, base: ConfigSource, other: ConfigSource, read: ArtifactReader
    ) -> ConfigDiff:
        """Compare two sources (versions or live snapshots)."""

    async def async_detect_drift(
        self,
        conn: RouterConnection,
        baseline: BackupRecord,
        read: ArtifactReader,
        acks: Sequence[DriftAck],
    ) -> DriftReport:
        """Compare live configuration with ``baseline``."""

    async def async_prepare_restore(
        self,
        conn: RouterConnection,
        record: BackupRecord,
        target: RouterRecord,
        read: ArtifactReader,
    ) -> RestorePlan:
        """Dry run: compatibility plus plan. Never writes."""

    async def async_execute_restore(
        self,
        conn: RouterConnection,
        plan: RestorePlan,
        authorization: WriteAuthorization,
    ) -> RestoreResult:
        """Write to the router. Must consume ``authorization`` first.

        Phase 1: the core only calls this when the provider declares
        ``config.restore`` available; otherwise CapabilityUnavailableError.
        """


@runtime_checkable
class RouterRegistryProtocol(Protocol):
    """Read side of the router registry (fleet-wide, one per HA instance)."""

    def get(self, router_id: str) -> RouterRecord:
        """Record by router id; RouterNotFoundError if unknown."""

    def get_by_entry(self, entry_id: str) -> RouterRecord:
        """Active record of a config entry; RouterNotFoundError if none."""

    def find(self, router_id: str) -> RouterRecord | None:
        """Record by router id or None."""

    def list(self, *, include_orphaned: bool = False) -> tuple[RouterRecord, ...]:
        """All active (and optionally orphaned) records."""

    def capabilities(self, router_id: str) -> Mapping[str, CapabilityStatus]:
        """Capability map of a router."""

    def has_capability(self, router_id: str, capability: str) -> bool:
        """True if available now."""

    def require_capability(self, router_id: str, capability: str) -> None:
        """Raise CapabilityUnavailableError unless available."""

    def adoption_candidates(self, entry_id: str) -> tuple[AdoptionCandidate, ...]:
        """Orphaned records whose fingerprint matches the entry's router."""

    async def async_adopt(
        self, entry_id: str, orphan_router_id: str, *, actor: Actor
    ) -> RouterRecord:
        """Bind an orphaned record (history, versions) to ``entry_id``."""


@runtime_checkable
class ActionGuardProtocol(Protocol):
    """Decides every mutating or critical action; mints WriteAuthorizations."""

    def authorize(
        self,
        action: str,
        router_id: str,
        actor: Actor,
        *,
        subject_id: str | None = None,
        checksum: str | None = None,
        approval_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuthorizationDecision:
        """Synchronous decision; always writes one audit entry."""

    def approve(self, approval_id: str, *, actor: Actor) -> ApprovalRequest:
        """Admin user approves a pending request."""

    def reject(
        self, approval_id: str, *, actor: Actor, reason: str | None = None
    ) -> ApprovalRequest:
        """Admin user rejects a pending request."""

    def get_approval(self, approval_id: str) -> ApprovalRequest:
        """Request by id; ApprovalInvalidError if unknown."""

    def pending_approvals(
        self, router_id: str | None = None
    ) -> tuple[ApprovalRequest, ...]:
        """Open requests, newest first."""

    def register_action(
        self,
        name: str,
        action_class: ActionClass,
        *,
        module: str,
        admin_user_only: bool = False,
    ) -> None:
        """Register an extension action ``<module>.<action>``."""


@runtime_checkable
class VersionStoreProtocol(Protocol):
    """Index plus artifact files under hass.config.path(*CONFIG_BACKUP_PATH).

    Directories 0700, files 0600, atomic writes via ``.partial`` + rename,
    index entry written last, all file I/O in the executor.
    """

    async def async_put_version(
        self,
        router_id: str,
        artifacts: Mapping[str, ArtifactPayload],
        meta: VersionMeta,
        *,
        authorization: WriteAuthorization,
    ) -> PutVersionResult:
        """Store a version; a content_hash/uci_hash hit only moves last_seen_at."""

    async def async_list_versions(
        self,
        router_id: str | None = None,
        *,
        since: datetime | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> tuple[BackupRecord, ...]:
        """Versions, newest first."""

    async def async_get_version(self, version_id: str) -> BackupRecord:
        """One version; BackupNotFoundError if unknown."""

    async def async_read_artifact(self, storage_ref: StorageRef) -> bytes:
        """Bytes of one artifact (checks storage_format and sha256)."""

    async def async_delete_versions(
        self, version_ids: Sequence[str], *, authorization: WriteAuthorization
    ) -> tuple[str, ...]:
        """Delete versions (delete or prune authorization); returns deleted ids."""

    async def async_set_protected(
        self, version_id: str, protected: bool, *, authorization: WriteAuthorization
    ) -> BackupRecord:
        """Set or clear protection against prune."""

    async def async_set_validation(
        self, version_id: str, validation: ValidationInfo
    ) -> BackupRecord:
        """Store a validation result (core-internal, no authorization)."""

    async def async_put_drift_ack(
        self, ack: DriftAck, *, authorization: WriteAuthorization
    ) -> DriftAck:
        """Store a drift acknowledgement."""

    async def async_list_drift_acks(self, router_id: str) -> tuple[DriftAck, ...]:
        """Acknowledgements of a router."""

    async def async_sweep(self) -> SweepReport:
        """Startup cleanup: partials, index-less files, missing files."""

    async def async_archive_router(self, router_id: str) -> None:
        """Move a removed router's folder to ``removed/<router_id>/``."""

    def usage_bytes(self, router_id: str | None = None) -> int:
        """Bytes used by one router or in total."""


@runtime_checkable
class ConfigurationApiProtocol(Protocol):
    """Configuration API v1, from ``async_get_configuration_api(hass, 1)``."""

    @property
    def api_version(self) -> int:
        """The version this object implements."""

    @property
    def registry(self) -> RouterRegistryProtocol:
        """Router registry."""

    @property
    def guard(self) -> ActionGuardProtocol:
        """Action guard."""

    @property
    def versions(self) -> VersionStoreProtocol:
        """Version store."""

    @property
    def provider_id(self) -> str | None:
        """Registered provider or None."""

    def register_provider(self, provider: ConfigBackupProvider) -> Callable[[], None]:
        """Register the provider; returns an unregister callback."""

    async def async_get_installation_key(self) -> bytes:
        """32-byte installation key for HMAC secret digests."""

    async def async_capture(
        self, router_id: str, *, actor: Actor, configs: tuple[str, ...] | None = None
    ) -> ConfigSnapshot:
        """Read the live configuration (READ)."""

    async def async_list_backups(
        self,
        router_id: str | None = None,
        *,
        since: datetime | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> tuple[BackupRecord, ...]:
        """List versions (READ)."""

    async def async_get_backup(self, backup_id: str) -> BackupRecord:
        """One version (READ)."""

    async def async_validate_backup(self, backup_id: str) -> BackupRecord:
        """Validate and store the result (READ)."""

    async def async_compare(
        self, base: ConfigRef, other: ConfigRef, *, actor: Actor
    ) -> ConfigDiff:
        """Compare two references (READ)."""

    async def async_detect_drift(
        self, router_id: str, *, actor: Actor, baseline_backup_id: str | None = None
    ) -> DriftReport:
        """Compare live configuration with a baseline (READ)."""

    async def async_check_restore_compatibility(
        self, backup_id: str, target_router_id: str, *, actor: Actor
    ) -> CompatibilityCheck:
        """Compatibility only (READ, audited as restore_checked)."""

    async def async_prepare_restore(
        self, backup_id: str, target_router_id: str, *, actor: Actor
    ) -> RestorePlan:
        """Dry run (READ, audited as restore_checked)."""

    async def async_create_backup(
        self,
        router_id: str,
        *,
        reason: BackupReason,
        actor: Actor,
        backup_type: BackupType | None = None,
        note: str | None = None,
        links: BackupLinks | None = None,
    ) -> PutVersionResult:
        """Collect and store a version (MUTATING)."""

    async def async_set_protected(
        self, backup_id: str, protected: bool, *, actor: Actor
    ) -> BackupRecord:
        """Protect against prune (MUTATING, admin user)."""

    async def async_acknowledge_drift(
        self,
        router_id: str,
        drift_id: str,
        *,
        state: DriftAckState,
        actor: Actor,
        note: str | None = None,
    ) -> DriftAck:
        """Acknowledge a drift (MUTATING, admin user)."""

    async def async_list_drift_acks(self, router_id: str) -> tuple[DriftAck, ...]:
        """Acknowledgements of a router (READ)."""

    async def async_request_export(
        self, backup_id: str, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to export a plain-text archive (CRITICAL, admin user)."""

    async def async_export_backup(
        self, approval_id: str, *, actor: Actor
    ) -> ExportHandle:
        """Export after approval; single use per download."""

    async def async_request_deletion(
        self, backup_ids: Sequence[str], *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to delete versions (CRITICAL)."""

    async def async_delete_backups(
        self, approval_id: str, *, actor: Actor
    ) -> tuple[str, ...]:
        """Delete after approval."""

    async def async_request_restore(
        self, plan: RestorePlan, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to restore (CRITICAL; phase 1: CapabilityUnavailableError)."""

    async def async_approve(self, approval_id: str, *, actor: Actor) -> ApprovalRequest:
        """Approve any pending request (admin user)."""

    async def async_reject(
        self, approval_id: str, *, actor: Actor, reason: str | None = None
    ) -> ApprovalRequest:
        """Reject any pending request (admin user)."""

    async def async_execute_restore(
        self, approval_id: str, *, actor: Actor
    ) -> RestoreResult:
        """Restore after approval (phase 1: CapabilityUnavailableError)."""

    def get_approval(self, approval_id: str) -> ApprovalRequest:
        """Request by id."""

    def pending_approvals(
        self, router_id: str | None = None
    ) -> tuple[ApprovalRequest, ...]:
        """Open requests."""

    def events(
        self,
        *,
        router_id: str | None = None,
        types: Iterable[str] | None = None,
        since: datetime | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> tuple[CoreEvent, ...]:
        """Audit entries, newest first."""

    def subscribe(self, listener: CoreEventListener) -> Callable[[], None]:
        """Listen to new events; returns an unsubscribe callback."""

    def register_event_prefix(self, prefix: str, *, module: str) -> None:
        """Allow a module's own event types below ``prefix``."""

    def emit(
        self,
        event_type: str,
        *,
        source: str,
        router_id: str | None = None,
        severity: Severity = Severity.INFO,
        result: EventResult = EventResult.INFO,
        actor: Actor | None = None,
        correlation_id: str | None = None,
        dedup_key: str | None = None,
        data: Mapping[str, Any] | None = None,
    ) -> CoreEvent | None:
        """Write an audit entry and fire EVENT_CORE; None if deduplicated."""
