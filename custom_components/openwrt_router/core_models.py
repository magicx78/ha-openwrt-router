"""Data types of the enterprise core and the Configuration API v1.

Plan: docs/plans/2026-11-17-enterprise-core.md, contract:
docs/dev/configuration-api-v1.md.

This module holds constants, enums, frozen dataclasses, pure helpers (ids,
checksums, guard policy, dedup and retention rules) and the service
interfaces (Protocols) at the end of the file. It holds no state, makes no
router call and touches ``hass`` only in the actor helpers.

Rules for changes within API v1:

* Additive only: new optional fields with a default, new methods, new
  non-persisted enum values (capabilities, event types, reasons).
* A new value of an enum that is PERSISTED in a versioned record
  (``BackupType``, ``BackupReason``, ``VersionStatus``, ``ValidationStatus``,
  ``ArtifactKind``, ``ErrorClass`` in BackupRecord, ``DriftAckState``,
  ``ActorKind``) bumps that record's format version (BACKUP_METADATA_VERSION
  or the store version), because older readers reject unknown values.

Dataclasses are ``frozen`` and ``kw_only``; mapping fields are stored as
read-only ``MappingProxyType`` (deep), enum fields are coerced and checked.

Naming: a "backup" and a "version" are the same thing. The id is
``backup_id`` (``bkp_<32 hex>``); ``BackupRecord.version_id`` is an alias.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import re
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
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
    NON_PERSISTED_ERROR_CLASSES,
    ApiVersionError,
    ApprovalInvalidError,
    ApprovalRequiredError,
    AuthorizationError,
    BackupMetadataError,
    ErrorClass,
    InvalidStorageRefError,
    UnsupportedStorageFormatError,
    VersionProtectedError,
)
from .core_masking import (
    IDENTIFIER_PSEUDONYM_HEX_LENGTH,
    IDENTIFIER_PSEUDONYM_PREFIXES,
    is_secret_option,
    mask_secrets,
    mask_value,
    scrub_text,
)
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
# Version of the ConfigBackupProvider protocol a provider implements;
# register_provider() refuses a provider_api_version outside this tuple.
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
VERIFICATION_ID_PREFIX: Final = "vac_"
CORRELATION_ID_PREFIX: Final = "cor_"
# Fleet-wide subject (installation_key_reset, audit entries of an unknown
# router). Never a router id: the registry refuses it (contract §4.1).
FLEET_ROUTER_ID: Final = "-"

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
# Created ONLY on the very first initialisation (no versions, no acks, no key
# store); never regenerated silently (see installation_key_state).
INSTALLATION_KEY_STORE_KEY: Final = f"{DOMAIN}.installation_key"
INSTALLATION_KEY_BYTES: Final = 32
INSTALLATION_KEY_ID_LENGTH: Final = 16
# Repair issue id raised when the key is lost (issue registry, later step).
ISSUE_INSTALLATION_KEY_LOST: Final = "installation_key_lost"
# An unreadable key file was replaced by a new key (no versions existed).
ISSUE_INSTALLATION_KEY_REPLACED: Final = "installation_key_replaced"
CORE_STORE_VERSION: Final = 1

# Per-router SSH host-key pins of the config/backup path (1.44.0). Own store
# (private, atomic), keyed by router_id: the pin follows the router, not
# its address. Only the pinned path reads it; the shared SSH transport of
# the poll keeps its known_hosts=None behaviour.
SSH_PIN_STORE_KEY: Final = f"{DOMAIN}.ssh_host_keys"
SSH_PIN_STORE_MINOR_VERSION: Final = 1
# What happens with a router's FIRST host key on the pinned path:
# "confirm" = it becomes a PENDING pin and every pinned call refuses
#             (reason pin_pending) until an admin confirms the fingerprint
#             with the critical guard action ssh_pin_confirm;
# "tofu"    = trust on first use (the key is pinned at once, audited).
# One constant on purpose: the owner decides; "confirm" until then.
SSH_PIN_POLICY_CONFIRM: Final = "confirm"
SSH_PIN_POLICY_TOFU: Final = "tofu"
SSH_PIN_FIRST_USE_POLICY: Final = SSH_PIN_POLICY_CONFIRM

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
# A locator is one file name inside the router folder.
STORAGE_LOCATOR_PATTERN: Final = re.compile(r"[A-Za-z0-9._-]+")
NOTE_MAX_LENGTH: Final = 500
# Version warnings are machine codes, optionally with a subject:
# "config_missing_in_archive:firewall", "uci_missing:sqm".
WARNING_CODE_PATTERN: Final = re.compile(r"[a-z0-9_]+(?::[A-Za-z0-9_.@-]+)?")
MAX_WARNINGS: Final = 50

# Snapshot format v1 of the configuration provider (ConfigSnapshot.configs):
# configs[config] = {"sections": {name: {"type": str, "options": {opt: v}}},
#                    "order": [section names]}; secret values are
# {"secret": "<hmac16>"} markers. The core treats configs as opaque.
SNAPSHOT_FORMAT_UCI_NORMALIZED: Final = "uci_normalized"

# Options-flow switch that gates all config.* capabilities and the matching
# ACL tier. Default OFF (1.44.0): only an explicit True enables it.
OPTION_CONFIG_BACKUP_ENABLED: Final = "config_backup_enabled"
DEFAULT_CONFIG_BACKUP_ENABLED: Final = False

# Naming scheme (contract §5 / §12.3). Capability namespaces:
# core-owned (derived from the poll) ...
CORE_CAPABILITY_NAMESPACES: Final = ("transport.", "data.", "stream.", "pkg.")
# ... decided by the one configuration provider (config-manager) ...
CONFIG_CAPABILITY_NAMESPACE: Final = "config."
# ... and reserved for modules: the core never names a capability there,
# with ONE exception (1.44.0): rf.txpowerlist / rf.survey / rf.scan are
# facts about the deployed rpcd ACL, which only the core knows; they are
# listed in CORE_OWNED_MODULE_CAPABILITIES and refused for module detectors.
# security. = Security Center, diag. = Network Diagnostics, rf. = WiFi RF,
# log. = log sources shared by several modules.
RESERVED_NAMESPACES: Final = ("security.", "diag.", "log.", "rf.")
# Capability namespace of each known module (log. is shared, not owned).
MODULE_CAPABILITY_NAMESPACES: Final[Mapping[str, str]] = MappingProxyType(
    {"security_center": "security.", "net_diagnostics": "diag.", "wifi_rf": "rf."}
)
# Event prefix of each known module. A known module may only register its
# own prefix; nobody else may register below it. Event prefixes never use a
# core event namespace (CORE_EVENT_NAMESPACES) or a capability namespace.
MODULE_EVENT_PREFIXES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "security_center": "security_center.",
        "net_diagnostics": "net_diagnostics.",
        "wifi_rf": "wifi_rf.",
    }
)

APPROVAL_TTL: Final = timedelta(minutes=15)
WRITE_AUTHORIZATION_TTL: Final = timedelta(minutes=5)
# A VerifiedActor is accepted by the guard for this long after verification.
ACTOR_VERIFICATION_TTL: Final = timedelta(seconds=60)
# Mutating operations wait at most this long for the per-router lock.
ROUTER_LOCK_TIMEOUT: Final = timedelta(minutes=5)
# Fleet-wide backup queue owned by the core. Order of one backup:
# fleet slot -> router lock -> authorize -> collect -> put, so a
# WriteAuthorization is minted only once the backup can start.
FLEET_BACKUP_CONCURRENCY: Final = 1
# Fixed window: a repeat of the same dedup scope inside it is not published.
FAILURE_EVENT_COOLDOWN: Final = timedelta(hours=24)
AUDIT_MAX_EVENTS: Final = 1000
# Core entries of the security ring (only core entries evict them).
SECURITY_AUDIT_MAX_EVENTS: Final = 500
# Security-relevant module entries (review M2 of PR #56): a separate quota,
# per module and for all modules together, so a module never pushes a core
# entry out and one module cannot push out another beyond its own quota.
SECURITY_MODULE_QUOTA: Final = 100
SECURITY_MODULE_MAX_EVENTS: Final = 500
AUDIT_RETENTION_DAYS: Final = 90
# General ring: a guaranteed share per owner (core or module). It is a floor,
# not a cap: while the ring has room anyone may write more. Only when it is
# full does the oldest entry of an owner above its share go, so a loud module
# never pushes out entries of an owner below its share. 100 per module equals
# SECURITY_MODULE_QUOTA and covers six modules (config_manager,
# net_diagnostics, security_center, wifi_rf, traffic_analytics and one more);
# the core keeps the rest (400): its fleet-wide entries (routers, backups,
# approvals, configuration) are the trail diagnostics rely on. The shares add
# up to AUDIT_MAX_EVENTS, which stays the hard limit of the ring.
AUDIT_MODULE_SHARE: Final = 100
AUDIT_SHARED_MODULES: Final = 6
AUDIT_CORE_SHARE: Final = AUDIT_MAX_EVENTS - AUDIT_SHARED_MODULES * AUDIT_MODULE_SHARE
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


def is_fleet_router_id(value: object) -> bool:
    """True for ``FLEET_ROUTER_ID`` ("-"), the fleet-wide subject."""
    return isinstance(value, str) and value == FLEET_ROUTER_ID


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
    if isinstance(value, Mapping):
        return dict(value)
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
    """Checksum an approval / WriteAuthorization is bound to (contract §6.4)."""
    return canonical_checksum(list(parts))


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


def validate_locator(locator: object) -> str:
    """Return ``locator`` if it is one safe file name, else InvalidStorageRefError."""
    if (
        not isinstance(locator, str)
        or STORAGE_LOCATOR_PATTERN.fullmatch(locator) is None
        or ".." in locator
        or locator.startswith(".")
    ):
        raise InvalidStorageRefError(
            "Storage locator must be a plain file name",
            details={"reason": "bad_locator"},
        )
    return locator


def resolve_artifact_path(router_dir: str, locator: str) -> str:
    """Absolute path of ``locator`` inside ``router_dir``.

    Follows symlinks (``os.path.realpath``), so call it in the executor. Raises
    InvalidStorageRefError if the result leaves the router folder.
    """
    validate_locator(locator)
    root = os.path.realpath(router_dir)
    path = os.path.realpath(os.path.join(root, locator))
    if path == root or os.path.commonpath([root, path]) != root:
        raise InvalidStorageRefError(
            "Storage locator resolves outside the router folder",
            details={"reason": "path_escape"},
        )
    return path


def _freeze(value: Any) -> Any:
    """Deep read-only copy: mappings -> MappingProxyType, lists -> tuples."""
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, set):
        return frozenset(value)
    return value


def _thaw(value: Any) -> Any:
    """Plain JSON-safe copy of a frozen structure (dicts and lists)."""
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw(v) for v in value]
    return value


def _set(obj: object, name: str, value: Any) -> None:
    """Set a field on a frozen dataclass during __post_init__."""
    object.__setattr__(obj, name, value)


def _coerce(obj: object, name: str, enum_cls: type[Enum], *, optional: bool = False):
    """Coerce ``obj.name`` to ``enum_cls``; ValueError for an invalid value."""
    value = getattr(obj, name)
    if value is None and optional:
        return
    _set(obj, name, enum_cls(value))


def _iso(value: datetime | None) -> str | None:
    """ISO 8601 string of an aware datetime, or None."""
    return None if value is None else value.isoformat()


def _require_aware(value: datetime | None, name: str) -> None:
    """Raise unless ``value`` is None or an aware datetime."""
    if value is None:
        return
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None:
        raise ValueError(f"{name} must be an aware datetime")


def _parse_dt(value: Any, name: str) -> datetime | None:
    """Parse an aware ISO 8601 string; naive values and other types fail."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{name} is not an ISO 8601 string")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"{name} has no time zone")
    return parsed


def _opt_str(data: Mapping[str, Any], key: str) -> str | None:
    """``data[key]`` if it is a string or absent/None; TypeError otherwise."""
    value = data.get(key)
    if value is not None and not isinstance(value, str):
        raise TypeError(f"{key} must be a string")
    return value


def _opt_bool(data: Mapping[str, Any], key: str, default: bool) -> bool:
    """``data[key]`` if it is a bool, ``default`` if absent; TypeError otherwise."""
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise TypeError(f"{key} must be a bool")
    return value


def _list_of_str(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    """``data[key]`` as a tuple of strings; empty if absent."""
    value = data.get(key) or []
    if not isinstance(value, list | tuple) or not all(
        isinstance(v, str) for v in value
    ):
        raise TypeError(f"{key} must be a list of strings")
    return tuple(value)


def _opt_hash(data: Mapping[str, Any], key: str) -> str | None:
    """``data[key]`` if it is a sha256 hex string; None if absent."""
    value = data.get(key)
    if value is None:
        return None
    if not is_sha256(value):
        raise ValueError(f"{key} must be 64 lower-case hex characters")
    return value


def _check_note(note: str | None) -> None:
    """Raise for a non-string or too long note."""
    if note is None:
        return
    if not isinstance(note, str):
        raise TypeError("note must be a string")
    if len(note) > NOTE_MAX_LENGTH:
        raise ValueError(f"note must be at most {NOTE_MAX_LENGTH} characters")


def _check_stored_error_class(error_class: ErrorClass | None) -> None:
    """Raise for a call-time error class (``NON_PERSISTED_ERROR_CLASSES``).

    Such a class describes a refused call, not a stored version; keeping it
    out of every record means an older core never reads an unknown value.
    """
    if error_class in NON_PERSISTED_ERROR_CLASSES:
        raise ValueError(
            f"error_class {error_class.value!r} is call-time only and never stored"
        )


# Provider-supplied metadata text (versions, board names, fetch methods).
META_TEXT_MAX_LENGTH: Final = 128
# Provider-supplied ids (drift_id, plan_id) and config names in reports.
TOKEN_MAX_LENGTH: Final = 128
TOKEN_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]*")


def _check_meta_text(name: str, value: object) -> None:
    """Untrusted metadata text: str, bounded, no control characters."""
    if value is None:
        return
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if len(value) > META_TEXT_MAX_LENGTH:
        raise ValueError(f"{name} must be at most {META_TEXT_MAX_LENGTH} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{name} must not contain control characters")


_KEY_ID_RE: Final = re.compile(rf"[0-9a-f]{{{INSTALLATION_KEY_ID_LENGTH}}}")


def check_key_id(value: object) -> None:
    """``installation_key_id``: None or exactly 16 lower-case hex characters."""
    if value is None:
        return
    if not isinstance(value, str) or _KEY_ID_RE.fullmatch(value) is None:
        raise ValueError(
            f"installation_key_id must be {INSTALLATION_KEY_ID_LENGTH} "
            "lower-case hex characters"
        )


def check_token(name: str, value: object, *, optional: bool = False) -> None:
    """Untrusted id: bounded, no path separators, no ``..``, no NUL."""
    if value is None and optional:
        return
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if (
        not value
        or len(value) > TOKEN_MAX_LENGTH
        or ".." in value
        or TOKEN_PATTERN.fullmatch(value) is None
    ):
        raise ValueError(
            f"{name} must be 1-{TOKEN_MAX_LENGTH} characters of [A-Za-z0-9._:@-], "
            "without '..' or path separators"
        )


def _check_warnings(warnings: Iterable[str]) -> tuple[str, ...]:
    """Validated tuple of warning codes (WARNING_CODE_PATTERN, MAX_WARNINGS)."""
    if isinstance(warnings, str):
        raise TypeError("warnings must be a sequence of codes, not a string")
    codes = tuple(warnings)
    if len(codes) > MAX_WARNINGS:
        raise ValueError(f"at most {MAX_WARNINGS} warnings")
    for code in codes:
        if not isinstance(code, str) or WARNING_CODE_PATTERN.fullmatch(code) is None:
            raise ValueError("warnings must be machine codes like 'uci_missing:sqm'")
    return codes


def installation_key_id(key: bytes) -> str:
    """Public, non-secret id of an installation key (16 hex).

    Stamped on versions so the core can tell digests made with an older key
    (after an ``installation_key_reset``) from comparable ones.
    """
    if not isinstance(key, bytes) or len(key) < 16:
        raise ValueError("installation key must be at least 16 bytes")
    digest = hmac.new(key, b"openwrt_router.installation_key_id", hashlib.sha256)
    return digest.hexdigest()[:INSTALLATION_KEY_ID_LENGTH]


# Module keys (§11.5): HKDF-SHA256 over the installation key. The salt and
# the info prefix are fixed and versioned; a new derivation gets ``/v2``.
MODULE_KEY_BYTES: Final = 32
MODULE_KEY_SALT: Final = b"openwrt_router/hkdf-salt/v1"
MODULE_KEY_INFO_PREFIX: Final = b"openwrt_router/module-key/v1"
MODULE_NAME_PATTERN: Final = re.compile(r"[a-z][a-z0-9_]{0,63}")
MODULE_KEY_PURPOSE_PATTERN: Final = re.compile(r"[a-z0-9_.:-]{0,64}")
# Name of the core's own derivations (bus pseudonym); never a module name.
CORE_KEY_OWNER: Final = "core"


def hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869): extract, then expand to ``length`` bytes."""
    if not isinstance(ikm, bytes) or not ikm:
        raise ValueError("input key material must be non-empty bytes")
    if not 0 < length <= 255 * hashlib.sha256().digest_size:
        raise ValueError("HKDF length out of range")
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def check_module_name(module: object) -> str:
    """A plain module name (``[a-z][a-z0-9_]*``, at most 64); ValueError else."""
    if not isinstance(module, str) or MODULE_NAME_PATTERN.fullmatch(module) is None:
        raise ValueError("module must be a plain lower-case name")
    return module


def derive_module_key(installation_key: bytes, module: str, purpose: str = "") -> bytes:
    """32-byte key of ``module`` for ``purpose`` (pure; the key stays secret).

    ``info`` = MODULE_KEY_INFO_PREFIX, NUL, module, NUL, purpose: neither part
    may contain NUL, so two (module, purpose) pairs never share an info
    string. ``core`` is refused (the core derives its own keys internally).
    """
    check_module_name(module)
    if module == CORE_KEY_OWNER:
        raise ValueError("core is not a module name")
    return _derive(installation_key, module, purpose)


def _derive(installation_key: bytes, owner: str, purpose: str) -> bytes:
    if (
        not isinstance(purpose, str)
        or MODULE_KEY_PURPOSE_PATTERN.fullmatch(purpose) is None
        or ".." in purpose
    ):
        raise ValueError("purpose must be up to 64 characters of [a-z0-9_.:-]")
    if not isinstance(installation_key, bytes) or len(installation_key) < 16:
        raise ValueError("installation key must be at least 16 bytes")
    info = b"\x00".join(
        (MODULE_KEY_INFO_PREFIX, owner.encode("ascii"), purpose.encode("ascii"))
    )
    return hkdf_sha256(
        installation_key, salt=MODULE_KEY_SALT, info=info, length=MODULE_KEY_BYTES
    )


def derive_core_key(installation_key: bytes, purpose: str) -> bytes:
    """The core's own derived key (e.g. ``bus_pseudonym``); core-internal."""
    return _derive(installation_key, CORE_KEY_OWNER, purpose)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class RouterRole(StrEnum):
    """Role of a router in the fleet."""

    GATEWAY = "gateway"
    ACCESS_POINT = "access_point"
    UNKNOWN = "unknown"


class IdentityFlag(StrEnum):
    """Doubts about a router record; several can be set at once."""

    UNVERIFIED = "unverified"  # no data seen yet (e.g. entry in setup_retry)
    CHANGED = "changed"  # board/model changed or no MAC overlap: swap suspected
    DUPLICATE_SUSPECTED = "duplicate_suspected"  # another entry shares MACs


class IdentityStatus(StrEnum):
    """Primary identity status, derived from the flags (see primary_status)."""

    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    CHANGED = "changed"
    DUPLICATE_SUSPECTED = "duplicate_suspected"


def primary_identity_status(flags: Iterable[IdentityFlag]) -> IdentityStatus:
    """CHANGED outranks DUPLICATE_SUSPECTED outranks UNVERIFIED; none = CONFIRMED."""
    present = set(flags)
    for flag in (
        IdentityFlag.CHANGED,
        IdentityFlag.DUPLICATE_SUSPECTED,
        IdentityFlag.UNVERIFIED,
    ):
        if flag in present:
            return IdentityStatus(flag.value)
    return IdentityStatus.CONFIRMED


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
    # Rights in the DEPLOYED rpcd ACL file of the integration (1.44.0): read
    # once per entry setup by ensure_acl, never in the poll. Core-owned
    # names inside the reserved rf. namespace (see RESERVED_NAMESPACES).
    RF_TXPOWERLIST = "rf.txpowerlist"
    RF_SURVEY = "rf.survey"
    RF_SCAN = "rf.scan"


# Capabilities the configuration provider decides (no provider: unavailable).
CONFIG_CAPABILITIES: Final = frozenset(
    c for c in Capability if c.value.startswith("config.")
)
# Decided from the deployed ACL the core observed at entry setup.
ACL_CAPABILITIES: Final = frozenset(
    {Capability.RF_TXPOWERLIST, Capability.RF_SURVEY, Capability.RF_SCAN}
)
# Core-owned names inside a module namespace; a module detector may never
# report them (refused and counted).
CORE_OWNED_MODULE_CAPABILITIES: Final = ACL_CAPABILITIES
# These follow their source exactly: "unknown" replaces a known state (the
# source is a setting or a one-off observation, not a flaky poll value).
STRICT_CAPABILITIES: Final = CONFIG_CAPABILITIES | ACL_CAPABILITIES
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
    # config.*: a probe cannot tell without doing real work on the router
    # (state unknown); callers may try, the first real use settles it.
    DETERMINED_ON_FIRST_USE = "determined_on_first_use"


@dataclass(frozen=True, kw_only=True, slots=True)
class DeployedAclObservation:
    """What the core knows about the integration's rpcd ACL file on a router.

    Made from the ONE ``file/read`` ensure_acl does at entry setup (or from
    what it wrote / what an approved offer deploy wrote); never a router
    call of its own. ``known`` False means the file could not be read or a
    deploy failed: the rf.* capabilities are then ``unknown`` with
    ``reason_text`` saying why. Only this file is considered; other files in
    rpcd's acl.d may grant more (a known blind spot, documented).

    ``granted``/``missing``: sorted ``(capability, ...)`` pairs (hashable,
    part of the capability signature).
    """

    known: bool
    reason: str  # current | tiered | written | deploy_failed | unreadable | ...
    kind: str | None = None  # acl_provisioning.DeployedAclKind value
    tiers: tuple[str, ...] = ()
    acl_checksum: str | None = None
    granted: tuple[tuple[str, bool], ...] = ()
    missing: tuple[tuple[str, tuple[str, ...]], ...] = ()
    observed_at: datetime | None = None

    def is_granted(self, capability: str) -> bool | None:
        """True/False if known, None if this observation cannot tell."""
        if not self.known:
            return None
        return dict(self.granted).get(str(capability))

    def missing_for(self, capability: str) -> tuple[str, ...]:
        """Permission strings the deployed ACL lacks for ``capability``."""
        return dict(self.missing).get(str(capability), ())

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (diagnostics; no ACL content)."""
        return {
            "known": self.known,
            "reason": self.reason,
            "kind": self.kind,
            "tiers": list(self.tiers),
            "acl_checksum": self.acl_checksum,
            "granted": dict(self.granted),
            "missing": {k: list(v) for k, v in self.missing},
            "observed_at": None
            if self.observed_at is None
            else self.observed_at.isoformat(),
        }


class ActorKind(StrEnum):
    """Who triggered an operation."""

    USER = "user"
    AUTOMATION = "automation"
    SYSTEM = "system"
    MODULE = "module"


class ActionClass(StrEnum):
    """Guard class of an action.

    CRITICAL means "needs request + admin approval", not "writes": export
    only reads but is critical because it discloses secrets. ACTIVE (B5)
    means "acts on the router or the network without changing its
    configuration" (scan, ping, survey): like MUTATING for the policy, no
    approval, audited on the general ring, optionally rate limited.
    Not persisted (additive member).
    """

    READ = "read"
    MUTATING = "mutating"
    CRITICAL = "critical"
    ACTIVE = "active"


# Bounds of a RateLimit (register_action(..., rate_limit=...)).
RATE_LIMIT_MAX_CALLS: Final = 100_000
RATE_LIMIT_MAX_PERIOD: Final = timedelta(days=1)


@dataclass(frozen=True, kw_only=True, slots=True)
class RateLimit:
    """At most ``max_calls`` grants of one active action per router and
    sliding window ``per`` (B5). Only grants count; a denial never does."""

    max_calls: int
    per: timedelta

    def __post_init__(self) -> None:
        """Validate the bounds."""
        if isinstance(self.max_calls, bool) or not isinstance(self.max_calls, int):
            raise TypeError("max_calls must be an int")
        if not 1 <= self.max_calls <= RATE_LIMIT_MAX_CALLS:
            raise ValueError(f"max_calls must be 1..{RATE_LIMIT_MAX_CALLS}")
        if not isinstance(self.per, timedelta):
            raise TypeError("per must be a timedelta")
        if not timedelta(0) < self.per <= RATE_LIMIT_MAX_PERIOD:
            raise ValueError("per must be > 0 and at most one day")

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (seconds)."""
        return {"max_calls": self.max_calls, "per": self.per.total_seconds()}


class GuardedAction(StrEnum):
    """Actions known to the guard in v1.

    Later modules register further actions as ``<module>.<action>`` (e.g.
    ``router_settings.change``) with ``ActionGuardProtocol.register_action``;
    APIs take actions as ``str``.
    """

    BACKUP = "backup"
    PROTECT = "protect"
    DRIFT_ACK = "drift_ack"
    EXPORT = "export"
    DELETE = "delete"
    PRUNE = "prune"  # only the core's own retention run (system actor)
    RESTORE = "restore"
    ADOPT = "adopt"
    ACL_DEPLOY = "acl_deploy"
    INSTALLATION_KEY_RESET = "installation_key_reset"
    # Host-key pins of the pinned SSH path (1.44.0): confirm a pending
    # first-use fingerprint / drop a router's pin (both bound to router_id
    # + fingerprint).
    SSH_PIN_CONFIRM = "ssh_pin_confirm"
    SSH_PIN_RESET = "ssh_pin_reset"


ACTION_CLASSES: Final[Mapping[str, ActionClass]] = MappingProxyType(
    {
        GuardedAction.INSTALLATION_KEY_RESET: ActionClass.CRITICAL,
        GuardedAction.BACKUP: ActionClass.MUTATING,
        GuardedAction.PROTECT: ActionClass.MUTATING,
        GuardedAction.DRIFT_ACK: ActionClass.MUTATING,
        GuardedAction.EXPORT: ActionClass.CRITICAL,
        GuardedAction.DELETE: ActionClass.CRITICAL,
        GuardedAction.PRUNE: ActionClass.MUTATING,
        GuardedAction.RESTORE: ActionClass.CRITICAL,
        GuardedAction.ADOPT: ActionClass.MUTATING,
        GuardedAction.ACL_DEPLOY: ActionClass.CRITICAL,
        GuardedAction.SSH_PIN_CONFIRM: ActionClass.CRITICAL,
        GuardedAction.SSH_PIN_RESET: ActionClass.CRITICAL,
    }
)
# Only a verified admin USER may perform these.
ADMIN_USER_ONLY_ACTIONS: Final = frozenset(
    {
        GuardedAction.PROTECT,
        GuardedAction.DRIFT_ACK,
        GuardedAction.EXPORT,
        GuardedAction.ADOPT,
        GuardedAction.ACL_DEPLOY,
        GuardedAction.INSTALLATION_KEY_RESET,
        GuardedAction.SSH_PIN_CONFIRM,
        GuardedAction.SSH_PIN_RESET,
    }
)
# Only the core itself (ActorKind.SYSTEM) may perform these.
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
    """Kind of backup artifact set (persisted)."""

    FULL_ARCHIVE = "full_archive"  # sysupgrade -b style archive (+ uci, inventory)
    UCI_SNAPSHOT = "uci_snapshot"
    PARTIAL = "partial"


class BackupReason(StrEnum):
    """Why a version was taken (persisted; config-manager calls it ``kind``)."""

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


# Only these reasons may end in a dedup hit; all others always create.
DEDUP_REASONS: Final = frozenset({BackupReason.SCHEDULED, BackupReason.DRIFT})


class VersionStatus(StrEnum):
    """Collection result of a version (persisted)."""

    OK = "ok"
    PARTIAL = "partial"  # some artifacts missing (error_class says why)
    FAILED = "failed"  # nothing usable; kept for history


class ArtifactKind(StrEnum):
    """Artifacts of a version (persisted as artifact map keys)."""

    ARCHIVE = "archive"
    UCI = "uci"
    INVENTORY = "inventory"


class ValidationStatus(StrEnum):
    """Integrity state of a stored version (persisted)."""

    UNVERIFIED = "unverified"
    VALID = "valid"
    INVALID = "invalid"  # readable but not a usable backup
    CORRUPT = "corrupt"  # checksum or size mismatch
    MISSING = "missing"  # file gone (sweep marks index entries without file)


USABLE_VALIDATION: Final = frozenset(
    {ValidationStatus.UNVERIFIED, ValidationStatus.VALID}
)


class DriftAckState(StrEnum):
    """User decision about one drift (persisted)."""

    ACKNOWLEDGED = "acknowledged"  # seen, baseline stays
    KNOWN = "known"  # this drift_id is the new baseline


class ConfigRefKind(StrEnum):
    """What a ConfigRef points at."""

    BACKUP = "backup"
    LIVE = "live"


class DriftComparison(StrEnum):
    """How much of the configuration a drift check could compare."""

    COMPLETE = "complete"
    PARTIAL = "partial"  # some configs could not be read/compared (listed)
    UNKNOWN = "unknown"  # the comparison as a whole is not trustworthy


class ChangeKind(StrEnum):
    """Kind of one configuration change in a diff."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"  # config-manager: "changed"
    REORDERED = "reordered"
    # Secret digests made with different installation keys: not a drift.
    NOT_COMPARABLE = "not_comparable"


class BaselineRule(StrEnum):
    """Which rule picked a drift baseline (highest priority first)."""

    EXPLICIT = "explicit"  # caller named baseline_backup_id
    KNOWN_ACK = "known_ack"  # newest DriftAck with state KNOWN
    NEWEST_VALID = "newest_valid"  # newest usable version


class InstallationKeyState(StrEnum):
    """State of the installation key (never regenerated silently)."""

    OK = "ok"
    LOST = "lost"  # key store missing/unreadable while versions or acks exist
    UNINITIALISED = "uninitialised"  # first start: nothing exists yet


def installation_key_state(
    *, key_readable: bool, has_versions: bool, has_acks: bool
) -> InstallationKeyState:
    """Decide the key state; only UNINITIALISED may create a new key.

    A missing or unreadable key store with existing versions or acks is
    LOST: the core raises InstallationKeyLostError, emits
    ``core.installation_key_lost`` once and opens a repair issue; a new key
    then only comes from the critical action ``installation_key_reset``.
    """
    if key_readable:
        return InstallationKeyState.OK
    if has_versions or has_acks:
        return InstallationKeyState.LOST
    return InstallationKeyState.UNINITIALISED


class RestoreStatus(StrEnum):
    """Outcome of a restore execution."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class KeepReason(StrEnum):
    """Why retention kept a version (not persisted; order = priority)."""

    PROTECTED = "protected"
    NEWEST_VALID = "newest_valid"
    DAILY = "daily"  # newest usable version of one of the last N days
    WEEKLY = "weekly"  # ... of one of the last N ISO weeks
    MONTHLY = "monthly"  # ... of one of the last N calendar months
    WITHIN_POLICY = "within_policy"  # max_versions / max_age rule
    # Not usable (failed, partial, invalid): kept for diagnosis only while
    # recent; never represents a period, never pushes a usable one out.
    RECENT_FAILED = "recent_failed"
    # GFS never thins a manual or pre_* version (1.44.0); only the size
    # limit can remove one, and RetentionResult.limit_deleted_manual names it.
    MANUAL = "manual"


class EventResult(StrEnum):
    """Result field of a CoreEvent."""

    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    PENDING = "pending"
    INFO = "info"


class AuditRing(StrEnum):
    """Which audit ring an event is kept in."""

    GENERAL = "general"  # AUDIT_MAX_EVENTS
    SECURITY = "security"  # SECURITY_AUDIT_MAX_EVENTS


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
    # Review PR #55 (additive): an orphaned record was dropped from the
    # registry (aged out or over the cap); security ring, audit-mandatory.
    ROUTER_FORGOTTEN = "router.forgotten"
    BACKUP_CREATED = "configuration.backup_created"
    BACKUP_FAILED = "configuration.backup_failed"
    BACKUP_RECOVERED = "configuration.backup_recovered"
    BACKUP_VALIDATED = "configuration.backup_validated"
    BACKUP_PROTECTION_CHANGED = "configuration.backup_protection_changed"
    BACKUP_EXPORTED = "configuration.backup_exported"
    BACKUP_DELETED = "configuration.backup_deleted"
    RETENTION_APPLIED = "configuration.retention_applied"
    DRIFT_DETECTED = "configuration.drift_detected"
    DRIFT_ACKNOWLEDGED = "configuration.drift_acknowledged"
    CHANGE_CRITICAL = "configuration.change_critical"
    CHANGE_UNKNOWN = "configuration.change_unknown"
    # A drift check could not compare everything (comparison partial or
    # unknown): never an all-clear (additive, part 2).
    DRIFT_INCOMPLETE = "configuration.drift_incomplete"
    INTEGRITY_FAILED = "configuration.integrity_failed"
    RESTORE_CHECKED = "configuration.restore_checked"  # dry run / compatibility
    RESTORE_REQUESTED = "configuration.restore_requested"
    RESTORE_APPROVED = "configuration.restore_approved"
    RESTORE_REJECTED = "configuration.restore_rejected"
    RESTORE_COMPLETED = "configuration.restore_completed"
    RESTORE_FAILED = "configuration.restore_failed"
    STORAGE_SWEPT = "configuration.storage_swept"
    # Retention ran and the router (or the store) is still above its size
    # limit; the next put raises StorageFullError (additive, part 2).
    STORAGE_LIMIT_EXCEEDED = "configuration.storage_limit_exceeded"
    AUTHORIZATION_DENIED = "security.authorization_denied"
    AUTHORIZATION_CONSUMED = "security.authorization_consumed"
    # A mutating action was authorized (additive, part 2: "authorize always
    # writes one audit entry" needed a type for the approved case).
    AUTHORIZATION_GRANTED = "security.authorization_granted"
    APPROVAL_REQUESTED = "security.approval_requested"
    APPROVAL_APPROVED = "security.approval_approved"
    APPROVAL_REJECTED = "security.approval_rejected"
    APPROVAL_EXPIRED = "security.approval_expired"
    INSTALLATION_KEY_LOST = "core.installation_key_lost"
    INSTALLATION_KEY_RESET = "core.installation_key_reset"
    # Security review (1.44.0, additive): a new key was created although a
    # key file existed (unreadable / unusable); security ring, repair issue.
    INSTALLATION_KEY_REPLACED = "core.installation_key_replaced"
    # A core store was unreadable, copied to .bak and rebuilt (additive, part 1:
    # router ids are deterministic; adoption links are what can be lost).
    STORE_RECOVERED = "core.store_recovered"
    # 1.44.0 (additive): approved tiered-ACL deploy and its failure (data
    # carries command and rollback_command) ...
    ACL_DEPLOYED = "security.acl_deployed"
    ACL_DEPLOY_FAILED = "security.acl_deploy_failed"
    # ... host-key pins of the pinned SSH path ...
    SSH_PIN_PENDING = "security.ssh_pin_pending"
    SSH_PIN_CONFIRMED = "security.ssh_pin_confirmed"
    SSH_PIN_MISMATCH = "security.ssh_pin_mismatch"
    SSH_PIN_RESET = "security.ssh_pin_reset"
    # ... and the version folder of a removed entry moved to removed/<id>/.
    ROUTER_ARCHIVED = "configuration.router_archived"
    # Security review (1.44.0, additive): the options-flow switch
    # config_backup_enabled changed (actor, old and new value).
    CONFIG_OPTION_CHANGED = "security.config_option_changed"
    # Follow-up B5 (additive): an ACTIVE action was authorized (general
    # ring, audit-mandatory) / refused by its rate limit (general ring, one
    # entry per router, action and window; repeats are counted).
    ACTIVE_ACTION_GRANTED = "core.active_action_granted"
    ACTION_RATE_LIMITED = "core.action_rate_limited"


# Namespaces of core event types. Only the core emits these (also the ones
# derived from provider results); modules emit below a registered prefix.
CORE_EVENT_NAMESPACES: Final = ("router.", "configuration.", "security.", "core.")


def is_core_event_type(event_type: str) -> bool:
    """True for a type in a core namespace (not emittable by modules)."""
    return str(event_type).startswith(CORE_EVENT_NAMESPACES)


# Kept in the security ring (besides every "security.*" type).
SECURITY_EVENT_TYPES: Final = frozenset(
    {
        CoreEventType.INSTALLATION_KEY_LOST,
        CoreEventType.INSTALLATION_KEY_RESET,
        CoreEventType.INSTALLATION_KEY_REPLACED,
        CoreEventType.ROUTER_ARCHIVED,
        CoreEventType.BACKUP_EXPORTED,
        CoreEventType.BACKUP_DELETED,
        CoreEventType.ROUTER_ADOPTED,
        CoreEventType.ROUTER_FORGOTTEN,
        CoreEventType.RESTORE_REQUESTED,
        CoreEventType.RESTORE_APPROVED,
        CoreEventType.RESTORE_REJECTED,
        CoreEventType.RESTORE_COMPLETED,
        CoreEventType.RESTORE_FAILED,
    }
)
# Always written as a new audit entry; their dedup_key is ignored.
AUDIT_MANDATORY_EVENT_TYPES: Final = frozenset(
    {
        CoreEventType.BACKUP_PROTECTION_CHANGED,
        CoreEventType.BACKUP_EXPORTED,
        CoreEventType.BACKUP_DELETED,
        CoreEventType.RETENTION_APPLIED,
        CoreEventType.DRIFT_ACKNOWLEDGED,
        CoreEventType.RESTORE_CHECKED,
        CoreEventType.RESTORE_REQUESTED,
        CoreEventType.RESTORE_APPROVED,
        CoreEventType.RESTORE_REJECTED,
        CoreEventType.RESTORE_COMPLETED,
        CoreEventType.RESTORE_FAILED,
        CoreEventType.ROUTER_ADOPTED,
        CoreEventType.ROUTER_FORGOTTEN,
        CoreEventType.AUTHORIZATION_DENIED,
        CoreEventType.AUTHORIZATION_CONSUMED,
        CoreEventType.AUTHORIZATION_GRANTED,
        CoreEventType.ACTIVE_ACTION_GRANTED,
        CoreEventType.APPROVAL_REQUESTED,
        CoreEventType.APPROVAL_APPROVED,
        CoreEventType.APPROVAL_REJECTED,
        CoreEventType.APPROVAL_EXPIRED,
        CoreEventType.INSTALLATION_KEY_LOST,
        CoreEventType.INSTALLATION_KEY_RESET,
        CoreEventType.INSTALLATION_KEY_REPLACED,
        CoreEventType.STORE_RECOVERED,
        CoreEventType.ACL_DEPLOYED,
        CoreEventType.ACL_DEPLOY_FAILED,
        CoreEventType.SSH_PIN_CONFIRMED,
        CoreEventType.SSH_PIN_MISMATCH,
        CoreEventType.SSH_PIN_RESET,
        CoreEventType.ROUTER_ARCHIVED,
        CoreEventType.CONFIG_OPTION_CHANGED,
    }
)


def audit_ring_for(event_type: str) -> AuditRing:
    """SECURITY for critical actions, denials, approvals, exports, adoption."""
    if str(event_type).startswith("security.") or event_type in SECURITY_EVENT_TYPES:
        return AuditRing.SECURITY
    return AuditRing.GENERAL


# ---------------------------------------------------------------------------
# Actor and verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class Actor:
    """Who performs an operation (a record, not a credential).

    ``is_admin`` is what the core found when it verified the actor; a value a
    caller passes in is never trusted. The guard only accepts a
    :class:`VerifiedActor`, built by :func:`async_verify_actor`.
    """

    kind: ActorKind
    user_id: str | None = None
    context_id: str | None = None
    parent_context_id: str | None = None
    module: str | None = None
    is_admin: bool = False

    def __post_init__(self) -> None:
        """Coerce the kind and drop admin rights of non-user actors."""
        _coerce(self, "kind", ActorKind)
        if self.kind is not ActorKind.USER and self.is_admin:
            _set(self, "is_admin", False)

    @classmethod
    def system(cls, module: str | None = None) -> Actor:
        """The core itself (startup, retention, migrations)."""
        return cls(kind=ActorKind.SYSTEM, module=module)

    @classmethod
    def for_module(cls, module: str, *, context_id: str | None = None) -> Actor:
        """Another enterprise module acting on its own."""
        return cls(kind=ActorKind.MODULE, module=module, context_id=context_id)

    def same_principal(self, other: Actor) -> bool:
        """Same user (by user_id), same module, or both system."""
        if self.kind is not other.kind:
            return False
        if self.kind is ActorKind.USER:
            return self.user_id is not None and self.user_id == other.user_id
        if self.kind is ActorKind.MODULE:
            return self.module is not None and self.module == other.module
        return self.kind is ActorKind.SYSTEM

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
        if not isinstance(data, Mapping):
            raise TypeError("actor must be a mapping")
        return cls(
            kind=ActorKind(data["kind"]),
            user_id=_opt_str(data, "user_id"),
            context_id=_opt_str(data, "context_id"),
            parent_context_id=_opt_str(data, "parent_context_id"),
            module=_opt_str(data, "module"),
            is_admin=_opt_bool(data, "is_admin", False),
        )


def _user_is_admin(user: Any) -> bool:
    """Exists, active, admin and not system-generated."""
    return bool(
        user is not None
        and getattr(user, "is_active", False) is True
        and getattr(user, "is_admin", False) is True
        and getattr(user, "system_generated", True) is False
    )


async def async_actor_from_context(
    hass: HomeAssistant, context: Context | None, module: str | None = None
) -> Actor:
    """Build an (unverified) Actor from an HA ``Context``.

    Order: a ``user_id`` makes a USER (``is_admin`` from hass.auth); else a
    given ``module`` makes a MODULE; else a ``parent_id`` makes an
    AUTOMATION; else SYSTEM. Use :func:`async_resolve_actor` for the guard.
    """
    context_id = context.id if context is not None else None
    parent_id = context.parent_id if context is not None else None
    if context is not None and context.user_id:
        user = await hass.auth.async_get_user(context.user_id)
        return Actor(
            kind=ActorKind.USER,
            user_id=context.user_id,
            context_id=context_id,
            parent_context_id=parent_id,
            module=module,
            is_admin=_user_is_admin(user),
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


# Module-private sentinel: only async_verify_actor builds a VerifiedActor.
_VERIFY_SENTINEL: Final = object()


class VerifiedActor:
    """An Actor the core has just re-checked against ``hass.auth``.

    For a USER, ``is_admin`` means: the user exists, is active, is admin and
    is not system-generated, at ``verified_at``. A caller-supplied
    ``Actor.is_admin`` is ignored. Accepted by the guard for
    :data:`ACTOR_VERIFICATION_TTL`. Threat model: in-process modules are
    trusted code; this defends against users, automations and module bugs,
    not against a module that deliberately imports private helpers.
    """

    __slots__ = ("_actor", "_verification_id", "_verified_at")

    def __init__(
        self, *, actor: Actor, verified_at: datetime, _sentinel: object = None
    ) -> None:
        """Refuse construction outside async_verify_actor."""
        if _sentinel is not _VERIFY_SENTINEL:
            raise TypeError("VerifiedActor can only be built by async_verify_actor")
        _require_aware(verified_at, "verified_at")
        self._actor = actor
        self._verified_at = verified_at
        self._verification_id = new_id(VERIFICATION_ID_PREFIX)

    @property
    def actor(self) -> Actor:
        """The verified actor record (``is_admin`` as found by the core)."""
        return self._actor

    @property
    def is_admin(self) -> bool:
        """True only for a verified admin user."""
        return self._actor.kind is ActorKind.USER and self._actor.is_admin

    @property
    def verified_at(self) -> datetime:
        """When hass.auth was checked."""
        return self._verified_at

    @property
    def verification_id(self) -> str:
        """``vac_<32 hex>``, for audit."""
        return self._verification_id

    def is_fresh(self, now: datetime | None = None) -> bool:
        """True within ACTOR_VERIFICATION_TTL of verification."""
        return (now or utcnow()) - self._verified_at <= ACTOR_VERIFICATION_TTL

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form for audit."""
        return {
            **self._actor.to_dict(),
            "verified_at": _iso(self._verified_at),
            "verification_id": self._verification_id,
        }

    def __repr__(self) -> str:
        """Short representation."""
        return f"VerifiedActor({self._actor.kind}, admin={self.is_admin})"


async def async_verify_actor(
    hass: HomeAssistant, actor: Actor, *, now: datetime | None = None
) -> VerifiedActor:
    """Re-check ``actor`` against hass.auth and return a VerifiedActor.

    A USER whose user does not exist or is inactive raises
    AuthorizationError (reason ``unknown_user``); ``is_admin`` is recomputed.
    Module, automation and system actors pass through without admin rights.
    """
    verified = replace(actor, is_admin=False)
    if actor.kind is ActorKind.USER:
        user = await hass.auth.async_get_user(actor.user_id) if actor.user_id else None
        if user is None or getattr(user, "is_active", False) is not True:
            raise AuthorizationError(
                "User is unknown or inactive", details={"reason": "unknown_user"}
            )
        verified = replace(actor, is_admin=_user_is_admin(user))
    return VerifiedActor(
        actor=verified, verified_at=now or utcnow(), _sentinel=_VERIFY_SENTINEL
    )


async def async_resolve_actor(
    hass: HomeAssistant, context: Context | None, module: str | None = None
) -> VerifiedActor:
    """async_actor_from_context + async_verify_actor in one step."""
    return await async_verify_actor(
        hass, await async_actor_from_context(hass, context, module)
    )


def policy_denial_reason(
    action: str,
    actor: object,
    *,
    now: datetime | None = None,
    action_classes: Mapping[str, ActionClass] = ACTION_CLASSES,
    admin_user_only: frozenset[str] = ADMIN_USER_ONLY_ACTIONS,
    system_only: frozenset[str] = SYSTEM_ONLY_ACTIONS,
    sensitive_reads: frozenset[str] = frozenset(),
) -> str | None:
    """Guard policy: None if ``actor`` may perform/request ``action``.

    Reasons: unverified_actor, actor_verification_expired, unknown_action,
    system_only, not_admin, automation_not_allowed. A user who is not a
    verified admin may not perform or request any mutating, active or
    critical action, nor a read listed in ``sensitive_reads``. Critical
    actions may be requested by verified admin users, modules and the
    system only.
    """
    if not isinstance(actor, VerifiedActor):
        return "unverified_actor"
    if not actor.is_fresh(now):
        return "actor_verification_expired"
    action_class = action_classes.get(str(action))
    if action_class is None:
        return "unknown_action"
    kind = actor.actor.kind
    if action in system_only:
        return None if kind is ActorKind.SYSTEM else "system_only"
    if action in admin_user_only and not actor.is_admin:
        return "not_admin"
    if action_class is ActionClass.READ and action not in sensitive_reads:
        return None
    if kind is ActorKind.USER and not actor.is_admin:
        return "not_admin"
    if action_class is ActionClass.CRITICAL and kind is ActorKind.AUTOMATION:
        return "automation_not_allowed"
    return None


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
    """Identity snapshot of one router. router_id never follows host/hostname.

    ``identity_flags`` holds every current doubt (a swapped device can be
    CHANGED and DUPLICATE_SUSPECTED at once); ``status`` is the primary one.
    """

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
    identity_flags: frozenset[IdentityFlag] = frozenset({IdentityFlag.UNVERIFIED})

    def __post_init__(self) -> None:
        """Validate the id, timestamps and enums."""
        if not is_valid_id(self.router_id, ROUTER_ID_PREFIX):
            raise ValueError("router_id must be rtr_<32 hex>")
        _require_aware(self.first_seen, "first_seen")
        _require_aware(self.last_seen, "last_seen")
        _coerce(self, "role", RouterRole)
        _set(
            self,
            "identity_flags",
            frozenset(IdentityFlag(f) for f in self.identity_flags),
        )

    @property
    def status(self) -> IdentityStatus:
        """Primary status: changed > duplicate_suspected > unverified > confirmed."""
        return primary_identity_status(self.identity_flags)

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
            "identity_flags": sorted(f.value for f in self.identity_flags),
            "status": self.status.value,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class RouterReachability:
    """Reachability derived from the entry's coordinator."""

    state: ReachabilityState = ReachabilityState.UNKNOWN
    last_success: datetime | None = None
    last_attempt: datetime | None = None

    def __post_init__(self) -> None:
        """Coerce and validate."""
        _coerce(self, "state", ReachabilityState)
        _require_aware(self.last_success, "last_success")
        _require_aware(self.last_attempt, "last_attempt")

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

    def __post_init__(self) -> None:
        """Coerce."""
        _coerce(self, "transport", Transport)

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
    detail: str | None = None  # free text: never configuration values
    updated_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "name": self.name,
            "available": self.available,
            "detail": scrub_text(self.detail),
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
    ``config.uci_read`` (stored read-only).
    """

    capability: str
    state: CapabilityState
    reason: str
    source: str
    detected_at: datetime
    reason_text: str | None = None  # free text: never configuration values
    required_permissions: tuple[str, ...] = ()
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Coerce, validate and freeze."""
        _coerce(self, "state", CapabilityState)
        _require_aware(self.detected_at, "detected_at")
        _set(self, "required_permissions", tuple(self.required_permissions))
        _set(self, "detail", _freeze(self.detail))

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
            "reason_text": scrub_text(self.reason_text),
            "source": self.source,
            "required_permissions": list(self.required_permissions),
            "detected_at": _iso(self.detected_at),
            "detail": mask_secrets(_thaw(self.detail)),
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class RouterRecord:
    """Registry entry of one router (active or orphaned).

    The registry hands out these immutable records; ``capabilities`` is a
    read-only mapping, so callers cannot change the registry's state.
    """

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

    def __post_init__(self) -> None:
        """Coerce and freeze."""
        _coerce(self, "state", RecordState)
        _set(
            self,
            "capabilities",
            MappingProxyType({str(k): v for k, v in self.capabilities.items()}),
        )
        _set(self, "previous_entry_ids", tuple(self.previous_entry_ids))

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
                cap: status.to_dict()
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

    def __post_init__(self) -> None:
        """Coerce."""
        _coerce(self, "transport", Transport)


# ---------------------------------------------------------------------------
# Version store: storage references and artifacts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class StorageRef:
    """Where the core keeps one artifact. Core-internal: modules never read
    files through it (they get a scoped ArtifactReader).

    ``locator`` is one plain file name inside the router's folder
    (``STORAGE_LOCATOR_PATTERN``, no ``..``); anything else raises
    InvalidStorageRefError. ``storage_format`` names the encoding (phase 1:
    ``plain-v1``); reading an unknown format raises
    UnsupportedStorageFormatError.
    """

    locator: str
    kind: str = "file"
    storage_format: str = STORAGE_FORMAT_PLAIN_V1
    encrypted: bool = False

    def __post_init__(self) -> None:
        """Validate the locator and field types."""
        validate_locator(self.locator)
        for name in ("kind", "storage_format"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.encrypted, bool):
            raise TypeError("encrypted must be a bool")

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
        """Inverse of :meth:`to_dict` (missing storage_format = plain-v1)."""
        if not isinstance(data, Mapping):
            raise TypeError("storage must be a mapping")
        return cls(
            locator=data["locator"],
            kind=data.get("kind", "file"),
            storage_format=data.get("storage_format", STORAGE_FORMAT_PLAIN_V1),
            encrypted=_opt_bool(data, "encrypted", False),
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
        if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool):
            raise TypeError("artifact size_bytes must be an int")
        if self.size_bytes < 0:
            raise ValueError("artifact size_bytes must not be negative")

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
        if not isinstance(data, Mapping):
            raise TypeError("artifact must be a mapping")
        return cls(
            storage=StorageRef.from_dict(data["storage"]),
            sha256=data["sha256"],
            size_bytes=data["size_bytes"],
            content_type=_opt_str(data, "content_type") or "application/octet-stream",
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class ArtifactPayload:
    """Bytes of one artifact handed to the put path.

    The store recomputes sha256 and refuses a mismatch (checksum_mismatch).
    """

    data: bytes = field(repr=False)
    sha256: str
    content_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        """Validate."""
        if not isinstance(self.data, bytes):
            raise TypeError("data must be bytes")
        if not is_sha256(self.sha256):
            raise ValueError("sha256 must be 64 lower-case hex characters")

    @property
    def size_bytes(self) -> int:
        """Length of ``data``."""
        return len(self.data)


def _freeze_artifacts(artifacts: Mapping[Any, Any]) -> MappingProxyType[str, Any]:
    """Read-only artifact map with ArtifactKind keys as plain strings."""
    if not isinstance(artifacts, Mapping):
        raise TypeError("artifacts must be a mapping")
    return MappingProxyType({ArtifactKind(k).value: v for k, v in artifacts.items()})


# ---------------------------------------------------------------------------
# Version metadata (index and bytes owned by the core)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True, slots=True)
class ValidationInfo:
    """Result of the last integrity check of a version."""

    status: ValidationStatus = ValidationStatus.UNVERIFIED
    checked_at: datetime | None = None
    details: str | None = None  # free text: never configuration values

    def __post_init__(self) -> None:
        """Coerce and validate."""
        _coerce(self, "status", ValidationStatus)
        _require_aware(self.checked_at, "checked_at")

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (details scrubbed)."""
        return {
            "status": self.status.value,
            "checked_at": _iso(self.checked_at),
            "details": scrub_text(self.details),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ValidationInfo:
        """Inverse of :meth:`to_dict`."""
        if not isinstance(data, Mapping):
            raise TypeError("validation must be a mapping")
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
        if not isinstance(data, Mapping):
            raise TypeError("compatibility must be a mapping")
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
        if not isinstance(data, Mapping):
            raise TypeError("links must be a mapping")
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


@dataclass(frozen=True, kw_only=True, slots=True)
class BackupRecord:
    """Index entry of one version (metadata format BACKUP_METADATA_VERSION).

    ``sha256`` is the archive's sha256 and ``size_bytes`` the sum over all
    artifacts (both derived). A FAILED version may have no artifacts.
    ``created_by`` is set by the store from the authorization's actor.
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
    note: str | None = None  # user text, shown back to admins only
    warnings: tuple[str, ...] = ()  # machine codes from VersionMeta.warnings
    installation_key_id: str | None = None  # key the secret digests used
    metadata_version: int = BACKUP_METADATA_VERSION

    def __post_init__(self) -> None:
        """Validate ids, hashes, enums, flags, note and timestamps."""
        _set(self, "warnings", _check_warnings(self.warnings))
        check_key_id(self.installation_key_id)
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
        for name in ("contains_secrets", "protected"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be a bool")
        if not isinstance(self.created_by, Actor):
            raise TypeError("created_by must be an Actor")
        _check_note(self.note)
        _coerce(self, "backup_type", BackupType)
        _coerce(self, "reason", BackupReason)
        _coerce(self, "status", VersionStatus)
        _coerce(self, "error_class", ErrorClass, optional=True)
        _check_stored_error_class(self.error_class)
        _set(self, "artifacts", _freeze_artifacts(self.artifacts))
        if self.metadata_version != BACKUP_METADATA_VERSION:
            raise ValueError("metadata_version must be the current version")

    @property
    def version_id(self) -> str:
        """Alias of ``backup_id`` (a backup is a version)."""
        return self.backup_id

    @property
    def sha256(self) -> str | None:
        """sha256 of the archive artifact, None without archive."""
        archive = self.artifacts.get(ArtifactKind.ARCHIVE.value)
        return None if archive is None else archive.sha256

    @property
    def size_bytes(self) -> int:
        """Total size of all artifacts."""
        return sum(a.size_bytes for a in self.artifacts.values())

    @property
    def usable(self) -> bool:
        """Status ok and validation unverified or valid."""
        return (
            self.status is VersionStatus.OK
            and self.validation.status in USABLE_VALIDATION
        )

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
                kind: ref.to_dict() for kind, ref in sorted(self.artifacts.items())
            },
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "validation": self.validation.to_dict(),
            "links": self.links.to_dict(),
            "created_by": self.created_by.to_dict(),
            "contains_secrets": self.contains_secrets,
            "protected": self.protected,
            "note": self.note,
            "warnings": list(self.warnings),
            "installation_key_id": self.installation_key_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> BackupRecord:
        """Parse (and migrate) index metadata; raises BackupMetadataError.

        Bad types are rejected, never silently fixed (``protected: "yes"``,
        ``note: 5``, naive timestamps).
        """
        if not isinstance(data, Mapping):
            raise BackupMetadataError("Backup metadata must be a mapping")
        current = migrate_backup_metadata(data)
        try:
            return cls._from_current(current)
        except (KeyError, TypeError, ValueError, InvalidStorageRefError) as err:
            raise BackupMetadataError(
                f"Invalid backup metadata: {type(err).__name__}"
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
                kind: ArtifactRef.from_dict(ref) for kind, ref in raw_artifacts.items()
            },
            validation=ValidationInfo.from_dict(data.get("validation") or {}),
            links=BackupLinks.from_dict(data.get("links")),
            created_by=Actor.from_dict(data["created_by"]),
            contains_secrets=_opt_bool(data, "contains_secrets", True),
            protected=_opt_bool(data, "protected", False),
            note=_opt_str(data, "note"),
            warnings=_list_of_str(data, "warnings"),
            installation_key_id=_opt_str(data, "installation_key_id"),
            metadata_version=data["metadata_version"],
        )


# Alias: "version" and "backup" name the same record.
VersionRecord = BackupRecord


@dataclass(frozen=True, kw_only=True, slots=True)
class VersionMeta:
    """Metadata handed to the put path together with the artifacts.

    There is no ``created_by``: the store takes it from the authorization.
    ``content_hash`` and ``uci_hash`` always come from the provider; the core
    never recomputes them. ``warnings`` are machine codes (e.g.
    ``config_missing_in_archive:firewall``, ``uci_missing:sqm``) and are
    copied to the record.
    """

    backup_type: BackupType
    reason: BackupReason
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
    warnings: tuple[str, ...] = ()
    installation_key_id: str | None = None

    def __post_init__(self) -> None:
        """Coerce enums, validate hashes and the note."""
        _coerce(self, "backup_type", BackupType)
        _coerce(self, "reason", BackupReason)
        _coerce(self, "status", VersionStatus)
        _coerce(self, "error_class", ErrorClass, optional=True)
        _check_stored_error_class(self.error_class)
        for name in ("content_hash", "uci_hash"):
            value = getattr(self, name)
            if value is not None and not is_sha256(value):
                raise ValueError(f"{name} must be 64 lower-case hex characters")
        _check_note(self.note)
        for name in (
            "fetch_method",
            "openwrt_version",
            "hardware_model",
            "board_name",
            "correlation_id",
        ):
            _check_meta_text(name, getattr(self, name))
        check_key_id(self.installation_key_id)
        _set(self, "warnings", _check_warnings(self.warnings))
        # ok carries no error_class; partial/failed must say what failed
        # ("archive failed, uci ok" = backup_type partial, status partial,
        # error_class of the archive).
        if (self.status is VersionStatus.OK) != (self.error_class is None):
            raise ValueError("error_class is required exactly for partial/failed")


# Validation states that rule a version out as dedup candidate.
_DEDUP_EXCLUDED_VALIDATION: Final = frozenset(
    {ValidationStatus.INVALID, ValidationStatus.CORRUPT, ValidationStatus.MISSING}
)


def dedup_candidate(
    records: Iterable[BackupRecord], backup_type: BackupType
) -> BackupRecord | None:
    """Newest version a new one of ``backup_type`` may repeat, or None.

    Only versions of the SAME backup_type with status ok or partial whose
    validation is not invalid, corrupt or missing; FAILED never takes part.
    """
    candidates = [
        r
        for r in records
        if r.backup_type is BackupType(backup_type)
        and r.status is not VersionStatus.FAILED
        and r.validation.status not in _DEDUP_EXCLUDED_VALIDATION
    ]
    return max(candidates, key=lambda r: r.created_at, default=None)


def should_deduplicate(
    candidate: BackupRecord | None,
    meta: VersionMeta,
    artifact_kinds: Iterable[str],
    *,
    artifact_sha256: Mapping[str, str] | None = None,
) -> bool:
    """True if a new version would only repeat ``candidate`` (dedup hit).

    ``candidate`` comes from :func:`dedup_candidate`. All must hold: the
    reason is scheduled or drift; no incident link; the new status is not
    failed and equals the candidate's (partial never dedups against ok, nor
    the reverse); same backup_type and artifact kinds; equal ``content_hash``
    when there is an archive, else equal ``uci_hash`` (both provider-made);
    the same ``installation_key_id`` (a version made under another key is
    never a repeat: its secret digests differ, and a re-baseline after a key
    reset must store a version stamped with the new key). On a hit the core only moves ``last_seen_at`` and returns created=False;
    manual, pre_* and incident-linked versions always create, so no note or
    reason is lost.

    ``artifact_sha256`` (1.44.0 ruling): the sha256 the CORE computed of
    the new artifacts, per kind. When given, every kind must also equal the
    candidate's stored sha256 — the provider's hashes alone no longer make
    a repeat (byte-identical artifacts are required).
    """
    kinds = {ArtifactKind(k).value for k in artifact_kinds}
    if candidate is None or candidate.status is VersionStatus.FAILED:
        return False
    if candidate.validation.status in _DEDUP_EXCLUDED_VALIDATION:
        return False
    if meta.reason not in DEDUP_REASONS or meta.links.incident_id is not None:
        return False
    if meta.status is VersionStatus.FAILED or meta.status is not candidate.status:
        return False
    if meta.installation_key_id != candidate.installation_key_id:
        return False
    if (
        candidate.backup_type is not meta.backup_type
        or set(candidate.artifacts) != kinds
    ):
        return False
    if ArtifactKind.ARCHIVE.value in kinds:
        same = meta.content_hash is not None and meta.content_hash == (
            candidate.content_hash
        )
    else:
        same = meta.uci_hash is not None and meta.uci_hash == candidate.uci_hash
    if not same or artifact_sha256 is None:
        return same
    return all(
        artifact_sha256.get(kind) == ref.sha256
        for kind, ref in candidate.artifacts.items()
    )


@dataclass(frozen=True, kw_only=True, slots=True)
class PutVersionResult:
    """Result of the put path: a dedup hit means ``created=False``."""

    record: BackupRecord
    created: bool

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {"record": self.record.to_dict(), "created": self.created}


def validate_deletion(records: Sequence[BackupRecord], *, router_id: str) -> None:
    """Check a ``delete`` request before anything is removed.

    Raises AuthorizationError (reason ``router_mismatch``) if a version
    belongs to another router than the authorization, and
    VersionProtectedError naming the protected ids (unprotect first).
    """
    foreign = sorted(r.backup_id for r in records if r.router_id != router_id)
    if foreign:
        raise AuthorizationError(
            "Versions belong to another router",
            router_id=router_id,
            details={"reason": "router_mismatch", "version_ids": foreign},
        )
    protected = sorted(r.backup_id for r in records if r.protected)
    if protected:
        raise VersionProtectedError(
            "Protected versions cannot be deleted; unprotect them first",
            router_id=router_id,
            details={"version_ids": protected},
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class RetentionPolicy:
    """Retention a module supplies; the core executes it (``prune``).

    Two rule sets, never mixed:

    * GFS (grandfather-father-son): keep the newest USABLE version of each
      of the last ``daily`` calendar days, ``weekly`` ISO weeks and
      ``monthly`` calendar months (current period included), counted in the
      time zone of ``now``. ``None`` for a count means 0 in GFS mode.
    * Count/age: ``max_versions`` and ``max_age`` (legacy rules).

    ``max_bytes_per_router`` works with both. None means "no limit".
    Protected versions and the newest usable version of each router are
    ALWAYS kept, whatever the policy says. GFS together with
    ``max_versions``/``max_age`` raises ValueError.
    """

    max_versions: int | None = None
    max_age: timedelta | None = None
    max_bytes_per_router: int | None = None
    daily: int | None = None
    weekly: int | None = None
    monthly: int | None = None

    def __post_init__(self) -> None:
        """Positive limits, non-negative GFS counts, one rule set."""
        for name in ("max_versions", "max_bytes_per_router"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 1
            ):
                raise ValueError(f"{name} must be a positive int or None")
        if self.max_age is not None and (
            not isinstance(self.max_age, timedelta) or self.max_age <= timedelta(0)
        ):
            raise ValueError("max_age must be a positive timedelta or None")
        for name in ("daily", "weekly", "monthly"):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise ValueError(f"{name} must be a non-negative int or None")
        if self.uses_gfs and (self.max_versions is not None or self.max_age):
            raise ValueError("GFS counts cannot be combined with max_versions/max_age")

    @classmethod
    def gfs(
        cls,
        daily: int = 7,
        weekly: int = 4,
        monthly: int = 6,
        *,
        max_bytes_per_router: int | None = None,
    ) -> RetentionPolicy:
        """GFS policy (default 7 daily / 4 weekly / 6 monthly)."""
        return cls(
            daily=daily,
            weekly=weekly,
            monthly=monthly,
            max_bytes_per_router=max_bytes_per_router,
        )

    @property
    def uses_gfs(self) -> bool:
        """True if any GFS count is set."""
        return any(v is not None for v in (self.daily, self.weekly, self.monthly))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "max_versions": self.max_versions,
            "max_age_seconds": (
                None if self.max_age is None else self.max_age.total_seconds()
            ),
            "max_bytes_per_router": self.max_bytes_per_router,
            "daily": self.daily,
            "weekly": self.weekly,
            "monthly": self.monthly,
        }


# What the core applies while no module supplied a policy.
DEFAULT_RETENTION_POLICY: Final = RetentionPolicy.gfs()

# Primary keep reason = the first in this order.
_KEEP_ORDER: Final = tuple(KeepReason)


@dataclass(frozen=True, kw_only=True, slots=True)
class RetentionResult:
    """What one retention run decided for one router; nothing is silent.

    Every evaluated version is either in ``deleted`` (oldest first) or in
    ``kept`` with its primary reason; ``reasons`` lists all reasons of a
    kept version. ``total_bytes`` is the size of the kept versions,
    ``max_bytes`` the effective limit and ``over_limit`` True if the kept
    versions still exceed it (only protected/newest-valid remain).
    ``limit_deleted`` (1.44.0, additive): the deleted versions the policy
    alone would have kept, removed only because of the size limit;
    ``limit_deleted_manual`` the manual/pre_* ones among them (named on
    purpose: GFS itself never thins those).
    """

    router_id: str
    evaluated_at: datetime
    deleted: tuple[str, ...] = ()
    kept: Mapping[str, KeepReason] = field(default_factory=dict)
    reasons: Mapping[str, tuple[KeepReason, ...]] = field(default_factory=dict)
    total_bytes: int = 0
    max_bytes: int | None = None
    over_limit: bool = False
    limit_deleted: tuple[str, ...] = ()
    limit_deleted_manual: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Coerce and freeze."""
        _set(self, "deleted", tuple(self.deleted))
        _set(self, "limit_deleted", tuple(self.limit_deleted))
        _set(self, "limit_deleted_manual", tuple(self.limit_deleted_manual))
        _set(
            self,
            "kept",
            MappingProxyType({k: KeepReason(v) for k, v in self.kept.items()}),
        )
        reasons = {k: tuple(KeepReason(r) for r in v) for k, v in self.reasons.items()}
        for version_id, reason in self.kept.items():
            reasons.setdefault(version_id, (KeepReason(reason),))
        _set(self, "reasons", MappingProxyType(reasons))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "router_id": self.router_id,
            "evaluated_at": _iso(self.evaluated_at),
            "deleted": list(self.deleted),
            "kept": {k: v.value for k, v in sorted(self.kept.items())},
            "reasons": {
                k: [r.value for r in v] for k, v in sorted(self.reasons.items())
            },
            "total_bytes": self.total_bytes,
            "max_bytes": self.max_bytes,
            "over_limit": self.over_limit,
            "limit_deleted": list(self.limit_deleted),
            "limit_deleted_manual": list(self.limit_deleted_manual),
        }


# Reasons GFS never thins (1.44.0 ruling): a user's own backup and the
# safety copies taken before a change are kept until a size limit forces
# a choice.
GFS_KEEP_REASONS: Final = frozenset(
    {
        BackupReason.MANUAL,
        BackupReason.PRE_FIRMWARE_UPDATE,
        BackupReason.PRE_RESTORE,
        BackupReason.PRE_CHANGE,
    }
)


def _month_back(day: date, months: int) -> tuple[int, int]:
    """(year, month) ``months`` calendar months before ``day``'s month."""
    index = day.year * 12 + (day.month - 1) - months
    return index // 12, index % 12 + 1


def plan_retention(
    router_id: str,
    records: Iterable[BackupRecord],
    policy: RetentionPolicy,
    *,
    now: datetime | None = None,
    max_bytes: int | None = None,
) -> RetentionResult:
    """Decide which versions of one router the core's prune run deletes.

    ``now`` must be time-zone aware (default: UTC now); GFS periods are
    counted in ITS time zone. ``max_bytes`` is an extra size limit (the
    store's per-router limit); the effective limit is the smaller one.

    1. Always kept: protected versions and the newest usable version.
    2. GFS: the newest usable version of each day/week/month in the window.
       Count/age: usable versions newest first while within ``max_age`` and
       ``max_versions`` (protected and newest usable count first), THEN
       unusable ones by the same rule, so a failed version never pushes a
       usable one out.
    3. Unusable versions never represent a period; in GFS mode they stay
       (``recent_failed``) while inside the daily window. GFS never thins a
       usable manual or pre_* version (``KeepReason.MANUAL``).
    4. Over the size limit: evict kept versions except protected and newest
       usable: unusable first, then the oldest; manual/pre_* versions only
       after every other one; no newer version is skipped to keep an older
       one within a group. Still over: ``over_limit``, nothing forced. Every
       eviction is listed in ``limit_deleted`` (manual/pre_* also in
       ``limit_deleted_manual``).

    Raises ValueError for a naive ``now``, duplicate ids or a foreign router.
    """
    when = now if now is not None else utcnow()
    if not isinstance(when, datetime) or when.tzinfo is None:
        raise ValueError("now must be a time-zone aware datetime")
    if when.utcoffset() is None:
        raise ValueError("now must be a time-zone aware datetime")
    items = list(records)
    seen: set[str] = set()
    for record in items:
        if record.router_id != router_id:
            raise ValueError("records must all belong to router_id")
        if record.backup_id in seen:
            raise ValueError(f"duplicate version id {record.backup_id}")
        seen.add(record.backup_id)
    limits = [v for v in (policy.max_bytes_per_router, max_bytes) if v is not None]
    limit = min(limits) if limits else None

    tz = when.tzinfo
    local = {r.backup_id: r.created_at.astimezone(tz) for r in items}
    chrono = sorted(items, key=lambda r: (local[r.backup_id], r.backup_id))
    newest_first = list(reversed(chrono))
    newest_usable = next((r for r in newest_first if r.usable), None)

    reasons: dict[str, set[KeepReason]] = {}

    def keep(version_id: str, reason: KeepReason) -> None:
        reasons.setdefault(version_id, set()).add(reason)

    for record in items:
        if record.protected:
            keep(record.backup_id, KeepReason.PROTECTED)
    if newest_usable is not None:
        keep(newest_usable.backup_id, KeepReason.NEWEST_VALID)

    if policy.uses_gfs:
        today = when.date()
        days = {today - timedelta(days=k) for k in range(policy.daily or 0)}
        weeks = {
            (today - timedelta(weeks=k)).isocalendar()[:2]
            for k in range(policy.weekly or 0)
        }
        months = {_month_back(today, k) for k in range(policy.monthly or 0)}
        newest_day: dict[date, str] = {}
        newest_week: dict[tuple[int, int], str] = {}
        newest_month: dict[tuple[int, int], str] = {}
        for record in chrono:  # later entries overwrite: newest per period
            at = local[record.backup_id]
            if not record.usable:
                if at.date() in days:
                    keep(record.backup_id, KeepReason.RECENT_FAILED)
                continue
            newest_day[at.date()] = record.backup_id
            newest_week[tuple(at.isocalendar()[:2])] = record.backup_id
            newest_month[(at.year, at.month)] = record.backup_id
        for day, version_id in newest_day.items():
            if day in days:
                keep(version_id, KeepReason.DAILY)
        for week, version_id in newest_week.items():
            if week in weeks:
                keep(version_id, KeepReason.WEEKLY)
        for month, version_id in newest_month.items():
            if month in months:
                keep(version_id, KeepReason.MONTHLY)
        for record in items:
            if record.usable and record.reason in GFS_KEEP_REASONS:
                keep(record.backup_id, KeepReason.MANUAL)
    else:
        count = len(reasons)
        for usable_pass in (True, False):
            for record in newest_first:
                if record.backup_id in reasons or record.usable is not usable_pass:
                    continue
                if policy.max_age is not None and (
                    when - record.created_at > policy.max_age
                ):
                    continue
                if policy.max_versions is not None and count >= policy.max_versions:
                    continue
                keep(
                    record.backup_id,
                    KeepReason.WITHIN_POLICY
                    if usable_pass
                    else KeepReason.RECENT_FAILED,
                )
                count += 1

    by_id = {r.backup_id: r for r in items}
    total = sum(by_id[v].size_bytes for v in reasons)
    limit_deleted: list[str] = []
    if limit is not None and total > limit:
        evictable = [
            r
            for r in chrono
            if r.backup_id in reasons and not r.protected and r is not newest_usable
        ]
        # unusable first, then oldest (chrono order inside each group);
        # versions GFS keeps for their reason (manual/pre_*) go last.
        evictable.sort(
            key=lambda r: (
                KeepReason.MANUAL in reasons[r.backup_id],
                r.usable,
                local[r.backup_id],
                r.backup_id,
            )
        )
        for record in evictable:
            if total <= limit:
                break
            del reasons[record.backup_id]
            limit_deleted.append(record.backup_id)
            total -= record.size_bytes
    over_limit = limit is not None and total > limit
    limit_manual = [
        v
        for v in limit_deleted
        if by_id[v].usable and by_id[v].reason in GFS_KEEP_REASONS
    ]
    ordered_reasons = {
        version_id: tuple(r for r in _KEEP_ORDER if r in reasons[version_id])
        for version_id in (r.backup_id for r in chrono if r.backup_id in reasons)
    }
    return RetentionResult(
        router_id=router_id,
        evaluated_at=when,
        deleted=tuple(r.backup_id for r in chrono if r.backup_id not in reasons),
        kept={k: v[0] for k, v in ordered_reasons.items()},
        reasons=ordered_reasons,
        total_bytes=total,
        max_bytes=limit,
        over_limit=over_limit,
        limit_deleted=tuple(limit_deleted),
        limit_deleted_manual=tuple(limit_manual),
    )


@dataclass(frozen=True, kw_only=True, slots=True)
class SweepReport:
    """What the startup sweep of the version store did."""

    checked_at: datetime
    partial_deleted: int = 0
    orphaned_moved: int = 0
    marked_missing: int = 0
    # Security review 2026-11-18 (additive): symbolic links are never
    # followed, moved or deleted, only counted; index-less files are kept
    # (not moved to orphaned/) while the index is recovered or empty.
    symlinks_skipped: int = 0
    unindexed_kept: int = 0

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "checked_at": _iso(self.checked_at),
            "partial_deleted": self.partial_deleted,
            "orphaned_moved": self.orphaned_moved,
            "marked_missing": self.marked_missing,
            "symlinks_skipped": self.symlinks_skipped,
            "unindexed_kept": self.unindexed_kept,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class DriftAck:
    """User decision about one drift (stored in the core's catalog store).

    ``KNOWN`` makes the drifted live content the new baseline: before storing
    the ack the core takes (or dedups to) a version of the live
    configuration with reason ``drift`` and puts its id into ``version_id``.
    ``ACKNOWLEDGED`` keeps the baseline and has no ``version_id``.
    """

    router_id: str
    drift_id: str
    state: DriftAckState
    actor: Actor
    ts: datetime
    note: str | None = None
    version_id: str | None = None

    def __post_init__(self) -> None:
        """Validate."""
        _coerce(self, "state", DriftAckState)
        check_token("drift_id", self.drift_id)
        if not isinstance(self.ts, datetime):
            raise TypeError("ts must be a datetime")
        _require_aware(self.ts, "ts")
        _check_note(self.note)
        if self.state is DriftAckState.KNOWN:
            if not is_valid_id(self.version_id, BACKUP_ID_PREFIX):
                raise ValueError("a known ack needs the accepted version_id")
        elif self.version_id is not None:
            raise ValueError("only a known ack carries a version_id")

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "router_id": self.router_id,
            "drift_id": self.drift_id,
            "state": self.state.value,
            "actor": self.actor.to_dict(),
            "ts": _iso(self.ts),
            "note": self.note,
            "version_id": self.version_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DriftAck:
        """Inverse of :meth:`to_dict`; ValueError/TypeError/KeyError on bad data."""
        ts = _parse_dt(data["ts"], "ts")
        if ts is None:
            raise ValueError("ts is required")
        for key in ("router_id", "drift_id"):
            if not isinstance(data[key], str):
                raise TypeError(f"{key} must be a string")
        return cls(
            router_id=data["router_id"],
            drift_id=data["drift_id"],
            state=DriftAckState(data["state"]),
            actor=Actor.from_dict(data["actor"]),
            ts=ts,
            note=_opt_str(data, "note"),
            version_id=_opt_str(data, "version_id"),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class Baseline:
    """The version drift is measured against, and the rule that picked it."""

    router_id: str
    version_id: str
    rule: BaselineRule
    drift_id: str | None = None  # the KNOWN ack's drift (rule known_ack)
    decided_at: datetime | None = None  # ack ts or version created_at

    def __post_init__(self) -> None:
        """Coerce."""
        _coerce(self, "rule", BaselineRule)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "router_id": self.router_id,
            "version_id": self.version_id,
            "rule": self.rule.value,
            "drift_id": self.drift_id,
            "decided_at": _iso(self.decided_at),
        }


def select_baseline(
    router_id: str,
    records: Iterable[BackupRecord],
    acks: Iterable[DriftAck],
    *,
    explicit_backup_id: str | None = None,
) -> Baseline | None:
    """Pick the drift baseline: explicit > newest KNOWN ack > newest usable.

    An explicit id must name a usable version of this router (else
    ValueError). A KNOWN ack whose version is gone or no longer usable is
    skipped. None if the router has no usable version at all.
    """
    usable = {r.backup_id: r for r in records if r.router_id == router_id and r.usable}
    if explicit_backup_id is not None:
        record = usable.get(explicit_backup_id)
        if record is None:
            raise ValueError("explicit baseline is not a usable version of router")
        return Baseline(
            router_id=router_id,
            version_id=record.backup_id,
            rule=BaselineRule.EXPLICIT,
            decided_at=record.created_at,
        )
    known = sorted(
        (
            a
            for a in acks
            if a.router_id == router_id
            and a.state is DriftAckState.KNOWN
            and a.version_id in usable
        ),
        key=lambda a: a.ts,
        reverse=True,
    )
    if known:
        return Baseline(
            router_id=router_id,
            version_id=str(known[0].version_id),
            rule=BaselineRule.KNOWN_ACK,
            drift_id=known[0].drift_id,
            decided_at=known[0].ts,
        )
    newest = max(usable.values(), key=lambda r: r.created_at, default=None)
    if newest is None:
        return None
    return Baseline(
        router_id=router_id,
        version_id=newest.backup_id,
        rule=BaselineRule.NEWEST_VALID,
        decided_at=newest.created_at,
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
    """Live configuration as the provider captured it.

    ``configs`` is OPAQUE to the core: provider-defined, JSON-safe content
    described by ``format`` + ``format_version`` (v1:
    SNAPSHOT_FORMAT_UCI_NORMALIZED, see the contract). It is stored deep
    read-only. ``uci_hash`` is the provider's content hash (the one stored in
    versions); :attr:`checksum` is only the core's binding checksum (e.g.
    RestorePlan.live_checksum) and is NOT comparable with ``uci_hash``.
    """

    router_id: str
    captured_at: datetime
    configs: Mapping[str, Any]
    openwrt_version: str | None = None
    board_name: str | None = None
    format: str = SNAPSHOT_FORMAT_UCI_NORMALIZED
    format_version: int = 1
    contains_secrets: bool = True
    uci_hash: str | None = None
    installation_key_id: str | None = None

    def __post_init__(self) -> None:
        """Freeze the configuration."""
        _require_aware(self.captured_at, "captured_at")
        if self.uci_hash is not None and not is_sha256(self.uci_hash):
            raise ValueError("uci_hash must be 64 lower-case hex characters")
        _set(self, "configs", _freeze(self.configs))

    @property
    def checksum(self) -> str:
        """Core binding checksum of the unmasked content (not uci_hash)."""
        return canonical_checksum(_thaw(self.configs))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form with secrets masked."""
        return {
            "router_id": self.router_id,
            "captured_at": _iso(self.captured_at),
            "configs": mask_secrets(_thaw(self.configs)),
            "openwrt_version": self.openwrt_version,
            "board_name": self.board_name,
            "format": self.format,
            "format_version": self.format_version,
            "contains_secrets": self.contains_secrets,
            "uci_hash": self.uci_hash,
            "installation_key_id": self.installation_key_id,
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

    def __post_init__(self) -> None:
        """Coerce."""
        _coerce(self, "backup_type", BackupType)
        _coerce(self, "reason", BackupReason)
        _check_note(self.note)


@dataclass(frozen=True, kw_only=True, slots=True)
class CollectedVersion:
    """What a provider fetched: artifact bytes plus metadata. Not stored yet.

    Warnings travel in ``meta.warnings`` and end up in the record.
    """

    artifacts: Mapping[str, ArtifactPayload]
    meta: VersionMeta

    def __post_init__(self) -> None:
        """Freeze."""
        _set(self, "artifacts", _freeze_artifacts(self.artifacts))


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
# Scoped reader the core hands to a provider per call: (version_id, kind) ->
# bytes. It only serves the versions of that call and checks sha256 against
# the index (BackupIntegrityError on mismatch).
ArtifactReader = Callable[[str, str], Awaitable[bytes]]
# Pinned SSH of the core per call (1.44.0): (router_id, command, timeout_s,
# binary) -> api.PinnedSshResult. Bound to the core's per-router host-key
# pin store; refuses (OpenWrtHostKeyError) on a pending or mismatching pin.
# The ONLY SSH a provider may use for config/backup work.
PinnedSshRunner = Callable[[str, str, float, bool], Awaitable[Any]]


@dataclass(frozen=True, kw_only=True, slots=True, eq=False)
class ProviderContext:
    """What the core hands a provider with every call.

    ``read`` is scoped to the versions of this call; ``registry`` is the
    read side of the router registry. The installation key is fetched per
    use and never kept: :meth:`async_get_installation_key` raises
    InstallationKeyLostError while the key is lost.
    """

    registry: RouterRegistryProtocol = field(repr=False)
    read: ArtifactReader = field(repr=False)
    installation_key: Callable[[], Awaitable[bytes]] = field(repr=False)
    installation_key_state: InstallationKeyState = InstallationKeyState.OK
    correlation_id: str | None = None
    # Additive (1.44.0): pinned SSH bound to the core's host-key pin store.
    ssh: PinnedSshRunner | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Coerce."""
        _coerce(self, "installation_key_state", InstallationKeyState)

    async def async_get_installation_key(self) -> bytes:
        """The 32-byte installation key for HMAC secret digests."""
        return await self.installation_key()

    async def async_ssh_run_pinned(
        self,
        router_id: str,
        command: str,
        *,
        timeout: float = 60.0,
        binary: bool = False,
        max_output_bytes: int | None = None,
    ) -> Any:
        """Run one command over the pinned SSH path (never the shared one).

        ``max_output_bytes`` caps stdout (default: the per-artifact limit
        plus a margin); above it ArtifactTooLargeError (``too_large``).

        Raises AuthorizationError (reason ``ssh_pin_unavailable``) when the
        core has no pin store; the pin store's own refusals
        (``api.OpenWrtHostKeyError``: ``pin_pending``, ``mismatch`` ...)
        pass through unchanged.
        """
        if self.ssh is None:
            raise AuthorizationError(
                "No host-key pin store: the pinned SSH path is unavailable",
                router_id=router_id,
                details={"reason": "ssh_pin_unavailable"},
            )
        if max_output_bytes is None:
            return await self.ssh(router_id, command, timeout, binary)
        return await self.ssh(router_id, command, timeout, binary, max_output_bytes)


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

    def __post_init__(self) -> None:
        """Coerce and freeze values."""
        _coerce(self, "kind", ChangeKind)
        _set(self, "before", _freeze(self.before))
        _set(self, "after", _freeze(self.after))

    @property
    def secret(self) -> bool:
        """True if the option holds a secret here (values are masked)."""
        return self.option is not None and is_secret_option(
            self.config, self.section_type or "", self.option
        )

    def _raw(self) -> dict[str, Any]:
        """Unmasked content, only for checksums."""
        return {
            "kind": self.kind,
            "config": self.config,
            "section": self.section,
            "option": self.option,
            "section_type": self.section_type,
            "before": _thaw(self.before),
            "after": _thaw(self.after),
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
            data["before"] = mask_secrets(data["before"])
            data["after"] = mask_secrets(data["after"])
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

    def __post_init__(self) -> None:
        """Freeze."""
        _set(self, "changes", tuple(self.changes))

    @property
    def has_changes(self) -> bool:
        """True if anything differs."""
        return bool(self.changes)

    @property
    def comparable_changes(self) -> tuple[ConfigChange, ...]:
        """Changes without NOT_COMPARABLE ones (these are no drift)."""
        return tuple(c for c in self.changes if c.kind is not ChangeKind.NOT_COMPARABLE)

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
    """Live configuration compared with a baseline version.

    The provider only returns this report; the CORE emits
    ``configuration.drift_detected`` (``drifted``),
    ``configuration.change_critical`` (``critical_count > 0``) and
    ``configuration.change_unknown`` (``unknown_count > 0``) from it, with
    ``drift_id`` as dedup key. ``drift_id`` resets when the drift clears
    (``drifted=False``) or the baseline changes.

    ``secrets_comparable=False``: the baseline's secret digests were made
    with another installation key (or the key is lost); such options are
    NOT_COMPARABLE changes, not drift.

    ``rebaseline=True`` says "the installation key changed". It may come
    together with real changes (``drifted=True`` / comparable changes):
    then the report IS a drift and the core emits its events. The core
    makes the live state the new baseline only when nothing comparable
    changed and the comparison is complete (:attr:`rebaseline_allowed`).

    ``comparison``: ``complete``, ``partial`` (``not_compared`` lists the
    configs that could not be read or compared) or ``unknown``. Only a
    complete comparison without drift is an all-clear (:attr:`all_clear`);
    otherwise the core emits ``configuration.drift_incomplete`` and keeps
    the drift dedup state.
    """

    router_id: str
    baseline_backup_id: str
    checked_at: datetime
    drifted: bool
    diff: ConfigDiff
    drift_id: str | None = None  # stable id of this drift (dedup, acks)
    ack_state: DriftAckState | None = None
    ignored_paths: tuple[str, ...] = ()  # volatile options left out
    baseline_rule: BaselineRule | None = None
    critical_count: int = 0  # changes the provider rates critical
    unknown_count: int = 0  # changes the provider cannot classify
    secrets_comparable: bool = True
    rebaseline: bool = False
    comparison: DriftComparison = DriftComparison.COMPLETE
    not_compared: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Coerce and validate (provider output: untrusted)."""
        _coerce(self, "ack_state", DriftAckState, optional=True)
        _coerce(self, "baseline_rule", BaselineRule, optional=True)
        _coerce(self, "comparison", DriftComparison)
        _set(self, "ignored_paths", tuple(self.ignored_paths))
        if isinstance(self.not_compared, str):
            raise TypeError("not_compared must be a sequence of config names")
        _set(self, "not_compared", tuple(self.not_compared))
        for name in self.not_compared:
            check_token("not_compared entry", name)
        check_token("drift_id", self.drift_id, optional=True)
        if self.drifted and self.drift_id is None:
            raise ValueError("a drift needs a drift_id")
        for name in ("critical_count", "unknown_count"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative int")
        if self.comparison is DriftComparison.COMPLETE and self.not_compared:
            raise ValueError("a complete comparison lists no not_compared configs")
        if self.comparison is DriftComparison.PARTIAL and not self.not_compared:
            raise ValueError("a partial comparison lists the configs not compared")

    @property
    def rebaseline_allowed(self) -> bool:
        """Key changed and NOTHING else: complete, no drift, no real change."""
        return (
            self.rebaseline
            and not self.drifted
            and not self.diff.comparable_changes
            and self.comparison is DriftComparison.COMPLETE
        )

    @property
    def all_clear(self) -> bool:
        """No drift AND everything compared (only then dedup state resets)."""
        return (
            not self.drifted
            and not self.diff.comparable_changes
            and self.comparison is DriftComparison.COMPLETE
        )

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
            "baseline_rule": (
                None if self.baseline_rule is None else self.baseline_rule.value
            ),
            "critical_count": self.critical_count,
            "unknown_count": self.unknown_count,
            "secrets_comparable": self.secrets_comparable,
            "rebaseline": self.rebaseline,
            "comparison": self.comparison.value,
            "not_compared": list(self.not_compared),
        }


def drift_event_types(report: DriftReport) -> tuple[CoreEventType, ...]:
    """Core event types the core emits for one drift report (in order).

    A report that says ``rebaseline`` but also carries real changes is a
    drift; an incomplete comparison adds ``drift_incomplete``.
    """
    if report.rebaseline_allowed:
        return ()
    types: list[CoreEventType] = []
    if report.drifted or report.diff.comparable_changes:
        types.append(CoreEventType.DRIFT_DETECTED)
        if report.critical_count:
            types.append(CoreEventType.CHANGE_CRITICAL)
        if report.unknown_count:
            types.append(CoreEventType.CHANGE_UNKNOWN)
    if report.comparison is not DriftComparison.COMPLETE:
        types.append(CoreEventType.DRIFT_INCOMPLETE)
    return tuple(types)


def integrity_failed(validation: ValidationInfo) -> bool:
    """True if the core emits ``configuration.integrity_failed`` for it."""
    return validation.status in _DEDUP_EXCLUDED_VALIDATION


@dataclass(frozen=True, kw_only=True, slots=True)
class CompatibilityIssue:
    """One finding of a restore compatibility check."""

    code: str  # e.g. "board_mismatch", "major_version_mismatch"
    message: str  # free text: never configuration values
    blocking: bool = True

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (message scrubbed)."""
        return {
            "code": self.code,
            "message": scrub_text(self.message),
            "blocking": self.blocking,
        }


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
    description: str | None = None  # free text: never configuration values
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Freeze."""
        _set(self, "detail", _freeze(self.detail))

    def _raw(self) -> dict[str, Any]:
        """Unmasked content, only for checksums."""
        return {
            "order": self.order,
            "action": self.action,
            "target": self.target,
            "description": self.description,
            "detail": _thaw(self.detail),
        }

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form with secrets masked."""
        data = self._raw()
        data["description"] = scrub_text(self.description)
        data["detail"] = mask_secrets(data["detail"])
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

    def __post_init__(self) -> None:
        """Freeze; the plan id comes from the provider (untrusted)."""
        check_token("plan_id", self.plan_id)
        for name in ("steps", "warnings", "instructions"):
            _set(self, name, tuple(getattr(self, name)))

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
            "warnings": [scrub_text(w) for w in self.warnings],
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
    message: str | None = None  # free text: never configuration values
    reboot_required: bool = False
    rolled_back: bool = False
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        """Coerce."""
        _coerce(self, "status", RestoreStatus)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (message scrubbed)."""
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
            "message": scrub_text(self.message),
            "reboot_required": self.reboot_required,
            "rolled_back": self.rolled_back,
            "correlation_id": self.correlation_id,
        }


@dataclass(frozen=True, kw_only=True, slots=True)
class ExportHandle:
    """Download handle of an exported version; ``reader`` returns the bytes once."""

    backup_id: str
    artifact: str  # ArtifactKind value
    filename: str
    content_type: str
    size_bytes: int
    sha256: str
    contains_secrets: bool
    reader: Callable[[], Awaitable[bytes]] = field(repr=False, compare=False)
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        """Validate the artifact kind."""
        _set(self, "artifact", ArtifactKind(self.artifact).value)

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
    key (delete); ``checksum`` is the binding checksum of the action. Only
    ``requested_by`` may redeem it (see :func:`check_redeem`). Approval ids
    are not secrets. Pending approvals live in memory only and do NOT
    survive a restart.
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
    reason: str | None = None  # free text: never configuration values
    correlation_id: str | None = None

    def __post_init__(self) -> None:
        """Coerce and validate."""
        _coerce(self, "status", ApprovalStatus)
        _require_aware(self.requested_at, "requested_at")
        _require_aware(self.expires_at, "expires_at")
        _require_aware(self.decided_at, "decided_at")

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
            "reason": scrub_text(self.reason),
            "correlation_id": self.correlation_id,
        }


def approver_denial_reason(
    approval: ApprovalRequest, approver: object, *, now: datetime | None = None
) -> str | None:
    """None if ``approver`` may approve/reject ``approval`` now.

    Reasons: unverified_actor, actor_verification_expired, not_admin,
    not_pending, expired.
    """
    now = now or utcnow()
    if not isinstance(approver, VerifiedActor):
        return "unverified_actor"
    if not approver.is_fresh(now):
        return "actor_verification_expired"
    if not approver.is_admin:
        return "not_admin"
    if approval.status is not ApprovalStatus.PENDING:
        return "not_pending"
    if now >= approval.expires_at:
        return "expired"
    return None


def check_redeem(
    approval: ApprovalRequest,
    actor: object,
    *,
    action: str,
    router_id: str,
    checksum: str,
    now: datetime | None = None,
) -> None:
    """Raise unless ``actor`` may redeem ``approval`` for this action now.

    Only the requester (same principal, re-verified; a user must still be
    admin) may redeem; action, router and binding checksum must match.
    AuthorizationError for an unverified actor, ApprovalRequiredError while
    pending, ApprovalInvalidError otherwise (``details["reason"]``).
    """
    now = now or utcnow()
    if not isinstance(actor, VerifiedActor) or not actor.is_fresh(now):
        raise AuthorizationError(
            "Actor is not verified", details={"reason": "unverified_actor"}
        )

    def _invalid(reason: str) -> ApprovalInvalidError:
        return ApprovalInvalidError(
            f"Approval cannot be redeemed: {reason}",
            router_id=approval.router_id,
            details={"reason": reason, "approval_id": approval.approval_id},
        )

    if approval.status is ApprovalStatus.PENDING:
        raise ApprovalRequiredError(
            "Approval is still pending",
            router_id=approval.router_id,
            details={"reason": "pending", "approval_id": approval.approval_id},
        )
    if approval.status is not ApprovalStatus.APPROVED:
        raise _invalid(approval.status.value)
    if now >= approval.expires_at:
        raise _invalid("expired")
    if str(action) != str(approval.action):
        raise _invalid("action_mismatch")
    if router_id != approval.router_id:
        raise _invalid("router_mismatch")
    if checksum != approval.checksum:
        raise _invalid("checksum_mismatch")
    if not actor.actor.same_principal(approval.requested_by):
        raise _invalid("not_requester")
    if actor.actor.kind is ActorKind.USER and not actor.is_admin:
        raise _invalid("not_admin")


# Module-private mint sentinel: only the ActionGuard (core_guard.py) may call
# _mint_write_authorization(). Python cannot enforce this; the guard's ledger
# rejects any authorization it did not issue.
_MINT_SENTINEL: Final = object()


class WriteAuthorization:
    """Single-use permission for one guarded action, minted only by the guard.

    Bound to action, router_id and (optionally) a binding checksum. Whoever
    performs the action calls ``guard.consume(authorization, ...)`` right
    before it acts; the guard checks its ledger and calls :meth:`_consume`.
    Every consume attempt uses the authorization up, also a failed one.
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
        """Who the action is performed for (the store's ``created_by``)."""
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
        """After this, consume fails."""
        return self._expires_at

    @property
    def consumed(self) -> bool:
        """True once a consume was attempted (successfully or not)."""
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

    def _consume(
        self,
        *,
        action: str,
        router_id: str,
        checksum: str | None = None,
        now: datetime | None = None,
    ) -> None:
        """Guard-internal: use once or raise AuthorizationError.

        ``checksum`` is required (and must match) when the authorization is
        bound to one. Reasons: already_used, expired, action_mismatch,
        router_mismatch, checksum_mismatch. Synchronous: call on the event
        loop, never in an executor job.
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
    """Mint a WriteAuthorization. PRIVATE: only core_guard.ActionGuard calls
    it and records the id in its ledger."""
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
    entry written for this decision. ``retry_after`` (seconds) is set only
    for a ``rate_limited`` denial (B5).
    """

    state: DecisionState
    action: str
    router_id: str
    audit_id: str
    authorization: WriteAuthorization | None = field(default=None, repr=False)
    approval_request: ApprovalRequest | None = None
    reason: str | None = None
    retry_after: float | None = None

    def __post_init__(self) -> None:
        """Coerce."""
        _coerce(self, "state", DecisionState)
        if self.retry_after is not None and (
            isinstance(self.retry_after, bool)
            or not isinstance(self.retry_after, int | float)
            or not math.isfinite(self.retry_after)
            or self.retry_after < 0
        ):
            raise ValueError("retry_after must be a finite number >= 0")

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
            "retry_after": self.retry_after,
        }


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------


# Follow-up B8: typed optional event fields for modules.
EVENT_CLASSIFICATION_PATTERN: Final = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,63}")
CLIENT_REF_PATTERN: Final = re.compile(
    re.escape(IDENTIFIER_PSEUDONYM_PREFIXES["client"])
    + rf"[0-9a-f]{{{IDENTIFIER_PSEUDONYM_HEX_LENGTH}}}"
)
EVENT_REF_FIELDS: Final = (
    "client_ref",
    "confidence",
    "classification",
    "incident_ref",
    "radio_id",
)


def _check_event_refs(event: CoreEvent) -> None:
    """Validate the B8 fields; ``confidence`` is stored as float."""
    client_ref = event.client_ref
    if client_ref is not None:
        if not isinstance(client_ref, str):
            raise TypeError("client_ref must be a string")
        if CLIENT_REF_PATTERN.fullmatch(client_ref) is None:
            raise ValueError(
                "client_ref must be a client pseudonym cli_<16 hex> "
                "(pseudonymise_identifier('client', ...)), never a raw identifier"
            )
    confidence = event.confidence
    if confidence is not None:
        if isinstance(confidence, bool) or not isinstance(confidence, int | float):
            raise TypeError("confidence must be a number")
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")
        _set(event, "confidence", float(confidence))
    classification = event.classification
    if classification is not None:
        if not isinstance(classification, str):
            raise TypeError("classification must be a string")
        if EVENT_CLASSIFICATION_PATTERN.fullmatch(classification) is None:
            raise ValueError("classification must match EVENT_CLASSIFICATION_PATTERN")
    check_token("incident_ref", event.incident_ref, optional=True)
    check_token("radio_id", event.radio_id, optional=True)


@dataclass(frozen=True, kw_only=True, slots=True)
class CoreEvent:
    """One audit / bus event.

    ``type`` is a CoreEventType value or a module type below a registered
    prefix (kept as str when it comes from a newer version). ``data`` must
    carry ids and counters, never configuration values; it is stored
    read-only and masked on output as a second safety net.

    Dedup: ``dedup_key`` is the discriminator (drift_id, error_class, …);
    the scope is ``(router_id, type, dedup_key)``. A repeat inside the fixed
    cooldown window is not published on the bus; the stored entry's
    ``repeat_count`` / ``last_repeat_at`` are updated instead. Types in
    AUDIT_MANDATORY_EVENT_TYPES ignore ``dedup_key``.

    ``security_relevant`` (a module marks its own event) puts it on the
    security ring; ``audit_mandatory`` (set by the audit log for a type a
    module registered as mandatory) disables dedup. Both default False, so
    entries stored before them read unchanged.

    B8 fields (all optional, default None, never part of the dedup scope):
    ``client_ref`` (``cli_<16 hex>`` pseudonym), ``confidence`` (0..1),
    ``classification`` (machine code), ``incident_ref``, ``radio_id``
    (tokens). They are not masked: only pseudonyms and codes fit them.
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
    repeat_count: int = 0
    last_repeat_at: datetime | None = None
    data: Mapping[str, Any] = field(default_factory=dict)
    security_relevant: bool = False
    audit_mandatory: bool = False
    client_ref: str | None = None
    confidence: float | None = None
    classification: str | None = None
    incident_ref: str | None = None
    radio_id: str | None = None

    def __post_init__(self) -> None:
        """Coerce, validate and freeze."""
        _check_event_refs(self)
        if not isinstance(self.type, str) or not self.type:
            raise ValueError("event type must be a non-empty string")
        for flag in ("security_relevant", "audit_mandatory"):
            if not isinstance(getattr(self, flag), bool):
                raise TypeError(f"{flag} must be a bool")
        _require_aware(self.ts, "ts")
        _require_aware(self.last_repeat_at, "last_repeat_at")
        _coerce(self, "severity", Severity)
        _coerce(self, "result", EventResult)
        if not isinstance(self.repeat_count, int) or self.repeat_count < 0:
            raise ValueError("repeat_count must be a non-negative int")
        _set(self, "data", _freeze(self.data))

    @property
    def dedup_scope(self) -> tuple[str, str, str] | None:
        """``(router_id or "-", type, dedup_key)``; None if not deduplicated."""
        if (
            self.dedup_key is None
            or self.audit_mandatory
            or self.type in AUDIT_MANDATORY_EVENT_TYPES
        ):
            return None
        return (self.router_id or "-", str(self.type), self.dedup_key)

    @property
    def audit_ring(self) -> AuditRing:
        """Which ring keeps this event (security if marked so)."""
        if self.security_relevant:
            return AuditRing.SECURITY
        return audit_ring_for(self.type)

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
            "repeat_count": self.repeat_count,
            "last_repeat_at": _iso(self.last_repeat_at),
            "data": mask_secrets(_thaw(self.data)),
            "security_relevant": self.security_relevant,
            "audit_mandatory": self.audit_mandatory,
            "client_ref": self.client_ref,
            "confidence": self.confidence,
            "classification": self.classification,
            "incident_ref": self.incident_ref,
            "radio_id": self.radio_id,
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
        if payload is not None and not isinstance(payload, Mapping):
            raise TypeError("data must be a mapping")
        return cls(
            event_id=data["event_id"],
            ts=ts,
            type=event_type,
            source=data["source"],
            severity=Severity(data.get("severity", Severity.INFO)),
            result=EventResult(data.get("result", EventResult.INFO)),
            router_id=_opt_str(data, "router_id"),
            entry_id=_opt_str(data, "entry_id"),
            actor=None if actor is None else Actor.from_dict(actor),
            correlation_id=_opt_str(data, "correlation_id"),
            dedup_key=_opt_str(data, "dedup_key"),
            repeat_count=data.get("repeat_count", 0),
            last_repeat_at=_parse_dt(data.get("last_repeat_at"), "last_repeat_at"),
            data=payload or {},
            security_relevant=data.get("security_relevant", False),
            audit_mandatory=data.get("audit_mandatory", False),
            client_ref=data.get("client_ref"),
            confidence=data.get("confidence"),
            classification=data.get("classification"),
            incident_ref=data.get("incident_ref"),
            radio_id=data.get("radio_id"),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class EmitResult:
    """Result of ``emit``: the stored entry and whether the bus saw it."""

    event: CoreEvent
    published: bool
    deduplicated: bool = False


CoreEventListener = Callable[[CoreEvent], None]


# ---------------------------------------------------------------------------
# Service interfaces (implemented in later steps; contract only)
# ---------------------------------------------------------------------------


@runtime_checkable
class ConfigBackupProvider(Protocol):
    """The one configuration provider (config-manager).

    Produces and analyses artifacts only: it reads from the router through
    the entry's existing OpenWrtAPI and never stores, exports or deletes
    bytes itself. Every call gets a :class:`ProviderContext` (scoped
    ``read``, registry read access, installation key). The provider never
    fires bus events: it returns results and the core emits the events.
    ``async_probe`` reports every config.* capability it decides, also
    unavailable ones (e.g. ``config.restore`` in phase 1). Before writing
    to a router it calls ``api.guard.consume(authorization, ...)``. Exactly
    one provider can be registered.
    """

    @property
    def provider_id(self) -> str:
        """Stable id, e.g. ``config_manager``."""

    @property
    def provider_api_version(self) -> int:
        """Version of this protocol (in SUPPORTED_PROVIDER_API_VERSIONS)."""

    def supported(self, router: RouterRecord) -> bool:
        """Cheap, synchronous pre-check (no router call)."""

    async def async_probe(
        self, conn: RouterConnection, ctx: ProviderContext
    ) -> Mapping[str, CapabilityStatus]:
        """Probe config.* capabilities on the router (setup, ACL redeploy,
        firmware change; never in the poll)."""

    async def async_capture(
        self, conn: RouterConnection, request: CaptureRequest, ctx: ProviderContext
    ) -> ConfigSnapshot:
        """Read the live configuration (uci_hash made by the provider)."""

    async def async_collect(
        self, conn: RouterConnection, request: CollectRequest, ctx: ProviderContext
    ) -> CollectedVersion:
        """Fetch a version (archive, uci, inventory) from the router."""

    async def async_validate(
        self, record: BackupRecord, ctx: ProviderContext
    ) -> ValidationInfo:
        """Check a stored version beyond checksums (format, members)."""

    async def async_compare(
        self,
        base: ConfigSource,
        other: ConfigSource,
        ctx: ProviderContext,
        *,
        base_router: RouterRecord,
        other_router: RouterRecord,
    ) -> ConfigDiff:
        """Compare two sources; the RouterRecords carry the management host."""

    async def async_detect_drift(
        self,
        conn: RouterConnection,
        baseline: BackupRecord,
        acks: Sequence[DriftAck],
        ctx: ProviderContext,
        *,
        router: RouterRecord,
    ) -> DriftReport:
        """Compare live configuration with ``baseline``."""

    async def async_prepare_restore(
        self,
        conn: RouterConnection,
        record: BackupRecord,
        target: RouterRecord,
        ctx: ProviderContext,
    ) -> RestorePlan:
        """Dry run: compatibility plus plan. Never writes."""

    async def async_execute_restore(
        self,
        conn: RouterConnection,
        plan: RestorePlan,
        authorization: WriteAuthorization,
        ctx: ProviderContext,
    ) -> RestoreResult:
        """Write to the router after ``guard.consume(authorization, ...)``.

        Phase 1: the core only calls this when the provider declares
        ``config.restore`` available; otherwise CapabilityUnavailableError.
        """


@runtime_checkable
class RouterRegistryProtocol(Protocol):
    """Read side of the router registry (fleet-wide, one per HA instance).

    Records are immutable; every call returns the current snapshot.
    """

    def get(self, router_id: str) -> RouterRecord:
        """Record by router id; RouterNotFoundError if unknown."""

    def get_by_entry(self, entry_id: str) -> RouterRecord:
        """Active record of a config entry; RouterNotFoundError if none."""

    def find(self, router_id: str) -> RouterRecord | None:
        """Record by router id or None."""

    def list(self, *, include_orphaned: bool = False) -> tuple[RouterRecord, ...]:
        """All active (and optionally orphaned) records."""

    def capabilities(self, router_id: str) -> Mapping[str, CapabilityStatus]:
        """Read-only capability map of a router."""

    def has_capability(self, router_id: str, capability: str) -> bool:
        """True if available now."""

    def require_capability(self, router_id: str, capability: str) -> None:
        """Raise CapabilityUnavailableError unless available."""

    def adoption_candidates(self, entry_id: str) -> tuple[AdoptionCandidate, ...]:
        """Orphaned records whose fingerprint matches the entry's router."""

    async def async_adopt(
        self, entry_id: str, orphan_router_id: str, *, actor: Actor
    ) -> RouterRecord:
        """Bind an orphaned record (history, versions) to ``entry_id``.

        ``actor`` is re-verified; only an admin user may adopt."""


@runtime_checkable
class ActionGuardProtocol(Protocol):
    """Decides every mutating or critical action; mints and consumes
    WriteAuthorizations (with a ledger of issued ids)."""

    async def async_verify_actor(self, actor: Actor) -> VerifiedActor:
        """Re-check an Actor against hass.auth (ignores its is_admin)."""

    async def async_resolve_actor(
        self, context: Context | None, *, module: str | None = None
    ) -> VerifiedActor:
        """Actor from an HA Context, verified."""

    def authorize(
        self,
        action: str,
        router_id: str,
        actor: VerifiedActor,
        *,
        subject_id: str | None = None,
        checksum: str | None = None,
        approval_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuthorizationDecision:
        """Synchronous decision; always writes one audit entry.

        Unverified or stale actors are denied. With ``approval_id`` the
        approval is redeemed (check_redeem).
        """

    def consume(
        self,
        authorization: WriteAuthorization,
        *,
        action: str,
        router_id: str,
        checksum: str | None = None,
    ) -> None:
        """Check ledger, single use, expiry and binding; audit; or raise
        AuthorizationError (``unknown_authorization`` if not issued here).
        Synchronous: call on the event loop, never in an executor job."""

    def approve(self, approval_id: str, *, actor: VerifiedActor) -> ApprovalRequest:
        """Verified admin user approves a pending request."""

    def reject(
        self, approval_id: str, *, actor: VerifiedActor, reason: str | None = None
    ) -> ApprovalRequest:
        """Verified admin user rejects a pending request."""

    def get_approval(self, approval_id: str) -> ApprovalRequest:
        """Request by id; ApprovalInvalidError if unknown."""

    def pending_approvals(
        self, router_id: str | None = None
    ) -> tuple[ApprovalRequest, ...]:
        """Open requests, newest first (in memory; lost on restart)."""

    def register_action(
        self,
        name: str,
        action_class: ActionClass,
        *,
        module: str,
        admin_user_only: bool = False,
        sensitive_read: bool = False,
        rate_limit: RateLimit | None = None,
    ) -> None:
        """Register an extension action ``<module>.<action>``.

        ``sensitive_read`` (READ only): a user must be a verified admin.
        ``rate_limit`` (ACTIVE only): grants per router and window.
        """


@runtime_checkable
class VersionReadView(Protocol):
    """Module-facing, read-only view of the version index (no bytes)."""

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

    async def async_list_drift_acks(self, router_id: str) -> tuple[DriftAck, ...]:
        """Acknowledgements of a router."""

    def usage_bytes(self, router_id: str | None = None) -> int:
        """Bytes used by one router or in total."""


@runtime_checkable
class VersionStoreProtocol(VersionReadView, Protocol):
    """CORE-INTERNAL store: index plus artifact files.

    Directories 0700, files 0600, atomic writes via ``.partial`` + rename,
    index entry written last, all file I/O in the executor. Modules never
    get this object.
    """

    async def async_put_version(
        self,
        router_id: str,
        artifacts: Mapping[str, ArtifactPayload],
        meta: VersionMeta,
        *,
        authorization: WriteAuthorization,
    ) -> PutVersionResult:
        """Store a version (``created_by`` = authorization.actor); a dedup
        hit (should_deduplicate) only moves last_seen_at."""

    async def async_read_artifact(self, version_id: str, kind: str) -> bytes:
        """Bytes of one artifact; checks storage_format, locator and sha256."""

    async def async_delete_versions(
        self, version_ids: Sequence[str], *, authorization: WriteAuthorization
    ) -> tuple[str, ...]:
        """``delete``: validate_deletion first; ``prune``: only ids from
        plan_retention. Returns deleted ids."""

    async def async_set_protected(
        self, version_id: str, protected: bool, *, authorization: WriteAuthorization
    ) -> BackupRecord:
        """Set or clear protection."""

    async def async_set_validation(
        self, version_id: str, validation: ValidationInfo
    ) -> BackupRecord:
        """Store a validation result."""

    async def async_put_drift_ack(
        self, ack: DriftAck, *, authorization: WriteAuthorization
    ) -> DriftAck:
        """Store a drift acknowledgement."""

    async def async_sweep(self) -> SweepReport:
        """Startup cleanup: partials, index-less files, missing files."""

    async def async_archive_router(
        self, router_id: str, *, entry_id: str | None = None
    ) -> bool:
        """Move a removed router's folder to ``removed/<router_id>/`` (audited;
        True if a folder was moved). Runs automatically on entry removal."""


@runtime_checkable
class ConfigurationApiProtocol(Protocol):
    """Configuration API v1, from ``async_get_configuration_api(hass, 1)``.

    Every method that takes ``actor: Actor`` re-verifies it against
    hass.auth; a caller-supplied ``is_admin`` is ignored. Mutating and
    critical operations take the router lock first, then authorize.
    """

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
    def versions(self) -> VersionReadView:
        """Read-only version index."""

    @property
    def provider_id(self) -> str | None:
        """Registered provider or None."""

    def register_provider(self, provider: ConfigBackupProvider) -> Callable[[], None]:
        """Register the provider; returns an unregister callback."""

    async def async_get_installation_key(self) -> bytes:
        """32-byte installation key; InstallationKeyLostError while LOST."""

    async def async_get_module_key(self, module: str, purpose: str = "") -> bytes:
        """HKDF-SHA256 key of a registered module (§11.5); never logged."""

    @property
    def installation_key_state(self) -> InstallationKeyState:
        """ok, lost or uninitialised (see installation_key_state())."""

    async def async_request_installation_key_reset(
        self, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask for a new key after a loss (CRITICAL, admin user)."""

    async def async_reset_installation_key(
        self, approval_id: str, *, actor: Actor
    ) -> None:
        """Create the new key after approval; requester only. The next
        drift check per router is a rebaseline, not a drift."""

    async def async_get_baseline(
        self, router_id: str, *, baseline_backup_id: str | None = None
    ) -> Baseline | None:
        """Current drift baseline and the rule that picked it (READ)."""

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

    async def async_validate_backup(
        self, backup_id: str, *, actor: Actor
    ) -> BackupRecord:
        """Validate and store the result (READ; actor required, users need admin)."""

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

    async def async_put_version(
        self,
        router_id: str,
        artifacts: Mapping[str, ArtifactPayload],
        meta: VersionMeta,
        *,
        authorization: WriteAuthorization,
    ) -> PutVersionResult:
        """Store a version a module collected itself (``backup`` authorization)."""

    async def async_set_protected(
        self, backup_id: str, protected: bool, *, actor: Actor
    ) -> BackupRecord:
        """Protect against retention and delete (MUTATING, admin user)."""

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

    def set_retention_policy(self, policy: RetentionPolicy, *, module: str) -> None:
        """Supply the retention policy the core's prune run applies."""

    async def async_apply_retention(
        self, router_id: str | None = None
    ) -> tuple[RetentionResult, ...]:
        """Run retention now (as system); one result per router."""

    async def async_request_export(
        self, backup_id: str, *, actor: Actor, artifact: str = ArtifactKind.ARCHIVE
    ) -> ApprovalRequest:
        """Ask to export one artifact (CRITICAL, admin user)."""

    async def async_export_backup(
        self, approval_id: str, *, actor: Actor
    ) -> ExportHandle:
        """Export after approval; requester only, one download."""

    async def async_request_deletion(
        self, backup_ids: Sequence[str], *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to delete versions (CRITICAL; VersionProtectedError if protected)."""

    async def async_delete_backups(
        self, approval_id: str, *, actor: Actor
    ) -> tuple[str, ...]:
        """Delete after approval; requester only."""

    async def async_request_restore(
        self, plan: RestorePlan, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to restore (CRITICAL; phase 1: CapabilityUnavailableError)."""

    async def async_approve(self, approval_id: str, *, actor: Actor) -> ApprovalRequest:
        """Approve any pending request (verified admin user)."""

    async def async_reject(
        self, approval_id: str, *, actor: Actor, reason: str | None = None
    ) -> ApprovalRequest:
        """Reject any pending request (verified admin user)."""

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
        ring: AuditRing | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> tuple[CoreEvent, ...]:
        """Audit entries from both rings (or one), newest first."""

    def subscribe(self, listener: CoreEventListener) -> Callable[[], None]:
        """Listen to published events; returns an unsubscribe callback."""

    def register_event_prefix(self, prefix: str, *, module: str) -> Callable[[], None]:
        """Allow a module's own event types below ``prefix`` (not a core
        namespace, see CORE_EVENT_NAMESPACES); returns a remover."""

    def register_audit_mandatory_types(
        self, event_types: Iterable[str], *, module: str
    ) -> Callable[[], None]:
        """Make the module's own types audit-mandatory (§12.5); returns a remover."""

    def emit(
        self,
        event_type: str,
        *,
        source: str,
        router_id: str | None = None,
        entry_id: str | None = None,
        severity: Severity = Severity.INFO,
        result: EventResult = EventResult.INFO,
        actor: Actor | None = None,
        correlation_id: str | None = None,
        dedup_key: str | None = None,
        data: Mapping[str, Any] | None = None,
        security_relevant: bool = False,
        client_ref: str | None = None,
        confidence: float | None = None,
        classification: str | None = None,
        incident_ref: str | None = None,
        radio_id: str | None = None,
    ) -> EmitResult:
        """Write an audit entry and fire EVENT_CORE unless deduplicated.

        For modules: only types below a prefix registered by the same
        module; core types (is_core_event_type) raise ValueError, the core
        emits them itself from provider results.
        """
