"""Backup provider of the configuration manager (Configuration API v1).

Plan: docs/plans/2026-11-17-config-manager.md; contract:
docs/dev/configuration-api-v1.md, sections 10 and 11.

:class:`ConfigManagerProvider` implements ``core_models.ConfigBackupProvider``
on top of the config-manager engine (collector, archive check, snapshot,
diff, restore dry run):

- It reads from the router only through the four ``config_*`` read methods
  of the entry's existing ``OpenWrtAPI`` (``RouterConnection.api``).
- It returns artifacts and metadata. It never stores, exports or deletes
  bytes, never fires events, never calls the guard and never writes to a
  router: ``config.restore`` is unavailable in phase 1.
- Raw router data (archive texts, UCI values with plaintext secrets) lives
  only inside one call. The ``uci`` artifact holds the normalized snapshot
  with HMAC digests of secrets; the ``archive`` artifact is the router's
  ``sysupgrade -b`` archive, unchanged.
- Log lines carry the operation, fetch method, error class, duration and
  size only.

The provider keeps no state between calls, so one instance serves every
router. Every router call of one operation shares the deadline
``FETCH_TIMEOUTS["job"]``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final, TypeVar

from .config_archive import (
    ArchiveError,
    ArchiveReport,
    extract_uci_texts,
    validate_archive,
    verify_checksum,
    with_uci_cross_check,
)
from .config_collector import (
    PROGRAMMING_ERRORS,
    ArchiveFetch,
    UciCollection,
    classify_error,
    collect_archive,
    collect_inventory,
    collect_uci,
    collect_uci_snapshot,
)
from .config_const import (
    ARCHIVE_CONFIG_PREFIX,
    CHAIN_SKIP_ERRORS,
    DEFAULT_ARCHIVE_LIMITS,
    ERR_AUTH,
    ERR_CHECKSUM_MISMATCH,
    ERR_INCOMPLETE,
    ERR_INVALID,
    ERR_NOT_AVAILABLE,
    ERR_PERMISSION,
    ERR_TIMEOUT,
    ERR_TOO_LARGE,
    ERR_UNREACHABLE,
    FETCH_JOB,
    FETCH_METHOD_CGI,
    FETCH_METHOD_SSH,
    FETCH_METHODS,
    FETCH_PACKAGELIST,
    FETCH_TIMEOUTS,
    FETCH_UCI,
    SECRET_MARKER_KEY,
    UCI_CONFIGS,
    WARN_CONFIG_MISSING_IN_ARCHIVE,
    ArchiveLimits,
)
from .config_diff import (
    DETAIL_SECRET_CHANGED,
    Area,
    Change,
    diff_snapshots,
    evaluate_drift,
    not_comparable,
)
from .config_diff import DriftAck as EngineDriftAck
from .config_inventory import Inventory
from .config_mask import mask_for_output, redact_text, secret_digest_factory
from .config_restore import INSTR_NOT_REVERSIBLE, LEVEL_BLOCK, Finding, dry_run
from .config_snapshot import (
    NORM_ORDER,
    NORM_SECTIONS,
    UciSnapshot,
    build_snapshot,
    canonical_json,
    parse_uci_file,
)
from .core_errors import (
    ArtifactTooLargeError,
    BackupIncompleteError,
    BackupIntegrityError,
    BackupNotFoundError,
    CapabilityUnavailableError,
    ConfigApiError,
    ErrorClass,
    OperationTimeoutError,
    ProviderError,
    RouterAuthError,
    RouterPermissionError,
    RouterUnavailableError,
)
from .core_models import (
    MAX_WARNINGS,
    PLAN_ID_PREFIX,
    PROVIDER_API_VERSION,
    SNAPSHOT_FORMAT_UCI_NORMALIZED,
    WARNING_CODE_PATTERN,
    ArtifactKind,
    ArtifactPayload,
    BackupRecord,
    BackupType,
    Capability,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    CaptureRequest,
    ChangeKind,
    CollectedVersion,
    CollectRequest,
    CompatibilityCheck,
    CompatibilityInfo,
    CompatibilityIssue,
    ConfigChange,
    ConfigDiff,
    ConfigRef,
    ConfigSnapshot,
    ConfigSource,
    DriftAck,
    DriftAckState,
    DriftReport,
    ProviderContext,
    RecordState,
    RestorePlan,
    RestoreResult,
    RestoreStep,
    RouterConnection,
    RouterRecord,
    ValidationInfo,
    ValidationStatus,
    VersionMeta,
    VersionStatus,
    installation_key_id,
    new_id,
    utcnow,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

    from .core_models import WriteAuthorization

_LOGGER = logging.getLogger(__name__)

_T = TypeVar("_T")

__all__ = [
    "PROVIDER_ID",
    "ConfigManagerProvider",
    "error_for_class",
]

PROVIDER_ID: Final = "config_manager"
PROBE_SOURCE: Final = f"probe:{PROVIDER_ID}"

# Artifact formats (CompatibilityInfo.format and the JSON documents).
FORMAT_ARCHIVE: Final = "sysupgrade_tar_gz"
FORMAT_INVENTORY: Final = "inventory"
DOCUMENT_FORMAT_VERSION: Final = 1
CONTENT_TYPE_ARCHIVE: Final = "application/gzip"
CONTENT_TYPE_JSON: Final = "application/json"
# fetch_method of a version without archive: the live UCI read delivered it.
FETCH_METHOD_UCI: Final = "uci"
UCI_SOURCE_LIVE: Final = "live"
UCI_SOURCE_ARCHIVE: Final = "archive"

# CapabilityStatus / CapabilityUnavailableError reasons of this provider.
REASON_PHASE1: Final = "provider:phase1"
REASON_NO_ARCHIVE: Final = "provider:no_archive"

# VersionMeta warning codes (``<code>:<item>``, WARNING_CODE_PATTERN).
WARN_ARCHIVE_UNAVAILABLE: Final = "archive_unavailable"
WARN_ARCHIVE: Final = "archive_warning"
WARN_UCI_MISSING: Final = "uci_missing"
WARN_UCI_FAILED: Final = "uci_failed"
WARN_UCI_UNAVAILABLE: Final = "uci_unavailable"
WARN_UCI_SOURCE: Final = "uci_source"
WARN_UCI_ARCHIVE_MISMATCH: Final = "uci_archive_mismatch"

STEP_ARCHIVE_RESTORE: Final = "archive_restore"
STEP_REBOOT: Final = "reboot"

# Share of the job deadline kept back for the phases after archive, UCI and
# inventory: the archive gets 60 %, the UCI read the next 30 % at least.
_RESERVE_AFTER_ARCHIVE: Final = 0.40
_RESERVE_AFTER_UCI: Final = 0.10
_RESERVE_AFTER_INVENTORY: Final = 0.02
# The archive probes stop after this many bytes (too_large = path works).
_PROBE_MAX_BYTES: Final = 1
# Digest put into secret markers when digests are not comparable.
_NEUTRAL_DIGEST: Final = "-"

_ARCHIVE: Final = ArtifactKind.ARCHIVE.value
_UCI: Final = ArtifactKind.UCI.value
_INVENTORY: Final = ArtifactKind.INVENTORY.value

_REQUIRED_ARTIFACTS: Final[Mapping[BackupType, frozenset[str]]] = MappingProxyType(
    {
        BackupType.FULL_ARCHIVE: frozenset({_ARCHIVE}),
        BackupType.UCI_SNAPSHOT: frozenset({_UCI}),
        BackupType.PARTIAL: frozenset({_UCI}),
    }
)

_REQUIRED_PERMISSIONS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        Capability.CONFIG_CGI_BACKUP.value: ("cgi-io:backup",),
        Capability.CONFIG_SSH_ROOT.value: ("ssh:root",),
    }
)

_CHANGE_KINDS: Final[Mapping[str, ChangeKind]] = MappingProxyType(
    {
        "added": ChangeKind.ADDED,
        "removed": ChangeKind.REMOVED,
        "changed": ChangeKind.MODIFIED,
        "reordered": ChangeKind.REORDERED,
    }
)

_ERRORS: Final[Mapping[str, type[ConfigApiError]]] = MappingProxyType(
    {
        ERR_UNREACHABLE: RouterUnavailableError,
        ERR_TIMEOUT: OperationTimeoutError,
        ERR_AUTH: RouterAuthError,
        ERR_PERMISSION: RouterPermissionError,
        ERR_TOO_LARGE: ArtifactTooLargeError,
        ERR_INCOMPLETE: BackupIncompleteError,
        ERR_CHECKSUM_MISMATCH: BackupIntegrityError,
    }
)

_VALIDATION_RANK: Final = MappingProxyType(
    {
        ValidationStatus.VALID: 0,
        ValidationStatus.INVALID: 1,
        ValidationStatus.MISSING: 2,
        ValidationStatus.CORRUPT: 3,
    }
)
_VALIDATION_CLASS: Final = MappingProxyType(
    {
        ValidationStatus.INVALID: ERR_INVALID,
        ValidationStatus.MISSING: ErrorClass.NOT_FOUND.value,
        ValidationStatus.CORRUPT: ERR_CHECKSUM_MISMATCH,
    }
)

_INVENTORY_TEXT_FIELDS: Final = (
    "board_name",
    "model",
    "release_version",
    "release_revision",
    "target",
    "kernel",
    "package_manager",
    "package_source",
)

# ---------------------------------------------------------------------------
# Errors and logging
# ---------------------------------------------------------------------------


def error_for_class(
    error_class: str,
    *,
    router_id: str | None,
    operation: str,
    capability: str = Capability.CONFIG_BACKUP.value,
) -> ConfigApiError:
    """Return the Configuration API error for a collector error class.

    ``not_available`` names ``capability``; ``invalid`` and unknown classes
    become ``ProviderError``. The message holds the operation and the class
    only, never router data.
    """
    message = f"config {operation} failed: {error_class}"
    if error_class == ERR_NOT_AVAILABLE:
        return CapabilityUnavailableError(
            message,
            capability=capability,
            reason=CapabilityReason.NOT_DETECTED.value,
            router_id=router_id,
        )
    details = {"operation": operation}
    error_type = _ERRORS.get(error_class)
    if error_type is not None:
        return error_type(message, router_id=router_id, details=details)
    try:
        category = ErrorClass(error_class)
    except ValueError:
        category = ErrorClass.INTERNAL
    return ProviderError(
        message, router_id=router_id, error_class=category, details=details
    )


def _invalid(message: str, *, router_id: str | None, finding: str) -> ProviderError:
    return ProviderError(
        message,
        router_id=router_id,
        error_class=ErrorClass.INVALID,
        details={"finding": finding},
    )


def _log(
    operation: str,
    started: float,
    *,
    method: str | None = None,
    error_class: str | None = None,
    size: int | None = None,
) -> None:
    _LOGGER.debug(
        "config %s: method=%s error_class=%s duration=%.2fs size=%s",
        operation,
        method or "-",
        error_class or "-",
        time.monotonic() - started,
        "-" if size is None else size,
    )


class _Deadline:
    """What is left of one operation's deadline, split into phase budgets."""

    __slots__ = ("_end", "_loop", "total")

    def __init__(self, total: float) -> None:
        self._loop = asyncio.get_running_loop()
        self.total = total
        self._end = self._loop.time() + total

    def budget(self, reserve: float) -> float:
        """Seconds left minus ``reserve`` (share of the total) for later phases."""
        return max(0.0, self._end - self._loop.time() - reserve * self.total)


class _Warnings:
    """Ordered, de-duplicated warning codes, at most MAX_WARNINGS."""

    def __init__(self) -> None:
        self._codes: list[str] = []

    def add(self, code: str, item: str | None = None) -> None:
        text = code if item is None else f"{code}:{item}"
        if (
            text in self._codes
            or len(self._codes) >= MAX_WARNINGS
            or WARNING_CODE_PATTERN.fullmatch(text) is None
        ):
            return
        self._codes.append(text)

    def codes(self) -> tuple[str, ...]:
        return tuple(self._codes)


# ---------------------------------------------------------------------------
# Snapshot and artifact documents
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _ArchiveAnalysis:
    """Archive check plus the snapshot of its etc/config files (digested)."""

    report: ArchiveReport
    snapshot: UciSnapshot | None = field(repr=False)

    @property
    def ok(self) -> bool:
        return self.report.ok and self.snapshot is not None


def _analyse_archive(
    data: bytes, limits: ArchiveLimits, digest: Callable[[str], str]
) -> _ArchiveAnalysis:
    """Check the archive and normalize its UCI files (executor job).

    The plaintext UCI texts exist only inside this function.
    """
    report = validate_archive(data, limits)
    if not report.ok:
        return _ArchiveAnalysis(report, None)
    try:
        texts = extract_uci_texts(data, limits)
    except ArchiveError:
        return _ArchiveAnalysis(report, None)
    raw = {
        name: parse_uci_file(text)
        for name, text in texts.items()
        if name in UCI_CONFIGS
    }
    return _ArchiveAnalysis(report, build_snapshot(raw, digest))


def _snapshot_hash(configs: Mapping[str, Any]) -> str:
    """Same hash as ``UciSnapshot.content_hash`` (config_snapshot)."""
    data = canonical_json(configs).encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(data).hexdigest()


def _plain(value: Any) -> Any:
    """JSON-safe copy of a (possibly frozen) structure."""
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    return value


def _json_bytes(doc: Mapping[str, Any]) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _payload(data: bytes, content_type: str) -> ArtifactPayload:
    return ArtifactPayload(
        data=data, sha256=hashlib.sha256(data).hexdigest(), content_type=content_type
    )


def _uci_document(snapshot: UciSnapshot, key_id: str, source: str) -> bytes:
    return _json_bytes(
        {
            "format": SNAPSHOT_FORMAT_UCI_NORMALIZED,
            "format_version": DOCUMENT_FORMAT_VERSION,
            "uci_hash": snapshot.content_hash,
            "installation_key_id": key_id,
            "configs": _plain(snapshot.configs),
            "missing": sorted(snapshot.missing),
            "source": source,
        }
    )


def _configs_ok(configs: Any) -> bool:
    """True for ``{config: {"sections": {...}, "order": [...]}}``."""
    if not isinstance(configs, Mapping):
        return False
    for name, config in configs.items():
        if not isinstance(name, str) or not isinstance(config, Mapping):
            return False
        sections = config.get(NORM_SECTIONS)
        if not isinstance(sections, Mapping) or not isinstance(
            config.get(NORM_ORDER), list | tuple
        ):
            return False
        if not all(isinstance(section, Mapping) for section in sections.values()):
            return False
    return True


def _load_json(data: bytes) -> Any:
    """Parsed JSON or None."""
    try:
        return json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        return None


def _uci_findings(doc: Any, expected_hash: str | None) -> list[str]:
    """Finding codes of a ``uci`` artifact document (empty = fine)."""
    if doc is None:
        return ["not_json"]
    if not isinstance(doc, Mapping):
        return ["not_object"]
    codes: list[str] = []
    if (
        doc.get("format") != SNAPSHOT_FORMAT_UCI_NORMALIZED
        or doc.get("format_version") != DOCUMENT_FORMAT_VERSION
    ):
        codes.append("unsupported_format")
    configs = doc.get("configs")
    if not _configs_ok(configs):
        codes.append("bad_configs")
        return codes
    actual = _snapshot_hash(configs)
    if doc.get("uci_hash") != actual:
        codes.append("uci_hash_mismatch")
    if expected_hash is not None and expected_hash != actual:
        codes.append("record_hash_mismatch")
    key_id = doc.get("installation_key_id")
    if key_id is not None and not isinstance(key_id, str):
        codes.append("bad_key_id")
    return codes


def _parse_uci_document(
    data: bytes, record: BackupRecord
) -> tuple[UciSnapshot, str | None]:
    """Snapshot and installation key id of a stored ``uci`` artifact."""
    doc = _load_json(data)
    codes = _uci_findings(doc, record.uci_hash)
    if codes:
        raise _invalid(
            "uci artifact of the version is not usable",
            router_id=record.router_id,
            finding=codes[0],
        )
    configs = _plain(doc["configs"])
    missing = doc.get("missing")
    snapshot = UciSnapshot(
        configs=configs,
        content_hash=_snapshot_hash(configs),
        missing=frozenset(name for name in (missing or ()) if isinstance(name, str)),
    )
    return snapshot, doc.get("installation_key_id") or record.installation_key_id


def _str(value: Any) -> str | None:
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _inventory_document(inventory: Inventory) -> bytes:
    return _json_bytes(
        {
            "format": FORMAT_INVENTORY,
            "format_version": DOCUMENT_FORMAT_VERSION,
            "board_name": inventory.board_name,
            "model": inventory.model,
            "release_version": inventory.release_version,
            "release_revision": inventory.release_revision,
            "target": inventory.target,
            "kernel": inventory.kernel,
            "package_manager": inventory.package_manager,
            "packages": (
                None if inventory.packages is None else dict(inventory.packages)
            ),
            "package_source": inventory.package_source,
            "free_bytes": inventory.free_bytes,
            "archive_members": list(inventory.archive_members),
            "partial": inventory.partial,
        }
    )


def _inventory_from_document(data: bytes) -> Inventory | None:
    """Inventory of a stored ``inventory`` artifact, None if malformed."""
    doc = _load_json(data)
    if not isinstance(doc, Mapping) or doc.get("format") != FORMAT_INVENTORY:
        return None
    texts = {name: doc.get(name) for name in _INVENTORY_TEXT_FIELDS}
    if any(
        value is not None and not isinstance(value, str) for value in texts.values()
    ):
        return None
    packages = doc.get("packages")
    if packages is not None and (
        not isinstance(packages, Mapping)
        or not all(
            isinstance(name, str) and (version is None or isinstance(version, str))
            for name, version in packages.items()
        )
    ):
        return None
    free = doc.get("free_bytes")
    if free is not None and (not isinstance(free, int) or isinstance(free, bool)):
        return None
    members = doc.get("archive_members", [])
    if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
        return None
    partial = doc.get("partial", False)
    if not isinstance(partial, bool):
        return None
    return Inventory(
        **texts,
        packages=packages,
        free_bytes=free,
        archive_members=tuple(members),
        partial=partial,
    )


def _inventory_from_info(info: Mapping[str, Any]) -> Inventory:
    """Board and release from ``router_info`` only (no package list)."""
    release = info.get("release")
    release = release if isinstance(release, Mapping) else {}
    return Inventory(
        board_name=_str(info.get("board_name")),
        model=_str(info.get("model")),
        release_version=_str(release.get("version")),
        release_revision=_str(release.get("revision")),
        target=_str(release.get("target")),
        kernel=_str(info.get("kernel")),
        partial=True,
    )


def _info_from_record(record: RouterRecord) -> dict[str, Any]:
    """``router_info`` shape from a registry record (coordinator has none)."""
    identity, firmware = record.identity, record.firmware
    return {
        "model": identity.model,
        "board_name": identity.board_name or firmware.board_name,
        "kernel": firmware.kernel,
        "release": {
            "version": firmware.version or identity.openwrt_version,
            "revision": firmware.revision or identity.openwrt_revision,
            "target": firmware.target,
        },
    }


# ---------------------------------------------------------------------------
# Diff mapping
# ---------------------------------------------------------------------------


def _core_change(change: Change, *, secrets_comparable: bool) -> ConfigChange:
    """Engine change -> core ConfigChange (secret values stay digest markers)."""
    kind = _CHANGE_KINDS[change.kind]
    if not secrets_comparable and change.detail == DETAIL_SECRET_CHANGED:
        kind = ChangeKind.NOT_COMPARABLE
    return ConfigChange(
        kind=kind,
        config=change.config,
        section=change.section,
        option=change.option,
        section_type=change.section_type or None,
        before=change.old,
        after=change.new,
        area=str(change.area),
        risk=str(change.risk),
    )


def _core_changes(
    changes: Iterable[Change],
    skipped_configs: Iterable[str],
    *,
    secrets_comparable: bool,
) -> tuple[ConfigChange, ...]:
    """Mapped changes plus one NOT_COMPARABLE entry per one-sided config."""
    mapped = [
        _core_change(change, secrets_comparable=secrets_comparable)
        for change in changes
    ]
    mapped.extend(
        ConfigChange(kind=ChangeKind.NOT_COMPARABLE, config=config, section="")
        for config in skipped_configs
    )
    return tuple(mapped)


def _neutral(value: Any) -> Any:
    if isinstance(value, Mapping):
        if len(value) == 1 and isinstance(value.get(SECRET_MARKER_KEY), str):
            return {SECRET_MARKER_KEY: _NEUTRAL_DIGEST}
        return {key: _neutral(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_neutral(item) for item in value]
    return value


def _neutralised(snapshot: UciSnapshot) -> UciSnapshot:
    """The snapshot with every secret digest replaced by the same value."""
    configs = _neutral(snapshot.configs)
    return UciSnapshot(
        configs=configs, content_hash=_snapshot_hash(configs), missing=snapshot.missing
    )


def _finding_message(finding: Finding) -> str:
    params = ", ".join(
        f"{key}={value}" for key, value in sorted(finding.params.items())
    )
    return redact_text(f"{finding.code}: {params}" if params else finding.code)


def _restore_steps(archive_sha256: str) -> tuple[RestoreStep, ...]:
    return (
        RestoreStep(
            order=1,
            action=STEP_ARCHIVE_RESTORE,
            target=FORMAT_ARCHIVE,
            description=(
                "Upload the archive in LuCI or run sysupgrade -r by hand; "
                "not reversible"
            ),
            detail=mask_for_output(
                {"archive_sha256": archive_sha256, "manual": True, "reversible": False}
            ),
        ),
        RestoreStep(
            order=2,
            action=STEP_REBOOT,
            target="system",
            description="The router reboots to apply the archive",
        ),
    )


# ---------------------------------------------------------------------------
# Collect helpers
# ---------------------------------------------------------------------------


def _archive_order(request: CollectRequest) -> tuple[str, ...]:
    """Archive methods to try, preferred first; () = UCI snapshot only."""
    method = request.fetch_method
    if request.backup_type is BackupType.UCI_SNAPSHOT or method == FETCH_METHOD_UCI:
        return ()
    if method is None:
        return tuple(FETCH_METHODS)
    if method in FETCH_METHODS:
        return (method, *(m for m in FETCH_METHODS if m != method))
    raise _invalid(
        "unknown backup fetch method",
        router_id=request.router_id,
        finding="unknown_fetch_method",
    )


def _archive_failure(fetch: ArchiveFetch) -> tuple[str, bool]:
    """(error class, skipped) of a chain that delivered no archive.

    ``skipped`` is True when every method said permission/not_available:
    the router cannot deliver an archive at all (not a failure).
    """
    real = [
        attempt.error_class
        for attempt in fetch.attempts
        if attempt.error_class is not None
        and attempt.error_class not in CHAIN_SKIP_ERRORS
    ]
    if real:
        return real[0], False
    return fetch.error_class or ERR_NOT_AVAILABLE, True


def _uci_failure(uci: UciCollection) -> str:
    """Error class of a UCI read that gave no config at all."""
    if uci.error_class is not None:
        return uci.error_class
    for _name, error_class in uci.failed:
        if error_class != ERR_NOT_AVAILABLE:
            return error_class
    return ERR_NOT_AVAILABLE


def _uci_gap(uci: UciCollection | None, uci_stop: str | None) -> str | None:
    """Error class when the live read left out configs that may exist.

    None when every config was read or reported not_available (absent on
    the router). An abort (unreachable/timeout/auth) gives its own class,
    single unreadable configs give ``incomplete``.
    """
    if uci_stop is not None:
        return uci_stop
    if uci is None:
        return ERR_INCOMPLETE
    if uci.not_tried or any(
        error_class != ERR_NOT_AVAILABLE for _name, error_class in uci.failed
    ):
        return ERR_INCOMPLETE
    return None


def _filled_from_archive(
    live: UciSnapshot, archived: UciSnapshot, warnings: _Warnings
) -> UciSnapshot:
    """``live`` plus the configs only the archive holds (review H3).

    The archive was taken in the same run, so it stands in for configs the
    live read could not deliver; each one gets ``uci_source:<config>``.
    """
    filled = sorted(set(archived.configs) - set(live.configs))
    if not filled:
        return live
    configs = dict(live.configs)
    for name in filled:
        configs[name] = archived.configs[name]
        warnings.add(WARN_UCI_SOURCE, name)
    return UciSnapshot(
        configs=configs,
        content_hash=_snapshot_hash(configs),
        missing=live.missing - set(filled),
    )


def _collect_failure(
    uci: UciCollection | None,
    uci_stop: str | None,
    archive_class: str | None,
    archive_skipped: bool,
) -> str:
    """Error class when neither archive nor UCI delivered anything."""
    if uci_stop is not None:
        return uci_stop
    if archive_class is not None and not archive_skipped:
        return archive_class
    if uci is not None:
        for _name, error_class in uci.failed:
            if error_class != ERR_NOT_AVAILABLE:
                return error_class
    return archive_class or ERR_NOT_AVAILABLE


# ---------------------------------------------------------------------------
# Probe helpers
# ---------------------------------------------------------------------------


def _probe_status(
    capability: str,
    error_class: str | None,
    now: Any,
    *,
    detail: Mapping[str, Any] | None = None,
) -> CapabilityStatus:
    required: tuple[str, ...] = ()
    if error_class is None:
        state, reason = CapabilityState.AVAILABLE, CapabilityReason.OK.value
    elif error_class == ERR_PERMISSION:
        state, reason = (
            CapabilityState.UNAVAILABLE,
            CapabilityReason.PERMISSION_DENIED.value,
        )
        required = _REQUIRED_PERMISSIONS.get(capability, ())
    elif error_class == ERR_NOT_AVAILABLE:
        state, reason = CapabilityState.UNAVAILABLE, CapabilityReason.NOT_DETECTED.value
    elif error_class in (ERR_UNREACHABLE, ERR_TIMEOUT):
        state, reason = CapabilityState.UNKNOWN, CapabilityReason.ROUTER_OFFLINE.value
    else:
        state, reason = CapabilityState.UNKNOWN, f"provider:{error_class}"
    return CapabilityStatus(
        capability=capability,
        state=state,
        reason=reason,
        source=PROBE_SOURCE,
        detected_at=now,
        required_permissions=required,
        detail=detail or {},
    )


def _as(capability: str, status: CapabilityStatus) -> CapabilityStatus:
    return replace(status, capability=capability, detail={})


def _any_of(capability: str, parts: Sequence[CapabilityStatus]) -> CapabilityStatus:
    """Available if one part is; else the first unknown, else the first."""
    for wanted in (CapabilityState.AVAILABLE, CapabilityState.UNKNOWN):
        for part in parts:
            if part.state is wanted:
                return _as(capability, part)
    return _as(capability, parts[0])


def _all_of(capability: str, parts: Sequence[CapabilityStatus]) -> CapabilityStatus:
    """Available if all parts are; else the first unavailable, else unknown."""
    for wanted in (CapabilityState.UNAVAILABLE, CapabilityState.UNKNOWN):
        for part in parts:
            if part.state is wanted:
                return _as(capability, part)
    return _as(capability, parts[0])


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class ConfigManagerProvider:
    """``ConfigBackupProvider`` of the configuration manager (phase 1).

    ``hass`` is only used to run CPU-bound archive checks in its executor
    (without it: the loop's default executor). ``timeouts`` overrides
    entries of ``FETCH_TIMEOUTS`` (seconds); ``job`` is the deadline of one
    whole operation.
    """

    def __init__(
        self,
        hass: HomeAssistant | None = None,
        *,
        timeouts: Mapping[str, float] | None = None,
        limits: ArchiveLimits = DEFAULT_ARCHIVE_LIMITS,
    ) -> None:
        """Keep the executor owner, timeouts and archive limits; no state."""
        merged = {**FETCH_TIMEOUTS, **(timeouts or {})}
        for name, value in merged.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, int | float)
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"timeout {name!r} must be a positive number")
        self._hass = hass
        self._timeouts: Mapping[str, float] = MappingProxyType(
            {name: float(value) for name, value in merged.items()}
        )
        self._limits = limits

    @property
    def provider_id(self) -> str:
        """Stable id, e.g. ``config_manager``."""
        return PROVIDER_ID

    @property
    def provider_api_version(self) -> int:
        """Version of this protocol (in SUPPORTED_PROVIDER_API_VERSIONS)."""
        return PROVIDER_API_VERSION

    def supported(self, router: RouterRecord) -> bool:
        """Cheap, synchronous pre-check (no router call)."""
        return router.state is RecordState.ACTIVE

    # -- shared helpers ----------------------------------------------------

    async def _run_job(self, func: Callable[..., _T], *args: Any) -> _T:
        if self._hass is not None:
            return await self._hass.async_add_executor_job(func, *args)
        return await asyncio.get_running_loop().run_in_executor(None, func, *args)

    def _capped(self, budget: float, *names: str) -> dict[str, float]:
        timeouts = dict(self._timeouts)
        for name in names:
            timeouts[name] = min(timeouts[name], budget)
        return timeouts

    async def _bounded(
        self, operation: str, router_id: str, started: float, work: Awaitable[_T]
    ) -> _T:
        """Await ``work`` within the job deadline; a miss is a clean timeout."""
        try:
            async with asyncio.timeout(self._timeouts[FETCH_JOB]):
                return await work
        except TimeoutError as err:
            _log(operation, started, error_class=ERR_TIMEOUT)
            raise OperationTimeoutError(
                f"config {operation} exceeded its deadline",
                router_id=router_id,
                details={"operation": operation},
            ) from err
        except ConfigApiError as err:
            _log(operation, started, error_class=err.error_class.value)
            raise

    def _router_info(
        self, conn: RouterConnection, ctx: ProviderContext
    ) -> Mapping[str, Any]:
        info = conn.coordinator.router_info
        if isinstance(info, Mapping) and info:
            return info
        record = ctx.registry.find(conn.router_id)
        return _info_from_record(record) if record is not None else {}

    async def _live_uci(
        self,
        conn: RouterConnection,
        digest: Callable[[str], str],
        operation: str,
        configs: Sequence[str] = UCI_CONFIGS,
    ) -> UciCollection:
        uci = await collect_uci_snapshot(
            conn.api, configs, digest, timeouts=self._timeouts
        )
        if not uci.snapshot.configs:
            raise error_for_class(
                _uci_failure(uci),
                router_id=conn.router_id,
                operation=operation,
                capability=Capability.CONFIG_UCI_READ.value,
            )
        return uci

    async def _record_snapshot(
        self, record: BackupRecord, ctx: ProviderContext
    ) -> tuple[UciSnapshot, str | None]:
        """Snapshot of a stored version: its ``uci`` artifact, else the archive."""
        if _UCI in record.artifacts:
            return _parse_uci_document(await ctx.read(record.backup_id, _UCI), record)
        if _ARCHIVE in record.artifacts:
            key = await ctx.async_get_installation_key()
            analysis = await self._run_job(
                _analyse_archive,
                await ctx.read(record.backup_id, _ARCHIVE),
                self._limits,
                secret_digest_factory(key),
            )
            if analysis.snapshot is None:
                raise _invalid(
                    "archive of the version is not usable",
                    router_id=record.router_id,
                    finding=analysis.report.error or ERR_INVALID,
                )
            return analysis.snapshot, installation_key_id(key)
        raise BackupIncompleteError(
            "version holds no configuration artifact",
            router_id=record.router_id,
            details={"backup_id": record.backup_id},
        )

    async def _source(
        self, source: ConfigSource, ctx: ProviderContext
    ) -> tuple[UciSnapshot, str | None, ConfigRef]:
        if isinstance(source, ConfigSnapshot):
            if (
                source.format != SNAPSHOT_FORMAT_UCI_NORMALIZED
                or source.format_version != DOCUMENT_FORMAT_VERSION
            ):
                raise _invalid(
                    "unsupported snapshot format",
                    router_id=source.router_id,
                    finding="unsupported_format",
                )
            configs = _plain(source.configs)
            if not _configs_ok(configs):
                raise _invalid(
                    "snapshot configs are malformed",
                    router_id=source.router_id,
                    finding="bad_configs",
                )
            snapshot = UciSnapshot(
                configs=configs,
                content_hash=_snapshot_hash(configs),
                missing=frozenset(),
            )
            return (
                snapshot,
                source.installation_key_id,
                ConfigRef.live(source.router_id),
            )
        if isinstance(source, BackupRecord):
            snapshot, key_id = await self._record_snapshot(source, ctx)
            return snapshot, key_id, ConfigRef.backup(source.backup_id)
        raise TypeError("source must be a BackupRecord or a ConfigSnapshot")

    async def _source_inventory(
        self, record: BackupRecord, ctx: ProviderContext
    ) -> Inventory:
        if _INVENTORY in record.artifacts:
            inventory = _inventory_from_document(
                await ctx.read(record.backup_id, _INVENTORY)
            )
            if inventory is not None:
                return inventory
        compat = record.compatibility
        return Inventory(
            board_name=record.board_name or (compat.board_name if compat else None),
            model=record.hardware_model or (compat.model if compat else None),
            release_version=record.openwrt_version
            or (compat.openwrt_version if compat else None),
            target=compat.target if compat else None,
            package_manager=compat.package_manager if compat else None,
            partial=True,
        )

    # -- probe -------------------------------------------------------------

    async def async_probe(
        self, conn: RouterConnection, ctx: ProviderContext
    ) -> Mapping[str, CapabilityStatus]:
        """Probe config.* capabilities on the router (setup, ACL redeploy,
        firmware change; never in the poll)."""
        started = time.monotonic()
        statuses = await self._bounded(
            "probe", conn.router_id, started, self._probe(conn)
        )
        _log("probe", started)
        return statuses

    async def _probe_archive(
        self, fetch: Callable[..., Awaitable[bytes]], timeout: float
    ) -> str | None:
        """Error class of one archive path; stops after _PROBE_MAX_BYTES."""
        try:
            await fetch(max_bytes=_PROBE_MAX_BYTES, timeout=timeout)
        except Exception as err:
            if isinstance(err, PROGRAMMING_ERRORS):
                raise
            error_class = classify_error(err)
            return None if error_class == ERR_TOO_LARGE else error_class
        return None

    async def _probe(self, conn: RouterConnection) -> dict[str, CapabilityStatus]:
        api = conn.api
        fetch = await collect_uci(api, UCI_CONFIGS, timeouts=self._timeouts)
        readable = {
            name: fetch.raw.get(name) is not None
            for name in fetch.configs
            if name not in fetch.not_tried
        }
        failed = [error_class for _name, error_class in fetch.failed]
        stop = fetch.error_class
        del fetch  # raw values hold plaintext secrets

        uci_class: str | None
        if any(readable.values()):
            uci_class = None
        elif stop is not None:
            uci_class = stop
        else:
            uci_class = next(
                (cls for cls in failed if cls != ERR_NOT_AVAILABLE), ERR_NOT_AVAILABLE
            )

        cgi_class: str | None
        ssh_class: str | None
        pkg_class: str | None
        if uci_class in (ERR_UNREACHABLE, ERR_TIMEOUT):
            # Dead router: no archive probe that would only wait again.
            cgi_class = ssh_class = pkg_class = uci_class
        else:
            cgi_class = await self._probe_archive(
                api.config_fetch_backup_cgi, self._timeouts[FETCH_METHOD_CGI]
            )
            ssh_class = await self._probe_archive(
                api.config_fetch_backup_ssh, self._timeouts[FETCH_METHOD_SSH]
            )
            try:
                async with asyncio.timeout(self._timeouts[FETCH_PACKAGELIST]):
                    packages = await api.config_packagelist()
            except Exception as err:
                if isinstance(err, PROGRAMMING_ERRORS):
                    raise
                pkg_class = classify_error(err)
            else:
                has_packages = isinstance(packages, Mapping) and bool(packages)
                pkg_class = None if has_packages else ERR_NOT_AVAILABLE

        now = utcnow()
        uci = _probe_status(
            Capability.CONFIG_UCI_READ.value, uci_class, now, detail=readable
        )
        cgi = _probe_status(Capability.CONFIG_CGI_BACKUP.value, cgi_class, now)
        ssh = _probe_status(Capability.CONFIG_SSH_ROOT.value, ssh_class, now)
        pkg = _probe_status(Capability.CONFIG_PACKAGELIST.value, pkg_class, now)
        backup = _any_of(Capability.CONFIG_BACKUP.value, (uci, cgi, ssh))
        archive = _any_of(Capability.CONFIG_BACKUP.value, (cgi, ssh))
        statuses = (
            uci,
            cgi,
            ssh,
            pkg,
            backup,
            _as(Capability.CONFIG_CAPTURE.value, uci),
            _as(Capability.CONFIG_DRIFT.value, uci),
            # Export reads stored versions in the core; it needs versions.
            _as(Capability.CONFIG_EXPORT.value, backup),
            _all_of(Capability.CONFIG_RESTORE_DRY_RUN.value, (uci, archive)),
            # Validate and diff work on stored data, no router needed.
            _probe_status(Capability.CONFIG_VALIDATE.value, None, now),
            _probe_status(Capability.CONFIG_DIFF.value, None, now),
            CapabilityStatus(
                capability=Capability.CONFIG_RESTORE.value,
                state=CapabilityState.UNAVAILABLE,
                reason=REASON_PHASE1,
                source=PROBE_SOURCE,
                detected_at=now,
            ),
        )
        _LOGGER.debug(
            "config probe: uci=%s cgi=%s ssh=%s packagelist=%s",
            uci_class or "ok",
            cgi_class or "ok",
            ssh_class or "ok",
            pkg_class or "ok",
        )
        return {status.capability: status for status in statuses}

    # -- capture -----------------------------------------------------------

    async def async_capture(
        self, conn: RouterConnection, request: CaptureRequest, ctx: ProviderContext
    ) -> ConfigSnapshot:
        """Read the live configuration (uci_hash made by the provider)."""
        started = time.monotonic()
        key = await ctx.async_get_installation_key()
        configs = tuple(request.configs) if request.configs else UCI_CONFIGS
        uci = await self._bounded(
            "capture",
            conn.router_id,
            started,
            self._live_uci(conn, secret_digest_factory(key), "capture", configs),
        )
        info = self._router_info(conn, ctx)
        release = info.get("release")
        release = release if isinstance(release, Mapping) else {}
        snapshot = ConfigSnapshot(
            router_id=conn.router_id,
            captured_at=utcnow(),
            configs=_plain(uci.snapshot.configs),
            openwrt_version=_str(release.get("version")),
            board_name=_str(info.get("board_name")),
            uci_hash=uci.snapshot.content_hash,
            installation_key_id=installation_key_id(key),
        )
        _log("capture", started, method=FETCH_METHOD_UCI)
        return snapshot

    # -- collect -----------------------------------------------------------

    async def async_collect(
        self, conn: RouterConnection, request: CollectRequest, ctx: ProviderContext
    ) -> CollectedVersion:
        """Fetch a version (archive, uci, inventory) from the router."""
        started = time.monotonic()
        order = _archive_order(request)
        key = await ctx.async_get_installation_key()
        version = await self._bounded(
            "collect",
            conn.router_id,
            started,
            self._collect(conn, request, ctx, key, order),
        )
        meta = version.meta
        _log(
            "collect",
            started,
            method=meta.fetch_method,
            error_class=None if meta.error_class is None else meta.error_class.value,
            size=sum(payload.size_bytes for payload in version.artifacts.values()),
        )
        return version

    async def _collect(
        self,
        conn: RouterConnection,
        request: CollectRequest,
        ctx: ProviderContext,
        key: bytes,
        order: tuple[str, ...],
    ) -> CollectedVersion:
        deadline = _Deadline(self._timeouts[FETCH_JOB])
        api = conn.api
        digest = secret_digest_factory(key)
        key_id = installation_key_id(key)

        # 1. Archive along the chain; the check runs in the executor.
        fetch: ArchiveFetch | None = None
        analysis: _ArchiveAnalysis | None = None
        archive_class: str | None = None
        archive_skipped = not order
        if order:
            budget = deadline.budget(_RESERVE_AFTER_ARCHIVE)
            if budget > 0:
                try:
                    async with asyncio.timeout(budget):
                        fetch = await collect_archive(
                            api,
                            order=order,
                            is_root=True,  # api.py refuses non-root SSH itself
                            limits=self._limits,
                            timeouts=self._capped(
                                budget, FETCH_METHOD_CGI, FETCH_METHOD_SSH
                            ),
                        )
                except TimeoutError:
                    archive_class = ERR_TIMEOUT
            else:
                archive_class = ERR_TIMEOUT
            if fetch is not None and fetch.data is not None:
                analysis = await self._run_job(
                    _analyse_archive, fetch.data, self._limits, digest
                )
                if not analysis.ok:
                    archive_class = analysis.report.error or ERR_INVALID
            elif fetch is not None:
                archive_class, archive_skipped = _archive_failure(fetch)
        archive_ok = analysis is not None and analysis.ok

        # 2. Live UCI configs (normalized and digested right away).
        uci: UciCollection | None = None
        uci_stop: str | None = None
        budget = deadline.budget(_RESERVE_AFTER_UCI)
        if budget > 0:
            try:
                async with asyncio.timeout(budget):
                    uci = await collect_uci_snapshot(
                        api,
                        UCI_CONFIGS,
                        digest,
                        timeouts=self._capped(budget, FETCH_UCI),
                    )
            except TimeoutError:
                uci_stop = ERR_TIMEOUT
        else:
            uci_stop = ERR_TIMEOUT
        if uci is not None and uci.error_class is not None:
            uci_stop = uci.error_class
        live = uci.snapshot if uci is not None and uci.snapshot.configs else None

        if not archive_ok and live is None:
            raise error_for_class(
                _collect_failure(uci, uci_stop, archive_class, archive_skipped),
                router_id=conn.router_id,
                operation="collect",
            )

        # 3. Inventory: router_info plus the package list.
        info = self._router_info(conn, ctx)
        budget = deadline.budget(_RESERVE_AFTER_INVENTORY)
        if budget > 0:
            inventory = await collect_inventory(
                api, info, timeouts=self._capped(budget, FETCH_PACKAGELIST)
            )
        else:
            inventory = _inventory_from_info(info)

        # 4. Outcome, warnings, artifacts.
        warnings = _Warnings()
        if uci is not None:
            for name, error_class in uci.failed:
                missing = error_class == ERR_NOT_AVAILABLE
                warnings.add(WARN_UCI_MISSING if missing else WARN_UCI_FAILED, name)
            for name in uci.not_tried:
                warnings.add(WARN_UCI_FAILED, name)
        elif uci_stop is not None:
            warnings.add(WARN_UCI_UNAVAILABLE, uci_stop)

        report: ArchiveReport | None = None
        error_class_out: ErrorClass | None = None
        if archive_ok and analysis is not None and analysis.snapshot is not None:
            report = with_uci_cross_check(
                analysis.report, live.configs if live is not None else ()
            )
            for finding in report.warnings:
                path = finding.path or ""
                if finding.code == WARN_CONFIG_MISSING_IN_ARCHIVE and path.startswith(
                    ARCHIVE_CONFIG_PREFIX
                ):
                    warnings.add(finding.code, path[len(ARCHIVE_CONFIG_PREFIX) :])
                else:
                    warnings.add(WARN_ARCHIVE, finding.code)
            if live is not None:
                uci_snapshot = _filled_from_archive(live, analysis.snapshot, warnings)
                source = UCI_SOURCE_LIVE
                for name in sorted(set(live.configs) & set(analysis.snapshot.configs)):
                    if live.configs[name] != analysis.snapshot.configs[name]:
                        warnings.add(WARN_UCI_ARCHIVE_MISMATCH, name)
            else:
                uci_snapshot, source = analysis.snapshot, UCI_SOURCE_ARCHIVE
                warnings.add(WARN_UCI_SOURCE, UCI_SOURCE_ARCHIVE)
            backup_type, status = BackupType.FULL_ARCHIVE, VersionStatus.OK
            fetch_method = fetch.method if fetch is not None else None
            inventory = replace(
                inventory, archive_members=tuple(m.name for m in report.members)
            )
        else:
            assert live is not None
            uci_snapshot, source = live, UCI_SOURCE_LIVE
            fetch_method = FETCH_METHOD_UCI
            uci_gap = _uci_gap(uci, uci_stop)
            if archive_skipped and uci_gap is not None:
                # Configs that exist could not be read: never a baseline
                # (review H2). not_available alone (config absent) is fine.
                backup_type, status = BackupType.PARTIAL, VersionStatus.PARTIAL
                error_class_out = ErrorClass(uci_gap)
                if order:
                    warnings.add(WARN_ARCHIVE_UNAVAILABLE, archive_class)
            elif archive_skipped:
                # The router cannot deliver an archive: a UCI snapshot is the
                # complete result (usable as baseline), not a partial one.
                backup_type, status = BackupType.UCI_SNAPSHOT, VersionStatus.OK
                if order:
                    warnings.add(WARN_ARCHIVE_UNAVAILABLE, archive_class)
            else:
                backup_type, status = BackupType.PARTIAL, VersionStatus.PARTIAL
                error_class_out = ErrorClass(archive_class or ERR_INCOMPLETE)

        artifacts: dict[str, ArtifactPayload] = {}
        if report is not None and fetch is not None and fetch.data is not None:
            artifacts[_ARCHIVE] = _payload(fetch.data, CONTENT_TYPE_ARCHIVE)
        artifacts[_UCI] = _payload(
            _uci_document(uci_snapshot, key_id, source), CONTENT_TYPE_JSON
        )
        artifacts[_INVENTORY] = _payload(
            _inventory_document(inventory), CONTENT_TYPE_JSON
        )

        record = ctx.registry.find(conn.router_id)
        architecture = (
            record.identity.architecture or record.firmware.architecture
            if record is not None
            else None
        )
        meta = VersionMeta(
            backup_type=backup_type,
            reason=request.reason,
            status=status,
            error_class=error_class_out,
            fetch_method=fetch_method,
            content_hash=None if report is None else report.content_hash,
            uci_hash=uci_snapshot.content_hash,
            openwrt_version=inventory.release_version,
            hardware_model=inventory.model,
            board_name=inventory.board_name,
            compatibility=CompatibilityInfo(
                format=FORMAT_ARCHIVE
                if report is not None
                else SNAPSHOT_FORMAT_UCI_NORMALIZED,
                format_version=DOCUMENT_FORMAT_VERSION,
                openwrt_version=inventory.release_version,
                target=inventory.target,
                board_name=inventory.board_name,
                model=inventory.model,
                architecture=architecture,
                package_manager=inventory.effective_package_manager,
            ),
            # Digest markers are no secrets; only the archive holds plaintext.
            contains_secrets=report is not None,
            note=request.note,
            links=request.links,
            correlation_id=request.correlation_id or ctx.correlation_id,
            warnings=warnings.codes(),
            installation_key_id=key_id,
        )
        return CollectedVersion(artifacts=artifacts, meta=meta)

    # -- validate ----------------------------------------------------------

    async def async_validate(
        self, record: BackupRecord, ctx: ProviderContext
    ) -> ValidationInfo:
        """Check a stored version beyond checksums (format, members)."""
        started = time.monotonic()
        findings: list[tuple[ValidationStatus, str, str]] = []
        required = _REQUIRED_ARTIFACTS.get(record.backup_type, frozenset())
        for kind in sorted(required - set(record.artifacts)):
            findings.append((ValidationStatus.INVALID, kind, "absent"))
        for kind, ref in sorted(record.artifacts.items()):
            try:
                data = await ctx.read(record.backup_id, kind)
            except BackupIntegrityError:
                findings.append((ValidationStatus.CORRUPT, kind, ERR_CHECKSUM_MISMATCH))
                continue
            except BackupNotFoundError:
                findings.append((ValidationStatus.MISSING, kind, "not_found"))
                continue
            if len(data) != ref.size_bytes:
                findings.append((ValidationStatus.CORRUPT, kind, "size_mismatch"))
                continue
            if not verify_checksum(data, ref.sha256):
                findings.append((ValidationStatus.CORRUPT, kind, ERR_CHECKSUM_MISMATCH))
                continue
            findings.extend(
                (ValidationStatus.INVALID, kind, code)
                for code in await self._structure_findings(kind, data, record)
            )
        status = max(
            (finding[0] for finding in findings),
            key=_VALIDATION_RANK.__getitem__,
            default=ValidationStatus.VALID,
        )
        details: str | None = None
        error_class: str | None = None
        if status is not ValidationStatus.VALID:
            error_class = _VALIDATION_CLASS[status]
            codes = ",".join(f"{kind}.{code}" for _status, kind, code in findings)
            details = f"{error_class} {codes}"
        _log("validate", started, error_class=error_class, size=record.size_bytes)
        return ValidationInfo(status=status, checked_at=utcnow(), details=details)

    async def _structure_findings(
        self, kind: str, data: bytes, record: BackupRecord
    ) -> list[str]:
        if kind == _ARCHIVE:
            report = await self._run_job(validate_archive, data, self._limits)
            if not report.ok:
                codes = [report.error or ERR_INVALID]
                codes.extend(f.code for f in report.findings if f.code not in codes)
                return codes
            if record.content_hash is not None and (
                report.content_hash != record.content_hash
            ):
                return ["content_hash_mismatch"]
            return []
        if kind == _UCI:
            return _uci_findings(_load_json(data), record.uci_hash)
        if kind == _INVENTORY:
            return [] if _inventory_from_document(data) is not None else ["malformed"]
        return []

    # -- compare -----------------------------------------------------------

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
        started = time.monotonic()
        base_snapshot, base_key, base_ref = await self._source(base, ctx)
        other_snapshot, other_key, other_ref = await self._source(other, ctx)
        mgmt_host = other_router.connection.host or base_router.connection.host
        changes = diff_snapshots(base_snapshot, other_snapshot, mgmt_host=mgmt_host)
        diff = ConfigDiff(
            base=base_ref,
            other=other_ref,
            compared_at=utcnow(),
            changes=_core_changes(
                changes,
                not_comparable(base_snapshot, other_snapshot),
                secrets_comparable=base_key is not None and base_key == other_key,
            ),
        )
        _log("compare", started)
        return diff

    # -- drift -------------------------------------------------------------

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
        started = time.monotonic()
        key = await ctx.async_get_installation_key()
        key_id = installation_key_id(key)
        base, base_key, live = await self._bounded(
            "drift",
            router.router_id,
            started,
            self._drift_inputs(conn, baseline, ctx, secret_digest_factory(key)),
        )
        mgmt_host = router.connection.host
        comparable = base_key is not None and base_key == key_id
        # Baseline digests of another key: the key was reset since.
        key_reset = base_key is not None and base_key != key_id
        engine_acks = tuple(
            EngineDriftAck(
                drift_id=ack.drift_id,
                state=DriftAckState(ack.state).value,
                by_user=ack.actor.user_id,
                at=ack.ts,
            )
            for ack in acks
            if ack.router_id == router.router_id
        )
        hidden: tuple[Change, ...] = ()
        if comparable:
            report = evaluate_drift(base, live, engine_acks, mgmt_host=mgmt_host)
        else:
            # Secret digests cannot be compared: report them as not
            # comparable and judge the drift on everything else.
            hidden = tuple(
                change
                for change in diff_snapshots(base, live, mgmt_host=mgmt_host)
                if change.detail == DETAIL_SECRET_CHANGED
            )
            report = evaluate_drift(
                _neutralised(base),
                _neutralised(live),
                engine_acks,
                mgmt_host=mgmt_host,
            )
        now = utcnow()
        diff = ConfigDiff(
            base=ConfigRef.backup(baseline.backup_id),
            other=ConfigRef.live(router.router_id),
            compared_at=now,
            changes=_core_changes(
                (*report.changes, *hidden),
                report.not_comparable,
                secrets_comparable=comparable,
            ),
        )
        # A key reset only rebuilds the baseline when nothing but the secret
        # digests differs; a real change is drift as usual (review H1).
        if key_reset and not report.changes and not report.not_comparable:
            result = DriftReport(
                router_id=router.router_id,
                baseline_backup_id=baseline.backup_id,
                checked_at=now,
                drifted=False,
                diff=diff,
                secrets_comparable=False,
                rebaseline=True,
            )
        else:
            result = DriftReport(
                router_id=router.router_id,
                baseline_backup_id=baseline.backup_id,
                checked_at=now,
                drifted=report.is_drift,
                diff=diff,
                drift_id=report.drift_id,
                ack_state=(
                    None if report.ack is None else DriftAckState(report.ack.state)
                ),
                critical_count=report.critical_count,
                unknown_count=sum(1 for c in report.changes if c.area == Area.OTHER),
                secrets_comparable=comparable,
            )
        _log("drift", started, method=FETCH_METHOD_UCI)
        return result

    async def _drift_inputs(
        self,
        conn: RouterConnection,
        baseline: BackupRecord,
        ctx: ProviderContext,
        digest: Callable[[str], str],
    ) -> tuple[UciSnapshot, str | None, UciSnapshot]:
        base, base_key = await self._record_snapshot(baseline, ctx)
        live = await self._live_uci(conn, digest, "drift")
        return base, base_key, live.snapshot

    # -- restore -----------------------------------------------------------

    async def async_prepare_restore(
        self,
        conn: RouterConnection,
        record: BackupRecord,
        target: RouterRecord,
        ctx: ProviderContext,
    ) -> RestorePlan:
        """Dry run: compatibility plus plan. Never writes."""
        started = time.monotonic()
        if _ARCHIVE not in record.artifacts:
            raise CapabilityUnavailableError(
                "version holds no archive to restore",
                capability=Capability.CONFIG_RESTORE_DRY_RUN.value,
                reason=REASON_NO_ARCHIVE,
                router_id=target.router_id,
            )
        key = await ctx.async_get_installation_key()
        analysis, source, current, target_inventory = await self._bounded(
            "restore_dry_run",
            target.router_id,
            started,
            self._restore_inputs(conn, record, ctx, secret_digest_factory(key)),
        )
        archive_snapshot = analysis.snapshot or UciSnapshot(
            configs={}, content_hash=_snapshot_hash({}), missing=frozenset()
        )
        plan = dry_run(
            analysis.report,
            archive_snapshot,
            current,
            source,
            target_inventory,
            mgmt_host=target.connection.host,
            snapshot_age_s=0.0,
            expected_sha256=record.sha256,
        )
        now = utcnow()
        compat = plan.compatibility
        steps = () if compat.blocked else _restore_steps(plan.archive_sha256)
        live = ConfigSnapshot(
            router_id=target.router_id,
            captured_at=now,
            configs=_plain(current.configs),
            openwrt_version=target_inventory.release_version,
            board_name=target_inventory.board_name,
            uci_hash=current.content_hash,
            installation_key_id=installation_key_id(key),
        )
        result = RestorePlan(
            plan_id=new_id(PLAN_ID_PREFIX),
            backup_id=record.backup_id,
            source_router_id=record.router_id,
            target_router_id=target.router_id,
            provider_id=PROVIDER_ID,
            created_at=now,
            compatibility=CompatibilityCheck(
                compatible=not compat.blocked,
                issues=tuple(
                    CompatibilityIssue(
                        code=finding.code,
                        message=_finding_message(finding),
                        blocking=finding.level == LEVEL_BLOCK,
                    )
                    for finding in compat.findings
                ),
            ),
            steps=steps,
            diff=ConfigDiff(
                base=ConfigRef.live(target.router_id),
                other=ConfigRef.backup(record.backup_id),
                compared_at=now,
                changes=_core_changes(
                    plan.changes, plan.not_comparable, secrets_comparable=True
                ),
            ),
            live_checksum=live.checksum,
            requires_reboot=bool(steps),
            # Never reversible (the core RestorePlan has no field for it).
            warnings=tuple(dict.fromkeys((*plan.warnings, INSTR_NOT_REVERSIBLE))),
            instructions=plan.instructions,
        )
        _log("restore_dry_run", started, size=record.size_bytes)
        return result

    async def _restore_inputs(
        self,
        conn: RouterConnection,
        record: BackupRecord,
        ctx: ProviderContext,
        digest: Callable[[str], str],
    ) -> tuple[_ArchiveAnalysis, Inventory, UciSnapshot, Inventory]:
        analysis = await self._run_job(
            _analyse_archive,
            await ctx.read(record.backup_id, _ARCHIVE),
            self._limits,
            digest,
        )
        source = await self._source_inventory(record, ctx)
        current = await self._live_uci(conn, digest, "restore_dry_run")
        target_inventory = await collect_inventory(
            conn.api, self._router_info(conn, ctx), timeouts=self._timeouts
        )
        return analysis, source, current.snapshot, target_inventory

    async def async_execute_restore(
        self,
        conn: RouterConnection,
        plan: RestorePlan,
        authorization: WriteAuthorization,
        ctx: ProviderContext,
    ) -> RestoreResult:
        """Write to the router after ``guard.consume(authorization, ...)``.

        Phase 1: never. A restore is a manual step (see the plan's
        instructions); ``config.restore`` is reported unavailable.
        """
        raise CapabilityUnavailableError(
            "restore runs manually in phase 1",
            capability=Capability.CONFIG_RESTORE.value,
            reason=REASON_PHASE1,
            router_id=conn.router_id,
        )
