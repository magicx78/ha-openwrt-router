"""Version store and installation key of the enterprise core (contract §7, §11.3).

CORE-INTERNAL. Modules only ever see :class:`VersionReadView` (``api.versions``);
every writing method needs a :class:`WriteAuthorization` that the store hands
to ``guard.consume`` right before it acts.

Layout (§7.1): the index lives in the HA store ``openwrt_router.config_catalog``;
the artifact bytes in ``<config>/openwrt_router/config_backups/<router_id>/``
(folders 0700, files 0600), one file per artifact named ``<backup_id>.<kind>``.
Writes go to ``<name>.partial``, are fsynced and renamed; the index entry is
written LAST. Every file operation runs in the executor.

Startup sweep (§7.2): ``*.partial`` files are deleted, files without an index
entry that are older than an hour move to ``orphaned/<router_id>/``, index
entries without a file are marked ``missing``; ``configuration.storage_swept``
reports it. Size limits: 50 MiB per router, 250 MiB in total (StorageFullError,
nothing written; the caller runs retention and retries once).

Installation key (§11.3): 32 random bytes in the store
``openwrt_router.installation_key``. It is created ONLY in the state
``uninitialised`` (first use, nothing stored yet). A missing or unreadable key
while versions or drift acks exist is ``lost``: ``InstallationKeyLostError``,
one ``core.installation_key_lost`` event, a repair issue, and a new key only
through the critical action ``installation_key_reset``.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import errno
import functools
import hashlib
import logging
import os
import secrets
import shutil
import stat
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir

from . import core_store
from .const import (
    CONFIG_CATALOG_SAVE_DELAY_SECONDS,
    CONFIG_CATALOG_STORE_MINOR_VERSION,
    INSTALLATION_KEY_STORE_MINOR_VERSION,
)
from .core_audit import CORE_SOURCE, AuditLog
from .core_errors import (
    ArtifactTooLargeError,
    AuthorizationError,
    BackupIntegrityError,
    BackupMetadataError,
    BackupNotFoundError,
    ConfigApiError,
    ErrorClass,
    InstallationKeyLostError,
    InvalidStorageRefError,
    StorageError,
    StorageFullError,
)
from .core_models import (
    BACKUP_ID_PREFIX,
    CONFIG_BACKUP_ORPHANED_DIR,
    CONFIG_BACKUP_PATH,
    CONFIG_BACKUP_REMOVED_DIR,
    CONFIG_CATALOG_STORE_KEY,
    CORE_STORE_VERSION,
    DEFAULT_LIST_LIMIT,
    DEFAULT_ROUTER_STORAGE_LIMIT_BYTES,
    DEFAULT_TOTAL_STORAGE_LIMIT_BYTES,
    INSTALLATION_KEY_BYTES,
    INSTALLATION_KEY_STORE_KEY,
    ISSUE_INSTALLATION_KEY_LOST,
    ISSUE_INSTALLATION_KEY_REPLACED,
    MAX_LIST_LIMIT,
    ORPHAN_SWEEP_MIN_AGE,
    PARTIAL_SUFFIX,
    ROUTER_ID_PREFIX,
    STORAGE_DIR_MODE,
    STORAGE_FILE_MODE,
    ArtifactKind,
    ArtifactPayload,
    ArtifactRef,
    BackupRecord,
    CoreEventType,
    DriftAck,
    EventResult,
    GuardedAction,
    InstallationKeyState,
    PutVersionResult,
    Severity,
    StorageRef,
    SweepReport,
    ValidationInfo,
    ValidationStatus,
    VersionMeta,
    WriteAuthorization,
    binding_checksum,
    dedup_candidate,
    ensure_supported_storage_format,
    installation_key_id,
    installation_key_state,
    integrity_failed,
    is_valid_id,
    new_id,
    resolve_artifact_path,
    should_deduplicate,
    utcnow,
    validate_deletion,
    validate_locator,
)
from .issues import async_clear_issue, async_raise_issue

_LOGGER = logging.getLogger(__name__)

# guard.consume(authorization, action=, router_id=, checksum=)
Consumer = Callable[..., None]


def migrate_catalog_store(
    old_major: int, old_minor: int, old_data: Any
) -> dict[str, Any]:
    """Store migration of the catalog. v1.x: additive minors."""
    if old_major != CORE_STORE_VERSION or not isinstance(old_data, dict):
        raise NotImplementedError(f"config catalog store version {old_major} unknown")
    data = dict(old_data)
    if not isinstance(data.get("versions"), dict):
        data["versions"] = {}
    if not isinstance(data.get("acks"), dict):
        data["acks"] = {}
    if not isinstance(data.get("rebaseline"), list):
        data["rebaseline"] = []
    data["key_lost_reported"] = data.get("key_lost_reported") is True
    return data


def migrate_key_store(old_major: int, old_minor: int, old_data: Any) -> dict[str, Any]:
    """Store migration of the installation key. v1.x: additive minors."""
    if old_major != CORE_STORE_VERSION or not isinstance(old_data, dict):
        raise NotImplementedError(f"installation key store version {old_major} unknown")
    return dict(old_data)


def _decode_key(data: Any) -> bytes | None:
    """The 32 key bytes of a stored key document, None if unusable."""
    if not isinstance(data, Mapping):
        return None
    raw = data.get("key")
    if not isinstance(raw, str):
        return None
    try:
        key = base64.b64decode(raw.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        return None
    if len(key) != INSTALLATION_KEY_BYTES:
        return None
    if data.get("key_id") != installation_key_id(key):
        return None
    return key


# -- executor helpers (blocking file I/O) ---------------------------------------------


def _ensure_dir(path: str) -> None:
    os.makedirs(path, mode=STORAGE_DIR_MODE, exist_ok=True)
    with contextlib.suppress(OSError):  # best effort on file systems without modes
        os.chmod(path, STORAGE_DIR_MODE)


# POSIX: never open through a symbolic link. Platforms without it (Windows)
# rely on O_EXCL alone, which also refuses an existing link or junction.
_O_NOFOLLOW: int = getattr(os, "O_NOFOLLOW", 0)
REASON_PARTIAL_NOT_REGULAR = "partial_not_regular"


def _partial_refused(kind: str) -> StorageError:
    return StorageError(
        "A link or folder sits where a version file is written; refused",
        details={"reason": REASON_PARTIAL_NOT_REGULAR, "found": kind},
    )


def _open_partial(partial: str) -> int:
    """Create ``partial`` exclusively (0o600), never through a link.

    Something already there: a link (symbolic or junction), a folder or any
    other non-regular entry is refused (``partial_not_regular``) and left
    alone. A regular file of the same name can only be a crashed write of
    this very locator: it is removed and the exclusive create retried once.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW
    flags |= getattr(os, "O_BINARY", 0)
    try:
        return os.open(partial, flags, STORAGE_FILE_MODE)
    except OSError as err:
        # FileExistsError; ELOOP = O_NOFOLLOW met a link; Windows answers a
        # folder with PermissionError. Anything else, with nothing at the
        # path, is a plain write error.
        if err.errno == errno.ELOOP or _path_is_link(partial):
            raise _partial_refused("symlink") from err
        if not isinstance(err, FileExistsError) and not os.path.lexists(partial):
            raise
    try:
        mode = os.lstat(partial).st_mode
    except FileNotFoundError:
        mode = None  # gone meanwhile: just create it
    if mode is not None:
        if not stat.S_ISREG(mode):
            raise _partial_refused("folder" if stat.S_ISDIR(mode) else "other")
        os.remove(partial)  # removes the entry itself, never a link target
    return os.open(partial, flags, STORAGE_FILE_MODE)


def _write_atomic(router_dir: str, locator: str, data: bytes) -> str:
    """Write ``data`` to ``router_dir/locator`` via .partial, fsync, rename.

    The .partial is created with ``O_CREAT | O_EXCL`` (+ ``O_NOFOLLOW``),
    see :func:`_open_partial`; the rename replaces a link at the final
    path itself, it never writes through it.
    """
    _ensure_dir(router_dir)
    path = resolve_artifact_path(router_dir, locator)
    partial = path + PARTIAL_SUFFIX
    fd = _open_partial(partial)
    try:
        with os.fdopen(fd, "wb") as handle:
            fchmod = getattr(os, "fchmod", None)
            if fchmod is not None:  # on the open file, never by path
                with contextlib.suppress(OSError):
                    fchmod(handle.fileno(), STORAGE_FILE_MODE)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(partial, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(partial)
        raise
    return path


def _read_file(router_dir: str, locator: str) -> bytes:
    path = resolve_artifact_path(router_dir, locator)
    with open(path, "rb") as handle:
        return handle.read()


def _remove_files(router_dir: str, locators: Iterable[str]) -> int:
    removed = 0
    for locator in locators:
        try:
            path = resolve_artifact_path(router_dir, locator)
        except InvalidStorageRefError:
            continue
        for candidate in (path, path + PARTIAL_SUFFIX):
            try:
                os.remove(candidate)
                removed += 1
            except FileNotFoundError:
                continue
    return removed


def _hash_payloads(payloads: Mapping[str, ArtifactPayload]) -> dict[str, str]:
    return {kind: hashlib.sha256(p.data).hexdigest() for kind, p in payloads.items()}


@dataclass(slots=True)
class _SweepFiles:
    partial_deleted: int = 0
    orphaned_moved: int = 0
    unknown_entries: int = 0
    symlinks_skipped: int = 0
    unindexed_kept: int = 0
    present: dict[str, set[str]] | None = None


def _scan(path: str) -> list[os.DirEntry[str]]:
    """Directory entries sorted by name (no symlink is followed here)."""
    with os.scandir(path) as entries:
        return sorted(entries, key=lambda e: e.name)


def _is_link(entry: os.DirEntry[str]) -> bool:
    """Symbolic link, or a Windows junction (Python 3.12+), never followed."""
    is_junction = getattr(entry, "is_junction", None)
    return entry.is_symlink() or bool(is_junction and is_junction())


def _path_is_link(path: str) -> bool:
    is_junction = getattr(os.path, "isjunction", None)
    return os.path.islink(path) or bool(is_junction and is_junction(path))


def _sweep_files(
    root: str,
    indexed: Mapping[str, set[str]],
    now: float,
    *,
    keep_unindexed: bool = False,
) -> _SweepFiles:
    """Delete partials, move old index-less files to orphaned/ (executor).

    Symbolic links (to files or folders) are never followed, deleted or
    moved; they are counted in ``symlinks_skipped``. ``keep_unindexed``
    (index recovered or empty): index-less files stay where they are and
    are counted in ``unindexed_kept`` instead of being moved.
    """
    out = _SweepFiles(present={})
    if _path_is_link(root) or not os.path.isdir(root):
        out.symlinks_skipped += int(_path_is_link(root))
        return out
    min_age = ORPHAN_SWEEP_MIN_AGE.total_seconds()
    for top in _scan(root):
        name = top.name
        path = top.path
        if name in (CONFIG_BACKUP_ORPHANED_DIR, CONFIG_BACKUP_REMOVED_DIR):
            continue
        if _is_link(top):
            out.symlinks_skipped += 1
            continue
        if name.endswith(PARTIAL_SUFFIX) and top.is_file(follow_symlinks=False):
            os.remove(path)
            out.partial_deleted += 1
            continue
        if not top.is_dir(follow_symlinks=False) or not is_valid_id(
            name, ROUTER_ID_PREFIX
        ):
            out.unknown_entries += 1
            continue
        known = indexed.get(name, set())
        present: set[str] = set()
        for item in _scan(path):
            file_name = item.name
            file_path = item.path
            if _is_link(item):
                out.symlinks_skipped += 1
                continue
            if not item.is_file(follow_symlinks=False):
                out.unknown_entries += 1
                continue
            if file_name.endswith(PARTIAL_SUFFIX):
                os.remove(file_path)
                out.partial_deleted += 1
                continue
            if file_name in known:
                present.add(file_name)
                continue
            if keep_unindexed:
                out.unindexed_kept += 1
                continue
            if now - item.stat(follow_symlinks=False).st_mtime < min_age:
                continue  # may belong to a put that is still running
            target_dir = os.path.join(root, CONFIG_BACKUP_ORPHANED_DIR, name)
            _ensure_dir(target_dir)
            target = os.path.join(target_dir, file_name)
            if os.path.exists(target):
                target = f"{target}.{int(now)}"
            os.replace(file_path, target)
            out.orphaned_moved += 1
        out.present[name] = present
    return out


def _archive_dir(root: str, router_id: str, now: float) -> bool:
    source = os.path.join(root, router_id)
    if not os.path.isdir(source):
        return False
    target_root = os.path.join(root, CONFIG_BACKUP_REMOVED_DIR)
    _ensure_dir(target_root)
    target = os.path.join(target_root, router_id)
    if os.path.exists(target):
        target = f"{target}.{int(now)}"
    shutil.move(source, target)
    return True


# -- the store --------------------------------------------------------------------------


class VersionStore:
    """Implements ``VersionStoreProtocol`` (core-internal) plus the key."""

    def __init__(
        self,
        hass: HomeAssistant,
        audit: AuditLog,
        *,
        consume: Consumer,
        clock: Callable[[], datetime] = utcnow,
        router_limit: int = DEFAULT_ROUTER_STORAGE_LIMIT_BYTES,
        total_limit: int = DEFAULT_TOTAL_STORAGE_LIMIT_BYTES,
    ) -> None:
        """Create an empty store; :meth:`async_load` reads index and key."""
        self.hass = hass
        self.audit = audit
        self._consume = consume
        self._clock = clock
        self.router_limit = router_limit
        self.total_limit = total_limit
        self._catalog: Any = core_store.create_store(
            hass,
            CORE_STORE_VERSION,
            CONFIG_CATALOG_STORE_KEY,
            minor_version=CONFIG_CATALOG_STORE_MINOR_VERSION,
            migrate=migrate_catalog_store,
        )
        self._key_store: Any = core_store.create_store(
            hass,
            CORE_STORE_VERSION,
            INSTALLATION_KEY_STORE_KEY,
            minor_version=INSTALLATION_KEY_STORE_MINOR_VERSION,
            migrate=migrate_key_store,
            # The key is a secret: file mode 0600, never a half-written file.
            private=True,
            atomic_writes=True,
        )
        self._lock = asyncio.Lock()
        self._key_lock = asyncio.Lock()
        self._records: dict[str, BackupRecord] = {}
        self._acks: dict[str, dict[str, DriftAck]] = {}
        self._rebaseline: set[str] = set()
        self._reserved: dict[str, int] = {}
        # Newest created_at handed out: versions get strictly increasing
        # timestamps, so history order never depends on clock resolution, a
        # clock step back or the random id (1.44.0).
        self._last_created_at: datetime | None = None
        self._key: bytes | None = None
        self._key_state = InstallationKeyState.UNINITIALISED
        self._key_lost_reported = False
        # A key file existed but gave no usable key (review #9): a new key
        # is then audited and raises a repair issue (hook, replaceable).
        self._key_doc_unusable = False
        self.key_replaced_hook: Callable[[str], None] = self._raise_key_replaced_issue
        # The index was unreadable (review #13): when it happened (ISO), kept
        # in the catalog; the sweep then never moves index-less files.
        self.index_recovered_at: str | None = None
        self._root = self._resolve_root()
        self.loaded = False
        self.closed = False
        self._save_pending = False
        self.last_sweep: SweepReport | None = None
        self.stats: dict[str, int] = {
            "puts": 0,
            "created": 0,
            "dedup_hits": 0,
            "storage_full": 0,
            "too_large": 0,
            "refused_input": 0,
            "write_errors": 0,
            "partial_refused": 0,
            "reads": 0,
            "integrity_failures": 0,
            "deleted": 0,
            "pruned": 0,
            "protected_changes": 0,
            "acks": 0,
            "records_skipped_on_load": 0,
            "acks_skipped_on_load": 0,
            "catalog_saves": 0,
            "catalog_saves_delayed": 0,
            "sweeps": 0,
            "sweep_unknown_entries": 0,
            "archived_routers": 0,
            "archive_missing_folder": 0,
            "created_at_adjusted": 0,
            "dedup_refused_sha256": 0,
            "keys_created": 0,
            "keys_replaced": 0,
            "key_resets": 0,
            "key_lost_events": 0,
            "key_lost_already_reported": 0,
            "refused_not_ready": 0,
            "sweep_symlinks_skipped": 0,
            "sweep_unindexed_kept": 0,
            "sweeps_skipped": 0,
        }

    def _require_loaded(self) -> None:
        """Writes, key creation and the sweep need the loaded index.

        Without it a write would replace the stored index with an empty
        one, the key could be regenerated and the sweep would remove every
        file as index-less.
        """
        if not self.loaded or self.closed:
            self.stats["refused_not_ready"] += 1
            raise StorageError(
                "The version store is not ready",
                retryable=True,
                details={"reason": "store_closed" if self.closed else "not_loaded"},
            )

    def _resolve_root(self) -> str | None:
        try:
            root = self.hass.config.path(*CONFIG_BACKUP_PATH)
        except (AttributeError, TypeError, ValueError, OSError):
            _LOGGER.warning("Version store: the config path is not readable")
            return None
        if not isinstance(root, str) or not root:
            _LOGGER.debug("Version store: no usable config path; files disabled")
            return None
        return root

    @property
    def storage_available(self) -> bool:
        """True if a backup folder can be used."""
        return self._root is not None

    def now(self) -> datetime:
        """The store's clock (aware UTC)."""
        return self._clock()

    # -- load / save -----------------------------------------------------------------

    async def async_load(self) -> None:
        """Read index and key once; decide the key state (lost is reported)."""
        if self.loaded:
            return
        loaded = await core_store.async_load_store(
            self.hass, self._catalog, CONFIG_CATALOG_STORE_KEY
        )
        self._restore(loaded.data or {})
        if loaded.failed:
            self.index_recovered_at = self.now().isoformat()
            self._report_recovered(backup_written=loaded.backed_up)
            self._schedule_save()  # keep index_recovered_at
        key_load = await core_store.async_load_store(
            self.hass, self._key_store, INSTALLATION_KEY_STORE_KEY
        )
        key = None if key_load.failed else _decode_key(key_load.data)
        self._key_doc_unusable = key is None and (
            key_load.failed or key_load.data is not None
        )
        if key_load.data is not None and key is None and not key_load.failed:
            _LOGGER.warning("Installation key store has an unusable key document")
            await core_store.async_backup_store(
                self.hass, self._key_store, INSTALLATION_KEY_STORE_KEY
            )
        self._key = key
        self._key_state = installation_key_state(
            key_readable=key is not None,
            has_versions=bool(self._records),
            has_acks=any(self._acks.values()),
        )
        self.loaded = True
        if self._key_state is InstallationKeyState.LOST:
            self._report_key_lost()

    def _restore(self, data: Mapping[str, Any]) -> None:
        skipped = 0
        versions = data.get("versions")
        for backup_id, raw in (
            versions if isinstance(versions, Mapping) else {}
        ).items():
            try:
                record = BackupRecord.from_dict(raw)
            except BackupMetadataError:
                skipped += 1
                continue
            if record.backup_id != backup_id:
                skipped += 1
                continue
            self._records[backup_id] = record
            if self._last_created_at is None or (
                record.created_at > self._last_created_at
            ):
                self._last_created_at = record.created_at
        acks_skipped = 0
        acks = data.get("acks")
        for router_id, items in (acks if isinstance(acks, Mapping) else {}).items():
            for raw in items if isinstance(items, list) else []:
                try:
                    ack = DriftAck.from_dict(raw)
                except (KeyError, TypeError, ValueError):
                    acks_skipped += 1
                    continue
                if ack.router_id != router_id:
                    acks_skipped += 1
                    continue
                self._acks.setdefault(router_id, {})[ack.drift_id] = ack
        rebaseline = data.get("rebaseline")
        self._rebaseline = {
            r
            for r in (rebaseline if isinstance(rebaseline, list) else [])
            if isinstance(r, str)
        }
        self._key_lost_reported = data.get("key_lost_reported") is True
        recovered = data.get("index_recovered_at")
        self.index_recovered_at = recovered if isinstance(recovered, str) else None
        self.stats["records_skipped_on_load"] += skipped
        self.stats["acks_skipped_on_load"] += acks_skipped
        if skipped or acks_skipped:
            _LOGGER.warning(
                "Config catalog: %d version(s) and %d drift ack(s) unreadable, skipped",
                skipped,
                acks_skipped,
            )
            self._report_recovered(
                backup_written=False,
                records_skipped=skipped,
                acks_skipped=acks_skipped,
            )

    def _report_recovered(self, *, backup_written: bool, **counts: int) -> None:
        self._emit(
            CoreEventType.STORE_RECOVERED,
            severity=Severity.WARNING,
            data={
                "store": CONFIG_CATALOG_STORE_KEY,
                "backup_written": backup_written,
                **counts,
            },
        )

    def _data(self) -> dict[str, Any]:
        self._save_pending = False
        return {
            "versions": {k: r.to_dict() for k, r in sorted(self._records.items())},
            "acks": {
                rid: [a.to_dict() for a in sorted(acks.values(), key=lambda a: a.ts)]
                for rid, acks in sorted(self._acks.items())
                if acks
            },
            "rebaseline": sorted(self._rebaseline),
            "key_lost_reported": self._key_lost_reported,
            **(
                {"index_recovered_at": self.index_recovered_at}
                if self.index_recovered_at
                else {}
            ),
        }

    async def _async_save(self) -> None:
        """Write the index now (after every create/delete/protect/ack)."""
        self.stats["catalog_saves"] += 1
        try:
            await self._catalog.async_save(self._data())
        except Exception as err:
            self.stats["write_errors"] += 1
            raise StorageError(
                "The version index could not be written",
                details={"cause": type(err).__name__},
            ) from err

    @callback
    def _schedule_save(self) -> None:
        """Delayed index write (last_seen_at only)."""
        if self._save_pending or self.closed:
            return
        self._save_pending = True
        self.stats["catalog_saves_delayed"] += 1
        self._catalog.async_delay_save(self._data, CONFIG_CATALOG_SAVE_DELAY_SECONDS)

    async def async_flush(self) -> None:
        """Write the index now (also with nothing pending)."""
        if not self.loaded:
            return
        await self._catalog.async_save(self._data())

    @callback
    def close(self) -> None:
        """No more delayed writes are scheduled."""
        self.closed = True

    # -- read view -------------------------------------------------------------------

    async def async_list_versions(
        self,
        router_id: str | None = None,
        *,
        since: datetime | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> tuple[BackupRecord, ...]:
        """Versions, newest first (``limit`` 1..MAX_LIST_LIMIT, else ValueError)."""
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError("limit must be an int")
        if not 1 <= limit <= MAX_LIST_LIMIT:
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        if since is not None and since.tzinfo is None:
            raise ValueError("since must be time-zone aware")
        out = [
            r
            for r in self._records.values()
            if (router_id is None or r.router_id == router_id)
            and (since is None or r.created_at >= since)
        ]
        out.sort(key=lambda r: (r.created_at, r.backup_id), reverse=True)
        return tuple(out[:limit])

    def records(self, router_id: str | None = None) -> tuple[BackupRecord, ...]:
        """All versions (core-internal, unlimited), oldest first."""
        out = [
            r
            for r in self._records.values()
            if router_id is None or r.router_id == router_id
        ]
        out.sort(key=lambda r: (r.created_at, r.backup_id))
        return tuple(out)

    def router_ids(self) -> tuple[str, ...]:
        """Routers that have versions."""
        return tuple(sorted({r.router_id for r in self._records.values()}))

    async def async_get_version(self, version_id: str) -> BackupRecord:
        """One version; BackupNotFoundError if unknown."""
        return self.get(version_id)

    def get(self, version_id: str) -> BackupRecord:
        """One version (sync); a malformed id is never echoed back."""
        if not is_valid_id(version_id, BACKUP_ID_PREFIX):
            self.stats["refused_input"] += 1
            raise BackupNotFoundError(
                "Unknown version", details={"reason": "invalid_version_id"}
            )
        record = self._records.get(version_id)
        if record is None:
            raise BackupNotFoundError(
                "Unknown version", details={"version_id": version_id}
            )
        return record

    async def async_list_drift_acks(self, router_id: str) -> tuple[DriftAck, ...]:
        """Acknowledgements of a router, newest first."""
        acks = self._acks.get(router_id, {})
        return tuple(sorted(acks.values(), key=lambda a: a.ts, reverse=True))

    def acks(self, router_id: str) -> tuple[DriftAck, ...]:
        """Acknowledgements of a router (sync)."""
        return tuple(self._acks.get(router_id, {}).values())

    def usage_bytes(self, router_id: str | None = None) -> int:
        """Bytes used by one router or in total (index sizes)."""
        return sum(
            r.size_bytes
            for r in self._records.values()
            if router_id is None or r.router_id == router_id
        )

    # -- installation key ------------------------------------------------------------

    @property
    def key_state(self) -> InstallationKeyState:
        """ok / lost / uninitialised."""
        return self._key_state

    @property
    def key_id(self) -> str | None:
        """Public id of the current key (None without a key)."""
        return None if self._key is None else installation_key_id(self._key)

    def existing_installation_key(self) -> bytes | None:
        """Core-internal: the loaded key, or None (never creates, no I/O)."""
        if self._key_state is not InstallationKeyState.OK:
            return None
        return self._key

    async def async_get_installation_key(self) -> bytes:
        """The key; created only in state ``uninitialised``.

        Raises InstallationKeyLostError while the key is lost.
        """
        self._require_loaded()
        async with self._key_lock:
            if self._key_state is InstallationKeyState.LOST:
                raise InstallationKeyLostError(
                    "The installation key is lost; an admin must reset it",
                    details={"state": self._key_state.value},
                )
            if self._key is not None:
                return self._key
            key = secrets.token_bytes(INSTALLATION_KEY_BYTES)
            await self._async_store_key(key)
            self.stats["keys_created"] += 1
            if self._key_doc_unusable:
                self._report_key_replaced(key)
            else:
                _LOGGER.info("Enterprise core: installation key created (first use)")
            return key

    @property
    def file_activity(self) -> int:
        """Writes, deletions and moves of version files by this store."""
        return sum(
            self.stats[name]
            for name in (
                "puts",
                "deleted",
                "pruned",
                "write_errors",
                "archived_routers",
                "archive_missing_folder",
                "keys_created",
                "keys_replaced",
                "key_resets",
            )
        )

    @property
    def has_pending_save(self) -> bool:
        """True while a delayed index write is scheduled."""
        return self._save_pending

    def _report_key_replaced(self, key: bytes) -> None:
        """A key file existed but was unusable: audit + repair issue."""
        self._key_doc_unusable = False
        self.stats["keys_replaced"] += 1
        key_id = installation_key_id(key)
        _LOGGER.warning(
            "Enterprise core: the installation key file was unreadable and has "
            "been replaced by a new key (%s); no stored version used the old key",
            key_id,
        )
        self._emit(
            CoreEventType.INSTALLATION_KEY_REPLACED,
            severity=Severity.WARNING,
            result=EventResult.FAILURE,
            data={"key_id": key_id, "store": INSTALLATION_KEY_STORE_KEY},
        )
        try:
            self.key_replaced_hook(key_id)
        except Exception:
            _LOGGER.warning("Repair issue for the replaced key failed", exc_info=True)

    def _raise_key_replaced_issue(self, key_id: str) -> None:
        async_raise_issue(
            self.hass,
            ISSUE_INSTALLATION_KEY_REPLACED,
            ISSUE_INSTALLATION_KEY_REPLACED,
            ir.IssueSeverity.WARNING,
            {"key_id": key_id},
        )

    async def _async_store_key(self, key: bytes) -> None:
        document = {
            "key": base64.b64encode(key).decode("ascii"),
            "key_id": installation_key_id(key),
            "created_at": self.now().isoformat(),
        }
        try:
            await self._key_store.async_save(document)
        except Exception as err:
            raise StorageError(
                "The installation key could not be written",
                details={"cause": type(err).__name__},
            ) from err
        self._key = key
        self._key_state = InstallationKeyState.OK

    def newest_key_id(self) -> str | None:
        """``installation_key_id`` of the newest version (reset binding)."""
        stamped = [r for r in self._records.values() if r.installation_key_id]
        if not stamped:
            return None
        return max(stamped, key=lambda r: r.created_at).installation_key_id

    async def async_reset_installation_key(
        self, *, authorization: WriteAuthorization, checksum: str
    ) -> str:
        """New key after a loss (critical action consumed here). Returns key id.

        Every router with versions gets a re-baseline on its next drift check.
        """
        self._require_loaded()
        async with self._key_lock:
            self._consume(
                authorization,
                action=GuardedAction.INSTALLATION_KEY_RESET,
                router_id="-",
                checksum=checksum,
            )
            old_state = self._key_state
            key = secrets.token_bytes(INSTALLATION_KEY_BYTES)
            await self._async_store_key(key)
            self.stats["key_resets"] += 1
            async with self._lock:
                self._rebaseline = set(self.router_ids())
                self._key_lost_reported = False
                await self._async_save()
        async_clear_issue(self.hass, ISSUE_INSTALLATION_KEY_LOST)
        self._emit(
            CoreEventType.INSTALLATION_KEY_RESET,
            actor=authorization.actor,
            correlation_id=authorization.correlation_id,
            result=EventResult.SUCCESS,
            data={
                "key_id": installation_key_id(key),
                "previous_state": old_state.value,
                "rebaseline_routers": len(self._rebaseline),
                "authorization_id": authorization.authorization_id,
            },
        )
        return installation_key_id(key)

    def needs_rebaseline(self, router_id: str) -> bool:
        """True until the first drift check after a key reset."""
        return router_id in self._rebaseline

    async def async_clear_rebaseline(self, router_id: str) -> None:
        """The router's re-baseline is done."""
        self._require_loaded()
        async with self._lock:
            if router_id in self._rebaseline:
                self._rebaseline.discard(router_id)
                await self._async_save()

    def _report_key_lost(self) -> None:
        """One event per loss (persisted flag), the repair issue every start."""
        try:
            async_raise_issue(
                self.hass,
                ISSUE_INSTALLATION_KEY_LOST,
                ISSUE_INSTALLATION_KEY_LOST,
                ir.IssueSeverity.ERROR,
                {"versions": str(len(self._records))},
            )
        except Exception:
            _LOGGER.warning("Repair issue for the lost key failed", exc_info=True)
        _LOGGER.error(
            "Enterprise core: the installation key is missing or unreadable while "
            "%d version(s) exist; secret digests are not comparable until an admin "
            "resets the key",
            len(self._records),
        )
        if self._key_lost_reported:
            self.stats["key_lost_already_reported"] += 1
            return
        self._key_lost_reported = True
        self.stats["key_lost_events"] += 1
        self._emit(
            CoreEventType.INSTALLATION_KEY_LOST,
            severity=Severity.CRITICAL,
            result=EventResult.FAILURE,
            data={
                "versions": len(self._records),
                "acks": sum(len(a) for a in self._acks.values()),
                "last_key_id": self.newest_key_id(),
            },
        )
        self._schedule_save()

    # -- put -------------------------------------------------------------------------

    def _router_dir(self, router_id: str) -> str:
        if self._root is None:
            raise StorageError(
                "No storage folder is available",
                router_id=router_id,
                details={"reason": "storage_unavailable"},
            )
        if not is_valid_id(router_id, ROUTER_ID_PREFIX):
            raise InvalidStorageRefError(
                "Invalid router id", details={"reason": "bad_router_id"}
            )
        return os.path.join(self._root, router_id)

    async def async_put_version(
        self,
        router_id: str,
        artifacts: Mapping[str, ArtifactPayload],
        meta: VersionMeta,
        *,
        authorization: WriteAuthorization,
    ) -> PutVersionResult:
        """Store a version (``backup`` authorization); dedup per §7.4.

        Limits are checked BEFORE the authorization is consumed, so a
        StorageFullError leaves it usable for the one retry after retention.

        Everything handed in is untrusted: artifact kinds are a closed set,
        only ArtifactPayload bytes are accepted (a caller never supplies a
        path; locators are generated here), the per-artifact size limit is
        checked before any hashing, and the sha256 recorded is the one
        computed here (a different claimed sha256 is refused).
        """
        self._require_loaded()
        self.stats["puts"] += 1
        if not isinstance(meta, VersionMeta):
            raise TypeError("meta must be a VersionMeta")
        router_dir = self._router_dir(router_id)
        payloads = self._check_payloads(router_id, artifacts)
        largest = max((p.size_bytes for p in payloads.values()), default=0)
        if largest > self.router_limit:
            self.stats["too_large"] += 1
            raise ArtifactTooLargeError(
                "Artifact is larger than the per-router limit",
                router_id=router_id,
                details={"size_bytes": largest, "limit_bytes": self.router_limit},
            )
        hashes = await self.hass.async_add_executor_job(_hash_payloads, payloads)
        bad = sorted(k for k, p in payloads.items() if hashes[k] != p.sha256)
        if bad:
            self.stats["integrity_failures"] += 1
            raise BackupIntegrityError(
                "Artifact checksum does not match its bytes",
                router_id=router_id,
                details={"reason": "checksum_mismatch", "artifacts": bad},
            )
        size = sum(p.size_bytes for p in payloads.values())
        async with self._lock:
            now = self._next_created_at()
            records = self.records(router_id)
            candidate = dedup_candidate(records, meta.backup_type)
            repeat = should_deduplicate(
                candidate, meta, payloads.keys(), artifact_sha256=hashes
            )
            if not repeat and should_deduplicate(candidate, meta, payloads.keys()):
                # Provider hashes say "same", the core's sha256 says "not
                # byte-identical": stored as a new version (counted).
                self.stats["dedup_refused_sha256"] += 1
                _LOGGER.debug(
                    "Version of %s kept: provider hash equal, artifact sha256 differs",
                    router_id,
                )
            if repeat:
                assert candidate is not None
                self._consume(
                    authorization, action=GuardedAction.BACKUP, router_id=router_id
                )
                updated = replace(candidate, last_seen_at=now)
                self._records[updated.backup_id] = updated
                self.stats["dedup_hits"] += 1
                self._schedule_save()
                return PutVersionResult(record=updated, created=False)
            self._check_limits(router_id, payloads, size)
            self._consume(
                authorization, action=GuardedAction.BACKUP, router_id=router_id
            )
            self._reserved[router_id] = self._reserved.get(router_id, 0) + size
        backup_id = new_id(BACKUP_ID_PREFIX)
        refs: dict[str, ArtifactRef] = {}
        try:
            for kind, payload in sorted(payloads.items()):
                locator = validate_locator(f"{backup_id}.{kind}")
                await self.hass.async_add_executor_job(
                    _write_atomic, router_dir, locator, payload.data
                )
                refs[kind] = ArtifactRef(
                    storage=StorageRef(locator=locator),
                    sha256=hashes[kind],  # computed here, never the claimed one
                    size_bytes=payload.size_bytes,
                    content_type=payload.content_type,
                )
            record = BackupRecord(
                backup_id=backup_id,
                router_id=router_id,
                created_at=now,
                backup_type=meta.backup_type,
                reason=meta.reason,
                created_by=authorization.actor,
                status=meta.status,
                error_class=meta.error_class,
                fetch_method=meta.fetch_method,
                content_hash=meta.content_hash,
                uci_hash=meta.uci_hash,
                openwrt_version=meta.openwrt_version,
                hardware_model=meta.hardware_model,
                board_name=meta.board_name,
                compatibility=meta.compatibility,
                artifacts=refs,
                links=replace(
                    meta.links,
                    correlation_id=meta.links.correlation_id
                    or meta.correlation_id
                    or authorization.correlation_id,
                ),
                contains_secrets=meta.contains_secrets,
                note=meta.note,
                warnings=meta.warnings,
                installation_key_id=meta.installation_key_id,
            )
            async with self._lock:
                self._records[backup_id] = record  # the index entry comes last
                try:
                    await self._async_save()
                except StorageError:
                    del self._records[backup_id]
                    raise
        except BaseException as err:
            await self._async_cleanup(router_dir, refs, backup_id, payloads)
            if (
                isinstance(err, StorageError)
                and err.details.get("reason") == REASON_PARTIAL_NOT_REGULAR
            ):
                self.stats["write_errors"] += 1
                self.stats["partial_refused"] += 1
                _LOGGER.warning(
                    "Version store: a %s sits where a version file of %s is "
                    "written; refused, nothing was followed",
                    err.details.get("found"),
                    router_id,
                )
                raise StorageError(
                    "Writing the version failed",
                    router_id=router_id,
                    details=dict(err.details),
                ) from err
            if isinstance(err, OSError):
                self.stats["write_errors"] += 1
                raise StorageError(
                    "Writing the version failed",
                    router_id=router_id,
                    details={"cause": type(err).__name__},
                ) from err
            raise
        finally:
            self._reserved[router_id] = max(0, self._reserved.get(router_id, 0) - size)
        self.stats["created"] += 1
        return PutVersionResult(record=record, created=True)

    async def _async_cleanup(
        self,
        router_dir: str,
        refs: Mapping[str, ArtifactRef],
        backup_id: str,
        payloads: Mapping[str, ArtifactPayload],
    ) -> None:
        locators = {f"{backup_id}.{kind}" for kind in payloads} | {
            ref.storage.locator for ref in refs.values()
        }
        try:
            await self.hass.async_add_executor_job(_remove_files, router_dir, locators)
        except Exception:
            _LOGGER.warning(
                "Version store: cleaning up a failed write of %s failed (the next "
                "startup sweep removes the files)",
                backup_id,
                exc_info=True,
            )

    def _check_payloads(
        self, router_id: str, artifacts: Mapping[str, ArtifactPayload]
    ) -> dict[str, ArtifactPayload]:
        """Closed artifact kinds and payload objects only (no refs, no paths)."""
        if not isinstance(artifacts, Mapping):
            raise TypeError("artifacts must be a mapping")
        payloads: dict[str, ArtifactPayload] = {}
        for key, payload in artifacts.items():
            try:
                kind = ArtifactKind(key).value
            except ValueError:
                self.stats["refused_input"] += 1
                raise BackupMetadataError(
                    "Unknown artifact kind",
                    router_id=router_id,
                    error_class=ErrorClass.INVALID,
                    details={"reason": "unknown_artifact_kind"},
                ) from None
            if not isinstance(payload, ArtifactPayload):
                self.stats["refused_input"] += 1
                raise BackupMetadataError(
                    "Artifacts must be ArtifactPayload bytes; a locator is never "
                    "accepted from a caller",
                    router_id=router_id,
                    error_class=ErrorClass.INVALID,
                    details={"reason": "artifact_not_a_payload", "artifact": kind},
                )
            payloads[kind] = payload
        return payloads

    def _check_limits(
        self, router_id: str, payloads: Mapping[str, ArtifactPayload], size: int
    ) -> None:
        router_used = self.usage_bytes(router_id) + self._reserved.get(router_id, 0)
        total_used = self.usage_bytes() + sum(self._reserved.values())
        for scope, used, limit in (
            ("router", router_used, self.router_limit),
            ("total", total_used, self.total_limit),
        ):
            if used + size > limit:
                self.stats["storage_full"] += 1
                raise StorageFullError(
                    f"Storage limit ({scope}) reached; nothing was written",
                    router_id=router_id,
                    details={
                        "scope": scope,
                        "used_bytes": used,
                        "needed_bytes": size,
                        "limit_bytes": limit,
                    },
                )

    # -- read ------------------------------------------------------------------------

    async def async_read_artifact(self, version_id: str, kind: str) -> bytes:
        """Bytes of one artifact; checks locator, storage_format and sha256.

        A mismatch marks the version ``corrupt``, a missing file ``missing``
        (both emit ``configuration.integrity_failed``) and raises
        BackupIntegrityError.
        """
        self.stats["reads"] += 1
        record = self.get(version_id)
        try:
            kind = ArtifactKind(kind).value
        except ValueError:
            self.stats["refused_input"] += 1
            raise BackupNotFoundError(
                "The version has no such artifact",
                router_id=record.router_id,
                details={"version_id": version_id, "reason": "unknown_artifact_kind"},
            ) from None
        ref = record.artifacts.get(kind)
        if ref is None:
            raise BackupNotFoundError(
                "The version has no such artifact",
                router_id=record.router_id,
                details={"version_id": version_id, "artifact": kind},
            )
        ensure_supported_storage_format(ref.storage.storage_format)
        router_dir = self._router_dir(record.router_id)
        try:
            data = await self.hass.async_add_executor_job(
                _read_file, router_dir, ref.storage.locator
            )
        except FileNotFoundError:
            await self._async_integrity(
                record, ValidationStatus.MISSING, kind, "missing"
            )
            raise BackupIntegrityError(
                "The artifact file is missing",
                router_id=record.router_id,
                details={
                    "version_id": version_id,
                    "artifact": kind,
                    "reason": "missing",
                },
            ) from None
        except OSError as err:
            raise StorageError(
                "Reading the artifact failed",
                router_id=record.router_id,
                details={"cause": type(err).__name__},
            ) from err
        digest = await self.hass.async_add_executor_job(
            lambda: hashlib.sha256(data).hexdigest()
        )
        if len(data) != ref.size_bytes or digest != ref.sha256:
            reason = (
                "size_mismatch" if len(data) != ref.size_bytes else "checksum_mismatch"
            )
            await self._async_integrity(record, ValidationStatus.CORRUPT, kind, reason)
            raise BackupIntegrityError(
                "The artifact does not match its index entry",
                router_id=record.router_id,
                details={"version_id": version_id, "artifact": kind, "reason": reason},
            )
        return data

    async def _async_integrity(
        self, record: BackupRecord, status: ValidationStatus, kind: str, reason: str
    ) -> None:
        self.stats["integrity_failures"] += 1
        await self.async_set_validation(
            record.backup_id,
            ValidationInfo(
                status=status, checked_at=self.now(), details=f"{kind}:{reason}"
            ),
        )

    # -- mutations ---------------------------------------------------------------------

    async def async_set_validation(
        self, version_id: str, validation: ValidationInfo
    ) -> BackupRecord:
        """Store a validation result (core-internal); failures emit an event."""
        self._require_loaded()
        async with self._lock:
            record = self.get(version_id)
            updated = replace(record, validation=validation)
            self._records[version_id] = updated
            await self._async_save()
        if integrity_failed(validation):
            self._emit(
                CoreEventType.INTEGRITY_FAILED,
                router_id=record.router_id,
                severity=Severity.WARNING,
                result=EventResult.FAILURE,
                dedup_key=f"{version_id}:{validation.status.value}",
                data={"version_id": version_id, "status": validation.status.value},
            )
        return updated

    async def async_delete_versions(
        self, version_ids: Sequence[str], *, authorization: WriteAuthorization
    ) -> tuple[str, ...]:
        """``delete`` (validate_deletion first) or ``prune`` (core retention)."""
        self._require_loaded()
        ids = sorted(set(version_ids))
        if not ids:
            return ()
        action = authorization.action
        if action not in (GuardedAction.DELETE, GuardedAction.PRUNE):
            raise AuthorizationError(
                "Deleting needs a delete or prune authorization",
                router_id=authorization.router_id,
                details={"reason": "action_mismatch", "action": action},
            )
        async with self._lock:
            records = [self.get(v) for v in ids]
            validate_deletion(records, router_id=authorization.router_id)
            self._consume(
                authorization,
                action=action,
                router_id=authorization.router_id,
                checksum=binding_checksum(*ids),
            )
            router_dir = self._router_dir(authorization.router_id)
            locators = [
                a.storage.locator for r in records for a in r.artifacts.values()
            ]
            for record in records:
                del self._records[record.backup_id]
            try:
                await self._async_save()
            except StorageError:
                for record in records:
                    self._records[record.backup_id] = record
                raise
        try:
            await self.hass.async_add_executor_job(_remove_files, router_dir, locators)
        except Exception:
            _LOGGER.warning(
                "Version store: index updated but %d file(s) could not be removed; "
                "the next startup sweep moves them to orphaned/",
                len(locators),
                exc_info=True,
            )
        self.stats["pruned" if action == GuardedAction.PRUNE else "deleted"] += len(ids)
        return tuple(ids)

    async def async_set_protected(
        self, version_id: str, protected: bool, *, authorization: WriteAuthorization
    ) -> BackupRecord:
        """Set or clear protection (``protect`` authorization)."""
        self._require_loaded()
        async with self._lock:
            record = self.get(version_id)
            self._consume(
                authorization,
                action=GuardedAction.PROTECT,
                router_id=record.router_id,
                checksum=binding_checksum(version_id, bool(protected)),
            )
            updated = replace(record, protected=bool(protected))
            self._records[version_id] = updated
            try:
                await self._async_save()
            except StorageError:
                self._records[version_id] = record
                raise
        self.stats["protected_changes"] += 1
        return updated

    async def async_put_drift_ack(
        self, ack: DriftAck, *, authorization: WriteAuthorization
    ) -> DriftAck:
        """Store an acknowledgement (``drift_ack``); replaces the same drift_id."""
        self._require_loaded()
        async with self._lock:
            self._consume(
                authorization,
                action=GuardedAction.DRIFT_ACK,
                router_id=ack.router_id,
                checksum=binding_checksum(ack.router_id, ack.drift_id, ack.state.value),
            )
            await self._async_store_ack(ack)
        return ack

    async def async_put_rebaseline_ack(self, ack: DriftAck) -> DriftAck:
        """Core-internal: the re-baseline after a key reset (no user action)."""
        self._require_loaded()
        async with self._lock:
            await self._async_store_ack(ack)
        return ack

    async def _async_store_ack(self, ack: DriftAck) -> None:
        if ack.version_id is not None:
            version = self.get(ack.version_id)
            if version.router_id != ack.router_id:
                raise AuthorizationError(
                    "The acknowledged version belongs to another router",
                    router_id=ack.router_id,
                    details={"reason": "router_mismatch"},
                )
        acks = self._acks.setdefault(ack.router_id, {})
        previous = acks.get(ack.drift_id)
        acks[ack.drift_id] = ack
        try:
            await self._async_save()
        except StorageError:
            if previous is None:
                del acks[ack.drift_id]
            else:
                acks[ack.drift_id] = previous
            raise
        self.stats["acks"] += 1

    # -- sweep / archive -------------------------------------------------------------

    async def async_sweep(self) -> SweepReport:
        """Startup cleanup: partials, index-less files, missing files."""
        self._require_loaded()
        now = self.now()
        if self._root is None:
            report = SweepReport(checked_at=now)
            self.last_sweep = report
            return report
        indexed: dict[str, set[str]] = {}
        for record in self._records.values():
            names = indexed.setdefault(record.router_id, set())
            names.update(a.storage.locator for a in record.artifacts.values())
        keep_unindexed = self.index_recovered_at is not None or not self._records
        try:
            files = await self.hass.async_add_executor_job(
                functools.partial(
                    _sweep_files,
                    self._root,
                    indexed,
                    time.time(),
                    keep_unindexed=keep_unindexed,
                )
            )
        except OSError as err:
            raise StorageError(
                "The startup sweep failed", details={"cause": type(err).__name__}
            ) from err
        present = files.present or {}
        missing: list[BackupRecord] = []
        for record in self._records.values():
            if record.validation.status is ValidationStatus.MISSING:
                continue
            have = present.get(record.router_id, set())
            if any(a.storage.locator not in have for a in record.artifacts.values()):
                missing.append(record)
        if missing:
            async with self._lock:
                for record in missing:
                    self._records[record.backup_id] = replace(
                        record,
                        validation=ValidationInfo(
                            status=ValidationStatus.MISSING,
                            checked_at=now,
                            details="sweep:file_missing",
                        ),
                    )
                await self._async_save()
        self.stats["sweeps"] += 1
        self.stats["sweep_unknown_entries"] += files.unknown_entries
        self.stats["sweep_symlinks_skipped"] += files.symlinks_skipped
        self.stats["sweep_unindexed_kept"] += files.unindexed_kept
        report = SweepReport(
            checked_at=now,
            partial_deleted=files.partial_deleted,
            orphaned_moved=files.orphaned_moved,
            marked_missing=len(missing),
            symlinks_skipped=files.symlinks_skipped,
            unindexed_kept=files.unindexed_kept,
        )
        self.last_sweep = report
        if files.symlinks_skipped:
            _LOGGER.warning(
                "Version store sweep: %d symbolic link(s) in the backup folder "
                "left alone (never followed)",
                files.symlinks_skipped,
            )
        if files.unindexed_kept:
            _LOGGER.warning(
                "Version store sweep: %d file(s) without an index entry kept in "
                "place (index %s); rebuilding the index is not automatic",
                files.unindexed_kept,
                "recovered" if self.index_recovered_at else "empty",
            )
            self._emit(
                CoreEventType.STORE_RECOVERED,
                severity=Severity.WARNING,
                result=EventResult.FAILURE,
                data={
                    "store": CONFIG_CATALOG_STORE_KEY,
                    "index_state": "recovered" if self.index_recovered_at else "empty",
                    "index_recovered_at": self.index_recovered_at,
                    "unindexed_files_kept": files.unindexed_kept,
                },
            )
        if (
            report.partial_deleted
            or report.orphaned_moved
            or report.marked_missing
            or report.symlinks_skipped
        ):
            self._emit(
                CoreEventType.STORAGE_SWEPT,
                severity=Severity.WARNING if missing else Severity.INFO,
                data={
                    **report.to_dict(),
                    "unknown_entries": files.unknown_entries,
                    "missing_version_ids": sorted(r.backup_id for r in missing)[:50],
                },
            )
            for record in missing:
                self._emit(
                    CoreEventType.INTEGRITY_FAILED,
                    router_id=record.router_id,
                    severity=Severity.WARNING,
                    result=EventResult.FAILURE,
                    dedup_key=f"{record.backup_id}:missing",
                    data={"version_id": record.backup_id, "status": "missing"},
                )
        return report

    def _next_created_at(self) -> datetime:
        """Clock time, but strictly after every created_at handed out before.

        Call with ``self._lock`` held. Equal clock readings (Windows returns
        the same microsecond for quick consecutive calls) and a clock that
        steps back would otherwise give two versions the same or a reversed
        order (history sorts by created_at, ties by the random id).
        """
        now = self.now()
        last = self._last_created_at
        if last is not None and now <= last:
            now = last + timedelta(microseconds=1)
            self.stats["created_at_adjusted"] += 1
        self._last_created_at = now
        return now

    async def async_archive_router(
        self, router_id: str, *, entry_id: str | None = None
    ) -> bool:
        """Move a removed router's folder to ``removed/<router_id>/``.

        Its index entries stay (history) and are marked ``missing`` by the
        next sweep; nothing is ever deleted automatically. Audited
        (``configuration.router_archived``) whether or not a folder existed.
        Returns True if a folder was moved.
        """
        self._require_loaded()
        router_dir = self._router_dir(router_id)  # validates the id
        root = os.path.dirname(router_dir)
        try:
            moved = await self.hass.async_add_executor_job(
                _archive_dir, root, router_id, time.time()
            )
        except OSError as err:
            self._emit(
                CoreEventType.ROUTER_ARCHIVED,
                router_id=router_id,
                entry_id=entry_id,
                severity=Severity.WARNING,
                result=EventResult.FAILURE,
                data={"moved": False, "cause": type(err).__name__},
            )
            raise StorageError(
                "Archiving the router folder failed",
                router_id=router_id,
                details={"cause": type(err).__name__},
            ) from err
        if moved:
            self.stats["archived_routers"] += 1
        else:
            self.stats["archive_missing_folder"] += 1
        self._emit(
            CoreEventType.ROUTER_ARCHIVED,
            router_id=router_id,
            entry_id=entry_id,
            data={
                "moved": bool(moved),
                "target": f"{CONFIG_BACKUP_REMOVED_DIR}/{router_id}" if moved else None,
                "versions": len(self.records(router_id)),
            },
        )
        return bool(moved)

    # -- diagnostics -----------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Counts, sizes and the key STATE (never the key or its id)."""
        status: dict[str, int] = {}
        validation: dict[str, int] = {}
        for record in self._records.values():
            status[record.status.value] = status.get(record.status.value, 0) + 1
            key = record.validation.status.value
            validation[key] = validation.get(key, 0) + 1
        return {
            "loaded": self.loaded,
            "storage_available": self.storage_available,
            "versions": len(self._records),
            "routers": len(self.router_ids()),
            "protected": sum(1 for r in self._records.values() if r.protected),
            "status": status,
            "validation": validation,
            "total_bytes": self.usage_bytes(),
            "router_limit_bytes": self.router_limit,
            "total_limit_bytes": self.total_limit,
            "drift_acks": sum(len(a) for a in self._acks.values()),
            "rebaseline_pending": len(self._rebaseline),
            "installation_key_state": self._key_state.value,
            "index_recovered_at": self.index_recovered_at,
            "last_sweep": None
            if self.last_sweep is None
            else self.last_sweep.to_dict(),
            **self.stats,
        }

    # -- helpers ---------------------------------------------------------------------

    def _emit(self, event_type: CoreEventType, **kwargs: Any) -> None:
        try:
            self.audit.emit(event_type, source=CORE_SOURCE, **kwargs)
        except Exception:
            _LOGGER.warning(
                "Core event %s could not be recorded", event_type, exc_info=True
            )


def version_error_class(err: BaseException) -> ErrorClass:
    """error_class of a store/provider failure (for backup_failed).

    Call-time classes (``NON_PERSISTED_ERROR_CLASSES``) map to the stored
    class closest to them: rate limited -> busy, safety refused -> denied.
    """
    if isinstance(err, ConfigApiError):
        return _STORED_ERROR_CLASS.get(err.error_class, err.error_class)
    return ErrorClass.INTERNAL


_STORED_ERROR_CLASS: dict[ErrorClass, ErrorClass] = {
    ErrorClass.RATE_LIMITED: ErrorClass.BUSY,
    ErrorClass.SAFETY_REFUSED: ErrorClass.DENIED,
}


__all__ = [
    "VersionStore",
    "migrate_catalog_store",
    "migrate_key_store",
    "version_error_class",
]
