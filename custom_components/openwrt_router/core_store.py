"""Versioned HA store of the enterprise core (registry, audit).

Each core store has a migrate function from day one (HA calls it when the
stored major/minor differ from the current ones). Loading follows the
engines (``net_engine``/``client_engine``): an unreadable or foreign store
is copied to ``<store>.bak`` once and the caller starts empty. The caller
decides what "empty" means; for the registry the router ids come back
deterministically (``default_router_id``), only adoption links can be lost.

Home Assistant's own ``Store.async_load`` does not raise for a file that is
not valid JSON: it renames it to ``<file>.corrupt.<ISO time>``, opens its
own repair issue and returns None, exactly like a missing file. The loader
therefore looks for such a sibling when the store returns None and treats
it as a failed load (security review 2026-11-18, finding 13).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.storage import Store

from .net_engine import _backup_file

_LOGGER = logging.getLogger(__name__)

# (old_major, old_minor, old_data) -> data in the current format
StoreMigration = Callable[[int, int, Any], dict[str, Any]]


class CoreStore(Store[dict[str, Any]]):
    """HA ``Store`` with a migrate function given at construction."""

    def __init__(
        self,
        hass: HomeAssistant,
        version: int,
        key: str,
        *,
        minor_version: int,
        migrate: StoreMigration,
        private: bool = False,
        atomic_writes: bool = False,
    ) -> None:
        """Create the store; ``migrate`` runs inside HA's load.

        ``private`` (file mode 0600) and ``atomic_writes`` are HA's own
        ``Store`` options, used for stores that hold secrets.
        """
        super().__init__(
            hass,
            version,
            key,
            private=private,
            atomic_writes=atomic_writes,
            minor_version=minor_version,
        )
        self._migrate = migrate

    async def _async_migrate_func(
        self, old_major_version: int, old_minor_version: int, old_data: Any
    ) -> dict[str, Any]:
        """Hand the stored data to the module's migrate function."""
        return self._migrate(old_major_version, old_minor_version, old_data)


def create_store(
    hass: HomeAssistant,
    version: int,
    key: str,
    *,
    minor_version: int,
    migrate: StoreMigration,
    private: bool = False,
    atomic_writes: bool = False,
) -> Any:
    """Build the store (module-level so tests can swap the class)."""
    return CoreStore(
        hass,
        version,
        key,
        minor_version=minor_version,
        migrate=migrate,
        private=private,
        atomic_writes=atomic_writes,
    )


@dataclass(slots=True)
class StoreLoad:
    """Outcome of :func:`async_load_store`."""

    data: dict[str, Any] | None
    failed: bool = False
    backed_up: bool = False
    # Home Assistant's .corrupt.<time> copy, when it renamed the file
    corrupt_path: str | None = None


CORRUPT_INFIX = ".corrupt."


def _corrupt_copy(path: Any) -> str | None:
    """Newest ``<path>.corrupt.*`` sibling while ``path`` is gone (executor).

    Only meaningful right after the store returned None: Home Assistant
    renamed an unreadable file (missing main file + corrupt copy). A main
    file that exists means the store was written again since.
    """
    if not isinstance(path, str) or not path or os.path.exists(path):
        return None
    directory, base = os.path.split(path)
    prefix = base + CORRUPT_INFIX
    try:
        names = [n for n in os.listdir(directory or ".") if n.startswith(prefix)]
    except OSError:
        return None
    if not names:
        return None
    return os.path.join(directory, max(names))


async def async_load_store(hass: HomeAssistant, store: Any, key: str) -> StoreLoad:
    """Read ``store``; on any failure keep a ``.bak`` copy and return no data.

    Never raises. ``failed`` tells the caller to start empty and to report
    the recovery (log line + audit event), ``backed_up`` whether a copy of
    the unreadable file exists.
    """
    try:
        stored = await store.async_load()
    except Exception:
        _LOGGER.warning(
            "Enterprise core store %s could not be read; rebuilding it",
            key,
            exc_info=True,
        )
        return StoreLoad(None, True, await async_backup_store(hass, store, key))
    if stored is not None and not isinstance(stored, dict):
        _LOGGER.warning(
            "Enterprise core store %s has an unknown format; rebuilding it", key
        )
        return StoreLoad(None, True, await async_backup_store(hass, store, key))
    if stored is None:
        try:
            corrupt = await hass.async_add_executor_job(
                _corrupt_copy, getattr(store, "path", None)
            )
        except Exception:
            _LOGGER.debug("Store %s: corrupt-copy check failed", key, exc_info=True)
            corrupt = None
        if isinstance(corrupt, str):
            _LOGGER.warning(
                "Enterprise core store %s was unreadable; Home Assistant kept it "
                "as %s; rebuilding it",
                key,
                corrupt,
            )
            return StoreLoad(None, True, True, corrupt)
    return StoreLoad(stored)


async def async_backup_store(hass: HomeAssistant, store: Any, key: str) -> bool:
    """Copy the store file to ``<file>.bak`` (executor); never raises."""
    path = getattr(store, "path", None)
    try:
        copied = bool(await hass.async_add_executor_job(_backup_file, path))
    except Exception:
        _LOGGER.warning(
            "Enterprise core store %s: the backup copy failed; the next save "
            "replaces the unreadable file",
            key,
            exc_info=True,
        )
        return False
    if copied:
        _LOGGER.warning(
            "Enterprise core kept a copy of the unreadable store %s at %s.bak",
            key,
            path,
        )
    return copied


def _remove_copies(path: Any) -> int:
    """Delete ``<path>.bak`` and every ``<path>.corrupt.*`` (executor)."""
    if not isinstance(path, str) or not path:
        return 0
    directory, base = os.path.split(path)
    try:
        names = os.listdir(directory or ".")
    except OSError:
        return 0
    removed = 0
    for name in names:
        if name == base + ".bak" or name.startswith(base + CORRUPT_INFIX):
            try:
                os.remove(os.path.join(directory, name))
            except FileNotFoundError:
                continue
            removed += 1
    return removed


async def async_remove_copies(hass: HomeAssistant, store: Any, key: str) -> int:
    """Delete the ``.bak`` / ``.corrupt.*`` copies of a store (count).

    For data the user asked to delete: an old copy must not keep it
    (Time Machine review K4). Never raises.
    """
    try:
        return int(
            await hass.async_add_executor_job(
                _remove_copies, getattr(store, "path", None)
            )
        )
    except Exception:
        _LOGGER.warning("Store %s: its old copies were not deleted", key, exc_info=True)
        return 0
