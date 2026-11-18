"""Versioned HA store of the enterprise core (registry, audit).

Each core store has a migrate function from day one (HA calls it when the
stored major/minor differ from the current ones). Loading follows the
engines (``net_engine``/``client_engine``): an unreadable or foreign store
is copied to ``<store>.bak`` once and the caller starts empty. The caller
decides what "empty" means; for the registry the router ids come back
deterministically (``default_router_id``), only adoption links can be lost.
"""

from __future__ import annotations

import logging
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
    ) -> None:
        """Create the store; ``migrate`` runs inside HA's load."""
        super().__init__(hass, version, key, minor_version=minor_version)
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
) -> Any:
    """Build the store (module-level so tests can swap the class)."""
    return CoreStore(hass, version, key, minor_version=minor_version, migrate=migrate)


@dataclass(slots=True)
class StoreLoad:
    """Outcome of :func:`async_load_store`."""

    data: dict[str, Any] | None
    failed: bool = False
    backed_up: bool = False


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
