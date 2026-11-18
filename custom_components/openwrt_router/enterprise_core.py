"""Enterprise core: router identity, fleet registry, audit, guard, versions.

One :class:`EnterpriseCore` per HA instance, kept under the single key
``hass.data[DATA_ENTERPRISE_CORE]`` (``openwrt_router_enterprise_core``),
never in a module-level singleton. It holds the :class:`RouterRegistry`,
the :class:`AuditLog` (part 1), the :class:`ActionGuard`, the
:class:`VersionStore` and the :class:`ConfigurationManager` (part 2).
Modules reach part 2 only through
:func:`.config_api.async_get_configuration_api`.

Lifecycle (wired in ``__init__.py``, each call wrapped so a core error
never fails setup, a poll or an unload):

* :func:`async_setup_entry_core` ``(hass, entry)`` early in setup, BEFORE
  the router login: assigns the router id. Called again with the
  coordinator once it exists: attaches the poll listener.
* :func:`async_unload_entry_core`: detaches the entry; the LAST entry
  releases the core (listeners cancelled, stores flushed, key removed).
* :func:`async_remove_entry_core`: orphans the entry's record (kept, never
  deleted), also when the core is already released.

Release and reload: the released core is removed from ``hass.data``
first, then flushed while holding a flush claim; a new core waits for
that claim before it loads, so a quick reload sees the flushed state.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from dataclasses import dataclass, field
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback

from .config_api import ConfigurationManager
from .const import DOMAIN
from .core_audit import AuditLog
from .core_guard import ActionGuard
from .core_models import DATA_ENTERPRISE_CORE, RouterRecord
from .core_security import SecurityActions, SshPinRegistry
from .router_registry import RouterRegistry
from .version_store import VersionStore

_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class _CoreSlot:
    """What lives under ``hass.data[DATA_ENTERPRISE_CORE]``."""

    core: EnterpriseCore | None = None
    # Set while a released core (or a removal) writes its stores.
    flush: asyncio.Future[None] | None = None
    releases: int = 0
    stats: dict[str, int] = field(default_factory=dict)


def _slot(hass: HomeAssistant) -> _CoreSlot:
    slot = hass.data.get(DATA_ENTERPRISE_CORE)
    if not isinstance(slot, _CoreSlot):
        slot = _CoreSlot()
        hass.data[DATA_ENTERPRISE_CORE] = slot
    return slot


class EnterpriseCore:
    """Registry, audit, guard, versions and config API of all entries."""

    def __init__(
        self, hass: HomeAssistant, *, claim: asyncio.Future[None] | None = None
    ) -> None:
        """Create the services; :meth:`async_load` reads their stores."""
        self.hass = hass
        self.audit = AuditLog(hass)
        self.registry = RouterRegistry(hass, self.audit)
        self.guard = ActionGuard(hass, self.audit)
        self.versions = VersionStore(hass, self.audit, consume=self.guard.consume)
        self.manager = ConfigurationManager(
            hass,
            audit=self.audit,
            registry=self.registry,
            guard=self.guard,
            versions=self.versions,
        )
        # Adoption goes through the guard (admin user, consumed once).
        self.registry.set_adopt_authorizer(self.manager.async_authorize_adopt)
        self.registry.set_authorization_consumer(self.manager.consume_adopt)
        self.registry.set_probe_listener(self.manager.on_probe_trigger)
        # SSH host-key pins + ACL deploy / pin approval flows (1.44.0).
        self.pins = SshPinRegistry(hass, self.audit)
        self.security = SecurityActions(self.manager, self.pins)
        self.manager.security = self.security
        self.load_errors: dict[str, int] = {}
        self._claim = claim
        self._entries: set[str] = set()
        self._unload_hooked: set[str] = set()
        self._load_lock = asyncio.Lock()
        self.loaded = False
        self.closed = False

    async def async_load(self) -> None:
        """Load audit first (the registry reports into it), then the registry."""
        async with self._load_lock:
            if self.loaded:
                return
            await _async_wait_for_flush(self.hass, own=self._claim)
            await self.audit.async_load()
            known = [e.entry_id for e in _domain_entries(self.hass)]
            await self.registry.async_load(known)
            # The version store must never fail setup: on an error it stays
            # unloaded and refuses every write (StorageError not_loaded).
            for name, step in (
                ("versions", self.versions.async_load),
                ("sweep", self.versions.async_sweep),
                ("ssh_pins", self.pins.async_load),
            ):
                if name == "sweep" and not self.versions.loaded:
                    continue  # counted as a "versions" load error already
                try:
                    await step()
                except Exception:
                    self.load_errors[name] = self.load_errors.get(name, 0) + 1
                    _LOGGER.warning(
                        "Enterprise core: version store %s failed (see load_errors)",
                        name,
                        exc_info=True,
                    )
            self.loaded = True

    @property
    def entry_ids(self) -> frozenset[str]:
        """Entries whose setup ran the core hook and that are not unloaded."""
        return frozenset(self._entries)

    @callback
    def track_entry(self, entry: ConfigEntry) -> None:
        """Remember the entry; on a failed setup HA's unload hook forgets it."""
        self._entries.add(entry.entry_id)
        if entry.entry_id in self._unload_hooked:
            return
        self._unload_hooked.add(entry.entry_id)
        entry_id = entry.entry_id
        hass = self.hass

        def _on_entry_unload() -> Coroutine[Any, Any, None] | None:
            # Runs after async_unload_entry and after a failed setup
            # (setup_retry). The normal unload has released already. A
            # returned coroutine is run and awaited by HA as an entry task.
            self._unload_hooked.discard(entry_id)
            if self.closed:
                return None
            self.forget_entry(entry_id)
            if self._entries:
                return None
            return _async_release(hass, self)

        entry.async_on_unload(_on_entry_unload)

    @callback
    def forget_entry(self, entry_id: str) -> None:
        """Detach the entry's listener and drop it from the live set."""
        self.registry.detach(entry_id)
        self._entries.discard(entry_id)

    @callback
    def close(self) -> None:
        """Cancel listeners and probes, drop the provider, expire approvals."""
        self.closed = True
        for name, close in (
            ("manager", self.manager.close),
            ("guard", self.guard.close),
            ("versions", self.versions.close),
            ("ssh_pins", self.pins.close),
            ("registry", self.registry.close),
            ("audit", self.audit.close),
        ):
            try:
                close()
            except Exception:
                _LOGGER.warning(
                    "Enterprise core: closing the %s failed", name, exc_info=True
                )

    async def async_flush(self) -> None:
        """Write every store now (each independently)."""
        for name, flush in (
            ("registry", self.registry.async_flush),
            ("versions", self.versions.async_flush),
            ("ssh_pins", self.pins.async_flush),
            ("audit", self.audit.async_flush),
        ):
            try:
                await flush()
            except Exception:
                _LOGGER.warning(
                    "Enterprise core: writing the %s store failed", name, exc_info=True
                )

    def summary(self) -> dict[str, Any]:
        """Diagnostics summary (counts only)."""
        return {
            "entries": len(self._entries),
            "registry": self.registry.summary(),
            "audit": self.audit.summary(),
            "guard": self.guard.summary(),
            "versions": self.versions.summary(),
            "configuration_api": self.manager.summary(),
            "ssh_pins": self.pins.summary(),
            "load_errors": dict(self.load_errors),
        }


def _domain_entries(hass: HomeAssistant) -> list[ConfigEntry]:
    try:
        entries = hass.config_entries.async_entries(DOMAIN)
    except Exception:
        _LOGGER.debug("Config entries not readable", exc_info=True)
        return []
    return list(entries) if isinstance(entries, list) else []


@callback
def async_get_core(hass: HomeAssistant) -> EnterpriseCore | None:
    """The running core or None (never creates one)."""
    slot = hass.data.get(DATA_ENTERPRISE_CORE)
    if isinstance(slot, _CoreSlot) and isinstance(slot.core, EnterpriseCore):
        return slot.core
    return None


async def async_get_enterprise_core(hass: HomeAssistant) -> EnterpriseCore:
    """Return the per-HA-instance core; create and load it lazily."""
    if not isinstance(hass.data, dict):
        # Only a real HomeAssistant (hass.data is a dict) can hold the core.
        raise TypeError("hass.data is not a dict; enterprise core not started")
    slot = _slot(hass)
    core = slot.core
    if core is None or core.closed:
        core = EnterpriseCore(hass)
        slot.core = core
    await core.async_load()
    return core


async def async_setup_entry_core(
    hass: HomeAssistant, entry: ConfigEntry, coordinator: Any = None
) -> RouterRecord:
    """Assign the router id (no router contact); attach the listener if given."""
    core = await async_get_enterprise_core(hass)
    core.track_entry(entry)
    record = await core.registry.async_ensure_entry(entry)
    if coordinator is not None:
        core.registry.attach(entry, coordinator)
    return record


async def async_unload_entry_core(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Detach the entry; release the core after the last one."""
    core = async_get_core(hass)
    if core is None:
        return
    core.forget_entry(entry.entry_id)
    if core.entry_ids:
        return
    await _async_release(hass, core)


async def async_remove_entry_core(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Orphan the removed entry's record (kept with its history)."""
    if not isinstance(hass.data, dict):
        raise TypeError("hass.data is not a dict; enterprise core not started")
    while True:
        await _async_wait_for_flush(hass)
        core = async_get_core(hass)
        if core is None:
            break
        await core.async_load()
        if core is async_get_core(hass):
            core.forget_entry(entry.entry_id)
            record = await core.registry.async_orphan_entry(entry.entry_id)
            await _async_archive_versions(core, record, entry.entry_id)
            return
    # No core running (last entry already unloaded): edit the stores with a
    # temporary core under a claim, so a racing setup loads after the write.
    slot = _slot(hass)
    claim = _claim(hass, slot)
    try:
        temp = EnterpriseCore(hass, claim=claim)
        await temp.async_load()
        record = await temp.registry.async_orphan_entry(entry.entry_id)
        await _async_archive_versions(temp, record, entry.entry_id)
        temp.close()
        await temp.async_flush()
    finally:
        _release_claim(slot, claim)


async def _async_archive_versions(
    core: EnterpriseCore, record: RouterRecord | None, entry_id: str
) -> None:
    """Move the removed router's version folder to ``removed/<router_id>/``.

    Never deletes, never fails the removal: an error is logged and counted
    (``archive_errors`` in load_errors); the store audits every attempt.
    """
    if record is None:
        return
    if not core.versions.loaded:
        core.load_errors["archive_skipped"] = (
            core.load_errors.get("archive_skipped", 0) + 1
        )
        _LOGGER.warning(
            "Enterprise core: version store not loaded, folder of %s not archived",
            record.router_id,
        )
        return
    try:
        await core.versions.async_archive_router(record.router_id, entry_id=entry_id)
    except Exception:
        core.load_errors["archive_errors"] = (
            core.load_errors.get("archive_errors", 0) + 1
        )
        _LOGGER.warning(
            "Enterprise core: archiving the versions of %s failed",
            record.router_id,
            exc_info=True,
        )


async def _async_release(hass: HomeAssistant, core: EnterpriseCore) -> None:
    """Remove ``core`` from hass.data, then flush it under a claim."""
    slot = _slot(hass)
    if slot.core is not core or core.entry_ids:
        return
    slot.core = None
    core.close()
    claim = _claim(hass, slot)
    try:
        await core.async_flush()
    finally:
        _release_claim(slot, claim)
        slot.releases += 1
    _LOGGER.debug("Enterprise core released (stores flushed)")


def _claim(hass: HomeAssistant, slot: _CoreSlot) -> asyncio.Future[None]:
    claim: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    slot.flush = claim
    return claim


def _release_claim(slot: _CoreSlot, claim: asyncio.Future[None]) -> None:
    if not claim.done():
        claim.set_result(None)
    if slot.flush is claim:
        slot.flush = None


async def _async_wait_for_flush(
    hass: HomeAssistant, own: asyncio.Future[None] | None = None
) -> None:
    """Wait until no released core or removal is writing the stores."""
    while True:
        slot = hass.data.get(DATA_ENTERPRISE_CORE)
        pending = slot.flush if isinstance(slot, _CoreSlot) else None
        if pending is None or pending.done() or pending is own:
            return
        await pending
