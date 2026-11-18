"""Enterprise core, part 1: router identity, fleet registry, capabilities, audit.

One :class:`EnterpriseCore` per HA instance, kept under the single key
``hass.data[DATA_ENTERPRISE_CORE]`` (``openwrt_router_enterprise_core``),
never in a module-level singleton. It holds the :class:`RouterRegistry`
and the :class:`AuditLog`; part 2 adds the guard, the version store and
the ConfigurationManager next to them (see the ``# part 2`` seams).

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

from .const import DOMAIN
from .core_audit import AuditLog
from .core_models import DATA_ENTERPRISE_CORE, RouterRecord
from .router_registry import RouterRegistry

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
    """Registry + audit log of all openwrt_router entries."""

    def __init__(
        self, hass: HomeAssistant, *, claim: asyncio.Future[None] | None = None
    ) -> None:
        """Create the services; :meth:`async_load` reads their stores."""
        self.hass = hass
        self.audit = AuditLog(hass)
        self.registry = RouterRegistry(hass, self.audit)
        # part 2: self.guard, self.versions, self.manager
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
        """Cancel listeners; schedule no more writes."""
        self.closed = True
        self.registry.close()
        self.audit.close()

    async def async_flush(self) -> None:
        """Write both stores now (each independently)."""
        for name, flush in (
            ("registry", self.registry.async_flush),
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
            await core.registry.async_orphan_entry(entry.entry_id)
            return
    # No core running (last entry already unloaded): edit the stores with a
    # temporary core under a claim, so a racing setup loads after the write.
    slot = _slot(hass)
    claim = _claim(hass, slot)
    try:
        temp = EnterpriseCore(hass, claim=claim)
        await temp.async_load()
        await temp.registry.async_orphan_entry(entry.entry_id)
        temp.close()
        await temp.async_flush()
    finally:
        _release_claim(slot, claim)


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
