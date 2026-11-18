"""Configuration manager runtime: wires the backup engine into the core.

Plan: docs/plans/2026-11-18-config-manager-integration.md, sections 1, 3-5.

One :class:`ConfigManagerRuntime` per HA instance in
``hass.data[DATA_CONFIG_MANAGER]``, reference-counted per config entry. The
first entry registers the provider (``ConfigManagerProvider``) with the
running enterprise core; the last release unregisters it, stops the timer,
unsubscribes and cancels every task. A foreign provider in the single slot
keeps the runtime passive (``provider_conflict``).

The runtime holds memory only (no store of its own): the schedule state is
rebuilt from the version index (``api.async_list_backups``) and the audit
(``api.events``) at start. Every router contact goes through the
Configuration API, which calls the provider; this module never talks to a
router itself. ``coordinator.py`` is not touched: the drift trigger listens
to finished polls from outside (``coordinator.async_add_listener``).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections.abc import Callable, Coroutine, Iterable
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.util import dt as dt_util

from .const import (
    CONFIG_MANAGER_MODULE,
    CONFIG_STATUS_DISABLED,
    CONFIG_STATUS_FAILED,
    CONFIG_STATUS_NEVER,
    CONFIG_STATUS_RUNNING,
    DATA_CONFIG_MANAGER,
    SIGNAL_CONFIG_MANAGER,
)
from .core_errors import ConfigApiError, ProviderConflictError
from .core_models import (
    MAX_LIST_LIMIT,
    OPTION_CONFIG_BACKUP_ENABLED,
    Actor,
    BackupReason,
    BackupRecord,
    CoreEvent,
    CoreEventType,
)

_LOGGER = logging.getLogger(__name__)

# Bus types that change what the runtime shows (refresh from the store).
_EVENT_PREFIXES = ("configuration.",)
_EVENT_TYPES = frozenset(
    {
        str(CoreEventType.ROUTER_ADOPTED),
        "security.config_option_changed",
    }
)

ProviderFactory = Callable[[HomeAssistant], Any]


def _default_provider(hass: HomeAssistant) -> Any:
    """The real backup engine (imported late: it pulls in the archive code)."""
    from .config_provider import ConfigManagerProvider

    return ConfigManagerProvider(hass)


@dataclass
class RouterState:
    """Memory of one router (rebuilt from the store after a restart)."""

    router_id: str
    entry_id: str
    # --- what the store says (refreshed after every relevant event)
    version_count: int = 0
    last_backup_at: datetime | None = None  # newest usable version
    newest_status: str | None = None  # status of the newest version
    newest_error_class: str | None = None
    newest_ok_release: str | None = None  # openwrt_version of the newest usable
    # --- own attempts and failures seen on the bus
    running: bool = False
    last_attempt_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_error_class: str | None = None
    # --- schedule memory (section 3)
    last_scheduled_day: date | None = None
    retry_at: datetime | None = None
    retried_day: date | None = None
    last_fp: str | None = None
    fp_changed_at: datetime | None = None
    last_drift_at: datetime | None = None
    drift_day: date | None = None
    drift_versions_today: int = 0
    release_seen: dict[str, datetime] = field(default_factory=dict)
    release_done: set[str] = field(default_factory=set)
    # --- drift summary (from the last check or the audit at start)
    drift: dict[str, Any] | None = None
    drift_ids: set[str] = field(default_factory=set)
    loaded: bool = False


def _local_day(when: datetime | None) -> date | None:
    return None if when is None else dt_util.as_local(when).date()


class ConfigManagerRuntime:
    """Provider registration, schedule, drift trigger and the shown state."""

    def __init__(
        self,
        hass: HomeAssistant,
        core: Any,
        api: Any,
        *,
        provider_factory: ProviderFactory | None = None,
    ) -> None:
        """Bind to the running core; nothing is registered before start()."""
        self.hass = hass
        self.core = core
        self.api = api
        self.provider_factory = provider_factory or _default_provider
        # Salt of the user pseudonyms in responses (per HA session).
        self.salt = secrets.token_bytes(16)
        self.now: Callable[[], datetime] = dt_util.now
        self.module_actor = Actor.for_module(CONFIG_MANAGER_MODULE)
        self.entries: dict[str, Any] = {}
        self.coordinators: dict[str, Any] = {}
        self.routers: dict[str, RouterState] = {}
        self.provider: Any = None
        self.provider_conflict = False
        self.closed = False
        self._unregister: Callable[[], None] | None = None
        self._unsubscribe: Callable[[], None] | None = None
        self._entry_unsubs: dict[str, list[Callable[[], None]]] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        self._refresh_pending: set[str] = set()
        self.stats: dict[str, int] = {
            "runs_started": 0,
            "runs_failed": 0,
            "refreshes": 0,
        }

    # -- lifecycle ---------------------------------------------------------------------

    @property
    def provider_registered(self) -> bool:
        """True while OUR provider holds the core's slot."""
        return self.provider is not None and not self.provider_conflict

    @callback
    def start(self) -> None:
        """Register the provider once and subscribe to the core's events."""
        if self.api.provider_id is None:
            provider = self.provider_factory(self.hass)
            try:
                self._unregister = self.api.register_provider(provider)
            except ProviderConflictError:
                self.provider_conflict = True
            else:
                self.provider = provider
        else:
            self.provider_conflict = True
        if self.provider_conflict:
            _LOGGER.warning(
                "Another configuration provider is registered; the "
                "configuration manager stays passive"
            )
        self._unsubscribe = self.api.subscribe(self._on_core_event)

    async def async_attach(self, entry: Any, coordinator: Any) -> RouterState | None:
        """Track one config entry (its router id comes from the registry)."""
        entry_id = entry.entry_id
        self.entries[entry_id] = entry
        self.coordinators[entry_id] = coordinator
        router_id = self._router_id_of(entry_id)
        if router_id is None:
            return None
        state = self.routers.get(router_id)
        if state is None or state.entry_id != entry_id:
            state = RouterState(router_id=router_id, entry_id=entry_id)
            self.routers[router_id] = state
        await self._async_load_state(state)
        return state

    @callback
    def release(self, entry_id: str) -> None:
        """Forget one entry; the last one closes the runtime (idempotent)."""
        if self.closed:
            return
        for unsub in self._entry_unsubs.pop(entry_id, []):
            try:
                unsub()
            except Exception:  # noqa: BLE001 - listener already gone
                _LOGGER.debug("Listener of %s already removed", entry_id)
        self.entries.pop(entry_id, None)
        self.coordinators.pop(entry_id, None)
        for router_id in [
            rid for rid, s in self.routers.items() if s.entry_id == entry_id
        ]:
            del self.routers[router_id]
        if not self.entries:
            self.close()

    @callback
    def close(self) -> None:
        """Stop everything and unregister the provider (idempotent)."""
        if self.closed:
            return
        self.closed = True
        self._stop_timers()
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        for unsubs in self._entry_unsubs.values():
            for unsub in unsubs:
                try:
                    unsub()
                except Exception:  # noqa: BLE001 - listener already gone
                    _LOGGER.debug("Listener already removed")
        self._entry_unsubs.clear()
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()
        if self._unregister is not None:
            self._unregister()
            self._unregister = None
        self.provider = None
        if self.hass.data.get(DATA_CONFIG_MANAGER) is self:
            self.hass.data.pop(DATA_CONFIG_MANAGER, None)

    @callback
    def _stop_timers(self) -> None:
        """Cancel the timers (none in this part)."""

    def _spawn(self, coro: Coroutine[Any, Any, Any], name: str) -> asyncio.Task[Any]:
        """A background task that ends with the runtime."""
        task = self.hass.async_create_background_task(coro, name)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # -- lookups -----------------------------------------------------------------------

    def _router_id_of(self, entry_id: str) -> str | None:
        try:
            return self.api.registry.get_by_entry(entry_id).router_id
        except ConfigApiError:
            return None

    def state_for_entry(self, entry_id: str) -> RouterState | None:
        """The router state of a config entry (None before the first attach)."""
        return next((s for s in self.routers.values() if s.entry_id == entry_id), None)

    def options(self, router_id: str) -> Any:
        """Options of the router's config entry (empty if unknown)."""
        state = self.routers.get(router_id)
        entry = self.entries.get(state.entry_id) if state is not None else None
        return getattr(entry, "options", None) or {}

    def enabled(self, router_id: str) -> bool:
        """``config_backup_enabled`` of the router's entry (default OFF)."""
        return self.options(router_id).get(OPTION_CONFIG_BACKUP_ENABLED) is True

    def status(self, router_id: str) -> str:
        """ok, partial, failed, running, disabled or never."""
        state = self.routers.get(router_id)
        if state is None or not self.enabled(router_id):
            return CONFIG_STATUS_DISABLED
        if state.running:
            return CONFIG_STATUS_RUNNING
        newest = state.last_backup_at
        if state.last_failure_at is not None and (
            newest is None or state.last_failure_at > newest
        ):
            return CONFIG_STATUS_FAILED
        if state.newest_status is None:
            return CONFIG_STATUS_NEVER
        return state.newest_status

    def error_class(self, router_id: str) -> str | None:
        """Error class behind a failed / partial status."""
        state = self.routers.get(router_id)
        if state is None:
            return None
        status = self.status(router_id)
        if status == CONFIG_STATUS_FAILED and state.last_error_class:
            return state.last_error_class
        if status in ("partial", CONFIG_STATUS_FAILED):
            return state.newest_error_class
        return None

    # -- memory from the store ---------------------------------------------------------

    async def _async_load_state(self, state: RouterState) -> None:
        """First fill: versions, drift summary and failures from the audit."""
        await self.async_refresh(state.router_id)
        if state.loaded:
            return
        state.loaded = True
        try:
            events = self.api.events(
                router_id=state.router_id,
                types=[
                    str(CoreEventType.DRIFT_DETECTED),
                    str(CoreEventType.DRIFT_ACKNOWLEDGED),
                ],
                limit=20,
            )
        except Exception:  # noqa: BLE001 - audit not readable: start empty
            _LOGGER.debug("Audit of %s not readable", state.router_id)
            events = ()
        self._drift_from_events(state, events)

    def _drift_from_events(self, state: RouterState, events: Iterable[Any]) -> None:
        """Drift summary from the newest detection and its acknowledgement."""
        acks: dict[str, str] = {}
        for event in events:  # newest first
            data = getattr(event, "data", None) or {}
            drift_id = data.get("drift_id")
            if not isinstance(drift_id, str):
                continue
            if event.type == str(CoreEventType.DRIFT_ACKNOWLEDGED):
                acks.setdefault(drift_id, str(data.get("state") or "acknowledged"))
                continue
            state.drift_ids.add(drift_id)
            if state.drift is None:
                state.drift = {
                    "state": acks.get(drift_id, "open"),
                    "drift_id": drift_id,
                    "critical_count": int(data.get("critical_count") or 0),
                    "unknown_count": int(data.get("unknown_count") or 0),
                    "comparison": data.get("comparison"),
                    "baseline_backup_id": data.get("baseline_version_id"),
                    "checked_at": event.ts,
                }

    async def async_refresh(self, router_id: str) -> None:
        """Re-read the router's versions from the store (no router call)."""
        state = self.routers.get(router_id)
        if state is None or self.closed:
            return
        try:
            records = await self.api.async_list_backups(router_id, limit=MAX_LIST_LIMIT)
        except ConfigApiError:
            _LOGGER.debug("Versions of %s not readable", router_id)
            return
        self.stats["refreshes"] += 1
        self._apply_records(state, records)
        self._notify(router_id)

    def _apply_records(
        self, state: RouterState, records: Iterable[BackupRecord]
    ) -> None:
        records = list(records)  # newest first
        state.version_count = len(records)
        newest = records[0] if records else None
        state.newest_status = None if newest is None else str(newest.status)
        state.newest_error_class = (
            None
            if newest is None or newest.error_class is None
            else str(newest.error_class)
        )
        usable = next((r for r in records if r.usable), None)
        state.last_backup_at = None if usable is None else usable.created_at
        state.newest_ok_release = None if usable is None else usable.openwrt_version
        today = _local_day(self.now())
        for record in records:
            if record.reason is BackupReason.SCHEDULED:
                for when in (record.created_at, record.last_seen_at):
                    day = _local_day(when)
                    if day is not None and (
                        state.last_scheduled_day is None
                        or day > state.last_scheduled_day
                    ):
                        state.last_scheduled_day = day
            elif (
                record.reason is BackupReason.RELEASE_CHANGE and record.openwrt_version
            ):
                state.release_done.add(record.openwrt_version)
        drift_today = sum(
            1
            for r in records
            if r.reason is BackupReason.DRIFT and _local_day(r.created_at) == today
        )
        if state.drift_day != today:
            state.drift_day = today
            state.drift_versions_today = 0
        state.drift_versions_today = max(state.drift_versions_today, drift_today)

    @callback
    def _notify(self, router_id: str) -> None:
        async_dispatcher_send(self.hass, SIGNAL_CONFIG_MANAGER, router_id)

    # -- core events -------------------------------------------------------------------

    @callback
    def _on_core_event(self, event: CoreEvent) -> None:
        """Bus listener: refresh the router the event is about."""
        if self.closed:
            return
        event_type = str(event.type)
        if event_type not in _EVENT_TYPES and not event_type.startswith(
            _EVENT_PREFIXES
        ):
            return
        if event_type == str(CoreEventType.ROUTER_ADOPTED):
            self._rebind(event.entry_id)
        router_id = event.router_id
        state = self.routers.get(router_id) if router_id else None
        if state is None:
            return
        if event_type == str(CoreEventType.BACKUP_FAILED):
            data = event.data or {}
            state.last_failure_at = event.ts
            error_class = data.get("error_class")
            state.last_error_class = (
                error_class if isinstance(error_class, str) else None
            )
        if router_id in self._refresh_pending:
            return
        self._refresh_pending.add(router_id)
        self._spawn(self._async_refresh_soon(router_id), "config_manager_refresh")

    async def _async_refresh_soon(self, router_id: str) -> None:
        self._refresh_pending.discard(router_id)
        await self.async_refresh(router_id)

    @callback
    def _rebind(self, entry_id: str | None) -> None:
        """An adoption moved an entry to another router id."""
        if entry_id is None or entry_id not in self.entries:
            return
        new_id = self._router_id_of(entry_id)
        old = self.state_for_entry(entry_id)
        if new_id is None or (old is not None and old.router_id == new_id):
            return
        if old is not None:
            del self.routers[old.router_id]
        self.routers[new_id] = RouterState(router_id=new_id, entry_id=entry_id)
        self._spawn(
            self._async_load_state(self.routers[new_id]), "config_manager_rebind"
        )


# -- module entry points --------------------------------------------------------------


def async_get_runtime(hass: HomeAssistant) -> ConfigManagerRuntime | None:
    """The running runtime or None (never creates one)."""
    data = getattr(hass, "data", None)
    runtime = data.get(DATA_CONFIG_MANAGER) if isinstance(data, dict) else None
    if isinstance(runtime, ConfigManagerRuntime) and not runtime.closed:
        return runtime
    return None


async def async_setup_config_manager(
    hass: HomeAssistant,
    entry: Any,
    coordinator: Any,
    *,
    provider_factory: ProviderFactory | None = None,
) -> ConfigManagerRuntime | None:
    """Attach ``entry``; the first one creates the runtime (plan section 1)."""
    from .config_api import async_get_configuration_api
    from .enterprise_core import async_get_core

    core = async_get_core(hass)
    if core is None:
        return None
    api = await async_get_configuration_api(hass, 1)
    runtime = async_get_runtime(hass)
    if runtime is None or runtime.core is not core:
        if runtime is not None:
            runtime.close()  # a stale runtime of an older core
        runtime = ConfigManagerRuntime(
            hass, core, api, provider_factory=provider_factory
        )
        hass.data[DATA_CONFIG_MANAGER] = runtime
        runtime.start()
        if runtime.provider_registered:
            # register_provider schedules one probe task per attached router.
            # Give them their first step now: with the option off they finish
            # at once (no router contact) instead of being cancelled unstarted
            # by an early unload.
            await asyncio.sleep(0)
    await runtime.async_attach(entry, coordinator)
    entry.async_on_unload(_release_callback(runtime, entry.entry_id))
    return runtime


def _release_callback(
    runtime: ConfigManagerRuntime, entry_id: str
) -> Callable[[], None]:
    @callback
    def _release() -> None:
        runtime.release(entry_id)

    return _release


@callback
def async_release_config_manager(hass: HomeAssistant, entry_id: str) -> None:
    """Called by ``async_unload_entry`` before the core lets go of the entry."""
    runtime = async_get_runtime(hass)
    if runtime is not None:
        runtime.release(entry_id)


__all__ = [
    "ConfigManagerRuntime",
    "RouterState",
    "async_get_runtime",
    "async_release_config_manager",
    "async_setup_config_manager",
]
