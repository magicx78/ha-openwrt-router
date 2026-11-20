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
import hashlib
import logging
import math
import secrets
import unicodedata
from collections.abc import AsyncIterator, Callable, Coroutine, Iterable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from typing import Any

import voluptuous as vol
from homeassistant.const import ATTR_DEVICE_ID
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.util import dt as dt_util

from .config_const import (
    DRIFT_DEBOUNCE_S,
    DRIFT_MIN_INTERVAL_S,
    FETCH_RETRY_DELAY_S,
    MANUAL_BACKUP_MIN_GAP_S,
    MANUAL_LIVE_CHECK_MIN_GAP_S,
)
from .config_snapshot import fingerprint_from_coordinator
from .const import (
    CONF_PROTOCOL,
    CONFIG_BACKUP_SCHEDULE_DAILY,
    CONFIG_DRIFT_VERSIONS_PER_DAY,
    CONFIG_MANAGER_EVENT_PREFIX,
    CONFIG_MANAGER_MODULE,
    CONFIG_MANAGER_TICK_SECONDS,
    CONFIG_NOTE_MAX_LENGTH,
    CONFIG_RELEASE_CHANGE_DELAY_SECONDS,
    CONFIG_ROUTE_PSEUDONYM_PURPOSE,
    CONFIG_STAGGER_SECONDS,
    CONFIG_STATUS_DISABLED,
    CONFIG_STATUS_FAILED,
    CONFIG_STATUS_NEVER,
    CONFIG_STATUS_RUNNING,
    DATA_CONFIG_MANAGER,
    DEFAULT_CONFIG_BACKUP_SCHEDULE,
    DEFAULT_CONFIG_BACKUP_TIME,
    DEFAULT_CONFIG_DRIFT_CHECK,
    DEFAULT_PROTOCOL,
    DOMAIN,
    OPTION_CONFIG_BACKUP_SCHEDULE,
    OPTION_CONFIG_BACKUP_TIME,
    OPTION_CONFIG_DRIFT_CHECK,
    PROTOCOL_HTTP,
    SERVICE_CREATE_CONFIG_BACKUP,
    SIGNAL_CONFIG_MANAGER,
)
from .core_errors import (
    AuthorizationError,
    BackupNotFoundError,
    ConfigApiError,
    ErrorClass,
    OperationInProgressError,
    ProviderConflictError,
    RateLimitedError,
    RouterNotFoundError,
)
from .core_models import (
    MAX_LIST_LIMIT,
    OPTION_CONFIG_BACKUP_ENABLED,
    Actor,
    BackupReason,
    BackupRecord,
    BackupType,
    CapabilityReason,
    CapabilityState,
    CoreEvent,
    CoreEventType,
    DriftReport,
    EventResult,
    PutVersionResult,
    async_actor_from_context,
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

# Own audit type: the backup right is missing (once per router and day).
EVENT_BACKUP_BLOCKED = f"{CONFIG_MANAGER_EVENT_PREFIX}backup_blocked"
# _backup_blocker(): wait for a later tick (lock held, nothing known yet).
BLOCK_BUSY = "busy"
# _router_access(manual=...): kinds with their own minimum gap.
MANUAL_BACKUP = "backup"
MANUAL_LIVE = "live_check"
# Severity of the own audit entry (net_events.Severity value; not imported).
_SEVERITY_WARNING = "warning"

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
    # details.reason of our last failed run (e.g. insecure_transport); not
    # in the core's audit entry, so unknown again after a restart
    last_error_reason: str | None = None
    # day a missing backup right was logged and audited (once per day)
    blocked_day: date | None = None
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
    # drift ids that already got (or never get) an automatic drift version
    drift_versioned: set[str] = field(default_factory=set)
    loaded: bool = False


def _local_day(when: datetime | None) -> date | None:
    return None if when is None else dt_util.as_local(when).date()


def stagger_offset(router_id: str) -> timedelta:
    """Stable per-router offset after the daily time (plan section 3)."""
    digest = hashlib.sha256(router_id.encode("utf-8")).hexdigest()
    return timedelta(seconds=int(digest, 16) % CONFIG_STAGGER_SECONDS)


def _parse_time(value: Any) -> time:
    """``HH:MM[:SS]`` of the option; the default for anything odd."""
    parsed = dt_util.parse_time(value) if isinstance(value, str) else None
    return parsed or dt_util.parse_time(DEFAULT_CONFIG_BACKUP_TIME) or time(3, 30)


# Drift summary states besides the DriftAckState values.
DRIFT_OPEN = "open"
DRIFT_CLEAR = "clear"


def _drift_summary(
    *,
    drift_id: str | None,
    state: str,
    critical_count: Any,
    unknown_count: Any,
    comparison: Any,
    baseline_backup_id: Any,
    checked_at: datetime | None,
) -> dict[str, Any]:
    def count(value: Any) -> int:
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    return {
        "state": state,
        "drift_id": drift_id,
        "critical_count": count(critical_count),
        "unknown_count": count(unknown_count),
        "comparison": None if comparison is None else str(comparison),
        "baseline_backup_id": (
            baseline_backup_id if isinstance(baseline_backup_id, str) else None
        ),
        "checked_at": checked_at,
    }


# Job kinds of the worker, in priority order (lower runs first).
JOB_RELEASE = "release_change"
JOB_SCHEDULED = "scheduled"
JOB_DRIFT = "drift_check"
_JOB_PRIORITY = {JOB_RELEASE: 0, JOB_SCHEDULED: 1, JOB_DRIFT: 2}


@dataclass(frozen=True)
class _Job:
    router_id: str
    kind: str
    release: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.router_id, self.kind)


def validate_note(note: Any) -> str | None:
    """A note: <= 200 characters, no control characters; ``""`` -> None.

    Raises TypeError or ValueError (callers map them to their own error).
    """
    if note is None:
        return None
    if not isinstance(note, str):
        raise TypeError("note must be a string")
    note = note.strip()
    if len(note) > CONFIG_NOTE_MAX_LENGTH:
        raise ValueError("note too long")
    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in note):
        raise ValueError("note contains control characters")
    return note or None


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
        # Salt of the user pseudonyms in route answers: the module key
        # (contract §11.5), else random for this run (async_route_salt).
        self._route_salt: bytes | None = None
        self.route_salt_stable = False
        self._unregister_prefix: Callable[[], None] | None = None
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
        self._unsub_tick: Callable[[], None] | None = None
        # Router access of this module: one lock per router (strictly serial
        # per router) and, inside it, one fleet slot (parallelism 1), always
        # taken in that order. Scheduled, drift and manual runs, the service
        # and the live routes all go through _router_access(). The core never
        # waits on these locks (the provider the core calls takes none), so
        # holding them across a core call cannot deadlock with the core's own
        # backup queue.
        self._router_locks: dict[str, asyncio.Lock] = {}
        self._run_lock = asyncio.Lock()
        # (router_id, kind) -> start of the last manual backup / live check
        self._manual_at: dict[tuple[str, str], datetime] = {}
        self._queue: list[_Job] = []
        self._queued: set[tuple[str, str]] = set()
        self._worker: asyncio.Task[Any] | None = None
        self._current: _Job | None = None
        self.stats: dict[str, int] = {
            "runs_started": 0,
            "runs_failed": 0,
            "runs_deferred": 0,
            "runs_blocked": 0,
            "drift_checks": 0,
            "drift_versions": 0,
            "refreshes": 0,
            "ticks": 0,
            "route_salt_ephemeral": 0,
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
        try:
            self._unregister_prefix = self.api.register_event_prefix(
                CONFIG_MANAGER_EVENT_PREFIX, module=CONFIG_MANAGER_MODULE
            )
        except ValueError:
            # Another module holds the prefix: no module key, random salt.
            _LOGGER.warning(
                "Event prefix of the configuration manager is taken; "
                "pseudonyms in its answers change on every restart"
            )
        self._unsubscribe = self.api.subscribe(self._on_core_event)

    async def async_route_salt(self) -> bytes:
        """Salt of the user pseudonyms in route answers (never logged).

        The module key (contract §11.5, purpose
        ``CONFIG_ROUTE_PSEUDONYM_PURPOSE``) while the installation key is
        ``ok``: stable over restarts, like the core's bus pseudonym. Without
        a usable key (first start, key lost, prefix taken) a random salt for
        the rest of this run, counted and logged once; a route never creates
        the installation key. Decided once per runtime, so pseudonyms stay
        the same for the whole run.
        """
        if self._route_salt is not None:
            return self._route_salt
        salt: bytes | None = None
        reason = "prefix_unavailable"
        if self._unregister_prefix is not None:
            reason = str(getattr(self.api.installation_key_state, "value", "unknown"))
            if reason == "ok":
                try:
                    salt = await self.api.async_get_module_key(
                        CONFIG_MANAGER_MODULE, CONFIG_ROUTE_PSEUDONYM_PURPOSE
                    )
                except ConfigApiError as err:
                    reason = str(err.details.get("reason") or err.code)
        if self._route_salt is None:  # a concurrent call may have decided
            if salt is None:
                salt = secrets.token_bytes(16)
                self.stats["route_salt_ephemeral"] += 1
                _LOGGER.info(
                    "Configuration manager: no module key (%s); user pseudonyms "
                    "in its answers are random for this run",
                    reason,
                )
            else:
                self.route_salt_stable = True
            self._route_salt = salt
        return self._route_salt

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
        if entry_id not in self._entry_unsubs:
            add_listener = getattr(coordinator, "async_add_listener", None)
            if callable(add_listener):
                self._entry_unsubs[entry_id] = [
                    add_listener(self._poll_listener(entry_id))
                ]
        await self._async_load_state(state)
        self._sync_timer()
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
        gone = {rid for rid, s in self.routers.items() if s.entry_id == entry_id}
        for router_id in gone:
            del self.routers[router_id]
        if not self.entries:
            self.close()
            return
        self._drop_jobs(gone)
        self._sync_timer()

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
        self._queue.clear()
        self._queued.clear()
        self._worker = None
        for task in list(self._tasks):
            task.cancel()
        self._tasks.clear()
        if self._unregister is not None:
            self._unregister()
            self._unregister = None
        if self._unregister_prefix is not None:
            self._unregister_prefix()
            self._unregister_prefix = None
        self._route_salt = None
        self.provider = None
        if self.hass.data.get(DATA_CONFIG_MANAGER) is self:
            self.hass.data.pop(DATA_CONFIG_MANAGER, None)

    @callback
    def _stop_timers(self) -> None:
        """Cancel the schedule tick."""
        if self._unsub_tick is not None:
            self._unsub_tick()
            self._unsub_tick = None

    @callback
    def _sync_timer(self, *, force: bool = False) -> None:
        """The tick runs only while a router of ours has the option on.

        Option off everywhere (the default) -> no timer at all: nothing of
        the configuration manager runs in HA while idle. ``force``: an
        option was just switched on (entry options not stored yet).
        """
        wanted = (
            not self.closed
            and self.provider_registered
            and (force or any(self.enabled(rid) for rid in self.routers))
        )
        if wanted and self._unsub_tick is None:
            self._unsub_tick = async_track_time_interval(
                self.hass,
                self.async_tick,
                timedelta(seconds=CONFIG_MANAGER_TICK_SECONDS),
                name="openwrt_router configuration manager",
                cancel_on_shutdown=True,
            )
        elif not wanted:
            self._stop_timers()

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

    def cgi_transport_secure(self, router_id: str) -> bool:
        """False when the router's entry talks plain HTTP.

        Same rule as ``api.config_cgi_transport_secure`` (only ``http`` is
        insecure), read from the entry the api was built from, so the api
        object is not touched. An unknown router keeps the TLS behaviour.
        """
        state = self.routers.get(router_id)
        entry = self.entries.get(state.entry_id) if state is not None else None
        data = getattr(entry, "data", None) or {}
        return data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL) != PROTOCOL_HTTP

    def enabled(self, router_id: str) -> bool:
        """``config_backup_enabled`` of the router's entry (default OFF)."""
        return self.options(router_id).get(OPTION_CONFIG_BACKUP_ENABLED) is True

    def schedule_daily(self, router_id: str) -> bool:
        """Option on and schedule ``daily`` (odd stored values: the default)."""
        if not self.enabled(router_id):
            return False
        value = self.options(router_id).get(
            OPTION_CONFIG_BACKUP_SCHEDULE, DEFAULT_CONFIG_BACKUP_SCHEDULE
        )
        if not isinstance(value, str):
            value = DEFAULT_CONFIG_BACKUP_SCHEDULE
        return value == CONFIG_BACKUP_SCHEDULE_DAILY

    def drift_check_enabled(self, router_id: str) -> bool:
        """Option on and ``config_drift_check`` on (default on)."""
        if not self.enabled(router_id):
            return False
        value = self.options(router_id).get(
            OPTION_CONFIG_DRIFT_CHECK, DEFAULT_CONFIG_DRIFT_CHECK
        )
        return value if isinstance(value, bool) else DEFAULT_CONFIG_DRIFT_CHECK

    def _slot_day(self, router_id: str, when: datetime | None) -> date | None:
        """Day of the daily slot ``when`` belongs to (offset taken off).

        A run at 00:20 for a 23:30 time with a 50-minute offset still counts
        for the day before.
        """
        if when is None:
            return None
        return (dt_util.as_local(when) - stagger_offset(router_id)).date()

    def _today_slot(self, router_id: str) -> date:
        """The slot day the current time belongs to."""
        return (dt_util.as_local(self.now()) - stagger_offset(router_id)).date()

    def _slot_at(self, router_id: str, day: date) -> datetime:
        """When the daily run of ``day`` is due (time + offset, local)."""
        at = _parse_time(self.options(router_id).get(OPTION_CONFIG_BACKUP_TIME))
        start = datetime.combine(day, at, tzinfo=dt_util.get_default_time_zone())
        return start + stagger_offset(router_id)

    def next_run_at(self, router_id: str) -> datetime | None:
        """Next planned daily run (or its retry); None without a schedule."""
        state = self.routers.get(router_id)
        if state is None or not self.schedule_daily(router_id):
            return None
        today = self._today_slot(router_id)
        if state.retry_at is not None and state.last_scheduled_day != today:
            return state.retry_at
        if state.last_scheduled_day == today:
            return self._slot_at(router_id, today + timedelta(days=1))
        return self._slot_at(router_id, today)

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

    def error_reason(self, router_id: str) -> str | None:
        """Reason code behind a failed status (e.g. ``insecure_transport``)."""
        state = self.routers.get(router_id)
        if state is None or self.status(router_id) != CONFIG_STATUS_FAILED:
            return None
        return state.last_error_reason

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
        # Drifts seen before the restart get no further automatic version.
        state.drift_versioned |= state.drift_ids
        self._failure_from_audit(state)

    def _failure_from_audit(self, state: RouterState) -> None:
        """Newest failed attempt from the audit (survives an HA restart).

        A repeated failure is one deduplicated audit entry; its newest time is
        ``last_repeat_at``. ``status()`` reports failed only while that time
        is newer than the newest version.
        """
        try:
            events = self.api.events(
                router_id=state.router_id,
                types=[str(CoreEventType.BACKUP_FAILED), EVENT_BACKUP_BLOCKED],
                limit=20,
            )
        except Exception:  # noqa: BLE001 - audit not readable: no failure known
            _LOGGER.debug("Audit of %s not readable", state.router_id)
            return
        newest: Any = None
        newest_at: datetime | None = None
        for event in events:
            when = getattr(event, "last_repeat_at", None) or getattr(event, "ts", None)
            if isinstance(when, datetime) and (newest_at is None or when > newest_at):
                newest, newest_at = event, when
        if newest is None or newest_at is None:
            return
        if state.last_failure_at is None or newest_at > state.last_failure_at:
            data = getattr(newest, "data", None) or {}
            error_class = data.get("error_class")
            state.last_failure_at = newest_at
            state.last_error_class = (
                error_class if isinstance(error_class, str) else None
            )
            state.last_error_reason = None
        if state.last_attempt_at is None or newest_at > state.last_attempt_at:
            state.last_attempt_at = newest_at

    def _drift_from_events(self, state: RouterState, events: Iterable[Any]) -> None:
        """Drift summary from the newest detection and its acknowledgement.

        Acknowledgements count regardless of their position in the audit (a
        drift id, once acknowledged, stays acknowledged in the core).
        """
        events = list(events)  # newest first
        acks: dict[str, str] = {}
        for event in events:
            data = getattr(event, "data", None) or {}
            drift_id = data.get("drift_id")
            if isinstance(drift_id, str) and str(event.type) == str(
                CoreEventType.DRIFT_ACKNOWLEDGED
            ):
                acks.setdefault(drift_id, str(data.get("state") or "acknowledged"))
        for event in events:
            data = getattr(event, "data", None) or {}
            drift_id = data.get("drift_id")
            if not isinstance(drift_id, str) or str(event.type) != str(
                CoreEventType.DRIFT_DETECTED
            ):
                continue
            state.drift_ids.add(drift_id)
            if state.drift is None:
                state.drift = _drift_summary(
                    drift_id=drift_id,
                    state=acks.get(drift_id, DRIFT_OPEN),
                    critical_count=data.get("critical_count"),
                    unknown_count=data.get("unknown_count"),
                    comparison=data.get("comparison"),
                    baseline_backup_id=data.get("baseline_version_id"),
                    checked_at=event.ts,
                )

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
                    day = self._slot_day(state.router_id, when)
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
        data = event.data or {}
        if event_type == str(CoreEventType.BACKUP_FAILED):
            state.last_failure_at = event.ts
            error_class = data.get("error_class")
            state.last_error_class = (
                error_class if isinstance(error_class, str) else None
            )
        elif event_type == str(CoreEventType.DRIFT_DETECTED):
            drift_id = data.get("drift_id")
            if isinstance(drift_id, str):
                state.drift_ids.add(drift_id)
                state.drift = _drift_summary(
                    drift_id=drift_id,
                    state=DRIFT_OPEN,
                    critical_count=data.get("critical_count"),
                    unknown_count=data.get("unknown_count"),
                    comparison=data.get("comparison"),
                    baseline_backup_id=data.get("baseline_version_id"),
                    checked_at=event.ts,
                )
        elif event_type == str(CoreEventType.DRIFT_ACKNOWLEDGED):
            drift = state.drift
            if drift is not None and drift.get("drift_id") == data.get("drift_id"):
                drift["state"] = str(data.get("state") or "acknowledged")
        elif event_type == "security.config_option_changed":
            # Emitted before Home Assistant stores the new options: the
            # event's value counts here; the tick re-syncs the timer later.
            if data.get("new") is True:
                self._sync_timer(force=True)
            else:
                state.last_fp = None  # a fresh reference value when back on
                state.fp_changed_at = None
                self._sync_timer()
        self._schedule_refresh(router_id)

    @callback
    def _schedule_refresh(self, router_id: str) -> None:
        """One pending store re-read per router (coalesced)."""
        if self.closed or router_id in self._refresh_pending:
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
            self._migrate_entities(old.router_id, new_id)
        self.routers[new_id] = RouterState(router_id=new_id, entry_id=entry_id)
        self._spawn(
            self._async_load_state(self.routers[new_id]), "config_manager_rebind"
        )

    @callback
    def _migrate_entities(self, old_id: str, new_id: str) -> None:
        """Keep the entity ids of the entry's sensors across the adoption."""
        try:
            from .config_entities import async_migrate_config_unique_ids

            async_migrate_config_unique_ids(self.hass, old_id, new_id)
        except Exception:  # a registry problem never breaks the adoption
            _LOGGER.debug("Entity migration after adoption failed", exc_info=True)

    # -- drift trigger: coordinator listener (hash only, no router call) ---------------

    def _poll_listener(self, entry_id: str) -> Callable[[], None]:
        @callback
        def _on_poll() -> None:
            try:
                self._on_poll(entry_id)
            except Exception:  # never break a poll
                _LOGGER.debug("Drift trigger of %s failed", entry_id, exc_info=True)

        return _on_poll

    @callback
    def _on_poll(self, entry_id: str) -> None:
        """A finished poll: compare the configuration fingerprint."""
        if self.closed:
            return
        state = self.state_for_entry(entry_id)
        coordinator = self.coordinators.get(entry_id)
        if state is None or coordinator is None:
            return
        if not self.drift_check_enabled(state.router_id):
            state.last_fp = None
            state.fp_changed_at = None
            return
        if getattr(coordinator, "last_update_success", False) is not True:
            return
        fingerprint = fingerprint_from_coordinator(coordinator.data)
        if state.last_fp is None:
            state.last_fp = fingerprint  # reference value only, no check
            return
        if fingerprint != state.last_fp:
            state.last_fp = fingerprint
            state.fp_changed_at = self.now()

    # -- schedule (plan section 3) -----------------------------------------------------

    @callback
    def async_tick(self, _now: datetime | None = None) -> None:
        """The 5-minute tick: plan due runs in memory, start the worker."""
        if self.closed or not self.provider_registered:
            return
        self.stats["ticks"] += 1
        now = self.now()
        for state in list(self.routers.values()):
            if not self.enabled(state.router_id):
                continue
            try:
                self._plan(state, now)
            except Exception:  # one router never stops the rest
                _LOGGER.debug("Planning of %s failed", state.router_id, exc_info=True)
        self._sync_timer()
        self._ensure_worker()

    def _plan(self, state: RouterState, now: datetime) -> None:
        router_id = state.router_id
        release = self._release_due(state, now)
        if release is not None:
            self._enqueue(_Job(router_id, JOB_RELEASE, release))
        if self._scheduled_due(state, now):
            self._enqueue(_Job(router_id, JOB_SCHEDULED))
        if self._drift_due(state, now):
            self._enqueue(_Job(router_id, JOB_DRIFT))

    def _scheduled_due(self, state: RouterState, now: datetime) -> bool:
        router_id = state.router_id
        if not self.schedule_daily(router_id):
            return False
        today = self._today_slot(router_id)
        if state.last_scheduled_day is not None and state.last_scheduled_day >= today:
            return False
        if state.retry_at is not None:
            if state.retried_day == today:
                return now >= state.retry_at
            state.retry_at = None  # a retry of an earlier day
        return now >= self._slot_at(router_id, today)

    def _release_due(self, state: RouterState, now: datetime) -> str | None:
        """New firmware release against the newest usable version (L3)."""
        record = self.api.registry.find(state.router_id)
        current = getattr(getattr(record, "firmware", None), "version", None)
        stored = state.newest_ok_release
        if (
            not isinstance(current, str)
            or not current
            or not stored
            or current == stored
            or current in state.release_done
        ):
            return None
        seen = state.release_seen.setdefault(current, now)
        if now - seen < timedelta(seconds=CONFIG_RELEASE_CHANGE_DELAY_SECONDS):
            return None
        return current

    def _drift_due(self, state: RouterState, now: datetime) -> bool:
        if state.fp_changed_at is None or not self.drift_check_enabled(state.router_id):
            return False
        if state.last_backup_at is None:
            state.fp_changed_at = None  # no baseline yet: the daily run first
            return False
        if now - state.fp_changed_at < timedelta(seconds=DRIFT_DEBOUNCE_S):
            return False
        return state.last_drift_at is None or now - state.last_drift_at >= timedelta(
            seconds=DRIFT_MIN_INTERVAL_S
        )

    # -- worker: one job at a time -----------------------------------------------------

    @callback
    def _enqueue(self, job: _Job) -> None:
        if job.key in self._queued:
            return
        self._queued.add(job.key)
        self._queue.append(job)
        self._queue.sort(key=lambda queued: _JOB_PRIORITY[queued.kind])

    @callback
    def _ensure_worker(self) -> None:
        if self.closed or not self._queue:
            return
        if self._worker is not None and not self._worker.done():
            return
        self._worker = self._spawn(
            self._async_work(), "openwrt_router configuration manager worker"
        )

    @callback
    def _drop_jobs(self, router_ids: set[str]) -> None:
        """Forget the jobs of released routers; cancel the one running."""
        if not router_ids:
            return
        self._queue = [job for job in self._queue if job.router_id not in router_ids]
        self._queued = {key for key in self._queued if key[0] not in router_ids}
        current = self._current
        worker = self._worker
        if current is not None and current.router_id in router_ids and worker:
            worker.cancel()  # the entry is going away: never wait for its router
            self._worker = None
            self._current = None
            self._ensure_worker()  # the others continue in a new worker

    # -- router access (one lock per router, fleet parallelism 1) ---------------------

    def _router_lock(self, router_id: str) -> asyncio.Lock:
        lock = self._router_locks.get(router_id)
        if lock is None:
            lock = self._router_locks[router_id] = asyncio.Lock()
        return lock

    def router_busy(self, router_id: str) -> bool:
        """True while a run of ours holds the router or the fleet slot."""
        return self._router_lock(router_id).locked() or self._run_lock.locked()

    def _check_gap(self, router_id: str, kind: str) -> None:
        """RateLimitedError while the last manual ``kind`` is too recent."""
        gap = (
            MANUAL_BACKUP_MIN_GAP_S
            if kind == MANUAL_BACKUP
            else MANUAL_LIVE_CHECK_MIN_GAP_S
        )
        last = self._manual_at.get((router_id, kind))
        if last is None:
            return
        elapsed = (self.now() - last).total_seconds()
        if 0 <= elapsed < gap:
            raise RateLimitedError(
                "Too soon after the last manual run",
                retry_after=max(1, math.ceil(gap - elapsed)),
                router_id=router_id,
                details={"reason": f"min_gap_{kind}"},
            )

    @asynccontextmanager
    async def _router_access(
        self, router_id: str, *, wait: bool, manual: str | None = None
    ) -> AsyncIterator[None]:
        """Hold the router's lock, then the fleet slot.

        ``wait`` False: busy -> OperationInProgressError at once (route: 409
        + Retry-After). ``manual`` (MANUAL_BACKUP / MANUAL_LIVE): the minimum
        gap applies (RateLimitedError, route: 429 + Retry-After); the start
        counts once both locks are held, whatever the outcome.
        """
        if manual is not None:
            self._check_gap(router_id, manual)
        if not wait and self.router_busy(router_id):
            raise OperationInProgressError(
                "The router is busy with another configuration run",
                router_id=router_id,
                details={"reason": "router_busy"},
            )
        async with self._router_lock(router_id), self._run_lock:
            if manual is not None:
                self._check_gap(router_id, manual)  # a waiting caller came late
                self._manual_at[(router_id, manual)] = self.now()
            yield

    @asynccontextmanager
    async def async_live_access(self, router_id: str) -> AsyncIterator[None]:
        """A manual live check (R8 live, R12): no waiting, minimum gap."""
        async with self._router_access(router_id, wait=False, manual=MANUAL_LIVE):
            yield

    async def _async_work(self) -> None:
        while self._queue and not self.closed:
            job = self._queue.pop(0)
            self._current = job
            try:
                async with self._router_access(job.router_id, wait=True):
                    await self._async_run_job(job)
            except asyncio.CancelledError:
                raise
            except Exception:  # the worker never dies of one job
                _LOGGER.warning(
                    "Configuration job %s of %s failed unexpectedly",
                    job.kind,
                    job.router_id,
                    exc_info=True,
                )
            finally:
                self._queued.discard(job.key)
                if self._current is job:
                    self._current = None

    def _backup_blocker(self, router_id: str) -> str | None:
        """Why a run cannot start now (no router call); None = it can.

        ``busy``: a router lock is held or the capability is not readable
        (again at a later tick). ``permission`` / ``not_available``: the
        provider reported config.backup unavailable - a problem the status
        shows instead of "ok".
        """
        try:
            if self.core.manager.locked(router_id):
                return BLOCK_BUSY
            status = self.api.capability(router_id, "config.backup")
        except ConfigApiError:
            return BLOCK_BUSY
        if status.available or (
            status.state is CapabilityState.UNKNOWN
            and str(status.reason) == CapabilityReason.DETERMINED_ON_FIRST_USE.value
        ):
            return None
        if status.state is not CapabilityState.UNAVAILABLE:
            return BLOCK_BUSY  # unknown / not probed yet: decided later
        if str(status.reason) == CapabilityReason.PERMISSION_DENIED.value:
            return str(ErrorClass.PERMISSION)
        return str(ErrorClass.NOT_AVAILABLE)

    def _backup_possible(self, router_id: str) -> bool:
        """No router lock held and config.backup usable (no router call)."""
        return self._backup_blocker(router_id) is None

    def _mark_blocked(self, state: RouterState, job: _Job, error_class: str) -> None:
        """The backup right is missing: failed status, the day counts as tried.

        Logged and audited (``config_manager.backup_blocked``) at most once
        per router and slot day; the status shows it until a version exists.
        """
        now = self.now()
        today = self._today_slot(state.router_id)
        state.last_attempt_at = now
        state.last_failure_at = now
        state.last_error_class = error_class
        state.last_error_reason = None
        if job.kind == JOB_SCHEDULED:
            state.last_scheduled_day = today
            state.retry_at = None
        else:
            state.release_done.add(job.release or "")
        self.stats["runs_blocked"] += 1
        self._notify(state.router_id)
        if state.blocked_day == today:
            return
        state.blocked_day = today
        _LOGGER.warning(
            "Configuration backup of %s skipped: the backup right is missing (%s)",
            state.router_id,
            error_class,
        )
        try:
            self.api.emit(
                EVENT_BACKUP_BLOCKED,
                source=CONFIG_MANAGER_MODULE,
                router_id=state.router_id,
                severity=_SEVERITY_WARNING,  # type: ignore[arg-type]
                result=EventResult.FAILURE,
                dedup_key=error_class,
                data={"error_class": error_class, "job": job.kind},
            )
        except Exception:  # noqa: BLE001 - the audit is optional here
            _LOGGER.debug("backup_blocked of %s not audited", state.router_id)

    async def _async_run_job(self, job: _Job) -> None:
        state = self.routers.get(job.router_id)
        if state is None or not self.enabled(job.router_id):
            return
        if job.kind == JOB_DRIFT:
            await self._async_auto_drift(state)
            return
        blocker = self._backup_blocker(job.router_id)
        if blocker == BLOCK_BUSY:
            self.stats["runs_deferred"] += 1  # again at a later tick
            return
        if blocker is not None:
            self._mark_blocked(state, job, blocker)
            return
        scheduled = job.kind == JOB_SCHEDULED
        today = self._today_slot(job.router_id)
        reason = BackupReason.SCHEDULED if scheduled else BackupReason.RELEASE_CHANGE
        try:
            await self._async_backup(state, reason=reason, actor=self.module_actor)
        except OperationInProgressError:
            self.stats["runs_deferred"] += 1  # not a failure: next tick
            return
        except ConfigApiError as err:
            self.stats["runs_failed"] += 1
            _LOGGER.info(
                "Configuration backup (%s) of %s failed: %s",
                job.kind,
                job.router_id,
                err.code,
            )
            if not scheduled:
                state.release_done.add(job.release or "")
            elif err.retryable and state.retried_day != today:
                state.retried_day = today
                state.retry_at = self.now() + timedelta(seconds=FETCH_RETRY_DELAY_S)
            else:
                state.last_scheduled_day = today
                state.retry_at = None
            return
        if scheduled:
            state.last_scheduled_day = today
            state.retry_at = None
        else:
            state.release_done.add(job.release or "")

    async def _async_backup(
        self,
        state: RouterState,
        *,
        reason: BackupReason,
        actor: Actor,
        backup_type: BackupType | None = None,
        note: str | None = None,
    ) -> PutVersionResult:
        """One create_backup through the Configuration API (the only path)."""
        router_id = state.router_id
        state.running = True
        state.last_attempt_at = self.now()
        self.stats["runs_started"] += 1
        self._notify(router_id)
        try:
            result = await self.api.async_create_backup(
                router_id,
                reason=reason,
                actor=actor,
                backup_type=backup_type,
                note=note,
            )
        except BaseException as err:
            state.running = False
            if isinstance(err, ConfigApiError) and not isinstance(
                err, (AuthorizationError, OperationInProgressError)
            ):
                # The core's backup_failed carries the class, not the reason.
                reason = err.details.get("reason")
                state.last_error_reason = reason if isinstance(reason, str) else None
            self._notify(router_id)
            self._schedule_refresh(router_id)
            raise
        state.running = False
        state.last_error_reason = None
        await self.async_refresh(router_id)
        return result

    async def async_backup_now(
        self,
        router_id: str,
        *,
        actor: Actor,
        note: str | None = None,
        wait: bool = False,
    ) -> PutVersionResult:
        """A manual version (service, route R5); the core guard decides.

        ``wait`` False: another run of ours -> OperationInProgressError at
        once (route: 409 + Retry-After). The service waits its turn. Both
        keep MANUAL_BACKUP_MIN_GAP_S per router (RateLimitedError, 429).
        """
        state = self.routers.get(router_id)
        if state is None:
            raise RouterNotFoundError("Unknown router", router_id=router_id)
        async with self._router_access(router_id, wait=wait, manual=MANUAL_BACKUP):
            return await self._async_backup(
                state, reason=BackupReason.MANUAL, actor=actor, note=note
            )

    # -- drift -------------------------------------------------------------------------

    async def async_check_drift(self, router_id: str, *, actor: Actor) -> DriftReport:
        """A manual drift check (route R10): no waiting, minimum gap."""
        async with self._router_access(router_id, wait=False, manual=MANUAL_LIVE):
            return await self._async_drift_check(router_id, actor=actor)

    async def _async_drift_check(self, router_id: str, *, actor: Actor) -> DriftReport:
        """One drift check (read-only in the core); the caller holds the router."""
        self.stats["drift_checks"] += 1
        report = await self.api.async_detect_drift(router_id, actor=actor)
        state = self.routers.get(router_id)
        if state is not None:
            self._apply_drift_report(state, report)
            self._notify(router_id)
        return report

    def _apply_drift_report(self, state: RouterState, report: DriftReport) -> None:
        if report.drift_id:
            state.drift_ids.add(report.drift_id)
        if not report.drifted:
            summary_state = DRIFT_CLEAR
        elif report.ack_state is not None:
            summary_state = str(report.ack_state)
        else:
            summary_state = DRIFT_OPEN
        state.drift = _drift_summary(
            drift_id=report.drift_id,
            state=summary_state,
            critical_count=report.critical_count,
            unknown_count=report.unknown_count,
            comparison=report.comparison,
            baseline_backup_id=report.baseline_backup_id,
            checked_at=report.checked_at,
        )

    def _roll_drift_day(self, state: RouterState) -> None:
        today = _local_day(self.now())
        if state.drift_day != today:
            state.drift_day = today
            state.drift_versions_today = 0

    async def _async_auto_drift(self, state: RouterState) -> None:
        """Debounced drift check; a new drift id gets one UCI version."""
        router_id = state.router_id
        state.fp_changed_at = None
        state.last_drift_at = self.now()
        try:
            report = await self._async_drift_check(router_id, actor=self.module_actor)
        except BackupNotFoundError:
            return  # no baseline: wait for the daily run
        except ConfigApiError as err:
            _LOGGER.debug("Drift check of %s failed: %s", router_id, err.code)
            return
        drift_id = report.drift_id
        if (
            not report.drifted
            or not drift_id
            or report.ack_state is not None
            or drift_id in state.drift_versioned
        ):
            return
        state.drift_versioned.add(drift_id)
        self._roll_drift_day(state)
        if state.drift_versions_today >= CONFIG_DRIFT_VERSIONS_PER_DAY:
            self.stats["drift_versions_capped"] = (
                self.stats.get("drift_versions_capped", 0) + 1
            )
            return
        if not self._backup_possible(router_id):
            return
        # Counted per attempt: bounds the router calls, not only the versions.
        state.drift_versions_today += 1
        try:
            await self._async_backup(
                state,
                reason=BackupReason.DRIFT,
                actor=self.module_actor,
                backup_type=BackupType.UCI_SNAPSHOT,
            )
        except ConfigApiError as err:
            _LOGGER.debug("Drift version of %s failed: %s", router_id, err.code)
            return
        self.stats["drift_versions"] += 1


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
    _register_views(hass)
    return runtime


def _register_views(hass: HomeAssistant) -> None:
    """HTTP routes R1-R20, bound once per HA session (also with the option off:
    they then answer ``disabled``). A failure never breaks the setup."""
    try:
        from .config_views import async_register_config_views

        async_register_config_views(hass)
    except Exception as err:  # noqa: BLE001 - routes missing, entry still loads
        _LOGGER.warning("Configuration routes not registered: %s", type(err).__name__)


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


# -- service create_config_backup (plan section 4) ------------------------------------

ATTR_NOTE = "note"

SERVICE_CREATE_CONFIG_BACKUP_SCHEMA = vol.Schema(
    {
        vol.Required(ATTR_DEVICE_ID): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(ATTR_NOTE): vol.Any(None, cv.string),
    }
)


def _service_error(key: str, **placeholders: str) -> ServiceValidationError:
    return ServiceValidationError(
        translation_domain=DOMAIN,
        translation_key=key,
        translation_placeholders=placeholders or None,
    )


def _resolve_targets(
    hass: HomeAssistant, runtime: ConfigManagerRuntime, device_ids: Iterable[str]
) -> list[str]:
    """Router ids of the devices; every validation error before any run."""
    registry = dr.async_get(hass)
    router_ids: list[str] = []
    for device_id in dict.fromkeys(device_ids):
        device = registry.async_get(device_id)
        entry_id = None
        if device is not None:
            entry_id = next(
                (
                    ident[1]
                    for ident in device.identifiers
                    if ident[0] == DOMAIN and ident[1] in runtime.entries
                ),
                None,
            )
        if device is None or entry_id is None:
            raise _service_error("config_backup_unknown_device", device_id=device_id)
        state = runtime.state_for_entry(entry_id)
        if state is None:
            raise _service_error("config_backup_not_ready")
        if not runtime.enabled(state.router_id):
            name = device.name_by_user or device.name or entry_id
            raise _service_error("config_backup_disabled", router=name)
        if state.router_id not in router_ids:
            router_ids.append(state.router_id)
    return router_ids


async def async_handle_create_config_backup(
    hass: HomeAssistant, call: ServiceCall
) -> ServiceResponse:
    """``openwrt_router.create_config_backup``: one manual version per router.

    Routers run one after the other. A router or storage failure of one
    router is reported in the response; only when every router failed the
    call raises ``config_backup_failed``.
    """
    try:
        note = validate_note(call.data.get(ATTR_NOTE))
    except (TypeError, ValueError) as err:
        raise _service_error("config_backup_invalid_note") from err
    runtime = async_get_runtime(hass)
    if runtime is None or not runtime.provider_registered:
        raise _service_error("config_backup_not_ready")
    router_ids = _resolve_targets(hass, runtime, call.data[ATTR_DEVICE_ID])
    actor = await async_actor_from_context(hass, call.context)
    results: list[dict[str, Any]] = []
    failures: list[ConfigApiError] = []
    for router_id in router_ids:
        try:
            result = await runtime.async_backup_now(
                router_id, actor=actor, note=note, wait=True
            )
        except AuthorizationError as err:
            raise _service_error("config_backup_denied") from err
        except ConfigApiError as err:
            failures.append(err)
            results.append(
                {
                    "router_id": router_id,
                    "backup_id": None,
                    "created": False,
                    "status": CONFIG_STATUS_FAILED,
                    "error_class": err.error_class.value,
                }
            )
            continue
        record = result.record
        results.append(
            {
                "router_id": router_id,
                "backup_id": record.backup_id,
                "created": result.created,
                "status": str(record.status),
                "error_class": (
                    None if record.error_class is None else str(record.error_class)
                ),
            }
        )
    if failures and len(failures) == len(results):
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key="config_backup_failed",
            translation_placeholders={"error_class": failures[0].error_class.value},
        )
    if call.return_response:
        return {"results": results}
    return None


@callback
def async_register_services(hass: HomeAssistant) -> None:
    """Register the action once (from ``async_setup``; it stays registered)."""
    if hass.services.has_service(DOMAIN, SERVICE_CREATE_CONFIG_BACKUP):
        return

    async def _async_handle(call: ServiceCall) -> ServiceResponse:
        return await async_handle_create_config_backup(hass, call)

    hass.services.async_register(
        DOMAIN,
        SERVICE_CREATE_CONFIG_BACKUP,
        _async_handle,
        schema=SERVICE_CREATE_CONFIG_BACKUP_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )


__all__ = [
    "ConfigManagerRuntime",
    "RouterState",
    "async_get_runtime",
    "async_handle_create_config_backup",
    "async_register_services",
    "async_release_config_manager",
    "async_setup_config_manager",
    "stagger_offset",
    "validate_note",
]
