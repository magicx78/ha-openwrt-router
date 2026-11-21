"""WiFi RF Intelligence center (release 1.48.0, part 1): collect and evaluate.

One center per Home Assistant instance (pattern of the Security Center).
Every config entry adds a listener to its coordinator. After each poll the
center takes the poll data and, when due, the answers of the extra RF reads
(``rf_collector`` plans them, ``api.async_rf_read`` makes them, as a
background task so the poll never waits) and evaluates every radio
(``rf_evaluate``: views, capability matrix, utilization from the counter
delta kept in memory, clients, conflicts, load, recommendations, health).

Rules:

* Off by default per entry (``wifi_rf_enabled``). Off, the listener returns
  at once: no router call and no evaluation, so a poll makes exactly the
  calls it made before (tested by counting ubus calls).
* On with no extra read switched on, only data the poll already has is used.
* An RF error never fails a poll or a setup: it is caught, logged by type
  only (identities at debug level at most) and shown as the router state
  ``source_unreachable`` or ``error``.
* Identity: the Core ``router_id`` from the router registry, the UCI radio
  name (phy only when no UCI name is known, marked), clients only as
  ``client_ref``. All output goes through ``rf_privacy.mask_rf_output`` with
  the ``wifi_rf`` module key (``rf_privacy.rf_key_request``).
* Not ready (no core, no module key, no router id, no poll yet): status
  ``not_ready`` with reasons, no health rating, never an all-clear.
* Sensitive reads (roaming history) are authorized by the Core guard once per
  panel session; the policy (``rf_guard.rf_policy_denial``) is checked
  before every read.
* No network access here: router reads go through ``api.py`` only.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.util import dt as dt_util

from . import api as api_module
from .const import DATA_WIFI_RF_CENTER, SCAN_INTERVAL_SECONDS
from .core_models import FLEET_ROUTER_ID, InstallationKeyState
from .rf_capabilities import RF_MODULE, capability_detector
from .rf_collector import (
    RadioPlanInput,
    RfCollector,
    RfOptions,
    RoundResult,
    Target,
    options_from_entry,
)
from .rf_evaluate import (
    FleetResult,
    PollInput,
    RadioInput,
    RadioMemory,
    RadioResult,
    clients_by_device,
    empty_fleet,
    evaluate_fleet,
    evaluate_radio,
    radio_inputs,
)
from .rf_events import (
    EVENT_PREFIX,
    EVENT_RECOMMENDATION_NEW,
    channel_conflict_event,
    channel_utilization_event,
    emit_kwargs,
    forget_router,
    forgotten_router_id,
    recommendation_events,
)
from .rf_guard import POLL_READ_MIN_INTERVAL_S, register_rf_actions, rf_policy_denial
from .rf_identity import RadioRef, require_router_id
from .rf_incidents import RfIncidentFeed
from .rf_models import CapabilityState
from .rf_privacy import client_ref, mask_rf_output, rf_key_request
from .rf_recommend import Recommendation
from .rf_store import SERIES_HEALTH, SERIES_ROAMS, RfStore

_LOGGER = logging.getLogger(__name__)

STATUS_OFF = "off"
STATUS_NOT_READY = "not_ready"
STATUS_READY = "ready"
ROUTER_OK = "ok"
ROUTER_NO_DATA = "no_data"
ROUTER_NOT_READY = "not_ready"
ROUTER_UNREACHABLE = "source_unreachable"
ROUTER_ERROR = "error"
REASON_NO_CORE = "no_core"
REASON_MODULE_KEY = "module_key_missing"
REASON_ROUTER_ID = "router_id_missing"
REASON_NO_DATA = "no_poll_data"
REASON_COLLECTOR = "collector_error"
REASON_TIMEOUT = "round_timeout"
REASON_EVALUATION = "radio_evaluation"
REASON_RESTART = "router_restart"
CORE_RETRY_S = 300.0
# DECIDED: a panel session is one HA login (its refresh token), see
# async_authorize_sensitive; the guard approval lasts this long.
SESSION_TTL_S = 1800.0
SESSIONS_MAX = 64
ROAM_WINDOW_S = 600.0
ROAMS_MAX = 200
CLIENTS_TRACKED_MAX = 2048
EVENTS_PER_EVALUATION_MAX = 20
MODULE_KEY_MIN_BYTES = 32
_FLUSH_KEY = f"{DATA_WIFI_RF_CENTER}_flush"
_COUNTERS = (
    "polls",
    "polls_off",
    "polls_skipped_busy",
    "rounds_started",
    "errors",
    "events_emitted",
    "events_dropped",
    "sessions_approved",
    "sessions_refused",
    "sensitive_reads",
    "roams_seen",
    "forgotten_routers",
)


class RfCenterError(Exception):
    """A refused request; ``reason`` is a fixed token."""

    def __init__(self, reason: str) -> None:
        """Refusal with a reason token."""
        super().__init__(reason)
        self.reason = reason


# --- life cycle ----------------------------------------------------------------------


@callback
def async_get_rf_center(hass: HomeAssistant) -> RfCenter | None:
    """The running center, or None."""
    center = hass.data.get(DATA_WIFI_RF_CENTER)
    return center if isinstance(center, RfCenter) else None


async def async_setup_rf_center(
    hass: HomeAssistant, entry: Any, coordinator: Any
) -> RfCenter:
    """Create/load the per-HA center once and add this entry (no router call)."""
    center = async_get_rf_center(hass)
    if center is None:
        center = RfCenter(hass)
        hass.data[DATA_WIFI_RF_CENTER] = center
    await center.async_load()
    center.add_entry(entry, coordinator)
    center.stage("http routes", _register_views, hass)
    return center


def _register_views(hass: HomeAssistant) -> None:
    from .rf_views import async_register_rf_views

    async_register_rf_views(hass)


async def async_release_rf_center(hass: HomeAssistant, entry_id: str) -> None:
    """Drop the entry; after the last one stop and write the history now."""
    center = async_get_rf_center(hass)
    if center is None:
        return
    center.remove_entry(entry_id)
    if center.entry_count:
        return
    hass.data.pop(DATA_WIFI_RF_CENTER, None)
    center.close()
    claim: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    hass.data[_FLUSH_KEY] = claim
    try:
        if center.store.dirty:
            await center.store.async_flush()
    finally:
        claim.set_result(None)
        if hass.data.get(_FLUSH_KEY) is claim:
            hass.data.pop(_FLUSH_KEY, None)


# --- state -------------------------------------------------------------------------------


@dataclass
class RouterState:
    """One router of the fleet (one config entry), memory only."""

    entry_id: str
    collector: RfCollector
    router_id: str | None = None
    status: str = ROUTER_NO_DATA
    reason: str | None = None
    options: RfOptions = field(default_factory=RfOptions)
    radios: dict[str, RadioMemory] = field(default_factory=dict)
    devices: set[str] = field(default_factory=set)
    last_poll_at: float | None = None
    last_uptime: float | None = None
    restarted: bool = False
    task: asyncio.Task[Any] | None = None


@dataclass
class _Binding:
    core: Any = None
    api: Any = None
    removers: list[Callable[[], None]] = field(default_factory=list)
    events_ok: bool = False
    actions_ok: bool = False


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, UTC)


class RfCenter:
    """Fleet-wide WiFi RF Intelligence: collect, evaluate, keep, show."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Empty center; ``async_load`` reads the history."""
        self.hass = hass
        self.store = RfStore(hass)
        self.counters: dict[str, int] = dict.fromkeys(_COUNTERS, 0)
        self._entries: dict[str, tuple[Any, Any]] = {}
        self._unsubs: dict[str, Callable[[], None]] = {}
        self.routers: dict[str, RouterState] = {}
        self.results: dict[RadioRef, RadioResult] = {}
        self.fleet: FleetResult = empty_fleet()
        self.roams: deque[dict[str, Any]] = deque(maxlen=ROAMS_MAX)
        self._roam_times: dict[RadioRef, deque[float]] = {}
        self._client_last: OrderedDict[str, tuple[RadioRef, float]] = OrderedDict()
        self._sessions: dict[tuple[str, str], float] = {}
        self._conflict_keys: set[str] = set()
        self._overload: dict[RadioRef, bool] = {}
        self._recs_seen: list[Recommendation] = []
        # Routers whose recommendations were evaluated once since the start.
        self._rec_routers: set[str] = set()
        self._binding = _Binding()
        self._core_tried: float | None = None
        self._bind_task: asyncio.Task[Any] | None = None
        self._cap_version = 0
        self.module_key: bytes | None = None
        self.closed = False
        self.loaded = False
        # Seams for tests; the defaults are the real sources.
        self.clock: Callable[[], float] = time.time
        self.monotonic: Callable[[], float] = time.monotonic
        self.router_id_of: Callable[[str], str | None] = self._registry_router_id
        self.capability_of: Callable[[str, str], tuple[bool, str | None]] = (
            self._core_capability
        )
        self.read: Callable[..., Any] = api_module.async_rf_read
        self.auto_bind = True
        # Part 2: measured RF findings as Network Intelligence events.
        self.incident_feed = RfIncidentFeed(self)

    # -- status ------------------------------------------------------------------------

    @property
    def entry_count(self) -> int:
        """Entries using the center."""
        return len(self._entries)

    def _enabled_states(self) -> list[RouterState]:
        return [
            self.routers[eid]
            for eid, (entry, _c) in self._entries.items()
            if eid in self.routers
            and options_from_entry(getattr(entry, "options", None)).enabled
        ]

    @property
    def enabled(self) -> bool:
        """True while at least one entry has ``wifi_rf_enabled`` on."""
        return bool(self._enabled_states())

    def not_ready_reasons(self) -> list[str]:
        """Why the module is not ready (empty when ready or off)."""
        states = self._enabled_states()
        if not states:
            return []
        reasons = []
        if self.auto_bind and self._binding.api is None:
            reasons.append(REASON_NO_CORE)
        if self.module_key is None:
            reasons.append(REASON_MODULE_KEY)
        if any(s.reason == REASON_ROUTER_ID for s in states):
            reasons.append(REASON_ROUTER_ID)
        if all(s.last_poll_at is None for s in states):
            reasons.append(REASON_NO_DATA)
        return reasons

    @property
    def status(self) -> str:
        """``off``, ``not_ready`` or ``ready``."""
        if not self.enabled:
            return STATUS_OFF
        return STATUS_NOT_READY if self.not_ready_reasons() else STATUS_READY

    def mask(self, data: Any) -> Any:
        """The one output step (pseudonyms with the module key, then masking)."""
        return mask_rf_output(data, key=self.module_key)

    # -- load / entries ---------------------------------------------------------------

    async def async_load(self) -> None:
        """Read the history once (waits for the flush of an earlier run)."""
        pending = self.hass.data.get(_FLUSH_KEY)
        if isinstance(pending, asyncio.Future) and not pending.done():
            await asyncio.shield(pending)
        await self.store.async_load()
        self.loaded = True

    @callback
    def add_entry(self, entry: Any, coordinator: Any) -> None:
        """Listen to the entry's polls (the listener costs no router call)."""
        entry_id = entry.entry_id
        self._entries[entry_id] = (entry, coordinator)
        if entry_id not in self.routers:
            collector = RfCollector(clock=lambda: self.monotonic())
            self.routers[entry_id] = RouterState(entry_id, collector)
        add = getattr(coordinator, "async_add_listener", None)
        if entry_id not in self._unsubs and callable(add):
            self._unsubs[entry_id] = add(functools.partial(self.on_poll, entry_id))

    @callback
    def remove_entry(self, entry_id: str) -> None:
        """Stop listening; the router's results leave the fleet view."""
        unsub = self._unsubs.pop(entry_id, None)
        if unsub is not None:
            self.stage("listener removal", unsub)
        self._entries.pop(entry_id, None)
        state = self.routers.pop(entry_id, None)
        if state is not None:
            self._cancel(state)
            self._drop_results(state.router_id)
            self.stage("fleet evaluation", self._evaluate, self._now())

    @staticmethod
    def _cancel(state: RouterState) -> None:
        if state.task is not None and not state.task.done():
            state.task.cancel()
        state.task = None
        state.collector.busy = False

    def _drop_results(self, router_id: str | None) -> None:
        for ref in [r for r in self.results if r.router_id == router_id]:
            del self.results[ref]
        self._cap_version += 1

    @callback
    def close(self) -> None:
        """Stop for good (no task and no core listener stays)."""
        self.closed = True
        for entry_id in list(self._entries):
            self.remove_entry(entry_id)
        if self._bind_task is not None and not self._bind_task.done():
            self._bind_task.cancel()
        self._unbind_core()
        self.stage("incident feed", self.incident_feed.detach)

    async def async_wait_rounds(self) -> None:
        """Wait for the running RF rounds (tests and diagnostics)."""
        tasks = [s.task for s in self.routers.values() if s.task is not None]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # -- errors --------------------------------------------------------------------------

    def _fail(self, stage: str, err: BaseException) -> None:
        """Log by type only (messages can carry router data); never raise."""
        self.counters["errors"] += 1
        _LOGGER.warning(
            "WiFi RF: %s failed (%s); the routers keep working",
            stage,
            type(err).__name__,
        )
        _LOGGER.debug("WiFi RF %s error", stage, exc_info=err)

    def stage(self, name: str, func: Callable[..., Any], *args: Any) -> Any:
        """Run one isolated step; an error is logged and gives None."""
        try:
            return func(*args)
        except Exception as err:  # noqa: BLE001 - isolated step
            self._fail(name, err)
            return None

    def _now(self) -> float:
        return self.clock()

    # -- core ----------------------------------------------------------------------------

    def _registry_router_id(self, entry_id: str) -> str | None:
        api = self._binding.api
        if api is None:
            return None
        try:
            return require_router_id(api.registry.get_by_entry(entry_id).router_id)
        except Exception:  # noqa: BLE001 - not registered (yet): no router id
            return None

    def _core_capability(self, router_id: str, name: str) -> tuple[bool, str | None]:
        api = self._binding.api
        if api is None:
            return False, REASON_NO_CORE
        try:
            status = api.capability(router_id, name)
        except Exception as err:  # noqa: BLE001 - unknown: not asked
            return False, type(err).__name__
        if getattr(status, "available", False) is True:
            return True, None
        reason = getattr(status, "reason", None)
        return False, str(getattr(reason, "value", reason) or "unknown")

    def _maybe_bind(self) -> None:
        """Bind the Core from the poll, at most every CORE_RETRY_S (own task)."""
        if not self.auto_bind or self.closed:
            return
        binding = self._binding
        if binding.api is not None and binding.events_ok and self.module_key:
            return
        if self._bind_task is not None and not self._bind_task.done():
            return
        mono = self.monotonic()
        if self._core_tried is not None and 0 <= mono - self._core_tried < CORE_RETRY_S:
            return
        self._core_tried = mono
        self._bind_task = self.hass.async_create_task(
            self._async_bind_safe(), name="openwrt_router wifi rf core"
        )

    async def _async_bind_safe(self) -> None:
        try:
            await self.async_bind_core()
        except Exception as err:  # noqa: BLE001 - runs on without the core
            self._fail("core binding", err)

    async def async_bind_core(self) -> None:
        """Events, guard actions, capability detector and the module key."""
        from .config_api import async_get_configuration_api
        from .enterprise_core import async_get_core

        core = async_get_core(self.hass)
        if core is None or getattr(core, "closed", False):
            self._unbind_core()
            return
        if self._binding.core is not core or self._binding.api is None:
            self._unbind_core()
            api = await async_get_configuration_api(self.hass, 1)
            binding = _Binding(core=core, api=api)
            self._binding = binding
            binding.removers.append(
                api.register_event_prefix(EVENT_PREFIX, module=RF_MODULE)
            )
            binding.events_ok = True
            binding.removers.append(api.subscribe(self._on_core_event))
            self.stage("capability detector", self._register_detector, api)
            self.stage("guard actions", self._register_actions, api)
            self.stage("forgotten routers", self._forget_unknown_routers)
        if self.module_key is None:
            await self._async_fetch_key()

    def _register_detector(self, api: Any) -> None:
        """RF metrics below ``rf.metric.`` (sync, no I/O, own signature).

        The matrices are this center's results of the record's router (the
        poll data alone does not say which router it is); the signature is
        the evaluation counter, so the Core re-reads after every evaluation.
        """

        def extract_for(router_id: str) -> Callable[[Any], list[Any] | None]:
            def extract(_data: Any) -> list[Any] | None:
                caps = [
                    r.caps
                    for r in self.results.values()
                    if r.ref.router_id == router_id
                ]
                return caps or None

            return extract

        def detect(record: Any, data: Any) -> dict[str, Any]:
            extract = extract_for(record.router_id)
            return capability_detector(extract, clock=dt_util.utcnow)(record, data)

        self._binding.removers.append(
            api.register_capability_detector(
                RF_MODULE,
                detect,
                prefix="rf.metric.",
                signature=lambda _data: self._cap_version,
            )
        )

    def _register_actions(self, api: Any) -> None:
        register_rf_actions(api.guard)
        self._binding.actions_ok = True

    async def _async_fetch_key(self) -> None:
        api = self._binding.api
        if api is None or not self._binding.events_ok or not self.enabled:
            return  # off: never make the Core create an installation key for it
        try:
            state = api.installation_key_state
            if state not in (
                InstallationKeyState.OK,
                InstallationKeyState.UNINITIALISED,
            ):
                _LOGGER.debug("WiFi RF: installation key state %s", state)
                return
            key = await rf_key_request(api)
        except Exception as err:  # noqa: BLE001 - not ready without the key
            _LOGGER.debug("WiFi RF: no module key (%s)", type(err).__name__)
            return
        if isinstance(key, bytes) and len(key) >= MODULE_KEY_MIN_BYTES:
            self.module_key = key

    def _unbind_core(self) -> None:
        binding, self._binding = self._binding, _Binding()
        self.module_key = None
        for remove in reversed(binding.removers):
            self.stage("core unbind", remove)

    def _on_core_event(self, event: Any) -> None:
        """Core listener (sync, short); never raises."""
        try:
            router_id = forgotten_router_id(event)
        except Exception as err:  # noqa: BLE001 - the bus goes on
            self._fail("core event", err)
            return
        if router_id is not None:
            self.stage("router forgotten", self.forget_router, router_id)

    def _forget_unknown_routers(self) -> None:
        """Drop the history of routers the registry no longer knows."""
        api = self._binding.api
        if api is None:
            return
        known = {r.router_id for r in api.registry.list(include_orphaned=True)}
        if not known:
            return  # unknown is not forgotten
        for router_id in sorted(self.store.routers() - known):
            self.forget_router(router_id)

    def forget_router(self, router_id: str) -> None:
        """``router.forgotten``: every RF datum of the router goes."""
        require_router_id(router_id)
        self.counters["forgotten_routers"] += 1
        self.store.forget_router(router_id)
        self._drop_results(router_id)
        for state in self.routers.values():
            if state.router_id == router_id:
                state.radios.clear()
        self._overload = forget_router(self._overload, router_id)
        self._rec_routers = self._rec_routers - {router_id}
        self._roam_times = forget_router(self._roam_times, router_id)
        self._client_last = OrderedDict(
            (mac, last)
            for mac, last in self._client_last.items()
            if last[0].router_id != router_id
        )
        kept = [
            r
            for r in self.roams
            if router_id not in (r["to"]["router_id"], r["from"]["router_id"])
        ]
        self.roams = deque(kept, maxlen=ROAMS_MAX)
        self.stage("fleet evaluation", self._evaluate, self._now())

    # -- poll ------------------------------------------------------------------------------

    def on_poll(self, entry_id: str) -> None:
        """Coordinator listener: never raises, never blocks the poll."""
        try:
            self._on_poll(entry_id)
        except Exception as err:  # noqa: BLE001 - the poll stays green
            state = self.routers.get(entry_id)
            if state is not None:
                state.status, state.reason = ROUTER_ERROR, type(err).__name__
            self._fail("poll", err)

    def _on_poll(self, entry_id: str) -> None:
        pair = self._entries.get(entry_id)
        state = self.routers.get(entry_id)
        if self.closed or pair is None or state is None:
            return
        entry, coordinator = pair
        options = options_from_entry(getattr(entry, "options", None))
        was_on, state.options = state.options.enabled, options
        if not options.enabled:
            self.counters["polls_off"] += 1
            if was_on:
                self._switch_off(state)
            return
        self.counters["polls"] += 1
        self._maybe_bind()
        self.stage("incident feed", self.incident_feed.attach, self.hass)
        data = getattr(coordinator, "data", None)
        if data is None:
            return
        router_id = self.router_id_of(entry_id)
        if router_id is None:
            state.status, state.reason = ROUTER_NOT_READY, REASON_ROUTER_ID
            return
        if state.router_id not in (None, router_id):  # adopted under a new id
            self._drop_results(state.router_id)
            state.radios.clear()
        state.router_id = router_id
        if state.collector.busy:
            self.counters["polls_skipped_busy"] += 1
            return
        self._start(state, coordinator, data, options)

    def _switch_off(self, state: RouterState) -> None:
        self._cancel(state)
        state.radios.clear()
        state.status, state.reason, state.last_poll_at = ROUTER_NO_DATA, None, None
        self._drop_results(state.router_id)
        self._evaluate(self._now())

    def _start(
        self, state: RouterState, coordinator: Any, data: Any, options: RfOptions
    ) -> None:
        radios = radio_inputs(data)
        devices = {d for r in radios for d in r.devices}
        for gone in state.devices - devices:
            state.collector.forget_device(gone)
        state.devices = devices
        router_id = state.router_id or ""
        targets = state.collector.plan(
            options,
            [
                RadioPlanInput(r.radio_id, r.devices, (r.channel, r.country))
                for r in radios
            ],
            paused=self._paused(coordinator),
            capability=lambda name: self.capability_of(router_id, name),
        )
        api = getattr(coordinator, "api", None)
        if targets and api is not None:
            self.counters["rounds_started"] += 1
            state.collector.busy = True
            state.task = self.hass.async_create_task(
                self._async_round(state, api, data, radios, targets),
                name="openwrt_router wifi rf round",
            )
            return
        self._process(state, data, radios, RoundResult(taken_at=self.clock()))

    @staticmethod
    def _paused(coordinator: Any) -> bool:
        """Throttled (CPU) or on the SSH fallback: the interval is longer."""
        interval = getattr(coordinator, "update_interval", None)
        seconds = getattr(interval, "total_seconds", None)
        return callable(seconds) and seconds() > SCAN_INTERVAL_SECONDS

    async def _async_round(
        self,
        state: RouterState,
        api: Any,
        data: Any,
        radios: list[RadioInput],
        targets: list[Target],
    ) -> None:
        failure = None
        try:
            try:
                result = await state.collector.async_run(
                    targets,
                    functools.partial(self.read, api),
                    list_bases={r.radio_id: (r.channel, r.country) for r in radios},
                    wall_clock=self.clock,
                )
            except asyncio.CancelledError:
                raise
            except Exception as err:  # noqa: BLE001 - shown as unreachable
                self._fail("RF reads", err)
                failure = REASON_COLLECTOR
                result = RoundResult(taken_at=self.clock())
            if self.closed or self.routers.get(state.entry_id) is not state:
                return
            self._process(state, data, radios, result, failure=failure)
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001 - never reaches the poll
            state.status, state.reason = ROUTER_ERROR, REASON_EVALUATION
            self._fail("RF evaluation", err)
        finally:
            state.collector.busy = False

    # -- evaluation -----------------------------------------------------------------------

    @staticmethod
    def _interval(options: RfOptions) -> float:
        """Seconds between two periodic reads (never below the guard floor)."""
        return max(
            POLL_READ_MIN_INTERVAL_S,
            float(options.every_n_polls * SCAN_INTERVAL_SECONDS),
        )

    def _process(
        self,
        state: RouterState,
        data: Any,
        radios: list[RadioInput],
        result: RoundResult,
        *,
        failure: str | None = None,
    ) -> None:
        router_id = state.router_id
        if router_id is None:
            return
        now = result.taken_at or self.clock()
        uptime = _number(getattr(data, "uptime", None))
        state.restarted = (
            uptime is not None
            and state.last_uptime is not None
            and uptime < state.last_uptime
        )
        state.last_uptime = uptime
        interval = self._interval(state.options)
        poll = PollInput(
            kinds=state.options.kinds,
            answers=result.answers,
            errors=result.errors,
            kind_state=state.collector.kind_state,
            now=now,
            uptime=uptime,
            max_age_s=interval * 2 + SCAN_INTERVAL_SECONDS,
            interval_s=interval,
        )
        for gone in set(state.radios) - {r.radio_id for r in radios}:
            del state.radios[gone]
        by_device = clients_by_device(data)
        fresh: dict[RadioRef, RadioResult] = {}
        failures = 0
        for radio in radios:
            memory = state.radios.setdefault(radio.radio_id, RadioMemory())
            clients = [c for d in radio.devices for c in by_device.get(d, [])]
            try:
                evaluated = evaluate_radio(router_id, radio, memory, clients, poll)
            except Exception as err:  # noqa: BLE001 - one radio, not the router
                failures += 1
                self._fail("radio evaluation", err)
                continue
            fresh[evaluated.ref] = evaluated
        self._drop_results(router_id)
        self.results.update(fresh)
        state.last_poll_at = now
        state.status, state.reason = self._router_status(
            state, result, failure, failures
        )
        roams = self.stage("roaming", self._track_roams, fresh, now) or {}
        self._evaluate(now)
        self._record(fresh, roams, now)

    @staticmethod
    def _router_status(
        state: RouterState, result: RoundResult, failure: str | None, failures: int
    ) -> tuple[str, str | None]:
        if failure is not None:
            return ROUTER_UNREACHABLE, failure
        if result.timed_out:
            return ROUTER_UNREACHABLE, REASON_TIMEOUT
        if result.errors and not result.answers:
            transient = [
                reason
                for key, reason in sorted(result.errors.items())
                if state.collector.kind_state(*key)[0] is CapabilityState.UNREACHABLE
            ]
            if transient:
                return ROUTER_UNREACHABLE, transient[0]
        if failures:
            return ROUTER_ERROR, REASON_EVALUATION
        if state.restarted:
            return ROUTER_OK, REASON_RESTART
        return ROUTER_OK, None

    def _evaluate(self, now: float) -> None:
        self.fleet = evaluate_fleet(list(self.results.values()))
        self._cap_version += 1
        self.stage("events", self._emit_events, now)

    def _record(
        self,
        fresh: Mapping[RadioRef, RadioResult],
        roams: Mapping[RadioRef, int],
        now: float,
    ) -> None:
        ready = self.status == STATUS_READY
        for ref, result in fresh.items():
            values = dict(result.store_values)
            values[SERIES_ROAMS] = roams.get(ref, 0)
            if ready:  # never a rating while not ready
                health = self.fleet.health.get(ref)
                values[SERIES_HEALTH] = health.score if health else None
            self.store.record(ref, values, now)
        if fresh:
            self.store.schedule_save()

    def _track_roams(
        self, fresh: Mapping[RadioRef, RadioResult], now: float
    ) -> dict[RadioRef, int]:
        """Client seen on another radio than last time (within ROAM_WINDOW_S)."""
        counts: dict[RadioRef, int] = {}
        for ref, result in fresh.items():
            for mac in result.client_macs:
                last = self._client_last.get(mac)
                if (
                    last is not None
                    and last[0] != ref
                    and now - last[1] <= ROAM_WINDOW_S
                ):
                    counts[ref] = counts.get(ref, 0) + 1
                    self.counters["roams_seen"] += 1
                    self._roam_times.setdefault(ref, deque(maxlen=ROAMS_MAX)).append(
                        now
                    )
                    self._remember_roam(mac, last, ref, now)
                self._client_last[mac] = (ref, now)
                self._client_last.move_to_end(mac)
        while len(self._client_last) > CLIENTS_TRACKED_MAX:
            self._client_last.popitem(last=False)
        return counts

    def _remember_roam(
        self, mac: str, last: tuple[RadioRef, float], ref: RadioRef, now: float
    ) -> None:
        if self.module_key is None:
            return  # without the key no client_ref: only the count is kept
        try:
            pseudonym = client_ref(mac, self.module_key)
        except ValueError:
            return
        self.roams.append(
            {
                "client_ref": pseudonym,
                "from": last[0].as_dict(),
                "to": ref.as_dict(),
                "at": now,
                "gap_s": round(now - last[1], 1),
            }
        )

    def roam_count(self, ref: RadioRef, now: float, window_s: float = 3600.0) -> int:
        """Roams onto a radio in the last ``window_s`` (no client identity)."""
        return sum(1 for ts in self._roam_times.get(ref, ()) if now - ts <= window_s)

    # -- events ------------------------------------------------------------------------------

    def _emit_events(self, now: float) -> None:
        """Measured conflicts, sustained utilization, new/resolved recommendations.

        Only on a change: a conflict once while it stays measured, high
        utilization once per rise to "sustained", recommendations against
        the previous evaluation (the first one after a start is the baseline,
        so a restart is no storm). At most EVENTS_PER_EVALUATION_MAX.
        """
        api = self._binding.api
        if api is None or not self._binding.events_ok or self.status != STATUS_READY:
            return
        when = _utc(now)
        events = []
        keys: set[str] = set()
        for conflict in self.fleet.conflicts:
            event = channel_conflict_event(conflict, now=when)
            if event is not None and event.dedup_key:
                keys.add(event.dedup_key)
                if event.dedup_key not in self._conflict_keys:
                    events.append(event)
        self._conflict_keys = keys
        for ref, result in self.results.items():
            sustained = result.summary.sustained_overload if result.summary else None
            if sustained is None:
                continue
            if sustained and self._overload.get(ref) is not True:
                event = channel_utilization_event(ref, result.summary, now=when)
                if event is not None:
                    events.append(event)
            self._overload[ref] = sustained
        events.extend(self._recommendation_changes(when))
        for event in events[:EVENTS_PER_EVALUATION_MAX]:
            self.stage("event", self._emit, api, event)
        self.counters["events_dropped"] += max(
            0, len(events) - EVENTS_PER_EVALUATION_MAX
        )

    def _recommendation_changes(self, when: Any) -> list[Any]:
        """New/resolved recommendations against the previous evaluation.

        An evaluation in which a router shows up for the first time since the
        start is a baseline for new ones: after a start the routers poll one
        by one, and each newcomer changes the recommendations of the others
        (co-channel neighbours) -- no storm on every restart. Resolved ones
        are always reported.
        """
        current = list(self.fleet.recommendations)
        routers = {ref.router_id for ref in self.results}
        fresh = bool(routers - self._rec_routers)
        changes = recommendation_events(self._recs_seen, current, now=when)
        self._recs_seen = current
        self._rec_routers = self._rec_routers | routers
        if not fresh:
            return changes
        return [e for e in changes if e.type != EVENT_RECOMMENDATION_NEW]

    def _emit(self, api: Any, event: Any) -> None:
        kwargs = emit_kwargs(event)
        kwargs.pop("now", None)  # the Core stamps its own time
        event_type = kwargs.pop("event_type")
        api.emit(event_type, **kwargs)  # general ring (not security relevant)
        self.counters["events_emitted"] += 1

    # -- sensitive reads -----------------------------------------------------------------

    async def async_authorize_sensitive(
        self, action: str, actor: Any, session_id: str
    ) -> Any:
        """Guard approval once per panel session, policy before every read.

        DECIDED: the Security Center has no session notion (it verifies the
        viewer per request). A panel session here is one HA login: the
        refresh token id of the request plus the user id (the view builds
        ``session_id``). The first sensitive read of a session asks the guard
        (``authorize`` + ``consume``, both audited); later reads within
        SESSION_TTL_S only re-verify the user and check the policy.
        """
        api = self._binding.api
        if api is None:
            raise RfCenterError(REASON_NO_CORE)
        verified = await api.guard.async_verify_actor(actor)
        denial = rf_policy_denial(action, verified, now=dt_util.utcnow())
        if denial is not None:
            self.counters["sessions_refused"] += 1
            raise RfCenterError("not_admin")
        if not self._binding.actions_ok:
            self._register_actions(api)
        key = (session_id, action)
        mono = self.monotonic()
        expires = self._sessions.get(key)
        if expires is None or expires <= mono:
            decision = api.guard.authorize(action, FLEET_ROUTER_ID, verified)
            if not decision.approved:
                self.counters["sessions_refused"] += 1
                raise RfCenterError("refused")
            api.guard.consume(
                decision.authorization, action=action, router_id=FLEET_ROUTER_ID
            )
            self.counters["sessions_approved"] += 1
            self._sessions[key] = mono + SESSION_TTL_S
            self._prune_sessions(mono)
        self.counters["sensitive_reads"] += 1
        return verified

    def _prune_sessions(self, mono: float) -> None:
        self._sessions = {k: v for k, v in self._sessions.items() if v > mono}
        while len(self._sessions) > SESSIONS_MAX:
            oldest = min(self._sessions, key=self._sessions.__getitem__)
            del self._sessions[oldest]

    # -- diagnostics ------------------------------------------------------------------------

    def diagnostics(self) -> dict[str, Any]:
        """Counts, states and reasons only (no id, MAC, address or key)."""
        return {
            "loaded": self.loaded,
            "status": self.status,
            "reasons": self.not_ready_reasons(),
            "entries": self.entry_count,
            "enabled_entries": len(self._enabled_states()),
            "radios": len(self.results),
            "core_bound": self._binding.api is not None,
            # not "..._key_...": the diagnostics redaction blanks such names
            "pseudonyms_ready": self.module_key is not None,
            "counters": dict(self.counters),
            "routers": [
                {
                    "status": s.status,
                    "reason": s.reason,
                    "radios": len(s.radios),
                    "options": {
                        "enabled": s.options.enabled,
                        "reads": sorted(s.options.kinds),
                        "every_n_polls": s.options.every_n_polls,
                    },
                    "collector": s.collector.summary(),
                }
                for s in self.routers.values()
            ],
            "fleet": {
                "conflicts": len(self.fleet.conflicts),
                "recommendations": len(self.fleet.recommendations),
                "monitoring_coverage": round(self.fleet.coverage, 3),
                "errors": self.fleet.errors,
            },
            "store": self.store.stats(),
            "sessions": len(self._sessions),
            "roams_kept": len(self.roams),
        }
