"""Traffic Analytics engine: life cycle and wiring (plan 2026-11-20, §6.1, §10).

One fleet-wide engine per Home Assistant instance. Phase B scope:

* **Life cycle.** ``async_setup_traffic`` adds an entry (one coordinator
  listener per entry while active), ``async_release_traffic`` removes it;
  after the last entry the engine stops (tasks cancelled and awaited,
  listeners removed).
* **Default off.** While ``enabled`` is not set no listener is added (and
  a listener still called returns at once): no snapshot, no store write,
  no entity, no event, no router call and no core registration. Only the
  settings store is read at setup.
* **Queue with backpressure.** The listener copies the poll's traffic
  fields synchronously (``traffic_collect.snapshot_from_data``) into a
  queue with one slot per router: a newer snapshot replaces an unprocessed
  one and ``dropped_snapshots`` counts it. A short drain task processes the
  queue (counter deltas, ``traffic_counters``) and ends when it is empty.
* **Core.** When active: event prefix ``traffic_analytics.``, a capability
  detector below ``traffic.`` and the module key (``client_ref``). Without
  the core or the key the engine is "not ready" with a reason; stations are
  then not taken at all (never a silent fallback).
* **Switchable extra calls** (``station_detail``, ``sysfs_fallback``,
  ``offload_probe``; per ``router_id``, all off by default) run through
  ``traffic_collect.ExtraCallPlanner``; the calls are ``api.py`` methods.
* **Accounting** (Phase C, ``traffic_accounting``): every new rate gets the
  coverage of its measuring area (offload, station counters) and the
  duplicate-sighting rule before it is kept in ``latest``; sums only go
  through ``sum_latest`` (one area, no overlap, named refusals).
* **Clients and VLANs** (Phase D, ``traffic_clients``/``traffic_vlan``):
  while a poll is copied, each station's MAC is looked up once in the
  client engine's history (read only, no second client database); only
  the answer is kept. Accounted station rates feed the bounded client
  tracker; VLAN views come from measured VLAN netdevs and show the
  configured ports apart.
* **History interface** (Phase E, ``traffic_series``): accounted rates
  also fill a bounded in-memory bucket ring (``series``) behind the
  ``BucketSource`` interface that the history store replaces in Phase I;
  top talkers (``talkers``) read only through it.
* **Anomaly candidates** (Phase F, ``traffic_anomaly``): at most every
  ``ANOMALY_EVAL_EVERY_S`` the detector evaluates the ring and publishes
  start/end as core events (when the event prefix is bound); there is no
  incident life cycle here (``incident_engine: not_connected``, wish W1).
* **Capacity** (Phase G, ``traffic_capacity``): ``capacity`` reads the ring
  with the link speed and duplex of the latest poll (unknown speed: no
  utilisation, never an assumed value).
* **Settings** live in the core store ``TRAFFIC_COARSE_STORE_KEY`` (private,
  atomic writes); the full history store follows in Phase I.

Every entry point catches its own errors and logs only the error type: a
poll, a setup or an unload never fails because of traffic analytics.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter, OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any

from homeassistant.core import HomeAssistant, callback

from .const import (
    DATA_TRAFFIC_ANALYTICS,
    EVENT_INCIDENT,
    SCAN_INTERVAL_SECONDS,
    SIGNAL_TRAFFIC_ANALYTICS,
)
from .core_models import CapabilityState, CapabilityStatus, InstallationKeyState
from .traffic_accounting import TrafficAccounting, TrafficSum, sum_rates
from .traffic_anomaly import AnomalyDetector
from .traffic_capacity import CapacityRow, LinkFacts, capacity_rows
from .traffic_clients import (
    ClientTracker,
    ClientTrafficView,
    StationFacts,
    registry_lookup,
    registry_routers,
    station_facts,
)
from .traffic_collect import (
    CallState,
    ExtraCallPlanner,
    ExtraTiming,
    OffloadState,
    PollState,
    Snapshot,
    detail_candidates,
    estimated_uptime,
    offload_from_reply,
    samples_from_snapshot,
    snapshot_from_data,
    station_sample,
    stations_from_detail,
    sysfs_candidates,
    sysfs_samples,
)
from .traffic_const import (
    ANOMALY_EVAL_EVERY_S,
    CAP_FLOW_COLLECTOR,
    CAP_NETDEV_COUNTERS,
    CAP_OFFLOAD_STATE,
    CAP_STATION_COUNTERS,
    CAP_STATION_DETAIL,
    CAPABILITY_PREFIX,
    CONNTRACK_SOURCE_COUNT_FILE,
    DEFAULT_HISTORY_PROFILE,
    DIAG_DATA_KEY,
    EVENT_PREFIX,
    EXTRA_OPTIONS,
    IDENTITY_KEY_PURPOSE,
    MAX_INTERVAL_S,
    MAX_QUEUE_ROUTERS,
    MAX_SETTINGS_ROUTERS,
    MODULE_NAME,
    NOTE_POINTS_OMITTED,
    OPT_OFFLOAD_PROBE,
    OPT_STATION_DETAIL,
    OPT_SYSFS_FALLBACK,
    REASON_CORE_MISSING,
    REASON_DISABLED,
    REASON_MODULE_KEY_MISSING,
    REASON_NO_DATA_YET,
    REASON_NO_STATIONS,
    REASON_NOT_CONFIGURED,
    REASON_NOT_PROBED,
    REASON_OK,
    REASON_PAUSED,
    REASON_PERMISSION_DENIED,
    REASON_SOURCE_MISSING,
    SETTINGS_VERSION,
    WIFI_RF_DATA_KEY,
)
from .traffic_correlate import (
    CorrelationReport,
    DiagnosticsAdapter,
    SecurityIndicators,
    TrafficCorrelator,
    TrafficReadApi,
    WifiRfAdapter,
)
from .traffic_counters import BaselineBook, process_samples, router_restarted
from .traffic_history import PROFILES, TrafficHistory
from .traffic_model import (
    Coverage,
    MeasurementPoint,
    Quality,
    Rate,
    RegistryFacts,
    Scope,
    Source,
    valid_router_id,
)
from .traffic_store import TrafficStore
from .traffic_talkers import TalkerBoard
from .traffic_vlan import VlanView, vlan_views

_LOGGER = logging.getLogger(__name__)

# The module key is asked for again at most this often while it is missing.
MODULE_KEY_RETRY_S = 300.0
# Baselines and latest rates are pruned at most this often.
PRUNE_EVERY_S = 300.0
_STATUS_SOURCE = "traffic_analytics"


def _local_tz() -> Any:
    """Home Assistant's time zone (local hours of the baselines), else UTC."""
    try:
        from homeassistant.util import dt as dt_util

        return dt_util.get_default_time_zone()
    except Exception:  # noqa: BLE001 - UTC is a safe fallback
        return UTC


# --- settings ------------------------------------------------------------------------------


def default_router_options() -> dict[str, bool]:
    """Options of one router: every extra call off."""
    return dict.fromkeys(EXTRA_OPTIONS, False)


def default_settings() -> dict[str, Any]:
    """Module off, no router options."""
    return {"v": SETTINGS_VERSION, "enabled": False, "routers": {}}


def _router_options(raw: Any, *, strict: bool) -> dict[str, bool]:
    out = default_router_options()
    if not isinstance(raw, Mapping):
        if strict:
            raise ValueError("router options must be an object")
        return out
    for key, value in raw.items():
        if key not in out:
            if strict:
                raise ValueError("unknown router option")
            continue
        if not isinstance(value, bool):
            if strict:
                raise ValueError("router options must be true or false")
            continue
        out[key] = value
    return out


def merge_settings(current: Mapping[str, Any], update: Any) -> dict[str, Any]:
    """``current`` with ``update`` applied; ValueError/TypeError if invalid.

    ``update`` may set ``enabled`` (bool) and per ``router_id`` the three
    options (partial objects merge). At most MAX_SETTINGS_ROUTERS routers.
    """
    if not isinstance(update, Mapping):
        raise TypeError("settings must be an object")
    unknown = set(update) - {"enabled", "routers", "history_profile"}
    if unknown:
        raise ValueError("unknown setting")
    merged = settings_from_store(current)
    if "enabled" in update:
        if not isinstance(update["enabled"], bool):
            raise ValueError("enabled must be true or false")
        merged["enabled"] = update["enabled"]
    if "history_profile" in update:
        if update["history_profile"] not in PROFILES:
            raise ValueError("unknown history profile")
        merged["history_profile"] = update["history_profile"]
    if "routers" in update:
        routers = update["routers"]
        if not isinstance(routers, Mapping):
            raise ValueError("routers must be an object")
        for rid, options in routers.items():
            if not valid_router_id(rid):
                raise ValueError("invalid router_id")
            base = merged["routers"].get(rid, default_router_options())
            new = _router_options(options, strict=True)
            given = {k: new[k] for k in options}
            merged["routers"][rid] = {**base, **given}
        if len(merged["routers"]) > MAX_SETTINGS_ROUTERS:
            raise ValueError("too many routers")
    # routers with every option off carry nothing: not stored
    merged["routers"] = {
        rid: opts for rid, opts in merged["routers"].items() if any(opts.values())
    }
    # the default profile carries nothing: not stored
    if merged.get("history_profile") == DEFAULT_HISTORY_PROFILE:
        del merged["history_profile"]
    return merged


def settings_from_store(raw: Any) -> dict[str, Any]:
    """Tolerant read of stored settings; anything broken falls back to off."""
    out = default_settings()
    if not isinstance(raw, Mapping):
        return out
    out["enabled"] = raw.get("enabled") is True
    profile = raw.get("history_profile")
    if profile in PROFILES and profile != DEFAULT_HISTORY_PROFILE:
        out["history_profile"] = profile
    routers = raw.get("routers")
    for rid, options in routers.items() if isinstance(routers, Mapping) else ():
        if len(out["routers"]) >= MAX_SETTINGS_ROUTERS:
            break
        if valid_router_id(rid):
            out["routers"][rid] = _router_options(options, strict=False)
    return out


# --- engine -------------------------------------------------------------------------------


@dataclass(slots=True)
class _Slot:
    """One loaded entry: its coordinator and listener (memory only)."""

    coordinator: Any
    unsub: Callable[[], None] | None = None
    poll_end_mono: float | None = None


@dataclass(slots=True)
class _Binding:
    """What the engine holds of the running core (released on deactivate)."""

    core: Any = None
    api: Any = None
    removers: list[Callable[[], None]] = field(default_factory=list)
    events_ok: bool = False
    detector_ok: bool = False


@dataclass(slots=True)
class RouterStatus:
    """Per-router facts of the last processed snapshot (counts only)."""

    devices: int | None = None  # None: no netdev counters (source missing)
    stations: int | None = None  # None: not ready (no module key)
    stations_total: int = 0
    stations_without_bytes: int = 0
    stations_dropped: int = 0
    conntrack_count: int | None = None
    snapshots: int = 0


@callback
def async_get_traffic_engine(hass: HomeAssistant) -> TrafficEngine | None:
    """The running engine or None (never creates one)."""
    engine = hass.data.get(DATA_TRAFFIC_ANALYTICS)
    return engine if isinstance(engine, TrafficEngine) else None


async def async_setup_traffic(
    hass: HomeAssistant, entry: Any, coordinator: Any
) -> TrafficEngine:
    """Create/load the engine once and add ``entry`` (one listener)."""
    engine = async_get_traffic_engine(hass)
    if engine is None:
        engine = TrafficEngine(hass)
        hass.data[DATA_TRAFFIC_ANALYTICS] = engine
    await engine.async_load()
    engine.add_entry(entry.entry_id, coordinator)
    _register_views(hass)
    if engine.enabled and not engine.active:
        await engine.async_activate()
    return engine


def _register_views(hass: HomeAssistant) -> None:
    """Bind the read-only dashboard routes once (also while the module is off)."""
    if getattr(hass, "http", None) is None:
        return
    try:
        from .traffic_views import async_register_traffic_views

        async_register_traffic_views(hass)
    except Exception as err:
        _LOGGER.warning("Traffic routes not bound (%s)", type(err).__name__)
        _LOGGER.debug("Traffic routes error", exc_info=err)


async def async_release_traffic(hass: HomeAssistant, entry_id: str) -> None:
    """Remove ``entry_id``; after the last entry stop the engine."""
    engine = async_get_traffic_engine(hass)
    if engine is None:
        return
    engine.remove_entry(entry_id)
    if engine.entry_count:
        return
    hass.data.pop(DATA_TRAFFIC_ANALYTICS, None)
    await engine.async_shutdown()


class TrafficEngine:
    """Fleet-wide traffic engine (Phase B: collection and counter deltas)."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Empty, off; ``async_load`` reads the settings."""
        self.hass = hass
        self.store = TrafficStore(hass)
        self._history_bound = False
        # Counter states of unloaded routers, kept for the next store write
        # only (rule 8 accepts at most a 900 s gap; older ones are useless).
        self._parked: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self.loaded = False
        self.load_failed = False
        self.settings: dict[str, Any] = default_settings()
        self.active = False
        self.closed = False
        self._entries: dict[str, _Slot] = {}
        self._rid_cache: dict[str, str] = {}
        self._queue: OrderedDict[str, tuple[str, Snapshot]] = OrderedDict()
        self._drain_task: asyncio.Task[Any] | None = None
        self._extra_tasks: set[asyncio.Task[Any]] = set()
        self._key_task: asyncio.Task[Any] | None = None
        self._key_tried: float | None = None
        self._key_warned = False
        self._module_key: bytes | None = None
        self._binding = _Binding()
        self.book = BaselineBook()
        self.accounting = TrafficAccounting()
        self.clients = ClientTracker()
        self.series = TrafficHistory()
        self.talkers = TalkerBoard(self.series)
        self.anomalies = AnomalyDetector(self.series, tz=_local_tz())
        self._last_anomaly_wall: float | None = None
        # Phase H: correlation, security indicators, read API.
        self.correlator = TrafficCorrelator()
        self.indicators = SecurityIndicators()
        self.read_api = TrafficReadApi(self)
        self._ni_unsub: Callable[[], Any] | None = None
        # Test seams: optional modules, looked up at run time (never imported).
        self.diagnostics = DiagnosticsAdapter(partial(self._optional, DIAG_DATA_KEY))
        self.wifi_rf = WifiRfAdapter(partial(self._optional, WIFI_RF_DATA_KEY))
        self._facts: dict[str, StationFacts] = {}
        self.planner = ExtraCallPlanner()
        self.latest: dict[str, Rate] = {}
        self.status: dict[str, RouterStatus] = {}
        self.offload: dict[str, OffloadState] = {}
        self._denied: dict[tuple[str, str], bool] = {}
        self._snapshots: dict[str, Snapshot] = {}
        self._router_clock: dict[str, tuple[float, int | None]] = {}
        self._cap_view: dict[str, tuple[Any, ...]] = {}
        self._cap_version = 0
        self._last_prune: float | None = None
        self.counters: Counter[str] = Counter()
        self.quality_counts: Counter[str] = Counter()
        self.blocked_counts: Counter[str] = Counter()
        # Test seams: entry id -> router id, monotonic and wall clock.
        self.router_id_of: Callable[[str], str | None] = self._registry_router_id
        self.clock: Callable[[], float] = time.monotonic
        self.wall: Callable[[], float] = time.time
        # Test seam: the client history (client engine) or None.
        self.registry_source: Callable[[], Any] = self._client_history

    # -- properties -------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """The ``enabled`` setting."""
        return self.settings.get("enabled") is True

    @property
    def entry_count(self) -> int:
        """Number of loaded entries."""
        return len(self._entries)

    @property
    def module_key_available(self) -> bool:
        """True once the core handed out the module key."""
        return self._module_key is not None

    @property
    def ready(self) -> bool:
        """Active, bound to the core and with the module key."""
        return self.not_ready_reason is None and self.active

    @property
    def not_ready_reason(self) -> str | None:
        """Why an active engine is not fully ready (None if ready or off)."""
        if not self.active:
            return None
        if self._binding.api is None:
            return REASON_CORE_MISSING
        if self._module_key is None:
            return REASON_MODULE_KEY_MISSING
        return None

    @property
    def queue_length(self) -> int:
        """Snapshots waiting for the drain task."""
        return len(self._queue)

    def router_options(self, router_id: str) -> dict[str, bool]:
        """The three extra-call options of ``router_id`` (default all off)."""
        stored = self.settings.get("routers", {}).get(router_id)
        return {**default_router_options(), **(stored or {})}

    def _optional(self, key: str) -> Any:
        """An optional module object from ``hass.data`` (None: not loaded)."""
        data = getattr(self.hass, "data", None)
        return data.get(key) if isinstance(data, dict) else None

    @property
    def history_source(self) -> Any:
        """The bucket source every reader uses (``BucketSource``)."""
        return self.series

    # -- errors -------------------------------------------------------------------------

    def _fail(self, stage: str, err: BaseException) -> None:
        """Log an error without identities (type only); never raises."""
        self.counters["errors"] += 1
        _LOGGER.warning(
            "Traffic analytics: %s failed (%s); the routers keep working",
            stage,
            type(err).__name__,
        )
        _LOGGER.debug("Traffic analytics %s error", stage, exc_info=err)

    # -- store ------------------------------------------------------------------------------

    async def async_load(self) -> None:
        """Read the settings once (nothing is written, no fine store opened)."""
        async with self._lock:
            if self.loaded:
                return
            try:
                data, failed = await self.store.async_load_coarse()
            except Exception as err:  # noqa: BLE001 - start off, never fail setup
                self._fail("store load", err)
                self.load_failed = True
                self.loaded = True
                return
            self.load_failed = failed
            self.settings = settings_from_store(data.get("settings"))
            self.series.set_profile(self.history_profile)
            self.loaded = True

    @property
    def history_profile(self) -> str:
        """The ``history_profile`` setting (compact unless chosen)."""
        return self.settings.get("history_profile", DEFAULT_HISTORY_PROFILE)

    async def _async_save(self) -> None:
        await self.store.async_save_settings(self.settings)
        self.counters["store_writes"] += 1

    async def _async_bind_history(self) -> None:
        """Module on: read the history stores once per activation."""
        if self._history_bound:
            return
        self._history_bound = True
        self.series.set_profile(self.history_profile)
        invalid = await self.store.async_bind(
            self.series,
            baselines=self._baseline_export,
            restore=lambda items: self.book.restore(items, now_mono=self.clock()),
        )
        if invalid:
            self.counters["history_invalid_entries"] += invalid

    def _baseline_export(self) -> list[dict[str, Any]]:
        """Counter states for the fine store: the book plus parked ones."""
        items = self.book.export()
        held = {i["baseline"]["point_id"] for i in items}
        oldest = self.wall() - MAX_INTERVAL_S
        for pid, item in list(self._parked.items()):
            wall = item["baseline"].get("wall_s")
            if pid in held or not isinstance(wall, int | float) or wall < oldest:
                del self._parked[pid]
                continue
            items.append(item)
        return items

    async def _async_unbind_history(self) -> None:
        """Module off / released: write both stores (kept), free the memory."""
        if not self._history_bound:
            return
        self._history_bound = False
        try:
            self.series.compact(self.wall())
        except Exception as err:  # noqa: BLE001 - write what is there
            self._fail("history compact", err)
        await self.store.async_unbind()
        self._parked.clear()

    async def async_update_settings(self, update: Any) -> dict[str, Any]:
        """Apply a settings change (admin only; the caller checks the user).

        ValueError for an invalid update (nothing changes then). Writes the
        store at once (atomic) and switches the engine on or off.
        """
        new = merge_settings(self.settings, update)
        async with self._lock:
            self.settings = new
            self.series.set_profile(self.history_profile)
            await self._async_save()
        if self.enabled and not self.active and self._entries:
            await self.async_activate()
        elif not self.enabled and self.active:
            await self.async_deactivate()
        else:
            self._refresh_caps()
        return settings_from_store(self.settings)

    # -- entries ------------------------------------------------------------------------

    @callback
    def add_entry(self, entry_id: str, coordinator: Any) -> None:
        """Remember the coordinator; listen to its polls while active.

        # Entscheidung: while off no listener is added at all (stricter than
        # plan §1, which allows one that returns at once); switching on
        # adds one per entry, switching off removes them again.
        """
        old = self._entries.pop(entry_id, None)
        if old is not None:
            self._unsubscribe(old)
        slot = _Slot(coordinator)
        self._entries[entry_id] = slot
        if self.active:
            self._subscribe(entry_id, slot)

    def _subscribe(self, entry_id: str, slot: _Slot) -> None:
        if slot.unsub is None:
            slot.unsub = slot.coordinator.async_add_listener(
                partial(self._on_poll, entry_id)
            )

    @callback
    def remove_entry(self, entry_id: str) -> None:
        """Remove the listener and forget the router's memory."""
        slot = self._entries.pop(entry_id, None)
        if slot is not None:
            self._unsubscribe(slot)
        rid = self._rid_cache.pop(entry_id, None)
        if rid is not None and rid not in self._rid_cache.values():
            self._drop_router(rid)

    def _unsubscribe(self, slot: _Slot) -> None:
        unsub, slot.unsub = slot.unsub, None
        if unsub is None:
            return
        try:
            unsub()
        except Exception as err:  # noqa: BLE001 - already removed
            _LOGGER.debug("Traffic listener removal raised (%s)", type(err).__name__)

    def _drop_router(self, rid: str) -> None:
        self._queue.pop(rid, None)
        if self._history_bound:
            for item in self.book.export():
                if item["point"].get("router_id") == rid:
                    self._parked[item["baseline"]["point_id"]] = item
        self.book.drop_router(rid)
        for pid in [p for p, r in self.latest.items() if r.point.router_id == rid]:
            del self.latest[pid]
        self.status.pop(rid, None)
        self.offload.pop(rid, None)
        self._snapshots.pop(rid, None)
        self._router_clock.pop(rid, None)
        self._cap_view.pop(rid, None)
        self.accounting.drop_router(rid)
        self.clients.drop_router(rid)
        self.anomalies.drop_router(rid)
        self.series.drop_router(rid)
        self.correlator.drop_router(rid)
        self.indicators.drop_router(rid)
        for key in [k for k in self._denied if k[0] == rid]:
            del self._denied[key]
        self.planner.drop_router(rid)

    def _registry_router_id(self, entry_id: str) -> str | None:
        api = self._binding.api
        if api is None:
            return None
        try:
            rid = api.registry.get_by_entry(entry_id).router_id
        except Exception:  # noqa: BLE001 - unknown entry: no router id yet
            return None
        return rid if valid_router_id(rid) else None

    def _rid(self, entry_id: str) -> str | None:
        rid = self._rid_cache.get(entry_id)
        if rid is None:
            found = self.router_id_of(entry_id)
            if valid_router_id(found):
                rid = self._rid_cache[entry_id] = found
        return rid

    # -- on / off --------------------------------------------------------------------------

    async def async_activate(self) -> None:
        """Switch on: bind the core (prefix, detector, module key), listen."""
        if self.active or self.closed:
            return
        self.active = True
        try:
            await self._async_bind_core()
        except Exception as err:  # noqa: BLE001 - "not ready", never raises
            self._fail("core binding", err)
        try:
            await self._async_bind_history()
        except Exception as err:  # noqa: BLE001 - runs without the stored history
            self._fail("history load", err)
        for entry_id, slot in self._entries.items():
            self._subscribe(entry_id, slot)
        self._listen_incidents()
        self._refresh_caps()

    def _listen_incidents(self) -> None:
        """Read NI incident events while active (ids and types only)."""
        if self._ni_unsub is not None:
            return
        try:
            self._ni_unsub = self.hass.bus.async_listen(
                EVENT_INCIDENT, self._on_incident
            )
        except Exception as err:  # noqa: BLE001 - NI stays "not connected"
            self._fail("incident listener", err)
            return
        self.correlator.ni_listening = True

    def _stop_incidents(self) -> None:
        unsub, self._ni_unsub = self._ni_unsub, None
        self.correlator.ni_listening = False
        if unsub is None:
            return
        try:
            unsub()
        except Exception as err:  # noqa: BLE001 - already removed
            _LOGGER.debug("Incident listener removal raised (%s)", type(err).__name__)

    @callback
    def _on_incident(self, event: Any) -> None:
        if not self.active:
            return
        try:
            self.correlator.observe_incident(
                getattr(event, "data", None), self._rid, self.wall()
            )
        except Exception as err:  # noqa: BLE001 - never disturbs NI
            self._fail("incident note", err)

    async def async_deactivate(self) -> None:
        """Switch off: no listener, no task, no core binding, no memory."""
        self.active = False
        for slot in self._entries.values():
            self._unsubscribe(slot)
        self._stop_incidents()
        self._queue.clear()
        await self._async_cancel_tasks()
        try:
            await self._async_unbind_history()
        except Exception as err:  # noqa: BLE001 - HA's final write retries
            self._fail("history write", err)
        self._unbind_core()
        self.book.clear()
        self.accounting.clear()
        self.clients.clear()
        self.series.clear()
        self.anomalies.clear()
        self.correlator.clear()
        self.indicators.clear()
        self._last_anomaly_wall = None
        self._facts.clear()
        self.latest.clear()
        self.status.clear()
        self.offload.clear()
        self._snapshots.clear()
        self._router_clock.clear()
        self._cap_view.clear()
        self._denied.clear()
        self._rid_cache.clear()
        self.planner = ExtraCallPlanner()

    async def async_shutdown(self) -> None:
        """Last entry gone: remove every listener and stop for good."""
        for slot in list(self._entries.values()):
            self._unsubscribe(slot)
        self._entries.clear()
        await self.async_deactivate()
        self.closed = True

    async def _async_cancel_tasks(self) -> None:
        tasks = [
            t
            for t in (self._drain_task, self._key_task, *self._extra_tasks)
            if t is not None and not t.done()
        ]
        current = asyncio.current_task()
        tasks = [t for t in tasks if t is not current]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._drain_task = None
        self._key_task = None
        self._extra_tasks.clear()

    # -- core -------------------------------------------------------------------------------

    async def _async_bind_core(self) -> None:
        from .config_api import async_get_configuration_api
        from .enterprise_core import async_get_core

        core = async_get_core(self.hass)
        if core is None or getattr(core, "closed", False):
            self._unbind_core()
            return
        if self._binding.core is core and self._binding.api is not None:
            await self._async_fetch_module_key()
            return
        self._unbind_core()
        api = await async_get_configuration_api(self.hass, 1)
        binding = _Binding(core=core, api=api)
        self._binding = binding
        self._rid_cache.clear()
        try:
            binding.removers.append(
                api.register_event_prefix(EVENT_PREFIX, module=MODULE_NAME)
            )
            binding.events_ok = True
            self.anomalies.publisher.emit = api.emit
            self.indicators.emit = api.emit
        except (TypeError, ValueError) as err:
            self._fail("event prefix registration", err)
        try:
            binding.removers.append(
                api.register_capability_detector(
                    MODULE_NAME,
                    self._detect_capabilities,
                    prefix=CAPABILITY_PREFIX,
                    signature=self._capability_signature,
                )
            )
            binding.detector_ok = True
        except (TypeError, ValueError) as err:
            self._fail("capability detector registration", err)
        await self._async_fetch_module_key()

    def _unbind_core(self) -> None:
        binding, self._binding = self._binding, _Binding()
        self._module_key = None
        self.anomalies.publisher.emit = None
        self.indicators.emit = None
        for remove in reversed(binding.removers):
            try:
                remove()
            except Exception as err:  # noqa: BLE001 - core already gone
                _LOGGER.debug("Traffic core remover raised (%s)", type(err).__name__)

    async def _async_fetch_module_key(self) -> None:
        binding = self._binding
        if self._module_key is not None or not binding.events_ok or not self.active:
            return
        self._key_tried = self.clock()
        try:
            state = binding.api.installation_key_state
            if state not in (
                InstallationKeyState.OK,
                InstallationKeyState.UNINITIALISED,
            ):
                self._key_missing(f"key state {getattr(state, 'value', state)}")
                return
            key = await binding.api.async_get_module_key(
                MODULE_NAME, purpose=IDENTITY_KEY_PURPOSE
            )
            if not isinstance(key, bytes) or len(key) < 16:
                raise TypeError("module key must be bytes")
        except Exception as err:  # noqa: BLE001 - stations stay "not ready"
            self._key_missing(type(err).__name__)
            return
        self._module_key = key
        self._key_warned = False

    def _key_missing(self, reason: str) -> None:
        self.counters["module_key_missing"] += 1
        if self._key_warned:
            return
        self._key_warned = True
        _LOGGER.warning(
            "Traffic analytics not ready: no module key from the core (%s); "
            "Wi-Fi station traffic is not recorded, retrying every %d s",
            reason[:64],
            MODULE_KEY_RETRY_S,
        )

    def _maybe_retry_key(self, now: float) -> None:
        if (
            self._module_key is not None
            or not self.active
            or self._binding.api is None
            or not self._binding.events_ok
            or (self._key_task is not None and not self._key_task.done())
        ):
            return
        tried = self._key_tried
        if tried is not None and 0 <= now - tried < MODULE_KEY_RETRY_S:
            return
        self._key_tried = now
        self._key_task = self.hass.async_create_task(
            self._async_fetch_module_key(), name="openwrt_router traffic key"
        )

    # -- capabilities ----------------------------------------------------------------------

    def _capability_signature(self, data: Any) -> int:
        """Changes when any traffic capability state changed (no I/O)."""
        return self._cap_version

    def _detect_capabilities(
        self, record: Any, data: Any
    ) -> dict[str, CapabilityStatus]:
        """Traffic capabilities of one router (sync, no I/O, contract §17)."""
        rid = getattr(record, "router_id", None)
        if not isinstance(rid, str):
            return {}
        now = datetime.now(UTC)
        return {
            name: CapabilityStatus(
                capability=name,
                state=state,
                reason=reason,
                source=_STATUS_SOURCE,
                detected_at=now,
            )
            for name, state, reason in self._capability_view(rid)
        }

    def _capability_view(
        self, rid: str
    ) -> tuple[tuple[str, CapabilityState, str], ...]:
        avail, unavail, unknown = (
            CapabilityState.AVAILABLE,
            CapabilityState.UNAVAILABLE,
            CapabilityState.UNKNOWN,
        )
        status = self.status.get(rid)
        if status is None:
            netdev = (CAP_NETDEV_COUNTERS, unknown, REASON_NO_DATA_YET)
        elif status.devices is None:
            netdev = (CAP_NETDEV_COUNTERS, unavail, REASON_SOURCE_MISSING)
        else:
            netdev = (CAP_NETDEV_COUNTERS, avail, REASON_OK)
        if self._module_key is None:
            station = (CAP_STATION_COUNTERS, unavail, REASON_MODULE_KEY_MISSING)
        elif status is None or status.stations is None:
            station = (CAP_STATION_COUNTERS, unknown, REASON_NO_DATA_YET)
        elif status.stations_total == 0:
            station = (CAP_STATION_COUNTERS, unknown, REASON_NO_STATIONS)
        elif status.stations == 0:
            station = (CAP_STATION_COUNTERS, unavail, REASON_SOURCE_MISSING)
        else:
            station = (CAP_STATION_COUNTERS, avail, REASON_OK)
        options = self.router_options(rid)
        return (
            netdev,
            station,
            self._option_view(rid, OPT_STATION_DETAIL, CAP_STATION_DETAIL, options),
            self._option_view(rid, OPT_OFFLOAD_PROBE, CAP_OFFLOAD_STATE, options),
            (CAP_FLOW_COLLECTOR, unavail, REASON_NOT_CONFIGURED),
        )

    def _option_view(
        self, rid: str, option: str, name: str, options: Mapping[str, bool]
    ) -> tuple[str, CapabilityState, str]:
        if not options.get(option):
            return (name, CapabilityState.UNAVAILABLE, REASON_DISABLED)
        state: CallState | None = self.planner.peek(rid, option)
        if state is not None and state.paused(self.clock()):
            return (name, CapabilityState.UNAVAILABLE, REASON_PAUSED)
        if self._denied.get((rid, option)):
            return (name, CapabilityState.UNAVAILABLE, REASON_PERMISSION_DENIED)
        if state is not None and state.last_ok_mono is not None:
            return (name, CapabilityState.AVAILABLE, REASON_OK)
        return (name, CapabilityState.UNKNOWN, REASON_NOT_PROBED)

    def _refresh_caps(self) -> None:
        """Bump the detector signature when a router's view changed."""
        changed = False
        rids = set(self._cap_view) | set(self.status)
        for rid in rids:
            view = self._capability_view(rid)
            if self._cap_view.get(rid) != view:
                self._cap_view[rid] = view
                changed = True
        if changed:
            self._cap_version += 1

    def capabilities(self, router_id: str) -> dict[str, dict[str, str]]:
        """Capability states of a router as plain dicts (panel, diagnostics)."""
        return {
            name: {"state": state.value, "reason": reason}
            for name, state, reason in self._capability_view(router_id)
        }

    # -- poll listener and queue -----------------------------------------------------------

    @callback
    def _on_poll(self, entry_id: str) -> None:
        """Coordinator listener: off -> return at once; on -> copy and queue."""
        if not self.active:
            return
        try:
            self._take_snapshot(entry_id)
        except Exception as err:  # noqa: BLE001 - never disturbs the poll
            self._fail("poll copy", err)

    def _take_snapshot(self, entry_id: str) -> None:
        slot = self._entries.get(entry_id)
        if slot is None:
            return
        now = self.clock()
        slot.poll_end_mono = now
        self._maybe_retry_key(now)
        coordinator = slot.coordinator
        if getattr(coordinator, "last_update_success", True) is not True:
            self.counters["polls_failed"] += 1
            return
        data = getattr(coordinator, "data", None)
        if data is None:
            return
        rid = self._rid(entry_id)
        if rid is None:
            self.counters["router_id_missing"] += 1
            return
        snapshot = snapshot_from_data(
            data,
            router_id=rid,
            module_key=self._module_key,
            wall_s=self.wall(),
            registry=self._registry_lookup(),
        )
        self._enqueue(entry_id, snapshot)

    def _client_history(self) -> Any:
        """The client engine's history while it runs and is on, else None."""
        from .client_engine import async_get_client_engine

        engine = async_get_client_engine(self.hass)
        if engine is None:
            return None
        settings = getattr(engine, "settings", None)
        if not isinstance(settings, Mapping) or settings.get("enabled") is not True:
            return None
        return getattr(engine, "history", None)

    def _registry_lookup(self) -> Callable[[str], RegistryFacts] | None:
        """Lookup into the client registry (None: no key or no registry)."""
        if self._module_key is None:
            return None
        try:
            history = self.registry_source()
        except Exception as err:  # noqa: BLE001 - the registry stays optional
            self._fail("client registry", err)
            return None
        if history is None:
            return None
        return registry_lookup(history, self._rid)

    def _enqueue(self, entry_id: str, snapshot: Snapshot) -> None:
        """One slot per router: a newer snapshot replaces an unprocessed one."""
        rid = snapshot.router_id
        if rid in self._queue:
            self.counters["dropped_snapshots"] += 1
        elif len(self._queue) >= MAX_QUEUE_ROUTERS:
            self.counters["dropped_snapshots"] += 1
            return
        self._queue[rid] = (entry_id, snapshot)
        self._queue.move_to_end(rid)
        self.counters["queued_snapshots"] += 1
        if self._drain_task is None or self._drain_task.done():
            self._drain_task = self.hass.async_create_task(
                self._async_drain(), name="openwrt_router traffic drain"
            )

    async def _async_drain(self) -> None:
        """Process queued snapshots until the queue is empty, then end."""
        processed = 0
        while self._queue and self.active:
            _rid, (entry_id, snapshot) = self._queue.popitem(last=False)
            try:
                self._process(entry_id, snapshot)
            except Exception as err:  # noqa: BLE001 - next snapshot goes on
                self._fail("snapshot processing", err)
            processed += 1
            await asyncio.sleep(0)
        if processed and self.active:
            self._signal()

    # -- processing ---------------------------------------------------------------------------

    def _process(self, entry_id: str, snapshot: Snapshot) -> None:
        rid = snapshot.router_id
        now = self.clock()
        restart = False
        prev = self._router_clock.get(rid)
        if snapshot.mono_s is not None:
            if prev is not None:
                dt = snapshot.mono_s - prev[0]
                restart = dt > 0 and router_restarted(prev[1], snapshot.uptime_s, dt)
            self._router_clock[rid] = (snapshot.mono_s, snapshot.uptime_s)
        if restart:
            self.counters["router_restarts"] += 1
        rates = process_samples(
            self.book,
            samples_from_snapshot(snapshot),
            now_mono=now,
            router_restart=restart,
            stale=snapshot.stale,
        )
        facts = station_facts(snapshot)
        self._facts.update(facts)
        accounted = self._account(rid, rates)
        self._keep_rates(accounted)
        self.correlator.observe_links(rid, snapshot.devices, snapshot.wall_s)
        self._end_associations(self.clients.observe(accounted, facts, now), now)
        if snapshot.wired is not None:
            self.clients.observe_wired(rid, snapshot.wired, now)
        self.counters["wired_dropped"] += snapshot.wired_dropped
        status = self.status.setdefault(rid, RouterStatus())
        status.devices = None if snapshot.devices is None else len(snapshot.devices)
        status.stations = None if snapshot.stations is None else len(snapshot.stations)
        status.stations_total = snapshot.stations_total
        status.stations_without_bytes = snapshot.stations_without_bytes
        status.stations_dropped = snapshot.stations_dropped
        status.conntrack_count = snapshot.conntrack_count
        status.snapshots += 1
        self.counters["processed_snapshots"] += 1
        self.counters["stations_dropped"] += snapshot.stations_dropped
        self.counters["invalid_items"] += snapshot.invalid_items
        if snapshot.stale:
            self.counters["stale_polls"] += 1
        self._snapshots[rid] = snapshot
        self._maybe_prune(now)
        self._persist_history()
        self._maybe_evaluate_anomalies()
        self._refresh_caps()
        self._plan_extras(entry_id, snapshot)

    def _account(self, rid: str, rates: list[Rate]) -> list[Rate]:
        """Phase C: every rate passes the accounting before it is kept."""
        return self.accounting.account(
            rates,
            offload=self.offload.get(rid),
            registry_router=registry_routers(self._facts),
        )

    def _end_associations(
        self, ended: list[tuple[str, str | None, str | None]], now: float
    ) -> None:
        """Roams: drop the baseline of the association a client left.

        A later return to that AP then starts a new baseline (no delta
        across the time at another AP).
        """
        for ref, router_id, radio_id in ended:
            try:
                point = MeasurementPoint(
                    router_id, Scope.STATION, radio_id=radio_id, client_ref=ref
                )
            except (TypeError, ValueError):
                continue
            if self.book.has(point.point_id):
                self.book.put(point, None, now)
                self.counters["roam_baselines_dropped"] += 1
            self.latest.pop(point.point_id, None)

    def _keep_rates(self, rates: list[Rate]) -> None:
        for rate in rates:
            self.quality_counts[rate.quality.value] += 1
            pid = rate.point.point_id
            if self.book.has(pid):
                self.latest[pid] = rate
            self.series.add_rate(rate)
        self.correlator.observe_rates(rates)

    def _persist_history(self) -> None:
        """Phase I: roll, apply retention, arm the throttled store writes."""
        if not self._history_bound:
            return
        coarse = self.series.compact(self.wall())
        self.store.schedule(coarse=coarse)

    def _maybe_prune(self, now: float) -> None:
        if self._last_prune is not None and 0 <= now - self._last_prune < PRUNE_EVERY_S:
            return
        self._last_prune = now
        self.book.prune(now)
        for pid in [p for p in self.latest if not self.book.has(p)]:
            del self.latest[pid]
        self.clients.prune(now)
        tracked = set(self.clients.refs())
        self._facts = {r: f for r, f in self._facts.items() if r in tracked}

    def _maybe_evaluate_anomalies(self) -> None:
        """Phase F: evaluate the ring at most every ANOMALY_EVAL_EVERY_S."""
        wall = self.wall()
        last = self._last_anomaly_wall
        if last is not None and 0 <= wall - last < ANOMALY_EVAL_EVERY_S:
            return
        self._last_anomaly_wall = wall
        sources = {
            rid: CONNTRACK_SOURCE_COUNT_FILE
            for rid, status in self.status.items()
            if status.conntrack_count is not None
        }
        try:
            self.anomalies.evaluate(wall, conntrack_sources=sources)
        except Exception as err:  # noqa: BLE001 - never disturbs processing
            self._fail("anomaly evaluation", err)
            return
        try:
            self.indicators.evaluate(
                list(self.anomalies.book.open.values()),
                self.history_source,
                now=wall,
                key=self._module_key,
                conntrack_sources=sources,
                has_points=bool(self.history_source.points()),
            )
        except Exception as err:  # noqa: BLE001 - never disturbs processing
            self._fail("indicator evaluation", err)

    def rates_of(self, router_id: str) -> list[Rate]:
        """Latest rate per point of ``router_id`` (copies of references only)."""
        return [r for r in self.latest.values() if r.point.router_id == router_id]

    def port_vlans(self) -> dict[str, dict[str, tuple[int, ...]]]:
        """Configured VLANs per port and router (last snapshots)."""
        return {
            rid: dict(snap.port_vlans)
            for rid, snap in self._snapshots.items()
            if snap.port_vlans is not None
        }

    def client_view(self, client_ref: str) -> ClientTrafficView | None:
        """Traffic view of one tracked client (None: not tracked)."""
        return self.clients.view(client_ref, port_vlans=self.port_vlans())

    def client_views(self) -> list[ClientTrafficView]:
        """Traffic views of every tracked client."""
        return self.clients.views(port_vlans=self.port_vlans())

    def vlan_views(self, router_id: str) -> list[VlanView]:
        """Measured and configured VLANs of ``router_id`` (Phase D)."""
        snapshot = self._snapshots.get(router_id)
        wired: dict[str, str] | None = None
        if snapshot is not None and snapshot.wired is not None:
            wired = {
                w.client_ref: w.port
                for w in snapshot.wired
                if not self.clients.is_wifi(w.client_ref)
            }
        return vlan_views(
            router_id,
            self.rates_of(router_id),
            port_vlans=None if snapshot is None else snapshot.port_vlans,
            wired_ports=wired,
            has_wifi=bool(snapshot is not None and snapshot.ap_interfaces),
        )

    def link_facts(self) -> dict[str, LinkFacts]:
        """Link speed and duplex per point from the latest snapshots."""
        out: dict[str, LinkFacts] = {}
        for snapshot in self._snapshots.values():
            for sample in samples_from_snapshot(snapshot):
                if sample.link_mbps is not None or sample.duplex is not None:
                    out[sample.point.point_id] = LinkFacts(
                        sample.link_mbps, sample.duplex
                    )
        return out

    def capacity(self, router_id: str | None = None) -> list[CapacityRow]:
        """Capacity rows (Phase G) over the history ring."""
        return capacity_rows(
            self.series,
            end=self.wall(),
            links=self.link_facts(),
            router_id=router_id,
            uplink_ports=self.uplink_ports(),
            tz=self.anomalies.clock.tz,
        )

    def congestion(self, router_id: str | None = None) -> CorrelationReport:
        """Bottleneck narrowing over the last hour (Phase H)."""
        return self.correlator.evaluate(
            self.history_source,
            now=self.wall(),
            links=self.link_facts(),
            uplink_ports=self.uplink_ports(),
            diagnostics=self.diagnostics,
            wifi_rf=self.wifi_rf,
            router_id=router_id,
        )

    def uplink_ports(self) -> dict[str, frozenset[str] | None]:
        """Known trunk ports per router from the last snapshots (sums)."""
        return {rid: snap.uplink_ports for rid, snap in self._snapshots.items()}

    def sum_latest(self, point_ids: list[str]) -> TrafficSum:
        """Accounting sum of the latest rates of ``point_ids`` (see Phase C).

        Unknown point ids are left out and counted as ``source_missing``.
        """
        rates = [self.latest[p] for p in point_ids if p in self.latest]
        result = sum_rates(rates, uplink_ports=self.uplink_ports())
        missing = len(point_ids) - len(rates)
        if not missing or not result.ok:
            return result
        omitted = dict(result.omitted_by_quality)
        omitted[Quality.SOURCE_MISSING.value] = (
            omitted.get(Quality.SOURCE_MISSING.value, 0) + missing
        )
        return replace(
            result,
            omitted=result.omitted + missing,
            omitted_by_quality=omitted,
            notes=(
                result.notes
                if NOTE_POINTS_OMITTED in result.notes
                else (*result.notes, NOTE_POINTS_OMITTED)
            ),
            coverage=(
                Coverage.PARTIAL
                if result.coverage is Coverage.FULL
                else result.coverage
            ),
        )

    # -- switchable extra calls ------------------------------------------------------------

    def _poll_state(self, slot: _Slot) -> PollState:
        coordinator = slot.coordinator
        api = getattr(coordinator, "api", None)
        interval = getattr(coordinator, "update_interval", None)
        seconds = interval.total_seconds() if isinstance(interval, timedelta) else None
        to_next: float | None = None
        if seconds is not None and slot.poll_end_mono is not None:
            to_next = seconds - (self.clock() - slot.poll_end_mono)
        return PollState(
            poll_running=getattr(coordinator, "poll_running", False) is True,
            throttled=seconds is not None and seconds > SCAN_INTERVAL_SECONDS,
            ssh_fallback=getattr(api, "uses_ssh_fallback", False) is True,
            seconds_to_next_poll=to_next,
        )

    def _plan_extras(self, entry_id: str, snapshot: Snapshot) -> None:
        rid = snapshot.router_id
        options = self.router_options(rid)
        if not any(options.values()):
            return  # the common case: nothing switched on, nothing to plan
        slot = self._entries.get(entry_id)
        if slot is None:
            return
        poll = self._poll_state(slot)
        now = self.clock()
        for option in EXTRA_OPTIONS:
            if not options.get(option):
                continue
            targets: tuple[str, ...] = ()
            if option == OPT_STATION_DETAIL:
                if self._module_key is None:
                    continue  # not ready: no MAC may be taken without the key
                targets = detail_candidates(snapshot)
            elif option == OPT_SYSFS_FALLBACK:
                targets = sysfs_candidates(snapshot)
            if option != OPT_OFFLOAD_PROBE and not targets:
                continue
            reason = self.planner.blocked_reason(
                rid, option, now, enabled=True, poll=poll
            )
            if reason is not None:
                self.blocked_counts[reason] += 1
                continue
            self.planner.reserve(rid, option, now)
            task = self.hass.async_create_task(
                self._async_extra(entry_id, rid, option, targets),
                name="openwrt_router traffic extra call",
            )
            self._extra_tasks.add(task)
            task.add_done_callback(self._extra_tasks.discard)
            return  # one traffic call per router at a time

    async def _async_extra(
        self, entry_id: str, rid: str, option: str, targets: tuple[str, ...]
    ) -> None:
        from .api import OpenWrtMethodNotFoundError

        slot = self._entries.get(entry_id)
        api = getattr(slot.coordinator, "api", None) if slot is not None else None
        if api is None:
            self.planner.busy.discard(rid)
            return
        if option == OPT_STATION_DETAIL:
            call = partial(api.async_traffic_station_detail, targets)
        elif option == OPT_SYSFS_FALLBACK:
            call = partial(api.async_traffic_sysfs_counters, targets)
        else:
            call = api.async_traffic_offload_state
        outcome = await self.planner.run(
            rid,
            option,
            call,
            clock=self.clock,
            permission_errors=(OpenWrtMethodNotFoundError,),
        )
        if not self.active:
            return
        self._denied[(rid, option)] = outcome.permission_denied
        if outcome.ok:
            try:
                self._take_extra(rid, option, outcome.value)
            except Exception as err:  # noqa: BLE001 - counted, never raises
                self._fail("extra call result", err)
        self._refresh_caps()

    def _take_extra(self, rid: str, option: str, value: Any) -> None:
        if option == OPT_OFFLOAD_PROBE:
            self.offload[rid] = offload_from_reply(value)
            return
        snapshot = self._snapshots.get(rid)
        if snapshot is None:
            return
        mono = self.clock()
        timing = ExtraTiming(mono, self.wall(), estimated_uptime(snapshot, mono))
        if option == OPT_STATION_DETAIL:
            key = self._module_key
            if key is None:
                return
            skip = {s.client_ref for s in snapshot.stations or ()}
            stations, invalid = stations_from_detail(value, key, skip_refs=skip)
            self.counters["invalid_items"] += invalid
            samples = [station_sample(rid, s, timing, Source.IWINFO) for s in stations]
        else:
            samples = sysfs_samples(
                rid,
                value,
                timing,
                wan_device=snapshot.wan_device,
                port_names=snapshot.port_names,
            )
        rates = process_samples(self.book, samples, now_mono=mono)
        accounted = self._account(rid, rates)
        self._keep_rates(accounted)
        self._end_associations(self.clients.observe(accounted, self._facts, mono), mono)

    # -- output --------------------------------------------------------------------------

    def _signal(self) -> None:
        try:
            from homeassistant.helpers.dispatcher import async_dispatcher_send

            async_dispatcher_send(self.hass, SIGNAL_TRAFFIC_ANALYTICS)
        except Exception as err:  # noqa: BLE001 - no listener must break the engine
            _LOGGER.debug("Traffic signal failed (%s)", type(err).__name__)

    def summary(self) -> dict[str, Any]:
        """Counts only (diagnostics, panel): no MAC, IP, host or client id."""
        return {
            "enabled": self.enabled,
            "active": self.active,
            "ready": self.ready,
            "not_ready_reason": self.not_ready_reason,
            "load_failed": self.load_failed,
            "routers": self.entry_count,
            "queue_length": self.queue_length,
            "points": {
                "infra": self.book.infra_count,
                "client": self.book.client_count,
            },
            "rates_by_quality": {
                q.value: self.quality_counts[q.value] for q in Quality
            },
            "counters": {**dict(self.counters), **self.book.counters},
            "accounting": self.accounting.summary(),
            "clients": self.clients.summary(),
            "series": self.series.summary(),
            "history_store": self.store.stats(),
            "anomalies": self.anomalies.summary(),
            "correlation": self.correlator.summary(),
            "indicators": self.indicators.summary(),
            "extra_calls": {
                **self.planner.counters,
                "blocked": dict(self.blocked_counts),
                "peak_in_flight": self.planner.peak_in_flight,
            },
        }
