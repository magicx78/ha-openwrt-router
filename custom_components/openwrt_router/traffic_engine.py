"""Traffic Analytics engine: life cycle and wiring (plan 2026-11-20, §6.1, §10).

One fleet-wide engine per Home Assistant instance. Phase B scope:

* **Life cycle.** ``async_setup_traffic`` adds an entry (one coordinator
  listener per entry while active), ``async_release_traffic`` removes it;
  after the last entry the engine stops (tasks cancelled and awaited,
  listeners removed).
* **Default off, per router** (Phase K). The switch is the router option
  ``traffic_enabled`` (options flow, applied without a reload by
  ``async_apply_traffic_options``). A router with it off gets no listener
  (and a listener still called returns at once). While no router has it
  on: no snapshot, no store access at all, no entity, no event, no router
  call and no core registration.
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
* **Settings.** Per router (options flow): ``traffic_enabled``,
  ``traffic_history_profile`` and the three extra-call switches. Fleet-wide
  (``/settings``, administrators, only while on): the optional collector
  and the optional client sensors, in the core store
  ``TRAFFIC_COARSE_STORE_KEY`` (private, atomic writes), read at the first
  activation.

Every entry point catches its own errors and logs only the error type: a
poll, a setup or an unload never fails because of traffic analytics.
"""

from __future__ import annotations

import asyncio
import logging
import re
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
    OPTION_TRAFFIC_ENABLED,
    OPTION_TRAFFIC_HISTORY_PROFILE,
    OPTION_TRAFFIC_OFFLOAD_PROBE,
    OPTION_TRAFFIC_STATION_DETAIL,
    OPTION_TRAFFIC_SYSFS_FALLBACK,
    SCAN_INTERVAL_SECONDS,
    SIGNAL_TRAFFIC_ANALYTICS,
    TRAFFIC_CLIENT_SENSORS_MAX,
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
    device_point,
    estimated_uptime,
    offload_from_reply,
    samples_from_snapshot,
    snapshot_from_data,
    station_sample,
    stations_from_detail,
    sysfs_candidates,
    sysfs_samples,
)
from .traffic_collector import CollectorIntake
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
    HISTORY_PROFILE_STANDARD,
    IDENTITY_KEY_PURPOSE,
    MAX_FLOW_QUERY,
    MAX_INTERVAL_S,
    MAX_QUEUE_ROUTERS,
    MODULE_NAME,
    NOTE_POINTS_OMITTED,
    OPT_OFFLOAD_PROBE,
    OPT_STATION_DETAIL,
    OPT_SYSFS_FALLBACK,
    REASON_CORE_MISSING,
    REASON_DEVICES_OMITTED,
    REASON_DISABLED,
    REASON_FLOW_SOURCE_SILENT,
    REASON_MODULE_KEY_MISSING,
    REASON_NO_DATA_YET,
    REASON_NO_STATIONS,
    REASON_NOT_CONFIGURED,
    REASON_NOT_PROBED,
    REASON_OK,
    REASON_PAUSED,
    REASON_PERMISSION_DENIED,
    REASON_SOURCE_MISSING,
    SECURITY_DATA_KEY,
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
from .traffic_counters import (
    BaselineBook,
    finite_time,
    process_samples,
    router_restarted,
)
from .traffic_flows import FlowStore
from .traffic_history import PROFILES, TrafficHistory
from .traffic_model import (
    Coverage,
    MeasurementPoint,
    Quality,
    Rate,
    RegistryFacts,
    Scope,
    Source,
    valid_client_ref,
    valid_router_id,
)
from .traffic_store import TrafficStore
from .traffic_talkers import TalkerBoard
from .traffic_vlan import VlanView, vlan_views

_LOGGER = logging.getLogger(__name__)

# Scopes whose valid deltas are summed for the sensors (bytes, errors).
_TOTAL_SCOPES = frozenset({Scope.WAN, Scope.PORT, Scope.INTERFACE})
# The module key is asked for again at most this often while it is missing.
MODULE_KEY_RETRY_S = 300.0
# Baselines and latest rates are pruned at most this often.
PRUNE_EVERY_S = 300.0
_STATUS_SOURCE = "traffic_analytics"
_USER_ID_RE = re.compile(r"[0-9a-f]{32}")


def _local_tz() -> Any:
    """Home Assistant's time zone (local hours of the baselines), else UTC."""
    try:
        from homeassistant.util import dt as dt_util

        return dt_util.get_default_time_zone()
    except Exception:  # noqa: BLE001 - UTC is a safe fallback
        return UTC


# --- options (per router, options flow) and settings (fleet, store) ------------------


# options flow key -> engine name of the three switchable extra calls
EXTRA_OPTION_KEYS: Mapping[str, str] = {
    OPT_STATION_DETAIL: OPTION_TRAFFIC_STATION_DETAIL,
    OPT_SYSFS_FALLBACK: OPTION_TRAFFIC_SYSFS_FALLBACK,
    OPT_OFFLOAD_PROBE: OPTION_TRAFFIC_OFFLOAD_PROBE,
}


@dataclass(frozen=True, slots=True)
class TrafficOptions:
    """The traffic options of one router (config entry options)."""

    enabled: bool = False
    history_profile: str = DEFAULT_HISTORY_PROFILE
    extras: tuple[tuple[str, bool], ...] = tuple((o, False) for o in EXTRA_OPTIONS)

    def extra(self) -> dict[str, bool]:
        """The three extra-call switches (all off while traffic is off)."""
        return {k: v and self.enabled for k, v in self.extras}


def options_from_entry(options: Any) -> TrafficOptions:
    """Read an entry's traffic options; only a real True switches on.

    An unknown history profile falls back to ``compact`` (never an error).
    """
    opts = options if isinstance(options, Mapping) else {}
    profile = opts.get(OPTION_TRAFFIC_HISTORY_PROFILE, DEFAULT_HISTORY_PROFILE)
    if profile not in PROFILES:
        profile = DEFAULT_HISTORY_PROFILE
    return TrafficOptions(
        enabled=opts.get(OPTION_TRAFFIC_ENABLED) is True,
        history_profile=profile,
        extras=tuple(
            (name, opts.get(key) is True) for name, key in EXTRA_OPTION_KEYS.items()
        ),
    )


def default_router_options() -> dict[str, bool]:
    """Options of one router: every extra call off."""
    return dict.fromkeys(EXTRA_OPTIONS, False)


class TrafficSettingsError(ValueError):
    """A refused settings change; ``reason`` is a fixed token."""

    def __init__(self, reason: str) -> None:
        """Refusal with a fixed reason (no value from the request)."""
        super().__init__(reason)
        self.reason = reason


def default_settings() -> dict[str, Any]:
    """Fleet settings: no collector, no client sensor."""
    return {
        "v": SETTINGS_VERSION,
        "collector": {"enabled": False, "user_id": None},
        "client_sensors": [],
    }


def valid_user_id(value: Any) -> bool:
    """True for a Home Assistant user id (32 lower-case hex characters)."""
    return isinstance(value, str) and _USER_ID_RE.fullmatch(value) is not None


def _client_sensors(raw: Any, *, strict: bool) -> list[str]:
    if not isinstance(raw, list | tuple):
        if strict:
            raise TrafficSettingsError("client_sensors")
        return []
    out: list[str] = []
    for ref in raw:
        if not valid_client_ref(ref):
            if strict:
                raise TrafficSettingsError("client_sensors")
            continue
        if ref not in out:
            out.append(ref)
    if len(out) > TRAFFIC_CLIENT_SENSORS_MAX:
        if strict:
            raise TrafficSettingsError("client_sensors_too_many")
        out = out[:TRAFFIC_CLIENT_SENSORS_MAX]
    return sorted(out)


def _collector(raw: Any, base: Mapping[str, Any], *, strict: bool) -> dict[str, Any]:
    out = {"enabled": base.get("enabled") is True, "user_id": base.get("user_id")}
    if not isinstance(raw, Mapping):
        if strict:
            raise TrafficSettingsError("collector")
        return {"enabled": False, "user_id": None}
    for key, value in raw.items():
        if key == "enabled":
            if not isinstance(value, bool):
                if strict:
                    raise TrafficSettingsError("collector")
                continue
            out["enabled"] = value
        elif key == "user_id":
            if value is not None and not valid_user_id(value):
                if strict:
                    raise TrafficSettingsError("collector_user")
                continue
            out["user_id"] = value
        elif strict:
            raise TrafficSettingsError("collector")
    if out["enabled"] and out["user_id"] is None:
        if strict:
            raise TrafficSettingsError("collector_user_missing")
        out["enabled"] = False
    return out


def merge_settings(current: Mapping[str, Any], update: Any) -> dict[str, Any]:
    """``current`` with ``update`` applied; TrafficSettingsError if invalid.

    ``update`` may set ``collector`` (``enabled``, ``user_id``; partial
    objects merge) and ``client_sensors`` (the full list, at most
    TRAFFIC_CLIENT_SENSORS_MAX ``cli_`` pseudonyms). Nothing else: the
    switch and the history profile are router options (options flow).
    """
    if not isinstance(update, Mapping):
        raise TrafficSettingsError("not_an_object")
    if set(update) - {"collector", "client_sensors"}:
        raise TrafficSettingsError("unknown_setting")
    merged = settings_from_store(current)
    if "collector" in update:
        merged["collector"] = _collector(
            update["collector"], merged["collector"], strict=True
        )
    if "client_sensors" in update:
        merged["client_sensors"] = _client_sensors(
            update["client_sensors"], strict=True
        )
    return merged


def settings_from_store(raw: Any) -> dict[str, Any]:
    """Tolerant read of stored settings; anything broken falls back to off.

    Keys of the Phase B-J layout (``enabled``, ``routers``,
    ``history_profile``) are ignored: the switch is a router option now.
    """
    out = default_settings()
    if not isinstance(raw, Mapping):
        return out
    collector = raw.get("collector")
    if collector is not None:
        out["collector"] = _collector(collector, out["collector"], strict=False)
    out["client_sensors"] = _client_sensors(raw.get("client_sensors"), strict=False)
    return out


# --- engine -------------------------------------------------------------------------------


@dataclass(slots=True)
class _Slot:
    """One loaded entry: its coordinator and listener (memory only)."""

    coordinator: Any
    options: TrafficOptions = field(default_factory=TrafficOptions)
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
    devices_omitted: int = 0  # netdevs left out by the cap (WAN kept first)
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
    """Create the engine once and add ``entry`` with its traffic options.

    Only a router with ``traffic_enabled`` gets a listener; while no router
    has it on, nothing else happens (no store access, no core binding).
    """
    engine = async_get_traffic_engine(hass)
    if engine is None:
        engine = TrafficEngine(hass)
        hass.data[DATA_TRAFFIC_ANALYTICS] = engine
    await engine.async_load()
    engine.add_entry(
        entry.entry_id,
        coordinator,
        options_from_entry(getattr(entry, "options", None)),
    )
    _register_views(hass)
    if engine.enabled and not engine.active:
        await engine.async_activate()
    elif engine.active:
        engine.apply_profile()
    return engine


async def async_apply_traffic_options(
    hass: HomeAssistant, entry_id: str, options: Any
) -> None:
    """The options flow saved ``options`` of ``entry_id``: apply them now.

    No reload and no update listener (pattern of the configuration backup
    option). Never raises; an engine that is not loaded reads the options
    at the next setup.
    """
    engine = async_get_traffic_engine(hass)
    if engine is None:
        return
    try:
        await engine.async_apply_options(entry_id, options_from_entry(options))
    except Exception as err:  # noqa: BLE001 - the options are saved anyway
        engine._fail("options change", err)


def _register_views(hass: HomeAssistant) -> None:
    """Bind the dashboard routes and the collector intake once (also while the module is off)."""
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
        self._store_loaded = False
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
        self.indicators = SecurityIndicators(
            security=partial(self._optional, SECURITY_DATA_KEY)
        )
        self.read_api = TrafficReadApi(self)
        # Phase K: optional external collector (push intake, RAM flow store).
        self.flows = FlowStore()
        self.collector = CollectorIntake()
        self._ni_unsub: Callable[[], Any] | None = None
        # Test seams: optional modules, looked up at run time (never imported).
        self.diagnostics = DiagnosticsAdapter(partial(self._optional, DIAG_DATA_KEY))
        self.wifi_rf = WifiRfAdapter(partial(self._optional, WIFI_RF_DATA_KEY))
        self._facts: dict[str, StationFacts] = {}
        self.planner = ExtraCallPlanner()
        self.latest: dict[str, Rate] = {}
        # Phase K: sums of valid deltas per WAN / port / interface point since
        # the module went on (sensors; never estimated across a gap).
        self.totals: dict[str, dict[str, int | None]] = {}
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
        """True while at least one loaded router has ``traffic_enabled`` on."""
        return any(slot.options.enabled for slot in self._entries.values())

    @property
    def entry_ids(self) -> list[str]:
        """Loaded entry ids (sorted)."""
        return sorted(self._entries)

    @property
    def enabled_entries(self) -> list[str]:
        """Entry ids with traffic on (sorted)."""
        return sorted(e for e, s in self._entries.items() if s.options.enabled)

    def entry_enabled(self, entry_id: str) -> bool:
        """True if ``entry_id`` is loaded and has traffic on."""
        slot = self._entries.get(entry_id)
        return slot is not None and slot.options.enabled

    def entry_options(self, entry_id: str) -> TrafficOptions | None:
        """The traffic options of a loaded entry (None: not loaded)."""
        slot = self._entries.get(entry_id)
        return None if slot is None else slot.options

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
        for entry_id, slot in self._entries.items():
            if self._rid_cache.get(entry_id) == router_id:
                return slot.options.extra()
        return default_router_options()

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
        """Mark the engine set up; the store is not touched here.

        The switch is a router option, so nothing has to be read while
        traffic is off. The coarse store (fleet settings and history) is
        read once at the first activation (``_async_load_store``).
        """
        self.loaded = True

    async def _async_load_store(self) -> None:
        """Module on: read the fleet settings and the coarse store once."""
        async with self._lock:
            if self._store_loaded:
                return
            self._store_loaded = True
            try:
                data, failed = await self.store.async_load_coarse()
            except Exception as err:  # noqa: BLE001 - runs with default settings
                self._fail("store load", err)
                self.load_failed = True
                return
            self.load_failed = failed
            self.settings = settings_from_store(data.get("settings"))

    @property
    def history_profile(self) -> str:
        """``standard`` if any router with traffic on chose it, else ``compact``.

        The history is fleet-wide (one store pair), so the larger profile
        of the routers that are on applies.
        """
        chosen = {
            s.options.history_profile
            for s in self._entries.values()
            if s.options.enabled
        }
        return (
            HISTORY_PROFILE_STANDARD
            if HISTORY_PROFILE_STANDARD in chosen
            else DEFAULT_HISTORY_PROFILE
        )

    def apply_profile(self) -> None:
        """Hand the effective profile to the history (trims on a downgrade)."""
        self.series.set_profile(self.history_profile)

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
        """Apply a fleet settings change (admin only; the caller checks the user).

        Only while the module runs (``disabled`` otherwise: no store access
        while off). TrafficSettingsError for an invalid update (nothing
        changes then). Writes the coarse store at once (atomic).
        """
        if not self.active:
            raise TrafficSettingsError("disabled")
        new = merge_settings(self.settings, update)
        async with self._lock:
            self.settings = new
            await self._async_save()
        self._refresh_caps()
        self._signal()
        return settings_from_store(self.settings)

    @property
    def client_sensor_refs(self) -> list[str]:
        """Clients chosen for sensors (empty while off)."""
        if not self.active:
            return []
        return list(self.settings.get("client_sensors") or [])

    async def async_apply_options(self, entry_id: str, options: TrafficOptions) -> None:
        """New traffic options of a loaded entry (options flow, no reload)."""
        slot = self._entries.get(entry_id)
        if slot is None or self.closed:
            return
        was_on = slot.options.enabled
        slot.options = options
        if options.enabled and not self.active:
            await self.async_activate()
        elif not self.enabled and self.active:
            await self.async_deactivate()
        elif self.active:
            if options.enabled:
                self._subscribe(entry_id, slot)
            elif was_on:
                self._unsubscribe(slot)
                rid = self._rid_cache.get(entry_id)
                if rid is not None:
                    self._drop_router(rid)
            self.apply_profile()
            self._refresh_caps()
        self._signal()

    # -- entries ------------------------------------------------------------------------

    @callback
    def add_entry(
        self,
        entry_id: str,
        coordinator: Any,
        options: TrafficOptions | None = None,
    ) -> None:
        """Remember the coordinator; listen to its polls while it is on.

        # Entscheidung: while off no listener is added at all (stricter than
        # plan §1, which allows one that returns at once); switching on
        # adds one per router with traffic on, switching off removes it.
        """
        old = self._entries.pop(entry_id, None)
        if old is not None:
            self._unsubscribe(old)
        slot = _Slot(coordinator, options or TrafficOptions())
        self._entries[entry_id] = slot
        if self.active:
            self._subscribe(entry_id, slot)

    def _subscribe(self, entry_id: str, slot: _Slot) -> None:
        if slot.unsub is None and slot.options.enabled:
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
        for pid in [p for p in self.totals if p not in self.latest]:
            del self.totals[pid]
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

    def router_id_for_entry(self, entry_id: str) -> str | None:
        """Core router id of a loaded entry (None if unknown or not loaded)."""
        if entry_id not in self._entries:
            return None
        return self._rid(entry_id)

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
        await self._async_load_store()
        self.apply_profile()
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
        self.flows.clear()
        self.collector.clear()
        self.totals.clear()
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
            self.collector.emit = api.emit
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
        self.collector.emit = None
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
        elif status.devices_omitted:
            netdev = (CAP_NETDEV_COUNTERS, avail, REASON_DEVICES_OMITTED)
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
            self._collector_view(),
        )

    def _collector_view(self) -> tuple[str, CapabilityState, str]:
        if not self.collector_enabled:
            return (
                CAP_FLOW_COLLECTOR,
                CapabilityState.UNAVAILABLE,
                REASON_NOT_CONFIGURED,
            )
        state = self.collector_state
        if state == "receiving":
            return (CAP_FLOW_COLLECTOR, CapabilityState.AVAILABLE, REASON_OK)
        if state == "silent":
            return (
                CAP_FLOW_COLLECTOR,
                CapabilityState.UNKNOWN,
                REASON_FLOW_SOURCE_SILENT,
            )
        return (CAP_FLOW_COLLECTOR, CapabilityState.UNKNOWN, REASON_NO_DATA_YET)

    # -- collector (Phase K) -------------------------------------------------------------

    @property
    def collector_enabled(self) -> bool:
        """True while on, switched on in the settings and with a user."""
        collector = self.settings.get("collector") or {}
        return (
            self.active
            and collector.get("enabled") is True
            and valid_user_id(collector.get("user_id"))
        )

    def is_collector_user(self, user_id: Any) -> bool:
        """True if ``user_id`` is the configured collector user (and it is on)."""
        if not self.collector_enabled or not isinstance(user_id, str):
            return False
        return user_id == (self.settings.get("collector") or {}).get("user_id")

    @property
    def collector_state(self) -> str:
        """``off`` / ``waiting`` / ``receiving`` / ``silent``."""
        enabled = self.collector_enabled
        if not enabled or self.collector.last_accepted_wall is None:
            # No clock read needed: off or nothing received yet.
            return self.collector.state(enabled=enabled, now_wall=0.0, ttl_s=0.0)
        return self.collector.state(
            enabled=True, now_wall=self.wall(), ttl_s=self.flows.ttl_s
        )

    def ingest_collector(self, raw: bytes, *, user_id: Any = None) -> dict[str, Any]:
        """One collector call (all or nothing, see ``traffic_collector``)."""
        before = self._collector_view()
        answer = self.collector.ingest(
            raw,
            now_wall=self.wall(),
            module_key=self._module_key,
            flows=self.flows,
            known_routers=self._routers_on(),
            user_id=user_id,
        )
        if self._collector_view() != before:
            self._refresh_caps()
        return answer

    def _routers_on(self) -> frozenset[str]:
        """Router ids of the loaded entries with traffic on."""
        rids = (self._rid(e) for e, s in self._entries.items() if s.options.enabled)
        return frozenset(r for r in rids if r is not None)

    def flow_query(
        self,
        *,
        router_id: str | None = None,
        client_ref: str | None = None,
        proto: str | None = None,
        limit: int = MAX_FLOW_QUERY,
    ) -> Any:
        """Pseudonymised flow rows of the collector (``FlowQuery``)."""
        return self.flows.query(
            self.wall(),
            module_key=self._module_key,
            router_id=router_id,
            client_ref=client_ref,
            proto=proto,
            limit=limit,
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
        if slot is None or not slot.options.enabled:
            return
        now = self.clock()
        coordinator = slot.coordinator
        if getattr(coordinator, "last_update_success", True) is not True:
            slot.poll_end_mono = now
            self._maybe_retry_key(now)
            self.counters["polls_failed"] += 1
            return
        data = getattr(coordinator, "data", None)
        if data is None:
            slot.poll_end_mono = now
            return
        rid = self._rid(entry_id)
        if rid is None:
            self.counters["router_id_missing"] += 1
            return
        if self._repeated(rid, data):
            # A listener call without a new poll (e.g. after the package
            # update check): the same counters at the same sample time give
            # no rate, so nothing is processed, planned or signalled.
            self.counters["repeated_snapshots"] += 1
            return
        slot.poll_end_mono = now
        self._maybe_retry_key(now)
        snapshot = snapshot_from_data(
            data,
            router_id=rid,
            module_key=self._module_key,
            wall_s=self.wall(),
            registry=self._registry_lookup(),
        )
        self._enqueue(entry_id, snapshot)

    def _repeated(self, rid: str, data: Any) -> bool:
        """True if ``data`` carries the sample time already taken for ``rid``.

        The time of the counter read is set in the poll itself (E4), so an
        unchanged ``counters_sampled_mono`` means no new poll has run.
        """
        mono = finite_time(getattr(data, "counters_sampled_mono", None))
        if mono is None:
            return False
        queued = self._queue.get(rid)
        if queued is not None and queued[1].mono_s == mono:
            return True
        prev = self._router_clock.get(rid)
        return prev is not None and prev[0] == mono

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
        status.devices_omitted = snapshot.devices_omitted
        self.counters["devices_omitted"] += snapshot.devices_omitted
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
        kept: list[Rate] = []
        for rate in rates:
            self.quality_counts[rate.quality.value] += 1
            if rate.quality is Quality.TIME_NOT_ADVANCING:
                # No time passed (or none is known): nothing was measured, so
                # the last rate stays and the series gets no quality bit.
                continue
            kept.append(rate)
            pid = rate.point.point_id
            if self.book.has(pid):
                self.latest[pid] = rate
                if rate.has_rate and rate.point.scope in _TOTAL_SCOPES:
                    self._add_totals(rate)
            self.series.add_rate(rate)
        self.correlator.observe_rates(kept)

    def _add_totals(self, rate: Rate) -> None:
        """Bytes (RX+TX, only when both are known) and error deltas."""
        totals = self.totals.setdefault(
            rate.point.point_id, {"bytes": None, "rx_errors": None, "tx_errors": None}
        )
        if rate.rx_delta is not None and rate.tx_delta is not None:
            totals["bytes"] = (totals["bytes"] or 0) + rate.rx_delta + rate.tx_delta
        else:
            self.counters["totals_incomplete"] += 1
        for key, delta in (
            ("rx_errors", rate.rx_errors_delta),
            ("tx_errors", rate.tx_errors_delta),
        ):
            if delta is not None:
                totals[key] = (totals[key] or 0) + delta

    # -- sensor facts (Phase K, read only) ---------------------------------------------

    def wan_point(self, router_id: str) -> MeasurementPoint | None:
        """The WAN point of a router that measured WAN traffic (else None)."""
        snapshot = self._snapshots.get(router_id)
        if snapshot is None or snapshot.wan_device is None:
            return None
        point = device_point(
            router_id,
            snapshot.wan_device,
            wan_device=snapshot.wan_device,
            port_names=snapshot.port_names,
        )
        rate = self.latest.get(point.point_id)
        return point if rate is not None and rate.has_rate else None

    def uplink_point(self, router_id: str) -> tuple[MeasurementPoint | None, str]:
        """The uplink of a router and how it was chosen.

        The WAN point of a gateway (``wan``); else the one trunk port of the
        topology (``lan_uplink``). Several or no trunk ports: None
        (``uplink_unknown``); nothing is guessed.
        """
        snapshot = self._snapshots.get(router_id)
        if snapshot is None:
            return None, REASON_NO_DATA_YET
        wan = self.wan_point(router_id)
        if wan is not None:
            return wan, "wan"
        ports = snapshot.uplink_ports
        if ports is not None and len(ports) == 1:
            name = next(iter(ports))
            try:
                point = device_point(
                    router_id,
                    name,
                    wan_device=snapshot.wan_device,
                    port_names=snapshot.port_names,
                )
            except (TypeError, ValueError):
                return None, "uplink_unknown"
            return point, "lan_uplink"
        return None, "uplink_unknown"

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
        self.flows.prune(self.wall())
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
            "entries_enabled": len(self.enabled_entries),
            "history_profile": self.history_profile,
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
            "collector": {
                **self.collector.summary(),
                "enabled": self.collector_enabled,
                "state": self.collector_state,
            },
            "flows": self.flows.summary(),
            "client_sensors": len(self.client_sensor_refs),
            "extra_calls": {
                **self.planner.counters,
                "blocked": dict(self.blocked_counts),
                "peak_in_flight": self.planner.peak_in_flight,
            },
        }
