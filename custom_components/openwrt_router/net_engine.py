"""Fleet-wide network intelligence engine: collect events and persist them.

One ``NetIntelligence`` per Home Assistant instance lives in ``hass.data``
(same pattern as ``fleet.FleetOutageTracker``). Every router coordinator
feeds it through a listener; the engine turns the log events of the latest
poll (``OpenWrtCoordinatorData.new_log_events`` with the cursor facts in
``new_log_batch``) into ``NetEvent`` records and counters and keeps them,
together with the full alarm machine state, in one ``Store`` file for the
whole fleet.

Scope of this module (plan 2026-11-16, P2/P3): collecting and persisting,
and running the infrastructure detectors (``net_rules.detect_infrastructure``)
on every poll; their findings become events and evidence for the alarm
machine. The WLAN detectors (P4) and the correlation (P5) run here too;
score, entities and bus events (P6) build on it.

Correlation (P5): the engine follows ``fleet.FleetOutageTracker`` (observer
hook) and turns its state into ``router_unreachable`` / ``lan_unreachable``
incidents. After every machine step (a poll of any router, an outage start
or end) it builds the router tree from LLDP and ``trunk_port_map``
(``net_rules.build_topology``, remembered per router while it is loaded)
and links follow-up incidents and events to their root cause
(``AlarmMachine.correlate``). The engine never talks to a router: it only reads
data the coordinator already has, so a poll costs exactly the same router
calls. The detectors' comparison state per router lives in memory only; a
reload or HA restart starts it fresh (first poll = baseline, no events).

Life cycle:
- ``async_get_net_intelligence`` creates the singleton on the first setup
  and loads the store before the first ingest.
- ``async_unload_net_intelligence`` drops a router's in-memory state; the
  last unload writes the store (awaited) and removes the singleton. Stored
  events of an unloaded router stay.
- ``async_remove_router_data`` deletes a removed config entry's events,
  counters, log mark and incidents from the store.

Clock: the engine uses the alarm machine's clock (``AlarmMachine.sync_clock``)
for every record, so a small step back of the HA clock never produces
times that go backwards, and a large one shifts the stored events together
with the machine state.

Log marks (plan c5): per router the cursor position (last log id and router
time) is stored. The first log read after a restart or reload is a
baseline; lines in it newer than the mark are taken in (they fell into the
gap), older ones are not. If the oldest line of that read is already newer
than the mark, lines may have been lost: a ``system.log_gap`` event (info)
records it.

Clock jumps: the listener passes ``time.monotonic()`` along, so a slow
poll (SSH fallback, 300 s plus the poll) is not mistaken for a forward jump
of the wall clock (see ``AlarmMachine.sync_clock``).

Failure handling: an unreadable, foreign or damaged store starts empty with
a warning; the file is first copied to ``<store>.bak`` (in the executor) so
the first write cannot destroy the history. An error while ingesting is
logged and never reaches the poll. After the last unload the engine is
closed: late polls are ignored and nothing is scheduled for writing.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import shutil
import time
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import timedelta
from typing import Any

from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.json import prepare_save_json
from homeassistant.helpers.storage import Store

from .const import (
    DOMAIN,
    ERROR_TYPE_AUTH,
    INTEL_MAX_STORE_BYTES,
    INTEL_PRUNE_INTERVAL_SECONDS,
    INTEL_SAVE_DELAY_SECONDS,
    INTEL_STORE_KEY,
    INTEL_STORE_MINOR_VERSION,
    INTEL_STORE_VERSION,
    LLDP_REFRESH_INTERVAL,
    LLDP_STATUS_NO_NEIGHBORS,
    LLDP_STATUS_OK,
)
from .coordinator import LogBatch
from .fleet import async_get_outage_tracker, dhcp_context
from .log_parser import (
    CATEGORY_DFS,
    CATEGORY_DHCP,
    CATEGORY_DNS,
    CATEGORY_IFACE,
    CATEGORY_LINK,
    CATEGORY_SYSTEM,
    CATEGORY_WIFI,
    COUNT_ONLY_KINDS,
    LogEvent,
)
from .net_events import (
    CLOCK_SKEW_LIMIT,
    Category,
    CauseStatus,
    EventCounters,
    EventRing,
    IncidentStatus,
    NetEvent,
    Origin,
    Scope,
    Severity,
    Source,
)
from .net_rules import (
    DECLINE_KIND,
    LAN_REACHABLE_KIND,
    LAN_UNREACHABLE_KEY,
    LAN_UNREACHABLE_KIND,
    LOG_EVENT_META,
    ROUTER_REACHABLE_KIND,
    ROUTER_UNREACHABLE_KIND,
    WIFI_LOG_RULES,
    AlarmMachine,
    Evidence,
    Finding,
    InfraSnapshot,
    InfraState,
    RouterLinks,
    Topology,
    Uplink,
    WifiContext,
    WifiSnapshot,
    WifiState,
    build_topology,
    decline_cause,
    detect_infrastructure,
    detect_wifi,
    finding_evidence,
    log_event_evidence,
    merge_settings,
    wifi_auth_evidence,
    wifi_context,
    wifi_log_meta,
)
from .topology_ports import collect_own_macs

_LOGGER = logging.getLogger(__name__)

_DATA_KEY = f"{DOMAIN}_net_intelligence"
_FLUSH_KEY = f"{DOMAIN}_net_intelligence_flush"

_DAY = 86400
_OPEN_STATES = (IncidentStatus.ACTIVE, IncidentStatus.ACKNOWLEDGED)
LOG_GAP_KIND = "system.log_gap"
_REBOOT_KIND = "system.reboot"
# ``NetEvent.router`` of the fleet-wide outage events (no single router).
FLEET_ROUTER = "fleet"

# Log event category -> NetEvent category. DFS radar/CAC lines are radio
# events, so they count as Wi-Fi.
_CATEGORY_MAP: dict[str, Category] = {
    CATEGORY_WIFI: Category.WIFI,
    CATEGORY_DHCP: Category.DHCP,
    CATEGORY_DFS: Category.WIFI,
    CATEGORY_LINK: Category.LAN,
    CATEGORY_IFACE: Category.LAN,
    CATEGORY_SYSTEM: Category.SYSTEM,
    CATEGORY_DNS: Category.DNS,
}
# Log categories stored as one event per (kind, name) and fetch, with the
# number of lines in ``count``: a crash loop or a dead resolver repeats.
_AGGREGATED_CATEGORIES = frozenset({CATEGORY_SYSTEM, CATEGORY_DNS})
_PROCESS_SOURCE = {"netifd": Source.NETIFD, "procd": Source.PROCD}


@callback
def async_get_engine(hass: HomeAssistant) -> NetIntelligence | None:
    """Return the running engine, or None (not set up / already unloaded)."""
    engine = hass.data.get(_DATA_KEY)
    return engine if isinstance(engine, NetIntelligence) else None


async def async_get_net_intelligence(hass: HomeAssistant) -> NetIntelligence:
    """Return the per-HA-instance engine; create and load it on first use."""
    engine = async_get_engine(hass)
    if engine is None:
        engine = NetIntelligence(hass)
        hass.data[_DATA_KEY] = engine
        engine.attach_outages(async_get_outage_tracker(hass))
    await engine.async_load()
    return engine


async def async_unload_net_intelligence(hass: HomeAssistant, entry_id: str) -> None:
    """Drop a router's in-memory state; save and remove the engine on the last one."""
    engine = async_get_engine(hass)
    if engine is None:
        return
    engine.unregister(entry_id)
    if engine.routers:
        return
    # Remove first, then write: a setup racing this unload builds a new
    # engine, and its load waits for the flush below. A closed engine
    # ignores late polls and schedules no write of its own.
    hass.data.pop(_DATA_KEY, None)
    engine.close()
    flush = _claim_store(hass)
    try:
        await engine.async_flush()
    finally:
        _release_store(hass, flush)


async def async_remove_router_data(hass: HomeAssistant, entry_id: str) -> None:
    """Delete everything stored about a removed config entry."""
    while True:
        await _async_wait_for_store(hass)
        engine = async_get_engine(hass)
        if engine is None:
            break
        await engine.async_load()  # a setup may still be loading it
        if engine is async_get_engine(hass):
            if engine.remove_router(entry_id):
                engine.schedule_save()
            return
    # Last entry removed: the engine is gone, edit the store directly.
    # Claim the store first, so a setup racing this removal loads only
    # after the write (otherwise it would bring the router's data back).
    claim = _claim_store(hass)
    try:
        engine = NetIntelligence(hass, claim=claim)
        await engine.async_load()
        if engine.remove_router(entry_id):
            await engine.async_flush()
    finally:
        _release_store(hass, claim)


def _claim_store(hass: HomeAssistant) -> asyncio.Future[None]:
    """Mark the store as being written; a new engine's load waits for it."""
    claim: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    hass.data[_FLUSH_KEY] = claim
    return claim


def _release_store(hass: HomeAssistant, claim: asyncio.Future[None]) -> None:
    if not claim.done():
        claim.set_result(None)
    if hass.data.get(_FLUSH_KEY) is claim:
        hass.data.pop(_FLUSH_KEY, None)


async def _async_wait_for_store(
    hass: HomeAssistant, own: asyncio.Future[None] | None = None
) -> None:
    """Wait until no other unload or removal is writing the store."""
    while True:
        pending = hass.data.get(_FLUSH_KEY)
        if not isinstance(pending, asyncio.Future) or pending.done() or pending is own:
            return
        await pending


class NetIntelligence:
    """Collects ``NetEvent``s of all routers and persists them in one store."""

    def __init__(
        self, hass: HomeAssistant, *, claim: asyncio.Future[None] | None = None
    ) -> None:
        self.hass = hass
        # The store claim this engine holds itself (removal of the last
        # entry); its load must not wait for it.
        self._claim = claim
        self._store: Store[dict[str, Any]] = Store(
            hass,
            INTEL_STORE_VERSION,
            INTEL_STORE_KEY,
            minor_version=INTEL_STORE_MINOR_VERSION,
        )
        self._lock = asyncio.Lock()
        self._loaded = False
        self.load_failed = False
        self.settings: dict[str, Any] = merge_settings(None)
        self.ring = self._new_ring()
        self.counters = EventCounters(self.settings["retention_days"])
        self.machine = AlarmMachine(self.settings)
        self._seq = 0
        self._log_marks: dict[str, dict[str, int]] = {}
        # In memory only: routers fed by a loaded entry, and the last data
        # object seen per router (a failed poll re-sends the old one).
        self._routers: set[str] = set()
        self._last_data: dict[str, Any] = {}
        # Comparison state of the infrastructure detectors per router.
        self._infra: dict[str, InfraState] = {}
        # Routers whose IPv4 WAN was connected once with the default route
        # (stored: a gateway stays one across restarts, P3 review H1).
        self._wan_gateways: set[str] = set()
        # In memory: own MACs and host IP per router, for LLDP fleet matches.
        self._identity: dict[str, frozenset[str]] = {}
        # In memory (P4): fleet-wide WLAN state, the configured host per
        # router (usteer node names) and, during one ingest, the stored
        # failed-auth lines that start an attempt (event id -> attempt key).
        self._wifi = WifiState()
        self._hosts: dict[str, str] = {}
        self._wifi_attempts: dict[str, str] = {}
        self._last_prune: float | None = None
        # P5 (in memory): the outage tracker followed, the routers and the
        # fleet outage last seen down (state change -> event), the routers
        # of the fleet outage, the last uplink per router and the topology.
        self._outages: Any = None
        self._unsub_outages: Callable[[], None] | None = None
        self._down: set[str] = set()
        self._lan_down = False
        self._lan_routers: list[str] = []
        self._uplinks: dict[str, Uplink] = {}
        self._topology = Topology()
        # True while a delayed write is scheduled: HA's async_delay_save
        # moves a pending write back on every call, so we call it once.
        self._save_pending = False
        self._closed = False
        self.last_save_bytes: int | None = None
        self.trimmed_events = 0

    # -- life cycle ---------------------------------------------------------------

    @property
    def routers(self) -> frozenset[str]:
        """Entry ids of the routers currently feeding the engine."""
        return frozenset(self._routers)

    @property
    def loaded(self) -> bool:
        """True once the store has been read (successfully or not)."""
        return self._loaded

    async def async_load(self) -> None:
        """Read the store once; a damaged or foreign store starts empty.

        In that case the file is copied to ``<store>.bak`` first (once,
        before anything is written), see the module doc.
        """
        async with self._lock:
            if self._loaded:
                return
            await _async_wait_for_store(self.hass, self._claim)
            try:
                stored = await self._store.async_load()
            except Exception:
                _LOGGER.warning(
                    "Network intelligence store %s could not be read; starting "
                    "with an empty history",
                    INTEL_STORE_KEY,
                    exc_info=True,
                )
                stored = None
                self.load_failed = True
            if stored is not None and not isinstance(stored, dict):
                _LOGGER.warning(
                    "Network intelligence store %s has an unknown format; "
                    "starting with an empty history",
                    INTEL_STORE_KEY,
                )
                stored = None
                self.load_failed = True
            if stored:
                try:
                    self._restore(stored)
                except Exception:
                    _LOGGER.warning(
                        "Network intelligence store %s could not be restored; "
                        "starting with an empty history",
                        INTEL_STORE_KEY,
                        exc_info=True,
                    )
                    self._reset()
                    self.load_failed = True
            if self.load_failed:
                await self._async_backup()
            self._loaded = True

    async def _async_backup(self) -> None:
        """Copy the unreadable store file to ``<store>.bak``; never raises."""
        path = getattr(self._store, "path", None)
        try:
            copied = await self.hass.async_add_executor_job(_backup_file, path)
        except Exception:
            _LOGGER.warning(
                "Network intelligence store backup failed; the next save "
                "replaces the old history",
                exc_info=True,
            )
            return
        if copied:
            _LOGGER.warning(
                "Network intelligence kept a copy of the unreadable store at %s.bak",
                path,
            )

    def _reset(self) -> None:
        """Back to the empty state (a store that could not be restored)."""
        self.settings = merge_settings(None)
        self.ring = self._new_ring()
        self.counters = EventCounters(self.settings["retention_days"])
        self.machine = AlarmMachine(self.settings)
        self._seq = 0
        self._log_marks = {}
        self._wan_gateways = set()

    @callback
    def register(self, entry_id: str) -> None:
        """A router's entry is loaded and starts feeding the engine."""
        self._routers.add(entry_id)
        # A reload starts from a clean comparison state (no false alarms).
        self._last_data.pop(entry_id, None)
        self._infra.pop(entry_id, None)
        self._wifi.forget(entry_id)

    @callback
    def close(self) -> None:
        """The last router is gone: ignore late polls, schedule no writes."""
        self._closed = True
        if self._unsub_outages is not None:
            self._unsub_outages()
            self._unsub_outages = None
        self._outages = None
        self._routers.clear()
        self._last_data.clear()
        self._infra.clear()
        self._identity.clear()
        self._wifi = WifiState()
        self._hosts.clear()
        self._down.clear()
        self._lan_down = False
        self._lan_routers = []
        self._uplinks.clear()
        self._topology = Topology()

    @callback
    def attach_outages(self, tracker: Any) -> None:
        """Follow the fleet outage tracker: every outage start and end
        runs the alarm machine and the correlation (P5)."""
        if self._unsub_outages is not None:
            self._unsub_outages()
        self._outages = tracker
        self._unsub_outages = tracker.add_listener(self._async_outage_changed)

    @callback
    def _async_outage_changed(self) -> None:
        """Outage observer; never raises into the tracker."""
        if self._closed or not self._loaded:
            return
        try:
            now = self._sync(time.time(), time.monotonic())
            self._run_machine(now, [])
            self.schedule_save()
        except Exception:
            _LOGGER.warning(
                "Network intelligence could not process an outage change",
                exc_info=True,
            )

    @callback
    def unregister(self, entry_id: str) -> None:
        """A router's entry is unloaded; its stored data stays."""
        self._routers.discard(entry_id)
        self._last_data.pop(entry_id, None)
        self._infra.pop(entry_id, None)
        self._identity.pop(entry_id, None)
        self._wifi.forget(entry_id)
        self._hosts.pop(entry_id, None)
        self._down.discard(entry_id)
        self._uplinks.pop(entry_id, None)

    def remove_router(self, entry_id: str) -> bool:
        """Forget all data of a router; True if anything was removed."""
        self.unregister(entry_id)
        removed = self.ring.remove_router(entry_id) > 0
        removed |= entry_id in self.counters.to_dict()
        self.counters.remove_router(entry_id)
        removed |= self._log_marks.pop(entry_id, None) is not None
        removed |= entry_id in self._wan_gateways
        self._wan_gateways.discard(entry_id)
        removed |= self.machine.remove_router(entry_id) > 0
        return removed

    @callback
    def schedule_save(self) -> None:
        """Write the store at most ``INTEL_SAVE_DELAY_SECONDS`` from now."""
        if self._save_pending or self._closed:
            return
        self._save_pending = True
        self._store.async_delay_save(self._data_to_save, INTEL_SAVE_DELAY_SECONDS)

    async def async_flush(self) -> None:
        """Write the store now (replaces a pending delayed write)."""
        await self._store.async_save(self._data_to_save())

    # -- ingest -------------------------------------------------------------------

    @callback
    def async_ingest_coordinator(self, entry_id: str, coordinator: Any) -> None:
        """Coordinator listener: ingest the latest poll; never raises."""
        try:
            entry = getattr(coordinator, "config_entry", None)
            entry_data = getattr(entry, "data", None)
            host = entry_data.get(CONF_HOST) if isinstance(entry_data, dict) else None
            interval = getattr(coordinator, "update_interval", None)
            self.ingest(
                entry_id,
                coordinator.data,
                time.time(),
                time.monotonic(),
                host=host if isinstance(host, str) else None,
                interval=interval.total_seconds()
                if isinstance(interval, timedelta)
                else None,
            )
        except Exception:
            _LOGGER.warning(
                "Network intelligence could not process a poll of %s",
                entry_id,
                exc_info=True,
            )

    def ingest(
        self,
        entry_id: str,
        data: Any,
        now: float,
        mono: float | None = None,
        *,
        host: str | None = None,
        interval: float | None = None,
    ) -> int:
        """Ingest one poll's data; return the number of stored events.

        Only registered routers are ingested (a poll can still arrive
        after the unload). The same data object is ingested only once:
        after a failed poll the coordinator notifies its listeners with the
        previous data. ``now`` (wall time) and ``mono`` (monotonic time, if
        known) go through the machine clock first (see module doc).
        ``host`` (the entry's router address) joins the router's identity
        for LLDP fleet matches; ``interval`` is the poll interval in seconds.
        """
        if self._closed or entry_id not in self._routers:
            return 0
        if data is None or self._last_data.get(entry_id) is data:
            return 0
        self._last_data[entry_id] = data
        self._update_identity(entry_id, data, host)
        now = self._sync(now, mono)
        log_events = getattr(data, "new_log_events", ())
        if not isinstance(log_events, (tuple, list)):
            log_events = ()
        batch = getattr(data, "new_log_batch", None)
        if not isinstance(batch, LogBatch):
            batch = None
        mark_before = self._log_marks.get(entry_id)
        context = wifi_context(
            getattr(data, "ap_interfaces", None), getattr(data, "clients", None)
        )
        self._wifi_attempts = {}
        stored, log_stored, accepted = self._ingest_log(
            entry_id,
            log_events,
            batch,
            now,
            getattr(data, "arp_table", None),
            context,
            interval,
        )
        fresh = batch is not None and not batch.baseline
        thresholds = self.settings["thresholds"]
        exclude = self._excluded_macs()
        evidence: list[Evidence] = []
        if fresh:
            evidence.extend(
                item
                for event in log_stored
                if (item := log_event_evidence(event)) is not None
            )
            evidence.extend(
                wifi_auth_evidence(
                    self._wifi,
                    log_stored,
                    self._wifi_attempts,
                    now,
                    entry_id,
                    thresholds,
                    exclude,
                )
            )
        snapshot = infra_snapshot(
            data,
            tuple(accepted) if fresh else (),
            fresh,
            log_times=_log_times(batch, mark_before, accepted) if fresh else (),
            poll_interval=interval,
            uplink_ports=self._topology.ports_of(entry_id),
        )
        findings = self._infra_findings(entry_id, snapshot, now)
        stored += self._store_findings(entry_id, findings, now, evidence)
        wifi = wifi_snapshot(
            data,
            context,
            tuple(accepted) if fresh else (),
            batch,
            dhcp=self._dhcp_context(),
            hosts={host: router for router, host in self._hosts.items()},
            rebooted=any(f.kind == _REBOOT_KIND for f in findings),
            poll_interval=interval,
            exclude=exclude,
        )
        stored += self._store_findings(
            entry_id,
            detect_wifi(self._wifi, wifi, now, entry_id, thresholds),
            now,
            evidence,
        )
        evidence.extend(self._wifi_holds(entry_id, now, context))
        stored += self._run_machine(now, evidence)
        self._prune(now)
        if stored or self._log_marks.get(entry_id) != mark_before:
            self.schedule_save()
        return stored

    def _sync(self, now: float, mono: float | None) -> float:
        """Advance the machine clock; move or reset the detector state on a
        clock jump; return the time to use for this step."""
        step = self.machine.sync_clock(now, mono)
        if step.shift:
            self.ring.shift(step.shift)
            for state in self._infra.values():
                state.shift(step.shift)
            self._wifi.shift(step.shift)
        if self.machine.prune_held:
            for state in self._infra.values():
                state.clock_jumped()
        return step.now

    def _run_machine(self, now: float, evidence: list[Evidence]) -> int:
        """Outage evidence, machine step, topology, correlation; return the
        number of stored (outage) events."""
        stored, outage = self._outage_evidence(now)
        self.machine.update(now, [*evidence, *outage])
        if self._lan_down:
            self.machine.set_routers(
                "lan_unreachable", LAN_UNREACHABLE_KEY, self._lan_routers
            )
        self._topology = self._build_topology()
        result = self.machine.correlate(now, self._topology, self.ring)
        self.ring.set_parents(result.events)
        return stored

    def _outage_evidence(self, now: float) -> tuple[int, list[Evidence]]:
        """Evidence for ``router_unreachable`` / ``lan_unreachable`` from
        the outage tracker; stores an event on every change.

        A loaded router is down while the tracker lists it past the failure
        threshold and it is reported, part of the fleet outage, or its
        incident is already open (after a fleet outage ends the routers
        still away get a new settle window: their incident stays). Auth
        errors are no outage. A router without a loaded entry keeps its
        open incident unchanged (unknown).
        """
        tracker = self._outages
        if tracker is None:
            return 0, []
        view = tracker.snapshot()
        fleet_since = view.fleet_since
        open_routers = {
            key for _t, _s, key in self.machine.open_keys(("router_unreachable",))
        }
        down: dict[str, Any] = {}
        for router in self._routers:
            outage = view.down.get(router)
            if outage is None or outage.error_type == ERROR_TYPE_AUTH:
                continue
            if outage.reported or fleet_since is not None or router in open_routers:
                down[router] = outage
        stored = 0
        evidence: list[Evidence] = []
        for router in sorted(self._routers):
            outage = down.get(router)
            event: NetEvent | None = None
            if (outage is not None) != (router in self._down):
                event = self._outage_event(
                    router,
                    ROUTER_UNREACHABLE_KIND if outage else ROUTER_REACHABLE_KIND,
                    now,
                    Severity.WARNING if outage else Severity.INFO,
                    {"error_type": outage.error_type} if outage else {},
                )
                stored += 1
            if outage is not None:
                self._down.add(router)
                evidence.append(
                    Evidence(
                        type="router_unreachable",
                        scope_key=router,
                        scope=Scope.ROUTER,
                        kind=ROUTER_UNREACHABLE_KIND,
                        event_id=event.id if event else None,
                        value=1.0,
                        router=router,
                        cause="router_unreachable",
                        cause_status=CauseStatus.CONFIRMED,
                        since=outage.since.timestamp(),
                    )
                )
            else:
                self._down.discard(router)
                if router in open_routers:
                    evidence.append(
                        Evidence(
                            type="router_unreachable",
                            scope_key=router,
                            kind=ROUTER_REACHABLE_KIND,
                            value=0.0,
                            router=router,
                        )
                    )
        lan = fleet_since is not None
        lan_open = bool(self.machine.open_keys(("lan_unreachable",)))
        event = None
        if lan != self._lan_down:
            event = self._outage_event(
                FLEET_ROUTER,
                LAN_UNREACHABLE_KIND if lan else LAN_REACHABLE_KIND,
                now,
                Severity.CRITICAL if lan else Severity.INFO,
                {"routers": len(down)} if lan else {},
            )
            stored += 1
        self._lan_down = lan
        self._lan_routers = sorted(down) if lan else []
        if lan:
            evidence.append(
                Evidence(
                    type="lan_unreachable",
                    scope_key=LAN_UNREACHABLE_KEY,
                    scope=Scope.FLEET,
                    kind=LAN_UNREACHABLE_KIND,
                    event_id=event.id if event else None,
                    value=1.0,
                    cause="lan_unreachable",
                    cause_status=CauseStatus.CONFIRMED,
                    since=fleet_since.timestamp(),  # type: ignore[union-attr]
                )
            )
        elif lan_open:
            evidence.append(
                Evidence(
                    type="lan_unreachable",
                    scope_key=LAN_UNREACHABLE_KEY,
                    scope=Scope.FLEET,
                    kind=LAN_REACHABLE_KIND,
                    value=0.0,
                )
            )
        return stored, evidence

    def _outage_event(
        self,
        router: str,
        kind: str,
        now: float,
        severity: Severity,
        params: dict[str, Any],
    ) -> NetEvent:
        self._seq += 1
        event = NetEvent(
            id=f"{router}:{self._seq}",
            ts=now,
            router=router,
            category=Category.SYSTEM,
            kind=kind,
            origin=Origin.OBSERVED,
            source=Source.FLEET,
            severity=severity,
            msg_key=kind,
            params=params,
        )
        self.ring.add(event)
        if router != FLEET_ROUTER:
            self.counters.add(router, kind, now)
        return event

    def _build_topology(self) -> Topology:
        """Router tree from the last data of the loaded routers."""
        links: dict[str, RouterLinks] = {}
        for router in self._routers:
            data = self._last_data.get(router)
            lldp = getattr(data, "lldp_neighbors", None)
            trunk = getattr(data, "trunk_port_map", None)
            links[router] = RouterLinks(
                ids=self._identity.get(router, frozenset()),
                host=self._hosts.get(router),
                lldp=tuple(n for n in lldp if isinstance(n, dict))
                if isinstance(lldp, list)
                else (),
                trunk={
                    ip: port
                    for ip, port in trunk.items()
                    if isinstance(ip, str) and isinstance(port, str)
                }
                if isinstance(trunk, dict)
                else {},
                gateway=router in self._wan_gateways,
            )
        topology = build_topology(links, self._uplinks)
        self._uplinks = dict(topology.uplinks)
        return topology

    def _ingest_log(
        self,
        entry_id: str,
        events: Iterable[Any],
        batch: LogBatch | None,
        now: float,
        arp: Any = None,
        wifi: WifiContext | None = None,
        interval: float | None = None,
    ) -> tuple[int, list[NetEvent], list[LogEvent]]:
        """Count and store the log events of one poll.

        Returns the number of stored events (a log gap included), the
        stored log events, and the log events taken in (for the detectors).
        ``arp`` (MAC -> IPv4 of this poll) confirms a DHCPDECLINE, ``wifi``
        (this poll's AP interfaces and clients) adds SSID, band and signal
        to fresh Wi-Fi lines (not to the lines of a log gap); ``interval``
        is the poll interval.
        """
        stored = 0
        baseline = batch is not None and batch.baseline
        if batch is not None and baseline:
            events, stored = self._gap_events(entry_id, events, batch, now)
        accepted: list[LogEvent] = []
        kept: list[NetEvent] = []
        groups: dict[tuple[str, str | None], list[tuple[LogEvent, float]]] = {}
        for event in events:
            if not isinstance(event, LogEvent):
                continue
            category = _CATEGORY_MAP.get(event.category)
            if category is None:
                continue
            accepted.append(event)
            src_ts = event.time_ms / 1000 if event.time_ms > 0 else None
            # Gap lines happened before this poll: keep their router time.
            ts = src_ts if baseline and src_ts is not None and src_ts <= now else now
            self.counters.add(entry_id, event.key, ts)
            if (event.category, event.kind) in COUNT_ONLY_KINDS:
                continue
            if event.category in _AGGREGATED_CATEGORIES:
                groups.setdefault((event.key, event.name), []).append((event, ts))
                continue
            kept.append(
                self._net_event(
                    entry_id,
                    category,
                    event,
                    ts,
                    src_ts,
                    now,
                    baseline,
                    arp=arp,
                    wifi=None if baseline else wifi,
                    interval=interval,
                )
            )
        for group in groups.values():
            event, ts = group[0]
            src_ts = event.time_ms / 1000 if event.time_ms > 0 else None
            kept.append(
                self._net_event(
                    entry_id,
                    _CATEGORY_MAP[event.category],
                    event,
                    ts,
                    src_ts,
                    now,
                    baseline,
                    count=len(group),
                    arp=arp,
                )
            )
        for net_event in kept:
            self.ring.add(net_event)
        stored += len(kept)
        if batch is not None and batch.last_id is not None:
            mark = {"last_id": batch.last_id}
            if batch.last_time_ms is not None:
                mark["last_time_ms"] = batch.last_time_ms
            self._log_marks[entry_id] = mark
        return stored, kept, accepted

    def _infra_findings(
        self, entry_id: str, snapshot: InfraSnapshot, now: float
    ) -> list[Finding]:
        """Run the infrastructure detectors for one poll."""
        state = self._infra.get(entry_id)
        if state is None:
            state = InfraState(wan_gateway=entry_id in self._wan_gateways)
            self._infra[entry_id] = state
        fleet = frozenset().union(
            *(ids for router, ids in self._identity.items() if router != entry_id)
        )
        findings = detect_infrastructure(
            state,
            snapshot,
            now,
            entry_id,
            self.settings["thresholds"],
            lldp_interval=LLDP_REFRESH_INTERVAL,
            fleet=fleet,
        )
        if state.wan_gateway and entry_id not in self._wan_gateways:
            self._wan_gateways.add(entry_id)
            self.schedule_save()
        return findings

    def _store_findings(
        self,
        entry_id: str,
        findings: Iterable[Finding],
        now: float,
        evidence: list[Evidence],
    ) -> int:
        """Store and count findings; return the number of stored events.

        Findings marked ``event`` are stored and counted, findings with a
        rule become evidence (appended to ``evidence``), the rest is only
        counted.
        """
        stored = 0
        for finding in findings:
            event: NetEvent | None = None
            if finding.event:
                event = self._finding_event(entry_id, finding, now)
                self.ring.add(event)
                stored += 1
            if finding.event or not finding.rule:
                self.counters.add(entry_id, finding.kind, now, finding.count)
            item = finding_evidence(finding, entry_id, event)
            if item is not None:
                evidence.append(item)
        return stored

    def _dhcp_context(
        self,
    ) -> tuple[frozenset[str], frozenset[str], frozenset[str]] | None:
        """``fleet.dhcp_context`` (None = unknown, also on any error)."""
        try:
            return dhcp_context(self.hass)
        except Exception:
            _LOGGER.debug("DHCP context unavailable", exc_info=True)
            return None

    def _excluded_macs(self) -> frozenset[str]:
        """``exclusions.macs`` of the settings, upper case."""
        macs = self.settings.get("exclusions", {}).get("macs") or ()
        return frozenset(m.strip().upper() for m in macs if isinstance(m, str))

    def _wifi_holds(
        self, entry_id: str, now: float, context: WifiContext
    ) -> list[Evidence]:
        """Keep the router's open log-based Wi-Fi incidents open while its
        log cannot be read: no lines is no proof of a healthy WLAN. Held at
        most _WIFI_HOLD_MAX after the log was lost, and a client incident
        only while the router still lists the client (P4 review K3)."""
        if not self._wifi.may_hold(entry_id, now):
            return []
        clients = context.clients
        return [
            Evidence(
                type=type_,
                scope_key=key,
                scope=scope,
                router=entry_id,
                hold=True,
            )
            for type_, scope, key in self.machine.open_keys(WIFI_LOG_RULES, entry_id)
            if scope is not Scope.CLIENT or clients is None or key in clients
        ]

    def _update_identity(self, entry_id: str, data: Any, host: str | None) -> None:
        """Own MACs and host address of a router (LLDP fleet matches)."""
        info = getattr(data, "router_info", None)
        aps = getattr(data, "ap_interfaces", None)
        stas = getattr(data, "sta_interfaces", None)
        try:
            macs = collect_own_macs(
                info if isinstance(info, dict) else None,
                [a for a in aps if isinstance(a, dict)]
                if isinstance(aps, list)
                else [],
                [s for s in stas if isinstance(s, dict)]
                if isinstance(stas, list)
                else [],
            )
        except (AttributeError, TypeError):
            macs = set()
        ids = set(macs) if macs else set(self._identity.get(entry_id, ()))
        if host:
            ids.add(host.strip().lower())
            self._hosts[entry_id] = host.strip().lower()
        if ids:
            self._identity[entry_id] = frozenset(ids)

    def _finding_event(self, entry_id: str, finding: Finding, now: float) -> NetEvent:
        self._seq += 1
        return NetEvent(
            id=f"{entry_id}:{self._seq}",
            ts=now,
            router=entry_id,
            category=finding.category,
            kind=finding.kind,
            origin=finding.origin,
            source=finding.source,
            subject=dict(finding.subject),
            count=finding.count,
            severity=finding.severity,
            cause=finding.cause,
            cause_status=finding.cause_status,
            confidence=finding.confidence,
            msg_key=finding.kind,
            params=dict(finding.params),
            signal=finding.signal,
        )

    def _gap_events(
        self,
        entry_id: str,
        events: Iterable[Any],
        batch: LogBatch,
        now: float,
    ) -> tuple[list[Any], int]:
        """Lines of a baseline read that are newer than the stored mark.

        Returns them and the number of events stored for a gap (0 or 1).
        Without a mark (first contact) or a usable router time nothing is
        taken: those lines are history the coordinator already counts.
        """
        last_ms = self._log_marks.get(entry_id, {}).get("last_time_ms")
        if last_ms is None:
            return [], 0
        gap = 0
        if batch.first_time_ms is not None and batch.first_time_ms > last_ms:
            self._record_gap(entry_id, (batch.first_time_ms - last_ms) / 1000, now)
            gap = 1
        newer = [e for e in events if isinstance(e, LogEvent) and e.time_ms > last_ms]
        return newer, gap

    def _record_gap(self, entry_id: str, gap_s: float, now: float) -> None:
        self._seq += 1
        self.counters.add(entry_id, LOG_GAP_KIND, now)
        self.ring.add(
            NetEvent(
                id=f"{entry_id}:{self._seq}",
                ts=now,
                router=entry_id,
                category=Category.SYSTEM,
                kind=LOG_GAP_KIND,
                origin=Origin.OBSERVED,
                source=Source.LOG,
                severity=Severity.INFO,
                msg_key=LOG_GAP_KIND,
                params={"gap_s": round(gap_s)},
            )
        )

    def _net_event(
        self,
        entry_id: str,
        category: Category,
        event: LogEvent,
        ts: float,
        src_ts: float | None,
        now: float,
        in_gap: bool = False,
        count: int = 1,
        arp: Any = None,
        wifi: WifiContext | None = None,
        interval: float | None = None,
    ) -> NetEvent:
        self._seq += 1
        # A gap line (read after a restart) is old by nature and newer than
        # the log mark; only a router time ahead of HA marks it as skewed.
        if src_ts is None:
            skew = False
        elif in_gap:
            skew = src_ts > now + CLOCK_SKEW_LIMIT
        else:
            skew = abs(src_ts - now) > CLOCK_SKEW_LIMIT
        subject = {
            key: value
            for key, value in (
                ("mac", event.mac),
                ("iface", event.interface),
                ("ip", event.ip),
                (_NAME_KEY.get(event.key, "name"), event.name),
            )
            if value
        }
        severity, cause, cause_status, confidence = LOG_EVENT_META.get(
            event.key, (Severity.INFO, None, None, 1.0)
        )
        if event.key == DECLINE_KIND:
            cause_status, confidence = decline_cause(event.ip, event.mac, arp)
        params = {
            key: value
            for key, value in (
                ("frequency", event.frequency),
                ("channel", event.channel),
            )
            if value is not None
        }
        signal: int | None = None
        if category is Category.WIFI and wifi is not None:
            meta = wifi_log_meta(
                self._wifi,
                wifi,
                event,
                entry_id,
                now,
                self.settings["thresholds"],
                interval,
            )
            subject.update(meta.subject)
            signal = meta.signal
            params.update(meta.params)
            if meta.cause is not None:
                cause, cause_status = meta.cause, meta.cause_status
            if meta.attempt and meta.attempt_key is not None:
                self._wifi_attempts[f"{entry_id}:{self._seq}"] = meta.attempt_key
        return NetEvent(
            id=f"{entry_id}:{self._seq}",
            ts=ts,
            router=entry_id,
            category=category,
            kind=event.key,
            origin=Origin.OBSERVED,
            source=_PROCESS_SOURCE.get(event.process or "", Source.LOG),
            subject=subject,
            count=count,
            severity=severity,
            cause=cause,
            cause_status=cause_status,
            confidence=confidence,
            msg_key=event.key,
            params=params,
            src_ts=src_ts,
            clock_skew=skew,
            signal=signal,
        )

    # -- read access (diagnostics, later the panel) -----------------------------------

    def diagnostics(self, entry_id: str, now: float) -> dict[str, Any]:
        """Identity-free summary of one router: counts, types and times only."""
        last = self.machine.last_now
        if last is not None and now < last:
            now = last  # the engine clock never goes backwards
        since = now - _DAY
        events = [e for e in self.ring if e.router == entry_id]
        by_category = Counter(e.category.value for e in events if e.ts >= since)
        counters = self.counters.to_dict().get(entry_id, {})
        by_kind = {
            kind: n
            for kind in sorted(counters)
            if (n := self.counters.hourly(entry_id, kind, now, 24))
        }
        active = Counter(
            inc.type
            for inc in self.machine.incidents()
            if inc.status in _OPEN_STATES
            and (entry_id in inc.routers or inc.scope_key == entry_id)
        )
        return {
            "loaded": self._loaded,
            "store_load_failed": self.load_failed,
            "events_stored": len(events),
            "events_stored_fleet": len(self.ring),
            "oldest_event_age_s": round(now - min(e.ts for e in events))
            if events
            else None,
            "counts_by_category_24h": dict(sorted(by_category.items())),
            "counts_by_kind_24h": by_kind,
            "active_by_type": dict(sorted(active.items())),
            "incidents_stored_fleet": len(self.machine.incidents()),
            "log_mark_stored": entry_id in self._log_marks,
            "store_bytes_last_save": self.last_save_bytes,
            "events_trimmed_for_size": self.trimmed_events,
            # Health score and coverage arrive with P6; P4 reports the
            # WLAN data coverage (no identities).
            "score": None,
            "coverage": None,
            "wifi_coverage": self._wifi.coverage(entry_id),
        }

    # -- persistence --------------------------------------------------------------

    def _new_ring(self) -> EventRing:
        return EventRing(
            max_count=self.settings["max_events"],
            max_age=self.settings["retention_days"] * _DAY,
        )

    def _restore(self, stored: dict[str, Any]) -> None:
        self.settings = merge_settings(stored.get("settings"))
        ring = EventRing.from_list(
            stored.get("events"),
            max_count=self.settings["max_events"],
            max_age=self.settings["retention_days"] * _DAY,
        )
        self.ring = ring
        self.counters = EventCounters.from_dict(
            stored.get("counters"), self.settings["retention_days"]
        )
        self.machine = AlarmMachine.from_dict(stored.get("machine"), self.settings)
        seq = stored.get("seq")
        self._seq = seq if isinstance(seq, int) and not isinstance(seq, bool) else 0
        self._seq = max(self._seq, _highest_seq(ring))
        self._log_marks = _load_marks(stored.get("log_marks"))
        gateways = stored.get("wan_gateways")
        self._wan_gateways = (
            {r for r in gateways if isinstance(r, str) and r}
            if isinstance(gateways, list)
            else set()
        )

    def _prune(self, now: float) -> None:
        if self.machine.prune_held:
            return  # right after a forward clock jump: keep the history
        if (
            self._last_prune is not None
            and 0 <= now - self._last_prune < INTEL_PRUNE_INTERVAL_SECONDS
        ):
            return
        self._last_prune = now
        self.ring.prune(now)
        self.counters.prune(now)

    def _payload(self) -> dict[str, Any]:
        return {
            "settings": self.settings,
            "seq": self._seq,
            "events": self.ring.to_list(compact=True),
            "machine": self.machine.to_dict(compact=True),
            "counters": self.counters.to_dict(),
            "log_marks": self._log_marks,
            "wan_gateways": sorted(self._wan_gateways),
        }

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        """Store payload, trimmed to ``INTEL_MAX_STORE_BYTES``.

        The oldest events go first; they are dropped from memory too, so
        memory and file agree. Incidents are never trimmed here (the
        machine caps them by count); if the file is still too large without
        any event, it is written anyway with a warning.
        """
        self._save_pending = False
        now = self.machine.last_now
        if now is not None and not self.machine.prune_held:
            self.ring.prune(now)
            self.counters.prune(now)
        payload = self._payload()
        size = _store_size(payload)
        # Built once; each round only re-measures a shorter event list,
        # dropping the excess divided by the average event size (usually
        # one round, a second one if the oldest events were small).
        events = payload["events"]
        drop = 0
        if size > INTEL_MAX_STORE_BYTES and events:
            payload["events"] = []
            base = _store_size(payload)
            while size > INTEL_MAX_STORE_BYTES and drop < len(events):
                per_event = max(1.0, (size - base) / (len(events) - drop))
                more = max(1, math.ceil((size - INTEL_MAX_STORE_BYTES) / per_event))
                drop = min(len(events), drop + more)
                payload["events"] = events[drop:]
                size = _store_size(payload)
        if drop:
            self._drop_oldest(drop)
            self.trimmed_events += drop
        if size > INTEL_MAX_STORE_BYTES:
            _LOGGER.warning(
                "Network intelligence store is %d bytes without any event (limit %d)",
                size,
                INTEL_MAX_STORE_BYTES,
            )
        self.last_save_bytes = size
        return payload

    def _drop_oldest(self, count: int) -> None:
        keep = list(self.ring)[count:]
        ring = self._new_ring()
        for event in keep:
            ring.add(event)
        self.ring = ring


# Subject key of ``LogEvent.name`` per kind (default "name").
_NAME_KEY = {"system.service_crash_loop": "service", "system.oom_kill": "process"}


def _log_times(
    batch: LogBatch | None,
    mark_before: dict[str, int] | None,
    accepted: Iterable[LogEvent],
) -> tuple[float, ...]:
    """Router times (epoch s) of the new lines of a fresh log fetch."""
    if batch is None or batch.last_id is None:
        return ()
    if mark_before is not None and mark_before.get("last_id") == batch.last_id:
        return ()  # nothing new
    times = {e.time_ms / 1000 for e in accepted if e.time_ms > 0}
    if batch.last_time_ms is not None:
        times.add(batch.last_time_ms / 1000)
    return tuple(sorted(times))


def infra_snapshot(
    data: Any,
    log_events: tuple[Any, ...] = (),
    log_read: bool = False,
    *,
    log_times: tuple[float, ...] = (),
    poll_interval: float | None = None,
    uplink_ports: frozenset[str] = frozenset(),
) -> InfraSnapshot:
    """Read the detector inputs from coordinator data; never raises.

    Coordinator defaults that stand for "not measured" become None:
    uptime 0 (then CPU and memory are not trusted either, they come from
    the same call), conntrack 0, empty port and pool lists, LLDP with a
    status other than ok/no_neighbors, the WAN unless ``wan_found``, and
    an empty map of our own service actions.
    """
    uptime = _positive(getattr(data, "uptime", None))
    cpu = getattr(data, "cpu_load", None)
    memory = getattr(data, "memory_pressure", None)
    clock = (getattr(data, "localtime", None), getattr(data, "localtime_at", None))
    clock_ok = _finite(clock[0]) and _finite(clock[1])
    conntrack = getattr(data, "active_connections", None)
    services = getattr(data, "service_instances", None)
    wan = getattr(data, "wan_status", None)
    if not (isinstance(wan, dict) and wan.get("wan_found") is True):
        wan = None  # no WAN on this router (or not read): unknown, not "down"
    connected = getattr(data, "wan_connected", None) if wan else None
    leases = getattr(data, "dhcp_leases", None)
    pools = _records(getattr(data, "dhcp_pools", None))
    lldp = getattr(data, "lldp_neighbors", None)
    wan_at = getattr(data, "wan_status_at", None)
    actions = getattr(data, "service_actions", None)
    batch = getattr(data, "new_log_batch", None)
    fetched = batch.fetched_at if isinstance(batch, LogBatch) else None
    lldp_ok = isinstance(lldp, list) and getattr(data, "lldp_status", None) in (
        LLDP_STATUS_OK,
        LLDP_STATUS_NO_NEIGHBORS,
    )
    return InfraSnapshot(
        uptime=uptime,
        cpu_load=float(cpu) if uptime and _finite(cpu) else None,
        memory_pressure=memory if uptime and isinstance(memory, dict) else None,
        localtime=float(clock[0]) if clock_ok else None,
        localtime_at=float(clock[1]) if clock_ok else None,
        conntrack=int(conntrack) if _positive(conntrack) else None,
        services=services if isinstance(services, dict) else None,
        service_actions=dict(actions)
        if isinstance(actions, dict) and actions
        else None,
        ports=_records(getattr(data, "port_stats", None)),
        wan=wan,
        wan_connected=connected if isinstance(connected, bool) else None,
        wan_at=float(wan_at) if wan and _finite(wan_at) else None,
        # no lease list: usage 0 % would be a guess, not a measurement
        dhcp_pools=pools if isinstance(leases, dict) and leases else None,
        lldp=tuple(n for n in lldp if isinstance(n, dict)) if lldp_ok else None,
        log_events=log_events,
        log_read=log_read,
        log_fetched_at=float(fetched) if _finite(fetched) else None,
        log_times=log_times,
        poll_interval=float(poll_interval) if _positive(poll_interval) else None,
        uplink_ports=uplink_ports,
    )


def wifi_snapshot(
    data: Any,
    context: WifiContext,
    log_events: tuple[Any, ...],
    batch: LogBatch | None,
    *,
    dhcp: tuple[frozenset[str], frozenset[str], frozenset[str]] | None = None,
    hosts: dict[str, str] | None = None,
    rebooted: bool = False,
    poll_interval: float | None = None,
    exclude: frozenset[str] = frozenset(),
) -> WifiSnapshot:
    """Build the WLAN detector input from coordinator data (P4).

    ``log_events`` are the new lines of a fresh log read (empty otherwise).
    """
    status = getattr(data, "log_status", None)
    stability = getattr(data, "client_stability", None)
    usteer_status = stability.get("usteer") if isinstance(stability, dict) else None
    usteer = getattr(data, "usteer_connected", None)
    actions = getattr(data, "wifi_actions", None)
    return WifiSnapshot(
        context=context,
        has_aps=bool(context.ifaces),
        log_events=log_events,
        log_status=status if isinstance(status, str) else None,
        log_lines=batch.new_lines if batch is not None else None,
        log_missed=batch.missed if batch is not None else 0,
        dhcp=dhcp,
        usteer=usteer if isinstance(usteer, dict) else None,
        usteer_status=usteer_status if isinstance(usteer_status, str) else None,
        hosts=hosts or {},
        rebooted=rebooted,
        poll_interval=poll_interval,
        wifi_actions=dict(actions) if isinstance(actions, dict) else None,
        exclude=exclude,
    )


def _finite(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _positive(value: Any) -> float | None:
    return float(value) if _finite(value) and value > 0 else None


def _records(value: Any) -> tuple[dict[str, Any], ...] | None:
    """A non-empty list of dicts as tuple; empty or broken = None (unknown)."""
    if not isinstance(value, list):
        return None
    records = tuple(item for item in value if isinstance(item, dict))
    return records or None


def _store_size(payload: dict[str, Any]) -> int:
    """Bytes of the store file exactly as HA's ``Store`` writes it."""
    wrapped = {
        "version": INTEL_STORE_VERSION,
        "minor_version": INTEL_STORE_MINOR_VERSION,
        "key": INTEL_STORE_KEY,
        "data": payload,
    }
    _mode, data = prepare_save_json(wrapped)
    return len(data.encode("utf-8") if isinstance(data, str) else data)


def _highest_seq(ring: EventRing) -> int:
    best = 0
    for event in ring:
        tail = event.id.rpartition(":")[2]
        if tail.isascii() and tail.isdigit():
            best = max(best, int(tail))
    return best


def _backup_file(path: Any) -> bool:
    """Copy ``path`` to ``<path>.bak`` (executor); False if there is no file."""
    if not isinstance(path, str) or not os.path.isfile(path):
        return False
    shutil.copyfile(path, f"{path}.bak")
    return True


def _load_marks(raw: Any) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    if not isinstance(raw, dict):
        return out
    for router, mark in raw.items():
        if not isinstance(router, str) or not isinstance(mark, dict):
            continue
        clean = {
            key: value
            for key in ("last_id", "last_time_ms")
            if isinstance(value := mark.get(key), int) and not isinstance(value, bool)
        }
        if clean:
            out[router] = clean
    return out
