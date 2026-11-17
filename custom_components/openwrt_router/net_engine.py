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

Score, entities and bus event (P6): after every machine step (and on a
timer for time-based changes) the engine re-reads the incidents after
``correlate``, announces new roots on the HA bus (``EVENT_INCIDENT``) once
the settle time has passed and no router is late (a parent may still be on
its way, e.g. an outage needs several failed polls), and builds a
``NetView`` (score per router and for the fleet, counts) that the entities
read when ``SIGNAL_NET_INTEL`` is sent. Children (``parent_id`` of a known
incident) never fire a bus event. Maintenance (per router from the switch,
fleet-wide via ``settings.maintenance.fleet_until``) marks events, blocks
new and reopened incidents and keeps the router out of the fleet score;
``settings.exclusions`` (incident types, routers, SSIDs, MACs) keep
evidence away from the machine.

Correlation (P5): the engine follows ``fleet.FleetOutageTracker`` (observer
hook) and turns its state into ``router_unreachable`` / ``lan_unreachable``
incidents. After every machine step (a poll of any router, an outage start
or end) it builds the router tree from LLDP and ``trunk_port_map``
(``net_rules.build_topology``, an edge remembered up to a day while loaded)
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
import re
import shutil
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import Any, Protocol

from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.json import prepare_save_json
from homeassistant.helpers.storage import Store

from .const import (
    DOMAIN,
    ERROR_TYPE_AUTH,
    EVENT_INCIDENT,
    INTEL_ANNOUNCE_HOLD_MAX_SECONDS,
    INTEL_ANNOUNCE_SETTLE_SECONDS,
    INTEL_MAX_STORE_BYTES,
    INTEL_PRUNE_INTERVAL_SECONDS,
    INTEL_SAVE_DELAY_SECONDS,
    INTEL_STORE_KEY,
    INTEL_STORE_MINOR_VERSION,
    INTEL_STORE_VERSION,
    LLDP_REFRESH_INTERVAL,
    LLDP_STATUS_NO_NEIGHBORS,
    LLDP_STATUS_OK,
    LOG_STATUS_OK,
    NOTIFICATION_FAILURE_THRESHOLD,
    SIGNAL_NET_INTEL,
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
    Incident,
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
    WIFI_AUTH_KINDS,
    WIFI_LOG_RULES,
    WIFI_RECONNECT_KIND,
    AlarmMachine,
    AreaInput,
    Evidence,
    Finding,
    InfraSnapshot,
    InfraState,
    RouterLinks,
    RouterScore,
    Topology,
    Uplink,
    WifiContext,
    WifiSnapshot,
    WifiState,
    build_topology,
    child_release_time,
    counted_incidents,
    counts_for_router,
    decline_cause,
    deep_merge,
    detect_infrastructure,
    detect_wifi,
    events_by_id,
    finding_evidence,
    fleet_score,
    incident_cause_level,
    log_event_evidence,
    merge_settings,
    normalize_mac,
    router_score,
    settings_errors,
    stores_down_line,
    suppressed_child,
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
# ``reason`` of the ``resolved`` event of an ignored incident (P7 review E15)
EVENT_REASON_IGNORED = "ignored"

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

# P6: data is fresh up to this many poll intervals (plan c6); a router is
# "late" (its outage may still be coming) after this many intervals, and
# only until its outage would have been reported (P6 review M1: the failure
# threshold plus one interval; a router stuck longer holds nothing).
_FRESH_INTERVALS = 3.0
_LATE_INTERVALS = 1.25
_LATE_UNTIL_INTERVALS = float(NOTIFICATION_FAILURE_THRESHOLD + 1)
_DEFAULT_INTERVAL = 60.0
# WAN reconnects (``wan_unstable`` evidence) for the WAN stability sensor.
_WAN_RECONNECT_KINDS = ("wan.up", "wan.reconnect")
_MAC_RE = re.compile(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}")


@dataclass(frozen=True)
class RouterView:
    """What the entities of one router show (built in ``_publish``)."""

    score: RouterScore
    maintenance: bool = False
    incidents_active: int = 0
    critical: bool = False
    reconnects_1h: int = 0
    auth_errors_1h: int = 0
    wan_reconnects_24h: int = 0


@dataclass(frozen=True)
class FleetView:
    """What the fleet entities show; ``score`` None = unknown."""

    score: int | None = None
    coverage: float = 0.0
    routers: int = 0
    maintenance: int = 0
    incidents_active: int = 0
    critical: bool = False


@dataclass(frozen=True)
class NetView:
    """Snapshot of the engine for the entities (read only)."""

    routers: Mapping[str, RouterView] = field(default_factory=dict)
    fleet: FleetView = field(default_factory=FleetView)


@dataclass(frozen=True, slots=True)
class PollFacts:
    """What one ingested poll gave, for read-only poll observers.

    Built once per new poll after the detectors and the alarm machine ran;
    observers read it and must not change the engine. ``now`` is the engine
    clock, ``interval`` the poll interval in seconds. ``fresh_clients``: a
    client list was read in this poll (``context.clients`` is not None).
    ``wifi_lines`` are the accepted Wi-Fi lines of a fresh log read (empty
    for a baseline or gap read), ``log_ok`` whether the log was readable.
    ``findings`` are this poll's Wi-Fi findings that were stored as events,
    ``stored_events`` the log events stored in it, ``auth_attempts`` the ids
    of those that start a new failed authentication attempt.
    ``loc`` maps the MACs of this router's client list to the router the
    fleet places them on; ``lease_macs``/``arp_macs`` are upper-case MACs
    with a lease or an ARP entry (fleet-wide, else this router's own).
    ``down_routers`` are the routers in outage, ``auth_failed`` those
    failing on their credentials, ``exclude`` the excluded client MACs.
    ``log_coverage`` is the router's share of log lines read (0..1, None =
    no log status yet; see ``WifiState.coverage``).
    """

    router: str
    now: float
    interval: float
    fresh_clients: bool
    context: WifiContext
    wifi_lines: tuple[LogEvent, ...] = ()
    log_ok: bool = False
    findings: tuple[Finding, ...] = ()
    stored_events: tuple[NetEvent, ...] = ()
    auth_attempts: frozenset[str] = frozenset()
    loc: Mapping[str, str] = field(default_factory=dict)
    lease_macs: frozenset[str] = frozenset()
    arp_macs: frozenset[str] = frozenset()
    down_routers: frozenset[str] = frozenset()
    auth_failed: frozenset[str] = frozenset()
    exclude: frozenset[str] = frozenset()
    log_coverage: float | None = None


class PollObserver(Protocol):
    """Reads every ingested poll (client stability); never changes the engine."""

    def on_poll(self, facts: PollFacts) -> None:
        """One new poll of one router."""

    def on_clock_shift(self, delta: float) -> None:
        """The engine clock jumped back; stored times move by ``delta``."""

    def on_router_removed(self, router: str) -> None:
        """All data of a removed router is being deleted."""


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
        # In memory (RT9): per router the log status of its last poll and
        # the engine time of its last log read (None: none yet).
        self._log_reads: dict[str, tuple[str | None, float | None]] = {}
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
        # Read-only observers of every ingested poll (client stability).
        self._poll_observers: list[PollObserver] = []
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
        # P6: routers in maintenance (stored; the switch restores it too),
        # the announced incidents (id -> reopen_count, stored: no second
        # "opened" after a restart), when an unannounced incident was first
        # seen open (in memory: a restart waits the settle time again), the
        # time and poll interval of each router's last new data, the view
        # for the entities, the wake-up timer and the fleet entity anchor.
        self._maintenance: set[str] = set()
        self._announced: dict[str, int] = {}
        # incidents that fired "opened" (stored; P6 review L5: a reopen of
        # an incident that never fired "opened" fires "opened")
        self._opened: set[str] = set()
        self._open_seen: dict[tuple[str, int], float] = {}
        self._seen: dict[str, tuple[float, float]] = {}
        self.view = NetView()
        self._unsub_timer: Callable[[], None] | None = None
        self._timer_due: float | None = None
        self._fleet_anchor: str | None = None
        self._fleet_claims: dict[str, dict[str, Callable[[], None]]] = {}
        # entry the fleet entities are moving away from (P6 review M2): its
        # successor creates them once that entry's platforms are unloaded
        self._fleet_leaving: str | None = None

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
        self._maintenance = set()
        self._announced = {}
        self._opened = set()

    @callback
    def register(self, entry_id: str) -> None:
        """A router's entry is loaded and starts feeding the engine."""
        self._routers.add(entry_id)
        # A reload starts from a clean comparison state (no false alarms).
        self._last_data.pop(entry_id, None)
        self._infra.pop(entry_id, None)
        self._wifi.forget(entry_id)
        self._seen.pop(entry_id, None)

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
        self._log_reads.clear()
        self._infra.clear()
        self._identity.clear()
        self._wifi = WifiState()
        self._hosts.clear()
        self._down.clear()
        self._lan_down = False
        self._lan_routers = []
        self._uplinks.clear()
        self._topology = Topology()
        self._seen.clear()
        self._open_seen.clear()
        self._cancel_timer()
        self._fleet_anchor = None
        self._fleet_claims.clear()
        self._fleet_leaving = None
        self.view = NetView()

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
        """A router's entry is unloaded; its stored data stays. Its open
        outage is resolved (``router_removed``): its state is unknown from
        now on (P5 review E7). That resolve is silent: no HA event, no
        logbook entry (P6 review E9)."""
        resolved_at: float | None = None
        if not self._closed and self._loaded:
            try:
                # at the last step: the machine clock is not moved here
                now = self.machine.last_now
                done = (
                    self.machine.resolve_router(entry_id, now)
                    if now is not None
                    else []
                )
                if done:
                    resolved_at = now
                # silent (E9): no "resolved" on the bus, none in the logbook
                silent = {tr.incident.id for tr in done}
                for inc_id in silent:
                    self._announced.pop(inc_id, None)
                self._open_seen = {
                    key: seen
                    for key, seen in self._open_seen.items()
                    if key[0] not in silent
                }
            except Exception:
                _LOGGER.warning(
                    "Network intelligence could not resolve the outage of an "
                    "unloaded router",
                    exc_info=True,
                )
        self._routers.discard(entry_id)
        self._last_data.pop(entry_id, None)
        self._log_reads.pop(entry_id, None)
        self._infra.pop(entry_id, None)
        self._identity.pop(entry_id, None)
        self._wifi.forget(entry_id)
        self._hosts.pop(entry_id, None)
        self._down.discard(entry_id)
        self._uplinks.pop(entry_id, None)
        self._seen.pop(entry_id, None)
        for claims in self._fleet_claims.values():
            claims.pop(entry_id, None)
        if self._fleet_anchor == entry_id:
            # not withdrawn first (a caller other than async_unload_entry)
            self._fleet_anchor = self._next_anchor(entry_id)
            self._create_fleet()
        elif self._fleet_leaving == entry_id:
            # withdrawn at the start of the unload: its entities are gone now
            self._fleet_leaving = None
            self._create_fleet()
        if resolved_at is not None:
            self._refresh(resolved_at)
            self.schedule_save()

    def remove_router(self, entry_id: str) -> bool:
        """Forget all data of a router; True if anything was removed."""
        self.unregister(entry_id)
        self._notify("on_router_removed", entry_id)
        removed = self.ring.remove_router(entry_id) > 0
        removed |= entry_id in self.counters.to_dict()
        self.counters.remove_router(entry_id)
        removed |= self._log_marks.pop(entry_id, None) is not None
        removed |= entry_id in self._wan_gateways
        self._wan_gateways.discard(entry_id)
        removed |= self.machine.remove_router(entry_id) > 0
        removed |= entry_id in self._maintenance
        self._maintenance.discard(entry_id)
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
        self._seen[entry_id] = (
            now,
            float(interval) if _positive(interval) else _DEFAULT_INTERVAL,
        )
        log_events = getattr(data, "new_log_events", ())
        if not isinstance(log_events, (tuple, list)):
            log_events = ()
        batch = getattr(data, "new_log_batch", None)
        if not isinstance(batch, LogBatch):
            batch = None
        mark_before = self._log_marks.get(entry_id)
        resumed = self._note_log_read(entry_id, data, batch, now)
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
            resumed=resumed,
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
            # edges from fresh data only: a remembered port must not stay an
            # uplink for ever (P5 review M3)
            uplink_ports=self._topology.ports_of(entry_id, remembered=False),
        )
        findings = self._infra_findings(entry_id, snapshot, now)
        stored += self._store_findings(entry_id, findings, now, evidence)
        dhcp = self._dhcp_context()
        wifi = wifi_snapshot(
            data,
            context,
            tuple(accepted) if fresh else (),
            batch,
            dhcp=dhcp,
            hosts={host: router for router, host in self._hosts.items()},
            rebooted=any(f.kind == _REBOOT_KIND for f in findings),
            poll_interval=interval,
            exclude=exclude,
        )
        wifi_findings = detect_wifi(self._wifi, wifi, now, entry_id, thresholds)
        stored += self._store_findings(entry_id, wifi_findings, now, evidence)
        evidence.extend(self._wifi_holds(entry_id, now, context))
        stored += self._run_machine(now, evidence)
        self._prune(now)
        if stored or self._log_marks.get(entry_id) != mark_before:
            self.schedule_save()
        if self._poll_observers:
            self._notify(
                "on_poll",
                self._poll_facts(
                    entry_id,
                    data,
                    now,
                    interval,
                    context,
                    lines=accepted if fresh else (),
                    findings=wifi_findings,
                    stored_events=log_stored,
                    dhcp=dhcp,
                    exclude=exclude,
                ),
            )
        return stored

    # -- poll observers (client stability) ------------------------------------------

    def add_poll_observer(self, observer: PollObserver) -> Callable[[], None]:
        """Call ``observer`` for every new poll; returns the unsubscribe."""
        self._poll_observers.append(observer)

        def unsubscribe() -> None:
            if observer in self._poll_observers:
                self._poll_observers.remove(observer)

        return unsubscribe

    def _notify(self, method: str, *args: Any) -> None:
        """Call one observer method on every observer; errors stay there."""
        for observer in tuple(self._poll_observers):
            try:
                getattr(observer, method)(*args)
            except Exception:
                _LOGGER.warning(
                    "A network intelligence poll observer failed in %s",
                    method,
                    exc_info=True,
                )

    def _poll_facts(
        self,
        entry_id: str,
        data: Any,
        now: float,
        interval: float | None,
        context: WifiContext,
        *,
        lines: Iterable[LogEvent],
        findings: Iterable[Finding],
        stored_events: Iterable[NetEvent],
        dhcp: tuple[frozenset[str], frozenset[str], frozenset[str]] | None,
        exclude: frozenset[str],
    ) -> PollFacts:
        """The immutable facts of this poll for the observers (no I/O)."""
        stored = tuple(stored_events)
        if dhcp is not None:
            leases, arp = dhcp[0], dhcp[1]
        else:
            leases = _upper_keys(getattr(data, "dhcp_leases", None))
            arp = _upper_keys(getattr(data, "arp_table", None))
        locs = self._wifi.loc
        return PollFacts(
            router=entry_id,
            now=now,
            interval=float(interval) if _positive(interval) else _DEFAULT_INTERVAL,
            fresh_clients=context.clients is not None,
            context=context,
            wifi_lines=tuple(e for e in lines if e.category == CATEGORY_WIFI),
            log_ok=getattr(data, "log_status", None) == LOG_STATUS_OK,
            findings=tuple(f for f in findings if f.event),
            stored_events=stored,
            auth_attempts=frozenset(
                e.id for e in stored if e.id in self._wifi_attempts
            ),
            loc={
                mac: loc.router
                for mac in context.clients or {}
                if (loc := locs.get(mac)) is not None
            },
            lease_macs=leases,
            arp_macs=arp,
            down_routers=frozenset(self._down),
            auth_failed=self._auth_failed(),
            exclude=exclude,
            log_coverage=_log_coverage(self._wifi.coverage(entry_id)),
        )

    def _sync(self, now: float, mono: float | None) -> float:
        """Advance the machine clock; move or reset the detector state on a
        clock jump; return the time to use for this step."""
        step = self.machine.sync_clock(now, mono)
        if step.shift:
            self.ring.shift(step.shift)
            for state in self._infra.values():
                state.shift(step.shift)
            self._wifi.shift(step.shift)
            self._seen = {r: (t + step.shift, i) for r, (t, i) in self._seen.items()}
            self._open_seen = {k: t + step.shift for k, t in self._open_seen.items()}
            self._notify("on_clock_shift", step.shift)
        if self.machine.prune_held:
            for state in self._infra.values():
                state.clock_jumped()
        return step.now

    def _run_machine(self, now: float, evidence: list[Evidence]) -> int:
        """Outage evidence, machine step, topology, correlation; return the
        number of stored (outage) events."""
        stored, outage = self._outage_evidence(now)
        self.machine.update(now, self._filter_evidence([*evidence, *outage], now))
        if self._lan_down:
            self.machine.set_routers(
                "lan_unreachable", LAN_UNREACHABLE_KEY, self._lan_routers
            )
        self._topology = self._build_topology(now)
        result = self.machine.correlate(now, self._topology, self.ring)
        self.ring.set_parents(result.events)
        if result:
            self.schedule_save()  # new links and releases are state (L2)
        # Re-read after correlate: a root announced now may otherwise turn
        # out to be a child a moment later (P5 hand-over to P6).
        self._refresh(now)
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
        event = self._mark(event)
        self.ring.add(event)
        if router != FLEET_ROUTER:
            self.counters.add(router, kind, now)
        return event

    def _build_topology(self, now: float) -> Topology:
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
        topology = build_topology(links, self._uplinks, now)
        self._uplinks = dict(topology.uplinks)
        return topology

    def _note_log_read(
        self, entry_id: str, data: Any, batch: LogBatch | None, now: float
    ) -> bool:
        """Remember the log status and read time; True if this poll read the
        log again after polls whose read failed."""
        status = getattr(data, "log_status", None)
        old, read_at = self._log_reads.get(entry_id, (None, None))
        self._log_reads[entry_id] = (
            status if isinstance(status, str) else None,
            now if batch is not None else read_at,
        )
        return batch is not None and old not in (None, LOG_STATUS_OK)

    def log_state(self, entry_id: str, now: float) -> dict[str, Any]:
        """Log status of a router's last poll, time and age of its last log
        read (RT9: under path D the log is the realtime source, read on
        every poll, so its age is the delay of the events)."""
        status, read_at = self._log_reads.get(entry_id, (None, None))
        return {
            "status": status,
            "read_at": read_at,
            "age_s": None if read_at is None else max(0, round(now - read_at)),
        }

    def _ingest_log(
        self,
        entry_id: str,
        events: Iterable[Any],
        batch: LogBatch | None,
        now: float,
        arp: Any = None,
        wifi: WifiContext | None = None,
        interval: float | None = None,
        *,
        resumed: bool = False,
    ) -> tuple[int, list[NetEvent], list[LogEvent]]:
        """Count and store the log events of one poll.

        Returns the number of stored events (a log gap included), the
        stored log events, and the log events taken in (for the detectors).
        ``arp`` (MAC -> IPv4 of this poll) confirms a DHCPDECLINE, ``wifi``
        (this poll's AP interfaces and clients) adds SSID, band and signal
        to fresh Wi-Fi lines (not to the lines of a log gap); ``interval``
        is the poll interval. ``resumed``: the log is read again after
        failed reads; lines lost in between (``missed``) are a log gap.
        """
        stored = 0
        baseline = batch is not None and batch.baseline
        if batch is not None and baseline:
            events, stored = self._gap_events(entry_id, events, batch, now)
        elif batch is not None and resumed and batch.missed > 0:
            # RT10 scenario 12: reads failed for a while and lines left the
            # router's buffer meanwhile (a busy log between two good reads
            # only lowers the coverage, as before)
            last_ms = self._log_marks.get(entry_id, {}).get("last_time_ms")
            gap_s = (
                (batch.first_time_ms - last_ms) / 1000
                if last_ms is not None and batch.first_time_ms is not None
                else None
            )
            self._record_gap(entry_id, gap_s, now, missed=batch.missed)
            stored = 1
        accepted: list[LogEvent] = []
        kept: list[NetEvent] = []
        groups: dict[tuple[str, str | None], list[tuple[LogEvent, float]]] = {}
        downs: set[tuple[Any, ...]] = set()
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
                # RT5-D: a disconnect with a problem reason is stored, once
                # per batch (the same line twice is one event)
                down = (event.key, event.mac, event.interface, event.time_ms)
                if not stores_down_line(event) or down in downs:
                    continue
                downs.add(down)
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
        kept = [self._mark(net_event) for net_event in kept]
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
                event = self._mark(self._finding_event(entry_id, finding, now))
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
        """``exclusions.macs`` of the settings (colons, upper case; a MAC
        with dashes works too, P7 review), plus the clients
        the loaded routers list on an SSID in ``exclusions.ssids`` (P6; a
        client is known by SSID only while a router lists it)."""
        exclusions = self.settings.get("exclusions", {})
        macs = {
            normalize_mac(m) for m in exclusions.get("macs") or () if isinstance(m, str)
        }
        ssids = {s for s in exclusions.get("ssids") or () if isinstance(s, str) and s}
        if ssids:
            for router in self._routers:
                data = self._last_data.get(router)
                context = wifi_context(
                    getattr(data, "ap_interfaces", None), getattr(data, "clients", None)
                )
                for mac, client in (context.clients or {}).items():
                    radio = client.get("radio")
                    _band, ssid, _phy = context.iface(
                        radio if isinstance(radio, str) else None
                    )
                    if ssid in ssids:
                        macs.add(mac)
        return frozenset(macs)

    # -- maintenance and exclusions (P6) ------------------------------------------

    def router_maintenance(self, router: str) -> bool:
        """The router's own maintenance switch (without the fleet window)."""
        return router in self._maintenance

    def in_maintenance(self, router: str) -> bool:
        """True while ``router`` (or the whole fleet) is in maintenance."""
        return router in self._maintenance or self._fleet_maintenance()

    def _fleet_maintenance(self, now: float | None = None) -> bool:
        """``settings.maintenance.fleet_until`` (epoch s) not yet reached."""
        until = self.settings.get("maintenance", {}).get("fleet_until")
        if now is None:
            now = self.machine.last_now
        return _finite(until) and now is not None and now < until

    @callback
    def set_maintenance(self, entry_id: str, on: bool) -> None:
        """Switch a router's maintenance mode (the maintenance switch).

        On: its events are stored marked, its evidence opens or reopens no
        incident (an open one still resolves), and it leaves the fleet
        score. Off: normal operation; the series broken during maintenance
        start from zero, so nothing fires late.
        """
        if (entry_id in self._maintenance) == on or self._closed:
            return
        if on:
            self._maintenance.add(entry_id)
        else:
            self._maintenance.discard(entry_id)
        self.schedule_save()
        now = self.machine.last_now
        if now is not None and self._loaded:
            self._refresh(now)

    # -- panel actions (P7) --------------------------------------------------------

    @callback
    def apply_settings(self, patch: Any) -> list[str]:
        """Merge a settings change from the panel; return the errors (none = done).

        ``patch`` is checked strictly (``settings_errors``) and laid over the
        current settings. The automaton, the ring limits and the counter
        retention take the new values at once; thresholds and exclusions act
        on the next evidence (open incidents of a newly excluded type end by
        ``auto_resolve``). Saved with the next delayed write.
        """
        errors = settings_errors(patch)
        if errors:
            return errors
        self.settings = merge_settings(deep_merge(self.settings, patch))
        self.machine.set_settings(self.settings)
        self.ring.resize(
            self.settings["max_events"], self.settings["retention_days"] * _DAY
        )
        self.counters.retention_days = self.settings["retention_days"]
        self.schedule_save()
        now = self.machine.last_now
        if now is not None and self._loaded:
            self._refresh(now)
        return []

    @callback
    def set_incident_status(
        self, incident_id: str, status: str, *, ignore_days: float | None = None
    ) -> bool | None:
        """Acknowledge, ignore or re-activate an incident (panel, admin only).

        None: unknown incident. False: not possible in its current status
        (or an unknown ``status``). ``ignore_days`` None ignores for the
        settings duration. Uses the engine clock, so the ignore period fits
        the incident times.
        """
        if self.machine.get(incident_id) is None:
            return None
        now = self.machine.last_now
        if now is None:
            now = time.time()
        if status == IncidentStatus.ACKNOWLEDGED:
            done = self.machine.acknowledge(incident_id)
        elif status == IncidentStatus.IGNORED:
            until = now + ignore_days * _DAY if ignore_days is not None else None
            done = self.machine.ignore(incident_id, now, until)
        elif status == IncidentStatus.ACTIVE:
            done = self.machine.reactivate(incident_id, now)
        else:
            return False
        if done:
            self.schedule_save()
            if self.machine.last_now is not None and self._loaded:
                self._refresh(self.machine.last_now)
        return done

    def _mark(self, event: NetEvent) -> NetEvent:
        """An event recorded during maintenance: marked; a reboot is info."""
        if not self.in_maintenance(event.router):
            return event
        severity = Severity.INFO if event.kind == _REBOOT_KIND else event.severity
        return replace(event, maintenance=True, severity=severity)

    def _filter_evidence(self, evidence: list[Evidence], now: float) -> list[Evidence]:
        """Apply ``exclusions`` (incident types, routers) and maintenance.

        Evidence of a router in maintenance is marked unless its incident
        is open: an open incident keeps counting and resolves normally, a
        new or resolved one never (re)opens. Fleet evidence (no router) is
        marked only during a fleet-wide maintenance.
        """
        exclusions = self.settings.get("exclusions", {})
        types = set(exclusions.get("incident_types") or ())
        routers = set(exclusions.get("routers") or ())
        fleet = self._fleet_maintenance(now)
        if not (types or routers or fleet or self._maintenance) and not any(
            item.maintenance for item in evidence
        ):
            return evidence
        open_keys = {
            (type_, key)
            for type_, _scope, key in self.machine.open_keys(
                self.settings["thresholds"]
            )
        }
        out: list[Evidence] = []
        for item in evidence:
            if item.type in types or (
                item.router is not None and item.router in routers
            ):
                continue
            paused = fleet or (
                item.router is not None and item.router in self._maintenance
            )
            want = paused and (item.type, item.scope_key) not in open_keys
            if item.maintenance != want:
                item = replace(item, maintenance=want)
            out.append(item)
        return out

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

    def _record_gap(
        self, entry_id: str, gap_s: float | None, now: float, missed: int = 0
    ) -> None:
        params: dict[str, Any] = {}
        if gap_s is not None:
            params["gap_s"] = round(gap_s)
        if missed > 0:
            params["missed"] = missed
        self._seq += 1
        self.counters.add(entry_id, LOG_GAP_KIND, now)
        self.ring.add(
            self._mark(
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
                    params=params,
                )
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
        view = self.view.routers.get(entry_id)
        mine = [
            inc
            for inc in self.machine.incidents()
            if inc.status in _OPEN_STATES
            and (entry_id in inc.routers or inc.scope_key == entry_id)
        ]
        active = Counter(inc.type for inc in mine)
        stored = events_by_id(self.ring)
        levels = Counter(incident_cause_level(inc, stored).value for inc in mine)
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
            "active_by_cause_level": dict(sorted(levels.items())),
            "incidents_stored_fleet": len(self.machine.incidents()),
            "log_mark_stored": entry_id in self._log_marks,
            "store_bytes_last_save": self.last_save_bytes,
            "events_trimmed_for_size": self.trimmed_events,
            "score": view.score.score if view else None,
            "coverage": view.score.coverage if view else None,
            "score_areas": view.score.areas if view else None,
            "maintenance": entry_id in self._maintenance,
            "incidents_announced_fleet": len(self._announced),
            "wifi_coverage": self._wifi.coverage(entry_id),
        }

    # -- score, entities and bus events (P6) --------------------------------------

    @callback
    def _refresh(self, now: float) -> None:
        """Announce, rebuild the view, re-arm the timer; never raises."""
        if self._closed:
            return
        try:
            if self._announce(now):
                self.schedule_save()
            self._publish(now)
            self._schedule_wakeup(now)
        except Exception:
            _LOGGER.warning(
                "Network intelligence could not update its entities", exc_info=True
            )

    def _interval(self, router: str) -> float:
        seen = self._seen.get(router)
        return seen[1] if seen else _DEFAULT_INTERVAL

    def _fresh(self, router: str, now: float) -> bool:
        seen = self._seen.get(router)
        return seen is not None and now - seen[0] <= _FRESH_INTERVALS * seen[1]

    def _late(self, now: float) -> bool:
        """A loaded router missed its poll but is not (yet) reported down:
        an outage that would become the parent of new roots may be coming.

        Only from 1.25 up to the failure threshold + 1 poll intervals: by
        then its outage is reported or it is not coming (P6 review M1). A
        router failing on its credentials is no outage and never late.
        """
        auth = self._auth_failed()
        return any(
            _LATE_INTERVALS * interval < now - seen <= _LATE_UNTIL_INTERVALS * interval
            for router, (seen, interval) in self._seen.items()
            if router in self._routers
            and router not in self._down
            and router not in auth
        )

    def _auth_failed(self) -> frozenset[str]:
        """Routers the outage tracker lists with an authentication error."""
        if self._outages is None:
            return frozenset()
        try:
            down = self._outages.snapshot().down
        except Exception:
            _LOGGER.debug("Outage tracker snapshot failed", exc_info=True)
            return frozenset()
        return frozenset(
            router
            for router, outage in down.items()
            if getattr(outage, "error_type", None) == ERROR_TYPE_AUTH
        )

    def _settle(self) -> float:
        longest = max(
            (self._interval(r) for r in self._routers), default=_DEFAULT_INTERVAL
        )
        return max(float(INTEL_ANNOUNCE_SETTLE_SECONDS), longest + 30.0)

    def _announce(self, now: float) -> bool:
        """Fire ``EVENT_INCIDENT`` for roots (plan c9, AK11); True if any fired.

        ``opened`` / ``reopened``: an active incident (not acknowledged, not
        ignored) at or above ``notify_min_severity`` that is no silent child
        (``suppressed_child``: a child counts again after its root's
        after-window with evidence of its own, P6 review E8, P7 review E12),
        not only on routers in maintenance, once per open period; only after
        the settle time since the engine first saw it open and while no
        router is late, at the latest after the hold maximum. ``resolved``:
        only for an announced incident; an announced incident that is
        ignored fires ``resolved`` with ``reason: ignored`` (P7 review E15),
        so an automation waiting for the end does not hang. An incident that
        resolves before it was announced stays silent; so does a silent
        child. ``reopened`` only for an incident that fired ``opened``
        before (L5); a re-activated incident that never fired ``opened``
        fires ``opened``.
        """
        incidents = {inc.id: inc for inc in self.machine.peek()}
        fired = False
        gone = self._opened - incidents.keys()
        if gone:
            self._opened -= gone
            fired = True  # stored state changed
        for inc_id, count in list(self._announced.items()):
            inc = incidents.get(inc_id)
            if inc is None:
                del self._announced[inc_id]
                fired = True  # stored state changed
            elif inc.status is IncidentStatus.IGNORED:
                del self._announced[inc_id]
                self._fire(inc, "resolved", reason=EVENT_REASON_IGNORED)
                fired = True
            elif inc.status is IncidentStatus.RESOLVED:
                del self._announced[inc_id]
                self._fire(inc, "resolved")
                fired = True
        min_rank = _severity_rank(self.settings.get("notify_min_severity"))
        settle = self._settle()
        late = self._late(now)
        pending: dict[tuple[str, int], float] = {}
        for inc in incidents.values():
            if inc.status is not IncidentStatus.ACTIVE:
                continue
            if self._announced.get(inc.id) == inc.reopen_count:
                continue
            if (
                inc.severity.rank < min_rank
                or suppressed_child(inc, incidents, now)
                or (inc.routers and all(self.in_maintenance(r) for r in inc.routers))
            ):
                continue  # the settle time starts when it becomes a candidate
            key = (inc.id, inc.reopen_count)
            seen = self._open_seen.get(key, now)
            pending[key] = seen
            waited = now - seen
            if waited < INTEL_ANNOUNCE_HOLD_MAX_SECONDS and (waited < settle or late):
                continue
            # "opened" once; "reopened" only after an "opened" (L5)
            reopened = inc.id in self._opened
            self._announced[inc.id] = inc.reopen_count
            self._opened.add(inc.id)
            self._fire(inc, "reopened" if reopened else "opened")
            fired = True
            del pending[key]
        self._open_seen = pending
        return fired

    def _fire(self, inc: Incident, state: str, *, reason: str | None = None) -> None:
        self.hass.bus.async_fire(
            EVENT_INCIDENT, self._event_data(inc, state, reason=reason)
        )

    def _event_data(
        self, inc: Incident, state: str, *, reason: str | None = None
    ) -> dict[str, Any]:
        """Bus payload (plan c9): router names, entry ids, the device of a
        single router; the MAC only for a client incident. ``reason``:
        ``ignored`` on the ``resolved`` of an ignored incident (E15), else
        None."""
        entry_ids = [r for r in inc.routers if r != FLEET_ROUTER]
        names: list[str] = []
        for entry_id in entry_ids:
            entry = self.hass.config_entries.async_get_entry(entry_id)
            title = getattr(entry, "title", None)
            names.append(title if isinstance(title, str) and title else entry_id)
        device_id: str | None = None
        if len(entry_ids) == 1:
            try:
                device = dr.async_get(self.hass).async_get_device(
                    identifiers={(DOMAIN, entry_ids[0])}
                )
                device_id = device.id if device is not None else None
            except Exception:  # no registry (tests) or a broken one
                _LOGGER.debug(
                    "No device registry for the incident event", exc_info=True
                )
                device_id = None
        data: dict[str, Any] = {
            "state": state,
            "incident_id": inc.id,
            "type": inc.type,
            "severity": inc.severity.value,
            "confidence": round(inc.confidence, 2),
            "cause": inc.cause,
            "cause_status": inc.cause_status.value if inc.cause_status else None,
            # RT6, additive: how sure the cause is (derived, never stored)
            "cause_level": incident_cause_level(inc, self._evidence_events(inc)).value,
            "scope": inc.scope.value,
            "routers": names,
            "entry_ids": entry_ids,
            "device_id": device_id if isinstance(device_id, str) else None,
            "reason": reason,
        }
        key = inc.scope_key.upper()
        if inc.scope is Scope.CLIENT and _MAC_RE.fullmatch(key):
            data["mac"] = key
        return data

    def _evidence_events(self, inc: Incident) -> dict[str, NetEvent]:
        """The stored events behind ``inc``'s evidence (for its cause level)."""
        wanted = {e.get("id") for e in inc.evidence if isinstance(e, dict)}
        return events_by_id(e for e in self.ring if e.id in wanted)

    def _publish(self, now: float) -> None:
        """Build the view for the entities and tell them (dispatcher)."""
        incidents = self.machine.peek()
        counted = counted_incidents(incidents, now)
        excluded = set(self.settings.get("exclusions", {}).get("routers") or ())
        since_1h = now - 3600
        reconnects: Counter[str] = Counter()
        auth: Counter[str] = Counter()
        for event in self.ring:  # not sorted by ts: gap lines keep router time
            if event.ts < since_1h or event.ts > now:
                continue
            if event.kind == WIFI_RECONNECT_KIND:
                reconnects[event.router] += event.count
            elif event.kind in WIFI_AUTH_KINDS:
                auth[event.router] += event.count
        routers: dict[str, RouterView] = {}
        scores: dict[str, RouterScore] = {}
        maintenance = 0
        for router in sorted(self._routers):
            score = router_score(
                router,
                area_inputs(
                    self._last_data.get(router),
                    fresh=self._fresh(router, now),
                    gateway=router in self._wan_gateways,
                ),
                counted,
                self.settings,
                offline=router in self._down,
                now=now,
            )
            mine = [inc for inc in counted if counts_for_router(inc, router)]
            paused = self.in_maintenance(router)
            if paused:
                maintenance += 1
            elif router not in excluded:
                scores[router] = score
            routers[router] = RouterView(
                score=score,
                maintenance=paused,
                incidents_active=len(mine),
                critical=any(i.severity is Severity.CRITICAL for i in mine),
                reconnects_1h=reconnects.get(router, 0),
                auth_errors_1h=auth.get(router, 0),
                wan_reconnects_24h=sum(
                    self.counters.hourly(router, kind, now, 24)
                    for kind in _WAN_RECONNECT_KINDS
                ),
            )
        # fleet incidents lower the fleet score only (P7 review E14), not
        # when all their routers are in maintenance or excluded
        fleet_incidents = [
            inc
            for inc in counted
            if inc.scope is Scope.FLEET and self._fleet_counts(inc)
        ]
        value, coverage = fleet_score(scores, self.settings, fleet_incidents, now)
        self.view = NetView(
            routers=routers,
            fleet=FleetView(
                score=value,
                coverage=coverage,
                routers=len(scores),
                maintenance=maintenance,
                incidents_active=len(counted),
                critical=any(i.severity is Severity.CRITICAL for i in counted),
            ),
        )
        async_dispatcher_send(self.hass, SIGNAL_NET_INTEL)

    def _fleet_counts(self, inc: Incident) -> bool:
        """Does a fleet incident lower the fleet score? Not when every
        router it lists is in maintenance or excluded (E14)."""
        excluded = set(self.settings.get("exclusions", {}).get("routers") or ())
        real = [r for r in inc.routers if r != FLEET_ROUTER]
        return not real or not all(
            r in excluded or self.in_maintenance(r) for r in real
        )

    def _schedule_wakeup(self, now: float) -> None:
        """Wake up for the next time-based change: an announcement coming
        due, a router getting late or its data getting stale."""
        due: list[float] = []
        if self._open_seen:
            settle = self._settle()
            first = min(self._open_seen.values())
            due.append(first + settle)
            due.append(first + INTEL_ANNOUNCE_HOLD_MAX_SECONDS)
        for router, (seen, interval) in self._seen.items():
            if router in self._routers:
                due.append(seen + _LATE_INTERVALS * interval)
                due.append(seen + _LATE_UNTIL_INTERVALS * interval)
                due.append(seen + _FRESH_INTERVALS * interval)
        # a child counting again after its root's after-window (E8)
        incidents = {inc.id: inc for inc in self.machine.peek()}
        for inc in incidents.values():
            if inc.status is IncidentStatus.ACTIVE:
                at = child_release_time(inc, incidents)
                if at is not None:
                    due.append(at)
        upcoming = [t for t in due if t > now]
        if not upcoming:
            self._cancel_timer()
            return
        target = min(upcoming)
        if self._unsub_timer is not None and self._timer_due == target:
            return  # already armed for the same time (P6 review L6)
        self._cancel_timer()
        delay = max(1.0, target - now + 1.0)
        self._timer_due = target
        self._unsub_timer = async_call_later(self.hass, delay, self._async_wakeup)

    @callback
    def _async_wakeup(self, _now: Any) -> None:
        self._unsub_timer = None
        self._timer_due = None
        if self._closed or not self._loaded:
            return
        try:
            self._refresh(self._sync(time.time(), time.monotonic()))
        except Exception:
            _LOGGER.warning("Network intelligence wake-up failed", exc_info=True)

    def _cancel_timer(self) -> None:
        self._timer_due = None
        if self._unsub_timer is not None:
            self._unsub_timer()
            self._unsub_timer = None

    @callback
    def claim_fleet(
        self, platform: str, entry_id: str, create: Callable[[], None]
    ) -> None:
        """A router's ``platform`` offers to host the fleet entities.

        The first router to claim is the anchor (plan F1) and ``create``
        runs at once; the others are kept. When the anchor unloads, the
        smallest remaining entry id takes over: ``withdraw_fleet`` at the
        start of the unload picks it (the caller moves the registry entries
        to it), its ``create`` runs once the old entities are gone
        (``unregister``; P6 review M2).
        """
        if self._closed:
            return
        self._fleet_claims.setdefault(platform, {})[entry_id] = create
        if self._fleet_anchor is None or self._fleet_anchor not in self._routers:
            self._fleet_anchor = entry_id
        if self._fleet_anchor == entry_id:
            create()

    @property
    def fleet_anchor(self) -> str | None:
        """Entry id hosting the fleet entities, None before any claim."""
        return self._fleet_anchor

    @callback
    def withdraw_fleet(self, entry_id: str) -> str | None:
        """``entry_id`` starts to unload: drop its claims (its add-entities
        callbacks die with its platforms) and, if it hosts the fleet
        entities, pick the successor now (smallest remaining entry id).

        Returns the successor when the fleet entities move, else None. The
        caller re-homes their registry entries to it at once; the entities
        themselves are created in ``unregister``, after the old ones are
        gone (HA refuses a second entity with a live entity id).
        """
        for claims in self._fleet_claims.values():
            claims.pop(entry_id, None)
        if self._closed or self._fleet_anchor != entry_id:
            return None
        self._fleet_anchor = self._next_anchor(entry_id)
        self._fleet_leaving = entry_id if self._fleet_anchor else None
        return self._fleet_anchor

    def _next_anchor(self, leaving: str) -> str | None:
        candidates = sorted(
            {
                entry
                for claims in self._fleet_claims.values()
                for entry in claims
                if entry in self._routers and entry != leaving
            }
        )
        return candidates[0] if candidates else None

    def _create_fleet(self) -> None:
        """Run the anchor's ``create`` callbacks (one per platform)."""
        if self._fleet_anchor is None:
            return
        for claims in self._fleet_claims.values():
            create = claims.get(self._fleet_anchor)
            if create is None:
                continue
            try:
                create()
            except Exception:
                _LOGGER.warning(
                    "Network intelligence could not move the fleet entities",
                    exc_info=True,
                )

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
        paused = stored.get("maintenance_routers")
        self._maintenance = (
            {r for r in paused if isinstance(r, str) and r}
            if isinstance(paused, list)
            else set()
        )
        announced = stored.get("announced")
        self._announced = (
            {
                inc_id: count
                for inc_id, count in announced.items()
                if isinstance(inc_id, str)
                and isinstance(count, int)
                and not isinstance(count, bool)
            }
            if isinstance(announced, dict)
            else {}
        )
        opened = stored.get("opened")
        self._opened = (
            {i for i in opened if isinstance(i, str) and i}
            if isinstance(opened, list)
            else set(self._announced)  # stored before L5: announced = opened
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
            "maintenance_routers": sorted(self._maintenance),
            "announced": dict(self._announced),
            "opened": sorted(self._opened),
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


def area_inputs(data: Any, *, fresh: bool, gateway: bool) -> dict[str, AreaInput]:
    """Score indicators of one router's last data (plan c6); never raises.

    An area is applicable when the router has it: Wi-Fi with AP
    interfaces, LAN with ports, WAN only on the IPv4 gateway, DHCP/DNS with
    pools; the system always. An indicator counts when its value was read
    (not a "not measured" default: an empty client list or memory dict is
    none, P6 review L1); all count 0 when the data is not fresh (older than
    3 poll intervals) or missing, the WLAN area also without a readable
    log (E11).
    """
    if data is None:
        return {"system": AreaInput(fresh=0, total=5)}

    def has_list(name: str) -> bool:
        value = getattr(data, name, None)
        return isinstance(value, list) and bool(value)

    uptime = _positive(getattr(data, "uptime", None))
    clock = getattr(data, "localtime", None)
    services = getattr(data, "service_instances", None)
    wan = getattr(data, "wan_status", None)
    wan = wan if isinstance(wan, dict) and wan.get("wan_found") is True else None
    leases = getattr(data, "dhcp_leases", None)
    log_ok = getattr(data, "log_status", None) == "ok"
    indicators: dict[str, tuple[bool, list[bool]]] = {
        # an empty client list is the coordinator default, not a reading
        "wifi": (has_list("ap_interfaces"), [has_list("clients"), log_ok]),
        "system": (
            True,
            [
                True,  # reachable: this data came from the router
                uptime is not None and _finite(getattr(data, "cpu_load", None)),
                uptime is not None
                and isinstance(getattr(data, "memory_pressure", None), dict)
                and bool(getattr(data, "memory_pressure", None)),
                isinstance(services, dict) and bool(services),
                _finite(clock),
            ],
        ),
        "lan": (has_list("port_stats"), [True]),
        "wan": (
            gateway,
            [
                wan is not None,
                wan is not None and _positive(wan.get("uptime")) is not None,
            ],
        ),
        "dhcp_dns": (
            has_list("dhcp_pools"),
            [True, isinstance(leases, dict) and bool(leases), log_ok],
        ),
    }
    # The WLAN area counts only with a readable log: without it no WLAN
    # detector sees anything (P6 review E11).
    return {
        area: AreaInput(
            applicable=applicable,
            fresh=sum(values) if fresh and (area != "wifi" or log_ok) else 0,
            total=len(values),
        )
        for area, (applicable, values) in indicators.items()
    }


def _severity_rank(value: Any) -> int:
    try:
        return Severity(value).rank
    except ValueError:
        return Severity.WARNING.rank


def _finite(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _positive(value: Any) -> float | None:
    return float(value) if _finite(value) and value > 0 else None


def _log_coverage(coverage: Mapping[str, Any]) -> float | None:
    """The ``log`` share of ``WifiState.coverage`` (None when unknown)."""
    value = coverage.get("log")
    return float(value) if _finite(value) else None


def _upper_keys(value: Any) -> frozenset[str]:
    """Upper-case string keys of a dict (a MAC table); empty for anything else."""
    if not isinstance(value, dict):
        return frozenset()
    return frozenset(k.upper() for k in value if isinstance(k, str))


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
