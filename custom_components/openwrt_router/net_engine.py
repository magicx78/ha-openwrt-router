"""Fleet-wide network intelligence engine: collect events and persist them.

One ``NetIntelligence`` per Home Assistant instance lives in ``hass.data``
(same pattern as ``fleet.FleetOutageTracker``). Every router coordinator
feeds it through a listener; the engine turns the log events of the latest
poll (``OpenWrtCoordinatorData.new_log_events`` with the cursor facts in
``new_log_batch``) into ``NetEvent`` records and counters and keeps them,
together with the full alarm machine state, in one ``Store`` file for the
whole fleet.

Scope of this module (plan 2026-11-16, P2): collecting and persisting. The
detectors (P3/P4), correlation (P5), score, entities and bus events (P6)
build on it. The engine never talks to a router: it only reads data the
coordinator already has, so a poll costs exactly the same router calls.

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

Failure handling: an unreadable or foreign store starts empty with a
warning; an error while ingesting is logged and never reaches the poll.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections import Counter
from collections.abc import Iterable
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.json import prepare_save_json
from homeassistant.helpers.storage import Store

from .const import (
    DOMAIN,
    INTEL_MAX_STORE_BYTES,
    INTEL_PRUNE_INTERVAL_SECONDS,
    INTEL_SAVE_DELAY_SECONDS,
    INTEL_STORE_KEY,
    INTEL_STORE_MINOR_VERSION,
    INTEL_STORE_VERSION,
)
from .coordinator import LogBatch
from .log_parser import (
    CATEGORY_DFS,
    CATEGORY_DHCP,
    CATEGORY_WIFI,
    COUNT_ONLY_KINDS,
    LogEvent,
)
from .net_events import (
    CLOCK_SKEW_LIMIT,
    Category,
    EventCounters,
    EventRing,
    IncidentStatus,
    NetEvent,
    Origin,
    Severity,
    Source,
)
from .net_rules import AlarmMachine, merge_settings

_LOGGER = logging.getLogger(__name__)

_DATA_KEY = f"{DOMAIN}_net_intelligence"
_FLUSH_KEY = f"{DOMAIN}_net_intelligence_flush"

_DAY = 86400
_OPEN_STATES = (IncidentStatus.ACTIVE, IncidentStatus.ACKNOWLEDGED)
LOG_GAP_KIND = "system.log_gap"

# Log event category -> NetEvent category. DFS radar/CAC lines are radio
# events, so they count as Wi-Fi.
_CATEGORY_MAP: dict[str, Category] = {
    CATEGORY_WIFI: Category.WIFI,
    CATEGORY_DHCP: Category.DHCP,
    CATEGORY_DFS: Category.WIFI,
}


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
    # engine, and its load waits for the flush below.
    hass.data.pop(_DATA_KEY, None)
    flush: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    hass.data[_FLUSH_KEY] = flush
    try:
        await engine.async_flush()
    finally:
        flush.set_result(None)
        if hass.data.get(_FLUSH_KEY) is flush:
            hass.data.pop(_FLUSH_KEY, None)


async def async_remove_router_data(hass: HomeAssistant, entry_id: str) -> None:
    """Delete everything stored about a removed config entry."""
    engine = async_get_engine(hass)
    if engine is not None:
        if engine.remove_router(entry_id):
            engine.schedule_save()
        return
    # Last entry removed: the engine is gone, edit the store directly.
    engine = NetIntelligence(hass)
    await engine.async_load()
    if engine.remove_router(entry_id):
        await engine.async_flush()


class NetIntelligence:
    """Collects ``NetEvent``s of all routers and persists them in one store."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
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
        self._last_prune: float | None = None
        # True while a delayed write is scheduled: HA's async_delay_save
        # moves a pending write back on every call, so we call it once.
        self._save_pending = False
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
        """Read the store once; a damaged or foreign store starts empty."""
        async with self._lock:
            if self._loaded:
                return
            pending = self.hass.data.get(_FLUSH_KEY)
            if isinstance(pending, asyncio.Future) and not pending.done():
                await pending
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
                self._restore(stored)
            self._loaded = True

    @callback
    def register(self, entry_id: str) -> None:
        """A router's entry is loaded and starts feeding the engine."""
        self._routers.add(entry_id)
        # A reload starts from a clean comparison state (no false alarms).
        self._last_data.pop(entry_id, None)

    @callback
    def unregister(self, entry_id: str) -> None:
        """A router's entry is unloaded; its stored data stays."""
        self._routers.discard(entry_id)
        self._last_data.pop(entry_id, None)

    def remove_router(self, entry_id: str) -> bool:
        """Forget all data of a router; True if anything was removed."""
        self.unregister(entry_id)
        removed = self.ring.remove_router(entry_id) > 0
        removed |= entry_id in self.counters.to_dict()
        self.counters.remove_router(entry_id)
        removed |= self._log_marks.pop(entry_id, None) is not None
        removed |= self.machine.remove_router(entry_id) > 0
        return removed

    @callback
    def schedule_save(self) -> None:
        """Write the store at most ``INTEL_SAVE_DELAY_SECONDS`` from now."""
        if self._save_pending:
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
            self.ingest(entry_id, coordinator.data, time.time())
        except Exception:
            _LOGGER.warning(
                "Network intelligence could not process a poll of %s",
                entry_id,
                exc_info=True,
            )

    def ingest(self, entry_id: str, data: Any, now: float) -> int:
        """Ingest one poll's data; return the number of stored events.

        The same data object is ingested only once: after a failed poll
        the coordinator notifies its listeners with the previous data.
        ``now`` goes through the machine clock first (see module doc).
        """
        if data is None or self._last_data.get(entry_id) is data:
            return 0
        self._last_data[entry_id] = data
        step = self.machine.sync_clock(now)
        if step.shift:
            self.ring.shift(step.shift)
        now = step.now
        log_events = getattr(data, "new_log_events", ())
        if not isinstance(log_events, (tuple, list)):
            log_events = ()
        batch = getattr(data, "new_log_batch", None)
        if not isinstance(batch, LogBatch):
            batch = None
        mark_before = self._log_marks.get(entry_id)
        stored = self._ingest_log(entry_id, log_events, batch, now)
        self.machine.update(now)
        self._prune(now)
        if stored or self._log_marks.get(entry_id) != mark_before:
            self.schedule_save()
        return stored

    def _ingest_log(
        self,
        entry_id: str,
        events: Iterable[Any],
        batch: LogBatch | None,
        now: float,
    ) -> int:
        stored = 0
        baseline = batch is not None and batch.baseline
        if batch is not None and baseline:
            events, stored = self._gap_events(entry_id, events, batch, now)
        for event in events:
            if not isinstance(event, LogEvent):
                continue
            category = _CATEGORY_MAP.get(event.category)
            if category is None:
                continue
            src_ts = event.time_ms / 1000 if event.time_ms > 0 else None
            # Gap lines happened before this poll: keep their router time.
            ts = src_ts if baseline and src_ts is not None and src_ts <= now else now
            self.counters.add(entry_id, event.key, ts)
            if (event.category, event.kind) in COUNT_ONLY_KINDS:
                continue
            self.ring.add(self._net_event(entry_id, category, event, ts, src_ts, now))
            stored += 1
        if batch is not None and batch.last_id is not None:
            mark = {"last_id": batch.last_id}
            if batch.last_time_ms is not None:
                mark["last_time_ms"] = batch.last_time_ms
            self._log_marks[entry_id] = mark
        return stored

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
    ) -> NetEvent:
        self._seq += 1
        skew = src_ts is not None and abs(src_ts - now) > CLOCK_SKEW_LIMIT
        subject = {
            key: value
            for key, value in (
                ("mac", event.mac),
                ("iface", event.interface),
                ("ip", event.ip),
            )
            if value
        }
        params = {
            key: value
            for key, value in (
                ("frequency", event.frequency),
                ("channel", event.channel),
            )
            if value is not None
        }
        return NetEvent(
            id=f"{entry_id}:{self._seq}",
            ts=ts,
            router=entry_id,
            category=category,
            kind=event.key,
            origin=Origin.OBSERVED,
            source=Source.LOG,
            subject=subject,
            severity=Severity.INFO,
            msg_key=event.key,
            params=params,
            src_ts=src_ts,
            clock_skew=skew,
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
            # Health score and coverage arrive with P6.
            "score": None,
            "coverage": None,
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
            "events": self.ring.to_list(),
            "machine": self.machine.to_dict(),
            "counters": self.counters.to_dict(),
            "log_marks": self._log_marks,
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
        while size > INTEL_MAX_STORE_BYTES and payload["events"]:
            events = payload["events"]
            share = (size - INTEL_MAX_STORE_BYTES) / size
            drop = min(len(events), max(1, math.ceil(len(events) * share)))
            self._drop_oldest(drop)
            self.trimmed_events += drop
            payload = self._payload()
            size = _store_size(payload)
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
        if tail.isdigit():
            best = max(best, int(tail))
    return best


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
