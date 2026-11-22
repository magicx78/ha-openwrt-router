"""Network Time Machine, Phase B: the engine that fills the own index.

Plan ``docs/plans/2026-11-21-network-time-machine.md`` §5, §9 (Phase B).
One engine per HA instance, created only while the fleet-wide switch
(``time_machine_enabled``) is on: off, nothing of this module runs (no
store, no listener, no task). It reads only what the integration already
has and never calls a router:

* **outages**: ``fleet.FleetOutageTracker`` (``add_listener`` +
  ``snapshot``). A reported router outage is a ``router_down`` interval,
  the fleet outage (every router down, HA side) a ``lan_down`` interval;
  their end adds ``router_up`` / ``lan_up`` with the duration.
* **polls**: one coordinator listener per router (HA calls it after every
  success and on the first failure). A failed poll opens an
  ``observation_gap`` (dropped when shorter than ``GAP_MIN_S`` or when an
  outage takes over); a successful one compares radios (channel, width,
  radio gone / back, two polls debounce), the configuration fingerprint
  (``config_snapshot.fingerprint_from_coordinator``, 16 hex, two polls
  debounce) and the uplink parent and role from the Network Intelligence
  topology (two polls debounce, remembered edges ignored).
* **audit**: ``ConfigurationApi.subscribe``: configuration and disruption
  entries of the modules (``tm_marks.REF_KINDS``) become reference marks,
  so they outlive the audit ring. Entries about a client are not taken.
* **own marks**: ``tm_started``, ``tm_disabled``, ``tm_store_recovered``,
  ``ha_gap`` (from the last write before a restart), ``clock_shift``.

A tick every ``TICK_S`` prunes the index (14 days), checks the clock,
writes a heartbeat (so a crash still leaves a recent ``saved_at``) and
takes the daily checkpoint. Writes are delayed and bundled
(``tm_store.SAVE_DELAY_S``); HA writes the last one at shutdown.

Client sessions (Phase C) live in ``tm_clients`` and are attached only
while the separate client switch is on.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Final

from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import CALLBACK_TYPE, Event, HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.util import dt as dt_util

from .const import (
    DATA_TIME_MACHINE_ENGINE,
    DOMAIN,
    OPTION_TIME_MACHINE_CLIENTS,
    OPTION_TIME_MACHINE_ENABLED,
)
from .tm_marks import (
    END_CLOSED,
    END_OPEN,
    END_UNKNOWN,
    QUOTA_CLIENTS,
    QUOTA_INFRA,
    REF_KINDS,
    RETENTION_S,
    MarkIndex,
    to_ms,
    valid_router_id,
)
from .tm_store import (
    STOP_DISABLED,
    STOP_HA,
    STOP_UNLOADED,
    TimeMachineStore,
    pack_radios,
    unpack_radios,
)

_LOGGER = logging.getLogger(__name__)

MODULE: Final = "time_machine"
EVENT_PREFIX: Final = "time_machine."
TICK_S: Final = 300.0
HEARTBEAT_S: Final = 900.0
_PSEUDONYM: Final = re.compile(r"tmc_[0-9a-f]{16}")
CLOCK_JUMP_S: Final = 300.0  # plan §5.4
# 1.52.0: a followed stretch gets a new base from the current state once
# its base is this old (tm_state needs every mark after a base)
REBASE_S: Final = 86_400.0
GAP_MIN_S: Final = 120.0  # an observation gap shorter than this is dropped
UNLOAD_GAP_MIN_S: Final = 600.0
# When the integration was set up in this HA run (``async_setup``; review
# K10): the end of an HA gap even if no router could be loaded at first.
DATA_HA_STARTED: Final = "openwrt_router_time_machine_ha_started"
DEBOUNCE_POLLS: Final = 2
CHECKPOINT_MAX: Final = 4000

_LOCK_KEY: Final = f"{DOMAIN}_time_machine_lock"


def _epoch(value: datetime | None) -> float | None:
    return value.timestamp() if isinstance(value, datetime) else None


def _token(value: Any) -> str | None:
    from .tm_sources import token

    return token(value)


# --- per router ---------------------------------------------------------------------


@dataclass(slots=True)
class _Debounce:
    """A value accepted after DEBOUNCE_POLLS equal polls in a row."""

    candidate: str | None = None
    count: int = 0
    # the first poll that saw the candidate (review B: a failed poll between
    # it and the confirming one does not feed the debounce)
    since: float | None = None

    def feed(self, value: str, now: float | None = None) -> bool:
        """True when ``value`` was just seen often enough."""
        if value != self.candidate:
            self.candidate, self.count, self.since = value, 1, now
        else:
            self.count += 1
        return self.count == DEBOUNCE_POLLS


@dataclass(slots=True)
class _Router:
    """Memory state of one router entry (nothing of it identifies a client)."""

    entry_id: str
    coordinator: Any
    unsub: CALLBACK_TYPE | None = None
    router_id: str | None = None
    gap_seq: int | None = None
    # review C: the first failed poll of a gap reopened after a clear (the
    # gap's own start is the clear; GAP_MIN_S counts from this one)
    gap_since: float | None = None
    # radio key -> (first missing ts, polls missing)
    missing: dict[str, tuple[float, int]] = field(default_factory=dict)
    radio_down: dict[str, int] = field(default_factory=dict)  # key -> seq
    fp: _Debounce = field(default_factory=_Debounce)
    uplink: _Debounce = field(default_factory=_Debounce)
    last_dfs: str | None = None


def radio_keys(radios: list[Any]) -> dict[str, tuple[int, int, str]]:
    """``{band}{ordinal}`` -> (channel, width, phy). The ordinal counts the
    radios of a band in phy order; the phy name itself is never stored."""
    out: dict[str, tuple[int, int, str]] = {}
    by_band: dict[str, list[Any]] = {}
    for radio in radios:
        by_band.setdefault(radio.band, []).append(radio)
    for band, items in by_band.items():
        for i, radio in enumerate(sorted(items, key=lambda r: r.phy)):
            out[f"{band}{i}"] = (int(radio.channel), int(radio.width), radio.phy)
    return out


@dataclass(slots=True)
class RouterState:
    """The stored per-router state (``tm_store.state``)."""

    fp: str = ""
    radios: dict[str, tuple[int, int]] = field(default_factory=dict)
    parent: str = ""
    role: str = ""

    @classmethod
    def parse(cls, raw: str | None) -> RouterState:
        """From ``fp|radios|parent|role`` (validated by the store)."""
        parts = (raw or "").split("|")
        if len(parts) != 4:
            return cls()
        return cls(parts[0], unpack_radios(parts[1]), parts[2], parts[3])

    def dump(self) -> str:
        """To ``fp|radios|parent|role``."""
        return f"{self.fp}|{pack_radios(self.radios)}|{self.parent}|{self.role}"


# --- engine -------------------------------------------------------------------------


class TimeMachine:
    """The running Time Machine index of one HA instance."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        store: TimeMachineStore | None = None,
    ) -> None:
        """Nothing is read or attached before :meth:`async_start`."""
        self.hass = hass
        self.clock = clock
        self.monotonic = monotonic
        self.store = store or TimeMachineStore(hass, clock=clock)
        self.routers: dict[str, _Router] = {}
        self.loaded = False
        self.closed = False
        self.load_failed = False
        self.clients_wanted = False
        self.recorder: Any = None  # tm_clients.ClientRecorder while on
        self._unsubs: list[Callable[[], None]] = []
        self._api: Any = None
        self._core: Any = None
        self._api_unsubs: list[Callable[[], None]] = []
        self._outage_seq: dict[str, int] = {}  # entry_id -> router_down seq
        # review E: per router the bands of radios that were off when the
        # engine lost sight of them (restart, clear, reload): they are not in
        # the radio state, so a base set without them is incomplete
        self._radios_off: dict[str, list[int | float]] = {}
        self._lan_seq: int | None = None
        self._last_wall: float | None = None
        self._last_mono: float | None = None
        self._last_save: float = 0.0
        # start of this run: an outage seen at start that began earlier is
        # recorded from here on (the time before is the restart's gap)
        self._live_from: float = 0.0
        self._checkpoint_day: date | None = None
        self.counters: dict[str, int] = {
            "refs_taken": 0,
            "gaps_dropped": 0,
            "clock_shifts": 0,
        }

    @property
    def index(self) -> Any:
        """The mark index (``tm_marks.MarkIndex``)."""
        return self.store.index

    # -- start / stop ------------------------------------------------------------------

    async def async_start(self, *, clients: bool) -> None:
        """Read the store, write the start marks and attach the listeners."""
        result = await self.store.async_load()
        now = self.clock()
        index = self.index
        self.load_failed = result.failed
        if result.failed:
            index.add(
                ts=now,
                kind="tm_store_recovered",
                router=None,
                severity="warning",
                code="store_recovered",
            )
        saved_at = result.saved_at
        # 1.52.0: nothing was followed after the last write of the last run
        self.store.seen_close_all(saved_at if saved_at is not None else now)
        self.store.clients_until(saved_at if saved_at is not None else now)
        if saved_at is not None:
            self.store.cover_until(saved_at)
            self._close_all_open(saved_at, END_UNKNOWN)
            self._mark_restart(now, saved_at, result.stop)
        else:
            self._close_all_open(now, END_UNKNOWN)
            if not result.failed:
                index.add(ts=now, kind="tm_started", router=None, code="first_start")
        self.store.cover_from(now)
        self._live_from = now
        index.prune(now)
        self.store.prune_meta(now, RETENTION_S)
        self._last_wall, self._last_mono = now, self.monotonic()
        self.loaded = True
        from .fleet import async_get_outage_tracker

        tracker = async_get_outage_tracker(self.hass)
        self._unsubs.append(tracker.add_listener(self._on_outage))
        self._unsubs.append(
            self.hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, self._on_ha_stop)
        )
        self._unsubs.append(
            async_track_time_interval(
                self.hass, self._on_tick, timedelta(seconds=TICK_S)
            )
        )
        await self.async_bind_core()
        if result.failed:
            self.emit("time_machine.store_recovered", severity="warning")
        self.clients_wanted = clients
        if not clients:
            self._drop_clients()
        await self.async_sync_clients()
        self._on_outage()
        self._checkpoint("start", now)
        self.store.schedule()

    def _mark_restart(self, now: float, saved_at: float, stop: str | None) -> None:
        index = self.index
        if now < saved_at - CLOCK_JUMP_S:
            self.counters["clock_shifts"] += 1
            # review A: the time up to the old wall clock is occupied twice
            index.note_until(QUOTA_INFRA, saved_at)
            index.note_until(QUOTA_CLIENTS, saved_at)
            index.add(
                ts=now,
                kind="clock_shift",
                router=None,
                severity="warning",
                code="backwards",
                params={"shift_s": round(now - saved_at)},
            )
            return
        gap = max(0.0, now - saved_at)
        if stop == STOP_DISABLED:
            index.add(
                ts=now,
                kind="tm_started",
                router=None,
                code="switched_on",
                params={"off_s": round(gap)},
            )
        elif stop == STOP_UNLOADED:
            if gap >= UNLOAD_GAP_MIN_S:
                index.add(
                    ts=saved_at,
                    kind="observation_gap",
                    router=None,
                    severity="info",
                    code="unloaded",
                    end=now,
                    end_state=END_CLOSED,
                    params={"gap_s": round(gap)},
                )
        else:
            # ``stop``: HA shut down cleanly; None: the last heartbeat before
            # an unclean end (its start is then only known to HEARTBEAT_S).
            # HA itself may have run long before the first router loaded
            # (all unreachable at the start, K10): the HA gap ends at HA's
            # start, the rest is an observation gap ``unloaded``.
            started = self.hass.data.get(DATA_HA_STARTED)
            end = now
            if (
                isinstance(started, float)
                and saved_at <= started
                and now - started >= UNLOAD_GAP_MIN_S
            ):
                end = started
                index.add(
                    ts=started,
                    kind="observation_gap",
                    router=None,
                    severity="info",
                    code="unloaded",
                    end=now,
                    end_state=END_CLOSED,
                    params={"gap_s": round(now - started)},
                )
            index.add(
                ts=saved_at,
                kind="ha_gap",
                router=None,
                severity="info" if stop == STOP_HA else "warning",
                code="restart" if stop == STOP_HA else "unclean",
                end=end,
                end_state=END_CLOSED,
                params={"gap_s": round(end - saved_at), "clean": stop == STOP_HA},
                derived=stop != STOP_HA,
            )

    def _close_all_open(self, at: float, state: str) -> None:
        """Every open interval ends (at ``at``, never before its start)."""
        for mark in self.index.open_marks():
            if mark.kind == "radio_down" and mark.router is not None:
                self._note_off(mark.router, (mark,))
            self.index.close(mark.seq, at, state)
        # evicted open intervals end here as well (review D)
        self.index.resolve_lost_open(at)
        self._outage_seq.clear()
        self._lan_seq = None
        for router in self.routers.values():
            router.gap_seq = None
            router.radio_down.clear()
        if self.recorder is not None:
            self.recorder.reset_open()

    def _note_off(self, rid: str | None, marks: Any) -> None:
        """Radios off whose return the engine will not see as a mark."""
        if rid is None:
            return
        bands = [m.params.get("band") for m in marks if m is not None]
        if bands:
            self._radios_off.setdefault(rid, []).extend(b for b in bands if b)

    def _after_reset(
        self, now: float, gap_since: Mapping[str, float] | None = None
    ) -> None:
        """Outages, observation gaps and radios off go on after the own
        history lost its open intervals (clear, reload; review C/E): from
        ``now`` on, as known by the fleet tracker and the last poll
        (``gap_since``: per entry the first failed poll of a gap before)."""
        self._live_from = now
        self._sync_outages()
        for router in self.routers.values():
            rid = self.router_id(router.entry_id)
            coordinator = router.coordinator
            if (
                rid is None
                or router.gap_seq is not None
                or router.entry_id in self._outage_seq
                or getattr(coordinator, "last_update_success", True) is not False
            ):
                continue
            mark = self.index.add(
                ts=now,
                kind="observation_gap",
                router=rid,
                code="poll_failed",
                end_state=END_OPEN,
                derived=True,
            )
            router.gap_seq = mark.seq if mark else None
            router.gap_since = (gap_since or {}).get(router.entry_id)

    async def async_stop(self, reason: str) -> None:
        """Detach everything and write now (switched off / last router gone)."""
        if self.closed:
            return
        now = self.clock()
        if reason == STOP_DISABLED and self.loaded:
            self._close_all_open(now, END_UNKNOWN)
            self.index.add(ts=now, kind="tm_disabled", router=None, code="switched_off")
            self._drop_clients()
        await self.async_detach_clients()
        for entry_id in list(self.routers):
            self.remove_entry(entry_id, close=False)
        for unsub in self._unsubs:
            unsub()
        self._unsubs.clear()
        self._unbind_core()
        self.closed = True
        if self.loaded:
            self.store.cover_until(now)
            self.store.seen_close_all(now)
            self.store.clients_until(now)
            await self.store.async_flush(reason)
        if reason == STOP_DISABLED:
            # the client histories are deleted: no old copy keeps them (K4)
            await self.store.async_remove_copies()
        self.store.closed = True

    @callback
    def _on_ha_stop(self, _event: Event) -> None:
        """HA shuts down: the final write (HA's) carries ``stop``."""
        now = self.clock()
        self.store.stop_reason = STOP_HA
        self.store.cover_until(now)
        self.store.seen_close_all(now)
        self.store.clients_until(now)
        self.store.schedule(0)

    # -- core binding ------------------------------------------------------------------

    async def async_bind_core(self) -> None:
        """Subscribe to the audit log and register ``time_machine.``; a core
        restart is followed by the tick. Never raises."""
        from .enterprise_core import async_get_core

        core = async_get_core(self.hass)
        if core is not None and core is self._core and self._api is not None:
            return
        self._unbind_core()
        if core is None or getattr(core, "closed", False):
            return
        try:
            from .config_api import async_get_configuration_api

            api = await async_get_configuration_api(self.hass, 1)
        except Exception as err:  # noqa: BLE001 - the index works without audit refs
            _LOGGER.debug("Time Machine: core not bound (%s)", type(err).__name__)
            return
        self._core, self._api = core, api
        try:
            self._api_unsubs.append(
                api.register_event_prefix(EVENT_PREFIX, module=MODULE)
            )
        except (TypeError, ValueError) as err:
            _LOGGER.debug(
                "Time Machine: prefix not registered (%s)", type(err).__name__
            )
        try:
            self._api_unsubs.append(api.subscribe(self._on_audit))
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Time Machine: audit not subscribed (%s)", type(err).__name__)

    def _unbind_core(self) -> None:
        for unsub in self._api_unsubs:
            with contextlib.suppress(Exception):  # a gone core removes its own
                unsub()
        self._api_unsubs.clear()
        self._api = self._core = None

    async def async_module_key(self) -> bytes | None:
        """The module key for client pseudonyms (None without a core)."""
        await self.async_bind_core()
        if self._api is None:
            return None
        try:
            key = await self._api.async_get_module_key(MODULE, "pseudonym")
        except Exception as err:  # noqa: BLE001 - clients stay unavailable
            _LOGGER.warning("Time Machine: no client key (%s)", type(err).__name__)
            return None
        return key if isinstance(key, bytes) and len(key) >= 16 else None

    def emit(
        self, event_type: str, *, severity: str = "info", data: Any = None
    ) -> None:
        """One own audit event (codes and counts only); never raises."""
        if self._api is None:
            return
        try:
            from .core_models import Severity

            self._api.emit(
                event_type,
                source=MODULE,
                severity=Severity(severity),
                data=dict(data or {}),
            )
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Time Machine event not emitted (%s)", type(err).__name__)

    def emit_checked(
        self, event_type: str, *, data: Any = None, user_id: str | None = None
    ) -> bool:
        """One own audit event on the security ring (codes and counts only)
        that must be written (1.52.0, the export): False when there is no
        core or the audit log refused it."""
        if self._api is None:
            return False
        try:
            from .core_models import Actor, ActorKind

            actor = (
                Actor(kind=ActorKind.USER, user_id=user_id)
                if isinstance(user_id, str) and user_id
                else None
            )
            self._api.emit(
                event_type,
                source=MODULE,
                data=dict(data or {}),
                actor=actor,
                security_relevant=True,
            )
        except Exception as err:  # noqa: BLE001 - the caller refuses then
            _LOGGER.warning("Time Machine event not written (%s)", type(err).__name__)
            return False
        return True

    @callback
    def _on_audit(self, event: Any) -> None:
        """A published audit entry: a reference mark for REF_KINDS."""
        if self.closed:
            return
        try:
            from .tm_sources import (
                _AUDIT_PARAMS,
                _audit_concerns_client,
                audit_kind,
                params_of,
                severity_of,
            )

            event_type = str(getattr(event, "type", ""))
            if event_type.startswith(EVENT_PREFIX):
                return
            kind = audit_kind(event_type)
            if kind not in REF_KINDS or _audit_concerns_client(event):
                return
            ts = _epoch(getattr(event, "ts", None))
            event_id = getattr(event, "event_id", None)
            if ts is None or not isinstance(event_id, str):
                return
            router = getattr(event, "router_id", None)
            data = event.data if isinstance(event.data, Mapping) else {}
            mark = self.index.add(
                ts=ts,
                kind=kind,
                router=router if valid_router_id(router) else None,
                severity=severity_of(getattr(event, "severity", None)),
                code=_token(event_type),
                params=params_of(data, _AUDIT_PARAMS),
                ref=("audit", event_id),
            )
            if mark is not None:
                self.counters["refs_taken"] += 1
                self.store.schedule()
        except Exception as err:  # noqa: BLE001 - never breaks the audit log
            _LOGGER.debug("Time Machine: audit entry skipped (%s)", type(err).__name__)

    # -- clients (Phase C) ---------------------------------------------------------------

    async def async_set_clients(self, on: bool) -> None:
        """The client switch: on attaches, off detaches and deletes."""
        self.clients_wanted = on
        if not on:
            await self.async_detach_clients()
            if self._drop_clients():
                self.store.schedule(0)
            await self.store.async_remove_copies()
            return
        await self.async_sync_clients()

    def _drop_clients(self) -> int:
        dropped = self.index.clear(clients_only=True, now=self.clock())
        self.store.clients_cov = []  # what was recorded is gone (1.52.0)
        return dropped

    async def async_sync_clients(self) -> None:
        """Attach the recorder to the running Client Stability (if any)."""
        if not self.clients_wanted or self.closed:
            return
        from .tm_clients import ClientRecorder

        if self.recorder is None:
            key = await self.async_module_key()
            if key is None or self.closed or not self.clients_wanted:
                return
            self.recorder = ClientRecorder(self, key)
        self.recorder.attach()

    async def async_detach_clients(self) -> None:
        """Stop recording client sessions (stored data stays)."""
        if self.recorder is not None:
            self.recorder.detach()
            self.recorder = None

    # -- routers -------------------------------------------------------------------------

    def router_id(self, entry_id: Any) -> str | None:
        """The contract router id of an entry (cached; None if unknown)."""
        if not isinstance(entry_id, str):
            return None
        router = self.routers.get(entry_id)
        if router is not None and router.router_id is not None:
            return router.router_id
        from .enterprise_core import async_get_core

        registry = getattr(async_get_core(self.hass), "registry", None)
        try:
            rid = registry.router_id_for_entry(entry_id) if registry else None
        except Exception:  # noqa: BLE001 - an unknown entry has no router id
            rid = None
        rid = rid if valid_router_id(rid) else None
        if router is not None:
            router.router_id = rid
        return rid

    @callback
    def add_entry(self, entry_id: str, coordinator: Any) -> None:
        """Follow the polls of one router (no extra call)."""
        if self.closed or coordinator is None:
            return
        old = self.routers.get(entry_id)
        if old is not None and old.coordinator is coordinator:
            return
        if old is not None:
            self.remove_entry(entry_id)
        router = _Router(entry_id, coordinator)
        self.routers[entry_id] = router
        self.router_id(entry_id)

        @callback
        def _listener() -> None:
            self._on_poll(entry_id)

        router.unsub = coordinator.async_add_listener(_listener)
        if self.loaded and old is None:
            # review C: an outage the tracker holds is recorded again (a
            # reloaded entry lost its open outage in ``remove_entry``)
            self._on_outage()

    @callback
    def remove_entry(self, entry_id: str, *, close: bool = True) -> None:
        """Stop following a router; its open intervals end as unknown."""
        router = self.routers.pop(entry_id, None)
        if router is None:
            return
        if router.unsub is not None:
            router.unsub()
        now = self.clock()
        self.store.seen_close(router.router_id, now)
        if not close:
            return
        self._note_off(
            router.router_id, [self.index.get(s) for s in router.radio_down.values()]
        )
        for seq in (router.gap_seq, *router.radio_down.values()):
            self.index.close(seq, now, END_UNKNOWN)
        self.index.close(self._outage_seq.pop(entry_id, None), now, END_UNKNOWN)
        self.store.schedule()

    # -- outages -------------------------------------------------------------------------

    @callback
    def _on_outage(self) -> None:
        """Outage start or end in the fleet tracker."""
        if self.closed or not self.loaded:
            return
        try:
            self._sync_outages()
        except Exception as err:  # noqa: BLE001 - never breaks the tracker
            _LOGGER.debug("Time Machine: outage skipped (%s)", type(err).__name__)

    def _sync_outages(self) -> None:
        from .fleet import async_get_outage_tracker

        view = async_get_outage_tracker(self.hass).snapshot()
        now = self.clock()
        index = self.index
        changed = False
        fleet_since = _epoch(view.fleet_since)
        if fleet_since is not None and self._lan_seq is None:
            mark = index.add(
                ts=self._since(fleet_since, now),
                kind="lan_down",
                router=None,
                severity="critical",
                code="lan_unreachable",
                end_state=END_OPEN,
                derived=fleet_since < self._live_from,
            )
            self._lan_seq = mark.seq if mark else None
            changed = True
        elif fleet_since is None and self._lan_seq is not None:
            lan_seq, self._lan_seq = self._lan_seq, None
            mark = index.get(lan_seq)
            if _ends(index, mark, now, lan_seq):
                index.add(
                    ts=now,
                    kind="lan_up",
                    router=None,
                    code="lan_reachable",
                    params=_duration(mark, now),
                )
            changed = True
        for entry_id, outage in view.down.items():
            if not outage.reported or entry_id in self._outage_seq:
                continue
            rid = self.router_id(entry_id)
            began = _epoch(outage.since) or now
            mark = index.add(
                ts=self._since(began, now),
                derived=began < self._live_from,
                kind="router_down",
                router=rid,
                severity="warning",
                code=_token(outage.error_type) or "unknown",
                end_state=END_OPEN,
            )
            if mark is not None:
                self._outage_seq[entry_id] = mark.seq
                # the outage takes over an open observation gap
                router = self.routers.get(entry_id)
                if router is not None and router.gap_seq is not None:
                    gap = router.gap_seq
                    if index.get(gap) is None:
                        index.close(gap, now)  # evicted while open (review D)
                    index.remove_where(lambda m, gap=gap: m.seq != gap)
                    router.gap_seq = None
            changed = True
        for entry_id in [e for e in self._outage_seq if e not in view.down]:
            seq = self._outage_seq.pop(entry_id)
            mark = index.get(seq)
            if _ends(index, mark, now, seq):
                index.add(
                    ts=now,
                    kind="router_up",
                    router=mark.router if mark else self.router_id(entry_id),
                    code="reachable",
                    params=_duration(mark, now),
                )
            changed = True
        if changed:
            self.store.schedule()

    def _since(self, began: float, now: float) -> float:
        """An outage start inside this run (never before it, never ahead)."""
        return max(min(began, now), min(self._live_from, now))

    # -- polls ---------------------------------------------------------------------------

    def _on_poll(self, entry_id: str) -> None:
        if self.closed or not self.loaded:
            return
        router = self.routers.get(entry_id)
        if router is None:
            return
        try:
            if self._poll(router):
                self.store.schedule()
        except Exception as err:  # noqa: BLE001 - never breaks the coordinator
            _LOGGER.debug("Time Machine: poll skipped (%s)", type(err).__name__)

    def _poll(self, router: _Router) -> bool:
        coordinator = router.coordinator
        now = self.clock()
        rid = self.router_id(router.entry_id)
        if rid is None:
            return False
        index = self.index
        # 1.52.0: the router is followed (a stretch of ``seen``) from its
        # first poll on, failed or not
        self.store.seen_open(rid, now)
        if not coordinator.last_update_success:
            if router.gap_seq is None and router.entry_id not in self._outage_seq:
                mark = index.add(
                    ts=now,
                    kind="observation_gap",
                    router=rid,
                    code="poll_failed",
                    end_state=END_OPEN,
                )
                router.gap_seq = mark.seq if mark else None
                return mark is not None
            return False
        changed = False
        if router.gap_seq is not None:
            gap = index.get(router.gap_seq)
            if gap is None:
                index.close(router.gap_seq, now)  # evicted while open (D)
            router.gap_seq = None
            began = gap.ts if gap is not None else now
            if router.gap_since is not None:
                began = min(began, router.gap_since)
            router.gap_since = None
            if gap is not None and now - began < GAP_MIN_S:
                index.remove_where(lambda m, s=gap.seq: m.seq != s)
                self.counters["gaps_dropped"] += 1
            elif gap is not None:
                index.close(gap.seq, now)
                gap.params["gap_s"] = round(now - gap.ts)
            changed = True
        data = coordinator.data
        if data is None:
            return changed
        state = RouterState.parse(self.store.state.get(rid))
        changed |= self._radios(router, rid, data, state, now)
        changed |= self._fingerprint(router, rid, data, state, now)
        changed |= self._topology(router, rid, state, now)
        changed |= self._rebase(router, rid, state, now)
        dumped = state.dump()
        if self.store.state.get(rid) != dumped:
            self.store.state[rid] = dumped
            changed = True
        return changed

    def _radios(
        self, router: _Router, rid: str, data: Any, state: RouterState, now: float
    ) -> bool:
        from .channel_plan import phy_of, radios_from_ap_interfaces

        ap = getattr(data, "ap_interfaces", None) or []
        current = radio_keys(
            radios_from_ap_interfaces("", "", ap, getattr(data, "sta_interfaces", None))
        )
        if not current:
            return False  # an empty poll keeps the state (iwinfo failed)
        no_htmode = {
            str(i.get("phy") or phy_of(str(i.get("ifname") or "")))
            for i in ap
            if isinstance(i, Mapping) and not i.get("htmode")
        }
        index = self.index
        changed = False
        silent = False  # a radio appeared without a mark (1.52.0)
        last = (getattr(data, "dfs", None) or {}).get("last_event")
        for key, (chan, width, phy) in current.items():
            before = state.radios.get(key)
            if phy in no_htmode and before is not None:
                width = before[1]  # unknown width: keep the previous one
            router.missing.pop(key, None)
            seq = router.radio_down.pop(key, None)
            silent |= before is None and seq is None
            if seq is not None:
                mark = index.get(seq)
                if _ends(index, mark, now, seq):
                    index.add(
                        ts=now,
                        kind="radio_up",
                        router=rid,
                        code="radio_on",
                        params={**_duration(mark, now), "channel": chan},
                    )
                changed = True
            if before is not None and before != (chan, width):
                dfs = (
                    isinstance(last, Mapping)
                    and last.get("type") == "channel_change"
                    and last.get("radio") == phy
                    and last.get("new_channel") == chan
                    and last.get("dfs_related") is True
                    and str(last.get("time")) != router.last_dfs
                )
                if dfs:
                    router.last_dfs = str(last.get("time"))
                index.add(
                    ts=now,
                    kind="channel_changed",
                    router=rid,
                    severity="warning" if dfs else "info",
                    code="dfs" if dfs else "channel",
                    params={
                        "band": _band_num(key),
                        "channel_from": before[0],
                        "channel_to": chan,
                        "width_from": before[1],
                        "width_to": width,
                        "dfs": dfs,
                    },
                )
                changed = True
            state.radios[key] = (chan, width)
        for key in [k for k in state.radios if k not in current]:
            first, polls = router.missing.get(key, (now, 0))
            polls += 1
            router.missing[key] = (first, polls)
            if polls == DEBOUNCE_POLLS and key not in router.radio_down:
                mark = index.add(
                    ts=first,
                    kind="radio_down",
                    router=rid,
                    severity="warning",
                    code="radio_off",
                    end_state=END_OPEN,
                    params={"band": _band_num(key), "channel": state.radios[key][0]},
                )
                if mark is not None:
                    router.radio_down[key] = mark.seq
                del state.radios[key]
                router.missing.pop(key, None)
                changed = True
        self._seen_radios(rid, state, now, silent)
        return changed

    def _seen_radios(
        self, rid: str, state: RouterState, now: float, silent: bool
    ) -> None:
        """The radio base of the followed stretch (1.52.0): the first poll
        with radios sets it; a radio that appeared without a mark later
        starts a new stretch, so every stretch is complete by its marks."""
        seg = self.store.seen_current(rid)
        off = self._radios_off.get(rid)
        if silent and off:
            # a radio is back without a mark: one radio of its band less
            # is off (review E)
            for key in state.radios:
                if seg is None or key not in seg.radios:
                    band = _band_num(key)
                    if band in off:
                        off.remove(band)
            if not off:
                self._radios_off.pop(rid, None)
        if seg is not None and seg.radios_at is not None and silent:
            seg = self.store.seen_split(rid, now, parent=state.parent, role=state.role)
            seg.off = len(self._radios_off.get(rid, ()))
        if seg is not None and seg.radios_at is None:
            seg.radios_at, seg.radios = now, dict(state.radios)
            seg.off = len(self._radios_off.get(rid, ()))

    def _rebase(
        self, router: _Router, rid: str, state: RouterState, now: float
    ) -> bool:
        """A followed stretch whose base is ``REBASE_S`` old, or older than
        a lost mark (``MarkIndex.lost``), starts anew from the state after
        this poll (1.52.0): the marks a stretch needs never reach the 14-day
        pruning, and a lost one spoils only the time up to it. Not while a radio is missing or off or an
        uplink / role change is still being debounced (the new base would
        hide it)."""
        seg = self.store.seen_current(rid)
        if seg is None or seg.radios_at is None:
            return False
        lost = max(
            self.index.lost.get(QUOTA_INFRA, -math.inf),
            self.index.lost_router.get(rid, -math.inf),
        )
        if now - seg.radios_at < REBASE_S and lost <= seg.radios_at:
            return False
        if lost > now:
            # a clock jump back (review A): the base waits until the wall
            # clock passed the time it had before
            return False
        if router.missing or router.radio_down:
            return False
        if seg.topo_at is not None and router.uplink.candidate != (
            f"{state.parent}|{state.role}"
        ):
            return False
        seg = self.store.seen_split(rid, now, parent=state.parent, role=state.role)
        seg.radios_at, seg.radios = now, dict(state.radios)
        return True

    def _fingerprint(
        self, router: _Router, rid: str, data: Any, state: RouterState, now: float
    ) -> bool:
        from .config_snapshot import fingerprint_from_coordinator

        value = fingerprint_from_coordinator(data)[:16]
        if not router.fp.feed(value) or value == state.fp:
            return False
        before = state.fp
        state.fp = value
        if before:
            self.index.add(
                ts=now,
                kind="config_fingerprint_changed",
                router=rid,
                code="fingerprint",
            )
        return True

    def _topology(
        self, router: _Router, rid: str, state: RouterState, now: float
    ) -> bool:
        from .net_engine import async_get_engine

        engine = async_get_engine(self.hass)
        topology = getattr(engine, "topology", None) if engine else None
        if topology is None or not getattr(engine, "loaded", False):
            return False
        uplink = topology.uplinks.get(router.entry_id)
        parent = ""
        if uplink is not None and not uplink.remembered:
            parent = self.router_id(uplink.parent) or ""
        elif uplink is not None:
            parent = state.parent  # a remembered edge changes nothing
        role = "g" if router.entry_id in topology.gateways else "n"
        if not router.uplink.feed(f"{parent}|{role}", now):
            return False
        changed = False
        # review B: the first poll that saw the new value (the change began
        # before it; failed polls may lie between it and this one)
        since = router.uplink.since
        first = {"since": since} if since is not None and since < now else {}
        if parent != state.parent:
            if state.parent or state.role:
                self.index.add(
                    ts=now,
                    kind="uplink_changed",
                    router=rid,
                    code="uplink" if parent else "uplink_lost",
                    peers=(state.parent or None, parent or None),
                    params=first,
                )
            state.parent = parent
            changed = True
        if role != state.role:
            if state.role:
                self.index.add(
                    ts=now,
                    kind="router_role_changed",
                    router=rid,
                    code="gateway" if role == "g" else "node",
                    params=first,
                )
            state.role = role
            changed = True
        seg = self.store.seen_current(rid)
        if seg is not None and (seg.topo_at is None or seg.topo_at == now):
            # 1.52.0: the first settled uplink and role of the stretch (or a
            # change at the very poll a new stretch began: it is the base)
            seg.topo_at, seg.parent, seg.role = now, state.parent, state.role
            changed = True
        return changed

    # -- tick ----------------------------------------------------------------------------

    @callback
    def _on_tick(self, _now: datetime | None = None) -> None:
        if self.closed:
            return
        try:
            self.tick()
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Time Machine tick failed (%s)", type(err).__name__)
        self.hass.async_create_background_task(
            self._async_tick_bind(), "openwrt_router time machine bind"
        )

    async def _async_tick_bind(self) -> None:
        try:
            await self.async_bind_core()
            if self.clients_wanted and self.recorder is None:
                await self.async_sync_clients()
            elif self.recorder is not None:
                self.recorder.attach()
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Time Machine bind failed (%s)", type(err).__name__)

    def tick(self) -> None:
        """Prune, clock check, heartbeat, daily checkpoint (sync, short)."""
        now = self.clock()
        mono = self.monotonic()
        if self._last_wall is not None and self._last_mono is not None:
            shift = (now - self._last_wall) - (mono - self._last_mono)
            if abs(shift) > CLOCK_JUMP_S:
                self.counters["clock_shifts"] += 1
                if shift < 0:
                    # review A: the wall time up to where the clock was is
                    # occupied twice; nothing up to it counts as known
                    for quota in (QUOTA_INFRA, QUOTA_CLIENTS):
                        self.index.note_until(quota, now - shift)
                self.index.add(
                    ts=now,
                    kind="clock_shift",
                    router=None,
                    severity="warning",
                    code="backwards" if shift < 0 else "forwards",
                    params={"shift_s": round(shift)},
                )
        self._last_wall, self._last_mono = now, mono
        self.index.prune(now)
        self.store.prune_meta(now, RETENTION_S)
        today = dt_util.as_local(dt_util.utc_from_timestamp(now)).date()
        if self._checkpoint_day is not None and today != self._checkpoint_day:
            self._checkpoint("day", now)
        self._checkpoint_day = today
        if self.index.changed or now - self._last_save >= HEARTBEAT_S:
            self._last_save = now
            self.store.schedule()

    def _checkpoint(self, reason: str, now: float) -> None:
        """Per router: up/down, fingerprint, uplink parent (plan §5.4)."""
        self._checkpoint_day = dt_util.as_local(dt_util.utc_from_timestamp(now)).date()
        parts: list[str] = []
        size = 0
        for entry_id in sorted(self.routers):
            rid = self.router_id(entry_id)
            if rid is None:
                continue
            state = RouterState.parse(self.store.state.get(rid))
            up = int(entry_id not in self._outage_seq)
            part = f"{rid}:u={up},fp={state.fp or '-'},p={state.parent or '-'}"
            if size + len(part) + 1 > CHECKPOINT_MAX - 32:
                break
            parts.append(part)
            size += len(part) + 1
        self.store.add_checkpoint(f"{to_ms(now)}|{reason}|{';'.join(parts)}")

    # -- reading -------------------------------------------------------------------------

    def topology_pending(self) -> dict[str, float]:
        """Per router the first poll of an uplink / role candidate the
        debounce has not confirmed yet (review B; read only)."""
        out: dict[str, float] = {}
        for router in self.routers.values():
            rid = router.router_id
            debounce = router.uplink
            if rid is None or debounce.candidate is None or debounce.since is None:
                continue
            state = RouterState.parse(self.store.state.get(rid))
            if debounce.candidate != f"{state.parent}|{state.role}":
                out[rid] = debounce.since
        return out

    def stats(self) -> dict[str, Any]:
        """Counts only (no ids) for diagnostics."""
        return {
            "loaded": self.loaded,
            "load_failed": self.load_failed,
            "routers": len(self.routers),
            "clients_recording": self.recorder is not None and self.recorder.attached,
            "index": self.index.stats(),
            "store": self.store.stats(),
            **self.counters,
        }


def _ends(index: MarkIndex, mark: Any, now: float, seq: int | None = None) -> bool:
    """Close an outage-like interval; True when its end is to be booked.

    A mark evicted while open (only when its quota held nothing else,
    review S2) still gets its end mark, without a duration: no hanging
    reference, no invented start. Its quota counts as lost up to ``now``
    (review D, ``MarkIndex.close`` of the gone ``seq``).
    """
    if mark is None:
        index.close(seq, now)
        return True
    return index.close(mark.seq, now)


def _duration(mark: Any, now: float) -> dict[str, int]:
    return {} if mark is None else {"duration_s": round(now - mark.ts)}


def _band_num(key: str) -> int | float:
    """``2.4g0`` -> 2.4, ``5g1`` -> 5, ``6g0`` -> 6."""
    head = key.split("g", 1)[0]
    try:
        value = float(head)
    except ValueError:
        return 0
    return int(value) if value.is_integer() else value


# --- life cycle ---------------------------------------------------------------------


def _entries(hass: HomeAssistant) -> list[Any]:
    from .tm_sources import domain_entries

    return domain_entries(hass)


def fleet_option(hass: HomeAssistant, key: str) -> bool:
    """A fleet-wide switch: on while any router entry has it on."""
    return any(
        isinstance(getattr(e, "options", None), Mapping) and e.options.get(key) is True
        for e in _entries(hass)
    )


@callback
def async_get_time_machine(hass: HomeAssistant) -> TimeMachine | None:
    """The running engine, or None (off)."""
    engine = hass.data.get(DATA_TIME_MACHINE_ENGINE)
    return engine if isinstance(engine, TimeMachine) and not engine.closed else None


def _lock(hass: HomeAssistant) -> asyncio.Lock:
    lock = hass.data.get(_LOCK_KEY)
    if not isinstance(lock, asyncio.Lock):
        lock = hass.data[_LOCK_KEY] = asyncio.Lock()
    return lock


def _coordinator_of(entry: Any) -> Any:
    return getattr(getattr(entry, "runtime_data", None), "coordinator", None)


async def _async_engine(hass: HomeAssistant, clients: bool) -> TimeMachine:
    engine = async_get_time_machine(hass)
    if engine is None:
        engine = TimeMachine(hass)
        hass.data[DATA_TIME_MACHINE_ENGINE] = engine
        await engine.async_start(clients=clients)
    return engine


async def async_setup_time_machine(hass: HomeAssistant, entry: Any) -> None:
    """Add a loaded router; off (the default) nothing is created."""
    if not fleet_option(hass, OPTION_TIME_MACHINE_ENABLED):
        return
    async with _lock(hass):
        clients = fleet_option(hass, OPTION_TIME_MACHINE_CLIENTS)
        engine = await _async_engine(hass, clients)
        engine.add_entry(entry.entry_id, _coordinator_of(entry))
        await engine.async_sync_clients()


async def async_release_time_machine(hass: HomeAssistant, entry_id: str) -> None:
    """Drop an unloaded router; after the last one stop and write."""
    async with _lock(hass):
        engine = async_get_time_machine(hass)
        if engine is None:
            return
        engine.remove_entry(entry_id)
        if engine.routers:
            return
        hass.data.pop(DATA_TIME_MACHINE_ENGINE, None)
        await engine.async_stop(STOP_UNLOADED)


async def async_apply_time_machine_options(
    hass: HomeAssistant, *, on: bool, clients: bool
) -> None:
    """The options flow changed a switch (no reload); never raises."""
    try:
        async with _lock(hass):
            engine = async_get_time_machine(hass)
            if not on:
                # Off deletes the client histories, whatever the client
                # switch says; the infrastructure history stays (1.51.0).
                if engine is not None:
                    hass.data.pop(DATA_TIME_MACHINE_ENGINE, None)
                    await engine.async_stop(STOP_DISABLED)
                else:
                    await async_purge_clients(hass)
                return
            if engine is None:
                engine = await _async_engine(hass, clients)
                for entry in _entries(hass):
                    if _coordinator_of(entry) is not None:
                        engine.add_entry(entry.entry_id, _coordinator_of(entry))
            await engine.async_set_clients(clients)
    except Exception as err:  # noqa: BLE001 - the form never fails because of it
        _LOGGER.warning("Time Machine options not applied (%s)", type(err).__name__)


async def async_purge_clients(hass: HomeAssistant) -> int:
    """No engine runs (the Time Machine is off, or switched off while no
    router was loaded): delete the stored client marks now (one read, one
    write only if there were any)."""
    store = TimeMachineStore(hass)
    result = await store.async_load()
    # an unreadable file is left alone; its old copies go either way (K4)
    await store.async_remove_copies()
    if result.failed:
        return 0
    dropped = store.index.clear(clients_only=True, now=store.clock())
    if dropped:
        store.clients_cov = []
        await store.async_flush(result.stop or STOP_DISABLED)
    return dropped


async def async_remove_router(hass: HomeAssistant, router_id: str | None) -> int:
    """A router was removed from HA: delete its marks (review K4, like the
    network intelligence does). The running engine drops them; without one
    the file is edited (one read, one write only if there were any)."""
    if not router_id:
        return 0
    async with _lock(hass):
        engine = async_get_time_machine(hass)
        if engine is not None and engine.loaded and not engine.closed:
            store = engine.store
            dropped = engine.index.forget_router(router_id, engine.clock())
            store.state.pop(router_id, None)
            store.seen.pop(router_id, None)
            if dropped:
                store.schedule(0)
        else:
            store = TimeMachineStore(hass)
            result = await store.async_load()
            if result.failed:
                return 0
            dropped = store.index.forget_router(router_id, store.clock())
            had_state = store.state.pop(router_id, None) is not None
            had_state |= store.seen.pop(router_id, None) is not None
            if dropped or had_state:
                await store.async_flush(result.stop or STOP_DISABLED)
        # The .bak / .corrupt.* copies stay (review K-b): router ids are no
        # personal data, and a copy of an unreadable or newer file (a
        # downgrade) holds every other router's history for a recovery.
        return dropped


# --- actions (administrators only) ------------------------------------------------

# Modules that keep client data of their own; the forget action does not
# reach them (plan F10: forgetting across modules is a later package).
NOT_FORGOTTEN_IN: Final = (
    "client_stability",
    "network_intelligence",
    "security_center",
    "traffic_analytics",
    "wifi_rf",
    "recorder",
)


def _service_error(key: str) -> Exception:
    from homeassistant.exceptions import ServiceValidationError

    return ServiceValidationError(translation_domain=DOMAIN, translation_key=key)


async def async_forget_client(
    hass: HomeAssistant, mac: Any = None, client: Any = None
) -> dict[str, Any]:
    """Delete every mark of one client, by MAC (not kept) or by its
    pseudonym ``tmc_…`` (review K2: exactly one of both)."""
    from homeassistant.exceptions import HomeAssistantError

    from .core_masking import pseudonymise_identifier

    mac = None if mac == "" else mac  # an empty form field is no input
    client = None if client == "" else client
    if (mac is None) == (client is None):
        raise _service_error("time_machine_mac_or_client")
    engine = async_get_time_machine(hass)
    if engine is None or not engine.loaded:
        raise _service_error("time_machine_off")
    if client is not None:
        if not isinstance(client, str) or not _PSEUDONYM.fullmatch(client):
            raise _service_error("time_machine_invalid_client")
        hexed = client[4:]
    else:
        key = await engine.async_module_key()
        if key is None:
            raise HomeAssistantError(
                translation_domain=DOMAIN, translation_key="time_machine_no_key"
            )
        try:
            hexed = pseudonymise_identifier("client", mac, key)[4:]
        except (TypeError, ValueError):
            raise _service_error("time_machine_invalid_mac") from None
    if engine.recorder is not None:
        deleted = engine.recorder.forget_client(hexed)
    else:
        deleted = engine.index.forget_client(hexed)
    now = engine.clock()
    engine.index.add(
        ts=now,
        kind="tm_forgot_client",
        router=None,
        code="forgot_client",
        params={"deleted": deleted},
    )
    engine.emit("time_machine.client_forgotten", data={"deleted": deleted})
    engine.store.schedule(0)
    await engine.store.async_remove_copies()
    return {"deleted": deleted, "not_deleted_in": list(NOT_FORGOTTEN_IN)}


async def async_clear_history(
    hass: HomeAssistant, clients_only: bool
) -> dict[str, Any]:
    """Delete the client marks or the whole own history."""
    engine = async_get_time_machine(hass)
    if engine is None or not engine.loaded:
        raise _service_error("time_machine_off")
    now = engine.clock()
    gap_since: dict[str, float] = {}
    for router in engine.routers.values():
        gap = engine.index.get(router.gap_seq)
        if gap is not None:
            gap_since[router.entry_id] = min(gap.ts, router.gap_since or gap.ts)
    if clients_only:
        deleted = engine.index.clear(clients_only=True, now=now)
        engine.store.clients_cov = [[now, None]] if _recording(engine) else []
    else:
        deleted = engine.index.clear(clients_only=False, now=now)
        engine.store.checkpoints.clear()
        engine.store.coverage = [[now, None]]
        engine.store.seen_restart(
            now,
            {
                rid: (parsed.parent, parsed.role)
                for rid, raw in engine.store.state.items()
                for parsed in (RouterState.parse(raw),)
            },
        )
        engine.store.clients_cov = [[now, None]] if _recording(engine) else []
        engine._outage_seq.clear()
        engine._lan_seq = None
        for router in engine.routers.values():
            engine._note_off(
                router.router_id,
                [engine.index.get(s) for s in router.radio_down.values()],
            )
            router.gap_seq = None
            router.radio_down.clear()
    if engine.recorder is not None:
        engine.recorder.reset_open()
    if not clients_only:
        # review C: a router down now stays down in the new history
        engine._after_reset(now, gap_since)
    engine.index.add(
        ts=now,
        kind="tm_cleared",
        router=None,
        code="clients" if clients_only else "all",
        params={"deleted": deleted},
    )
    engine.emit(
        "time_machine.history_cleared",
        data={"deleted": deleted, "clients_only": clients_only},
    )
    engine.store.schedule(0)
    await engine.store.async_remove_copies()
    return {"deleted": deleted}


def _recording(engine: TimeMachine) -> bool:
    return engine.recorder is not None and engine.recorder.attached


@callback
def note_ha_start(hass: HomeAssistant) -> None:
    """``async_setup``: remember when this HA run set the integration up
    (one float in ``hass.data``; nothing else happens while it is off)."""
    hass.data.setdefault(DATA_HA_STARTED, time.time())


@callback
def async_register_time_machine_services(hass: HomeAssistant) -> None:
    """Register both actions once (from ``async_setup``; admins only)."""
    import voluptuous as vol
    from homeassistant.core import ServiceCall, SupportsResponse
    from homeassistant.helpers import config_validation as cv
    from homeassistant.helpers.service import async_register_admin_service

    from .const import SERVICE_TIME_MACHINE_CLEAR, SERVICE_TIME_MACHINE_FORGET_CLIENT

    if hass.services.has_service(DOMAIN, SERVICE_TIME_MACHINE_FORGET_CLIENT):
        return

    async def _forget(call: ServiceCall) -> dict[str, Any]:
        return await async_forget_client(
            hass, call.data.get("mac"), call.data.get("client")
        )

    async def _clear(call: ServiceCall) -> dict[str, Any]:
        return await async_clear_history(hass, call.data["clients_only"])

    async_register_admin_service(
        hass,
        DOMAIN,
        SERVICE_TIME_MACHINE_FORGET_CLIENT,
        _forget,
        # both optional: "exactly one" is answered by async_forget_client
        # with the translated error, never voluptuous' text (review K-c)
        schema=vol.Schema(
            {
                vol.Optional("mac"): vol.All(cv.string, vol.Length(max=64)),
                vol.Optional("client"): vol.All(cv.string, vol.Length(max=64)),
            }
        ),
        supports_response=SupportsResponse.OPTIONAL,
    )
    async_register_admin_service(
        hass,
        DOMAIN,
        SERVICE_TIME_MACHINE_CLEAR,
        _clear,
        schema=vol.Schema({vol.Optional("clients_only", default=False): cv.boolean}),
        supports_response=SupportsResponse.OPTIONAL,
    )


__all__ = [
    "DEBOUNCE_POLLS",
    "GAP_MIN_S",
    "REBASE_S",
    "TICK_S",
    "RouterState",
    "TimeMachine",
    "async_apply_time_machine_options",
    "async_clear_history",
    "async_forget_client",
    "async_get_time_machine",
    "async_purge_clients",
    "async_register_time_machine_services",
    "async_release_time_machine",
    "async_remove_router",
    "async_setup_time_machine",
    "fleet_option",
    "note_ha_start",
]
