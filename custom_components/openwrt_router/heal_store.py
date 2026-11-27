"""Self-Healing (Phase 7), package B: the HA store of the remediation records.

Pattern of the other enterprise stores (``tm_store``, ``core_audit``):
``core_store.create_store`` (versioned, migrate function from day one,
private file, atomic writes) and ``core_store.async_load_store`` (an
unreadable, foreign or newer-major file is kept as ``.bak`` / HA's
``.corrupt.`` copy and the module starts empty; the setup never fails), a
delayed save armed at most once, an explicit flush, and HA's own final
write at shutdown. Developer document: ``docs/self-healing.md`` §2.3-2.5.

Store ``openwrt_router.self_healing`` (version 1.1), data:

* ``saved_at`` (wall time of the write) and ``write_seq`` (counts every
  payload; the write-before-act check reads it back);
* ``settings``: module switch, loop limits, mode and allowlist per router
  (``heal_model.HealSettings``; default: on, every router in Observe,
  no allowlist);
* ``actions``: one record per remediation action (``RemediationAction``);
* ``loop``: the loop-protection state (``heal_model.LoopState``);
* ``maintenance``: interface and service maintenance windows.

**Write before act.** :meth:`SelfHealingStore.async_apply_durable` writes
the new state and reads the file back before it reports success; only then
does the record change in memory. Home Assistant's ``Store.async_save``
does not raise when the disk write fails (it logs ``WriteError`` and
returns) and does not write at all while HA stops, so the read-back is the
only proof. Transitions the table marks ``durable`` (into EXECUTING and
ROLLING_BACK) are refused on the normal path (:meth:`apply`).

**Restart.** At load every record goes through
``heal_model.apply_restart_recovery``: in-flight actions become "unknown,
needs verification" and are never executed again; approvals and
preflights are lost. Locks of writes from outside the engine are dropped
(nothing can still run after a restart); dedupe ids and engine locks are
rebuilt from the records.

**Loss.** A lost, unreadable, newer-major or partly damaged file starts
the affected part empty (settings: the defaults, i.e. Observe) and pauses
Auto-Heal fleet-wide for ``LoopLimits.fleet_pause_s`` (24 h by default):
attempts and breakers are unknown. A damaged file is kept as ``.bak``.

**Limits** (never a non-terminal action is evicted): at most
``MAX_ACTIONS`` records and ``MAX_OPEN_PER_ROUTER`` non-terminal ones per
router (a new action beyond that is refused with :class:`CapacityError`),
terminal records older than ``TERMINAL_RETENTION_S`` are pruned, and the
file stays under ``STORE_MAX_BYTES`` by evicting terminal records oldest
first. A durable write whose payload is still over the limit is refused
(``over_size``: the action does not advance); a delayed write over the
limit with non-terminal records only is written anyway and counted,
because dropping an open action would lose it.

No secrets: the model refuses secret-named keys and key-material values;
the file holds ids, digests, codes, counts and short router-supplied names.
Blocking I/O (the read-back, the backup copy) runs in the executor.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from homeassistant.core import CoreState, HomeAssistant
from homeassistant.helpers.json import prepare_save_json

from . import core_store
from .const import DOMAIN
from .heal_model import (
    LOCKING_STATES,
    TERMINAL_STATES,
    TRANSITIONS,
    ActionState,
    Actor,
    BreakerState,
    ExternalWrite,
    FleetPause,
    HealModelError,
    HealSettings,
    IdempotencyRecord,
    LockHolder,
    LockRecord,
    LoopState,
    MaintenanceWindow,
    RemediationAction,
    apply_restart_recovery,
    transition,
)

_LOGGER = logging.getLogger(__name__)

HEAL_STORE_KEY: Final = f"{DOMAIN}.self_healing"
HEAL_STORE_VERSION: Final = 1
HEAL_STORE_MINOR_VERSION: Final = 1

STORE_MAX_BYTES: Final = 1_000_000
MAX_ACTIONS: Final = 500
MAX_OPEN_PER_ROUTER: Final = 20
TERMINAL_RETENTION_S: Final = 90 * 86400  # like the audit log
IDEMPOTENCY_TTL_S: Final = 86400
IDEMPOTENCY_MAX: Final = 1000
MAINTENANCE_MAX: Final = 100
MAINTENANCE_RETENTION_S: Final = 90 * 86400
ATTEMPTS_RETENTION_S: Final = 7 * 86400
ATTEMPTS_MAX: Final = 1000
BREAKERS_MAX: Final = 1000
SAVE_DELAY_S: Final = 10.0  # design §2.3; durable steps write at once
LOCK_SOURCE_ENGINE: Final = "self_healing"

REASON_STORE_LOST: Final = "store_lost"
REASON_STORE_DAMAGED: Final = "store_damaged"

_STOPPING: Final = (CoreState.stopping, CoreState.final_write, CoreState.stopped)

_COUNTERS: Final = (
    "writes",
    "save_over_size",
    "load_failed",
    "bad_records",
    "evicted_terminal",
    "pruned_terminal",
    "durable_writes",
    "durable_failed",
    "recovered",
)


class HealStoreError(Exception):
    """Base of the store's refusals (message without values)."""


class CapacityError(HealStoreError):
    """No room for one more non-terminal action (nothing was evicted)."""


class UnknownActionError(HealStoreError):
    """No action with that id."""


class WriteAheadRequiredError(HealStoreError):
    """The transition must go through :meth:`SelfHealingStore.async_apply_durable`."""


class RouterLockedError(HealStoreError):
    """Another holder has the router's repair lock."""


class BusyError(HealStoreError):
    """A durable write of this action is in progress."""


def _migrate(old_major: int, old_minor: int, data: Any) -> dict[str, Any]:
    """Version 1.x: additive minors. A newer or foreign major raises, so the
    loader keeps a ``.bak`` copy and the module starts empty."""
    if old_major != HEAL_STORE_VERSION or not isinstance(data, dict):
        raise NotImplementedError(f"self-healing store version {old_major} unknown")
    return dict(data)


def store_bytes(payload: Any) -> int:
    """Bytes of the store file exactly as HA's ``Store`` writes it."""
    wrapped = {
        "version": HEAL_STORE_VERSION,
        "minor_version": HEAL_STORE_MINOR_VERSION,
        "key": HEAL_STORE_KEY,
        "data": payload,
    }
    _mode, data = prepare_save_json(wrapped)
    return len(data.encode("utf-8") if isinstance(data, str) else data)


_EMPTY_ACTIONS_BYTES: Final = store_bytes({"actions": []})


def _record_bytes(action: RemediationAction) -> int:
    """Bytes one record adds to the file (at its nesting depth)."""
    return store_bytes({"actions": [action.to_dict()]}) - _EMPTY_ACTIONS_BYTES


def _read_store_file(path: Any) -> Any:
    """The stored ``data`` of the file at ``path`` (executor; None if
    unreadable). Module-level so tests on fake disks can swap it."""
    if not isinstance(path, str) or not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, ValueError):
        return None
    return raw.get("data") if isinstance(raw, dict) else None


@dataclass(slots=True)
class LoadResult:
    """What the engine needs to know after the load."""

    failed: bool = False  # the file was lost or unreadable: started empty
    fresh: bool = False  # there was no file (first start)
    bad_records: int = 0  # records or parts that did not validate
    # (action id, state found, state after the restart rule)
    recovered: list[tuple[str, ActionState, ActionState]] = field(default_factory=list)
    paused: bool = False  # Auto-Heal paused fleet-wide because of the load


@dataclass(frozen=True, slots=True)
class DurableResult:
    """Outcome of a write-before-act transition.

    ``ok``: the new state is on disk (read back) and in memory; the caller
    may go on. Otherwise ``action`` is the unchanged record and ``reason``
    says why (``not_loaded``, ``stopping``, ``router_locked``,
    ``over_size``, ``write_failed``, ``not_durable``).
    """

    ok: bool
    action: RemediationAction
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class AddResult:
    """Outcome of :meth:`SelfHealingStore.add`."""

    action: RemediationAction
    created: bool  # False: an existing action was returned (deduplicated)
    dedupe: str | None = None  # "idempotency", "action" or "incident"


def _copy_loop(loop: LoopState) -> LoopState:
    """Shallow copy (the records are frozen)."""
    return LoopState(
        attempts=dict(loop.attempts),
        breakers=dict(loop.breakers),
        fleet=loop.fleet,
        incident_dedupe=dict(loop.incident_dedupe),
        action_dedupe=dict(loop.action_dedupe),
        idempotency=dict(loop.idempotency),
        locks=dict(loop.locks),
        external_writes=list(loop.external_writes),
    )


def _engine_lock(action: RemediationAction, since: float) -> LockRecord:
    return LockRecord(
        router_id=action.router_id,
        holder=LockHolder.ENGINE,
        action_id=action.action_id,
        since=since,
        source=LOCK_SOURCE_ENGINE,
    )


def _book(
    loop: LoopState, old: RemediationAction | None, new: RemediationAction
) -> bool:
    """Keep dedupe ids and the router lock in step with ``new``'s state.

    False (nothing changed) when ``new`` needs the router lock and another
    holder has it.
    """
    if new.state in LOCKING_STATES:
        held = loop.locks.get(new.router_id)
        if held is not None and held.action_id != new.action_id:
            return False
        if held is None:
            loop.locks[new.router_id] = _engine_lock(new, new.updated_at)
    else:
        held = loop.locks.get(new.router_id)
        if held is not None and held.action_id == new.action_id:
            del loop.locks[new.router_id]
    if new.state in TERMINAL_STATES:
        for table, dedupe in (
            (loop.action_dedupe, new.action_dedupe),
            (loop.incident_dedupe, new.incident_dedupe),
        ):
            if dedupe is not None and table.get(dedupe) == new.action_id:
                del table[dedupe]
    elif old is None:
        loop.action_dedupe.setdefault(new.action_dedupe, new.action_id)
        if new.incident_dedupe is not None:
            loop.incident_dedupe.setdefault(new.incident_dedupe, new.action_id)
    return True


class SelfHealingStore:
    """Loads, bounds and writes the self-healing state (one per HA instance)."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        clock: Callable[[], float] = time.time,
        max_bytes: int = STORE_MAX_BYTES,
    ) -> None:
        """Nothing opened yet."""
        self.hass = hass
        self.clock = clock
        self.max_bytes = max_bytes
        self.settings = HealSettings()
        self.actions: dict[str, RemediationAction] = {}
        self.loop = LoopState()
        self.maintenance: list[MaintenanceWindow] = []
        self.counters: dict[str, int] = dict.fromkeys(_COUNTERS, 0)
        self.last_bytes: int | None = None
        self.closed = False
        self._store: Any = None
        self._seq = 0
        self._pending = False
        self._last_good: dict[str, Any] | None = None
        self._durable_lock = asyncio.Lock()
        self._busy: set[str] = set()

    # -- load ----------------------------------------------------------------------------

    def _new_store(self) -> Any:
        return core_store.create_store(
            self.hass,
            HEAL_STORE_VERSION,
            HEAL_STORE_KEY,
            minor_version=HEAL_STORE_MINOR_VERSION,
            migrate=_migrate,
            private=True,
            atomic_writes=True,
        )

    async def async_load(self) -> LoadResult:
        """Read the store once, apply the restart rule; never raises."""
        self._store = self._new_store()
        loaded = await core_store.async_load_store(
            self.hass, self._store, HEAL_STORE_KEY
        )
        now = self.clock()
        result = LoadResult()
        if loaded.failed:
            self.counters["load_failed"] += 1
            result.failed = True
            result.paused = self._pause(now, REASON_STORE_LOST)
            await self.async_flush()
            return result
        if loaded.data is None:
            result.fresh = True
            return result
        try:
            bad = self._restore(loaded.data)
        except Exception as err:  # noqa: BLE001 - a damaged file starts empty
            _LOGGER.warning(
                "Self-healing store not restored (%s); starting empty",
                type(err).__name__,
            )
            self.counters["load_failed"] += 1
            self._reset()
            await core_store.async_backup_store(self.hass, self._store, HEAL_STORE_KEY)
            result.failed = True
            result.paused = self._pause(now, REASON_STORE_LOST)
            await self.async_flush()
            return result
        if bad:
            _LOGGER.warning(
                "Self-healing store: %d damaged part(s) skipped; Auto-Heal paused",
                bad,
            )
            result.bad_records = bad
            self.counters["bad_records"] += bad
            await core_store.async_backup_store(self.hass, self._store, HEAL_STORE_KEY)
            result.paused = self._pause(now, REASON_STORE_DAMAGED)
        self._recover(now, result)
        self._rebuild_loop(now)
        if result.recovered or bad:
            await self.async_flush()  # the recovery is on disk at once
        return result

    def _reset(self) -> None:
        self.settings = HealSettings()
        self.actions = {}
        self.loop = LoopState()
        self.maintenance = []

    def _restore(self, data: Mapping[str, Any]) -> int:
        """Fill memory from ``data``; returns the number of damaged parts."""
        bad = 0
        seq = data.get("write_seq")
        if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0:
            self._seq = seq
        try:
            self.settings = HealSettings.from_dict(data.get("settings", {}))
        except HealModelError:
            bad += 1
        raw = data.get("actions")
        if raw is not None and not isinstance(raw, list):
            bad += 1
            raw = []
        for item in raw or []:
            try:
                action = RemediationAction.from_dict(item)
            except HealModelError:
                bad += 1
                continue
            if action.action_id in self.actions:
                bad += 1
                continue
            self.actions[action.action_id] = action
        try:
            self.loop = LoopState.from_dict(data.get("loop", {}))
        except HealModelError:
            bad += 1
        raw = data.get("maintenance")
        if raw is not None and not isinstance(raw, list):
            bad += 1
            raw = []
        for item in raw or []:
            try:
                self.maintenance.append(MaintenanceWindow.from_dict(item))
            except HealModelError:
                bad += 1
        self._last_good = dict(data)
        return bad

    def _recover(self, now: float, result: LoadResult) -> None:
        """The restart rule for every record (actor ``recovery``)."""
        for action_id, action in list(self.actions.items()):
            after = apply_restart_recovery(action, ts=now)
            if after is not action:
                self.actions[action_id] = after
                result.recovered.append((action_id, action.state, after.state))
                self.counters["recovered"] += 1

    def _rebuild_loop(self, now: float) -> None:
        """Locks and dedupe ids as the records say (after the restart rule)."""
        loop = self.loop
        for rid, lock in list(loop.locks.items()):
            owner = self.actions.get(lock.action_id or "")
            if (
                lock.holder is LockHolder.EXTERNAL
                or owner is None
                or owner.router_id != rid
                or owner.state not in LOCKING_STATES
            ):
                del loop.locks[rid]
        ordered = sorted(
            self.actions.values(), key=lambda a: (a.created_at, a.action_id)
        )
        for action in ordered:
            if action.state in LOCKING_STATES and action.router_id not in loop.locks:
                loop.locks[action.router_id] = _engine_lock(action, now)
        for table in (loop.action_dedupe, loop.incident_dedupe):
            for dedupe, action_id in list(table.items()):
                owner = self.actions.get(action_id)
                if owner is None or owner.is_terminal:
                    del table[dedupe]
        for action in ordered:
            if not action.is_terminal:
                loop.action_dedupe.setdefault(action.action_dedupe, action.action_id)
                if action.incident_dedupe is not None:
                    loop.incident_dedupe.setdefault(
                        action.incident_dedupe, action.action_id
                    )

    def _pause(self, now: float, reason: str) -> bool:
        """Pause Auto-Heal fleet-wide (attempts and breakers are unknown)."""
        until = now + self.settings.limits.fleet_pause_s
        fleet = self.loop.fleet
        if fleet.paused_until is None or fleet.paused_until < until:
            self.loop.fleet = FleetPause(
                paused_until=until,
                since=now,
                reason=reason,
                recent_failures=fleet.recent_failures,
            )
        return True

    # -- reading ---------------------------------------------------------------------

    def get(self, action_id: str) -> RemediationAction | None:
        """One record (None if unknown)."""
        return self.actions.get(action_id)

    def open_actions(self, router_id: str | None = None) -> list[RemediationAction]:
        """Non-terminal records (of one router), oldest first."""
        return sorted(
            (
                a
                for a in self.actions.values()
                if not a.is_terminal and (router_id is None or a.router_id == router_id)
            ),
            key=lambda a: (a.created_at, a.action_id),
        )

    def _current(self, action_id: str) -> RemediationAction:
        action = self.actions.get(action_id)
        if action is None:
            raise UnknownActionError("unknown action")
        if action_id in self._busy:
            raise BusyError("durable write in progress")
        return action

    # -- changes in memory (delayed save) ------------------------------------------

    def add(self, action: RemediationAction) -> AddResult:
        """Add a new record (DETECTED), or return the action it duplicates.

        Order of the checks: idempotency id, action dedupe, incident dedupe
        (an existing non-terminal action is returned, nothing is added), then
        the per-router limit of non-terminal actions and the total limit
        (oldest terminal records are evicted; never a non-terminal one).
        """
        if action.state is not ActionState.DETECTED:
            raise HealStoreError("a new action starts in DETECTED")
        if action.action_id in self.actions:
            raise HealStoreError("duplicate action id")
        if action.idempotency_id is not None:
            rec = self.loop.idempotency.get(action.idempotency_id)
            existing = self.actions.get(rec.action_id) if rec is not None else None
            if existing is not None:
                return AddResult(existing, False, "idempotency")
        for table, dedupe, label in (
            (self.loop.action_dedupe, action.action_dedupe, "action"),
            (self.loop.incident_dedupe, action.incident_dedupe, "incident"),
        ):
            existing = self.actions.get(table.get(dedupe or "", ""))
            if existing is not None and not existing.is_terminal:
                return AddResult(existing, False, label)
        if len(self.open_actions(action.router_id)) >= MAX_OPEN_PER_ROUTER:
            raise CapacityError("too many open actions on this router")
        excess = len(self.actions) + 1 - MAX_ACTIONS
        if excess > 0 and self._evict_oldest_terminal(excess) < excess:
            raise CapacityError("no terminal action left to evict")
        self.actions[action.action_id] = action
        _book(self.loop, None, action)
        if action.idempotency_id is not None:
            self.loop.idempotency[action.idempotency_id] = IdempotencyRecord(
                action_id=action.action_id, created_at=action.created_at
            )
            self._cap_idempotency()
        self.schedule()
        return AddResult(action, True)

    def apply(
        self,
        action_id: str,
        to_state: ActionState | str,
        *,
        actor: Actor | str,
        ts: float,
        reason: str,
        changes: Mapping[str, Any] | None = None,
    ) -> RemediationAction:
        """A transition on the normal path (memory now, file after the delay).

        Raises :class:`WriteAheadRequiredError` for a durable transition,
        ``TransitionError`` for an illegal one and :class:`RouterLockedError`
        when the new state needs a router lock another holder has.
        """
        current = self._current(action_id)
        try:
            rule = TRANSITIONS.get((current.state, ActionState(to_state)))
        except ValueError:
            rule = None
        if rule is not None and rule.durable:
            raise WriteAheadRequiredError("use the durable path")
        new = transition(
            current, to_state, actor=actor, ts=ts, reason=reason, changes=changes
        )
        if not _book(self.loop, current, new):
            raise RouterLockedError("router lock held by another holder")
        self.actions[action_id] = new
        self.schedule()
        return new

    def update(self, action_id: str, **changes: Any) -> RemediationAction:
        """Other fields of a record (never state, history or identity)."""
        new = self._current(action_id).with_changes(**changes)
        self.actions[action_id] = new
        self.schedule()
        return new

    # -- write before act ------------------------------------------------------------

    async def async_apply_durable(
        self,
        action_id: str,
        to_state: ActionState | str,
        *,
        actor: Actor | str,
        ts: float,
        reason: str,
        changes: Mapping[str, Any] | None = None,
    ) -> DurableResult:
        """Persist a transition durably BEFORE the caller proceeds.

        Writes the store with the new state at once and reads the file back
        (executor). Only when the read-back shows this write does the record
        change in memory and ``ok`` become True. Any other outcome leaves
        the record as it was and says why; the caller must not call the
        router then. Illegal transitions raise ``TransitionError`` (nothing
        written).
        """
        async with self._durable_lock:
            current = self._current(action_id)
            new = transition(
                current, to_state, actor=actor, ts=ts, reason=reason, changes=changes
            )
            if self._store is None or self.closed:
                return DurableResult(False, current, "not_loaded")
            if getattr(self.hass, "state", None) in _STOPPING:
                return DurableResult(False, current, "stopping")
            loop = _copy_loop(self.loop)
            if not _book(loop, current, new):
                return DurableResult(False, current, "router_locked")
            actions = dict(self.actions)
            actions[action_id] = new
            payload, evicted = self._fit(actions, loop)
            if payload is None:
                self.counters["durable_failed"] += 1
                return DurableResult(False, current, "over_size")
            # reserve the router lock while the write is in flight
            reserved = False
            if new.state in LOCKING_STATES and new.router_id not in self.loop.locks:
                self.loop.locks[new.router_id] = loop.locks[new.router_id]
                reserved = True
            self._busy.add(action_id)
            try:
                reason_failed = await self._async_write_and_verify(payload, new)
            finally:
                self._busy.discard(action_id)
            if reason_failed is not None:
                if reserved:
                    self.loop.locks.pop(new.router_id, None)
                self.counters["durable_failed"] += 1
                self._rearm()
                return DurableResult(False, current, reason_failed)
            self.actions[action_id] = new
            for gone in evicted:
                self.actions.pop(gone, None)
            self.counters["evicted_terminal"] += len(evicted)
            _book(self.loop, current, new)
            self._seq = int(payload["write_seq"])
            self._last_good = payload
            self.counters["durable_writes"] += 1
            self.counters["writes"] += 1
            return DurableResult(True, new)

    async def _async_write_and_verify(
        self, payload: dict[str, Any], new: RemediationAction
    ) -> str | None:
        """Save ``payload`` now and read it back; None on success."""
        # HA's async_save replaces a pending delayed write (its payload holds
        # every change in memory), so a later change must arm a new one.
        self._pending = False
        try:
            await self._store.async_save(payload)
        except Exception as err:  # noqa: BLE001 - reported to the caller
            _LOGGER.warning(
                "Self-healing store: durable write failed (%s)", type(err).__name__
            )
            return "write_failed"
        try:
            stored = await self.hass.async_add_executor_job(
                _read_store_file, getattr(self._store, "path", None)
            )
        except Exception as err:  # noqa: BLE001 - reported to the caller
            _LOGGER.warning(
                "Self-healing store: read-back failed (%s)", type(err).__name__
            )
            return "not_durable"
        expected = json.loads(json.dumps(new.to_dict()))
        if not (
            isinstance(stored, dict)
            and stored.get("write_seq") == payload["write_seq"]
            and any(
                rec == expected
                for rec in stored.get("actions") or []
                if isinstance(rec, dict) and rec.get("action_id") == new.action_id
            )
        ):
            _LOGGER.warning(
                "Self-healing store: the durable write is not on disk; the "
                "action does not proceed"
            )
            return "not_durable"
        return None

    def _rearm(self) -> None:
        """After a failed durable write: the next write is the memory state.

        Home Assistant keeps the payload of a save made while it stops and
        writes it at its final write; re-arming replaces it with the state
        that is really in force (the action did not advance).
        """
        if self._store is None or self.closed:
            return
        self._pending = True
        self._store.async_delay_save(self.payload, 0)

    # -- payload, size and eviction --------------------------------------------------

    def _payload_of(
        self,
        actions: Mapping[str, RemediationAction],
        loop: LoopState,
        seq: int,
    ) -> dict[str, Any]:
        return {
            "saved_at": round(self.clock(), 3),
            "write_seq": seq,
            "settings": self.settings.to_dict(),
            "actions": [
                a.to_dict()
                for a in sorted(
                    actions.values(), key=lambda a: (a.created_at, a.action_id)
                )
            ],
            "loop": loop.to_dict(),
            "maintenance": [w.to_dict() for w in self.maintenance],
        }

    def _fit(
        self, actions: dict[str, RemediationAction], loop: LoopState
    ) -> tuple[dict[str, Any] | None, list[str]]:
        """The payload under ``max_bytes`` by dropping terminal records of
        ``actions`` (a copy), oldest first; None if non-terminal ones alone
        are over the limit."""
        seq = self._seq + 1
        payload = self._payload_of(actions, loop, seq)
        size = store_bytes(payload)
        evicted: list[str] = []
        terminal = sorted(
            (a for a in actions.values() if a.is_terminal),
            key=lambda a: (a.updated_at, a.action_id),
        )
        while size > self.max_bytes and terminal:
            excess = size - self.max_bytes
            while excess > 0 and terminal:
                gone = terminal.pop(0)
                excess -= _record_bytes(gone)
                del actions[gone.action_id]
                evicted.append(gone.action_id)
            payload = self._payload_of(actions, loop, seq)
            size = store_bytes(payload)
        if size > self.max_bytes:
            return None, evicted
        self.last_bytes = size
        return payload, evicted

    def _evict_oldest_terminal(self, count: int) -> int:
        """Drop up to ``count`` terminal records, oldest first."""
        terminal = sorted(
            (a for a in self.actions.values() if a.is_terminal),
            key=lambda a: (a.updated_at, a.action_id),
        )[:count]
        for action in terminal:
            del self.actions[action.action_id]
        self.counters["evicted_terminal"] += len(terminal)
        return len(terminal)

    def payload(self) -> dict[str, Any]:
        """Data of the store (called by HA at write time, in the loop).

        Over the size limit even without terminal records, the payload is
        written anyway (counted): a non-terminal record is never dropped.
        """
        self._pending = False
        actions = dict(self.actions)
        payload, evicted = self._fit(actions, self.loop)
        for gone in evicted:
            self.actions.pop(gone, None)
        self.counters["evicted_terminal"] += len(evicted)
        if payload is None:
            self.counters["save_over_size"] += 1
            _LOGGER.warning(
                "Self-healing store over its size limit with open actions only; "
                "written anyway"
            )
            payload = self._payload_of(self.actions, self.loop, self._seq + 1)
            self.last_bytes = store_bytes(payload)
        self._seq = int(payload["write_seq"])
        self._last_good = payload
        self.counters["writes"] += 1
        return payload

    # -- retention ---------------------------------------------------------------

    def _cap_idempotency(self) -> None:
        extra = len(self.loop.idempotency) - IDEMPOTENCY_MAX
        if extra > 0:
            oldest = sorted(
                self.loop.idempotency.items(), key=lambda kv: (kv[1].created_at, kv[0])
            )[:extra]
            for key, _rec in oldest:
                del self.loop.idempotency[key]

    def prune(self, now: float) -> int:
        """Drop what is past its retention; never a non-terminal record or
        an open breaker. Returns the number of removed entries."""
        removed = 0
        cutoff = now - TERMINAL_RETENTION_S
        for action in list(self.actions.values()):
            if action.is_terminal and action.updated_at < cutoff:
                del self.actions[action.action_id]
                removed += 1
        self.counters["pruned_terminal"] += removed
        loop = self.loop
        for key, rec in list(loop.idempotency.items()):
            if rec.created_at < now - IDEMPOTENCY_TTL_S:
                del loop.idempotency[key]
                removed += 1
        keep = [
            w
            for w in self.maintenance
            if w.end is None or w.end >= now - MAINTENANCE_RETENTION_S
        ]
        removed += len(self.maintenance) - len(keep)
        self.maintenance = keep
        for key, att in list(loop.attempts.items()):
            last = att.last_at or att.window_start or 0.0
            if last < now - ATTEMPTS_RETENTION_S and (
                att.cooldown_until is None or att.cooldown_until < now
            ):
                del loop.attempts[key]
                removed += 1
        extra = len(loop.attempts) - ATTEMPTS_MAX
        if extra > 0:
            for key, _att in sorted(
                loop.attempts.items(), key=lambda kv: (kv[1].last_at or 0.0, kv[0])
            )[:extra]:
                del loop.attempts[key]
                removed += 1
        closed = sorted(
            (
                (key, br)
                for key, br in loop.breakers.items()
                if br.state is BreakerState.CLOSED
            ),
            key=lambda kv: (kv[1].acknowledged_at or kv[1].opened_at or 0.0, kv[0]),
        )
        for key, br in closed:
            stamp = br.acknowledged_at or br.opened_at or 0.0
            if stamp < now - TERMINAL_RETENTION_S or len(loop.breakers) > BREAKERS_MAX:
                del loop.breakers[key]
                removed += 1
        if removed:
            self.schedule()
        return removed

    # -- settings, maintenance, external writes ----------------------------------

    def set_settings(self, settings: HealSettings) -> None:
        """Replace the settings (validated by the model)."""
        if not isinstance(settings, HealSettings):
            raise HealStoreError("settings")
        self.settings = settings
        self.schedule()

    def add_maintenance(self, window: MaintenanceWindow) -> None:
        """Add a maintenance window (bounded)."""
        if any(w.window_id == window.window_id for w in self.maintenance):
            raise HealStoreError("duplicate maintenance window")
        if len(self.maintenance) >= MAINTENANCE_MAX:
            raise CapacityError("too many maintenance windows")
        self.maintenance.append(window)
        self.schedule()

    def remove_maintenance(self, window_id: str) -> bool:
        """Remove a maintenance window."""
        keep = [w for w in self.maintenance if w.window_id != window_id]
        changed = len(keep) != len(self.maintenance)
        self.maintenance = keep
        if changed:
            self.schedule()
        return changed

    def record_external_write(self, write: ExternalWrite) -> None:
        """Remember a router write from outside the engine."""
        self.loop.record_external_write(write)
        self.schedule()

    def try_external_lock(self, router_id: str, source: str, ts: float) -> bool:
        """Take the router lock for a write from outside the engine (False:
        a repair or another external write holds it)."""
        lock = LockRecord(
            router_id=router_id, holder=LockHolder.EXTERNAL, since=ts, source=source
        )
        if not self.loop.try_lock(lock):
            return False
        self.schedule()
        return True

    def release_external_lock(self, router_id: str, source: str) -> bool:
        """Release a lock taken with :meth:`try_external_lock`."""
        held = self.loop.locks.get(router_id)
        if (
            held is None
            or held.holder is not LockHolder.EXTERNAL
            or held.source != source
        ):
            return False
        del self.loop.locks[router_id]
        self.schedule()
        return True

    # -- writes --------------------------------------------------------------------

    def schedule(self, delay: float = SAVE_DELAY_S) -> None:
        """Arm one delayed write (none while one is pending or after close)."""
        if self._store is None or self.closed or (self._pending and delay > 0):
            return
        self._pending = True
        self._store.async_delay_save(self.payload, delay)

    async def async_flush(self) -> None:
        """Write now; never raises."""
        if self._store is None:
            return
        try:
            await self._store.async_save(self.payload())
        except Exception as err:  # noqa: BLE001 - a delayed write tries again
            _LOGGER.warning("Self-healing store not written (%s)", type(err).__name__)
            self.schedule()

    async def async_close(self) -> None:
        """Last write (module off or unload); no write is armed afterwards."""
        await self.async_flush()
        self.closed = True

    def stats(self) -> dict[str, Any]:
        """Sizes and counters (no ids)."""
        return {
            "bytes": self.last_bytes,
            "max_bytes": self.max_bytes,
            "actions": len(self.actions),
            "open": sum(1 for a in self.actions.values() if not a.is_terminal),
            "locks": len(self.loop.locks),
            "fleet_paused": self.loop.fleet.paused(self.clock()),
            **self.counters,
        }


__all__ = [
    "HEAL_STORE_KEY",
    "HEAL_STORE_MINOR_VERSION",
    "HEAL_STORE_VERSION",
    "MAX_ACTIONS",
    "MAX_OPEN_PER_ROUTER",
    "STORE_MAX_BYTES",
    "TERMINAL_RETENTION_S",
    "AddResult",
    "BusyError",
    "CapacityError",
    "DurableResult",
    "HealStoreError",
    "LoadResult",
    "RouterLockedError",
    "SelfHealingStore",
    "UnknownActionError",
    "WriteAheadRequiredError",
    "store_bytes",
]
