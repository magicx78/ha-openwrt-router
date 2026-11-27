"""Self-Healing (Phase 7), package B: the HA store of the remediation records.

Pattern of the other enterprise stores (``tm_store``, ``core_audit``):
``core_store.create_store`` (versioned, migrate function from day one,
private file, atomic writes) and ``core_store.async_load_store`` (an
unreadable, foreign or newer-major file is kept as ``.bak`` / HA's
``.corrupt.`` copy and the module starts empty; the setup never fails), a
delayed save armed at most once, an explicit flush, and HA's own final
write at shutdown. Developer document: ``docs/self-healing.md`` §5.

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
ROLLING_BACK) are refused on the normal path (:meth:`apply`). One durable
step runs at a time; flush and close wait for it, and every payload
written while it is in flight (a delayed write, HA's final write) carries
the in-flight record, so no later write can put the old state back. After
:meth:`async_close` no durable step reports success. The durable step into
EXECUTING also enforces the loop guards (hold, open breaker, cooldown,
attempts in 24 h) and books the attempt in the same write.

**Restart.** At load every record goes through
``heal_model.apply_restart_recovery``: in-flight actions become "unknown,
needs verification" and are never executed again; approvals and
preflights are lost. Locks of writes from outside the engine are dropped
(nothing can still run after a restart); dedupe ids, engine locks, terminal
stamps and the holds that terminal records place (unless an admin released
them, ``flags.hold_released``) are rebuilt from the records.

**Holds** (docs §5.1). An action that ran a call and ended with an unknown
outcome or escalated holds its router until an admin releases it; an
unreadable record holds its router (or, if its router id is unreadable,
the fleet) for ``UNREADABLE_HOLD_S``, or until an admin releases it when its
raw state or history still shows EXECUTING, VERIFYING or ROLLING_BACK; a
lost store holds the fleet for ``STORE_LOST_HOLD_S``.
A held router is in Observe: no approval, no Auto-Heal, no write of Risk 1
or more (:class:`RouterHeldError`); read-only diagnostics still run.

**Loss.** A lost, unreadable, newer-major or partly damaged file starts
the affected part empty (settings: the defaults, i.e. Observe), holds as
above, and pauses Auto-Heal fleet-wide for ``LoopLimits.fleet_pause_s``
(24 h by default): attempts and breakers are unknown. A damaged file is
kept as ``.bak``.

**Time.** Waits run on the safety clock (``heal_model.SafetyClock``,
:meth:`SelfHealingStore.now`). While this instance runs it follows the
monotonic clock, so no wall-clock change shortens a cooldown, a hold, a
pause or the life of an attempt counter; after a start it counts wall time
only beyond the highest wall time ever seen, at most one step (900 s).
Terminal records are kept from the safety time they ended
(``loop.terminal_at``), never by their wall stamps.

**Limits** (never a non-terminal action is evicted): at most
``MAX_ACTIONS`` records and ``MAX_OPEN_PER_ROUTER`` non-terminal ones per
router (a new action beyond that is refused with :class:`CapacityError`),
terminal records older than ``TERMINAL_RETENTION_S`` are pruned, and the
file stays under ``STORE_MAX_BYTES`` by evicting terminal records oldest
first. If the non-terminal records alone are over the limit, nothing is
evicted (it would not help): a durable write is refused (``over_size``:
the action does not advance) and a delayed write is written anyway and
counted, because dropping an open action would lose it. The size is an
upper-bound estimate from cached record sizes, not a second serialisation.

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
from dataclasses import dataclass, field, replace
from typing import Any, Final

from homeassistant.core import CoreState, HomeAssistant
from homeassistant.helpers.json import prepare_save_json

from . import core_store
from .const import DOMAIN
from .core_models import ROUTER_ID_PREFIX, is_valid_id
from .heal_model import (
    BACKOFF_STEP_MAX,
    FLEET_HOLD_KEY,
    IN_FLIGHT_STATES,
    LOCK_SOURCE_ENGINE,
    LOCKING_STATES,
    TERMINAL_STATES,
    TRANSITIONS,
    ActionState,
    Actor,
    AttemptRecord,
    BreakerState,
    ExternalWrite,
    FleetPause,
    HealMode,
    HealModelError,
    HealSettings,
    HoldReason,
    IdempotencyRecord,
    LockHolder,
    LockRecord,
    LoopKey,
    LoopState,
    MaintenanceWindow,
    RemediationAction,
    RiskClass,
    RollbackStatus,
    RouterHold,
    apply_restart_recovery,
    hold_reason_for,
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
ATTEMPT_WINDOW_S: Final = 86400  # attempts are counted per 24 h
UNREADABLE_HOLD_S: Final = 86400  # coordinator decision (review of PR #75)
STORE_LOST_HOLD_S: Final = 86400

REASON_STORE_LOST: Final = "store_lost"
REASON_STORE_DAMAGED: Final = "store_damaged"

# Entering these is a step towards a write; refused on a held router for an
# action of Risk 1 or more (read-only diagnostics still run).
HOLD_BLOCKED_STATES: Final = frozenset(
    {
        ActionState.WAITING_APPROVAL,
        ActionState.APPROVED,
        ActionState.EXECUTING,
        ActionState.ROLLBACK_PENDING,
        ActionState.ROLLING_BACK,
    }
)
# Size estimate: bytes allowed per record for the separators between them.
_SEPARATOR_BYTES: Final = 2

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


class RouterHeldError(HealStoreError):
    """The router (or the fleet) is held: no step towards a write."""


class IdempotencyExpiredError(HealStoreError):
    """The idempotency id is known but its action is gone (evicted or
    pruned): the request is refused, never turned into a new action."""


class NotAdminError(HealStoreError):
    """Only an admin may do this."""


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
# ``saved_at`` is read again for the real payload (a few more digits)
_SAVED_AT_SLACK: Final = 16


def _in_window(att: AttemptRecord, safe: float) -> bool:
    """The attempt record's 24 h window is still open at ``safe``."""
    return att.window_start is not None and safe < att.window_start + ATTEMPT_WINDOW_S


_IN_FLIGHT_NAMES: Final = frozenset(state.value for state in IN_FLIGHT_STATES)


def _shows_in_flight(item: Any) -> bool:
    """A damaged raw record whose state or history still says it reached
    EXECUTING, VERIFYING or ROLLING_BACK (a router call may have run)."""
    if not isinstance(item, Mapping):
        return False
    state = item.get("state")
    if isinstance(state, str) and state in _IN_FLIGHT_NAMES:
        return True
    history = item.get("history")
    if not isinstance(history, list):
        return False
    for entry in history:
        to_state = entry.get("to_state") if isinstance(entry, Mapping) else None
        if isinstance(to_state, str) and to_state in _IN_FLIGHT_NAMES:
            return True
    return False


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
    says why (``not_loaded``, ``closed``, ``stopping``, ``router_held``,
    ``breaker_open``, ``cooling_down``, ``max_attempts``,
    ``router_locked``, ``over_size``, ``write_failed``, ``not_durable``).
    """

    ok: bool
    action: RemediationAction
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class AddResult:
    """Outcome of :meth:`SelfHealingStore.add`."""

    action: RemediationAction
    created: bool  # False: an existing action was returned (deduplicated)
    # "idempotency", "action", "incident" or "component"
    dedupe: str | None = None


def _copy_loop(loop: LoopState) -> LoopState:
    """Shallow copy (the records are frozen)."""
    return LoopState(
        attempts=dict(loop.attempts),
        breakers=dict(loop.breakers),
        fleet=loop.fleet,
        incident_dedupe=dict(loop.incident_dedupe),
        action_dedupe=dict(loop.action_dedupe),
        component_dedupe=dict(loop.component_dedupe),
        idempotency=dict(loop.idempotency),
        locks=dict(loop.locks),
        holds=dict(loop.holds),
        clock=loop.clock,
        terminal_at=dict(loop.terminal_at),
        external_writes=list(loop.external_writes),
    )


def _dedupes(
    loop: LoopState, action: RemediationAction
) -> list[tuple[dict[str, str], str, str]]:
    """(table, dedupe id, label) of every dedupe id of ``action``."""
    out = [(loop.action_dedupe, action.action_dedupe, "action")]
    if action.incident_dedupe is not None:
        out.append((loop.incident_dedupe, action.incident_dedupe, "incident"))
    out.extend(
        (loop.component_dedupe, dedupe, "component")
        for dedupe in action.component_dedupes
    )
    return out


def _book(
    loop: LoopState,
    old: RemediationAction | None,
    new: RemediationAction,
    safe_now: float,
) -> bool:
    """Keep dedupe ids, the router lock, holds and the terminal stamp in
    step with ``new``.

    False (nothing changed) when ``new`` needs the router lock and another
    holder has it. A terminal outcome that leaves the router in an unknown
    or escalated state holds it (``heal_model.hold_reason_for``). Entering
    a terminal state stamps the safety-clock time (``loop.terminal_at``):
    the record's retention runs from there.
    """
    if new.state in LOCKING_STATES:
        held = loop.locks.get(new.router_id)
        if held is not None and held.action_id != new.action_id:
            return False
        if held is None:
            loop.locks[new.router_id] = LockRecord.engine(new, new.updated_at)
    else:
        held = loop.locks.get(new.router_id)
        if held is not None and held.action_id == new.action_id:
            del loop.locks[new.router_id]
    if new.state in TERMINAL_STATES:
        if old is None or not old.is_terminal:
            loop.terminal_at.setdefault(new.action_id, safe_now)
        for table, dedupe, _label in _dedupes(loop, new):
            if table.get(dedupe) == new.action_id:
                del table[dedupe]
        reason = hold_reason_for(new)
        if reason is not None and (old is None or old.state is not new.state):
            loop.place_hold(
                RouterHold(
                    router_id=new.router_id,
                    reason=reason,
                    since=safe_now,
                    action_id=new.action_id,
                )
            )
    elif old is None:
        for table, dedupe, _label in _dedupes(loop, new):
            table.setdefault(dedupe, new.action_id)
    return True


class SelfHealingStore:
    """Loads, bounds and writes the self-healing state (one per HA instance)."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] | None = time.monotonic,
        max_bytes: int = STORE_MAX_BYTES,
    ) -> None:
        """Nothing opened yet.

        ``clock``: the wall clock; ``monotonic``: a clock that never jumps
        (seconds), used for the safety clock while this instance runs
        (None: the wall clock's high-water mark only, docs §5.2).
        """
        self.hass = hass
        self.clock = clock
        self.monotonic = monotonic
        self._mono_last: float | None = None
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
        # (record, evicted ids, attempts) of the durable step in flight: every
        # payload built meanwhile carries it (no write puts the old state back)
        self._inflight: (
            tuple[RemediationAction, list[str], dict[LoopKey, AttemptRecord]] | None
        ) = None
        # action id -> (record, its bytes in the file): the size estimate
        self._sizes: dict[str, tuple[RemediationAction, int]] = {}

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
        self._mono_last = None  # the first observation of a run: wall time
        loaded = await core_store.async_load_store(
            self.hass, self._store, HEAL_STORE_KEY
        )
        result = LoadResult()
        if loaded.failed:
            self.counters["load_failed"] += 1
            result.failed = True
            self._lost(result)
            await self.async_flush()
            return result
        if loaded.data is None:
            result.fresh = True
            self.now()
            return result
        try:
            bad, timed, no_end = self._restore(loaded.data)
        except Exception as err:  # noqa: BLE001 - a damaged file starts empty
            _LOGGER.warning(
                "Self-healing store not restored (%s); starting empty",
                type(err).__name__,
            )
            self.counters["load_failed"] += 1
            self._reset()
            await core_store.async_backup_store(self.hass, self._store, HEAL_STORE_KEY)
            result.failed = True
            self._lost(result)
            await self.async_flush()
            return result
        wall = self.clock()
        safe = self.now()
        if bad:
            _LOGGER.warning(
                "Self-healing store: %d damaged part(s) skipped; Auto-Heal paused, "
                "affected routers held",
                bad,
            )
            result.bad_records = bad
            self.counters["bad_records"] += bad
            await core_store.async_backup_store(self.hass, self._store, HEAL_STORE_KEY)
            result.paused = self._pause(safe, REASON_STORE_DAMAGED)
            for router_id in sorted(timed, key=lambda r: r or ""):
                self._hold_for(router_id, HoldReason.RECORD_UNREADABLE, safe)
            for router_id in sorted(no_end, key=lambda r: r or ""):
                self._hold_for(
                    router_id, HoldReason.RECORD_UNREADABLE, safe, no_end=True
                )
        self._recover(wall, result)
        self._rebuild_loop(wall, safe)
        if result.recovered or bad:
            await self.async_flush()  # the recovery is on disk at once
        return result

    def _lost(self, result: LoadResult) -> None:
        """The store is lost: pause Auto-Heal and hold the fleet."""
        safe = self.now()
        result.paused = self._pause(safe, REASON_STORE_LOST)
        self._hold_for(None, HoldReason.STORE_LOST, safe)

    def _hold_for(
        self,
        router_id: str | None,
        reason: HoldReason,
        safe: float,
        *,
        no_end: bool = False,
    ) -> RouterHold:
        """Hold a router (None: the fleet) for the fixed load-damage time,
        or until an admin releases it (``no_end``)."""
        hold_s = (
            STORE_LOST_HOLD_S if reason is HoldReason.STORE_LOST else UNREADABLE_HOLD_S
        )
        return self.loop.place_hold(
            RouterHold(
                router_id=router_id,
                reason=reason,
                since=safe,
                until=None if no_end else safe + hold_s,
            )
        )

    def _reset(self) -> None:
        self.settings = HealSettings()
        self.actions = {}
        self.loop = LoopState()
        self.maintenance = []
        self._sizes = {}

    def _restore(
        self, data: Mapping[str, Any]
    ) -> tuple[int, set[str | None], set[str | None]]:
        """Fill memory from ``data``.

        Returns the number of damaged parts and two sets of hold keys
        (router id; None: the fleet, for an unreadable router id or a
        damaged loop state): held for ``UNREADABLE_HOLD_S``, and held until
        an admin releases them (the damaged record still shows that it
        reached EXECUTING, VERIFYING or ROLLING_BACK).
        """
        bad = 0
        timed: set[str | None] = set()
        no_end: set[str | None] = set()

        def damaged(item: Any) -> None:
            nonlocal bad
            bad += 1
            rid = item.get("router_id") if isinstance(item, Mapping) else None
            key = str(rid) if is_valid_id(rid, ROUTER_ID_PREFIX) else None
            (no_end if _shows_in_flight(item) else timed).add(key)

        seq = data.get("write_seq")
        if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0:
            self._seq = seq
        try:
            self.settings = HealSettings.from_dict(data.get("settings", {}))
        except HealModelError:
            bad += 1
        raw = data.get("actions")
        if raw is not None and not isinstance(raw, list):
            damaged(None)
            raw = []
        for item in raw or []:
            try:
                action = RemediationAction.from_dict(item)
            except HealModelError:
                damaged(item)
                continue
            if action.action_id in self.actions:
                damaged(item)
                continue
            self.actions[action.action_id] = action
        try:
            self.loop = LoopState.from_dict(data.get("loop", {}))
        except HealModelError:
            damaged(None)
        raw = data.get("maintenance")
        if raw is not None and not isinstance(raw, list):
            damaged(None)
            raw = []
        for item in raw or []:
            try:
                self.maintenance.append(MaintenanceWindow.from_dict(item))
            except HealModelError:
                damaged(item)
        self._last_good = dict(data)
        return bad, timed, no_end

    def _recover(self, wall: float, result: LoadResult) -> None:
        """The restart rule for every record (actor ``recovery``); the holds
        an outcome it makes final places come from :meth:`_rebuild_loop`."""
        for action_id, action in list(self.actions.items()):
            after = apply_restart_recovery(action, ts=wall)
            if after is not action:
                self.actions[action_id] = after
                result.recovered.append((action_id, action.state, after.state))
                self.counters["recovered"] += 1

    def _rebuild_loop(self, now: float, safe: float) -> None:
        """Locks, dedupe ids, terminal stamps and record holds as the
        records say (after the restart rule).

        Every terminal record whose end holds its router
        (``hold_reason_for``) and whose hold no admin released places its
        hold again, with no end: a hold lost with a damaged loop section
        comes back as it was, not as a 24 h hold. A terminal record without
        a stamp gets the current safety time (kept longer, never shorter).
        """
        loop = self.loop
        for action_id in list(loop.terminal_at):
            owner = self.actions.get(action_id)
            if owner is None or not owner.is_terminal:
                del loop.terminal_at[action_id]
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
                loop.locks[action.router_id] = LockRecord.engine(action, now)
        for table in (loop.action_dedupe, loop.incident_dedupe, loop.component_dedupe):
            for dedupe, action_id in list(table.items()):
                owner = self.actions.get(action_id)
                if owner is None or owner.is_terminal:
                    del table[dedupe]
        for action in ordered:
            if not action.is_terminal:
                for table, dedupe, _label in _dedupes(loop, action):
                    table.setdefault(dedupe, action.action_id)
                continue
            loop.terminal_at.setdefault(action.action_id, safe)
            reason = hold_reason_for(action)
            if reason is not None and not action.flags.hold_released:
                loop.place_hold(
                    RouterHold(
                        router_id=action.router_id,
                        reason=reason,
                        since=safe,
                        action_id=action.action_id,
                    )
                )

    def _pause(self, now: float, reason: str) -> bool:
        """Pause Auto-Heal fleet-wide (attempts and breakers are unknown).

        ``now`` is safety-clock time."""
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

    def now(self) -> float:
        """Safety-clock time after observing the wall clock (docs §5.2).

        Every wait of the loop protection compares with this value. The
        engine calls it (or any store method that reads time) at least
        every few minutes. While this instance runs the step is the
        monotonic time since the previous observation (capped); the first
        observation after the load uses the wall clock's high-water mark.
        """
        return self._observe(self.clock())

    def _observe(self, wall: float) -> float:
        """Observe ``wall`` (and the monotonic clock); the safety time."""
        elapsed: float | None = None
        if self.monotonic is not None:
            mono = float(self.monotonic())
            if self._mono_last is not None:
                elapsed = max(0.0, mono - self._mono_last)
            self._mono_last = mono
        self.loop.clock = self.loop.clock.observe(wall, elapsed)
        return float(self.loop.clock.safe or 0.0)

    def router_hold(self, router_id: str) -> RouterHold | None:
        """The active hold on a router (its own, else the fleet's)."""
        return self.loop.hold_on(router_id, self.now())

    def effective_mode(self, router_id: str) -> HealMode:
        """The mode in force: Observe while held or with the module off;
        Approval instead of Auto-Heal while Auto-Heal is paused."""
        if not self.settings.enabled or self.router_hold(router_id) is not None:
            return HealMode.OBSERVE
        mode = self.settings.router(router_id).mode
        if mode is HealMode.AUTO_HEAL and self.loop.fleet.paused(self.now()):
            return HealMode.APPROVAL
        return mode

    def _held(self, action: RemediationAction, to_state: ActionState) -> bool:
        """``action`` may not enter ``to_state`` because its router is held."""
        return (
            to_state in HOLD_BLOCKED_STATES
            and action.risk.risk_class > RiskClass.READ_ONLY
            and self.router_hold(action.router_id) is not None
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

        Order of the checks: idempotency id (its action is returned; a
        known id whose action is gone raises
        :class:`IdempotencyExpiredError`), then the action dedupe (router,
        type, params), the root incident (fleet-wide) and every (router,
        component) of the action: an existing non-terminal action is
        returned and nothing is added. Then the per-router limit of
        non-terminal actions and the total limit (oldest terminal records
        are evicted; never a non-terminal one).
        """
        if action.state is not ActionState.DETECTED:
            raise HealStoreError("a new action starts in DETECTED")
        if not action.is_new:
            # built with the constructor or from_dict: only the loader may
            # bring such a record (flags, approval, execution, history)
            raise HealStoreError("not a new record (use RemediationAction.new)")
        if action.action_id in self.actions:
            raise HealStoreError("duplicate action id")
        safe = self.now()
        if action.idempotency_id is not None:
            rec = self.loop.idempotency.get(action.idempotency_id)
            if rec is not None:
                existing = self.actions.get(rec.action_id)
                if existing is None:
                    raise IdempotencyExpiredError("idempotency id of a removed action")
                return AddResult(existing, False, "idempotency")
        for table, dedupe, label in _dedupes(self.loop, action):
            existing = self.actions.get(table.get(dedupe, ""))
            if existing is not None and not existing.is_terminal:
                return AddResult(existing, False, label)
        if len(self.open_actions(action.router_id)) >= MAX_OPEN_PER_ROUTER:
            raise CapacityError("too many open actions on this router")
        excess = len(self.actions) + 1 - MAX_ACTIONS
        if excess > 0 and self._evict_oldest_terminal(excess) < excess:
            raise CapacityError("no terminal action left to evict")
        self.actions[action.action_id] = action
        _book(self.loop, None, action, safe)
        if action.idempotency_id is not None:
            self.loop.idempotency[action.idempotency_id] = IdempotencyRecord(
                action_id=action.action_id, created_at=safe
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
        ``TransitionError`` for an illegal one, :class:`RouterHeldError`
        for a step towards a write (Risk 1 or more) on a held router and
        :class:`RouterLockedError` when the new state needs a router lock
        another holder has.
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
        if self._held(current, new.state):
            raise RouterHeldError("router held")
        if not _book(self.loop, current, new, self.now()):
            raise RouterLockedError("router lock held by another holder")
        self.actions[action_id] = new
        self.schedule()
        return new

    def update(self, action_id: str, **changes: Any) -> RemediationAction:
        """Other fields of a record, by the model's field rules
        (``RemediationAction.with_changes``)."""
        new = self._current(action_id).with_changes(**changes)
        self.actions[action_id] = new
        self.schedule()
        return new

    def update_flags(self, action_id: str, **flags: Any) -> RemediationAction:
        """``in_maintenance`` / ``acknowledged_by_admin`` of a record
        (``RemediationAction.with_flags``; never ``interrupted``, and
        ``hold_released`` only through :meth:`release_hold`)."""
        if "hold_released" in flags:
            raise HealStoreError("hold_released is set by release_hold only")
        new = self._current(action_id).with_flags(**flags)
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

        One durable step at a time (flush and close wait for it). The write
        sequence number is reserved before the write, and while the step is
        in flight every payload (a delayed write, HA's final write) carries
        the new record, so the read-back accepts this or any later write
        that holds it. Into EXECUTING the loop guards apply (hold, open
        breaker, cooldown, attempts in 24 h) and the attempt is booked in
        the same write (``execution.attempt_no``).
        """
        async with self._durable_lock:
            current = self._current(action_id)
            new = transition(
                current, to_state, actor=actor, ts=ts, reason=reason, changes=changes
            )
            if self._store is None:
                return DurableResult(False, current, "not_loaded")
            if self.closed:
                return DurableResult(False, current, "closed")
            if getattr(self.hass, "state", None) in _STOPPING:
                return DurableResult(False, current, "stopping")
            safe = self.now()
            if self._held(current, new.state):
                return DurableResult(False, current, "router_held")
            loop = _copy_loop(self.loop)
            attempts: dict[LoopKey, AttemptRecord] = {}
            if new.state is ActionState.EXECUTING:
                refused = self._attempt_refusal(new, safe)
                if refused is not None:
                    return DurableResult(False, current, refused)
                attempts, attempt_no = self._next_attempts(new, safe)
                loop.attempts.update(attempts)
                new = transition(
                    current,
                    to_state,
                    actor=actor,
                    ts=ts,
                    reason=reason,
                    changes={
                        **(changes or {}),
                        "execution": replace(new.execution, attempt_no=attempt_no),
                    },
                )
            if not _book(loop, current, new, safe):
                return DurableResult(False, current, "router_locked")
            actions = dict(self.actions)
            actions[action_id] = new
            seq = self._seq + 1
            self._seq = seq  # reserved: a payload built meanwhile counts on
            payload, evicted, over = self._fit(actions, loop, seq)
            if over:
                self.counters["durable_failed"] += 1
                return DurableResult(False, current, "over_size")
            # reserve the router lock while the write is in flight
            reserved = False
            if new.state in LOCKING_STATES and new.router_id not in self.loop.locks:
                self.loop.locks[new.router_id] = loop.locks[new.router_id]
                reserved = True
            self._busy.add(action_id)
            self._inflight = (new, evicted, attempts)
            try:
                reason_failed = await self._async_write_and_verify(payload, new, seq)
            finally:
                self._busy.discard(action_id)
                self._inflight = None
            if reason_failed is not None:
                if reserved:
                    self.loop.locks.pop(new.router_id, None)
                self.counters["durable_failed"] += 1
                self._rearm()
                return DurableResult(False, current, reason_failed)
            self.actions[action_id] = new
            for gone in evicted:
                self._forget(gone)
            self.counters["evicted_terminal"] += len(evicted)
            self.loop.attempts.update(attempts)
            _book(self.loop, current, new, safe)
            self._last_good = payload
            self.counters["durable_writes"] += 1
            self.counters["writes"] += 1
            return DurableResult(True, new)

    def _attempt_refusal(self, action: RemediationAction, safe: float) -> str | None:
        """Why the loop protection refuses running ``action`` now (or None)."""
        limits = self.settings.limits
        keys = action.loop_keys
        for key in keys:
            breaker = self.loop.breakers.get(key)
            if breaker is not None and breaker.state is BreakerState.OPEN:
                return "breaker_open"
        for key in keys:
            att = self.loop.attempts.get(key)
            if (
                att is not None
                and att.cooldown_until is not None
                and safe < att.cooldown_until
            ):
                return "cooling_down"
        for key in keys:
            att = self.loop.attempts.get(key)
            if (
                att is not None
                and _in_window(att, safe)
                and att.count >= limits.max_attempts_24h
            ):
                return "max_attempts"
        return None

    def _next_attempts(
        self, action: RemediationAction, safe: float
    ) -> tuple[dict[LoopKey, AttemptRecord], int]:
        """The attempt records after one more attempt of ``action``, and its
        attempt number (cooldown: the longer of the cooldown and the
        exponential backoff, capped)."""
        limits = self.settings.limits
        out: dict[LoopKey, AttemptRecord] = {}
        number = 1
        for key in action.loop_keys:
            att = self.loop.attempts.get(key) or AttemptRecord()
            fresh = not _in_window(att, safe)
            count = 1 if fresh else min(att.count + 1, 1000)
            step = min(count - 1, BACKOFF_STEP_MAX)
            backoff = min(limits.backoff_base_s * 2**step, limits.backoff_cap_s)
            out[key] = AttemptRecord(
                count=count,
                window_start=safe if fresh else att.window_start,
                last_at=safe,
                cooldown_until=safe + max(limits.cooldown_s, backoff),
                backoff_step=step,
                last_result=att.last_result,
            )
            number = max(number, count)
        return out, min(number, 100)

    async def _async_write_and_verify(
        self, payload: dict[str, Any], new: RemediationAction, seq: int
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
        stored_seq = stored.get("write_seq") if isinstance(stored, dict) else None
        if not (
            isinstance(stored, dict)
            and isinstance(stored_seq, int)
            and not isinstance(stored_seq, bool)
            and stored_seq >= seq
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

    def _size_of(self, action: RemediationAction) -> int:
        """Bytes of one record in the file (cached per record object)."""
        cached = self._sizes.get(action.action_id)
        if cached is not None and cached[0] is action:
            return cached[1]
        size = _record_bytes(action) + _SEPARATOR_BYTES
        self._sizes[action.action_id] = (action, size)
        return size

    def _fit(
        self, actions: dict[str, RemediationAction], loop: LoopState, seq: int
    ) -> tuple[dict[str, Any], list[str], bool]:
        """The payload of ``actions`` (a copy) and ``loop``, kept under
        ``max_bytes`` by dropping terminal records of ``actions`` oldest
        first, and whether it is still over the limit.

        The size is estimated from the cached record sizes (an upper bound:
        each record is measured at its depth in the file, with room for its
        separator); only the part outside the records is serialised. If the
        non-terminal records alone are over the limit nothing is dropped,
        because dropping could not bring the file under it.
        """
        base = store_bytes(self._payload_of({}, loop, seq)) + _SAVED_AT_SLACK
        sizes = {aid: self._size_of(a) for aid, a in actions.items()}
        total = base + sum(sizes.values())
        evicted: list[str] = []
        if total > self.max_bytes:
            open_total = base + sum(
                size for aid, size in sizes.items() if not actions[aid].is_terminal
            )
            if open_total <= self.max_bytes:
                for gone in sorted(
                    (a for a in actions.values() if a.is_terminal),
                    key=lambda a: (a.updated_at, a.action_id),
                ):
                    if total <= self.max_bytes:
                        break
                    total -= sizes[gone.action_id]
                    del actions[gone.action_id]
                    evicted.append(gone.action_id)
        if len(self._sizes) > 2 * MAX_ACTIONS:
            self._sizes = {k: v for k, v in self._sizes.items() if k in self.actions}
        self.last_bytes = total
        return self._payload_of(actions, loop, seq), evicted, total > self.max_bytes

    def _evict_oldest_terminal(self, count: int) -> int:
        """Drop up to ``count`` terminal records, oldest first."""
        terminal = sorted(
            (a for a in self.actions.values() if a.is_terminal),
            key=lambda a: (a.updated_at, a.action_id),
        )[:count]
        for action in terminal:
            self._forget(action.action_id)
        self.counters["evicted_terminal"] += len(terminal)
        return len(terminal)

    def _forget(self, action_id: str) -> None:
        """Drop a record with its size and terminal stamp."""
        self.actions.pop(action_id, None)
        self._sizes.pop(action_id, None)
        self.loop.terminal_at.pop(action_id, None)

    def _view(self) -> tuple[dict[str, RemediationAction], LoopState]:
        """Records and loop state to write now: memory, plus the durable step
        in flight (its record, evictions and attempts; its lock is already
        reserved in memory)."""
        actions = dict(self.actions)
        if self._inflight is None:
            return actions, self.loop
        new, evicted, attempts = self._inflight
        for gone in evicted:
            actions.pop(gone, None)
        actions[new.action_id] = new
        loop = _copy_loop(self.loop)
        loop.attempts.update(attempts)
        return actions, loop

    def payload(self) -> dict[str, Any]:
        """Data of the store (called by HA at write time, in the loop).

        Carries a durable step in flight. Over the size limit with the
        non-terminal records alone, nothing is evicted and the payload is
        written anyway (counted): a non-terminal record is never dropped.
        """
        self._pending = False
        self.now()
        actions, loop = self._view()
        seq = self._seq + 1
        payload, evicted, over = self._fit(actions, loop, seq)
        for gone in evicted:
            self._forget(gone)
        self.counters["evicted_terminal"] += len(evicted)
        if over:
            self.counters["save_over_size"] += 1
            _LOGGER.warning(
                "Self-healing store over its size limit with open actions only; "
                "written anyway"
            )
        self._seq = seq
        self._last_good = payload
        self.counters["writes"] += 1
        return payload

    # -- retention ---------------------------------------------------------------

    def _idempotency_open(self, rec: IdempotencyRecord) -> bool:
        action = self.actions.get(rec.action_id)
        return action is not None and not action.is_terminal

    def _cap_idempotency(self) -> None:
        """At most ``IDEMPOTENCY_MAX`` ids; never one of an open action."""
        extra = len(self.loop.idempotency) - IDEMPOTENCY_MAX
        if extra > 0:
            oldest = sorted(
                (
                    (key, rec)
                    for key, rec in self.loop.idempotency.items()
                    if not self._idempotency_open(rec)
                ),
                key=lambda kv: (kv[1].created_at, kv[0]),
            )[:extra]
            for key, _rec in oldest:
                del self.loop.idempotency[key]

    def prune(self, now: float | None = None) -> int:
        """Drop what is past its retention. Returns the number removed.

        ``now`` (wall time, default the store's clock) is observed by the
        safety clock first and every limit compares with safety-clock time,
        so a jump ahead cannot age anything out: a terminal record is kept
        ``TERMINAL_RETENTION_S`` of safety time from the safety time it
        became terminal (``loop.terminal_at``), never from its wall stamps.
        A maintenance window (wall times set by an admin) goes only when
        both the wall and the safety clock are past its retention. Never
        dropped: a non-terminal record, the idempotency id of an open
        action, an attempt record in its 24 h window or cooldown, an open
        breaker, a hold in force.
        """
        wall = self.clock() if now is None else now
        safe = self._observe(wall)
        removed = 0
        cutoff = safe - TERMINAL_RETENTION_S
        for action in list(self.actions.values()):
            if not action.is_terminal:
                continue
            ended = self.loop.terminal_at.get(action.action_id)
            if ended is None:  # not stamped yet: its retention starts now
                self.loop.terminal_at[action.action_id] = safe
            elif ended < cutoff:
                self._forget(action.action_id)
                removed += 1
        self.counters["pruned_terminal"] += removed
        loop = self.loop
        for key, rec in list(loop.idempotency.items()):
            if rec.created_at < safe - IDEMPOTENCY_TTL_S and not self._idempotency_open(
                rec
            ):
                del loop.idempotency[key]
                removed += 1
        window_cutoff = min(float(wall), safe) - MAINTENANCE_RETENTION_S
        keep = [w for w in self.maintenance if w.end is None or w.end >= window_cutoff]
        removed += len(self.maintenance) - len(keep)
        self.maintenance = keep

        def spent(att: AttemptRecord) -> bool:
            return not _in_window(att, safe) and (
                att.cooldown_until is None or att.cooldown_until <= safe
            )

        for key, att in list(loop.attempts.items()):
            last = att.last_at or att.window_start or 0.0
            if last < safe - ATTEMPTS_RETENTION_S and spent(att):
                del loop.attempts[key]
                removed += 1
        extra = len(loop.attempts) - ATTEMPTS_MAX
        if extra > 0:
            for key, _att in sorted(
                ((k, a) for k, a in loop.attempts.items() if spent(a)),
                key=lambda kv: (kv[1].last_at or 0.0, kv[0]),
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
            if stamp < safe - TERMINAL_RETENTION_S or len(loop.breakers) > BREAKERS_MAX:
                del loop.breakers[key]
                removed += 1
        removed += loop.drop_expired_holds(safe)
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

    def try_external_lock(self, router_id: str, source: str, ts: float) -> str | None:
        """Take the router lock for a write from outside the engine.

        Returns the new holder's ``lock_id`` (the only key that releases
        it), or None while a repair or any other write holds the lock, also
        one from the same source.
        """
        lock = LockRecord.external(router_id, source, ts)
        if not self.loop.try_lock(lock):
            return None
        self.schedule()
        return lock.lock_id

    def release_external_lock(self, router_id: str, lock_id: str) -> bool:
        """Release a lock taken with :meth:`try_external_lock` (by its id)."""
        held = self.loop.locks.get(router_id)
        if held is None or held.holder is not LockHolder.EXTERNAL:
            return False
        if not self.loop.release_lock(router_id, lock_id):
            return False
        self.schedule()
        return True

    # -- admin operations (the caller checks the HA admin; package F audits) ----

    def release_hold(
        self, router_id: str | None, *, actor: Actor | str, ts: float
    ) -> bool:
        """An admin releases the hold of a router (None: the fleet's).

        Every terminal record of the router whose end holds it is marked
        ``hold_released``, so the hold is not placed again when the holds
        are rebuilt from the records (a damaged loop section). ``ts`` is the
        admin's wall time (for the caller's audit entry).
        """
        _require_admin(actor, ts)
        gone = self.loop.holds.pop(router_id or FLEET_HOLD_KEY, None)
        marked = 0
        if router_id is not None:
            for action_id, action in list(self.actions.items()):
                if (
                    action.router_id == router_id
                    and action.is_terminal
                    and not action.flags.hold_released
                    and hold_reason_for(action) is not None
                ):
                    self.actions[action_id] = action.with_flags(hold_released=True)
                    marked += 1
        if gone is not None or marked:
            self.schedule()
        return gone is not None

    def admin_release_stuck(
        self, action_id: str, *, actor: Actor | str, ts: float
    ) -> RemediationAction:
        """An admin ends an action stuck in EXECUTING, VERIFYING or
        ROLLING_BACK: it becomes MANUAL_RECOVERY_REQUIRED (outcome unknown,
        interrupted) through the restart edges, the router lock is released
        and the router stays held (``stuck_released``) until an admin
        releases the hold. Never a new execution or rollback."""
        _require_admin(actor, ts)
        current = self._current(action_id)
        if current.state not in IN_FLIGHT_STATES:
            raise HealStoreError("action is not in a running state")
        safe = self.now()
        new = current
        if not (new.state is ActionState.VERIFYING and new.flags.interrupted):
            changes: dict[str, Any] = {}
            if new.state is ActionState.ROLLING_BACK:
                changes["rollback"] = replace(
                    new.rollback, status=RollbackStatus.UNKNOWN
                )
            new = transition(
                new,
                ActionState.VERIFYING,
                actor=Actor.RECOVERY,
                ts=ts,
                reason="released_by_admin",
                changes=changes,
            )
        new = transition(
            new,
            ActionState.MANUAL_RECOVERY_REQUIRED,
            actor=Actor.RECOVERY,
            ts=ts,
            reason="released_by_admin",
        )
        self.loop.place_hold(
            RouterHold(
                router_id=new.router_id,
                reason=HoldReason.STUCK_RELEASED,
                since=safe,
                action_id=action_id,
            )
        )
        _book(self.loop, current, new, safe)
        self.actions[action_id] = new
        self.schedule()
        return new

    def admin_force_release_lock(
        self, router_id: str, *, actor: Actor | str, ts: float
    ) -> bool:
        """An admin removes a stuck external lock; the router stays held
        (``lock_forced``) until an admin releases the hold. An engine lock
        is not touched here (see :meth:`admin_release_stuck`)."""
        _require_admin(actor, ts)
        held = self.loop.locks.get(router_id)
        if held is None or held.holder is not LockHolder.EXTERNAL:
            return False
        del self.loop.locks[router_id]
        self.loop.place_hold(
            RouterHold(
                router_id=router_id, reason=HoldReason.LOCK_FORCED, since=self.now()
            )
        )
        self.schedule()
        return True

    # -- writes --------------------------------------------------------------------

    def schedule(self, delay: float = SAVE_DELAY_S) -> None:
        """Arm one delayed write (none while one is pending or after close)."""
        if self._store is None or self.closed or (self._pending and delay > 0):
            return
        self._pending = True
        self._store.async_delay_save(self.payload, delay)

    async def _async_save_now(self) -> None:
        try:
            await self._store.async_save(self.payload())
        except Exception as err:  # noqa: BLE001 - a delayed write tries again
            _LOGGER.warning("Self-healing store not written (%s)", type(err).__name__)
            self.schedule()

    async def async_flush(self) -> None:
        """Write now (after a durable step in flight); never raises."""
        if self._store is None:
            return
        async with self._durable_lock:
            await self._async_save_now()

    async def async_close(self) -> None:
        """Last write (module off or unload), after a durable step in
        flight; no write is armed and no durable step succeeds afterwards."""
        if self._store is None:
            self.closed = True
            return
        async with self._durable_lock:
            if not self.closed:
                await self._async_save_now()
            self.closed = True

    def stats(self) -> dict[str, Any]:
        """Sizes and counters (no ids)."""
        safe = self.now()
        return {
            "bytes": self.last_bytes,
            "max_bytes": self.max_bytes,
            "actions": len(self.actions),
            "open": sum(1 for a in self.actions.values() if not a.is_terminal),
            "locks": len(self.loop.locks),
            "holds": sum(1 for h in self.loop.holds.values() if h.active(safe)),
            "fleet_paused": self.loop.fleet.paused(safe),
            "clock_jumps_ahead": self.loop.clock.jumps_ahead,
            "clock_jumps_back": self.loop.clock.jumps_back,
            **self.counters,
        }


def _require_admin(actor: Any, ts: Any) -> None:
    """Only an admin; ``ts`` must be a wall time."""
    try:
        who = Actor(actor)
    except (ValueError, TypeError):
        raise NotAdminError("admin only") from None
    if who is not Actor.ADMIN:
        raise NotAdminError("admin only")
    if (
        isinstance(ts, bool)
        or not isinstance(ts, int | float)
        or not 0 <= ts < float("inf")
    ):
        raise HealStoreError("invalid ts")


__all__ = [
    "HEAL_STORE_KEY",
    "HEAL_STORE_MINOR_VERSION",
    "HEAL_STORE_VERSION",
    "LOCK_SOURCE_ENGINE",
    "MAX_ACTIONS",
    "MAX_OPEN_PER_ROUTER",
    "STORE_MAX_BYTES",
    "TERMINAL_RETENTION_S",
    "UNREADABLE_HOLD_S",
    "AddResult",
    "BusyError",
    "CapacityError",
    "DurableResult",
    "HealStoreError",
    "IdempotencyExpiredError",
    "LoadResult",
    "NotAdminError",
    "RouterHeldError",
    "RouterLockedError",
    "SelfHealingStore",
    "UnknownActionError",
    "WriteAheadRequiredError",
    "store_bytes",
]
