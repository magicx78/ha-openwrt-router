"""Self-Healing (Phase 7), package C1: the engine skeleton (Observe only).

Developer document: ``docs/self-healing.md`` §2 (module layout), §5.2
(safety clock), §9 (decision), §11 (routes) and §15 (package C1).

**What it does.** One engine per HA instance, created with the first loaded
router entry while the fleet switch ``self_healing_enabled`` is on (the
default) and stopped with the last one (the lifecycle of the Time Machine
engine, ``tm_engine``). At start it loads ``heal_store`` (which applies the
restart rule before anything else: an interrupted action becomes "unknown,
needs verification" and is never executed), then listens to the incident
announcements of Network Intelligence (``EVENT_INCIDENT``, roots only, after
NI's settle time) with a ``@callback`` receiver, and ticks every
``TICK_S`` (5 minutes) to read the safety clock, prune and reconcile.

**The event is a trigger only.** Anyone inside HA can fire
``EVENT_INCIDENT`` (an automation, another integration); the REST and
WebSocket APIs fire with origin remote, which the engine ignores. Of a
local event only the incident id is used: state, routers, type and cause
are read from Network Intelligence's own incident. NI not loaded, or the
incident unknown to NI: nothing happens (counted). A new record needs NI's
own record that it announced the incident for its current open period
(``NetIntelligence.announced_reopen_count``); records close only when NI
shows the incident resolved, ignored, gone or a silent child.

An announced root incident on exactly one router that is in the engine,
enabled and LOADED (``ConfigEntryState``) with a router id becomes one
record per open period (``RemediationAction.new``, action
``observe.evaluate``, no router call) through ``SelfHealingStore.add``:
dedupe and limits are the store's job, refusals are counted here, never
raised. NI announces an incident once per open period and deferred
incidents live in memory only, so the start, every added router and every
tick also adopt announced roots without a record (at most
``RECONCILE_MAX`` per run, same path and guards). The record then moves
through the read-only part of the state machine only:

* DETECTED -> ANALYZED with the cause as Network Intelligence reported it
  (code, status, level, confidence, source families; never recomputed);
* ANALYZED -> PROPOSED with the outcome of the decision interface
  (:class:`HealDecider`). The default (:class:`ObserveOnlyDecider`)
  proposes nothing executable: ``insufficient_evidence`` with an
  unassessed risk. The engine clamps any decider: an incident whose cause
  is neither confirmed nor backed by two source families (time or a single
  indicator only) is ``insufficient_evidence``, and in this release nothing
  is executable (``no_write_path``).

The engine never goes past PROPOSED: no PREFLIGHT, no approval, no
execution, no router call, no HA service, no entity, no bus event. A record
whose incident resolves (NI shows it resolved, ignored, gone or
re-parented as a child) is closed DETECTED /
ANALYZED / PROPOSED -> CANCELLED by the engine with the wall time at which
the engine saw it. Holds and the fleet pause of the store are respected
(the effective mode stays Observe) and shown (``heal_views``).

**Performance.** Event driven plus one tick every 5 minutes; reads only
memory (NI's incidents, the core's registry); store writes are the store's
delayed writes. No coordinator listener, no refresh, no poll.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Final, Protocol, runtime_checkable

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import Event, EventOrigin, HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval

from .const import (
    DATA_SELF_HEALING_ENGINE,
    DOMAIN,
    EVENT_INCIDENT,
    OPTION_SELF_HEALING_ENABLED,
)
from .core_models import ROUTER_ID_PREFIX, is_valid_id
from .heal_model import (
    TERMINAL_STATES,
    ActionState,
    Actor,
    Cause,
    CauseLevel,
    CauseStatus,
    Change,
    Decision,
    DecisionOutcome,
    Factor,
    HealMode,
    HealModelError,
    Impact,
    RemediationAction,
    Risk,
    RiskClass,
    RouterHold,
)
from .heal_store import HealStoreError, LoadResult, SelfHealingStore

_LOGGER = logging.getLogger(__name__)

MODULE: Final = "self_healing"
# The safety clock must be read at least every 5 minutes while HA runs
# (docs §5.2): a longer gap is capped at 900 s per observation.
TICK_S: Final = 300.0
# The one action type of this package: evaluate existing data (catalog
# row ``observe.evaluate``, design §7: no router call, Risk 0 by nature;
# the record still carries the decider's risk, unassessed by default).
OBSERVE_ACTION: Final = "observe.evaluate"
# 1.53.0 is Observe only: no write path exists at all (owner decision).
WRITE_PATH_AVAILABLE: Final = False
# Deferred root incidents (the store returned the router's open record):
# retried when that record closes or on the tick; the oldest drop first.
PENDING_MAX: Final = 200
# Announced root incidents without a record that one start or one tick
# turns into records (the rest follow on the next ticks).
RECONCILE_MAX: Final = 20
# Longest incident id taken from an event (NI's ids are ``inc-N``).
INCIDENT_ID_MAX: Final = 64
# Independent source families a hypothesis needs (design §9, NI's
# ``LIKELY_FAMILIES``): fewer is time or one indicator only.
EVIDENCE_FAMILIES_MIN: Final = 2
# States the engine may close itself (engine-actor edges to CANCELLED that
# need no approval context): the planning part of this package.
_CLOSABLE: Final = frozenset(
    {ActionState.DETECTED, ActionState.ANALYZED, ActionState.PROPOSED}
)
# Event states that make the engine look at an incident (a trigger only).
_EVENT_STATES: Final = frozenset({"opened", "reopened", "resolved"})
_ACTIVE_STATUS: Final = "active"
# NI incident status -> the reason its records close with
_CLOSED_STATUS: Final[Mapping[str, str]] = {
    "resolved": "incident_cleared",
    "ignored": "incident_ignored",
}

# Engine-side blocker codes of a plan (``plan_for``), always codes.
BLOCK_NO_WRITE_PATH: Final = "no_write_path"
BLOCK_MODE_OBSERVE: Final = "mode_observe"
BLOCK_ROUTER_HELD: Final = "router_held"
BLOCK_FLEET_PAUSED: Final = "fleet_paused"
BLOCK_MODULE_DISABLED: Final = "module_disabled"
BLOCK_IN_MAINTENANCE: Final = "in_maintenance"
BLOCK_IDENTITY: Final = "identity_not_confirmed"
BLOCK_ROUTER_NOT_LOADED: Final = "router_not_loaded"
BLOCK_EVIDENCE: Final = "insufficient_evidence_sources"
BLOCK_NOT_EXECUTABLE: Final = "nothing_executable"
BLOCK_NOT_PLANNING: Final = "not_in_planning"

_COUNTERS: Final = (
    "incidents_seen",
    "records_created",
    "deduplicated",
    "deferred",
    "refused_capacity",
    "refused_invalid",
    "skipped_child",
    "skipped_no_single_router",
    "skipped_router_not_loaded",
    "skipped_router_disabled",
    "skipped_no_router_id",
    "skipped_module_disabled",
    "skipped_bad_event",
    "skipped_remote_event",
    "skipped_ni_unavailable",
    "skipped_unknown_incident",
    "skipped_not_announced",
    "reconciled",
    "analyzed",
    "proposed",
    "closed",
    "decider_failed",
    "decision_clamped",
    "ticks",
    "errors",
)


# --- the decision interface (package D plugs in here) ---------------------------------


@dataclass(frozen=True, slots=True)
class DecisionContext:
    """What a decider may read about one record (immutable; no router data
    beyond codes and counts, no entry id, no name)."""

    action: RemediationAction
    router_id: str
    configured_mode: HealMode
    effective_mode: HealMode
    hold: RouterHold | None
    fleet_paused: bool
    module_enabled: bool
    in_maintenance: bool
    router_loaded: bool
    identity_status: str | None  # core IdentityStatus value
    role: str | None  # core RouterRole value
    cause: Cause | None
    source_families: tuple[str, ...]
    # the cause is confirmed or backed by EVIDENCE_FAMILIES_MIN families
    evidence_sufficient: bool
    write_path_available: bool = WRITE_PATH_AVAILABLE


@dataclass(frozen=True, slots=True)
class Proposal:
    """A decider's answer; the engine validates and clamps it."""

    decision: Decision
    risk: Risk = field(default_factory=Risk)
    playbook_id: str | None = None
    playbook_version: int | None = None
    prerequisites: tuple[str, ...] = ()
    planned_changes: tuple[Change, ...] = ()
    expected_impact: Impact | None = None
    # the decider would execute something; never honoured in 1.53.0
    executable: bool = False


@runtime_checkable
class HealDecider(Protocol):
    """Decision and risk for one record (package D: ``heal_policy``).

    Must be pure and fast: no I/O, no router call, no store change, no
    HA call; the engine calls it in the event loop, also for the read-only
    ``plans`` route. An exception is counted and the default is used.
    """

    def propose(self, context: DecisionContext) -> Proposal:
        """The proposal for ``context.action``."""


class ObserveOnlyDecider:
    """The default until package D: proposes nothing executable.

    ``insufficient_evidence`` with score 0 and an unassessed risk (the
    model's default: the highest class, so a record no one assessed never
    passes a hold as read-only).
    """

    def propose(self, context: DecisionContext) -> Proposal:
        """Always the same conservative answer."""
        del context
        return Proposal(
            decision=Decision(
                outcome=DecisionOutcome.INSUFFICIENT_EVIDENCE,
                score=0.0,
                factors=(
                    Factor(factor="policy", value=0.0, reason="no_decision_policy"),
                ),
                why=None,
                why_not="no_decision_policy",
            ),
            risk=Risk(risk_class=RiskClass.HIGH, reasons=("not_assessed",)),
        )


DEFAULT_DECIDER: Final[HealDecider] = ObserveOnlyDecider()

# Outcomes that never lead to a write (the clamp keeps these as they are).
_NON_ACTING: Final = frozenset(
    {
        DecisionOutcome.INSUFFICIENT_EVIDENCE,
        DecisionOutcome.UNSUPPORTED,
        DecisionOutcome.NOT_SAFE,
    }
)


@dataclass(frozen=True, slots=True)
class Plan:
    """What the ``plans`` route reports for one open record (read only)."""

    action: RemediationAction
    proposal: Proposal
    executable: bool
    blockers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """JSON form: codes, counts and ids only."""
        decision = self.proposal.decision
        return {
            "action_id": self.action.action_id,
            "router_id": self.action.router_id,
            "state": self.action.state.value,
            "incident_id": self.action.incident_id,
            "incident_type": self.action.incident_type,
            "action_type": self.action.action_type,
            "decision": decision.to_dict(),
            "risk": self.proposal.risk.to_dict(),
            "playbook_id": self.proposal.playbook_id,
            "playbook_version": self.proposal.playbook_version,
            "executable": self.executable,
            "blockers": list(self.blockers),
        }


# --- helpers ----------------------------------------------------------------------------


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _value(raw: Any) -> str | None:
    """An enum's value or a plain string."""
    return _str(getattr(raw, "value", raw))


def _confidence(raw: Any) -> float | None:
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return None
    value = float(raw)
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        return None
    return round(value, 4)


def _reopen(inc: Any) -> int:
    """The incident's reopen count (0 when missing or odd)."""
    value = getattr(inc, "reopen_count", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _event_incident_id(data: Any) -> str | None:
    """The incident id of a well-formed announcement, else None.

    Only the shape is checked (state, id, the router list); the values are
    never used beyond the id: the incident itself is read from NI.
    """
    if not isinstance(data, Mapping):
        return None
    try:
        state = data.get("state")
        incident_id = data.get("incident_id")
        entry_ids = data.get("entry_ids", [])
    except Exception:  # noqa: BLE001 - an odd mapping is a bad event
        return None
    if not isinstance(state, str) or state not in _EVENT_STATES:
        return None
    if not isinstance(incident_id, str) or not 0 < len(incident_id) <= INCIDENT_ID_MAX:
        return None
    if entry_ids is not None and (
        not isinstance(entry_ids, list)
        or not all(isinstance(e, str) for e in entry_ids)
    ):
        return None
    return incident_id


def _entries(hass: HomeAssistant) -> list[Any]:
    try:
        entries = hass.config_entries.async_entries(DOMAIN)
    except Exception:  # noqa: BLE001 - a broken registry is "no entries"
        return []
    return list(entries) if isinstance(entries, list) else []


def self_healing_enabled(hass: HomeAssistant) -> bool:
    """The fleet switch: on unless a router entry has it off.

    The options flow writes the value through to every entry, so all agree;
    should they not, any entry that says off switches the module off (the
    stricter reading). An entry without the option counts as on (default).
    """
    for entry in _entries(hass):
        options = getattr(entry, "options", None)
        if (
            isinstance(options, Mapping)
            and options.get(OPTION_SELF_HEALING_ENABLED) is False
        ):
            return False
    return True


# --- the engine -------------------------------------------------------------------------


class HealEngine:
    """The running Self-Healing engine of one HA instance (Observe only)."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] | None = time.monotonic,
        store: SelfHealingStore | None = None,
        decider: HealDecider | None = None,
    ) -> None:
        """Nothing is read or attached before :meth:`async_start`."""
        self.hass = hass
        self.clock = clock
        self.monotonic = monotonic
        self.store = store or SelfHealingStore(hass, clock=clock, monotonic=monotonic)
        self.decider: HealDecider = decider or DEFAULT_DECIDER
        self.entries: set[str] = set()
        self.loaded = False
        self.closed = False
        self.load_result: LoadResult | None = None
        self.counters: dict[str, int] = dict.fromkeys(_COUNTERS, 0)
        self.last_tick_mono: float | None = None
        self._api: Any = None
        self._bind_task: asyncio.Task[Any] | None = None
        self._unsubs: list[Callable[[], None]] = []
        # incident id -> None: announced roots whose router had an open
        # record (oldest first; bounded)
        self._pending: OrderedDict[str, None] = OrderedDict()

    # -- start / stop ------------------------------------------------------------------

    async def async_start(self) -> None:
        """Load the store (restart rule first), then listen and tick."""
        self.load_result = await self.store.async_load()
        if self.load_result.recovered:
            _LOGGER.info(
                "Self-Healing: %d interrupted action(s) set to need verification "
                "after a restart; none is executed again",
                len(self.load_result.recovered),
            )
        self.loaded = True
        self._unsubs.append(
            self.hass.bus.async_listen(EVENT_INCIDENT, self._on_incident)
        )
        self._unsubs.append(
            async_track_time_interval(
                self.hass, self._on_tick, timedelta(seconds=TICK_S)
            )
        )
        await self.async_bind_core()
        self.last_tick_mono = self._mono()
        self._guard("start reconcile", self.reconcile)

    async def async_stop(self) -> None:
        """Detach everything and write the store a last time."""
        self.closed = True
        for unsub in self._unsubs:
            with contextlib.suppress(Exception):
                unsub()
        self._unsubs.clear()
        task, self._bind_task = self._bind_task, None
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._pending.clear()
        await self.store.async_close()

    async def async_bind_core(self) -> None:
        """The core's Configuration API (registry); None while it is down."""
        if self._api is not None or self.closed:
            return
        try:
            from .config_api import async_get_configuration_api

            self._api = await async_get_configuration_api(self.hass, 1)
        except Exception as err:  # noqa: BLE001 - runs on without router ids
            _LOGGER.debug("Self-Healing: no core yet (%s)", type(err).__name__)
            self._api = None

    def add_entry(self, entry_id: str) -> None:
        """A router entry is loaded."""
        self.entries.add(entry_id)

    async def async_add_entries(self, entry_ids: Iterable[str]) -> None:
        """Routers are (being) loaded: bind the core, then reconcile, so an
        announced incident of a router that is already LOADED gets its
        record now and not only on the next tick."""
        for entry_id in entry_ids:
            self.add_entry(entry_id)
        await self.async_bind_core()
        self._guard("reconcile", self.reconcile)

    def remove_entry(self, entry_id: str) -> None:
        """A router entry is unloaded (its records stay)."""
        self.entries.discard(entry_id)

    # -- reading the world (memory only) -----------------------------------------------

    def _mono(self) -> float | None:
        return None if self.monotonic is None else float(self.monotonic())

    def _ni(self) -> Any:
        from .net_engine import async_get_engine

        engine = async_get_engine(self.hass)
        return engine if engine is not None and engine.loaded else None

    def _incidents(self, ni: Any) -> dict[str, Any]:
        return {inc.id: inc for inc in ni.machine.peek()}

    def _record_of(self, entry_id: str) -> Any:
        if self._api is None:
            return None
        try:
            return self._api.registry.get_by_entry(entry_id)
        except Exception:  # noqa: BLE001 - not registered (yet)
            return None

    def router_id_for_entry(self, entry_id: str) -> str | None:
        """The core router id of an entry (Unified Router Identity)."""
        record = self._record_of(entry_id)
        rid = getattr(record, "router_id", None)
        if _value(getattr(record, "state", None)) not in (None, "active"):
            return None  # an orphaned record is no live router
        return rid if is_valid_id(rid, ROUTER_ID_PREFIX) else None

    def entry_for_router(self, router_id: str) -> str | None:
        """The entry id of a router id (None when the core does not know it)."""
        if self._api is None:
            return None
        try:
            record = self._api.registry.find(router_id)
        except Exception:  # noqa: BLE001
            return None
        return _str(getattr(getattr(record, "identity", None), "entry_id", None))

    def _identity(self, router_id: str) -> tuple[str | None, str | None]:
        """(identity status, role) as codes; (None, None) when unknown."""
        if self._api is None:
            return None, None
        try:
            from .core_models import primary_identity_status

            record = self._api.registry.find(router_id)
            identity = getattr(record, "identity", None)
            if identity is None:
                return None, None
            status = primary_identity_status(identity.identity_flags).value
            return status, _value(identity.role)
        except Exception:  # noqa: BLE001 - unknown identity
            return None, None

    def _entry_usable(self, entry_id: str) -> str | None:
        """None when the entry is in the engine, enabled and LOADED, else
        the counter. An entry still setting up, whose setup failed or whose
        unload failed is no router to act on (review of PR #78)."""
        if entry_id not in self.entries:
            return "skipped_router_not_loaded"
        try:
            entry = self.hass.config_entries.async_get_entry(entry_id)
        except Exception:  # noqa: BLE001
            entry = None
        if entry is None or getattr(entry, "disabled_by", None) is not None:
            return "skipped_router_disabled"
        if getattr(entry, "state", None) is not ConfigEntryState.LOADED:
            return "skipped_router_not_loaded"
        return None

    def router_loaded(self, router_id: str) -> bool:
        """The router's entry is in the engine, enabled and LOADED."""
        entry_id = self.entry_for_router(router_id)
        return entry_id is not None and self._entry_usable(entry_id) is None

    def module_enabled(self) -> bool:
        """The module switch of the store's settings (default on)."""
        return self.store.settings.enabled is True

    # -- events ------------------------------------------------------------------------

    def _guard(self, name: str, func: Callable[..., Any], *args: Any) -> Any:
        try:
            return func(*args)
        except Exception as err:  # noqa: BLE001 - never breaks the caller
            self.counters["errors"] += 1
            _LOGGER.warning("Self-Healing %s failed (%s)", name, type(err).__name__)
            return None

    @callback
    def _on_incident(self, event: Event) -> None:
        """A Network Intelligence announcement: a trigger, nothing more.

        An event fired from outside HA (REST or WebSocket API: origin
        remote) is not even a trigger. Inside HA anyone can fire the event
        too (an automation, another integration), so its fields are never
        trusted: :meth:`handle_incident` reads the incident from Network
        Intelligence itself.
        """
        if self.closed or not self.loaded:
            return
        origin = getattr(event, "origin", EventOrigin.local)
        if origin is not EventOrigin.local:
            self.counters["skipped_remote_event"] += 1
            return
        self._guard("incident", self.handle_incident, getattr(event, "data", None))

    def handle_incident(self, data: Any) -> None:
        """Bring one incident in line with Network Intelligence.

        The event names the incident and nothing else counts: its state,
        routers, type and cause come from NI's own incident. NI not loaded,
        or the incident unknown to NI: nothing (counted). Resolved or
        ignored in NI: its records close. Active in NI and announced by NI
        for its current open period: a record (:meth:`_detect`).
        """
        incident_id = _event_incident_id(data)
        if incident_id is None:
            self.counters["skipped_bad_event"] += 1
            return
        self.counters["incidents_seen"] += 1
        ni = self._ni()
        if ni is None:
            self.counters["skipped_ni_unavailable"] += 1
            return
        known = self._incidents(ni)
        inc = known.get(incident_id)
        if inc is None:
            self.counters["skipped_unknown_incident"] += 1
            return
        status = _value(getattr(inc, "status", None))
        if status in _CLOSED_STATUS:
            self._pending.pop(incident_id, None)
            if self._close_incident(incident_id, _CLOSED_STATUS[status]):
                self._retry_pending(ni, known)
            return
        if status != _ACTIVE_STATUS:
            return  # acknowledged: no new record, an open one stays
        reopen = _reopen(inc)
        self._detect(
            inc,
            ni,
            known,
            reason="incident_reopened" if reopen else "incident_opened",
        )

    @callback
    def _on_tick(self, _now: Any = None) -> None:
        """Every ``TICK_S``: safety clock, prune, reconcile (memory only)."""
        if self.closed:
            return
        self.counters["ticks"] += 1
        self.last_tick_mono = self._mono()
        self._guard("tick", self.tick)

    def tick(self) -> None:
        """Read the safety clock, prune, bind the core, reconcile."""
        self.store.now()
        self.store.prune()
        if self._api is None and (self._bind_task is None or self._bind_task.done()):
            self._bind_task = self.hass.async_create_task(
                self.async_bind_core(), name="openwrt_router self-healing core"
            )
        self.reconcile()

    # -- detect, analyse, propose ------------------------------------------------------

    @staticmethod
    def _announced(ni: Any, inc: Any) -> bool:
        """NI announced ``inc`` on the bus for its current open period.

        NI's own record of what it announced: a root at or above
        ``notify_min_severity``, after its settle time, not only on routers
        in maintenance (``NetIntelligence._announce``). Unknown: no.
        """
        getter = getattr(ni, "announced_reopen_count", None)
        if not callable(getter):
            return False
        try:
            count = getter(inc.id)
        except Exception:  # noqa: BLE001 - unknown is "not announced"
            return False
        return (
            isinstance(count, int)
            and not isinstance(count, bool)
            and count == _reopen(inc)
        )

    def _recorded(self, incident_id: str, reopen: int) -> bool:
        """An observe record of this incident's open period exists (in any
        state): one record per period, also after it closed."""
        return any(
            a.incident_id == incident_id
            and a.incident_reopen == reopen
            and a.action_type == OBSERVE_ACTION
            for a in self.store.actions.values()
        )

    def _detect(
        self,
        inc: Any,
        ni: Any,
        known: Mapping[str, Any],
        *,
        reason: str,
        deferred: bool = False,
        count: bool = True,
    ) -> str:
        """One root incident of NI -> one record. Returns the outcome code.

        ``count`` False (the reconcile of every tick): skips are not counted,
        so the counters say what happened to announcements, not how often
        the tick looked.
        """

        def skip(counter: str, outcome: str) -> str:
            if count:
                self.counters[counter] += 1
            return outcome

        incident_id = inc.id
        if not self.module_enabled():
            return skip("skipped_module_disabled", "module_disabled")
        if not self._announced(ni, inc):
            return skip("skipped_not_announced", "not_announced")
        if self._is_child(ni, inc, known):
            return skip("skipped_child", "child")
        from .net_engine import FLEET_ROUTER

        raw = getattr(inc, "routers", None)
        routers = [
            r
            for r in dict.fromkeys(
                r
                for r in (raw if isinstance(raw, list | tuple) else ())
                if isinstance(r, str)
            )
            if r != FLEET_ROUTER
        ]
        if len(routers) != 1:
            return skip("skipped_no_single_router", "no_single_router")
        entry_id = routers[0]
        skipped = self._entry_usable(entry_id)
        if skipped is not None:
            return skip(skipped, skipped)
        router_id = self.router_id_for_entry(entry_id)
        if router_id is None:
            return skip("skipped_no_router_id", "no_router_id")
        reopen = _reopen(inc)
        if self._recorded(incident_id, reopen):
            return skip("deduplicated", "deduplicated")
        try:
            action = RemediationAction.new(
                router_id=router_id,
                action_type=OBSERVE_ACTION,
                ts=self.clock(),
                actor=Actor.ENGINE,
                reason=reason,
                params={"incident": incident_id},
                incident_id=incident_id,
                incident_type=_str(getattr(inc, "type", None)),
                incident_reopen=reopen,
            )
        except HealModelError:
            return skip("refused_invalid", "invalid")
        try:
            result = self.store.add(action)
        except HealStoreError:
            return skip("refused_capacity", "refused")
        if not result.created:
            if (
                result.dedupe == "component"
                and result.action.incident_id != incident_id
            ):
                # the router's open record belongs to another incident: retry
                # when it closes (design §10: one open action per component)
                self._pending[incident_id] = None
                self._pending.move_to_end(incident_id)
                while len(self._pending) > PENDING_MAX:
                    self._pending.popitem(last=False)
                if not deferred and count:
                    self.counters["deferred"] += 1
                return "deferred"
            return skip("deduplicated", "deduplicated")
        self.counters["records_created"] += 1
        if self._in_maintenance(ni, entry_id):
            with contextlib.suppress(HealStoreError, HealModelError):
                self.store.update_flags(action.action_id, in_maintenance=True)
        self._advance(action.action_id, inc, ni)
        return "created"

    def _is_child(self, ni: Any, inc: Any, known: Mapping[str, Any]) -> bool:
        if getattr(inc, "parent_id", None) is None:
            return False
        from .net_rules import suppressed_child

        return suppressed_child(inc, known, getattr(ni.machine, "last_now", None))

    @staticmethod
    def _in_maintenance(ni: Any, entry_id: str) -> bool:
        try:
            return bool(ni.in_maintenance(entry_id))
        except Exception:  # noqa: BLE001
            return False

    def _cause(self, ni: Any, inc: Any) -> tuple[Cause | None, tuple[str, ...]]:
        """The cause as NI reports it (never recomputed) and its families."""
        if inc is None:
            return None, ()
        families: tuple[str, ...] = ()
        level: str | None = None
        try:
            from .net_rules import cause_families, events_by_id, incident_cause_level

            wanted = {e.get("id") for e in inc.evidence if isinstance(e, Mapping)}
            events = events_by_id(e for e in ni.ring if e.id in wanted)
            families = tuple(sorted(cause_families(inc, events)))
            level = incident_cause_level(inc, events).value
        except Exception as err:  # noqa: BLE001 - without families: unknown
            _LOGGER.debug("Self-Healing: no cause families (%s)", type(err).__name__)
        code = _str(getattr(inc, "cause", None))
        if code is None:
            return None, families
        try:
            cause = Cause(
                code=code,
                status=_value(getattr(inc, "cause_status", None))
                or CauseStatus.HYPOTHESIS,
                level=level or CauseLevel.UNKNOWN,
                confidence=_confidence(getattr(inc, "confidence", None)),
                source_families=families,
            )
        except HealModelError:
            return None, families
        return cause, families

    def _advance(self, action_id: str, inc: Any, ni: Any) -> None:
        """DETECTED -> ANALYZED -> PROPOSED, as far as the record is.

        A step the store or the model refuses is counted (``errors``) and
        the record stays where it is; the tick tries again.
        """
        try:
            self._advance_steps(action_id, inc, ni)
        except (HealStoreError, HealModelError) as err:
            self.counters["errors"] += 1
            _LOGGER.debug("Self-Healing: step refused (%s)", type(err).__name__)

    def _advance_steps(self, action_id: str, inc: Any, ni: Any) -> None:
        action = self.store.get(action_id)
        if action is None:
            return
        if action.state is ActionState.DETECTED:
            cause, _families = self._cause(ni, inc) if ni is not None else (None, ())
            action = self.store.apply(
                action_id,
                ActionState.ANALYZED,
                actor=Actor.ENGINE,
                ts=self.clock(),
                reason="cause_from_incident" if cause else "no_cause_reported",
                changes={"cause": cause},
            )
            self.counters["analyzed"] += 1
        if action.state is ActionState.ANALYZED:
            context = self.context_for(action)
            proposal, _clamped = self._decide(context)
            changes: dict[str, Any] = {
                "decision": proposal.decision,
                "risk": proposal.risk,
                "playbook_id": proposal.playbook_id,
                "playbook_version": proposal.playbook_version,
                "prerequisites": proposal.prerequisites,
                "planned_changes": proposal.planned_changes,
            }
            if proposal.expected_impact is not None:
                changes["expected_impact"] = proposal.expected_impact
            try:
                self.store.apply(
                    action_id,
                    ActionState.PROPOSED,
                    actor=Actor.ENGINE,
                    ts=self.clock(),
                    reason=f"decision_{proposal.decision.outcome.value}",
                    changes=changes,
                )
            except HealModelError:
                # a decider value the model refuses: the safe default instead
                self.counters["decider_failed"] += 1
                fallback = DEFAULT_DECIDER.propose(context)
                self.store.apply(
                    action_id,
                    ActionState.PROPOSED,
                    actor=Actor.ENGINE,
                    ts=self.clock(),
                    reason=f"decision_{fallback.decision.outcome.value}",
                    changes={"decision": fallback.decision, "risk": fallback.risk},
                )
            self.counters["proposed"] += 1

    def context_for(self, action: RemediationAction) -> DecisionContext:
        """The decider's view of one record (reads the safety clock)."""
        rid = action.router_id
        store = self.store
        safe = store.now()
        entry_id = self.entry_for_router(rid)
        ni = self._ni()
        status, role = self._identity(rid)
        cause = action.cause
        families = cause.source_families if cause is not None else ()
        sufficient = cause is not None and (
            cause.status is CauseStatus.CONFIRMED
            or len(families) >= EVIDENCE_FAMILIES_MIN
        )
        return DecisionContext(
            action=action,
            router_id=rid,
            configured_mode=store.settings.router(rid).mode,
            effective_mode=store.effective_mode(rid),
            hold=store.loop.hold_on(rid, safe),
            fleet_paused=store.loop.fleet.paused(safe),
            module_enabled=self.module_enabled(),
            in_maintenance=bool(
                action.flags.in_maintenance
                or (ni is not None and entry_id and self._in_maintenance(ni, entry_id))
            ),
            router_loaded=entry_id is not None and self._entry_usable(entry_id) is None,
            identity_status=status,
            role=role,
            cause=cause,
            source_families=tuple(families),
            evidence_sufficient=sufficient,
        )

    def _decide(self, context: DecisionContext) -> tuple[Proposal, bool]:
        """The decider's proposal, validated and clamped. (proposal, clamped)"""
        try:
            proposal = self.decider.propose(context)
            if (
                not isinstance(proposal, Proposal)
                or not isinstance(proposal.decision, Decision)
                or not isinstance(proposal.risk, Risk)
            ):
                raise TypeError("not a Proposal")
        except Exception as err:  # noqa: BLE001 - the safe default instead
            self.counters["decider_failed"] += 1
            _LOGGER.debug("Self-Healing decider failed (%s)", type(err).__name__)
            proposal = DEFAULT_DECIDER.propose(context)
        clamped = False
        if (
            not context.evidence_sufficient
            and proposal.decision.outcome not in _NON_ACTING
        ):
            # time or one indicator alone never leads to an acting outcome
            # (design §9: insufficient evidence)
            try:
                decision = Decision(
                    outcome=DecisionOutcome.INSUFFICIENT_EVIDENCE,
                    score=min(proposal.decision.score, 0.59),
                    factors=proposal.decision.factors,
                    why=None,
                    why_not=BLOCK_EVIDENCE,
                )
            except HealModelError:
                decision = DEFAULT_DECIDER.propose(context).decision
            proposal = Proposal(
                decision=decision,
                risk=proposal.risk,
                playbook_id=proposal.playbook_id,
                playbook_version=proposal.playbook_version,
                prerequisites=proposal.prerequisites,
                planned_changes=proposal.planned_changes,
                expected_impact=proposal.expected_impact,
                executable=False,
            )
            clamped = True
        if clamped:
            self.counters["decision_clamped"] += 1
        return proposal, clamped

    def plan_for(self, action: RemediationAction) -> Plan:
        """What would be proposed and what would block, read only.

        Calls the decider on the current facts; creates nothing, changes no
        record, no approval. Executable is always False in 1.53.0.
        """
        context = self.context_for(action)
        proposal, clamped = self._decide(context)
        blockers: list[str] = []
        if not WRITE_PATH_AVAILABLE:
            blockers.append(BLOCK_NO_WRITE_PATH)
        if action.state not in _CLOSABLE:
            blockers.append(BLOCK_NOT_PLANNING)
        if not context.module_enabled:
            blockers.append(BLOCK_MODULE_DISABLED)
        if context.effective_mode is HealMode.OBSERVE:
            blockers.append(BLOCK_MODE_OBSERVE)
        if context.hold is not None:
            blockers.append(BLOCK_ROUTER_HELD)
        if context.fleet_paused:
            blockers.append(BLOCK_FLEET_PAUSED)
        if context.in_maintenance:
            blockers.append(BLOCK_IN_MAINTENANCE)
        if not context.router_loaded:
            blockers.append(BLOCK_ROUTER_NOT_LOADED)
        if context.identity_status != "confirmed":
            blockers.append(BLOCK_IDENTITY)
        if clamped or not context.evidence_sufficient:
            blockers.append(BLOCK_EVIDENCE)
        if not proposal.executable or proposal.decision.outcome in _NON_ACTING:
            blockers.append(BLOCK_NOT_EXECUTABLE)
        return Plan(
            action=action,
            proposal=proposal,
            executable=False,
            blockers=tuple(dict.fromkeys(blockers)),
        )

    # -- close and reconcile -----------------------------------------------------------

    def _close(self, action: RemediationAction, reason: str) -> bool:
        if action.state not in _CLOSABLE:
            return False
        try:
            self.store.apply(
                action.action_id,
                ActionState.CANCELLED,
                actor=Actor.ENGINE,
                ts=self.clock(),
                reason=reason,
            )
        except (HealStoreError, HealModelError) as err:
            _LOGGER.debug("Self-Healing: not closed (%s)", type(err).__name__)
            return False
        self.counters["closed"] += 1
        return True

    def _close_incident(self, incident_id: str, reason: str) -> bool:
        """Close the open records of one incident; True if any closed."""
        closed = False
        for action in self.store.open_actions():
            if (
                action.incident_id == incident_id
                and action.action_type == OBSERVE_ACTION
            ):
                closed = self._close(action, reason) or closed
        return closed

    def reconcile(self) -> None:
        """Bring the open records in line with Network Intelligence.

        Without a loaded NI nothing is closed or made (unknown is not
        "cleared"). A record whose incident resolved, was ignored, is gone
        or became a silent child is closed; one left in DETECTED or
        ANALYZED (a restart between the steps) moves on. Deferred incidents
        are retried, then announced roots without a record are adopted.
        """
        ni = self._ni()
        if ni is None:
            return
        known = self._incidents(ni)
        for action in self.store.open_actions():
            if action.action_type != OBSERVE_ACTION or action.incident_id is None:
                continue
            if action.state not in _CLOSABLE:
                continue  # a later package's state: never touched here
            inc = known.get(action.incident_id)
            status = _value(getattr(inc, "status", None))
            if inc is None:
                self._close(action, "incident_gone")
            elif status in _CLOSED_STATUS:
                self._close(action, _CLOSED_STATUS[status])
            elif self._is_child(ni, inc, known):
                self._close(action, "incident_now_child")
            elif action.state is not ActionState.PROPOSED:
                self._advance(action.action_id, inc, ni)
        self._retry_pending(ni, known)
        self._adopt(ni, known)

    def _adopt(self, ni: Any, known: Mapping[str, Any]) -> None:
        """Announced active roots on one loaded router without a record of
        their open period get one (review of PR #78).

        Deferred incidents are lost on a restart and NI announces an
        incident once per open period (stored), so without this an open
        incident would never get its record. The same path and guards as
        an announcement (:meth:`_detect`), at most ``RECONCILE_MAX`` new
        records per call, skips not counted. Memory only.
        """
        if not self.module_enabled():
            return
        recorded = {
            (a.incident_id, a.incident_reopen)
            for a in self.store.actions.values()
            if a.action_type == OBSERVE_ACTION
        }
        created = 0
        for inc in known.values():
            if created >= RECONCILE_MAX:
                return
            incident_id = getattr(inc, "id", None)
            if not isinstance(incident_id, str) or incident_id in self._pending:
                continue
            if _value(getattr(inc, "status", None)) != _ACTIVE_STATUS:
                continue
            if (incident_id, _reopen(inc)) in recorded:
                continue
            if not self._announced(ni, inc):
                continue
            outcome = self._detect(
                inc, ni, known, reason="incident_reconciled", count=False
            )
            if outcome == "created":
                created += 1
                self.counters["reconciled"] += 1

    def _retry_pending(
        self, ni: Any = None, known: Mapping[str, Any] | None = None
    ) -> None:
        if not self._pending:
            return
        if ni is None:
            ni = self._ni()
            if ni is None:
                return
        if known is None:
            known = self._incidents(ni)
        for incident_id in list(self._pending):
            inc = known.get(incident_id)
            if inc is None or _value(getattr(inc, "status", None)) != _ACTIVE_STATUS:
                self._pending.pop(incident_id, None)
                continue
            outcome = self._detect(
                inc, ni, known, reason="incident_deferred", deferred=True
            )
            if outcome != "deferred":
                self._pending.pop(incident_id, None)

    # -- reading for routes and diagnostics --------------------------------------------

    def router_ids(self) -> list[str]:
        """Loaded routers first, then routers that only have records."""
        out: dict[str, bool] = {}
        for entry_id in sorted(self.entries):
            rid = self.router_id_for_entry(entry_id)
            if rid is not None:
                out[rid] = True
        for action in self.store.actions.values():
            out.setdefault(action.router_id, False)
        for rid in self.store.settings.routers:
            out.setdefault(rid, False)
        return list(out)

    def last_activity(self) -> float | None:
        """Wall time of the newest transition of any record."""
        stamps = [a.updated_at for a in self.store.actions.values()]
        return max(stamps) if stamps else None

    def pending_count(self) -> int:
        """Deferred root incidents waiting for their router's record."""
        return len(self._pending)

    def stats(self) -> dict[str, Any]:
        """Counters and sizes (no ids)."""
        mono = self._mono()
        return {
            "loaded": self.loaded,
            "routers_loaded": len(self.entries),
            "core_bound": self._api is not None,
            "pending": len(self._pending),
            "tick_s": TICK_S,
            "last_tick_s_ago": (
                None
                if mono is None or self.last_tick_mono is None
                else round(max(0.0, mono - self.last_tick_mono), 1)
            ),
            "decider": type(self.decider).__name__,
            **self.counters,
        }


def count_by_state(actions: Iterable[RemediationAction]) -> dict[str, int]:
    """Records per state (every state listed, terminal ones too)."""
    counts = dict.fromkeys((s.value for s in ActionState), 0)
    for action in actions:
        counts[action.state.value] += 1
    return counts


def open_count(actions: Iterable[RemediationAction]) -> int:
    """Records not in a terminal state."""
    return sum(1 for a in actions if a.state not in TERMINAL_STATES)


# --- life cycle -------------------------------------------------------------------------

_LOCK_KEY: Final = f"{DOMAIN}_self_healing_lock"


@callback
def async_get_self_healing(hass: HomeAssistant) -> HealEngine | None:
    """The running engine, or None (off, or no router loaded)."""
    engine = hass.data.get(DATA_SELF_HEALING_ENGINE)
    return engine if isinstance(engine, HealEngine) and not engine.closed else None


def _lock(hass: HomeAssistant) -> asyncio.Lock:
    lock = hass.data.get(_LOCK_KEY)
    if not isinstance(lock, asyncio.Lock):
        lock = hass.data[_LOCK_KEY] = asyncio.Lock()
    return lock


# The states of an entry whose own setup calls async_setup_self_healing:
# SETUP_IN_PROGRESS while async_setup_entry runs, LOADED on a later call.
_SETUP_STATES: Final = (ConfigEntryState.SETUP_IN_PROGRESS, ConfigEntryState.LOADED)
_NO_CONFIG_DIR_KEY: Final = f"{DOMAIN}_self_healing_no_config_dir"


def _loaded_entry_ids(hass: HomeAssistant) -> list[str]:
    """Entries that are LOADED and have run their setup (runtime data with a
    coordinator). Runtime data alone is not enough: a setup that failed
    after setting it leaves it behind (review of PR #78)."""
    out: list[str] = []
    for entry in _entries(hass):
        if getattr(entry, "disabled_by", None) is not None:
            continue
        if getattr(entry, "state", None) is not ConfigEntryState.LOADED:
            continue
        runtime = getattr(entry, "runtime_data", None)
        if getattr(runtime, "coordinator", None) is not None:
            out.append(entry.entry_id)
    return out


def _config_dir_usable(hass: HomeAssistant) -> bool:
    """HA's Store writes below ``hass.config.config_dir``; without a real
    one (a mocked hass) it would write into the working directory. No
    engine then, said once per instance."""
    config_dir = getattr(getattr(hass, "config", None), "config_dir", None)
    if isinstance(config_dir, str) and config_dir:
        return True
    if not hass.data.get(_NO_CONFIG_DIR_KEY):
        hass.data[_NO_CONFIG_DIR_KEY] = True
        _LOGGER.warning("Self-Healing not started: no configuration directory")
    return False


async def _async_engine(hass: HomeAssistant) -> HealEngine | None:
    engine = async_get_self_healing(hass)
    if engine is None:
        if not _config_dir_usable(hass):
            return None
        engine = HealEngine(hass)
        hass.data[DATA_SELF_HEALING_ENGINE] = engine
        try:
            await engine.async_start()
        except Exception:
            hass.data.pop(DATA_SELF_HEALING_ENGINE, None)
            with contextlib.suppress(Exception):
                await engine.async_stop()
            raise
        from .heal_views import async_register_self_healing_views

        async_register_self_healing_views(hass)
    return engine


async def async_setup_self_healing(hass: HomeAssistant, entry: Any) -> None:
    """Add a router at the end of its own setup; off, nothing is created
    (no store, no route).

    Called from the entry's ``async_setup_entry``, so the entry is still in
    SETUP_IN_PROGRESS (or LOADED on a later call); any other state is no
    router to add. The engine acts on it once it is LOADED. The switch is
    read again inside the lock: the options flow may have switched the
    module off while this setup waited (review of PR #78).
    """
    if not self_healing_enabled(hass):
        return
    if getattr(entry, "disabled_by", None) is not None:
        return
    if getattr(entry, "state", None) not in _SETUP_STATES:
        return
    async with _lock(hass):
        if not self_healing_enabled(hass):
            return
        engine = await _async_engine(hass)
        if engine is None:
            return
        await engine.async_add_entries([entry.entry_id])


async def async_release_self_healing(hass: HomeAssistant, entry_id: str) -> None:
    """Drop an unloaded router; after the last one stop and write."""
    async with _lock(hass):
        engine = async_get_self_healing(hass)
        if engine is None:
            return
        engine.remove_entry(entry_id)
        if engine.entries:
            return
        hass.data.pop(DATA_SELF_HEALING_ENGINE, None)
        await engine.async_stop()


async def async_apply_self_healing_option(hass: HomeAssistant, *, on: bool) -> None:
    """The options flow changed the switch (no reload); never raises."""
    try:
        async with _lock(hass):
            engine = async_get_self_healing(hass)
            if not on:
                if engine is not None:
                    hass.data.pop(DATA_SELF_HEALING_ENGINE, None)
                    await engine.async_stop()
                return
            loaded = _loaded_entry_ids(hass)
            if not loaded:
                return
            engine = await _async_engine(hass)
            if engine is None:
                return
            await engine.async_add_entries(loaded)
    except Exception as err:  # noqa: BLE001 - the form never fails because of it
        _LOGGER.warning("Self-Healing option not applied (%s)", type(err).__name__)


__all__ = [
    "DEFAULT_DECIDER",
    "MODULE",
    "OBSERVE_ACTION",
    "TICK_S",
    "WRITE_PATH_AVAILABLE",
    "DecisionContext",
    "HealDecider",
    "HealEngine",
    "ObserveOnlyDecider",
    "Plan",
    "Proposal",
    "async_apply_self_healing_option",
    "async_get_self_healing",
    "async_release_self_healing",
    "async_setup_self_healing",
    "count_by_state",
    "open_count",
    "self_healing_enabled",
]
