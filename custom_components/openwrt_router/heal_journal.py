"""Self-Healing (Phase 7), package K1: the journal of record transitions.

Developer document: ``docs/self-healing.md`` §11 (entities and the event)
and §12 (audit, Time Machine, Security).

**What it does.** The engine (``heal_engine``) hands every record of its
store to :meth:`HealJournal.sweep` after each incident, each tick, its start
and each added router. The journal compares a record's history with the
length it has seen and writes, for every new history entry (one state
change), exactly:

* one audit entry through the core's audit log (``ConfigurationApi.emit``),
  type ``self_healing.action_<to_state>`` (:data:`AUDIT_TYPES`, one per
  state), source ``self_healing``, correlation id the record's id. The data
  are codes, ids and numbers only (:data:`AUDIT_DATA_KEYS`); the audit
  time is the time of writing, the transition's own time is ``at``;
* at most one Home Assistant event ``openwrt_router_remediation_event``
  (:data:`EVENT_REMEDIATION`) for the states of :data:`EVENT_STATES`, with
  ids, codes, states, the risk class and the core router id only
  (:data:`EVENT_PAYLOAD_KEYS`); never an address, a host or client name, a
  secret or configuration content. At most :data:`EVENT_RATE_MAX` events
  in :data:`EVENT_RATE_WINDOW_S` seconds; the rest are dropped and counted
  (the audit entry is still written);
* one dispatcher signal (:data:`SIGNAL_SELF_HEALING`) per sweep with a
  change, so the read-only entities (``heal_entities``) write their state.

A sweep without a new history entry writes nothing: no audit entry per tick
and none for a decision that changed nothing. A record seen for the first
time is journaled from its first entry; at the start the journal takes the
stored lengths as seen, except the one entry the restart rule added to an
interrupted record (``LoadResult.recovered``).

**Without the core** (not set up yet, or its prefix refused) audit entries
wait in a bounded queue (:data:`AUDIT_QUEUE_MAX`, the oldest drop first,
counted) and are written once the engine binds the core; such an entry
carries ``delayed`` True when it is written more than :data:`DELAYED_S`
after its transition. Every failure is counted and logged by type only;
nothing here raises into the engine.

**Origin.** Events are fired by this integration inside Home Assistant
(``EventOrigin.local``) and only for transitions of the engine's own store;
the journal listens to no event and never fires one again that came from
outside (the engine ignores remote incident announcements).
"""

from __future__ import annotations

import contextlib
import logging
import math
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final

from homeassistant.core import EventOrigin, HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import DOMAIN
from .heal_model import ActionState, HistoryEntry, RemediationAction

_LOGGER = logging.getLogger(__name__)

S = ActionState

MODULE: Final = "self_healing"
# The audit prefix of the module (design §9; the record ids use ``rem_``).
EVENT_PREFIX: Final = "self_healing."
# The one Home Assistant event of the module (design §8).
EVENT_REMEDIATION: Final = f"{DOMAIN}_remediation_event"
# Dispatcher signal for the read-only entities (no payload).
SIGNAL_SELF_HEALING: Final = f"{DOMAIN}_self_healing_update"
# At most this many events in the sliding window; the rest are dropped.
EVENT_RATE_MAX: Final = 30
EVENT_RATE_WINDOW_S: Final = 60.0
# Audit entries waiting for the core (the oldest drop first).
AUDIT_QUEUE_MAX: Final = 100
# An audit entry written later than this after its transition is delayed.
DELAYED_S: Final = 5.0

# One audit type per state the record entered (closed set).
AUDIT_TYPES: Final[Mapping[ActionState, str]] = MappingProxyType(
    {state: f"{EVENT_PREFIX}action_{state.value}" for state in ActionState}
)
# Audit-mandatory (never deduplicated): every state from the approval on.
MANDATORY_STATES: Final = frozenset(
    {
        S.APPROVED,
        S.REJECTED,
        S.EXECUTING,
        S.VERIFYING,
        S.RESOLVED,
        S.FAILED,
        S.ROLLBACK_PENDING,
        S.ROLLING_BACK,
        S.ROLLED_BACK,
        S.ESCALATED,
        S.MANUAL_RECOVERY_REQUIRED,
    }
)
MANDATORY_TYPES: Final = tuple(sorted(AUDIT_TYPES[state] for state in MANDATORY_STATES))
# On the security ring: the two states that change a router (execution).
SECURITY_STATES: Final = frozenset({S.EXECUTING, S.ROLLING_BACK})
# (severity, result) of the audit entry per state entered.
AUDIT_LEVEL: Final[Mapping[ActionState, tuple[str, str]]] = MappingProxyType(
    {
        S.DETECTED: ("info", "info"),
        S.ANALYZED: ("info", "info"),
        S.PROPOSED: ("info", "info"),
        S.PREFLIGHT: ("info", "pending"),
        S.WAITING_APPROVAL: ("info", "pending"),
        S.APPROVED: ("info", "success"),
        S.REJECTED: ("info", "denied"),
        S.CANCELLED: ("info", "info"),
        S.EXECUTING: ("info", "pending"),
        S.VERIFYING: ("info", "pending"),
        S.RESOLVED: ("info", "success"),
        S.FAILED: ("warning", "failure"),
        S.ROLLBACK_PENDING: ("warning", "pending"),
        S.ROLLING_BACK: ("warning", "pending"),
        S.ROLLED_BACK: ("warning", "failure"),
        S.ESCALATED: ("warning", "failure"),
        S.MANUAL_RECOVERY_REQUIRED: ("critical", "failure"),
    }
)
AUDIT_DATA_KEYS: Final = (
    "action_id",
    "action_type",
    "actor",
    "at",
    "delayed",
    "from_state",
    "incident_id",
    "incident_type",
    "outcome",
    "reason",
    "risk_class",
    "to_state",
)

# The states of the event (design §8) and the state entered for each.
EVENT_STATES: Final = (
    "proposed",
    "approval_required",
    "started",
    "succeeded",
    "failed",
    "rollback_started",
    "rollback_failed",
    "manual_recovery_required",
    "escalated",
)
_EVENT_OF: Final[Mapping[ActionState, str]] = MappingProxyType(
    {
        S.PROPOSED: "proposed",
        S.WAITING_APPROVAL: "approval_required",
        S.EXECUTING: "started",
        S.RESOLVED: "succeeded",
        S.FAILED: "failed",
        S.ROLLING_BACK: "rollback_started",
        S.ESCALATED: "escalated",
        S.MANUAL_RECOVERY_REQUIRED: "manual_recovery_required",
    }
)
EVENT_PAYLOAD_KEYS: Final = (
    "action_id",
    "action_type",
    "actor",
    "device_id",
    "from_state",
    "incident_id",
    "incident_type",
    "outcome",
    "reason",
    "risk_class",
    "router_id",
    "state",
    "to_state",
    "ts",
)

JOURNAL_COUNTERS: Final = (
    "transitions",
    "events_fired",
    "events_suppressed",
    "events_failed",
    "audit_written",
    "audit_failed",
    "audit_queued",
    "audit_dropped",
    "audit_unavailable",
    "signals",
)


def event_state(from_state: ActionState | None, to_state: ActionState) -> str | None:
    """The event state of one transition (None: no event)."""
    if to_state is S.MANUAL_RECOVERY_REQUIRED and from_state is S.ROLLING_BACK:
        return "rollback_failed"
    return _EVENT_OF.get(to_state)


def _token(value: Any) -> str | None:
    """An id the core accepts as a reference token, else None."""
    if not isinstance(value, str):
        return None
    try:
        from .core_models import check_token

        check_token("ref", value)
    except (TypeError, ValueError):
        return None
    return value


def _ts(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


@dataclass(frozen=True, slots=True)
class _Entry:
    """One audit entry waiting to be written."""

    event_type: str
    router_id: str
    correlation_id: str
    incident_ref: str | None
    severity: str
    result: str
    security_relevant: bool
    data: Mapping[str, Any]
    at: float


def _facts(
    action: RemediationAction, entry: HistoryEntry, latest: bool
) -> dict[str, Any]:
    """Codes of one transition. The record's decision and risk belong to its
    newest entry only: an earlier step had another (or none)."""
    decision = action.decision
    return {
        "action_id": action.action_id,
        "action_type": action.action_type,
        "actor": entry.actor.value,
        "from_state": None if entry.from_state is None else entry.from_state.value,
        "incident_id": _token(action.incident_id),
        "incident_type": action.incident_type,
        "outcome": (
            decision.outcome.value if latest and decision is not None else None
        ),
        "reason": entry.reason,
        "risk_class": int(action.risk.risk_class) if latest else None,
        "to_state": entry.to_state.value,
    }


class HealJournal:
    """Audit entries, the bus event and the entity signal of one engine."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        """Nothing is attached before :meth:`start`."""
        self.hass = hass
        self.clock = clock
        self.monotonic = monotonic
        self.started = False
        self.closed = False
        # changes once per sweep with a new transition (entities' cache key)
        self.version = 0
        self.counters: dict[str, int] = dict.fromkeys(JOURNAL_COUNTERS, 0)
        self._seen: dict[str, int] = {}
        self._api: Any = None
        self._unsubs: list[Callable[[], None]] = []
        self._queue: deque[_Entry] = deque()
        self._fired: deque[float] = deque()

    # -- life cycle --------------------------------------------------------------------

    def start(
        self, actions: Mapping[str, RemediationAction], recovered: Iterable[str] = ()
    ) -> None:
        """The stored records are known: only later entries are journaled,
        and the restart rule's entry of each recovered record."""
        again = set(recovered)
        for action_id, action in actions.items():
            n = len(action.history)
            self._seen[action_id] = n - 1 if action_id in again and n > 0 else n
        self.started = True

    def bind(self, api: Any) -> None:
        """The core is there: register the prefix, write what waited."""
        if api is None or self._api is not None or self.closed:
            return
        unsubs: list[Callable[[], None]] = []
        try:
            unsubs.append(api.register_event_prefix(EVENT_PREFIX, module=MODULE))
            unsubs.append(
                api.register_audit_mandatory_types(MANDATORY_TYPES, module=MODULE)
            )
        except Exception as err:  # noqa: BLE001 - no audit, the rest goes on
            for unsub in reversed(unsubs):
                with contextlib.suppress(Exception):
                    unsub()
            self.counters["audit_unavailable"] += 1
            _LOGGER.debug("Self-Healing audit not bound (%s)", type(err).__name__)
            return
        self._api = api
        self._unsubs = unsubs
        while self._queue:
            self._write(self._queue.popleft())

    def close(self) -> None:
        """Detach from the core (its entries stay in the audit log)."""
        self.closed = True
        for unsub in reversed(self._unsubs):
            with contextlib.suppress(Exception):
                unsub()
        self._unsubs.clear()
        self._api = None
        self._queue.clear()
        self._seen.clear()

    # -- journaling --------------------------------------------------------------------

    def sweep(
        self,
        actions: Mapping[str, RemediationAction],
        device_id_of: Callable[[str], str | None] | None = None,
    ) -> int:
        """Journal every history entry not seen yet; the number journaled.

        ``device_id_of``: the HA device id of a core router id (None when
        unknown); read only when an event is fired.
        """
        if not self.started or self.closed:
            return 0
        new: list[tuple[float, str, int, RemediationAction, HistoryEntry]] = []
        for action_id, action in list(actions.items()):
            history = action.history
            seen = self._seen.get(action_id, 0)
            if len(history) < seen:
                # never shorter in the model; take it as seen, invent nothing
                self._seen[action_id] = len(history)
                continue
            for index in range(seen, len(history)):
                entry = history[index]
                new.append((entry.ts, action_id, index, action, entry))
            self._seen[action_id] = len(history)
        for gone in [k for k in self._seen if k not in actions]:
            del self._seen[gone]  # evicted or pruned: bounded by the store
        if not new:
            return 0
        new.sort(key=lambda item: (item[0], item[1], item[2]))
        for _ts_, _id, index, action, entry in new:
            latest = index == len(action.history) - 1
            self.counters["transitions"] += 1
            self._audit(action, entry, latest)
            self._event(action, entry, latest, device_id_of)
        self.version += 1
        self.signal()
        return len(new)

    def signal(self) -> None:
        """Tell the read-only entities to write their state (no payload)."""
        if self.closed:
            return
        try:
            async_dispatcher_send(self.hass, SIGNAL_SELF_HEALING)
            self.counters["signals"] += 1
        except Exception as err:  # noqa: BLE001 - the entities update on the tick
            _LOGGER.debug("Self-Healing signal failed (%s)", type(err).__name__)

    def _audit(
        self, action: RemediationAction, entry: HistoryEntry, latest: bool
    ) -> None:
        severity, result = AUDIT_LEVEL[entry.to_state]
        data = _facts(action, entry, latest)
        data["at"] = _ts(entry.ts)
        item = _Entry(
            event_type=AUDIT_TYPES[entry.to_state],
            router_id=action.router_id,
            correlation_id=action.action_id,
            incident_ref=data["incident_id"],
            severity=severity,
            result=result,
            security_relevant=entry.to_state in SECURITY_STATES,
            data=MappingProxyType(data),
            at=entry.ts,
        )
        if self._api is None:
            self.counters["audit_queued"] += 1
            self._queue.append(item)
            while len(self._queue) > AUDIT_QUEUE_MAX:
                self._queue.popleft()
                self.counters["audit_dropped"] += 1
            return
        self._write(item)

    def _write(self, item: _Entry) -> None:
        try:
            from .core_models import Actor, EventResult, Severity

            data = dict(item.data)
            data["delayed"] = bool(self.clock() - item.at > DELAYED_S)
            self._api.emit(
                item.event_type,
                source=MODULE,
                router_id=item.router_id,
                severity=Severity(item.severity),
                result=EventResult(item.result),
                actor=Actor.for_module(MODULE),
                correlation_id=item.correlation_id,
                data=data,
                security_relevant=item.security_relevant,
                incident_ref=item.incident_ref,
            )
        except Exception as err:  # noqa: BLE001 - counted, the engine goes on
            self.counters["audit_failed"] += 1
            _LOGGER.debug("Self-Healing audit entry failed (%s)", type(err).__name__)
            return
        self.counters["audit_written"] += 1

    def _allowed(self) -> bool:
        """One more event inside the rate bound (sliding window)."""
        now = float(self.monotonic())
        fired = self._fired
        while fired and now - fired[0] >= EVENT_RATE_WINDOW_S:
            fired.popleft()
        if len(fired) >= EVENT_RATE_MAX:
            return False
        fired.append(now)
        return True

    def _event(
        self,
        action: RemediationAction,
        entry: HistoryEntry,
        latest: bool,
        device_id_of: Callable[[str], str | None] | None,
    ) -> None:
        state = event_state(entry.from_state, entry.to_state)
        if state is None:
            return
        if not self._allowed():
            self.counters["events_suppressed"] += 1
            return
        device_id: str | None = None
        if device_id_of is not None:
            try:
                found = device_id_of(action.router_id)
                device_id = found if isinstance(found, str) and found else None
            except Exception:  # noqa: BLE001 - unknown device
                device_id = None
        payload = _facts(action, entry, latest)
        payload.update(
            state=state,
            router_id=action.router_id,
            device_id=device_id,
            ts=_ts(entry.ts),
        )
        try:
            self.hass.bus.async_fire(
                EVENT_REMEDIATION, payload, origin=EventOrigin.local
            )
        except Exception as err:  # noqa: BLE001 - counted
            self.counters["events_failed"] += 1
            _LOGGER.debug("Self-Healing event failed (%s)", type(err).__name__)
            return
        self.counters["events_fired"] += 1

    # -- reading -----------------------------------------------------------------------

    @property
    def audit_bound(self) -> bool:
        """The core's audit log takes the entries."""
        return self._api is not None

    def stats(self) -> dict[str, Any]:
        """Counters and sizes (no ids)."""
        return {
            "audit_bound": self._api is not None,
            "audit_waiting": len(self._queue),
            "records_seen": len(self._seen),
            **self.counters,
        }


def device_id_for_entry(hass: HomeAssistant, entry_id: str | None) -> str | None:
    """The HA device id of a router entry (memory only; None if unknown)."""
    if not entry_id:
        return None
    try:
        device = dr.async_get(hass).async_get_device(identifiers={(DOMAIN, entry_id)})
    except Exception:  # noqa: BLE001 - no registry (tests, shutdown)
        return None
    found = getattr(device, "id", None)
    return found if isinstance(found, str) and found else None


__all__ = [
    "AUDIT_DATA_KEYS",
    "AUDIT_LEVEL",
    "AUDIT_QUEUE_MAX",
    "AUDIT_TYPES",
    "DELAYED_S",
    "EVENT_PAYLOAD_KEYS",
    "EVENT_PREFIX",
    "EVENT_RATE_MAX",
    "EVENT_RATE_WINDOW_S",
    "EVENT_REMEDIATION",
    "EVENT_STATES",
    "JOURNAL_COUNTERS",
    "MANDATORY_STATES",
    "MANDATORY_TYPES",
    "MODULE",
    "SECURITY_STATES",
    "SIGNAL_SELF_HEALING",
    "HealJournal",
    "device_id_for_entry",
    "event_state",
]
