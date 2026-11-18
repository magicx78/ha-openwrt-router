"""RF findings as Core events (pure factories; nothing is sent).

Every factory returns a :class:`CoreEvent` of module ``wifi_rf`` below the
event prefix the Core assigns to it (``MODULE_EVENT_PREFIXES["wifi_rf"]``,
``wifi_rf.``). The later wiring hands it to the Core with
``api.emit(**emit_kwargs(event))`` after
``api.register_event_prefix("wifi_rf.", module="wifi_rf")``; the Core then
masks ``data`` again, stores it in the general audit ring (module types are
never ``security.*``) and publishes it.

Contract rules kept here:

- the radio of an event is the typed ``CoreEvent.radio_id`` (contract
  §12.1, #107), a kind of finding is ``classification`` and a confidence is
  ``confidence``; a client would be ``client_ref`` (Core pseudonym
  ``cli_<16 hex>``, :func:`.rf_privacy.client_ref`), never a MAC. No RF event
  names a client yet;
- ``data`` carries ids, codes and counters only (Core router ids under
  ``router_id``, UCI radio names under ``radio_id`` only where an event has
  several radios), never SSIDs, BSSIDs, MACs, channel parameters or user
  ids. It passes ``core_masking.mask_for_output`` here, and the tests show
  that pass leaves it unchanged, so the Core's second pass loses nothing;
- scan events stay in the general audit ring (``security_relevant`` False,
  no dedup key); the guard writes its own decisions to the security ring;
- who acted is the Core :class:`Actor` in ``CoreEvent.actor`` (the Core
  replaces its user id by a pseudonym on the bus and keeps it in the audit
  store); a user id is never copied into ``data``;
- ``router.forgotten`` is answered by :func:`forget_router`.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, Final

from .core_masking import mask_for_output
from .core_models import (
    EVENT_ID_PREFIX,
    EVENT_REF_FIELDS,
    MODULE_EVENT_PREFIXES,
    Actor,
    CoreEvent,
    CoreEventType,
    EventResult,
    VerifiedActor,
    binding_checksum,
    new_id,
)
from .net_events import Severity
from .rf_conflicts import Conflict, ConflictStatus
from .rf_identity import RadioRef, require_radio_id, require_router_id
from .rf_recommend import Recommendation
from .rf_scan_policy import ScanDecision
from .rf_utilization import UtilizationSummary

_LOGGER = logging.getLogger(__name__)

RF_MODULE: Final = "wifi_rf"
EVENT_PREFIX: Final = MODULE_EVENT_PREFIXES[RF_MODULE]
SCAN_ACTION_NAME: Final = f"{RF_MODULE}.scan"

EVENT_CHANNEL_CONFLICT: Final = f"{EVENT_PREFIX}channel_conflict_measured"
EVENT_UTILIZATION_HIGH: Final = f"{EVENT_PREFIX}channel_utilization_high"
EVENT_RECOMMENDATION_NEW: Final = f"{EVENT_PREFIX}recommendation_new"
EVENT_RECOMMENDATION_RESOLVED: Final = f"{EVENT_PREFIX}recommendation_resolved"
EVENT_SCAN_REQUESTED: Final = f"{EVENT_PREFIX}scan_requested"
EVENT_SCAN_REFUSED: Final = f"{EVENT_PREFIX}scan_refused"
EVENT_SCAN_EXECUTED: Final = f"{EVENT_PREFIX}scan_executed"
ALL_EVENT_TYPES: Final = (
    EVENT_CHANNEL_CONFLICT,
    EVENT_UTILIZATION_HIGH,
    EVENT_RECOMMENDATION_NEW,
    EVENT_RECOMMENDATION_RESOLVED,
    EVENT_SCAN_REQUESTED,
    EVENT_SCAN_REFUSED,
    EVENT_SCAN_EXECUTED,
)
# Length of the hashed dedup discriminators (sha256 hex prefix).
_DEDUP_LENGTH: Final = 32


def _event(
    event_type: str,
    *,
    now: datetime,
    data: Mapping[str, Any],
    router_id: str | None = None,
    severity: Severity = Severity.INFO,
    result: EventResult = EventResult.INFO,
    actor: Actor | None = None,
    correlation_id: str | None = None,
    dedup_key: str | None = None,
    radio_id: str | None = None,
    classification: str | None = None,
    confidence: float | None = None,
) -> CoreEvent:
    return CoreEvent(
        event_id=new_id(EVENT_ID_PREFIX),
        ts=now,
        type=event_type,
        source=RF_MODULE,
        severity=severity,
        result=result,
        router_id=router_id,
        actor=actor,
        correlation_id=correlation_id,
        dedup_key=dedup_key,
        data=mask_for_output(dict(data)),
        radio_id=radio_id,
        classification=classification,
        confidence=confidence,
    )


def _ref_data(ref: RadioRef) -> dict[str, str]:
    """A checked radio reference (``router_id``, ``radio_id``)."""
    return {
        "router_id": require_router_id(ref.router_id),
        "radio_id": require_radio_id(ref.radio_id),
    }


def _codes(evidence: Iterable[str]) -> list[str]:
    """Evidence codes without their values (``utilization:…`` → ``utilization``)."""
    return sorted({e.split(":", 1)[0] for e in evidence})


def _actor(actor: Actor | VerifiedActor) -> Actor:
    if isinstance(actor, VerifiedActor):
        return actor.actor
    if not isinstance(actor, Actor):
        raise TypeError("actor must be a Core Actor or VerifiedActor")
    return actor


def emit_kwargs(event: CoreEvent) -> dict[str, Any]:
    """Keyword arguments for ``AuditLog.emit`` / ``api.emit`` of ``event``.

    Includes every typed reference field (``core_models.EVENT_REF_FIELDS``).
    """
    return {
        "event_type": event.type,
        "source": event.source,
        "severity": event.severity,
        "result": event.result,
        "router_id": event.router_id,
        "entry_id": event.entry_id,
        "actor": event.actor,
        "correlation_id": event.correlation_id,
        "dedup_key": event.dedup_key,
        "data": event.data,
        "now": event.ts,
        **{name: getattr(event, name) for name in EVENT_REF_FIELDS},
    }


# --- findings ---------------------------------------------------------------


def channel_conflict_event(conflict: Conflict, *, now: datetime) -> CoreEvent | None:
    """Event for a measured channel conflict; None for other statuses.

    ``router_id`` is set when all members are on one router (cross-router
    conflicts name their routers in ``data.members``). The conflict kind is
    the typed ``classification``; with several radios there is no single
    ``radio_id``.
    """
    if conflict.status is not ConflictStatus.MEASURED:
        return None
    members = [_ref_data(m) for m in conflict.members]
    routers = {m["router_id"] for m in members}
    pairs = [(m["router_id"], m["radio_id"]) for m in members]
    return _event(
        EVENT_CHANNEL_CONFLICT,
        now=now,
        router_id=next(iter(routers)) if len(routers) == 1 else None,
        severity=Severity.WARNING,
        dedup_key=binding_checksum(str(conflict.kind), conflict.band, pairs)[
            :_DEDUP_LENGTH
        ],
        classification=conflict.kind.value,
        data={
            "band": conflict.band,
            "status": conflict.status.value,
            "members": members,
            "evidence_codes": _codes(conflict.evidence),
        },
    )


def channel_utilization_event(
    radio: RadioRef, summary: UtilizationSummary, *, now: datetime
) -> CoreEvent | None:
    """Event for sustained high channel utilization; None otherwise."""
    ref = _ref_data(radio)
    if summary.sustained_overload is not True:
        return None
    return _event(
        EVENT_UTILIZATION_HIGH,
        now=now,
        router_id=ref["router_id"],
        severity=Severity.WARNING,
        dedup_key=ref["radio_id"],
        radio_id=ref["radio_id"],
        data={
            "current_pct": summary.current,
            "mean_pct": summary.mean,
            "peak_pct": summary.peak,
            "phase_count": len(summary.phases),
            "valid_count": summary.valid_count,
            "coverage": summary.coverage,
        },
    )


def _target(rec: Recommendation) -> tuple[str | None, dict[str, str] | None]:
    if rec.target is None:
        return None, None
    if isinstance(rec.target, RadioRef):
        ref = _ref_data(rec.target)
        return ref["router_id"], ref
    router_id = require_router_id(rec.target)
    return router_id, {"router_id": router_id}


def recommendation_key(rec: Recommendation) -> str:
    """Identity of a recommendation: kind, problem, action and target.

    ``action_params`` and ``confidence`` are left out: a better channel or a
    higher confidence is the same recommendation, not a new one.
    """
    router_id, target = _target(rec)
    return binding_checksum(rec.kind, rec.problem, rec.action, router_id, target)[
        :_DEDUP_LENGTH
    ]


def _recommendation_event(
    event_type: str, rec: Recommendation, now: datetime
) -> CoreEvent:
    """The target goes into ``router_id``/``radio_id``, kind and confidence
    into ``classification``/``confidence`` (typed fields, not ``data``)."""
    router_id, target = _target(rec)
    return _event(
        event_type,
        now=now,
        router_id=router_id,
        radio_id=(target or {}).get("radio_id"),
        classification=rec.kind,
        confidence=rec.confidence,
        dedup_key=recommendation_key(rec),
        data={
            "problem": rec.problem,
            "action": rec.action,
            "scope": rec.scope,
            "priority": rec.priority,
            "risk": list(rec.risk),
        },
    )


def recommendation_events(
    previous: Sequence[Recommendation],
    current: Sequence[Recommendation],
    *,
    now: datetime,
) -> list[CoreEvent]:
    """Events for recommendations that are new or resolved since ``previous``."""
    before = {recommendation_key(r): r for r in previous}
    after = {recommendation_key(r): r for r in current}
    events = [
        _recommendation_event(EVENT_RECOMMENDATION_NEW, rec, now)
        for key, rec in after.items()
        if key not in before
    ]
    events.extend(
        _recommendation_event(EVENT_RECOMMENDATION_RESOLVED, rec, now)
        for key, rec in before.items()
        if key not in after
    )
    return events


# --- scan audit ---------------------------------------------------------------


def _scan_event(
    event_type: str,
    router_id: str,
    radio_id: str,
    *,
    actor: Actor | VerifiedActor,
    now: datetime,
    result: EventResult,
    correlation_id: str | None,
    severity: Severity = Severity.INFO,
    extra: Mapping[str, Any] | None = None,
) -> CoreEvent:
    return _event(
        event_type,
        now=now,
        router_id=require_router_id(router_id),
        severity=severity,
        result=result,
        actor=_actor(actor),
        correlation_id=correlation_id,
        radio_id=require_radio_id(radio_id),
        data={
            "action": SCAN_ACTION_NAME,
            **(extra or {}),
        },
    )


def scan_requested_event(
    router_id: str,
    radio_id: str,
    *,
    actor: Actor | VerifiedActor,
    now: datetime,
    correlation_id: str | None = None,
) -> CoreEvent:
    """Audit: an admin asked for a scan (waiting for the guard's approval)."""
    return _scan_event(
        EVENT_SCAN_REQUESTED,
        router_id,
        radio_id,
        actor=actor,
        now=now,
        result=EventResult.PENDING,
        correlation_id=correlation_id,
    )


def scan_refused_event(
    router_id: str,
    radio_id: str,
    decision: ScanDecision,
    *,
    actor: Actor | VerifiedActor,
    now: datetime,
    correlation_id: str | None = None,
) -> CoreEvent:
    """Audit: :func:`.rf_scan_policy.decide_scan` refused; reason is a ScanReason."""
    if decision.allowed:
        raise ValueError("an allowed scan decision is no refusal")
    return _scan_event(
        EVENT_SCAN_REFUSED,
        router_id,
        radio_id,
        actor=actor,
        now=now,
        result=EventResult.DENIED,
        correlation_id=correlation_id,
        extra={
            "reason": decision.reason.value,
            "retry_after_s": decision.retry_after_s,
        },
    )


def scan_executed_event(
    router_id: str,
    radio_id: str,
    *,
    actor: Actor | VerifiedActor,
    now: datetime,
    neighbor_count: int,
    own_count: int,
    correlation_id: str | None = None,
) -> CoreEvent:
    """Audit: a scan ran; only counts of the (already redacted) result."""
    return _scan_event(
        EVENT_SCAN_EXECUTED,
        router_id,
        radio_id,
        actor=actor,
        now=now,
        result=EventResult.SUCCESS,
        correlation_id=correlation_id,
        extra={"neighbor_count": int(neighbor_count), "own_count": int(own_count)},
    )


# --- router.forgotten -----------------------------------------------------------


def forgotten_router_id(event: CoreEvent) -> str | None:
    """Router id of a ``router.forgotten`` event, None for anything else."""
    if str(event.type) != CoreEventType.ROUTER_FORGOTTEN:
        return None
    try:
        return require_router_id(event.router_id)
    except ValueError:
        _LOGGER.debug("router.forgotten without a valid router id ignored")
        return None


def _belongs_to(key: Any, router_id: str) -> bool:
    if key == router_id:
        return True
    if isinstance(key, RadioRef):
        return key.router_id == router_id
    if isinstance(key, tuple):
        return any(_belongs_to(part, router_id) for part in key)
    return False


def forget_router(state: Mapping[Any, Any], router_id: str) -> dict[Any, Any]:
    """Return ``state`` without every entry of ``router_id`` (input unchanged).

    Keys may be the router id, a :class:`RadioRef` or a tuple containing
    either (e.g. ``(RadioRef, client_mac)``).
    """
    require_router_id(router_id)
    return {k: v for k, v in state.items() if not _belongs_to(k, router_id)}
