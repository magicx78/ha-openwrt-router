"""How RF actions and reads pass the Core guard (pure bridge; never scans).

Everything the guard must know is plain data here, registered by
:func:`register_rf_actions` (no Home Assistant, no api.py):

- :data:`SCAN_ACTION`: ``wifi_rf.scan``, class ``critical``, admin users
  only. Critical means "request + admin approval" (contract §6): a scan
  makes the radio leave its channel or adds a temporary interface, so it
  is treated like a change although it writes nothing. ``admin_user_only``
  also keeps modules, automations and the system from requesting it (plan
  decision Q3: only on an admin's button press).
- :data:`SENSITIVE_READ_ACTIONS`: three reads with ``sensitive_read=True``
  (contract §6): a user must be a verified admin, modules and the system
  read as before.
- :data:`POLL_READS`: the periodic and setup reads (survey, assoclist,
  txpowerlist, freqlist). DECIDED (plan 9.3): class ``read``, no guard
  action; see the comment there.

Flow of the later scan wiring (nothing of it runs here)::

    verified = await api.guard.async_verify_actor(actor)
    decision = decide_scan(scan_request_from_actor(verified, radio, t), ...)
    if not decision.allowed:
        emit(scan_refused_event(...)); raise scan_refusal_error(decision, ...)
    binding = scan_guard_request(router_id, radio)
    first = api.guard.authorize(actor=verified, **binding)      # PENDING
    emit(scan_requested_event(...))
    api.guard.approve(first.approval_request.approval_id, actor=admin)
    # again, right before scanning (state may have changed meanwhile):
    decision = decide_scan(...)
    granted = api.guard.authorize(actor=verified, approval_id=..., **binding)
    api.guard.consume(granted.authorization, action=..., router_id=...,
                      checksum=binding["checksum"])
    ... the one scan ..., then emit(scan_executed_event(...))

This module imports only the Core's type module (``core_models``) and
``core_errors``; ``core_guard`` imports Home Assistant and is used by the
wiring, not here.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal, Protocol

from .core_errors import (
    AuthorizationError,
    CapabilityUnavailableError,
    ConfigApiError,
    RateLimitedError,
    SafetyRefusedError,
)
from .core_models import (
    ActionClass,
    RateLimit,
    VerifiedActor,
    binding_checksum,
    policy_denial_reason,
)
from .rf_capabilities import capability_name
from .rf_events import RF_MODULE, SCAN_ACTION_NAME
from .rf_identity import require_radio_id, require_router_id
from .rf_models import (
    METRIC_SCAN,
    SOURCE_IWINFO_ASSOCLIST,
    SOURCE_IWINFO_FREQLIST,
    SOURCE_IWINFO_SURVEY,
    SOURCE_IWINFO_TXPOWERLIST,
)
from .rf_scan_policy import (
    DEFAULT_MIN_GAP_PER_ROUTER_S,
    DEFAULT_MIN_INTERVAL_MANUAL_S,
    ScanDecision,
    ScanReason,
    ScanRequest,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class RfAction:
    """One RF action as the Core guard registers it (data, no behaviour)."""

    name: str
    action_class: ActionClass
    admin_user_only: bool = False
    sensitive_read: bool = False
    rate_limit: RateLimit | None = None
    module: str = RF_MODULE

    @property
    def critical(self) -> bool:
        """True when the guard requires request + admin approval."""
        return self.action_class is ActionClass.CRITICAL


SCAN_ACTION: Final = RfAction(
    name=SCAN_ACTION_NAME, action_class=ActionClass.CRITICAL, admin_user_only=True
)

# Reads that show more than a status (plan document, section 9.3); the
# Core guard lets only verified admin users (and modules/system) read them.
SENSITIVE_READ_ACTIONS: Final = (
    # scan result: other people's networks (pseudonyms, signal, channel)
    # and the own BSSIDs -- a location profile even without names
    RfAction(
        name=f"{RF_MODULE}.neighbor_list",
        action_class=ActionClass.READ,
        sensitive_read=True,
    ),
    # per-client RF data (signal, retries, roaming, sticky) of one device
    RfAction(
        name=f"{RF_MODULE}.client_rf",
        action_class=ActionClass.READ,
        sensitive_read=True,
    ),
    # where a client was and when: a movement profile between the APs
    RfAction(
        name=f"{RF_MODULE}.client_roam_history",
        action_class=ActionClass.READ,
        sensitive_read=True,
    ),
)
RF_ACTIONS: Final = (SCAN_ACTION, *SENSITIVE_READ_ACTIONS)


@dataclass(frozen=True)
class PollRead:
    """One router read RF makes on a schedule (data; not a guard action).

    ``min_interval_s`` is the time floor of a periodic read per radio or
    interface: the wiring must not read more often, also not on a manual
    refresh. Setup reads run at setup and after a radio change only (None).
    """

    name: str
    source: str
    cadence: Literal["periodic", "setup"]
    min_interval_s: float | None
    action_class: ActionClass = ActionClass.READ


# Every 5th poll of the 60 s coordinator (plan 8.2), never below 5 minutes.
POLL_READ_MIN_INTERVAL_S: Final = 300.0

# DECIDED (point 7 of the Core follow-up; plan 9.3): survey, assoclist,
# txpowerlist and freqlist stay class ``read`` and are no guard actions.
# - ``active`` in the contract (§6) is an action an actor triggers and the
#   guard authorizes; each grant writes ``core.active_action_granted`` to
#   the general audit ring, without dedup. Four reads per radio every
#   5 minutes on six routers would be about 144 entries an hour and wrap
#   the 1000-entry ring in under 7 hours, pushing out the Core's entries.
# - A Core rate limit would double the schedule below and, when the poll
#   jitters, turn a refused grant into a data gap.
# - The load is the same kind as today's: every ``iwinfo info`` already
#   triggers a survey and a station dump on each poll, unguarded (plan 8.1).
# - The ath10k risk (up to 3 s per survey dump) is handled by the schedule,
#   the capability gate and the coordinator throttle, not by an actor check.
# A later user-triggered "survey now" would be a new ``active`` action with
# a RateLimit; the radio scan stays ``critical``.
POLL_READS: Final = (
    PollRead(
        name=f"{RF_MODULE}.survey",
        source=SOURCE_IWINFO_SURVEY,
        cadence="periodic",
        min_interval_s=POLL_READ_MIN_INTERVAL_S,
    ),
    PollRead(
        name=f"{RF_MODULE}.assoclist",
        source=SOURCE_IWINFO_ASSOCLIST,
        cadence="periodic",
        min_interval_s=POLL_READ_MIN_INTERVAL_S,
    ),
    PollRead(
        name=f"{RF_MODULE}.txpowerlist",
        source=SOURCE_IWINFO_TXPOWERLIST,
        cadence="setup",
        min_interval_s=None,
    ),
    PollRead(
        name=f"{RF_MODULE}.freqlist",
        source=SOURCE_IWINFO_FREQLIST,
        cadence="setup",
        min_interval_s=None,
    ),
)


class _Guard(Protocol):
    def register_action(
        self,
        name: str,
        action_class: ActionClass,
        *,
        module: str,
        admin_user_only: bool = False,
        sensitive_read: bool = False,
        rate_limit: RateLimit | None = None,
    ) -> None: ...


def register_rf_actions(guard: _Guard) -> None:
    """Register :data:`RF_ACTIONS` with the Core guard (idempotent there)."""
    for action in RF_ACTIONS:
        guard.register_action(
            action.name,
            action.action_class,
            module=action.module,
            admin_user_only=action.admin_user_only,
            sensitive_read=action.sensitive_read,
            rate_limit=action.rate_limit,
        )


def rf_policy_denial(
    name: str, actor: object, *, now: datetime | None = None
) -> str | None:
    """The Core guard's policy answer for an RF action (None = may go on).

    Same function and tables the guard uses once :data:`RF_ACTIONS` are
    registered; an unknown name gives ``unknown_action``.
    """
    return policy_denial_reason(
        name,
        actor,
        now=now,
        action_classes={a.name: a.action_class for a in RF_ACTIONS},
        admin_user_only=frozenset(a.name for a in RF_ACTIONS if a.admin_user_only),
        system_only=frozenset(),
        sensitive_reads=frozenset(a.name for a in RF_ACTIONS if a.sensitive_read),
    )


def scan_policy_denial(actor: object, *, now: datetime | None = None) -> str | None:
    """The Core guard's policy answer for :data:`SCAN_ACTION` (None = may ask)."""
    return rf_policy_denial(SCAN_ACTION.name, actor, now=now)


def scan_request_from_actor(
    actor: VerifiedActor, radio_id: str, *, requested_at: float, manual: bool = True
) -> ScanRequest:
    """Build the scan request; ``is_admin`` only from a Core-verified actor."""
    if not isinstance(actor, VerifiedActor):
        raise TypeError("a scan request needs a Core VerifiedActor")
    return ScanRequest(
        radio_id=require_radio_id(radio_id),
        requested_at=requested_at,
        manual=manual,
        is_admin=actor.is_admin,
    )


def scan_guard_request(router_id: str, radio_id: str) -> dict[str, str]:
    """Keyword arguments for ``guard.authorize`` (bound to router and radio).

    The checksum has the same parts the guard uses for its default binding,
    so an approval for one radio cannot be redeemed for another.
    """
    router_id = require_router_id(router_id)
    radio_id = require_radio_id(radio_id)
    return {
        "action": SCAN_ACTION.name,
        "router_id": router_id,
        "subject_id": radio_id,
        "checksum": binding_checksum(SCAN_ACTION.name, router_id, radio_id),
    }


_CAPABILITY_REASONS: Final = frozenset(
    {ScanReason.SCAN_UNSUPPORTED, ScanReason.SCAN_UNAVAILABLE}
)
# Unsafe for the link or a DFS channel; no reliable time to try again.
_SAFETY_REASONS: Final = frozenset(
    {
        ScanReason.UPLINK_RADIO,
        ScanReason.UPLINK_UNKNOWN,
        ScanReason.CAC_ACTIVE,
        ScanReason.CAC_UNKNOWN,
    }
)
# Full interval when the policy names no wait (never a retry right away).
_RATE_LIMIT_FALLBACK_S: Final = {
    ScanReason.RATE_LIMIT_RADIO: DEFAULT_MIN_INTERVAL_MANUAL_S,
    ScanReason.RATE_LIMIT_ROUTER: DEFAULT_MIN_GAP_PER_ROUTER_S,
}


def _retry_after(decision: ScanDecision) -> float:
    wait = decision.retry_after_s
    if wait is None or not math.isfinite(wait) or wait < 0:
        return _RATE_LIMIT_FALLBACK_S[decision.reason]
    return float(wait)


def scan_refusal_error(decision: ScanDecision, *, router_id: str) -> ConfigApiError:
    """The Core error a caller raises for a refused scan.

    - unsupported / unavailable -> ``CapabilityUnavailableError``
      (``rf.metric.scan``);
    - uplink radio, uplink state unknown, DFS check running or its state
      unknown -> ``SafetyRefusedError`` (never retryable, ``reason`` is the
      ScanReason value);
    - rate limit per radio or router -> ``RateLimitedError`` (retryable;
      ``retry_after`` from the policy, else the full interval);
    - not an admin, automatic scans off -> ``AuthorizationError``.

    ``details["reason"]`` is the ScanReason value in every case.
    """
    if decision.allowed:
        raise ValueError("an allowed scan decision is no error")
    reason = decision.reason
    details = {"reason": reason.value, "action": SCAN_ACTION.name}
    if reason in _CAPABILITY_REASONS:
        return CapabilityUnavailableError(
            capability=capability_name(METRIC_SCAN),
            reason=reason.value,
            router_id=router_id,
        )
    if reason in _SAFETY_REASONS:
        return SafetyRefusedError(
            f"Scan refused for safety: {reason.value}",
            reason=reason.value,
            router_id=router_id,
            details=details,
        )
    if reason in _RATE_LIMIT_FALLBACK_S:
        return RateLimitedError(
            f"Scan rate limit: {reason.value}",
            retry_after=_retry_after(decision),
            router_id=router_id,
            details=details,
        )
    return AuthorizationError(
        f"Scan refused: {reason.value}", router_id=router_id, details=details
    )
