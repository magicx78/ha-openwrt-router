"""How an RF scan passes the Core guard (pure bridge; never scans, no api.py).

The scan is registered with the Core guard as plain data
(:data:`SCAN_ACTION`): ``wifi_rf.scan``, class ``critical``, admin users
only. Critical means "request + admin approval" (contract §6): a scan
makes the radio leave its channel or adds a temporary interface, so it is
treated like a change although it writes nothing. ``admin_user_only``
also keeps modules, automations and the system from requesting it
(plan decision Q3: only on an admin's button press).

Flow of the later wiring (nothing of it runs here)::

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
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Protocol

from .core_errors import (
    AuthorizationError,
    CapabilityUnavailableError,
    ConfigApiError,
    OperationInProgressError,
)
from .core_models import (
    ActionClass,
    VerifiedActor,
    binding_checksum,
    policy_denial_reason,
)
from .rf_capabilities import capability_name
from .rf_events import RF_MODULE, SCAN_ACTION_NAME
from .rf_identity import require_radio_key, require_router_id
from .rf_models import METRIC_SCAN
from .rf_scan_policy import ScanDecision, ScanReason, ScanRequest

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class RfAction:
    """One RF action as the Core guard registers it (data, no behaviour)."""

    name: str
    action_class: ActionClass
    admin_user_only: bool
    module: str = RF_MODULE

    @property
    def critical(self) -> bool:
        """True when the guard requires request + admin approval."""
        return self.action_class is ActionClass.CRITICAL


SCAN_ACTION: Final = RfAction(
    name=SCAN_ACTION_NAME, action_class=ActionClass.CRITICAL, admin_user_only=True
)
RF_ACTIONS: Final = (SCAN_ACTION,)

# Later RF reads that count as sensitive (plan document, section 9.3). They
# are reads, not guard actions: the wiring serves them to admin users only.
SENSITIVE_READS: Final[Mapping[str, str]] = {
    "neighbor_list": "scan result: other people's networks (digests, signal, "
    "channel) and the own BSSIDs",
    "client_rf": "per-client RF data (signal, retries, roaming, sticky) keyed "
    "by the client's MAC",
    "client_roam_history": "where a client was and when (movement profile)",
}


class _Guard(Protocol):
    def register_action(
        self,
        name: str,
        action_class: ActionClass,
        *,
        module: str,
        admin_user_only: bool = False,
    ) -> None: ...


def register_rf_actions(guard: _Guard) -> None:
    """Register :data:`RF_ACTIONS` with the Core guard (idempotent there)."""
    for action in RF_ACTIONS:
        guard.register_action(
            action.name,
            action.action_class,
            module=action.module,
            admin_user_only=action.admin_user_only,
        )


def scan_policy_denial(actor: object, *, now: datetime | None = None) -> str | None:
    """The Core guard's policy answer for :data:`SCAN_ACTION` (None = may ask).

    Same function and tables the guard uses once the action is registered.
    """
    return policy_denial_reason(
        SCAN_ACTION.name,
        actor,
        now=now,
        action_classes={SCAN_ACTION.name: SCAN_ACTION.action_class},
        admin_user_only=frozenset({SCAN_ACTION.name}),
        system_only=frozenset(),
    )


def scan_request_from_actor(
    actor: VerifiedActor, radio_key: str, *, requested_at: float, manual: bool = True
) -> ScanRequest:
    """Build the scan request; ``is_admin`` only from a Core-verified actor."""
    if not isinstance(actor, VerifiedActor):
        raise TypeError("a scan request needs a Core VerifiedActor")
    return ScanRequest(
        radio_key=require_radio_key(radio_key),
        requested_at=requested_at,
        manual=manual,
        is_admin=actor.is_admin,
    )


def scan_guard_request(router_id: str, radio_key: str) -> dict[str, str]:
    """Keyword arguments for ``guard.authorize`` (bound to router and radio).

    The checksum has the same parts the guard uses for its default binding,
    so an approval for one radio cannot be redeemed for another.
    """
    router_id = require_router_id(router_id)
    radio_key = require_radio_key(radio_key)
    return {
        "action": SCAN_ACTION.name,
        "router_id": router_id,
        "subject_id": radio_key,
        "checksum": binding_checksum(SCAN_ACTION.name, router_id, radio_key),
    }


_CAPABILITY_REASONS: Final = frozenset(
    {ScanReason.SCAN_UNSUPPORTED, ScanReason.SCAN_UNAVAILABLE}
)
# The radio is busy for a while (DFS check) or asked too often: try later.
_BUSY_REASONS: Final = frozenset(
    {ScanReason.CAC_ACTIVE, ScanReason.RATE_LIMIT_RADIO, ScanReason.RATE_LIMIT_ROUTER}
)


def scan_refusal_error(decision: ScanDecision, *, router_id: str) -> ConfigApiError:
    """The Core error a caller raises for a refused scan.

    unsupported/unavailable → CapabilityUnavailableError (``rf.metric.scan``);
    DFS check running and rate limits → OperationInProgressError (retryable,
    ``retry_after_s`` in details); every other refusal (not admin, automatic
    scans off, uplink radio, uplink/DFS state unknown) →
    AuthorizationError. ``details["reason"]`` is the ScanReason value.
    """
    if decision.allowed:
        raise ValueError("an allowed scan decision is no error")
    reason = decision.reason
    details: dict[str, Any] = {"reason": reason.value, "action": SCAN_ACTION.name}
    if reason in _CAPABILITY_REASONS:
        return CapabilityUnavailableError(
            capability=capability_name(METRIC_SCAN),
            reason=reason.value,
            router_id=router_id,
        )
    if reason in _BUSY_REASONS:
        details["retry_after_s"] = decision.retry_after_s
        return OperationInProgressError(
            f"Scan not possible now: {reason.value}",
            router_id=router_id,
            details=details,
        )
    return AuthorizationError(
        f"Scan refused: {reason.value}", router_id=router_id, details=details
    )
