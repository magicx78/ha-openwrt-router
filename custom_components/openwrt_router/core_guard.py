"""Action guard of the enterprise core (contract §6).

One :class:`ActionGuard` per core decides every mutating or critical
action, keeps the in-memory approval requests and the LEDGER of every
:class:`WriteAuthorization` it minted. Nothing else mints authorizations
that the core accepts: :meth:`ActionGuard.consume` rejects every
authorization whose id is not in the ledger (``unknown_authorization``).

Rules (all from ``core_models``, this module only applies them):

* Actors are re-verified against ``hass.auth`` (:meth:`async_verify_actor`);
  a caller-supplied ``Actor.is_admin`` is ignored.
* ``authorize`` is synchronous and writes exactly one audit entry: a
  denial (``security.authorization_denied``), a new approval request
  (``security.approval_requested`` / ``configuration.restore_requested``)
  or a granted authorization (``security.authorization_granted``).
* Critical actions need a request, an admin approval and a second
  ``authorize`` by the SAME principal (``check_redeem``); approvals live
  15 minutes, are single use, bound to a checksum and do not survive a
  restart or an unload (they are expired and audited on close).
* ``consume`` is synchronous on the event loop: ledger, single use,
  expiry and binding; every attempt is audited.
* ACTIVE actions (B5: scan, ping, survey; nothing configured) follow the
  mutating policy without approval; a grant is audited as
  ``core.active_action_granted`` on the general ring. An optional
  :class:`RateLimit` per (action, router) refuses further grants with
  reason ``rate_limited`` (``core.action_rate_limited``, general ring,
  deduplicated per window, ``retry_after`` on the decision).

Threat model (§6.1): in-process code is trusted; the guard defends against
users, automations and module bugs, not against a module that imports
private helpers on purpose.
"""

from __future__ import annotations

import contextlib
import logging
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from homeassistant.core import Context, HomeAssistant, callback

from .core_audit import CORE_SOURCE, AuditLog
from .core_errors import (
    ApprovalInvalidError,
    ApprovalRequiredError,
    AuthorizationError,
    ConfigApiError,
    RateLimitedError,
)
from .core_models import (
    ACTION_CLASSES,
    ADMIN_USER_ONLY_ACTIONS,
    APPROVAL_ID_PREFIX,
    APPROVAL_TTL,
    CORE_EVENT_NAMESPACES,
    SYSTEM_ONLY_ACTIONS,
    WRITE_AUTHORIZATION_TTL,
    ActionClass,
    Actor,
    ApprovalRequest,
    ApprovalStatus,
    AuthorizationDecision,
    CoreEventType,
    DecisionState,
    EventResult,
    GuardedAction,
    RateLimit,
    Severity,
    VerifiedActor,
    WriteAuthorization,
    _mint_write_authorization,
    approver_denial_reason,
    async_actor_from_context,
    binding_checksum,
    check_redeem,
    new_id,
    policy_denial_reason,
    utcnow,
)
from .core_models import FLEET_ROUTER_ID as _FLEET_ROUTER_ID
from .core_models import async_verify_actor as _async_verify_actor

# Re-exported: the one fleet id lives in core_models (contract §4.1).
FLEET_ROUTER_ID = _FLEET_ROUTER_ID

_LOGGER = logging.getLogger(__name__)

# Decided approvals stay readable (get_approval) this long after expiry.
_APPROVAL_KEEP = APPROVAL_TTL * 2
# Ledger entries stay this long after expiry, so a late reuse is reported
# precisely (already_used / expired) instead of unknown_authorization.
_LEDGER_GRACE = WRITE_AUTHORIZATION_TTL
# Actions whose approval steps use the restore_* event types (§12.3).
_RESTORE_TYPES: Mapping[str, CoreEventType] = {
    "requested": CoreEventType.RESTORE_REQUESTED,
    "approved": CoreEventType.RESTORE_APPROVED,
    "rejected": CoreEventType.RESTORE_REJECTED,
}
_APPROVAL_TYPES: Mapping[str, CoreEventType] = {
    "requested": CoreEventType.APPROVAL_REQUESTED,
    "approved": CoreEventType.APPROVAL_APPROVED,
    "rejected": CoreEventType.APPROVAL_REJECTED,
}
# Open (pending or approved, not yet used) approvals: per principal and in
# total. Above it a new request is denied (audited, reason below) instead of
# growing the guard and the request data kept for it (security review #4).
MAX_OPEN_APPROVALS_PER_PRINCIPAL = 20
MAX_OPEN_APPROVALS_TOTAL = 200
REASON_TOO_MANY_OPEN = "too_many_open_approvals"
REASON_TOO_MANY_OPEN_TOTAL = "too_many_open_approvals_total"
# Follow-up B5: an active action over its RateLimit.
REASON_RATE_LIMITED = "rate_limited"
# Open rate windows (action, router_id) kept at most; above it the oldest
# window is dropped (counter rate_windows_dropped, debug log).
MAX_RATE_WINDOWS = 1024


@dataclass(slots=True)
class _LedgerEntry:
    """One minted authorization (the object itself, not a copy)."""

    authorization: WriteAuthorization
    used: bool = False


def error_for_decision(decision: AuthorizationDecision) -> ConfigApiError:
    """The exception a caller raises for a non-approved decision.

    PENDING (redeem of a still pending approval) -> ApprovalRequiredError;
    a denial from an approval check -> ApprovalInvalidError; a rate limited
    active action -> RateLimitedError (``retry_after``); any other
    denial -> AuthorizationError. ``details["reason"]`` and ``audit_id``
    are always set.
    """
    reason = decision.reason or "denied"
    details: dict[str, Any] = {"reason": reason, "audit_id": decision.audit_id}
    if decision.approval_request is not None:
        details["approval_id"] = decision.approval_request.approval_id
    if reason == REASON_RATE_LIMITED:
        return RateLimitedError(
            f"Action {decision.action} is rate limited",
            retry_after=decision.retry_after or 0.0,
            router_id=decision.router_id,
            details={**details, "action": str(decision.action)},
        )
    if decision.state is DecisionState.PENDING or reason == "pending":
        return ApprovalRequiredError(
            "Approval is still pending", router_id=decision.router_id, details=details
        )
    if reason in _APPROVAL_REASONS:
        return ApprovalInvalidError(
            f"Approval cannot be redeemed: {reason}",
            router_id=decision.router_id,
            details=details,
        )
    return AuthorizationError(
        f"Action {decision.action} denied: {reason}",
        router_id=decision.router_id,
        details=details,
    )


_APPROVAL_REASONS = frozenset(
    {
        "unknown_approval",
        "rejected",
        "expired",
        "used",
        "action_mismatch",
        "router_mismatch",
        "checksum_mismatch",
        "not_requester",
        "not_pending",
    }
)


def raise_for_decision(decision: AuthorizationDecision) -> WriteAuthorization:
    """Return the authorization of an approved decision, else raise."""
    if decision.state is DecisionState.APPROVED and decision.authorization:
        return decision.authorization
    raise error_for_decision(decision)


class ActionGuard:
    """Implements ``ActionGuardProtocol`` (one per core, never global)."""

    def __init__(
        self,
        hass: HomeAssistant,
        audit: AuditLog,
        *,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        """Create the guard; ``clock`` is the time source (tests move it)."""
        self.hass = hass
        self.audit = audit
        self._clock = clock
        self._action_classes: dict[str, ActionClass] = dict(ACTION_CLASSES)
        self._admin_only: set[str] = {str(a) for a in ADMIN_USER_ONLY_ACTIONS}
        self._system_only: set[str] = {str(a) for a in SYSTEM_ONLY_ACTIONS}
        self._action_owner: dict[str, str] = {}
        self._sensitive_reads: set[str] = set()
        self._rate_limits: dict[str, RateLimit] = {}
        # (action, router_id) -> grant times inside the window (oldest first)
        self._calls: dict[tuple[str, str], deque[datetime]] = {}
        self._approvals: dict[str, ApprovalRequest] = {}
        self._ledger: dict[str, _LedgerEntry] = {}
        self._listeners: list[Callable[[str, str], None]] = []
        self.closed = False
        self.stats: dict[str, int] = {
            "decisions_approved": 0,
            "decisions_denied": 0,
            "decisions_pending": 0,
            "consumed": 0,
            "consume_denied": 0,
            "approvals_approved": 0,
            "approvals_rejected": 0,
            "approvals_expired": 0,
            "approvals_dropped": 0,
            "ledger_pruned": 0,
            "actor_rejected": 0,
            "audit_errors": 0,
            "approvals_capped": 0,
            "listener_errors": 0,
            "active_granted": 0,
            "rate_limited": 0,
            "rate_windows_dropped": 0,
        }

    # -- actors ----------------------------------------------------------------------

    def now(self) -> datetime:
        """The guard's current time (aware UTC)."""
        return self._clock()

    async def async_verify_actor(self, actor: Actor) -> VerifiedActor:
        """Re-check ``actor`` against hass.auth; its ``is_admin`` is ignored.

        An unknown or inactive user is audited and raises AuthorizationError
        (``unknown_user``).
        """
        if not isinstance(actor, Actor):
            self._deny_audit("-", "verify_actor", None, "unverified_actor")
            raise AuthorizationError(
                "Not an Actor", details={"reason": "unverified_actor"}
            )
        try:
            return await _async_verify_actor(self.hass, actor, now=self.now())
        except AuthorizationError as err:
            self.stats["actor_rejected"] += 1
            self._deny_audit(
                "-", "verify_actor", actor, str(err.details.get("reason", "denied"))
            )
            raise

    async def async_resolve_actor(
        self, context: Context | None, *, module: str | None = None
    ) -> VerifiedActor:
        """Actor from an HA Context, verified."""
        return await self.async_verify_actor(
            await async_actor_from_context(self.hass, context, module)
        )

    # -- actions ---------------------------------------------------------------------

    def action_class(self, action: str) -> ActionClass | None:
        """Class of a known action, None if unknown."""
        return self._action_classes.get(str(action))

    def register_action(
        self,
        name: str,
        action_class: ActionClass,
        *,
        module: str,
        admin_user_only: bool = False,
        sensitive_read: bool = False,
        rate_limit: RateLimit | None = None,
    ) -> None:
        """Register ``<module>.<action>`` (below the module's own prefix).

        ``sensitive_read`` (READ only): a user must be a verified admin;
        module, system and automation actors read as before.
        ``rate_limit`` (ACTIVE only): at most ``max_calls`` grants per
        router within ``per``. Re-registering the same definition is a
        no-op; a different one, a name outside ``<module>.``, a core action
        or a core namespace raises ValueError.
        """
        name = str(name)
        action_class = ActionClass(action_class)
        if not isinstance(sensitive_read, bool):
            raise TypeError("sensitive_read must be a bool")
        if sensitive_read and action_class is not ActionClass.READ:
            raise ValueError("sensitive_read is only for read actions")
        if rate_limit is not None:
            if not isinstance(rate_limit, RateLimit):
                raise TypeError("rate_limit must be a RateLimit")
            if action_class is not ActionClass.ACTIVE:
                raise ValueError("rate_limit is only for active actions")
        if not isinstance(module, str) or not module or "." in module:
            raise ValueError("module must be a plain, non-empty name")
        prefix = f"{module}."
        if not name.startswith(prefix) or len(name) == len(prefix):
            raise ValueError(f"module actions must be named {prefix}<action>")
        if name.startswith(CORE_EVENT_NAMESPACES) or name in set(GuardedAction):
            raise ValueError(f"{name} is reserved for the core")
        known = self._action_classes.get(name)
        if known is not None:
            same = (
                self._action_owner.get(name) == module
                and known is action_class
                and (name in self._admin_only) == admin_user_only
                and (name in self._sensitive_reads) == sensitive_read
                and self._rate_limits.get(name) == rate_limit
            )
            if same:
                return
            raise ValueError(f"action {name} is already registered differently")
        self._action_classes[name] = action_class
        self._action_owner[name] = module
        if admin_user_only:
            self._admin_only.add(name)
        if sensitive_read:
            self._sensitive_reads.add(name)
        if rate_limit is not None:
            self._rate_limits[name] = rate_limit

    # -- decisions -------------------------------------------------------------------

    def authorize(
        self,
        action: str,
        router_id: str,
        actor: VerifiedActor,
        *,
        subject_id: str | None = None,
        checksum: str | None = None,
        approval_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuthorizationDecision:
        """Synchronous decision; always writes one audit entry."""
        action = str(action)
        now = self.now()
        self._expire(now)
        if self.closed:
            return self._denied(
                action, router_id, actor, "guard_closed", correlation_id
            )
        reason = policy_denial_reason(
            action,
            actor,
            now=now,
            action_classes=self._action_classes,
            admin_user_only=frozenset(self._admin_only),
            system_only=frozenset(self._system_only),
            sensitive_reads=frozenset(self._sensitive_reads),
        )
        if reason is not None:
            return self._denied(action, router_id, actor, reason, correlation_id)
        assert isinstance(actor, VerifiedActor)
        action_class = self._action_classes[action]
        if approval_id is not None:
            return self._redeem(
                action, router_id, actor, approval_id, checksum, correlation_id, now
            )
        if action_class is ActionClass.CRITICAL:
            return self._request(
                action, router_id, actor, subject_id, checksum, correlation_id, now
            )
        if action_class is ActionClass.ACTIVE:
            retry_after = self._rate_check(action, router_id, now)
            if retry_after is not None:
                return self._rate_limited(
                    action, router_id, actor, retry_after, correlation_id, now
                )
        return self._grant(
            action, router_id, actor, checksum, None, correlation_id, now
        )

    def _grant(
        self,
        action: str,
        router_id: str,
        actor: VerifiedActor,
        checksum: str | None,
        approval_id: str | None,
        correlation_id: str | None,
        now: datetime,
    ) -> AuthorizationDecision:
        authorization = _mint_write_authorization(
            action=action,
            router_id=router_id,
            actor=actor.actor,
            checksum=checksum,
            approval_id=approval_id,
            correlation_id=correlation_id,
            now=now,
        )
        self._ledger[authorization.authorization_id] = _LedgerEntry(authorization)
        self.stats["decisions_approved"] += 1
        event_type = CoreEventType.AUTHORIZATION_GRANTED
        if self._action_classes.get(action) is ActionClass.ACTIVE:
            event_type = CoreEventType.ACTIVE_ACTION_GRANTED
            self.stats["active_granted"] += 1
            self._record_call(action, router_id, now)
        audit_id = self._audit(
            event_type,
            router_id=router_id,
            actor=actor.actor,
            correlation_id=correlation_id,
            result=EventResult.SUCCESS,
            data={
                "action": action,
                "authorization_id": authorization.authorization_id,
                "approval_id": approval_id,
                "verification_id": actor.verification_id,
                "bound": checksum is not None,
            },
        )
        return AuthorizationDecision(
            state=DecisionState.APPROVED,
            action=action,
            router_id=router_id,
            audit_id=audit_id,
            authorization=authorization,
        )

    def _rate_check(self, action: str, router_id: str, now: datetime) -> float | None:
        """Seconds until the next grant is allowed; None if allowed now."""
        limit = self._rate_limits.get(action)
        if limit is None:
            return None
        calls = self._calls.get((action, str(router_id)))
        if calls is None:
            return None
        while calls and now - calls[0] >= limit.per:
            calls.popleft()
        if len(calls) < limit.max_calls:
            return None
        return max(0.0, (calls[0] + limit.per - now).total_seconds())

    def _record_call(self, action: str, router_id: str, now: datetime) -> None:
        limit = self._rate_limits.get(action)
        if limit is None:
            return
        key = (action, str(router_id))
        calls = self._calls.get(key)
        if calls is None:
            if len(self._calls) >= MAX_RATE_WINDOWS:
                self._prune_windows(now)
            calls = self._calls[key] = deque(maxlen=limit.max_calls)
        calls.append(now)

    def _prune_windows(self, now: datetime) -> None:
        """Forget passed windows; above MAX_RATE_WINDOWS - 1 the oldest."""
        for key, calls in list(self._calls.items()):
            limit = self._rate_limits.get(key[0])
            if limit is None or not calls or now - calls[-1] >= limit.per:
                del self._calls[key]
        excess = len(self._calls) - (MAX_RATE_WINDOWS - 1)
        if excess > 0:
            oldest = sorted(self._calls, key=lambda k: self._calls[k][-1])[:excess]
            for key in oldest:
                del self._calls[key]
            self.stats["rate_windows_dropped"] += excess
            _LOGGER.debug("Guard: %d open rate windows dropped (cap)", excess)

    def _rate_limited(
        self,
        action: str,
        router_id: str,
        actor: VerifiedActor,
        retry_after: float,
        correlation_id: str | None,
        now: datetime,
    ) -> AuthorizationDecision:
        """Refuse an active action over its limit (general ring, deduped)."""
        self.stats["decisions_denied"] += 1
        self.stats["rate_limited"] += 1
        limit = self._rate_limits[action]
        audit_id = self._audit(
            CoreEventType.ACTION_RATE_LIMITED,
            router_id=router_id,
            actor=actor.actor,
            correlation_id=correlation_id,
            severity=Severity.WARNING,
            result=EventResult.DENIED,
            dedup_key=action,
            cooldown=limit.per,
            now=now,
            data={
                "action": action,
                "reason": REASON_RATE_LIMITED,
                "retry_after": retry_after,
                **limit.to_dict(),
            },
        )
        return AuthorizationDecision(
            state=DecisionState.DENIED,
            action=action,
            router_id=router_id,
            audit_id=audit_id,
            reason=REASON_RATE_LIMITED,
            retry_after=retry_after,
        )

    def _request(
        self,
        action: str,
        router_id: str,
        actor: VerifiedActor,
        subject_id: str | None,
        checksum: str | None,
        correlation_id: str | None,
        now: datetime,
    ) -> AuthorizationDecision:
        cap_reason = self._open_cap_reason(actor)
        if cap_reason is not None:
            self.stats["approvals_capped"] += 1
            _LOGGER.warning(
                "Guard: approval request for %s refused (%s)", action, cap_reason
            )
            return self._denied(action, router_id, actor, cap_reason, correlation_id)
        subject = subject_id or router_id
        approval = ApprovalRequest(
            approval_id=new_id(APPROVAL_ID_PREFIX),
            action=action,
            router_id=router_id,
            subject_id=subject,
            checksum=checksum or binding_checksum(action, router_id, subject),
            requested_by=actor.actor,
            requested_at=now,
            expires_at=now + APPROVAL_TTL,
            correlation_id=correlation_id,
        )
        self._approvals[approval.approval_id] = approval
        self.stats["decisions_pending"] += 1
        audit_id = self._audit(
            self._approval_type(action, "requested"),
            router_id=router_id,
            actor=actor.actor,
            correlation_id=correlation_id,
            result=EventResult.PENDING,
            data={
                "action": action,
                "approval_id": approval.approval_id,
                "subject_id": subject,
                "expires_at": approval.expires_at.isoformat(),
            },
        )
        return AuthorizationDecision(
            state=DecisionState.PENDING,
            action=action,
            router_id=router_id,
            audit_id=audit_id,
            approval_request=approval,
        )

    def _open_cap_reason(self, actor: VerifiedActor) -> str | None:
        """Reason to refuse one more open approval, None if room is left."""
        open_ = [
            a
            for a in self._approvals.values()
            if a.status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED)
        ]
        if len(open_) >= MAX_OPEN_APPROVALS_TOTAL:
            return REASON_TOO_MANY_OPEN_TOTAL
        mine = sum(1 for a in open_ if a.requested_by.same_principal(actor.actor))
        if mine >= MAX_OPEN_APPROVALS_PER_PRINCIPAL:
            return REASON_TOO_MANY_OPEN
        return None

    def _redeem(
        self,
        action: str,
        router_id: str,
        actor: VerifiedActor,
        approval_id: str,
        checksum: str | None,
        correlation_id: str | None,
        now: datetime,
    ) -> AuthorizationDecision:
        approval = self._approvals.get(approval_id)
        if approval is None:
            return self._denied(
                action,
                router_id,
                actor,
                "unknown_approval",
                correlation_id,
                approval_id=approval_id,
            )
        try:
            check_redeem(
                approval,
                actor,
                action=action,
                router_id=router_id,
                checksum=checksum or "",
                now=now,
            )
        except ConfigApiError as err:
            reason = str(err.details.get("reason", "denied"))
            if reason == "pending":
                self.stats["decisions_pending"] += 1
                audit_id = self._audit(
                    CoreEventType.AUTHORIZATION_DENIED,
                    router_id=router_id,
                    actor=actor.actor,
                    correlation_id=correlation_id,
                    severity=Severity.INFO,
                    result=EventResult.PENDING,
                    data={
                        "action": action,
                        "reason": "pending",
                        "approval_id": approval_id,
                    },
                )
                return AuthorizationDecision(
                    state=DecisionState.PENDING,
                    action=action,
                    router_id=router_id,
                    audit_id=audit_id,
                    approval_request=approval,
                    reason="pending",
                )
            return self._denied(
                action,
                router_id,
                actor,
                reason,
                correlation_id,
                approval_id=approval_id,
                approval=approval,
            )
        self._approvals[approval_id] = replace(approval, status=ApprovalStatus.USED)
        return self._grant(
            action,
            router_id,
            actor,
            approval.checksum,
            approval_id,
            correlation_id or approval.correlation_id,
            now,
        )

    def _denied(
        self,
        action: str,
        router_id: str,
        actor: object,
        reason: str,
        correlation_id: str | None,
        *,
        approval_id: str | None = None,
        approval: ApprovalRequest | None = None,
    ) -> AuthorizationDecision:
        self.stats["decisions_denied"] += 1
        audit_id = self._deny_audit(
            router_id,
            action,
            actor,
            reason,
            correlation_id=correlation_id,
            approval_id=approval_id,
        )
        return AuthorizationDecision(
            state=DecisionState.DENIED,
            action=action,
            router_id=router_id,
            audit_id=audit_id,
            approval_request=approval,
            reason=reason,
        )

    # -- approvals -------------------------------------------------------------------

    def approve(self, approval_id: str, *, actor: VerifiedActor) -> ApprovalRequest:
        """A verified admin user approves a pending request."""
        return self._decide(approval_id, actor, approve=True, reason=None)

    def reject(
        self, approval_id: str, *, actor: VerifiedActor, reason: str | None = None
    ) -> ApprovalRequest:
        """A verified admin user rejects a pending request."""
        return self._decide(approval_id, actor, approve=False, reason=reason)

    def _decide(
        self,
        approval_id: str,
        actor: VerifiedActor,
        *,
        approve: bool,
        reason: str | None,
    ) -> ApprovalRequest:
        now = self.now()
        self._expire(now)
        approval = self._approvals.get(approval_id)
        step = "approve" if approve else "reject"
        if approval is None:
            self._deny_audit(
                "-", step, actor, "unknown_approval", approval_id=approval_id
            )
            raise ApprovalInvalidError(
                "Unknown approval",
                details={"reason": "unknown_approval", "approval_id": approval_id},
            )
        denial = approver_denial_reason(approval, actor, now=now)
        if denial is not None:
            self._deny_audit(
                approval.router_id,
                f"{step}:{approval.action}",
                actor,
                denial,
                correlation_id=approval.correlation_id,
                approval_id=approval_id,
            )
            details = {"reason": denial, "approval_id": approval_id}
            if denial in ("not_pending", "expired"):
                raise ApprovalInvalidError(
                    f"Approval cannot be decided: {denial}",
                    router_id=approval.router_id,
                    details=details,
                )
            raise AuthorizationError(
                f"Approval cannot be decided: {denial}",
                router_id=approval.router_id,
                details=details,
            )
        assert isinstance(actor, VerifiedActor)
        decided = replace(
            approval,
            status=ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED,
            decided_by=actor.actor,
            decided_at=now,
            reason=reason,
        )
        self._approvals[approval_id] = decided
        self.stats["approvals_approved" if approve else "approvals_rejected"] += 1
        if not approve:
            self._notify(approval_id, "rejected")
        self._audit(
            self._approval_type(approval.action, "approved" if approve else "rejected"),
            router_id=approval.router_id,
            actor=actor.actor,
            correlation_id=approval.correlation_id,
            result=EventResult.SUCCESS if approve else EventResult.DENIED,
            data={
                "action": str(approval.action),
                "approval_id": approval_id,
                "subject_id": approval.subject_id,
                "self_approved": actor.actor.same_principal(approval.requested_by),
            },
        )
        return decided

    def get_approval(self, approval_id: str) -> ApprovalRequest:
        """Request by id; ApprovalInvalidError if unknown (also after restart)."""
        self._expire(self.now())
        approval = self._approvals.get(approval_id)
        if approval is None:
            raise ApprovalInvalidError(
                "Unknown approval",
                details={"reason": "unknown_approval", "approval_id": approval_id},
            )
        return approval

    def pending_approvals(
        self, router_id: str | None = None
    ) -> tuple[ApprovalRequest, ...]:
        """Open requests, newest first (in memory; lost on restart)."""
        self._expire(self.now())
        out = [
            a
            for a in self._approvals.values()
            if a.status is ApprovalStatus.PENDING
            and (router_id is None or a.router_id == router_id)
        ]
        out.sort(key=lambda a: a.requested_at, reverse=True)
        return tuple(out)

    def _approval_type(self, action: str, step: str) -> CoreEventType:
        if str(action) == GuardedAction.RESTORE:
            return _RESTORE_TYPES[step]
        return _APPROVAL_TYPES[step]

    @callback
    def add_approval_listener(
        self, listener: Callable[[str, str], None]
    ) -> Callable[[], None]:
        """Call ``listener(approval_id, reason)`` when an approval ends unused.

        ``reason`` is ``ttl`` / ``unload`` (expired) or ``rejected``. Owners of
        per-approval request data drop it there. Returns the remover.
        """
        self._listeners.append(listener)

        def _remove() -> None:
            with contextlib.suppress(ValueError):
                self._listeners.remove(listener)

        return _remove

    def _notify(self, approval_id: str, reason: str) -> None:
        for listener in tuple(self._listeners):
            try:
                listener(approval_id, reason)
            except Exception:
                self.stats["listener_errors"] += 1
                _LOGGER.warning(
                    "Guard: approval listener failed for %s", reason, exc_info=True
                )

    @callback
    def _expire(self, now: datetime, *, reason: str = "ttl") -> None:
        """Expire pending/approved requests past their TTL (audited once)."""
        ended: list[str] = []
        for approval_id, approval in list(self._approvals.items()):
            if approval.status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED):
                if reason == "ttl" and now < approval.expires_at:
                    continue
                self._approvals[approval_id] = replace(
                    approval, status=ApprovalStatus.EXPIRED
                )
                self.stats["approvals_expired"] += 1
                self._audit(
                    CoreEventType.APPROVAL_EXPIRED,
                    router_id=approval.router_id,
                    actor=approval.requested_by,
                    correlation_id=approval.correlation_id,
                    result=EventResult.INFO,
                    data={
                        "action": str(approval.action),
                        "approval_id": approval_id,
                        "previous_status": approval.status.value,
                        "reason": reason,
                    },
                )
                ended.append(approval_id)
            elif now - approval.expires_at > _APPROVAL_KEEP:
                del self._approvals[approval_id]
                self.stats["approvals_dropped"] += 1
        if self._calls:
            self._prune_windows(now)
        for authorization_id, entry in list(self._ledger.items()):
            if now - entry.authorization.expires_at > _LEDGER_GRACE:
                del self._ledger[authorization_id]
                self.stats["ledger_pruned"] += 1
        for approval_id in ended:
            self._notify(approval_id, reason)

    # -- consume ---------------------------------------------------------------------

    def consume(
        self,
        authorization: WriteAuthorization,
        *,
        action: str,
        router_id: str,
        checksum: str | None = None,
    ) -> None:
        """Use ``authorization`` once or raise AuthorizationError (audited).

        Synchronous: call on the event loop right before acting, never in
        an executor job. Every attempt uses the authorization up.
        """
        action = str(action)
        now = self.now()
        entry = (
            self._ledger.get(authorization.authorization_id)
            if isinstance(authorization, WriteAuthorization)
            else None
        )
        if entry is None or entry.authorization is not authorization:
            self.stats["consume_denied"] += 1
            self._deny_audit(
                router_id,
                action,
                getattr(authorization, "actor", None),
                "unknown_authorization",
                authorization_id=getattr(authorization, "authorization_id", None),
            )
            raise AuthorizationError(
                "Authorization was not issued by this guard",
                router_id=router_id,
                details={"reason": "unknown_authorization", "action": action},
            )
        if self.closed:
            self.stats["consume_denied"] += 1
            self._deny_audit(
                router_id,
                action,
                authorization.actor,
                "guard_closed",
                authorization_id=authorization.authorization_id,
            )
            raise AuthorizationError(
                "The guard is closed",
                router_id=router_id,
                details={"reason": "guard_closed", "action": action},
            )
        try:
            authorization._consume(
                action=action, router_id=router_id, checksum=checksum, now=now
            )
        except AuthorizationError as err:
            entry.used = True
            self.stats["consume_denied"] += 1
            self._deny_audit(
                router_id,
                action,
                authorization.actor,
                str(err.details.get("reason", "denied")),
                correlation_id=authorization.correlation_id,
                authorization_id=authorization.authorization_id,
            )
            raise
        entry.used = True
        self.stats["consumed"] += 1
        self._audit(
            CoreEventType.AUTHORIZATION_CONSUMED,
            router_id=router_id,
            actor=authorization.actor,
            correlation_id=authorization.correlation_id,
            result=EventResult.SUCCESS,
            data={
                "action": action,
                "authorization_id": authorization.authorization_id,
                "approval_id": authorization.approval_id,
            },
        )

    def issued(self, authorization: object) -> bool:
        """True if ``authorization`` is in the ledger (minted here)."""
        if not isinstance(authorization, WriteAuthorization):
            return False
        entry = self._ledger.get(authorization.authorization_id)
        return entry is not None and entry.authorization is authorization

    def used(self, authorization: object) -> bool:
        """True if ``consume`` was called for this ledger entry."""
        if not self.issued(authorization):
            return False
        assert isinstance(authorization, WriteAuthorization)
        return self._ledger[authorization.authorization_id].used

    def denial_reason(self, action: str, actor: object) -> str | None:
        """Policy pre-check without minting or auditing (None = allowed).

        Callers that would do expensive work before ``authorize`` use it and
        then call ``authorize`` anyway, which audits the denial.
        """
        return policy_denial_reason(
            str(action),
            actor,
            now=self.now(),
            action_classes=self._action_classes,
            admin_user_only=frozenset(self._admin_only),
            system_only=frozenset(self._system_only),
            sensitive_reads=frozenset(self._sensitive_reads),
        )

    def audit_denial(
        self,
        router_id: str,
        action: str,
        actor: object,
        reason: str,
        *,
        correlation_id: str | None = None,
    ) -> str:
        """Audit a refusal decided outside ``authorize`` (core-internal)."""
        self.stats["decisions_denied"] += 1
        return self._deny_audit(
            router_id, action, actor, reason, correlation_id=correlation_id
        )

    # -- lifecycle -------------------------------------------------------------------

    @callback
    def close(self) -> None:
        """Discard open approvals (audited as expired) and the ledger."""
        if self.closed:
            return
        self._expire(self.now(), reason="unload")
        self.closed = True
        self._ledger.clear()

    def summary(self) -> dict[str, Any]:
        """Counters for diagnostics (no ids, no actors)."""
        states: dict[str, int] = {}
        for approval in self._approvals.values():
            states[approval.status.value] = states.get(approval.status.value, 0) + 1
        return {
            "closed": self.closed,
            "approvals": states,
            "ledger": len(self._ledger),
            "registered_actions": len(self._action_owner),
            **self.stats,
        }

    # -- audit -----------------------------------------------------------------------

    def _deny_audit(
        self,
        router_id: str,
        action: str,
        actor: object,
        reason: str,
        *,
        correlation_id: str | None = None,
        approval_id: str | None = None,
        authorization_id: str | None = None,
    ) -> str:
        if isinstance(actor, VerifiedActor):
            record: Actor | None = actor.actor
        elif isinstance(actor, Actor):
            record = replace(actor, is_admin=False)  # never echo a claimed admin
        else:
            record = None
        data: dict[str, Any] = {"action": str(action), "reason": reason}
        if approval_id is not None:
            data["approval_id"] = approval_id
        if authorization_id is not None:
            data["authorization_id"] = authorization_id
        return self._audit(
            CoreEventType.AUTHORIZATION_DENIED,
            router_id=router_id,
            actor=record,
            correlation_id=correlation_id,
            severity=Severity.WARNING,
            result=EventResult.DENIED,
            data=data,
        )

    def _audit(self, event_type: CoreEventType, **kwargs: Any) -> str:
        """Emit as the core; returns the event id ("" if the audit failed)."""
        try:
            result = self.audit.emit(event_type, source=CORE_SOURCE, **kwargs)
        except Exception:
            self.stats["audit_errors"] += 1
            _LOGGER.warning(
                "Guard: audit entry %s could not be written", event_type, exc_info=True
            )
            return ""
        return result.event.event_id
