"""Security actions of the enterprise core (1.44.0).

Two things that change trust on a router and therefore go through the
guard (CRITICAL, admin user, approval bound to a checksum) and are audited
on the ``security.`` ring:

* :class:`SshPinRegistry` — the per-router SSH host-key pin store behind
  ``api.async_ssh_run_pinned``. No silent trust on first use: under the
  policy :data:`SSH_PIN_FIRST_USE_POLICY` (``confirm``) a first-seen key
  becomes a *pending* pin and every pinned call refuses (``pin_pending``)
  until an admin confirms it (``ssh_pin_confirm``). A key that differs from
  the pin always refuses and is audited (``security.ssh_pin_mismatch``);
  ``ssh_pin_reset`` forgets the pin.
* :class:`SecurityActions` — the approval flows for the pin and the core's
  ACL offer deploy (``acl_deploy``): guard -> approval -> deploy -> clear
  the ACL-block cache -> re-probe capabilities -> audit with the rollback
  command. Its SSH fallback only uses the pinned path.

Nothing here runs per poll: the pin store is read once at core load and
written only on a pin event; router calls happen only inside an approved
action or a provider's own pinned call.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from homeassistant.core import HomeAssistant, callback

from . import core_store
from .acl_provisioning import (
    DEFAULT_TIER_REGISTRY,
    AclEnsureOutcome,
    AclOffer,
    AclOfferDeployError,
    AclOfferRefusedError,
    AclTierError,
    AclTierRegistry,
    async_deploy_acl_offer,
    describe_offer,
    observe_deployed_acl,
)
from .api import (
    HostKeyPin,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtHostKeyError,
    OpenWrtHostKeyMismatchError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
    PinnedSshResult,
    async_ssh_run_pinned,
)
from .core_audit import CORE_SOURCE, AuditLog
from .core_errors import (
    ApprovalInvalidError,
    AuthorizationError,
    ConfigApiError,
    ErrorClass,
    RouterUnavailableError,
)
from .core_models import (
    CORE_STORE_VERSION,
    OPTION_CONFIG_BACKUP_ENABLED,
    SSH_PIN_FIRST_USE_POLICY,
    SSH_PIN_POLICY_CONFIRM,
    SSH_PIN_POLICY_TOFU,
    SSH_PIN_STORE_KEY,
    SSH_PIN_STORE_MINOR_VERSION,
    Actor,
    ApprovalRequest,
    CoreEventType,
    EventResult,
    GuardedAction,
    Severity,
    VerifiedActor,
    binding_checksum,
    utcnow,
)

_LOGGER = logging.getLogger(__name__)

# rpcd restarts after an ACL write: wait, then log in again (as __init__).
ACL_DEPLOY_GRACE_S = 2.0
ACL_LOGIN_RETRY_DELAY_S = 1.5
_PIN_STATES = ("none", "pending", "pinned")


def migrate_pin_store(old_major: int, old_minor: int, old_data: Any) -> dict[str, Any]:
    """Store migration of the SSH host-key pins. v1.x: additive minors."""
    if old_major != CORE_STORE_VERSION or not isinstance(old_data, dict):
        raise NotImplementedError(f"ssh host key store version {old_major} unknown")
    return dict(old_data)


def _pin_or_none(raw: Any) -> HostKeyPin | None:
    try:
        return None if raw is None else HostKeyPin.from_dict(raw)
    except (TypeError, ValueError):
        return None


@dataclass(slots=True)
class _PinEntry:
    """Pin state of one router (store document ``routers[<router_id>]``)."""

    pin: HostKeyPin | None = None
    pending: HostKeyPin | None = None
    pending_since: str | None = None
    confirmed_at: str | None = None
    confirmed_by: str | None = None  # actor kind only (never a user id)
    policy: str | None = None

    @property
    def state(self) -> str:
        if self.pin is not None:
            return "pinned"
        return "pending" if self.pending is not None else "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "pin": None if self.pin is None else self.pin.to_dict(),
            "pending": None if self.pending is None else self.pending.to_dict(),
            "pending_since": self.pending_since,
            "confirmed_at": self.confirmed_at,
            "confirmed_by": self.confirmed_by,
            "policy": self.policy,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> _PinEntry:
        return cls(
            pin=_pin_or_none(data.get("pin")),
            pending=_pin_or_none(data.get("pending")),
            pending_since=data.get("pending_since"),
            confirmed_at=data.get("confirmed_at"),
            confirmed_by=data.get("confirmed_by"),
            policy=data.get("policy"),
        )


class RouterPinStore:
    """``api.HostKeyPinStore`` of ONE router, bound to its router_id."""

    __slots__ = ("_pins", "router_id")

    def __init__(self, pins: SshPinRegistry, router_id: str) -> None:
        """Bind to the registry and the router (the pin follows the id)."""
        self._pins = pins
        self.router_id = router_id

    async def async_load_pin(self) -> HostKeyPin | None:
        """Confirmed pin; refuses before connecting while one is pending."""
        return self._pins.load_for_call(self.router_id)

    async def async_save_pin(self, pin: HostKeyPin) -> None:
        """First use: pending (confirm policy) or pinned (tofu policy)."""
        await self._pins.async_first_use(self.router_id, pin)


class SshPinRegistry:
    """Per-router SSH host-key pins (own store, private, atomic writes)."""

    def __init__(
        self,
        hass: HomeAssistant,
        audit: AuditLog,
        *,
        policy: str = SSH_PIN_FIRST_USE_POLICY,
    ) -> None:
        """Create an empty registry; :meth:`async_load` reads the store."""
        if policy not in (SSH_PIN_POLICY_CONFIRM, SSH_PIN_POLICY_TOFU):
            raise ValueError(f"unknown SSH pin policy {policy!r}")
        self.hass = hass
        self.audit = audit
        self.policy = policy
        self._store: Any = core_store.create_store(
            hass,
            CORE_STORE_VERSION,
            SSH_PIN_STORE_KEY,
            minor_version=SSH_PIN_STORE_MINOR_VERSION,
            migrate=migrate_pin_store,
            private=True,
            atomic_writes=True,
        )
        self._entries: dict[str, _PinEntry] = {}
        self._lock = asyncio.Lock()
        self.loaded = False
        self.closed = False
        self.stats: dict[str, int] = {
            "load_failed": 0,
            "entries_skipped": 0,
            "store_writes": 0,
            "store_write_errors": 0,
            "pinned_calls": 0,
            "first_use_pending": 0,
            "first_use_pinned": 0,
            "refused_pending": 0,
            "refused_not_loaded": 0,
            "mismatches": 0,
            "confirmed": 0,
            "resets": 0,
        }

    # -- store ---------------------------------------------------------------------

    async def async_load(self) -> None:
        """Read the pins once; an unreadable store is kept as .bak, reported."""
        if self.loaded:
            return
        loaded = await core_store.async_load_store(
            self.hass, self._store, SSH_PIN_STORE_KEY
        )
        if loaded.failed:
            self.stats["load_failed"] += 1
            self._emit(
                CoreEventType.STORE_RECOVERED,
                severity=Severity.WARNING,
                data={"store": SSH_PIN_STORE_KEY, "backup_written": loaded.backed_up},
            )
        routers = (loaded.data or {}).get("routers")
        for router_id, raw in (routers if isinstance(routers, Mapping) else {}).items():
            if not isinstance(raw, Mapping):
                self.stats["entries_skipped"] += 1
                continue
            entry = _PinEntry.from_dict(raw)
            if raw.get("pin") is not None and entry.pin is None:
                # An unusable stored pin is never treated as "no pin" (that
                # would re-trust any key): keep it pending-less and refuse.
                self.stats["entries_skipped"] += 1
                _LOGGER.warning(
                    "SSH host key pin of %s is unusable; pinned SSH refuses "
                    "until ssh_pin_reset",
                    router_id,
                )
                entry.pending = None
                entry.policy = "unusable"
            self._entries[str(router_id)] = entry
        if self.stats["entries_skipped"]:
            _LOGGER.warning(
                "SSH pin store: %d entries skipped", self.stats["entries_skipped"]
            )
        self.loaded = True

    def _data(self) -> dict[str, Any]:
        return {
            "routers": {
                rid: entry.to_dict()
                for rid, entry in sorted(self._entries.items())
                if entry.state != "none" or entry.policy == "unusable"
            }
        }

    async def _async_save(self) -> None:
        """Write now (pin events are rare; atomic, mode 0600)."""
        try:
            await self._store.async_save(self._data())
            self.stats["store_writes"] += 1
        except Exception:
            self.stats["store_write_errors"] += 1
            _LOGGER.warning("SSH pin store could not be written", exc_info=True)
            raise

    async def async_flush(self) -> None:
        """Write the store now (only after a successful load)."""
        if self.loaded:
            await self._async_save()

    @callback
    def close(self) -> None:
        """No more writes from new calls."""
        self.closed = True

    # -- read ----------------------------------------------------------------------

    def store_for(self, router_id: str) -> RouterPinStore:
        """The ``HostKeyPinStore`` of one router."""
        return RouterPinStore(self, router_id)

    def pin(self, router_id: str) -> HostKeyPin | None:
        """Confirmed pin or None."""
        entry = self._entries.get(router_id)
        return None if entry is None else entry.pin

    def pending(self, router_id: str) -> HostKeyPin | None:
        """First-seen key awaiting ``ssh_pin_confirm`` or None."""
        entry = self._entries.get(router_id)
        return None if entry is None else entry.pending

    def status(self, router_id: str) -> dict[str, Any]:
        """JSON-safe pin state (fingerprints only, no key, no host)."""
        entry = self._entries.get(router_id) or _PinEntry()
        state = "unusable" if entry.policy == "unusable" else entry.state
        return {
            "router_id": router_id,
            "state": state,
            "policy": self.policy,
            "fingerprint": None if entry.pin is None else entry.pin.fingerprint,
            "algorithm": None if entry.pin is None else entry.pin.algorithm,
            "pinned_at": None if entry.pin is None else entry.pin.pinned_at,
            "pending_fingerprint": None
            if entry.pending is None
            else entry.pending.fingerprint,
            "pending_since": entry.pending_since,
            "confirmed_at": entry.confirmed_at,
            "confirmed_by": entry.confirmed_by,
        }

    def summary(self) -> dict[str, Any]:
        """Counts only."""
        states = [self.status(rid)["state"] for rid in self._entries]
        return {
            "policy": self.policy,
            "loaded": self.loaded,
            "routers": {s: states.count(s) for s in (*_PIN_STATES, "unusable")},
            **self.stats,
        }

    # -- the pinned call -------------------------------------------------------------

    def load_for_call(self, router_id: str) -> HostKeyPin | None:
        """What ``async_load_pin`` returns; raises to refuse before any I/O."""
        if not self.loaded or self.closed:
            self.stats["refused_not_loaded"] += 1
            raise OpenWrtHostKeyError(
                "pin_store_unavailable",
                "the SSH host key pin store is not loaded; pinned SSH refused",
            )
        entry = self._entries.get(router_id)
        if entry is None:
            return None
        if entry.policy == "unusable":
            raise OpenWrtHostKeyError(
                "pin_invalid",
                "the stored host key pin is unusable; reset it (ssh_pin_reset)",
            )
        if entry.pin is None and entry.pending is not None:
            self.stats["refused_pending"] += 1
            raise OpenWrtHostKeyError(
                "pin_pending",
                "a first-seen SSH host key awaits confirmation (ssh_pin_confirm)",
                presented_fingerprint=entry.pending.fingerprint,
            )
        return entry.pin

    async def async_first_use(self, router_id: str, pin: HostKeyPin) -> None:
        """First contact: record the key as pending (or pinned under tofu).

        Raises OpenWrtHostKeyError(``pin_pending``) under ``confirm`` so the
        command does not run; a second, different first-seen key is a
        mismatch (audited, refused).
        """
        async with self._lock:
            entry = self._entries.setdefault(router_id, _PinEntry())
            if entry.pin is not None:
                # A pin appeared meanwhile (confirm raced the call): never
                # overwrite it from a call that started without one.
                if entry.pin.public_key == pin.public_key:
                    return
                await self._mismatch(router_id, entry.pin.fingerprint, pin, "mismatch")
            if entry.pending is not None and entry.pending.public_key != pin.public_key:
                await self._mismatch(
                    router_id, entry.pending.fingerprint, pin, "pending_mismatch"
                )
            if self.policy == SSH_PIN_POLICY_TOFU:
                entry.pin = pin
                entry.pending = None
                entry.confirmed_at = utcnow().isoformat()
                entry.confirmed_by = "tofu"
                entry.policy = SSH_PIN_POLICY_TOFU
                await self._async_save()
                self.stats["first_use_pinned"] += 1
                self._emit(
                    CoreEventType.SSH_PIN_CONFIRMED,
                    router_id=router_id,
                    severity=Severity.WARNING,
                    data={
                        "fingerprint": pin.fingerprint,
                        "algorithm": pin.algorithm,
                        "policy": SSH_PIN_POLICY_TOFU,
                    },
                )
                return
            first = entry.pending is None
            if first:
                entry.pending = pin
                entry.pending_since = utcnow().isoformat()
                entry.policy = SSH_PIN_POLICY_CONFIRM
                await self._async_save()
                self.stats["first_use_pending"] += 1
            self.stats["refused_pending"] += 1
            self._emit(
                CoreEventType.SSH_PIN_PENDING,
                router_id=router_id,
                severity=Severity.WARNING,
                result=EventResult.DENIED,
                dedup_key=f"ssh_pin_pending:{router_id}:{pin.fingerprint}",
                data={
                    "fingerprint": pin.fingerprint,
                    "algorithm": pin.algorithm,
                    "first_seen": first,
                    "action": GuardedAction.SSH_PIN_CONFIRM.value,
                },
            )
            _LOGGER.warning(
                "SSH host key of %s seen for the first time (%s); pinned SSH "
                "refuses until an admin confirms it (ssh_pin_confirm)",
                router_id,
                pin.fingerprint,
            )
            raise OpenWrtHostKeyError(
                "pin_pending",
                "first-seen SSH host key recorded; awaiting ssh_pin_confirm",
                presented_fingerprint=pin.fingerprint,
            )

    async def _mismatch(
        self, router_id: str, expected: str, pin: HostKeyPin, reason: str
    ) -> None:
        self._audit_mismatch(router_id, expected, pin.fingerprint, reason)
        err = OpenWrtHostKeyMismatchError(
            "mismatch",
            "SSH host key differs from the pinned/pending key",
            expected_fingerprint=expected,
            presented_fingerprint=pin.fingerprint,
        )
        err.audited = True  # type: ignore[attr-defined]  # async_run: no 2nd event
        raise err

    def _audit_mismatch(
        self,
        router_id: str,
        expected: str | None,
        presented: str | None,
        reason: str,
    ) -> None:
        self.stats["mismatches"] += 1
        _LOGGER.error(
            "SSH host key of %s does not match its pin (%s); refused", router_id, reason
        )
        self._emit(
            CoreEventType.SSH_PIN_MISMATCH,
            router_id=router_id,
            severity=Severity.CRITICAL,
            result=EventResult.DENIED,
            data={
                "reason": reason,
                "expected_fingerprint": expected,
                "presented_fingerprint": presented,
            },
        )

    async def async_run(
        self,
        api: Any,
        router_id: str,
        command: str,
        *,
        timeout: float = 60.0,
        binary: bool = False,
    ) -> PinnedSshResult:
        """``api.async_ssh_run_pinned`` with this router's pin; audits mismatches."""
        self.stats["pinned_calls"] += 1
        try:
            return await async_ssh_run_pinned(
                api,
                command,
                pin_store=self.store_for(router_id),
                timeout=timeout,
                binary=binary,
            )
        except OpenWrtHostKeyMismatchError as err:
            if not getattr(err, "audited", False):
                self._audit_mismatch(
                    router_id,
                    err.expected_fingerprint,
                    err.presented_fingerprint,
                    err.reason,
                )
            raise

    # -- admin actions (called by SecurityActions after the guard) -------------------

    async def async_confirm(
        self, router_id: str, fingerprint: str, actor: VerifiedActor
    ) -> HostKeyPin:
        """Pending key -> pin (the fingerprint must still match)."""
        async with self._lock:
            entry = self._entries.get(router_id)
            pending = None if entry is None else entry.pending
            if entry is None or pending is None or pending.fingerprint != fingerprint:
                raise ApprovalInvalidError(
                    "The pending SSH host key changed since the request",
                    router_id=router_id,
                    details={"reason": "pin_changed"},
                )
            entry.pin = pending
            entry.pending = None
            entry.pending_since = None
            entry.confirmed_at = utcnow().isoformat()
            entry.confirmed_by = actor.actor.kind.value
            entry.policy = SSH_PIN_POLICY_CONFIRM
            await self._async_save()
            self.stats["confirmed"] += 1
        self._emit(
            CoreEventType.SSH_PIN_CONFIRMED,
            router_id=router_id,
            actor=actor.actor,
            result=EventResult.SUCCESS,
            data={
                "fingerprint": pending.fingerprint,
                "algorithm": pending.algorithm,
                "policy": SSH_PIN_POLICY_CONFIRM,
            },
        )
        return pending

    async def async_reset(
        self, router_id: str, checksum_fingerprint: str | None, actor: VerifiedActor
    ) -> dict[str, Any]:
        """Forget pin and pending key; the next pinned call is a first use."""
        async with self._lock:
            entry = self._entries.get(router_id)
            current = _fingerprint_of(entry)
            if entry is None or current != checksum_fingerprint:
                raise ApprovalInvalidError(
                    "The SSH host key pin changed since the request",
                    router_id=router_id,
                    details={"reason": "pin_changed"},
                )
            before = self.status(router_id)
            del self._entries[router_id]
            await self._async_save()
            self.stats["resets"] += 1
        self._emit(
            CoreEventType.SSH_PIN_RESET,
            router_id=router_id,
            actor=actor.actor,
            severity=Severity.WARNING,
            result=EventResult.SUCCESS,
            data={
                "previous_state": before["state"],
                "previous_fingerprint": before["fingerprint"]
                or before["pending_fingerprint"],
            },
        )
        return before

    def _emit(self, event_type: CoreEventType, **kwargs: Any) -> None:
        try:
            self.audit.emit(event_type, source=CORE_SOURCE, **kwargs)
        except Exception:
            _LOGGER.warning(
                "Core event %s could not be recorded", event_type, exc_info=True
            )


def _fingerprint_of(entry: _PinEntry | None) -> str | None:
    """Fingerprint a reset approval is bound to (pin, else pending)."""
    if entry is None:
        return None
    if entry.pin is not None:
        return entry.pin.fingerprint
    if entry.pending is not None:
        return entry.pending.fingerprint
    return "unusable" if entry.policy == "unusable" else None


@dataclass(frozen=True, slots=True)
class _AclRequest:
    tiers: tuple[str, ...]
    offer: AclOffer


class SecurityActions:
    """Approval flows of ``acl_deploy``, ``ssh_pin_confirm``, ``ssh_pin_reset``.

    Uses the manager's guard helpers (verify, request, grant, open request,
    router lock, audit) so the rules are exactly those of the config API.
    """

    def __init__(
        self,
        manager: Any,
        pins: SshPinRegistry | None,
        *,
        tier_registry: AclTierRegistry = DEFAULT_TIER_REGISTRY,
        grace_s: float = ACL_DEPLOY_GRACE_S,
        login_retry_s: float = ACL_LOGIN_RETRY_DELAY_S,
    ) -> None:
        """Bind to the core's manager and pin registry."""
        self._m = manager
        self.pins = pins
        self.tiers = tier_registry
        self.grace_s = grace_s
        self.login_retry_s = login_retry_s
        self.acl_requests: dict[str, _AclRequest] = {}
        self.pin_confirms: dict[str, str] = {}
        self.pin_resets: dict[str, str | None] = {}
        self.stats: dict[str, int] = {
            "acl_requests": 0,
            "acl_deploys": 0,
            "acl_deploys_unchanged": 0,
            "acl_deploy_failures": 0,
            "acl_refused_option": 0,
            "acl_post_step_errors": 0,
            "pin_confirms": 0,
            "pin_resets": 0,
        }

    @property
    def request_stores(self) -> tuple[dict[str, Any], ...]:
        """In-memory request data (dropped on reject and on close)."""
        return (self.acl_requests, self.pin_confirms, self.pin_resets)

    # -- pinned SSH runners ----------------------------------------------------------

    async def async_ssh_run(
        self, router_id: str, command: str, timeout: float, binary: bool
    ) -> PinnedSshResult:
        """``ProviderContext.ssh``: pinned SSH to an attached router."""
        if self.pins is None:
            raise AuthorizationError(
                "No host-key pin store: the pinned SSH path is unavailable",
                router_id=router_id,
                details={"reason": "ssh_pin_unavailable"},
            )
        api = self._api(router_id)
        return await self.pins.async_run(
            api, router_id, command, timeout=timeout, binary=binary
        )

    def _api(self, router_id: str) -> Any:
        conn = self._m._connection(router_id)
        if conn.api is None:
            raise RouterUnavailableError(
                "The router's entry has no API", router_id=router_id
            )
        return conn.api

    # -- ACL offer -------------------------------------------------------------------

    def _options(self, router_id: str) -> dict[str, Any]:
        return {
            OPTION_CONFIG_BACKUP_ENABLED: self._m.registry.config_enabled(router_id)
        }

    def _check_tiers(
        self, router_id: str, tiers: Iterable[str], verified: VerifiedActor
    ) -> tuple[str, ...]:
        try:
            tier_ids = self.tiers.normalize(tiers)
        except AclTierError as err:
            raise ConfigApiError(
                str(err),
                router_id=router_id,
                error_class=ErrorClass.INVALID,
                details={"reason": "unknown_tier"},
            ) from err
        try:
            self.tiers.check_options(tier_ids, self._options(router_id))
        except AclTierError as err:
            self.stats["acl_refused_option"] += 1
            self._m.guard.audit_denial(
                router_id, GuardedAction.ACL_DEPLOY, verified, "option_disabled"
            )
            raise AclOfferRefusedError(
                "option_disabled", str(err), router_id=router_id
            ) from err
        return tier_ids

    async def async_request_acl_deploy(
        self, router_id: str, tiers: Iterable[str], *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to deploy the tiered ACL (one ``file/read`` for the diff)."""
        verified = await self._m._verify(actor)
        self._m.registry.get(router_id)
        tier_ids = self._check_tiers(router_id, tiers, verified)
        self._m._precheck(GuardedAction.ACL_DEPLOY, router_id, verified)
        current = await self._read_current(router_id)
        offer = describe_offer(current, tier_ids, registry=self.tiers)
        approval = self._m._request(
            GuardedAction.ACL_DEPLOY,
            router_id,
            verified,
            subject_id=offer.acl_checksum,
            checksum=offer.binding_checksum(router_id),
        )
        self.acl_requests[approval.approval_id] = _AclRequest(tier_ids, offer)
        self.stats["acl_requests"] += 1
        return approval

    def acl_offer(self, approval_id: str) -> AclOffer:
        """The offer (diff, risks) behind an open ``acl_deploy`` request."""
        request = self.acl_requests.get(approval_id)
        if request is None:
            raise ApprovalInvalidError(
                "Unknown approval",
                details={"reason": "unknown_approval", "approval_id": approval_id},
            )
        return request.offer

    async def _read_current(self, router_id: str) -> Any:
        import json

        from .acl_provisioning import _read_current_acl

        try:
            state, text = await _read_current_acl(self._api(router_id))
        except AclOfferDeployError as err:
            raise RouterUnavailableError(
                "The router could not be read", router_id=router_id
            ) from err
        if state != "present":
            return None
        try:
            return json.loads(text or "")
        except ValueError:
            return None

    async def async_deploy_acl_offer(
        self, approval_id: str, *, actor: Actor
    ) -> dict[str, Any]:
        """Deploy after approval (requester only); audited with the way back."""
        verified = await self._m._verify(actor)
        approval, request = self._m._open_request(
            approval_id, GuardedAction.ACL_DEPLOY, verified, self.acl_requests
        )
        router_id = approval.router_id
        offer: AclOffer = request.offer
        checksum = offer.binding_checksum(router_id)
        async with self._m._locked(router_id):
            authorization = self._m._grant(
                GuardedAction.ACL_DEPLOY,
                router_id,
                verified,
                approval_id=approval_id,
                checksum=checksum,
            )
            self.acl_requests.pop(approval_id, None)
            conn = self._m._connection(router_id)
            api = conn.api
            runner = None
            if self.pins is not None:
                pins = self.pins

                async def runner(command: str, timeout: float) -> str | None:
                    result = await pins.async_run(
                        api, router_id, command, timeout=timeout
                    )
                    out = result.stdout
                    return out if isinstance(out, str) else out.decode(errors="replace")

            try:
                result = await async_deploy_acl_offer(
                    api,
                    request.tiers,
                    router_id=router_id,
                    authorization=authorization,
                    guard_consume=self._m.guard.consume,
                    options=self._options(router_id),
                    registry=self.tiers,
                    ssh_runner=runner,
                )
            except AclOfferRefusedError as err:
                self._deploy_failed(router_id, verified, approval_id, err.reason, None)
                raise
            except AclOfferDeployError as err:
                self._deploy_failed(router_id, verified, approval_id, err.reason, err)
                raise ConfigApiError(
                    f"ACL deploy failed: {err}",
                    router_id=router_id,
                    error_class=ErrorClass.PERMISSION
                    if err.reason in ("write_blocked", "ssh_pin_unavailable")
                    else ErrorClass.UNREACHABLE,
                    details={
                        "reason": err.reason,
                        "written": err.written,
                        "rollback_command": err.rollback_command,
                    },
                ) from err
            except OpenWrtHostKeyError as err:
                reason = f"ssh_{err.reason}"
                self._deploy_failed(router_id, verified, approval_id, reason, None)
                raise AuthorizationError(
                    "The pinned SSH path refused the ACL deploy",
                    router_id=router_id,
                    details={"reason": reason},
                ) from err
            except (
                OpenWrtAuthError,
                OpenWrtConnectionError,
                OpenWrtResponseError,
                OpenWrtTimeoutError,
            ) as err:
                self._deploy_failed(
                    router_id, verified, approval_id, "router_error", None
                )
                raise RouterUnavailableError(
                    f"ACL deploy failed on the router: {type(err).__name__}",
                    router_id=router_id,
                ) from err
            post_errors = await self._after_deploy(
                router_id, api, result.changed, offer
            )
        if result.changed:
            self.stats["acl_deploys"] += 1
        else:
            self.stats["acl_deploys_unchanged"] += 1
        data = result.to_dict()
        data.pop("router_id", None)
        data.update(
            approval_id=approval_id,
            approved_by_kind=None
            if approval.decided_by is None
            else approval.decided_by.kind.value,
            post_step_errors=post_errors,
        )
        self._m._emit(
            CoreEventType.ACL_DEPLOYED,
            router_id=router_id,
            actor=verified.actor,
            correlation_id=authorization.correlation_id,
            severity=Severity.WARNING,
            result=EventResult.SUCCESS,
            data=data,
        )
        return result.to_dict()

    async def _after_deploy(
        self, router_id: str, api: Any, changed: bool, offer: AclOffer
    ) -> list[str]:
        """Re-login, clear the ACL-block cache, re-evaluate, re-probe."""
        errors: list[str] = []
        if changed:
            await asyncio.sleep(self.grace_s)
            try:
                await api.login()
            except (
                OpenWrtConnectionError,
                OpenWrtTimeoutError,
                OpenWrtAuthError,
                OpenWrtResponseError,
            ):
                await asyncio.sleep(self.login_retry_s)
                try:
                    await api.login()
                except Exception:
                    errors.append("relogin")
                    _LOGGER.warning(
                        "Re-login after the ACL deploy on %s failed (the next "
                        "poll logs in again)",
                        router_id,
                        exc_info=True,
                    )
        steps: list[tuple[str, Any]] = [
            ("reset_acl_blocked", api.reset_acl_blocked),
            ("note_acl", lambda: self._note_acl(router_id, offer)),
            ("invalidate", self._m.registry.invalidate_capabilities),
            ("probe", lambda: self._m.request_probe(router_id, "acl_deployed")),
        ]
        for name, step in steps:
            try:
                step()
            except Exception:
                errors.append(name)
                _LOGGER.warning(
                    "Step %s after the ACL deploy on %s failed",
                    name,
                    router_id,
                    exc_info=True,
                )
        self.stats["acl_post_step_errors"] += len(errors)
        return errors

    def _note_acl(self, router_id: str, offer: AclOffer) -> None:
        entry_id = None
        attached = self._m.registry.attached(router_id)
        if attached is not None:
            entry_id = attached.entry_id
        if entry_id is None:
            return
        self._m.registry.note_deployed_acl(
            entry_id,
            observe_deployed_acl(
                AclEnsureOutcome(True, "offer_deployed", True, offer.acl),
                registry=self.tiers,
            ),
        )

    def _deploy_failed(
        self,
        router_id: str,
        verified: VerifiedActor,
        approval_id: str,
        reason: str,
        err: AclOfferDeployError | None,
    ) -> None:
        self.stats["acl_deploy_failures"] += 1
        self._m._emit(
            CoreEventType.ACL_DEPLOY_FAILED,
            router_id=router_id,
            actor=verified.actor,
            severity=Severity.CRITICAL,
            result=EventResult.FAILURE,
            data={
                "approval_id": approval_id,
                "reason": reason,
                "written": None if err is None else err.written,
                "backup_path": None if err is None else err.backup_path,
                "rollback_command": None if err is None else err.rollback_command,
            },
        )

    # -- SSH pin ---------------------------------------------------------------------

    def _require_pins(self, router_id: str) -> SshPinRegistry:
        if self.pins is None or not self.pins.loaded:
            raise ConfigApiError(
                "The SSH host key pin store is not available",
                router_id=router_id,
                error_class=ErrorClass.NOT_AVAILABLE,
                details={"reason": "ssh_pin_unavailable"},
            )
        return self.pins

    def ssh_pin_status(self, router_id: str) -> dict[str, Any]:
        """Pin state of a router (no router call)."""
        self._m.registry.get(router_id)
        return self._require_pins(router_id).status(router_id)

    async def async_request_ssh_pin_confirm(
        self, router_id: str, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to trust the pending first-seen key (CRITICAL, admin user)."""
        verified = await self._m._verify(actor)
        self._m.registry.get(router_id)
        pending = self._require_pins(router_id).pending(router_id)
        if pending is None:
            self._m.guard.audit_denial(
                router_id, GuardedAction.SSH_PIN_CONFIRM, verified, "no_pending_pin"
            )
            raise ConfigApiError(
                "No first-seen SSH host key awaits confirmation",
                router_id=router_id,
                error_class=ErrorClass.CONFLICT,
                details={"reason": "no_pending_pin"},
            )
        approval = self._m._request(
            GuardedAction.SSH_PIN_CONFIRM,
            router_id,
            verified,
            subject_id=pending.fingerprint,
            checksum=binding_checksum(router_id, pending.fingerprint),
        )
        self.pin_confirms[approval.approval_id] = pending.fingerprint
        return approval

    async def async_confirm_ssh_pin(
        self, approval_id: str, *, actor: Actor
    ) -> dict[str, Any]:
        """Pin the pending key after approval (requester only)."""
        verified = await self._m._verify(actor)
        approval, fingerprint = self._m._open_request(
            approval_id, GuardedAction.SSH_PIN_CONFIRM, verified, self.pin_confirms
        )
        router_id = approval.router_id
        pins = self._require_pins(router_id)
        checksum = binding_checksum(router_id, fingerprint)
        authorization = self._m._grant(
            GuardedAction.SSH_PIN_CONFIRM,
            router_id,
            verified,
            approval_id=approval_id,
            checksum=checksum,
        )
        self._m.guard.consume(
            authorization,
            action=GuardedAction.SSH_PIN_CONFIRM,
            router_id=router_id,
            checksum=checksum,
        )
        self.pin_confirms.pop(approval_id, None)
        try:
            await pins.async_confirm(router_id, fingerprint, verified)
        except ApprovalInvalidError:
            self._m.guard.audit_denial(
                router_id, GuardedAction.SSH_PIN_CONFIRM, verified, "pin_changed"
            )
            raise
        self.stats["pin_confirms"] += 1
        return pins.status(router_id)

    async def async_request_ssh_pin_reset(
        self, router_id: str, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to forget the router's pin (CRITICAL, admin user)."""
        verified = await self._m._verify(actor)
        self._m.registry.get(router_id)
        pins = self._require_pins(router_id)
        current = _fingerprint_of(pins._entries.get(router_id))
        if current is None:
            self._m.guard.audit_denial(
                router_id, GuardedAction.SSH_PIN_RESET, verified, "no_pin"
            )
            raise ConfigApiError(
                "The router has no SSH host key pin",
                router_id=router_id,
                error_class=ErrorClass.CONFLICT,
                details={"reason": "no_pin"},
            )
        approval = self._m._request(
            GuardedAction.SSH_PIN_RESET,
            router_id,
            verified,
            subject_id=current,
            checksum=binding_checksum(router_id, current, "reset"),
        )
        self.pin_resets[approval.approval_id] = current
        return approval

    async def async_reset_ssh_pin(
        self, approval_id: str, *, actor: Actor
    ) -> dict[str, Any]:
        """Forget the pin after approval (requester only)."""
        verified = await self._m._verify(actor)
        approval, fingerprint = self._m._open_request(
            approval_id, GuardedAction.SSH_PIN_RESET, verified, self.pin_resets
        )
        router_id = approval.router_id
        pins = self._require_pins(router_id)
        checksum = binding_checksum(router_id, fingerprint, "reset")
        authorization = self._m._grant(
            GuardedAction.SSH_PIN_RESET,
            router_id,
            verified,
            approval_id=approval_id,
            checksum=checksum,
        )
        self._m.guard.consume(
            authorization,
            action=GuardedAction.SSH_PIN_RESET,
            router_id=router_id,
            checksum=checksum,
        )
        self.pin_resets.pop(approval_id, None)
        try:
            before = await pins.async_reset(router_id, fingerprint, verified)
        except ApprovalInvalidError:
            self._m.guard.audit_denial(
                router_id, GuardedAction.SSH_PIN_RESET, verified, "pin_changed"
            )
            raise
        self.stats["pin_resets"] += 1
        return before

    def summary(self) -> dict[str, Any]:
        """Counts only."""
        return {
            "open_requests": {
                "acl_deploy": len(self.acl_requests),
                "ssh_pin_confirm": len(self.pin_confirms),
                "ssh_pin_reset": len(self.pin_resets),
            },
            **self.stats,
        }
