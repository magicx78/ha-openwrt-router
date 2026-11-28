"""Self-Healing, package K2: manual router writes respect the repair lock.

The existing buttons and switches that restart, start or stop a service,
reload or switch Wi-Fi or reboot a router run every press through
:func:`async_manual_action` (owner decision Q4 (b), "Sperre und Audit";
docs/self-healing.md §10.3):

1. While a Self-Healing **engine** action holds the router's repair lock
   (``LoopState.repair_active``) and really runs, the press is refused with
   a translated :class:`~homeassistant.exceptions.HomeAssistantError`
   (``repair_running``); no router call is made. A lock whose action a
   restart interrupted (the store rebuilds it at load for a record in
   VERIFYING with ``flags.interrupted``; no engine runs it) never refuses:
   the press runs and the audit says ``interrupted_repair``.
2. A router on **hold** (an outcome that waits for an admin) does not block
   a press; the audit entry says it was on hold.
3. Otherwise the press runs as before and holds the router's repair lock
   for its own duration (``SelfHealingStore.try_external_lock``), so the
   engine cannot start in the middle. Presses on the same router at the
   same time share one lock; the last one to finish releases it. The lock
   is released on every exit, also an exception, a timeout or a cancelled
   task; a release that raises is tried once more, then the guard drops
   its own lock (only its ``lock_id`` can match).
4. Every press writes **one** Core audit entry (who, router, action,
   target, result, hold). Never an address, a hostname, a client or SSID
   name, a UCI section or a secret.
5. With the module off (no running engine, engine not loaded or its
   settings switch off) a press works exactly as before: no lock, no
   refusal. The audit is written when the Core is running, else skipped.
   A failing audit never blocks or fails the press.

Nothing is awaited before the router call: the check and the lock are one
synchronous step, the Core is used only when it is already loaded (never
loaded, waited for or cancelled here), and the user of the service call is
looked up after the call, with the lock already released, for at most
``AUDIT_LOOKUP_TIMEOUT_S`` (the context ids are known at once).

This module calls no router and changes nothing in ``heal_store`` or
``heal_engine``; it uses their public surface only. In 1.53.0 the engine
never executes, so case 1 cannot happen in production yet.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final
from weakref import WeakKeyDictionary

from homeassistant.core import Context, HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .const import DEFAULT_SERVICES, DOMAIN

_LOGGER = logging.getLogger(__name__)

# Audit source and type. The source is the Self-Healing module name
# (heal_engine.MODULE). The prefix is registered here, lazily, because the
# module prefix of package K lives in core_models.py (not touched by K2):
# the master reconciles the two.
AUDIT_MODULE: Final = "self_healing"
AUDIT_PREFIX: Final = "self_healing.manual."
EVENT_MANUAL_ACTION: Final = "self_healing.manual.action"

# Translation key of the "busy" error (strings.json "exceptions").
TRANSLATION_REPAIR_RUNNING: Final = "repair_running"

# At most this long for the user lookup of the audit, after the router call
# and with the lock released; a slow lookup leaves the user unverified.
AUDIT_LOOKUP_TIMEOUT_S: Final = 2.0


class ManualAction(StrEnum):
    """The closed set of manual router writes."""

    SERVICE_RESTART = "service.restart"
    SERVICE_START = "service.start"
    SERVICE_STOP = "service.stop"
    WIFI_RELOAD = "wifi.reload"
    WIFI_ENABLE = "wifi.enable"
    WIFI_DISABLE = "wifi.disable"
    ROUTER_REBOOT = "router.reboot"


class ManualResult(StrEnum):
    """Result of a manual action in the audit entry."""

    OK = "ok"
    REFUSED_BUSY = "refused_busy"
    FAILED = "failed"


class LockMode(StrEnum):
    """How the press held the router's repair lock."""

    TAKEN = "taken"  # took the lock
    JOINED = "joined"  # shared the lock of a press already running
    NONE = "none"  # no lock (module off, router unknown or lock held elsewhere)


# Lock source (``LockRecord.source``) per action: which entity kind wrote.
LOCK_SOURCES: Final[dict[ManualAction, str]] = {
    ManualAction.SERVICE_RESTART: "button.service_restart",
    ManualAction.SERVICE_START: "switch.service",
    ManualAction.SERVICE_STOP: "switch.service",
    ManualAction.WIFI_RELOAD: "button.reload_wifi",
    ManualAction.WIFI_ENABLE: "switch.wifi",
    ManualAction.WIFI_DISABLE: "switch.wifi",
    ManualAction.ROUTER_REBOOT: "button.reboot",
}

TARGET_WIFI: Final = "wifi"
TARGET_SYSTEM: Final = "system"
TARGET_OTHER: Final = "other"
# The closed set of targets: the services of DEFAULT_SERVICES, Wi-Fi as a
# whole (never an SSID or UCI section) and the system.
TARGETS: Final = frozenset((*DEFAULT_SERVICES, TARGET_WIFI, TARGET_SYSTEM))

_SHARES_KEY: Final = f"{DOMAIN}_heal_guard_shares"


def audit_target(target: str) -> str:
    """``target`` when it is in the closed set, else ``other``."""
    return target if target in TARGETS else TARGET_OTHER


@dataclass
class _Share:
    """The external lock one or more presses on a router hold together."""

    lock_id: str
    count: int = 1


@dataclass
class ManualOutcome:
    """What the press reports back: ``failed()`` or ``report(success)``."""

    ok: bool = True

    def report(self, success: Any) -> None:
        """The router call returned ``success`` (False: not accepted)."""
        self.ok = bool(success)

    def failed(self) -> None:
        """The router call failed (the press handled the error itself)."""
        self.ok = False


@dataclass
class _Press:
    """One press: what was found before the call and what it holds."""

    hass: HomeAssistant | None
    entry_id: str
    action: ManualAction
    target: str
    context: Context | None = None
    store: Any = None
    router_id: str | None = None
    busy: bool = False
    interrupted: bool = False
    on_hold: bool = False
    hold_reason: str | None = None
    lock: LockMode = LockMode.NONE
    share: _Share | None = field(default=None, repr=False)


def _shares(hass: HomeAssistant) -> WeakKeyDictionary[Any, dict[str, _Share]]:
    shares = hass.data.get(_SHARES_KEY)
    if not isinstance(shares, WeakKeyDictionary):
        shares = hass.data[_SHARES_KEY] = WeakKeyDictionary()
    return shares


def _core_api_now(hass: HomeAssistant | None) -> Any:
    """The Core's Configuration API when the Core is already loaded, else
    None (never loads, waits for or cancels it)."""
    if hass is None:
        return None
    try:
        from .enterprise_core import async_get_core

        core = async_get_core(hass)
        if core is None or core.closed or core.loaded is not True:
            return None
        return core.manager.api(1)
    except Exception as err:  # noqa: BLE001 - no Core: no audit, press goes on
        _LOGGER.debug("Manual action: no Core audit (%s)", type(err).__name__)
        return None


def _actor_now(context: Context | None) -> Any:
    """The actor of the service call without waiting: the same as
    ``core_models.async_actor_from_context`` but with ``is_admin`` False
    (unverified; the user lookup is what sets it)."""
    try:
        from .core_models import Actor, ActorKind

        if context is None:
            return Actor(kind=ActorKind.SYSTEM)
        if context.user_id:
            kind = ActorKind.USER
        elif context.parent_id:
            kind = ActorKind.AUTOMATION
        else:
            kind = ActorKind.SYSTEM
        return Actor(
            kind=kind,
            user_id=context.user_id or None,
            context_id=context.id,
            parent_context_id=context.parent_id,
        )
    except Exception as err:  # noqa: BLE001 - unknown actor, press goes on
        _LOGGER.debug("Manual action: no actor (%s)", type(err).__name__)
        return None


async def _async_actor(hass: HomeAssistant, context: Context | None) -> Any:
    """The actor with its user looked up, at most AUDIT_LOOKUP_TIMEOUT_S;
    the immediate actor when the lookup is slow or fails."""
    try:
        if context is None or not context.user_id:
            return _actor_now(context)  # nobody to look up
        from .core_models import async_actor_from_context

        async with asyncio.timeout(AUDIT_LOOKUP_TIMEOUT_S):
            return await async_actor_from_context(hass, context)
    except Exception as err:  # noqa: BLE001 - unverified actor, press goes on
        _LOGGER.debug("Manual action: user not looked up (%s)", type(err).__name__)
        return _actor_now(context)


def _core_router_id(api: Any, entry_id: str) -> str | None:
    """The Core's router id of an entry (None when unknown)."""
    if api is None:
        return None
    try:
        from .core_models import ROUTER_ID_PREFIX, is_valid_id

        rid = getattr(api.registry.get_by_entry(entry_id), "router_id", None)
    except Exception:  # noqa: BLE001 - not registered
        return None
    return rid if is_valid_id(rid, ROUTER_ID_PREFIX) else None


def _running_engine(hass: HomeAssistant) -> Any:
    """The engine whose store the press must respect, or None (module off)."""
    from .heal_engine import async_get_self_healing

    engine = async_get_self_healing(hass)
    if engine is None or engine.loaded is not True:
        return None
    if engine.module_enabled() is not True:
        return None
    return engine


def _interrupted(store: Any, router_id: str) -> bool:
    """The engine lock belongs to an action a restart interrupted.

    The store rebuilds an engine lock at load for every record in a locking
    state; the restart rule moves EXECUTING, VERIFYING and ROLLING_BACK to
    VERIFYING with ``flags.interrupted``, which only a restart sets. Read
    through the public surface only (``loop.lock_holder``, ``get``).
    """
    lock = store.loop.lock_holder(router_id)
    action_id = getattr(lock, "action_id", None)
    owner = store.get(action_id) if action_id else None
    return owner is not None and owner.flags.interrupted is True


def _find_lock_state(press: _Press) -> None:
    """Fill the engine part of ``press`` (no await: the check and the lock
    are one step, so the engine cannot take the lock in between)."""
    if press.hass is None:
        return
    engine = _running_engine(press.hass)
    if engine is None:
        return
    rid = engine.router_id_for_entry(press.entry_id)
    if rid is None:
        return  # a router the engine does not know cannot be locked by it
    store = engine.store
    press.store, press.router_id = store, rid
    if store.loop.repair_active(rid):
        if _interrupted(store, rid):
            press.interrupted = True  # no engine runs it: the press goes on
        else:
            press.busy = True
    hold = store.router_hold(rid)
    if hold is not None:
        press.on_hold = True
        press.hold_reason = str(hold.reason)


def _take_lock(press: _Press) -> None:
    """Hold the router's repair lock for the press (shared between presses)."""
    store, rid = press.store, press.router_id
    if store is None or rid is None or press.hass is None:
        return
    shares = _shares(press.hass).setdefault(store, {})
    share = shares.get(rid)
    held = store.loop.lock_holder(rid)
    if share is not None and held is not None and held.lock_id == share.lock_id:
        share.count += 1
        press.share, press.lock = share, LockMode.JOINED
        return
    lock_id = store.try_external_lock(rid, LOCK_SOURCES[press.action], store.clock())
    if lock_id is None:
        # held by another external writer (the engine is kept out anyway) or
        # by an interrupted engine action
        return
    # the press owns the lock first, so a failure below still releases it
    press.share, press.lock = _Share(lock_id=lock_id), LockMode.TAKEN
    shares[rid] = press.share


def _release_lock(press: _Press) -> None:
    """Release the press's share; the last press releases the lock.

    Never raises. A release that raises is tried once more; when that fails
    too, the guard drops its own lock (``LoopState.release_lock`` frees only
    the lock with this ``lock_id``), so a later press can lock again.
    """
    share, press.share = press.share, None
    store, rid = press.store, press.router_id
    if share is None or store is None or rid is None:
        return
    share.count -= 1
    if share.count > 0:
        return
    if press.hass is not None:
        try:
            shares = _shares(press.hass).get(store)
            if shares is not None and shares.get(rid) is share:
                del shares[rid]
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Repair lock share not dropped (%s)", type(err).__name__)
    error: Exception | None = None
    for _attempt in range(2):  # the release and one retry
        try:
            # False when an admin removed it meanwhile: nothing is ours to free
            store.release_external_lock(rid, share.lock_id)
        except Exception as err:  # noqa: BLE001
            error = err
            continue
        return
    with contextlib.suppress(Exception):
        store.loop.release_lock(rid, share.lock_id)
    _LOGGER.warning(
        "Repair lock not released, the guard dropped its own lock (%s)",
        type(error).__name__,
    )


_SEVERITY: Final = {
    ManualResult.OK: "info",
    ManualResult.REFUSED_BUSY: "warning",
    ManualResult.FAILED: "warning",
}
_EVENT_RESULT: Final = {
    ManualResult.OK: "success",
    ManualResult.REFUSED_BUSY: "denied",
    ManualResult.FAILED: "failure",
}


def audit_data(press: _Press, result: ManualResult) -> dict[str, Any]:
    """The ``data`` of the audit entry: closed codes and flags only."""
    return {
        "action": str(press.action),
        "target": audit_target(press.target),
        "result": str(result),
        "on_hold": press.on_hold,
        "hold_reason": press.hold_reason,
        "lock": str(press.lock),
        "interrupted_repair": press.interrupted,
    }


def _emit(press: _Press, api: Any, actor: Any, result: ManualResult) -> str | None:
    """Write the one audit entry; its event id, or None (never raises)."""
    if api is None:
        return None
    kwargs: dict[str, Any] = {
        "source": AUDIT_MODULE,
        "router_id": _core_router_id(api, press.entry_id) or press.router_id,
        "entry_id": press.entry_id,
        "severity": _SEVERITY[result],
        "result": _EVENT_RESULT[result],
        "actor": actor,
        "data": audit_data(press, result),
    }
    try:
        try:
            emitted = api.emit(EVENT_MANUAL_ACTION, **kwargs)
        except ValueError:
            # first entry of this Core: the prefix is not registered yet
            api.register_event_prefix(AUDIT_PREFIX, module=AUDIT_MODULE)
            emitted = api.emit(EVENT_MANUAL_ACTION, **kwargs)
        return str(emitted.event.event_id)
    except Exception as err:  # noqa: BLE001 - the audit never fails a press
        _LOGGER.debug("Manual action not audited (%s)", type(err).__name__)
        return None


def _record_write(press: _Press, audit_ref: str | None) -> None:
    """Remember the write in the store (module on, router known)."""
    store, rid = press.store, press.router_id
    if store is None or rid is None:
        return
    try:
        from .heal_model import ExternalWrite

        store.record_external_write(
            ExternalWrite(
                router_id=rid,
                source=LOCK_SOURCES[press.action],
                target=audit_target(press.target),
                ts=store.clock(),
                audit_ref=audit_ref,
            )
        )
    except Exception as err:  # noqa: BLE001 - bookkeeping never fails a press
        _LOGGER.debug("Manual write not recorded (%s)", type(err).__name__)


async def _async_finish(
    press: _Press, result: ManualResult, *, look_up_user: bool = True
) -> None:
    """Release the lock (first, always), then audit and record.

    Raises nothing of its own. Only here, after the router call and with
    the lock released, the user may be looked up (capped); a cancel during
    that wait still writes the entry (with the immediate actor) and is then
    raised on.
    """
    _release_lock(press)
    api = _core_api_now(press.hass)
    cancelled: asyncio.CancelledError | None = None
    actor: Any = None
    if api is not None:
        if look_up_user and press.hass is not None:
            try:
                actor = await _async_actor(press.hass, press.context)
            except asyncio.CancelledError as err:
                actor, cancelled = _actor_now(press.context), err
        else:
            actor = _actor_now(press.context)
    ref = _emit(press, api, actor, result)
    if result is not ManualResult.REFUSED_BUSY:
        _record_write(press, ref)
    if cancelled is not None:
        raise cancelled


def _prepare(
    hass: HomeAssistant | None,
    entry_id: str,
    action: ManualAction,
    target: str,
    context: Context | None,
) -> _Press:
    """Everything before the router call, in one synchronous step (no await:
    the engine cannot take the lock between the check and the lock, and
    nothing can hold the press up); never raises."""
    press = _Press(
        hass=hass, entry_id=entry_id, action=action, target=target, context=context
    )
    if hass is None:
        return press
    try:
        _find_lock_state(press)
        if not press.busy:
            _take_lock(press)
    except Exception as err:  # noqa: BLE001 - a guard bug never blocks a press
        _LOGGER.warning("Repair lock not checked (%s)", type(err).__name__)
        _release_lock(press)
        # what was seen stays in the audit (hold, interrupted repair); the
        # behaviour falls back: no store, no refusal, no lock
        press.store = press.router_id = None
        press.busy, press.lock = False, LockMode.NONE
    return press


@contextlib.asynccontextmanager
async def async_manual_action(
    hass: HomeAssistant | None,
    entry_id: str,
    action: ManualAction,
    target: str,
    context: Context | None = None,
) -> AsyncIterator[ManualOutcome]:
    """Run one manual router write under the repair lock, audited.

    Raises HomeAssistantError (``repair_running``) without running the body
    while a Self-Healing engine action really holds the router's lock. The
    body makes the router call and reports with ``outcome.report(success)``
    or ``outcome.failed()``; an exception out of the body (also a timeout or
    a cancel) counts as ``failed`` and is raised on unchanged. Nothing is
    awaited before the body.
    """
    press = _prepare(hass, entry_id, ManualAction(action), target, context)
    if press.busy:
        await _async_finish(press, ManualResult.REFUSED_BUSY)
        raise HomeAssistantError(
            translation_domain=DOMAIN,
            translation_key=TRANSLATION_REPAIR_RUNNING,
        )
    outcome = ManualOutcome()
    try:
        yield outcome
    except Exception:
        await _async_finish(press, ManualResult.FAILED)
        raise
    except BaseException:
        # a cancel (or exit): audit at once, no user lookup
        await _async_finish(press, ManualResult.FAILED, look_up_user=False)
        raise
    await _async_finish(press, ManualResult.OK if outcome.ok else ManualResult.FAILED)


__all__ = [
    "AUDIT_LOOKUP_TIMEOUT_S",
    "AUDIT_MODULE",
    "AUDIT_PREFIX",
    "EVENT_MANUAL_ACTION",
    "LOCK_SOURCES",
    "TARGETS",
    "TARGET_OTHER",
    "TARGET_SYSTEM",
    "TARGET_WIFI",
    "TRANSLATION_REPAIR_RUNNING",
    "LockMode",
    "ManualAction",
    "ManualOutcome",
    "ManualResult",
    "async_manual_action",
    "audit_data",
    "audit_target",
]
