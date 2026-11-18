"""Audit log and event bus of the enterprise core (contract §12).

One fleet-wide :class:`AuditLog` keeps every :class:`CoreEvent` in one of
two rings (``general`` 1000, ``security`` 500 entries, 90 days each),
persists them in the store ``openwrt_router.audit`` and publishes each new
entry once on the HA bus as ``openwrt_router_core_event`` (payload masked by
``core_masking.mask_for_output``).

Dedup (§12.4): the scope is ``(router_id or "-", type, dedup_key)``. A
repeat inside the fixed cooldown window is NOT published again; the stored
entry gets ``repeat_count + 1`` and ``last_repeat_at`` instead, so nothing
is lost. Scopes never cross routers or types: a repeat of router A never
hides an event of router B. Types in ``AUDIT_MANDATORY_EVENT_TYPES`` ignore
``dedup_key``. ``reset_dedup`` ends a scope early (drift gone, success
after a failure).

Every suppression is counted (``stats``): deduplicated repeats, entries
pushed out of a full ring, entries dropped by retention, failing listeners
and bus errors.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from homeassistant.core import HomeAssistant, callback

from . import core_store
from .const import AUDIT_SAVE_DELAY_SECONDS, AUDIT_STORE_MINOR_VERSION
from .core_masking import mask_for_output, pseudonymise_user_ids
from .core_models import (
    AUDIT_MAX_EVENTS,
    AUDIT_RETENTION_DAYS,
    AUDIT_STORE_KEY,
    CORE_STORE_VERSION,
    EVENT_CORE,
    EVENT_ID_PREFIX,
    FAILURE_EVENT_COOLDOWN,
    MODULE_EVENT_PREFIXES,
    RESERVED_NAMESPACES,
    SECURITY_AUDIT_MAX_EVENTS,
    Actor,
    AuditRing,
    CoreEvent,
    CoreEventListener,
    CoreEventType,
    EmitResult,
    EventResult,
    Severity,
    is_core_event_type,
    new_id,
    utcnow,
)

_LOGGER = logging.getLogger(__name__)

# ``source`` of every event the core emits itself.
CORE_SOURCE = "core"
RETENTION = timedelta(days=AUDIT_RETENTION_DAYS)
_RING_SIZES: Mapping[AuditRing, int] = {
    AuditRing.GENERAL: AUDIT_MAX_EVENTS,
    AuditRing.SECURITY: SECURITY_AUDIT_MAX_EVENTS,
}
# Open dedup windows (security review #7): windows that have passed are
# pruned whenever a new scope opens; above this many the oldest windows are
# dropped (counted in stats["dedup_scopes_dropped"], logged). A dropped
# window only means the next repeat is published again.
MAX_DEDUP_SCOPES = 4096


def migrate_audit_store(
    old_major: int, old_minor: int, old_data: Any
) -> dict[str, Any]:
    """Store migration. v1.x: additive minors, fill missing rings."""
    if old_major != CORE_STORE_VERSION or not isinstance(old_data, dict):
        # A newer or foreign major: the loader keeps a .bak and starts empty.
        raise NotImplementedError(f"audit store version {old_major} unknown")
    data = dict(old_data)
    for ring in AuditRing:
        if not isinstance(data.get(ring.value), list):
            data[ring.value] = []
    return data


class AuditLog:
    """The two audit rings, dedup, bus event and listeners (fleet-wide)."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Create an empty log; call :meth:`async_load` before use."""
        self.hass = hass
        self._store: Any = core_store.create_store(
            hass,
            CORE_STORE_VERSION,
            AUDIT_STORE_KEY,
            minor_version=AUDIT_STORE_MINOR_VERSION,
            migrate=migrate_audit_store,
        )
        self._lock = asyncio.Lock()
        self._rings: dict[AuditRing, deque[CoreEvent]] = {
            ring: deque() for ring in AuditRing
        }
        # dedup scope -> (event_id of the stored entry, start of the window,
        # cooldown of the window)
        self._dedup: dict[tuple[str, str, str], tuple[str, datetime, timedelta]] = {}
        self._listeners: list[CoreEventListener] = []
        # Salt of the user pseudonyms on the bus; in memory only. Random per
        # audit log until the core sets the stable, key-derived salt
        # (set_bus_salt) or declares this run ephemeral (§12.1).
        self._bus_salt = secrets.token_bytes(16)
        self.bus_salt_stable = False
        # registered module event prefixes -> module (and the registration)
        self._prefixes: dict[str, str] = {}
        self._prefix_tokens: dict[str, object] = {}
        # module types registered as audit-mandatory -> module (follow-up B3)
        self._mandatory: dict[str, str] = {}
        self.loaded = False
        self.load_failed = False
        self.backed_up = False
        self.dirty = False
        self._save_pending = False
        self._closed = False
        self.stats: dict[str, int] = {
            "emitted": 0,
            "published": 0,
            "deduplicated": 0,
            "evicted_general": 0,
            "evicted_security": 0,
            "expired": 0,
            "listener_errors": 0,
            "bus_errors": 0,
            "skipped_on_load": 0,
            "dedup_scopes_pruned": 0,
            "dedup_scopes_dropped": 0,
            "bus_salt_ephemeral": 0,
            "module_mandatory_types": 0,
            "security_relevant_module_events": 0,
        }

    # -- bus pseudonym salt ------------------------------------------------------------

    @callback
    def set_bus_salt(self, salt: bytes | None, *, reason: str = "") -> None:
        """Core-internal: the stable bus salt, or None for a random one.

        None keeps a random salt for this run; that is counted
        (``bus_salt_ephemeral``) and logged once. Emission never fails on it.
        """
        if salt is not None:
            if not isinstance(salt, bytes) or len(salt) < 16:
                raise ValueError("bus salt must be at least 16 bytes")
            self._bus_salt = salt
            self.bus_salt_stable = True
            return
        self.bus_salt_stable = False
        if self.stats["bus_salt_ephemeral"]:
            return
        self.stats["bus_salt_ephemeral"] += 1
        _LOGGER.info(
            "Enterprise core: no usable installation key (%s); bus pseudonyms "
            "are random for this run and change on the next restart",
            reason or "unavailable",
        )

    def registered_modules(self) -> frozenset[str]:
        """Modules that registered an event prefix in this run."""
        return frozenset(self._prefixes.values())

    # -- store ---------------------------------------------------------------------

    async def async_load(self) -> None:
        """Read the store once; an unreadable store is kept as ``.bak``."""
        async with self._lock:
            if self.loaded:
                return
            result = await core_store.async_load_store(
                self.hass, self._store, AUDIT_STORE_KEY
            )
            self.load_failed = result.failed
            self.backed_up = result.backed_up
            if result.data:
                self._restore(result.data)
            self.loaded = True
        if self.load_failed:
            self.emit(
                CoreEventType.STORE_RECOVERED,
                severity=Severity.WARNING,
                result=EventResult.FAILURE,
                data={"store": AUDIT_STORE_KEY, "backup_written": self.backed_up},
            )

    def _restore(self, stored: Mapping[str, Any]) -> None:
        cutoff = utcnow() - RETENTION
        for ring in AuditRing:
            raw = stored.get(ring.value)
            if not isinstance(raw, list):
                continue
            items: list[CoreEvent] = []
            for item in raw:
                try:
                    event = CoreEvent.from_dict(item)
                except (ValueError, TypeError, KeyError, AttributeError):
                    # one bad entry never drops the others (counted, logged)
                    self.stats["skipped_on_load"] += 1
                    continue
                if event.ts < cutoff:
                    self.stats["expired"] += 1
                    continue
                items.append(event)
            items.sort(key=lambda e: e.ts)
            size = _RING_SIZES[ring]
            if len(items) > size:
                self.stats[f"evicted_{ring.value}"] += len(items) - size
                items = items[-size:]
            self._rings[ring] = deque(items)
            for event in items:
                scope = event.dedup_scope
                if scope is not None:
                    # the newest stored entry of a scope opens its window
                    self._dedup[scope] = (
                        event.event_id,
                        event.ts,
                        FAILURE_EVENT_COOLDOWN,
                    )
        if self.stats["skipped_on_load"]:
            _LOGGER.warning(
                "Audit store: %d unreadable entries skipped",
                self.stats["skipped_on_load"],
            )

    @callback
    def schedule_save(self) -> None:
        """Mark a change; one delayed write at a time."""
        self.dirty = True
        if self._save_pending or self._closed:
            return
        self._save_pending = True
        self._store.async_delay_save(self._data_to_save, AUDIT_SAVE_DELAY_SECONDS)

    async def async_flush(self) -> None:
        """Write the store now."""
        await self._store.async_save(self._data_to_save())

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        self._save_pending = False
        self.dirty = False
        return {
            ring.value: [event.to_dict() for event in self._rings[ring]]
            for ring in AuditRing
        }

    @callback
    def close(self) -> None:
        """No writes are scheduled after this; listeners are dropped."""
        self._closed = True
        self._listeners.clear()

    # -- emit ----------------------------------------------------------------------

    def register_event_prefix(self, prefix: str, *, module: str) -> Callable[[], None]:
        """Allow ``module`` to emit types below ``prefix`` (e.g. ``foo.``).

        Returns a remover (idempotent): it drops the prefix and the
        module's audit-mandatory types below it. Callers that ignore the
        return value keep the 1.44 behaviour.
        """
        self._add_prefix(prefix, module)
        token = object()
        self._prefix_tokens[prefix] = token

        @callback
        def _remove() -> None:
            if self._prefix_tokens.get(prefix) is not token:
                return  # removed already, or registered again since
            del self._prefix_tokens[prefix]
            self._prefixes.pop(prefix, None)
            for event_type in [
                t
                for t, owner in self._mandatory.items()
                if owner == module and not self._owns(t, module)
            ]:
                del self._mandatory[event_type]
            self.stats["module_mandatory_types"] = len(self._mandatory)

        return _remove

    def _owns(self, event_type: str, module: str) -> bool:
        """True if ``module`` owns a registered prefix of ``event_type``."""
        return any(
            event_type.startswith(prefix) and len(event_type) > len(prefix)
            for prefix, owner in self._prefixes.items()
            if owner == module
        )

    def register_audit_mandatory_types(
        self, event_types: Iterable[str], *, module: str
    ) -> Callable[[], None]:
        """Make ``module``'s own types audit-mandatory (never deduplicated).

        Every type must lie below a prefix ``module`` registered (not the
        bare prefix); core types, reserved namespaces and other modules'
        types raise ValueError (nothing is registered then). Open dedup
        windows of these types end now. Returns a remover; unregistering
        the prefix or a core release undoes it too.
        """
        if not isinstance(event_types, Iterable) or isinstance(event_types, str):
            raise TypeError("event_types must be a list of type names")
        wanted = [str(t) for t in event_types]
        if module == CORE_SOURCE:
            raise ValueError("the core's mandatory types are fixed")
        for event_type in wanted:
            if (
                is_core_event_type(event_type)
                or event_type.startswith(RESERVED_NAMESPACES)
                or not self._owns(event_type, module)
            ):
                raise ValueError(
                    f"{event_type} is not a type below a prefix of {module}"
                )
            owner = self._mandatory.get(event_type)
            if owner is not None and owner != module:
                raise ValueError(f"{event_type} belongs to {owner}")
        added = [t for t in wanted if t not in self._mandatory]
        for event_type in added:
            self._mandatory[event_type] = module
        for scope in [s for s in self._dedup if s[1] in added]:
            del self._dedup[scope]
        self.stats["module_mandatory_types"] = len(self._mandatory)

        @callback
        def _remove() -> None:
            for event_type in added:
                if self._mandatory.get(event_type) == module:
                    del self._mandatory[event_type]
            self.stats["module_mandatory_types"] = len(self._mandatory)

        return _remove

    def _add_prefix(self, prefix: str, module: str) -> None:
        if not isinstance(prefix, str) or not prefix.endswith("."):
            raise ValueError("event prefix must end with '.'")
        if is_core_event_type(prefix):
            raise ValueError("core event namespaces are reserved for the core")
        if prefix.startswith(RESERVED_NAMESPACES):
            # capability namespaces (diag., log., rf., …) are not event prefixes
            raise ValueError(f"{prefix} is a capability namespace, not an event prefix")
        assigned = MODULE_EVENT_PREFIXES.get(module)
        if assigned is not None and not prefix.startswith(assigned):
            raise ValueError(f"module {module} emits below {assigned} only")
        for other, other_prefix in MODULE_EVENT_PREFIXES.items():
            if other != module and prefix.startswith(other_prefix):
                raise ValueError(f"event prefix {prefix} belongs to {other}")
        owner = self._prefixes.get(prefix)
        if owner is not None and owner != module:
            raise ValueError(f"event prefix {prefix} belongs to {owner}")
        self._prefixes[prefix] = module

    def _check_type(self, event_type: str, source: str) -> None:
        if is_core_event_type(event_type):
            if source != CORE_SOURCE:
                raise ValueError(f"only the core emits {event_type}")
            return
        if not any(
            event_type.startswith(prefix) and owner == source
            for prefix, owner in self._prefixes.items()
        ):
            raise ValueError(
                f"event type {event_type} is not below a prefix registered by {source}"
            )

    @callback
    def emit(
        self,
        event_type: str,
        *,
        source: str = CORE_SOURCE,
        severity: Severity | str = Severity.INFO,
        result: EventResult | str = EventResult.INFO,
        router_id: str | None = None,
        entry_id: str | None = None,
        actor: Actor | None = None,
        correlation_id: str | None = None,
        dedup_key: str | None = None,
        data: Mapping[str, Any] | None = None,
        cooldown: timedelta | None = None,
        now: datetime | None = None,
        security_relevant: bool = False,
        client_ref: str | None = None,
        confidence: float | None = None,
        classification: str | None = None,
        incident_ref: str | None = None,
        radio_id: str | None = None,
    ) -> EmitResult:
        """Record one event; publish it unless it repeats a scope in cooldown.

        ``data`` must carry ids and counters only (never configuration
        values, MACs, IPs or hostnames). ``cooldown`` is the dedup window
        (default ``FAILURE_EVENT_COOLDOWN``). Raises ValueError for a core
        type from a module or a module type below no registered prefix.
        ``security_relevant`` puts the event on the security ring; a type
        registered as audit-mandatory is never deduplicated. ``client_ref``,
        ``confidence``, ``classification``, ``incident_ref`` and ``radio_id``
        are the typed optional fields of ``CoreEvent`` (B8).
        """
        event_type = str(event_type)
        self._check_type(event_type, source)
        if not isinstance(security_relevant, bool):
            raise TypeError("security_relevant must be a bool")
        ts = now or utcnow()
        event = CoreEvent(
            event_id=new_id(EVENT_ID_PREFIX),
            ts=ts,
            type=event_type,
            source=source,
            severity=Severity(severity),
            result=EventResult(result),
            router_id=router_id,
            entry_id=entry_id,
            actor=actor,
            correlation_id=correlation_id,
            dedup_key=dedup_key,
            # masked before it is kept, persisted or published (review #6)
            data=mask_for_output(dict(data or {})),
            security_relevant=security_relevant,
            audit_mandatory=self._mandatory.get(event_type) == source,
            client_ref=client_ref,
            confidence=confidence,
            classification=classification,
            incident_ref=incident_ref,
            radio_id=radio_id,
        )
        if security_relevant and source != CORE_SOURCE:
            self.stats["security_relevant_module_events"] += 1
        self._expire(ts)
        scope = event.dedup_scope
        if scope is not None:
            repeated = self._repeat(scope, ts, event.audit_ring)
            if repeated is not None:
                self.stats["deduplicated"] += 1
                self.schedule_save()
                _LOGGER.debug(
                    "Core event %s for %s repeated (%d) inside its cooldown; "
                    "not published again",
                    event_type,
                    router_id or "-",
                    repeated.repeat_count,
                )
                return EmitResult(event=repeated, published=False, deduplicated=True)
            self._prune_dedup(ts)
            self._dedup[scope] = (
                event.event_id,
                ts,
                cooldown or FAILURE_EVENT_COOLDOWN,
            )
        self._append(event)
        self.stats["emitted"] += 1
        self.schedule_save()
        published = self._publish(event)
        return EmitResult(event=event, published=published)

    def _prune_dedup(self, now: datetime) -> None:
        """Forget passed windows; keep at most MAX_DEDUP_SCOPES - 1 open."""
        passed = [
            scope
            for scope, (_eid, started, cooldown) in self._dedup.items()
            if now - started >= cooldown
        ]
        for scope in passed:
            del self._dedup[scope]
        self.stats["dedup_scopes_pruned"] += len(passed)
        excess = len(self._dedup) - (MAX_DEDUP_SCOPES - 1)
        if excess > 0:
            oldest = sorted(self._dedup, key=lambda sc: self._dedup[sc][1])[:excess]
            for scope in oldest:
                del self._dedup[scope]
            self.stats["dedup_scopes_dropped"] += excess
            _LOGGER.warning(
                "Audit dedup: %d open windows dropped (cap %d); their next "
                "repeat is published again",
                excess,
                MAX_DEDUP_SCOPES,
            )

    def _repeat(
        self, scope: tuple[str, str, str], ts: datetime, ring_name: AuditRing
    ) -> CoreEvent | None:
        """Bump the stored entry of ``scope`` if its window is still open.

        Only an entry in the same ring counts: a security-relevant event
        never bumps a general entry (it opens its own window instead).
        """
        known = self._dedup.get(scope)
        if known is None:
            return None
        event_id, started, cooldown = known
        if ts - started >= cooldown:
            return None
        ring = self._rings[ring_name]
        for index in range(len(ring) - 1, -1, -1):
            stored = ring[index]
            if stored.event_id == event_id:
                updated = _with_repeat(stored, ts)
                ring[index] = updated
                return updated
        # the entry left the ring (overflow / retention): start a new window
        return None

    def _append(self, event: CoreEvent) -> None:
        ring_name = event.audit_ring
        ring = self._rings[ring_name]
        if len(ring) >= _RING_SIZES[ring_name]:
            ring.popleft()
            self.stats[f"evicted_{ring_name.value}"] += 1
        ring.append(event)

    def _expire(self, now: datetime) -> None:
        cutoff = now - RETENTION
        for ring in self._rings.values():
            while ring and ring[0].ts < cutoff:
                ring.popleft()
                self.stats["expired"] += 1

    def _publish(self, event: CoreEvent) -> bool:
        # The bus event reaches the recorder and the logbook: user ids go
        # out as pseudonyms (review PR #55, finding 7). Listeners in this
        # process and the audit store keep the real id.
        payload = mask_for_output(
            pseudonymise_user_ids(event.to_dict(), self._bus_salt)
        )
        published = True
        try:
            self.hass.bus.async_fire(EVENT_CORE, payload)
            self.stats["published"] += 1
        except Exception:
            published = False
            self.stats["bus_errors"] += 1
            _LOGGER.warning(
                "Core event %s could not be fired", event.type, exc_info=True
            )
        for listener in list(self._listeners):
            try:
                listener(event)
            except Exception:
                self.stats["listener_errors"] += 1
                _LOGGER.warning(
                    "Core event listener %r raised for %s",
                    listener,
                    event.type,
                    exc_info=True,
                )
        return published

    @callback
    def reset_dedup(
        self, router_id: str | None, event_type: str, dedup_key: str | None = None
    ) -> int:
        """End dedup windows early (all keys of the type if ``dedup_key`` is None).

        Used when a drift disappears or a success follows failures, so the
        next occurrence is published again. Returns how many were reset.
        """
        rid = router_id or "-"
        doomed = [
            scope
            for scope in self._dedup
            if scope[0] == rid
            and scope[1] == str(event_type)
            and (dedup_key is None or scope[2] == dedup_key)
        ]
        for scope in doomed:
            del self._dedup[scope]
        return len(doomed)

    # -- read ----------------------------------------------------------------------

    def subscribe(self, listener: CoreEventListener) -> Callable[[], None]:
        """Call ``listener(event)`` for every published event (sync, short)."""
        self._listeners.append(listener)

        @callback
        def _unsubscribe() -> None:
            if listener in self._listeners:
                self._listeners.remove(listener)

        return _unsubscribe

    @property
    def listener_count(self) -> int:
        """Number of subscribed listeners."""
        return len(self._listeners)

    def events(
        self,
        router_id: str | None = None,
        types: Iterable[str] | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        correlation_id: str | None = None,
        *,
        ring: AuditRing | str | None = None,
        limit: int | None = None,
    ) -> tuple[CoreEvent, ...]:
        """Stored events, oldest first, filtered; ``limit`` keeps the newest."""
        wanted = None if types is None else {str(t) for t in types}
        rings = list(AuditRing) if ring is None else [AuditRing(ring)]
        out = [
            event
            for name in rings
            for event in self._rings[name]
            if (router_id is None or event.router_id == router_id)
            and (wanted is None or event.type in wanted)
            and (since is None or event.ts >= since)
            and (until is None or event.ts <= until)
            and (correlation_id is None or event.correlation_id == correlation_id)
        ]
        out.sort(key=lambda e: e.ts)
        if limit is not None:
            out = out[-limit:] if limit > 0 else []
        return tuple(out)

    def ring_size(self, ring: AuditRing | str) -> int:
        """Entries currently in ``ring``."""
        return len(self._rings[AuditRing(ring)])

    def summary(self) -> dict[str, Any]:
        """Counters for diagnostics (no event content)."""
        return {
            "loaded": self.loaded,
            "load_failed": self.load_failed,
            "general": self.ring_size(AuditRing.GENERAL),
            "security": self.ring_size(AuditRing.SECURITY),
            "listeners": len(self._listeners),
            "dedup_scopes": len(self._dedup),
            **self.stats,
        }


def _with_repeat(event: CoreEvent, ts: datetime) -> CoreEvent:
    """``event`` with one more repeat at ``ts`` (frozen: a new object).

    ``replace`` keeps every other field, also ones added later.
    """
    return replace(event, repeat_count=event.repeat_count + 1, last_repeat_at=ts)
