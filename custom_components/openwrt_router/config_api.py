"""Configuration API v1 of the enterprise core (contract §2, §8, §10).

:class:`ConfigurationManager` is core-internal: it owns the provider slot,
the router locks, the fleet backup queue, the probes and every
``configuration.*`` event. Modules get a :class:`ConfigurationApi` from
:func:`async_get_configuration_api` (``hass, version=1``); it only exposes
the contract methods plus read-only views of the registry, the guard and
the version index, so no mutating path (store writes, registry hooks,
audit as the core) is reachable through a public object.

Without a registered provider every ``config.*`` capability is
``unavailable``/``no_provider``, every operation that needs the router
raises CapabilityUnavailableError, and the core makes ZERO router calls.

Order of a backup (§8, fixed): fleet slot -> router lock -> verify actor
and ``authorize`` -> ``provider.async_collect`` -> dedup / consume / put ->
events -> release. Reads never take a lock and run concurrently.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
    Iterator,
    Mapping,
    Sequence,
)
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.util import dt as dt_util

from .const import (
    CONFIG_PROVIDER_CALL_TIMEOUT_SECONDS,
    CONFIG_PROVIDER_COLLECT_TIMEOUT_SECONDS,
    CONFIG_PROVIDER_PROBE_TIMEOUT_SECONDS,
    CONFIG_PROVIDER_RESTORE_TIMEOUT_SECONDS,
)
from .core_audit import CORE_SOURCE, AuditLog
from .core_errors import (
    ApiVersionError,
    ApprovalInvalidError,
    AuthorizationError,
    BackupIncompleteError,
    BackupNotFoundError,
    CapabilityUnavailableError,
    ConfigApiError,
    ErrorClass,
    OperationInProgressError,
    OperationTimeoutError,
    ProviderConflictError,
    ProviderError,
    RestoreIncompatibleError,
    RouterUnavailableError,
    StorageFullError,
)
from .core_guard import (
    FLEET_ROUTER_ID,
    ActionGuard,
    error_for_decision,
    raise_for_decision,
)
from .core_models import (
    APPROVAL_TTL,
    CONFIG_CAPABILITIES,
    CORE_KEY_OWNER,
    CORRELATION_ID_PREFIX,
    DEFAULT_LIST_LIMIT,
    DEFAULT_RETENTION_POLICY,
    FLEET_BACKUP_CONCURRENCY,
    OPTION_CONFIG_BACKUP_ENABLED,
    ROUTER_LOCK_TIMEOUT,
    SUPPORTED_API_VERSIONS,
    SUPPORTED_PROVIDER_API_VERSIONS,
    Actor,
    ActorKind,
    ApprovalRequest,
    ArtifactKind,
    ArtifactPayload,
    AuditRing,
    BackupLinks,
    BackupReason,
    BackupRecord,
    BackupType,
    Baseline,
    BaselineRule,
    Capability,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    CaptureRequest,
    CollectedVersion,
    CollectRequest,
    CompatibilityCheck,
    ConfigBackupProvider,
    ConfigDiff,
    ConfigRef,
    ConfigSnapshot,
    CoreEvent,
    CoreEventListener,
    CoreEventType,
    DecisionState,
    DriftAck,
    DriftAckState,
    DriftComparison,
    DriftReport,
    EmitResult,
    EventResult,
    ExportHandle,
    GuardedAction,
    InstallationKeyState,
    ProviderContext,
    PutVersionResult,
    ReachabilityState,
    RecordState,
    RestorePlan,
    RestoreResult,
    RestoreStatus,
    RetentionPolicy,
    RetentionResult,
    RouterConnection,
    RouterRecord,
    Severity,
    ValidationInfo,
    VerifiedActor,
    VersionMeta,
    VersionStatus,
    WriteAuthorization,
    binding_checksum,
    check_module_name,
    check_token,
    derive_module_key,
    drift_event_types,
    ensure_supported_api_version,
    new_id,
    plan_retention,
    select_baseline,
    utcnow,
    validate_deletion,
)
from .router_registry import RouterRegistry
from .version_store import VersionStore

_LOGGER = logging.getLogger(__name__)

# Capability each operation needs (the provider decides it per router).
_DRIFT_EVENT_TYPES = (
    CoreEventType.DRIFT_DETECTED,
    CoreEventType.CHANGE_CRITICAL,
    CoreEventType.CHANGE_UNKNOWN,
    CoreEventType.DRIFT_INCOMPLETE,
)
# Max ids listed in event data (counts are always complete).
_EVENT_ID_LIST_MAX = 50
REBASELINE_DRIFT_PREFIX = "rebaseline:"
_ARTIFACT_KINDS = frozenset(kind.value for kind in ArtifactKind)
# Reads of configuration content (secrets): the ``action`` named in the
# audited refusal of a user who is not a verified admin (no guard action:
# reads mint no authorization).
READ_CAPTURE = "config_capture"
READ_COMPARE = "config_compare"
# Same rule for validation, drift and the restore dry run (follow-up B2).
READ_VALIDATE = "config_validate"
READ_DRIFT = "config_drift"
READ_RESTORE_DRY_RUN = "config_restore_dry_run"
# Dry-run plans waiting for async_request_restore (security review #4):
# dropped after this long, and the oldest beyond the cap (both counted).
RESTORE_PLAN_TTL = APPROVAL_TTL
MAX_RESTORE_PLANS = 50


def _ids(values: Iterable[str]) -> list[str]:
    return sorted(values)[:_EVENT_ID_LIST_MAX]


def _first_use(status: CapabilityStatus) -> bool:
    """``unknown`` until the first real use (a probe could not tell safely)."""
    return (
        status.state is CapabilityState.UNKNOWN
        and str(status.reason) == CapabilityReason.DETERMINED_ON_FIRST_USE.value
    )


def _check_collected(router_id: str, collected: object) -> CollectedVersion:
    """Provider output is untrusted input: closed artifact kinds, payloads only.

    A provider never supplies a path: anything but ArtifactPayload (e.g. an
    ArtifactRef with a locator) is refused. Sizes and sha256 are checked
    by the store from the bytes themselves.
    """

    def invalid(reason: str) -> ProviderError:
        return ProviderError(
            "Provider returned an unusable version",
            router_id=router_id,
            error_class=ErrorClass.INVALID,
            details={"operation": "collect", "reason": reason},
        )

    if not isinstance(collected, CollectedVersion):
        raise invalid("not_a_collected_version")
    if not isinstance(collected.meta, VersionMeta):
        raise invalid("meta_not_version_meta")
    for kind, value in collected.artifacts.items():
        if kind not in _ARTIFACT_KINDS:
            raise invalid("unknown_artifact_kind")
        if not isinstance(value, ArtifactPayload):
            raise invalid("artifact_not_a_payload")
    return collected


# -- read-only views (what modules get) -----------------------------------------------


class RegistryReadView:
    """``api.registry``: the read side of the router registry plus adopt."""

    __slots__ = ("_registry",)

    def __init__(self, registry: RouterRegistry) -> None:
        """Wrap the registry (the hooks stay unreachable)."""
        self._registry = registry

    def get(self, router_id: str) -> RouterRecord:
        """Record by router id; RouterNotFoundError if unknown."""
        return self._registry.get(router_id)

    def get_by_entry(self, entry_id: str) -> RouterRecord:
        """Active record of a config entry."""
        return self._registry.get_by_entry(entry_id)

    def find(self, router_id: str) -> RouterRecord | None:
        """Record by router id or None."""
        return self._registry.find(router_id)

    def list(self, *, include_orphaned: bool = False) -> tuple[RouterRecord, ...]:
        """All active (and optionally orphaned) records."""
        return self._registry.list(include_orphaned=include_orphaned)

    def capabilities(self, router_id: str) -> Mapping[str, CapabilityStatus]:
        """Read-only capability map of a router."""
        return self._registry.capabilities(router_id)

    def has_capability(self, router_id: str, capability: str) -> bool:
        """True if available now."""
        return self._registry.has_capability(router_id, capability)

    def require_capability(self, router_id: str, capability: str) -> None:
        """Raise CapabilityUnavailableError unless available."""
        self._registry.require_capability(router_id, capability)

    def adoption_candidates(self, entry_id: str) -> tuple[Any, ...]:
        """Orphaned records matching the entry's router."""
        return self._registry.adoption_candidates(entry_id)

    async def async_adopt(
        self, entry_id: str, orphan_router_id: str, *, actor: Actor
    ) -> RouterRecord:
        """Adopt through the guard (admin user only)."""
        return await self._registry.async_adopt(entry_id, orphan_router_id, actor=actor)


class GuardView:
    """``api.guard``: the ActionGuardProtocol methods, nothing else."""

    __slots__ = ("_guard",)

    def __init__(self, guard: ActionGuard) -> None:
        """Wrap the guard (ledger and audit stay unreachable)."""
        self._guard = guard

    async def async_verify_actor(self, actor: Actor) -> VerifiedActor:
        """Re-check an Actor against hass.auth."""
        return await self._guard.async_verify_actor(actor)

    async def async_resolve_actor(
        self, context: Any, *, module: str | None = None
    ) -> VerifiedActor:
        """Actor from an HA Context, verified."""
        return await self._guard.async_resolve_actor(context, module=module)

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
    ) -> Any:
        """Synchronous decision (audited)."""
        return self._guard.authorize(
            action,
            router_id,
            actor,
            subject_id=subject_id,
            checksum=checksum,
            approval_id=approval_id,
            correlation_id=correlation_id,
        )

    def consume(
        self,
        authorization: WriteAuthorization,
        *,
        action: str,
        router_id: str,
        checksum: str | None = None,
    ) -> None:
        """Use an authorization once (audited)."""
        self._guard.consume(
            authorization, action=action, router_id=router_id, checksum=checksum
        )

    def approve(self, approval_id: str, *, actor: VerifiedActor) -> ApprovalRequest:
        """A verified admin user approves."""
        return self._guard.approve(approval_id, actor=actor)

    def reject(
        self, approval_id: str, *, actor: VerifiedActor, reason: str | None = None
    ) -> ApprovalRequest:
        """A verified admin user rejects."""
        return self._guard.reject(approval_id, actor=actor, reason=reason)

    def get_approval(self, approval_id: str) -> ApprovalRequest:
        """Request by id."""
        return self._guard.get_approval(approval_id)

    def pending_approvals(
        self, router_id: str | None = None
    ) -> tuple[ApprovalRequest, ...]:
        """Open requests, newest first."""
        return self._guard.pending_approvals(router_id)

    def register_action(
        self,
        name: str,
        action_class: Any,
        *,
        module: str,
        admin_user_only: bool = False,
        sensitive_read: bool = False,
        rate_limit: Any = None,
    ) -> None:
        """Register ``<module>.<action>`` (``sensitive_read``, ``rate_limit``: B5)."""
        self._guard.register_action(
            name,
            action_class,
            module=module,
            admin_user_only=admin_user_only,
            sensitive_read=sensitive_read,
            rate_limit=rate_limit,
        )


class VersionView:
    """``api.versions``: VersionReadView (index only, no bytes, no writes)."""

    __slots__ = ("_store",)

    def __init__(self, store: VersionStore) -> None:
        """Wrap the store."""
        self._store = store

    async def async_list_versions(
        self,
        router_id: str | None = None,
        *,
        since: datetime | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> tuple[BackupRecord, ...]:
        """Versions, newest first."""
        return await self._store.async_list_versions(
            router_id, since=since, limit=limit
        )

    async def async_get_version(self, version_id: str) -> BackupRecord:
        """One version."""
        return await self._store.async_get_version(version_id)

    async def async_list_drift_acks(self, router_id: str) -> tuple[DriftAck, ...]:
        """Acknowledgements of a router."""
        return await self._store.async_list_drift_acks(router_id)

    def usage_bytes(self, router_id: str | None = None) -> int:
        """Bytes used by one router or in total."""
        return self._store.usage_bytes(router_id)


# -- the manager ----------------------------------------------------------------------


class ConfigurationManager:
    """Core-internal implementation of the Configuration API v1."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        audit: AuditLog,
        registry: RouterRegistry,
        guard: ActionGuard,
        versions: VersionStore,
        clock: Callable[[], datetime] = utcnow,
        lock_timeout: timedelta = ROUTER_LOCK_TIMEOUT,
        collect_timeout: float = CONFIG_PROVIDER_COLLECT_TIMEOUT_SECONDS,
        call_timeout: float = CONFIG_PROVIDER_CALL_TIMEOUT_SECONDS,
        probe_timeout: float = CONFIG_PROVIDER_PROBE_TIMEOUT_SECONDS,
        restore_timeout: float = CONFIG_PROVIDER_RESTORE_TIMEOUT_SECONDS,
    ) -> None:
        """Wire the services; nothing runs until a provider registers."""
        self.hass = hass
        self.audit = audit
        self.registry = registry
        self.guard = guard
        self.versions = versions
        self._clock = clock
        self.lock_timeout = lock_timeout
        self.collect_timeout = collect_timeout
        self.call_timeout = call_timeout
        self.probe_timeout = probe_timeout
        self.restore_timeout = restore_timeout
        self._provider: ConfigBackupProvider | None = None
        self._remove_capability_hook: Callable[[], None] | None = None
        self._probes: dict[str, dict[str, CapabilityStatus]] = {}
        self._probe_tasks: dict[str, asyncio.Task[None]] = {}
        self._probe_again: dict[str, str] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._fleet = asyncio.Semaphore(FLEET_BACKUP_CONCURRENCY)
        self._retention_policy: RetentionPolicy = DEFAULT_RETENTION_POLICY
        self._retention_module: str | None = None
        self._failing: dict[str, set[str]] = {}
        self._exports: dict[str, tuple[str, str]] = {}
        self._deletions: dict[str, tuple[str, ...]] = {}
        self._plans: dict[str, RestorePlan] = {}
        self._plan_made: dict[str, datetime] = {}
        self._restores: dict[str, RestorePlan] = {}
        self._apis: dict[int, ConfigurationApi] = {}
        # ACL deploy + SSH pin flows (core_security.SecurityActions), set by
        # the enterprise core; None in bare manager tests.
        self.security: Any = None
        self.closed = False
        self.stats: dict[str, int] = {
            "providers_registered": 0,
            "providers_rejected": 0,
            "probes": 0,
            "probe_errors": 0,
            "probes_skipped": 0,
            "probes_coalesced": 0,
            "probe_entries_dropped": 0,
            "backups_started": 0,
            "backups_created": 0,
            "backups_deduplicated": 0,
            "backups_failed": 0,
            "backup_failed_events_suppressed": 0,
            "lock_waits": 0,
            "lock_timeouts": 0,
            "provider_errors": 0,
            "provider_timeouts": 0,
            "retention_runs": 0,
            "retention_deleted": 0,
            "storage_limit_exceeded": 0,
            "first_use_settled": 0,
            "drift_checks": 0,
            "drift_incomplete": 0,
            "drift_inconsistent": 0,
            "rebaselines": 0,
            "rebaseline_refused": 0,
            "rebaseline_unconfirmed": 0,
            "exports": 0,
            "deletions": 0,
            "restores": 0,
            "requests_dropped_on_close": 0,
            "requests_dropped_on_expiry": 0,
            "plans_expired": 0,
            "plans_evicted": 0,
            "refused_disabled": 0,
            "module_keys_issued": 0,
            "module_keys_refused": 0,
            "validate_without_actor": 0,
        }
        # Request data dies with its approval (expired, rejected, unload).
        self._remove_approval_listener = guard.add_approval_listener(
            self._approval_ended
        )

    def now(self) -> datetime:
        """Current time (aware UTC)."""
        return self._clock()

    # -- api objects -----------------------------------------------------------------

    def api(self, version: int) -> ConfigurationApi:
        """The public object for ``version`` (ApiVersionError if unknown)."""
        version = ensure_supported_api_version(version)
        api = self._apis.get(version)
        if api is None:
            api = ConfigurationApi(self, version)
            self._apis[version] = api
        return api

    @property
    def provider_id(self) -> str | None:
        """Registered provider or None."""
        return None if self._provider is None else str(self._provider.provider_id)

    # -- provider --------------------------------------------------------------------

    @callback
    def register_provider(self, provider: ConfigBackupProvider) -> Callable[[], None]:
        """Register THE provider; returns an idempotent unregister callback."""
        if self.closed:
            raise ConfigApiError(
                "The enterprise core is shutting down",
                retryable=True,
                details={"reason": "core_closed"},
            )
        if self._provider is not None:
            self.stats["providers_rejected"] += 1
            raise ProviderConflictError(
                "A configuration provider is already registered",
                details={"registered": self.provider_id},
            )
        version = getattr(provider, "provider_api_version", None)
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version not in SUPPORTED_PROVIDER_API_VERSIONS
        ):
            self.stats["providers_rejected"] += 1
            raise ApiVersionError(
                f"Provider API version {version!r} is not supported",
                requested=version,
                supported_versions=SUPPORTED_PROVIDER_API_VERSIONS,
            )
        if not isinstance(provider, ConfigBackupProvider):
            self.stats["providers_rejected"] += 1
            raise TypeError("provider does not implement ConfigBackupProvider")
        provider_id = getattr(provider, "provider_id", None)
        if not isinstance(provider_id, str) or not provider_id:
            self.stats["providers_rejected"] += 1
            raise ValueError("provider_id must be a non-empty string")
        self._provider = provider
        self._probes.clear()
        self.stats["providers_registered"] += 1
        self._remove_capability_hook = self.registry.set_config_capability_provider(
            self._capability_hook
        )
        _LOGGER.info("Configuration provider %s registered", provider_id)
        for router_id in self.registry.attached_router_ids():
            self._schedule_probe(router_id, "provider_registered")

        @callback
        def _unregister() -> None:
            if self._provider is provider:
                self._drop_provider()

        return _unregister

    @callback
    def _drop_provider(self) -> None:
        provider_id = self.provider_id
        self._provider = None
        self._probes.clear()
        for task in self._probe_tasks.values():
            task.cancel()
        self._probe_tasks.clear()
        self._probe_again.clear()
        if self._remove_capability_hook is not None:
            self._remove_capability_hook()
            self._remove_capability_hook = None
        if provider_id is not None:
            _LOGGER.info("Configuration provider %s unregistered", provider_id)

    def _capability_hook(self, record: RouterRecord) -> Mapping[str, CapabilityStatus]:
        """Registry hook: probe results (sync, no I/O)."""
        provider = self._provider
        if provider is None:
            return {}
        if not provider.supported(record):
            now = self.now()
            return {
                name: CapabilityStatus(
                    capability=name,
                    state=CapabilityState.UNAVAILABLE,
                    reason=CapabilityReason.PROVIDER_DECLINED,
                    source=f"provider:{provider.provider_id}",
                    detected_at=now,
                )
                for name in sorted(CONFIG_CAPABILITIES)
            }
        return dict(self._probes.get(record.router_id, {}))

    def capability(self, router_id: str, capability: str) -> CapabilityStatus:
        """Current status of one config.* capability (no router call)."""
        name = str(capability)
        record = self.registry.get(router_id)
        now = self.now()

        def status(state: CapabilityState, reason: str) -> CapabilityStatus:
            return CapabilityStatus(
                capability=name,
                state=state,
                reason=reason,
                source="config_api",
                detected_at=now,
            )

        provider = self._provider
        if record.state is RecordState.ACTIVE and not self.registry.config_enabled(
            router_id
        ):
            # Option config_backup_enabled (default OFF since 1.44.0; read
            # from the config entry when the entry is not loaded). Same order
            # as the registry: the option wins over a missing provider.
            return status(CapabilityState.UNAVAILABLE, CapabilityReason.DISABLED)
        if provider is None:
            return status(CapabilityState.UNAVAILABLE, CapabilityReason.NO_PROVIDER)
        if record.state is not RecordState.ACTIVE:
            return status(
                CapabilityState.UNAVAILABLE, CapabilityReason.ENTRY_NOT_LOADED
            )
        if not provider.supported(record):
            return status(
                CapabilityState.UNAVAILABLE, CapabilityReason.PROVIDER_DECLINED
            )
        probed = self._probes.get(router_id, {}).get(name)
        if probed is None:
            return status(CapabilityState.UNKNOWN, CapabilityReason.NOT_PROBED)
        return probed

    def _require(self, router_id: str, capability: str) -> ConfigBackupProvider:
        """The provider if ``capability`` is available or may be tried.

        ``unknown`` + ``determined_on_first_use`` may be tried: the result of
        that first real use settles the status (:meth:`_settle_first_use`).
        """
        status = self.capability(router_id, capability)
        if self._provider is None or not (status.available or _first_use(status)):
            raise CapabilityUnavailableError(
                capability=str(capability),
                reason=str(status.reason),
                router_id=router_id,
            )
        return self._provider

    def _settle_first_use(
        self,
        router_id: str,
        capability: str,
        *,
        error: ConfigApiError | None = None,
        operation: str,
    ) -> None:
        """Turn ``determined_on_first_use`` into a real state after a use.

        Success -> available; a permission / not-available error ->
        unavailable; any other error (offline, timeout) leaves it unknown.
        """
        name = str(capability)
        probes = self._probes.get(router_id)
        current = None if probes is None else probes.get(name)
        if current is None or not _first_use(current):
            return
        if error is None:
            state, reason = CapabilityState.AVAILABLE, CapabilityReason.OK.value
        elif error.error_class is ErrorClass.PERMISSION:
            state = CapabilityState.UNAVAILABLE
            reason = CapabilityReason.PERMISSION_DENIED.value
        elif error.error_class is ErrorClass.NOT_AVAILABLE:
            state = CapabilityState.UNAVAILABLE
            reason = CapabilityReason.NOT_DETECTED.value
        else:
            return
        probes[name] = CapabilityStatus(
            capability=name,
            state=state,
            reason=reason,
            source=current.source,
            detected_at=self.now(),
            required_permissions=current.required_permissions,
            detail={"settled_by": operation},
        )
        self.stats["first_use_settled"] += 1
        _LOGGER.info(
            "Capability %s of %s settled on first use: %s", name, router_id, state
        )
        self.registry.invalidate_capabilities()

    @contextlib.contextmanager
    def _settling(
        self, router_id: str, capability: str, operation: str
    ) -> Iterator[None]:
        """Settle a first-use capability from the outcome of the wrapped call."""
        try:
            yield
        except ConfigApiError as err:
            if not isinstance(err, AuthorizationError):
                self._settle_first_use(
                    router_id, capability, error=err, operation=operation
                )
            raise
        self._settle_first_use(router_id, capability, operation=operation)

    def _require_provider(self, capability: str) -> ConfigBackupProvider:
        if self._provider is None:
            raise CapabilityUnavailableError(
                capability=str(capability), reason=CapabilityReason.NO_PROVIDER.value
            )
        return self._provider

    def _require_enabled(self, router_id: str, capability: str) -> None:
        """Refuse a stored-version operation while the option is OFF.

        Only for an ACTIVE router whose entry has ``config_backup_enabled``
        off; versions of orphaned routers keep their existing behaviour.
        Counted in ``refused_disabled``.
        """
        record = self.registry.find(router_id)
        if (
            record is not None
            and record.state is RecordState.ACTIVE
            and not self.registry.config_enabled(router_id)
        ):
            self.stats["refused_disabled"] += 1
            raise CapabilityUnavailableError(
                capability=str(capability),
                reason=CapabilityReason.DISABLED.value,
                router_id=router_id,
            )

    @callback
    def on_config_option_changed(
        self, router_id: str, enabled: bool, *, actor: Actor | None = None
    ) -> None:
        """Options flow: ``config_backup_enabled`` changed for a router.

        Audited first (security ring, ``security.config_option_changed``
        with actor, old and new value). ON probes again (one provider probe,
        only with a provider); OFF drops the stored probe results so nothing
        stale comes back.
        """
        self.audit_config_option_changed(router_id, enabled, actor=actor)
        if enabled:
            self.request_probe(router_id, "config_option_enabled")
            return
        if self._probes.pop(router_id, None) is not None:
            self.registry.invalidate_capabilities()

    def audit_config_option_changed(
        self, router_id: str | None, enabled: bool, *, actor: Actor | None = None
    ) -> None:
        """One security-ring entry for a changed ``config_backup_enabled``.

        ``actor`` None: Home Assistant did not say who submitted the options
        form (``actor_known`` False in the data).
        """
        self._emit(
            CoreEventType.CONFIG_OPTION_CHANGED,
            router_id=router_id or "-",
            actor=actor,
            result=EventResult.SUCCESS,
            data={
                "option": OPTION_CONFIG_BACKUP_ENABLED,
                "old": not enabled,
                "new": bool(enabled),
                "source": "options_flow",
                "actor_known": actor is not None,
            },
        )

    # -- probes ----------------------------------------------------------------------

    @callback
    def on_probe_trigger(self, entry_id: str, router_id: str, reason: str) -> None:
        """Registry listener: attach or firmware change (never per poll)."""
        if self._provider is None or self.closed:
            self.stats["probes_skipped"] += 1
            return
        self._schedule_probe(router_id, reason)

    @callback
    def request_probe(self, router_id: str, reason: str) -> bool:
        """Probe again (e.g. after an ACL redeploy). False without a provider."""
        if self._provider is None or self.closed:
            self.stats["probes_skipped"] += 1
            return False
        self.registry.get(router_id)
        self._schedule_probe(router_id, reason)
        return True

    @callback
    def _schedule_probe(self, router_id: str, reason: str) -> None:
        running = self._probe_tasks.get(router_id)
        if running is not None and not running.done():
            self.stats["probes_coalesced"] += 1
            self._probe_again[router_id] = reason
            return
        self._probe_tasks[router_id] = self.hass.async_create_task(
            self._async_probe_loop(router_id, reason),
            name=f"openwrt_router config probe {router_id}",
        )

    async def _async_probe_loop(self, router_id: str, reason: str) -> None:
        try:
            while True:
                await self.async_probe(router_id, reason)
                again = self._probe_again.pop(router_id, None)
                if again is None:
                    return
                reason = again
        finally:
            task = self._probe_tasks.get(router_id)
            if task is asyncio.current_task():
                self._probe_tasks.pop(router_id, None)

    async def async_probe(self, router_id: str, reason: str) -> bool:
        """Run the provider's probe for one router; never raises.

        Returns True if results were stored. Unknown names or non-status
        values are dropped and counted (``probe_entries_dropped``).
        """
        provider = self._provider
        if provider is None or self.closed:
            self.stats["probes_skipped"] += 1
            return False
        record = self.registry.find(router_id)
        attached = self.registry.attached(router_id)
        if record is None or attached is None or not attached.config_enabled:
            self.stats["probes_skipped"] += 1
            return False
        if not provider.supported(record):
            self.stats["probes_skipped"] += 1
            self._probes.pop(router_id, None)
            self.registry.invalidate_capabilities()
            return False
        self.stats["probes"] += 1
        try:
            conn = self._connection(router_id)
            result = await self._call(
                router_id,
                "probe",
                provider.async_probe(conn, self._context()),
                self.probe_timeout,
            )
        except ConfigApiError as err:
            self.stats["probe_errors"] += 1
            _LOGGER.warning(
                "Config probe of %s (%s) failed: %s", router_id, reason, err.code
            )
            return False
        if self._provider is not provider:
            return False  # unregistered meanwhile: results are void
        stored: dict[str, CapabilityStatus] = {}
        dropped = 0
        for name, status in dict(result or {}).items():
            if str(name) in CONFIG_CAPABILITIES and isinstance(
                status, CapabilityStatus
            ):
                stored[str(name)] = status
            else:
                dropped += 1
        if dropped:
            self.stats["probe_entries_dropped"] += dropped
            _LOGGER.warning(
                "Config probe of %s returned %d entries outside config.*; dropped",
                router_id,
                dropped,
            )
        self._probes[router_id] = stored
        self.registry.invalidate_capabilities()
        _LOGGER.debug(
            "Config probe of %s (%s): %d capabilities", router_id, reason, len(stored)
        )
        return True

    # -- shared helpers --------------------------------------------------------------

    def _context(
        self, version_ids: Iterable[str] = (), correlation_id: str | None = None
    ) -> ProviderContext:
        allowed = frozenset(version_ids)
        store = self.versions

        async def read(version_id: str, kind: str) -> bytes:
            if version_id not in allowed:
                raise AuthorizationError(
                    "The provider may only read the versions of this call",
                    details={"reason": "read_out_of_scope"},
                )
            return await store.async_read_artifact(version_id, kind)

        security = self.security
        return ProviderContext(
            registry=RegistryReadView(self.registry),
            read=read,
            installation_key=store.async_get_installation_key,
            installation_key_state=store.key_state,
            correlation_id=correlation_id,
            ssh=None if security is None else security.async_ssh_run,
        )

    def _connection(self, router_id: str) -> RouterConnection:
        record = self.registry.get(router_id)
        attached = self.registry.attached(router_id)
        if attached is None:
            raise RouterUnavailableError(
                "The router's entry is not loaded",
                router_id=router_id,
                details={"reason": CapabilityReason.ENTRY_NOT_LOADED.value},
            )
        if record.reachability.state is ReachabilityState.OFFLINE:
            raise RouterUnavailableError(
                "The router is offline",
                router_id=router_id,
                details={"reason": CapabilityReason.ROUTER_OFFLINE.value},
            )
        coordinator = attached.coordinator
        return RouterConnection(
            router_id=router_id,
            entry_id=attached.entry_id,
            api=getattr(coordinator, "api", None),
            coordinator=coordinator,
            transport=record.connection.transport,
        )

    async def _call(
        self,
        router_id: str | None,
        operation: str,
        call: Awaitable[Any],
        timeout: float,
    ) -> Any:
        """Await a provider call: ConfigApiError passes, timeouts become
        OperationTimeoutError, anything else ProviderError."""
        try:
            async with asyncio.timeout(timeout):
                return await call
        except ConfigApiError:
            raise
        except TimeoutError as err:
            self.stats["provider_timeouts"] += 1
            raise OperationTimeoutError(
                f"Provider {operation} took longer than {timeout:g} s",
                router_id=router_id,
                details={"operation": operation, "timeout_s": timeout},
            ) from err
        except asyncio.CancelledError:
            raise
        except Exception as err:
            self.stats["provider_errors"] += 1
            raise ProviderError(
                f"Provider {operation} failed",
                router_id=router_id,
                cause=err,
                details={"operation": operation},
            ) from err

    @contextlib.asynccontextmanager
    async def _locked(self, router_id: str) -> AsyncIterator[None]:
        lock = self._locks.setdefault(router_id, asyncio.Lock())
        if lock.locked():
            self.stats["lock_waits"] += 1
        try:
            async with asyncio.timeout(self.lock_timeout.total_seconds()):
                await lock.acquire()
        except TimeoutError as err:
            self.stats["lock_timeouts"] += 1
            raise OperationInProgressError(
                "Another operation holds this router's lock",
                router_id=router_id,
                details={"timeout_s": self.lock_timeout.total_seconds()},
            ) from err
        try:
            yield
        finally:
            lock.release()

    def locked(self, router_id: str) -> bool:
        """True while a mutating operation holds the router lock."""
        lock = self._locks.get(router_id)
        return lock is not None and lock.locked()

    async def _verify(self, actor: Actor) -> VerifiedActor:
        return await self.guard.async_verify_actor(actor)

    def _grant(
        self,
        action: str,
        router_id: str,
        verified: VerifiedActor,
        *,
        checksum: str | None = None,
        approval_id: str | None = None,
        correlation_id: str | None = None,
    ) -> WriteAuthorization:
        return raise_for_decision(
            self.guard.authorize(
                action,
                router_id,
                verified,
                checksum=checksum,
                approval_id=approval_id,
                correlation_id=correlation_id,
            )
        )

    def _request(
        self,
        action: str,
        router_id: str,
        verified: VerifiedActor,
        *,
        subject_id: str,
        checksum: str,
        correlation_id: str | None = None,
    ) -> ApprovalRequest:
        decision = self.guard.authorize(
            action,
            router_id,
            verified,
            subject_id=subject_id,
            checksum=checksum,
            correlation_id=correlation_id,
        )
        if decision.state is DecisionState.PENDING and decision.approval_request:
            return decision.approval_request
        raise error_for_decision(decision)

    def _require_content_reader(
        self, action: str, router_id: str, verified: VerifiedActor
    ) -> None:
        """Reads of configuration content: a user must be a verified admin.

        Live configuration and diffs carry secrets. Module, system and
        automation actors pass (contract §6.2: only users need admin
        rights; a ``backup`` by them reads the same content). A refusal is
        audited on the security ring and raised before any provider call.
        """
        if verified.actor.kind is not ActorKind.USER or verified.is_admin:
            return
        audit_id = self.guard.audit_denial(router_id, action, verified, "not_admin")
        raise AuthorizationError(
            f"Reading configuration content ({action}) needs an admin user",
            router_id=router_id,
            details={"reason": "not_admin", "audit_id": audit_id, "action": action},
        )

    def _known_router_id(self, router_id: object) -> str:
        """``router_id`` if the registry knows it, else the fleet (audit only)."""
        if isinstance(router_id, str) and self.registry.find(router_id) is not None:
            return router_id
        return FLEET_ROUTER_ID

    def _version_router_id(self, backup_id: object) -> str:
        """Router of a known version, else the fleet (never raises)."""
        try:
            return self.versions.get(str(backup_id)).router_id
        except ConfigApiError:
            return FLEET_ROUTER_ID

    def _ref_router_id(self, ref: ConfigRef) -> str:
        """Router of a reference for an audit entry (never raises)."""
        if ref.is_live:
            return str(ref.router_id)
        try:
            return self.versions.get(str(ref.backup_id)).router_id
        except ConfigApiError:
            return FLEET_ROUTER_ID

    def _precheck(self, action: str, router_id: str, verified: VerifiedActor) -> None:
        """Deny early (audited) before doing work for an action."""
        if self.guard.denial_reason(action, verified) is not None:
            raise error_for_decision(self.guard.authorize(action, router_id, verified))

    def _emit(self, event_type: CoreEventType, **kwargs: Any) -> EmitResult | None:
        try:
            return self.audit.emit(event_type, source=CORE_SOURCE, **kwargs)
        except Exception:
            _LOGGER.warning(
                "Core event %s could not be recorded", event_type, exc_info=True
            )
            return None

    def _open_request(
        self,
        approval_id: str,
        action: str,
        verified: VerifiedActor,
        store: Mapping[str, Any],
    ) -> tuple[ApprovalRequest, Any]:
        """Approval plus the core's data of the request (audited if unknown).

        Both live in memory only: after a restart, a reject or an unload the
        id is unknown and the refusal is audited to the security ring.
        """
        approval = None
        try:
            approval = self.guard.get_approval(approval_id)
            data = store.get(approval_id)
            if data is None:
                raise ApprovalInvalidError(
                    "Unknown approval",
                    details={"reason": "unknown_approval", "approval_id": approval_id},
                )
        except ApprovalInvalidError as err:
            self.guard.audit_denial(
                FLEET_ROUTER_ID if approval is None else approval.router_id,
                action,
                verified,
                str(err.details.get("reason", "unknown_approval")),
            )
            raise
        return approval, data

    # -- installation key --------------------------------------------------------------

    async def async_get_module_key(self, module: str, purpose: str = "") -> bytes:
        """HKDF key of a registered module (contract §11.5); never logged.

        ``module`` must own an event prefix registered in this core run;
        ``core`` is never a module. A lost installation key raises
        InstallationKeyLostError (nothing is substituted); while it is
        ``uninitialised`` the first use creates it, exactly as for the
        provider (logged, ``keys_created``).
        """

        def refuse(reason: str, message: str) -> ConfigApiError:
            self.stats["module_keys_refused"] += 1
            _LOGGER.debug("Module key refused (%s)", reason)
            return ConfigApiError(
                message, error_class=ErrorClass.INVALID, details={"reason": reason}
            )

        try:
            check_module_name(module)
        except ValueError:
            raise refuse("invalid_module", "Not a module name") from None
        if module == CORE_KEY_OWNER:
            raise refuse("reserved_module", "The core is not a module")
        if module not in self.audit.registered_modules():
            raise refuse(
                "module_not_registered",
                "Only a module that registered its event prefix gets a key",
            )
        try:
            derive_module_key(b"\x00" * 16, module, purpose)  # validates purpose
        except ValueError:
            raise refuse("invalid_purpose", "Not a valid key purpose") from None
        try:
            installation_key = await self.versions.async_get_installation_key()
        except ConfigApiError:
            self.stats["module_keys_refused"] += 1
            raise
        self.stats["module_keys_issued"] += 1
        return derive_module_key(installation_key, module, purpose)

    async def async_request_installation_key_reset(
        self, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask for a new key; only while the key is LOST."""
        verified = await self._verify(actor)
        if self.versions.key_state is not InstallationKeyState.LOST:
            self.guard.audit_denial(
                FLEET_ROUTER_ID,
                GuardedAction.INSTALLATION_KEY_RESET,
                verified,
                "key_not_lost",
            )
            raise ConfigApiError(
                "The installation key is not lost; nothing to reset",
                error_class=ErrorClass.CONFLICT,
                details={
                    "reason": "key_not_lost",
                    "state": self.versions.key_state.value,
                },
            )
        return self._request(
            GuardedAction.INSTALLATION_KEY_RESET,
            FLEET_ROUTER_ID,
            verified,
            subject_id="installation_key",
            checksum=binding_checksum(self.versions.newest_key_id()),
        )

    async def async_reset_installation_key(
        self, approval_id: str, *, actor: Actor
    ) -> None:
        """Create the new key (requester only, after approval)."""
        verified = await self._verify(actor)
        checksum = binding_checksum(self.versions.newest_key_id())
        authorization = self._grant(
            GuardedAction.INSTALLATION_KEY_RESET,
            FLEET_ROUTER_ID,
            verified,
            approval_id=approval_id,
            checksum=checksum,
        )
        await self.versions.async_reset_installation_key(
            authorization=authorization, checksum=checksum
        )

    # -- reads -----------------------------------------------------------------------

    async def async_get_baseline(
        self, router_id: str, *, baseline_backup_id: str | None = None
    ) -> Baseline | None:
        """Current drift baseline and its rule."""
        self.registry.get(router_id)
        try:
            return select_baseline(
                router_id,
                self.versions.records(router_id),
                self.versions.acks(router_id),
                explicit_backup_id=baseline_backup_id,
            )
        except ValueError as err:
            raise BackupNotFoundError(
                "The baseline is not a usable version of this router",
                router_id=router_id,
                details={"version_id": str(baseline_backup_id)[:40]},
            ) from err

    async def async_capture(
        self, router_id: str, *, actor: Actor, configs: tuple[str, ...] | None = None
    ) -> ConfigSnapshot:
        """Live configuration (READ; a user must be a verified admin)."""
        verified = await self._verify(actor)
        self._require_content_reader(READ_CAPTURE, router_id, verified)
        provider = self._require(router_id, Capability.CONFIG_CAPTURE)
        with self._settling(router_id, Capability.CONFIG_CAPTURE, "capture"):
            return await self._capture(provider, router_id, verified, configs)

    async def _capture(
        self,
        provider: ConfigBackupProvider,
        router_id: str,
        verified: VerifiedActor,
        configs: tuple[str, ...] | None = None,
        correlation_id: str | None = None,
    ) -> ConfigSnapshot:
        conn = self._connection(router_id)
        snapshot = await self._call(
            router_id,
            "capture",
            provider.async_capture(
                conn,
                CaptureRequest(
                    router_id=router_id,
                    actor=verified.actor,
                    correlation_id=correlation_id,
                    configs=configs,
                ),
                self._context(correlation_id=correlation_id),
            ),
            self.call_timeout,
        )
        if not isinstance(snapshot, ConfigSnapshot) or snapshot.router_id != router_id:
            raise ProviderError(
                "Provider returned no snapshot of this router",
                router_id=router_id,
                error_class=ErrorClass.INVALID,
                details={"operation": "capture"},
            )
        return snapshot

    async def async_list_backups(
        self,
        router_id: str | None = None,
        *,
        since: datetime | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> tuple[BackupRecord, ...]:
        """Versions, newest first."""
        if router_id is not None:
            self.registry.get(router_id)
        return await self.versions.async_list_versions(
            router_id, since=since, limit=limit
        )

    async def async_get_backup(self, backup_id: str) -> BackupRecord:
        """One version."""
        return self.versions.get(backup_id)

    async def async_validate_backup(
        self, backup_id: str, *, actor: Actor | None = None
    ) -> BackupRecord:
        """Core sha256 check of every artifact, then the provider's check.

        With ``actor`` a user must be a verified admin (checked before any
        lookup, audited on the security ring). Without one the call is a
        legacy call: allowed as before 1.45, counted
        (``validate_without_actor``).
        """
        if actor is None:
            self.stats["validate_without_actor"] += 1
            _LOGGER.debug("async_validate_backup called without an actor")
        else:
            verified = await self._verify(actor)
            self._require_content_reader(
                READ_VALIDATE, self._version_router_id(backup_id), verified
            )
        provider = self._require_provider(Capability.CONFIG_VALIDATE)
        record = self.versions.get(backup_id)
        self._require_enabled(record.router_id, Capability.CONFIG_VALIDATE)
        for kind in sorted(record.artifacts):
            try:
                await self.versions.async_read_artifact(backup_id, kind)
            except ConfigApiError:
                return self.versions.get(backup_id)  # marked + event by the store
        validation = await self._call(
            record.router_id,
            "validate",
            provider.async_validate(record, self._context((backup_id,))),
            self.call_timeout,
        )
        if not isinstance(validation, ValidationInfo):
            raise ProviderError(
                "Provider returned no ValidationInfo",
                router_id=record.router_id,
                error_class=ErrorClass.INVALID,
                details={"operation": "validate"},
            )
        updated = await self.versions.async_set_validation(backup_id, validation)
        self._emit(
            CoreEventType.BACKUP_VALIDATED,
            router_id=record.router_id,
            result=EventResult.SUCCESS
            if validation.status.value == "valid"
            else EventResult.FAILURE,
            data={"version_id": backup_id, "status": validation.status.value},
        )
        return updated

    async def async_compare(
        self, base: ConfigRef, other: ConfigRef, *, actor: Actor
    ) -> ConfigDiff:
        """Compare two references (stored and/or live; a user must be admin).

        The admin check comes before any lookup, so a refused user learns
        nothing about version ids; the audit entry names the live router of
        ``base`` (live router or the router of a known version), else the
        fleet (``-``); the error is the same either way.
        """
        verified = await self._verify(actor)
        if verified.actor.kind is ActorKind.USER and not verified.is_admin:
            self._require_content_reader(
                READ_COMPARE, self._ref_router_id(base), verified
            )
        provider = self._require_provider(Capability.CONFIG_DIFF)
        sources: list[Any] = []
        routers: list[RouterRecord] = []
        version_ids: list[str] = []
        for ref in (base, other):
            if ref.is_live:
                rid = str(ref.router_id)
                self._require(rid, Capability.CONFIG_DIFF)
                self._require(rid, Capability.CONFIG_CAPTURE)
                sources.append(await self._capture(provider, rid, verified))
                routers.append(self.registry.get(rid))
            else:
                record = self.versions.get(str(ref.backup_id))
                self._require_enabled(record.router_id, Capability.CONFIG_DIFF)
                sources.append(record)
                routers.append(self.registry.get(record.router_id))
                version_ids.append(record.backup_id)
        diff = await self._call(
            routers[0].router_id,
            "compare",
            provider.async_compare(
                sources[0],
                sources[1],
                self._context(version_ids),
                base_router=routers[0],
                other_router=routers[1],
            ),
            self.call_timeout,
        )
        if not isinstance(diff, ConfigDiff):
            raise ProviderError(
                "Provider returned no ConfigDiff",
                router_id=routers[0].router_id,
                error_class=ErrorClass.INVALID,
                details={"operation": "compare"},
            )
        return diff

    async def async_detect_drift(
        self, router_id: str, *, actor: Actor, baseline_backup_id: str | None = None
    ) -> DriftReport:
        """Live configuration against the baseline; the core emits events.

        After an installation key change the live state becomes the new
        baseline ONLY if the provider's report is an all-clear (nothing
        comparable changed, comparison complete). A key change together
        with real changes, or with an incomplete comparison, is reported
        as drift with its events and the old baseline stays.
        """
        verified = await self._verify(actor)
        self._require_content_reader(
            READ_DRIFT, self._known_router_id(router_id), verified
        )
        provider = self._require(router_id, Capability.CONFIG_DRIFT)
        self.stats["drift_checks"] += 1
        baseline = await self.async_get_baseline(
            router_id, baseline_backup_id=baseline_backup_id
        )
        if baseline is None:
            raise BackupNotFoundError(
                "The router has no usable version to compare with",
                router_id=router_id,
                details={"reason": "no_baseline"},
            )
        record = self.versions.get(baseline.version_id)
        with self._settling(router_id, Capability.CONFIG_DRIFT, "detect_drift"):
            conn = self._connection(router_id)
            report = await self._call(
                router_id,
                "detect_drift",
                provider.async_detect_drift(
                    conn,
                    record,
                    self.versions.acks(router_id),
                    self._context((record.backup_id,)),
                    router=self.registry.get(router_id),
                ),
                self.call_timeout,
            )
        if (
            not isinstance(report, DriftReport)
            or report.router_id != router_id
            or report.baseline_backup_id != record.backup_id
        ):
            raise ProviderError(
                "Provider returned no drift report for this baseline",
                router_id=router_id,
                error_class=ErrorClass.INVALID,
                details={"operation": "detect_drift"},
            )
        if report.baseline_rule is None:
            report = replace(report, baseline_rule=baseline.rule)
        key_changed = baseline_backup_id is None and (
            self.versions.needs_rebaseline(router_id)
            or (
                record.installation_key_id is not None
                and self.versions.key_id is not None
                and record.installation_key_id != self.versions.key_id
            )
        )
        report = self._normalise_drift(report, key_changed=key_changed)
        if key_changed and report.all_clear:
            return await self._rebaseline(router_id, report)
        self._drift_events(report, verified, key_changed=key_changed)
        return report

    def _normalise_drift(
        self, report: DriftReport, *, key_changed: bool
    ) -> DriftReport:
        """Provider output is untrusted: never a silent baseline switch."""
        if report.rebaseline and not report.rebaseline_allowed:
            self.stats["rebaseline_refused"] += 1
            _LOGGER.warning(
                "Drift check of %s: the provider reported a key change together "
                "with real changes or an incomplete comparison; reported as drift, "
                "the baseline stays",
                report.router_id,
            )
            report = replace(report, rebaseline=False)
        elif report.rebaseline and not key_changed:
            self.stats["rebaseline_unconfirmed"] += 1
            _LOGGER.warning(
                "Drift check of %s: the provider reported a key change the core "
                "cannot confirm; no re-baseline",
                report.router_id,
            )
            report = replace(report, rebaseline=False)
        if not report.drifted and report.diff.comparable_changes:
            self.stats["drift_inconsistent"] += 1
            _LOGGER.warning(
                "Drift check of %s: %d comparable change(s) but drifted=False; "
                "reported as drift",
                report.router_id,
                len(report.diff.comparable_changes),
            )
            derived = (
                "core:"
                + binding_checksum(
                    report.baseline_backup_id,
                    [c._raw() for c in report.diff.comparable_changes],
                )[:32]
            )
            report = replace(report, drifted=True, drift_id=report.drift_id or derived)
        return report

    def _drift_events(
        self, report: DriftReport, verified: VerifiedActor, *, key_changed: bool
    ) -> None:
        """Events of one report; only an all-clear resets the dedup state."""
        if report.all_clear:
            for event_type in _DRIFT_EVENT_TYPES:
                self.audit.reset_dedup(report.router_id, event_type)
            return
        if report.comparison is not DriftComparison.COMPLETE:
            self.stats["drift_incomplete"] += 1
        data = {
            "drift_id": report.drift_id,
            "baseline_version_id": report.baseline_backup_id,
            "changes": len(report.diff.comparable_changes),
            "critical_count": report.critical_count,
            "unknown_count": report.unknown_count,
            "secrets_comparable": report.secrets_comparable,
            "ack_state": None if report.ack_state is None else report.ack_state.value,
            "comparison": report.comparison.value,
            "not_compared": list(report.not_compared[:_EVENT_ID_LIST_MAX]),
            "not_compared_count": len(report.not_compared),
            "installation_key_changed": key_changed,
        }
        incomplete_key = (
            "incomplete:"
            + binding_checksum(report.comparison.value, *sorted(report.not_compared))[
                :16
            ]
        )
        for event_type in drift_event_types(report):
            self._emit(
                event_type,
                router_id=report.router_id,
                severity=Severity.CRITICAL
                if event_type is CoreEventType.CHANGE_CRITICAL
                else Severity.WARNING,
                result=EventResult.INFO,
                actor=verified.actor,
                dedup_key=incomplete_key
                if event_type is CoreEventType.DRIFT_INCOMPLETE
                else report.drift_id,
                data=data,
            )

    async def _rebaseline(self, router_id: str, report: DriftReport) -> DriftReport:
        """Key changed, nothing else: the live state becomes the baseline."""
        system = await self._verify(Actor.system())
        result = await self._backup(
            router_id, reason=BackupReason.DRIFT, verified=system
        )
        version = result.record
        if not version.usable:
            raise BackupIncompleteError(
                "The re-baseline version is not usable; the next check retries",
                router_id=router_id,
                details={"version_id": version.backup_id, "reason": "not_usable"},
            )
        now = self.now()
        drift_id = f"{REBASELINE_DRIFT_PREFIX}{self.versions.key_id}"
        await self.versions.async_put_rebaseline_ack(
            DriftAck(
                router_id=router_id,
                drift_id=drift_id,
                state=DriftAckState.KNOWN,
                actor=system.actor,
                ts=now,
                version_id=version.backup_id,
            )
        )
        await self.versions.async_clear_rebaseline(router_id)
        self.stats["rebaselines"] += 1
        self._emit(
            CoreEventType.DRIFT_ACKNOWLEDGED,
            router_id=router_id,
            actor=system.actor,
            result=EventResult.SUCCESS,
            data={
                "drift_id": drift_id,
                "state": DriftAckState.KNOWN.value,
                "version_id": version.backup_id,
                "previous_baseline_version_id": report.baseline_backup_id,
                "not_comparable_changes": len(report.diff.changes),
                "rebaseline": True,
            },
        )
        return replace(
            report,
            drifted=False,
            drift_id=drift_id,
            ack_state=DriftAckState.KNOWN,
            baseline_rule=BaselineRule.KNOWN_ACK,
            rebaseline=True,
        )

    async def async_list_drift_acks(self, router_id: str) -> tuple[DriftAck, ...]:
        """Acknowledgements of a router."""
        self.registry.get(router_id)
        return await self.versions.async_list_drift_acks(router_id)

    # -- restore dry run -----------------------------------------------------------------

    async def async_check_restore_compatibility(
        self, backup_id: str, target_router_id: str, *, actor: Actor
    ) -> CompatibilityCheck:
        """Compatibility only (audited as restore_checked)."""
        plan = await self.async_prepare_restore(
            backup_id, target_router_id, actor=actor
        )
        return plan.compatibility

    async def async_prepare_restore(
        self, backup_id: str, target_router_id: str, *, actor: Actor
    ) -> RestorePlan:
        """Dry run; never writes. The plan is kept for a later request.

        A user must be a verified admin (before any lookup; audited).
        """
        verified = await self._verify(actor)
        self._require_content_reader(
            READ_RESTORE_DRY_RUN, self._known_router_id(target_router_id), verified
        )
        record = self.versions.get(backup_id)
        provider = self._require(target_router_id, Capability.CONFIG_RESTORE_DRY_RUN)
        target = self.registry.get(target_router_id)
        with self._settling(
            target_router_id, Capability.CONFIG_RESTORE_DRY_RUN, "prepare_restore"
        ):
            conn = self._connection(target_router_id)
            plan = await self._call(
                target_router_id,
                "prepare_restore",
                provider.async_prepare_restore(
                    conn, record, target, self._context((backup_id,))
                ),
                self.call_timeout,
            )
        if (
            not isinstance(plan, RestorePlan)
            or plan.backup_id != backup_id
            or plan.target_router_id != target_router_id
            or plan.source_router_id != record.router_id
        ):
            raise ProviderError(
                "Provider returned no plan for this version and router",
                router_id=target_router_id,
                error_class=ErrorClass.INVALID,
                details={"operation": "prepare_restore"},
            )
        self._prune_plans()
        while len(self._plans) >= MAX_RESTORE_PLANS:
            oldest = min(self._plan_made, key=self._plan_made.__getitem__)
            self._plans.pop(oldest, None)
            self._plan_made.pop(oldest, None)
            self.stats["plans_evicted"] += 1
        self._plans[plan.plan_id] = plan
        self._plan_made[plan.plan_id] = self.now()
        self._emit(
            CoreEventType.RESTORE_CHECKED,
            router_id=target_router_id,
            actor=verified.actor,
            result=EventResult.SUCCESS
            if plan.compatibility.compatible
            else EventResult.FAILURE,
            data={
                "version_id": backup_id,
                "plan_id": plan.plan_id,
                "compatible": plan.compatibility.compatible,
                "issues": len(plan.compatibility.issues),
                "steps": len(plan.steps),
            },
        )
        return plan

    # -- backups -----------------------------------------------------------------------

    async def async_create_backup(
        self,
        router_id: str,
        *,
        reason: BackupReason,
        actor: Actor,
        backup_type: BackupType | None = None,
        note: str | None = None,
        links: BackupLinks | None = None,
    ) -> PutVersionResult:
        """Collect and store a version (MUTATING)."""
        verified = await self._verify(actor)
        return await self._backup(
            router_id,
            reason=BackupReason(reason),
            verified=verified,
            backup_type=None if backup_type is None else BackupType(backup_type),
            note=note,
            links=links,
        )

    def _choose_backup_type(
        self, provider: ConfigBackupProvider, record: RouterRecord
    ) -> BackupType:
        """The provider's choice; else archive when a probe allows it."""
        chooser = getattr(provider, "default_backup_type", None)
        if callable(chooser):
            return BackupType(chooser(record))
        probes = self._probes.get(record.router_id, {})
        for name in (Capability.CONFIG_CGI_BACKUP, Capability.CONFIG_SSH_ROOT):
            status = probes.get(name)
            if status is not None and (status.available or _first_use(status)):
                return BackupType.FULL_ARCHIVE
        return BackupType.UCI_SNAPSHOT

    async def _backup(
        self,
        router_id: str,
        *,
        reason: BackupReason,
        verified: VerifiedActor,
        backup_type: BackupType | None = None,
        note: str | None = None,
        links: BackupLinks | None = None,
    ) -> PutVersionResult:
        record = self.registry.get(router_id)
        provider = self._require(router_id, Capability.CONFIG_BACKUP)
        correlation_id = new_id(CORRELATION_ID_PREFIX)
        chosen = backup_type or self._choose_backup_type(provider, record)
        # 1. fleet slot, then 2. router lock (entered in this order)
        async with self._fleet, self._locked(router_id):
            authorization = self._grant(  # 3. authorize (audited)
                GuardedAction.BACKUP,
                router_id,
                verified,
                correlation_id=correlation_id,
            )
            self.stats["backups_started"] += 1
            try:
                conn = self._connection(router_id)
                collected = await self._call(  # 4. collect
                    router_id,
                    "collect",
                    provider.async_collect(
                        conn,
                        CollectRequest(
                            router_id=router_id,
                            backup_type=chosen,
                            reason=reason,
                            actor=verified.actor,
                            correlation_id=correlation_id,
                            note=note,
                            links=links or BackupLinks(),
                        ),
                        self._context(correlation_id=correlation_id),
                    ),
                    self.collect_timeout,
                )
                collected = _check_collected(router_id, collected)
                meta = replace(
                    collected.meta,
                    reason=reason,
                    note=note,
                    links=links or collected.meta.links,
                    correlation_id=correlation_id,
                )
                result = await self._store(  # 5. dedup, consume, put
                    router_id, collected.artifacts, meta, authorization
                )
            except ConfigApiError as err:
                self._settle_backup_capabilities(router_id, chosen, None, err)
                self._backup_failed(router_id, err, verified, correlation_id, chosen)
                raise
        self._settle_backup_capabilities(router_id, chosen, result.record, None)
        return result  # 6./7. events emitted in _store, lock and slot released

    def _settle_backup_capabilities(
        self,
        router_id: str,
        backup_type: BackupType,
        record: BackupRecord | None,
        error: ConfigApiError | None,
    ) -> None:
        """A backup settles config.backup (and config.cgi_backup for archives)."""
        if isinstance(error, AuthorizationError):
            return
        if record is not None and record.status is VersionStatus.FAILED:
            error = ConfigApiError(
                "collection failed",
                router_id=router_id,
                error_class=record.error_class or ErrorClass.INTERNAL,
            )
        self._settle_first_use(
            router_id, Capability.CONFIG_BACKUP, error=error, operation="backup"
        )
        if backup_type is BackupType.FULL_ARCHIVE:
            archive_error = error
            if error is None and (
                record is None or ArtifactKind.ARCHIVE.value not in record.artifacts
            ):
                archive_error = ConfigApiError(
                    "no archive",
                    router_id=router_id,
                    error_class=(record.error_class if record else None)
                    or ErrorClass.NOT_AVAILABLE,
                )
            self._settle_first_use(
                router_id,
                Capability.CONFIG_CGI_BACKUP,
                error=archive_error,
                operation="backup",
            )

    async def async_put_version(
        self,
        router_id: str,
        artifacts: Mapping[str, ArtifactPayload],
        meta: VersionMeta,
        *,
        authorization: WriteAuthorization,
    ) -> PutVersionResult:
        """Store a version a module collected itself (``backup`` authorization)."""
        self.registry.get(router_id)
        async with self._locked(router_id):
            try:
                return await self._store(router_id, artifacts, meta, authorization)
            except AuthorizationError:
                raise
            except ConfigApiError as err:
                self._backup_failed(
                    router_id,
                    err,
                    None,
                    authorization.correlation_id,
                    meta.backup_type,
                )
                raise

    async def _store(
        self,
        router_id: str,
        artifacts: Mapping[str, ArtifactPayload],
        meta: VersionMeta,
        authorization: WriteAuthorization,
    ) -> PutVersionResult:
        """Put (retention + one retry on StorageFullError), then events.

        Called with the router lock held.
        """
        try:
            result = await self.versions.async_put_version(
                router_id, artifacts, meta, authorization=authorization
            )
        except StorageFullError:
            await self._retain(router_id)
            try:
                result = await self.versions.async_put_version(
                    router_id, artifacts, meta, authorization=authorization
                )
            except StorageFullError as err:
                self._limit_exceeded(router_id, err.details)
                raise
        record = result.record
        if not result.created:
            self.stats["backups_deduplicated"] += 1
            if record.status is not VersionStatus.FAILED:
                # an unchanged configuration is a successful collection too
                self._recovered(router_id, record)
            return result
        if record.status is VersionStatus.FAILED:
            raise_from = ConfigApiError(
                "The provider reported a failed collection",
                router_id=router_id,
                error_class=record.error_class or ErrorClass.INTERNAL,
                details={"version_id": record.backup_id},
            )
            self._backup_failed(
                router_id,
                raise_from,
                None,
                authorization.correlation_id,
                record.backup_type,
                version_id=record.backup_id,
            )
        else:
            self.stats["backups_created"] += 1
            self._emit(
                CoreEventType.BACKUP_CREATED,
                router_id=router_id,
                actor=record.created_by,
                correlation_id=authorization.correlation_id,
                result=EventResult.SUCCESS,
                severity=Severity.WARNING
                if record.status is VersionStatus.PARTIAL
                else Severity.INFO,
                data={
                    "version_id": record.backup_id,
                    "backup_type": record.backup_type.value,
                    "reason": record.reason.value,
                    "status": record.status.value,
                    "size_bytes": record.size_bytes,
                    "warnings": len(record.warnings),
                },
            )
            self._recovered(router_id, record)
        await self._retain(router_id)
        return result

    def _backup_failed(
        self,
        router_id: str,
        err: ConfigApiError,
        verified: VerifiedActor | None,
        correlation_id: str | None,
        backup_type: BackupType | None,
        *,
        version_id: str | None = None,
    ) -> None:
        """``configuration.backup_failed`` (dedup per router + error_class).

        Authorization denials are audited by the guard and are no failure.
        The dedup only suppresses the bus event; the audit entry counts.
        """
        if isinstance(err, AuthorizationError):
            return
        self.stats["backups_failed"] += 1
        error_class = err.error_class.value
        self._failing.setdefault(router_id, set()).add(error_class)
        emitted = self._emit(
            CoreEventType.BACKUP_FAILED,
            router_id=router_id,
            actor=None if verified is None else verified.actor,
            correlation_id=correlation_id,
            severity=Severity.WARNING,
            result=EventResult.FAILURE,
            dedup_key=error_class,
            data={
                "error_class": error_class,
                "code": err.code,
                "backup_type": None if backup_type is None else backup_type.value,
                "version_id": version_id,
                "retryable": err.retryable,
            },
        )
        if emitted is not None and emitted.deduplicated:
            self.stats["backup_failed_events_suppressed"] += 1

    def _recovered(self, router_id: str, record: BackupRecord) -> None:
        """A successful backup: end every backup_failed window of the router.

        The dedup reset always covers ALL error classes (also windows
        restored from the audit store after a restart); "was failing" comes
        from memory and from the persisted audit entries, so a failure
        before a restart is still followed by ``backup_recovered``.
        """
        failing = self._failing.pop(router_id, set()) | self._failing_in_audit(
            router_id, record.backup_id
        )
        self.audit.reset_dedup(router_id, CoreEventType.BACKUP_FAILED)
        if not failing:
            return
        self._emit(
            CoreEventType.BACKUP_RECOVERED,
            router_id=router_id,
            result=EventResult.SUCCESS,
            data={"version_id": record.backup_id, "error_classes": sorted(failing)},
        )

    def _failing_in_audit(self, router_id: str, version_id: str) -> set[str]:
        """Error classes of backup_failed entries after the last success."""
        try:
            events = self.audit.events(
                router_id=router_id,
                types=(
                    CoreEventType.BACKUP_FAILED,
                    CoreEventType.BACKUP_RECOVERED,
                    CoreEventType.BACKUP_CREATED,
                ),
            )
        except Exception:
            _LOGGER.debug("Audit not readable for %s", router_id, exc_info=True)
            return set()
        classes: set[str] = set()
        for event in sorted(
            events, key=lambda e: e.last_repeat_at or e.ts, reverse=True
        ):
            if (
                event.type == CoreEventType.BACKUP_CREATED
                and event.data.get("version_id") == version_id
            ):
                continue  # the success being handled right now
            if event.type != CoreEventType.BACKUP_FAILED:
                break
            error_class = event.data.get("error_class")
            if isinstance(error_class, str):
                classes.add(error_class)
        return classes

    # -- protect / drift ack -------------------------------------------------------------

    async def async_set_protected(
        self, backup_id: str, protected: bool, *, actor: Actor
    ) -> BackupRecord:
        """Protect or unprotect (admin user)."""
        verified = await self._verify(actor)
        record = self.versions.get(backup_id)
        protected = bool(protected)
        async with self._locked(record.router_id):
            authorization = self._grant(
                GuardedAction.PROTECT,
                record.router_id,
                verified,
                checksum=binding_checksum(backup_id, protected),
            )
            updated = await self.versions.async_set_protected(
                backup_id, protected, authorization=authorization
            )
        self._emit(
            CoreEventType.BACKUP_PROTECTION_CHANGED,
            router_id=record.router_id,
            actor=verified.actor,
            result=EventResult.SUCCESS,
            data={"version_id": backup_id, "protected": protected},
        )
        return updated

    async def async_acknowledge_drift(
        self,
        router_id: str,
        drift_id: str,
        *,
        state: DriftAckState,
        actor: Actor,
        note: str | None = None,
    ) -> DriftAck:
        """Acknowledge a drift; KNOWN first takes a ``drift`` version."""
        verified = await self._verify(actor)
        state = DriftAckState(state)
        check_token("drift_id", drift_id)
        self.registry.get(router_id)
        self._precheck(GuardedAction.DRIFT_ACK, router_id, verified)
        version_id: str | None = None
        if state is DriftAckState.KNOWN:
            result = await self._backup(
                router_id, reason=BackupReason.DRIFT, verified=verified
            )
            if not result.record.usable:
                self.guard.audit_denial(
                    router_id,
                    GuardedAction.DRIFT_ACK,
                    verified,
                    "drift_version_not_usable",
                )
                raise BackupIncompleteError(
                    "The live state could not be stored as a usable version; "
                    "the drift was not marked known",
                    router_id=router_id,
                    details={
                        "version_id": result.record.backup_id,
                        "reason": "drift_version_not_usable",
                    },
                )
            version_id = result.record.backup_id
        async with self._locked(router_id):
            authorization = self._grant(
                GuardedAction.DRIFT_ACK,
                router_id,
                verified,
                checksum=binding_checksum(router_id, drift_id, state.value),
            )
            ack = await self.versions.async_put_drift_ack(
                DriftAck(
                    router_id=router_id,
                    drift_id=drift_id,
                    state=state,
                    actor=verified.actor,
                    ts=self.now(),
                    note=note,
                    version_id=version_id,
                ),
                authorization=authorization,
            )
            # The KNOWN version was made with the current key: no re-baseline
            # is needed any more after a key reset.
            if version_id is not None and self.versions.needs_rebaseline(router_id):
                await self.versions.async_clear_rebaseline(router_id)
        self._emit(
            CoreEventType.DRIFT_ACKNOWLEDGED,
            router_id=router_id,
            actor=verified.actor,
            result=EventResult.SUCCESS,
            data={"drift_id": drift_id, "state": state.value, "version_id": version_id},
        )
        return ack

    # -- retention -----------------------------------------------------------------------

    def set_retention_policy(self, policy: RetentionPolicy, *, module: str) -> None:
        """The policy the core's prune run applies (one module supplies it)."""
        if not isinstance(policy, RetentionPolicy):
            raise TypeError("policy must be a RetentionPolicy")
        if not isinstance(module, str) or not module or module == CORE_SOURCE:
            raise ValueError("module must be a module name")
        if self._retention_module not in (None, module):
            raise ProviderConflictError(
                "Another module already supplied the retention policy",
                details={"module": self._retention_module},
            )
        self._retention_policy = policy
        self._retention_module = module
        _LOGGER.info("Retention policy supplied by %s: %s", module, policy.to_dict())

    async def async_apply_retention(
        self, router_id: str | None = None
    ) -> tuple[RetentionResult, ...]:
        """Run retention now (as system); one result per router."""
        router_ids = (router_id,) if router_id else self.versions.router_ids()
        out: list[RetentionResult] = []
        for rid in router_ids:
            async with self._locked(rid):
                result = await self._retain(rid)
            if result is not None:
                out.append(result)
        return tuple(out)

    async def _retain(self, router_id: str) -> RetentionResult | None:
        """Plan and prune one router (router lock held by the caller)."""
        records = self.versions.records(router_id)
        if not records:
            return None
        self.stats["retention_runs"] += 1
        result = plan_retention(
            router_id,
            records,
            self._retention_policy,
            now=dt_util.now(),
            max_bytes=self.versions.router_limit,
        )
        if result.deleted:
            system = await self._verify(Actor.system())
            authorization = self._grant(
                GuardedAction.PRUNE,
                router_id,
                system,
                checksum=binding_checksum(*sorted(set(result.deleted))),
            )
            await self.versions.async_delete_versions(
                result.deleted, authorization=authorization
            )
            self.stats["retention_deleted"] += len(result.deleted)
        if result.deleted or result.over_limit:
            self._emit(
                CoreEventType.RETENTION_APPLIED,
                router_id=router_id,
                result=EventResult.SUCCESS,
                data={
                    "deleted": len(result.deleted),
                    "deleted_ids": _ids(result.deleted),
                    "kept": len(result.kept),
                    "total_bytes": result.total_bytes,
                    "max_bytes": result.max_bytes,
                    "over_limit": result.over_limit,
                    "policy_module": self._retention_module,
                },
            )
        if result.over_limit:
            self._limit_exceeded(
                router_id,
                {
                    "scope": "router",
                    "used_bytes": result.total_bytes,
                    "limit_bytes": result.max_bytes,
                    "reason": "retention_cannot_free",
                },
            )
        return result

    def _limit_exceeded(self, router_id: str, details: Mapping[str, Any]) -> None:
        self.stats["storage_limit_exceeded"] += 1
        self._emit(
            CoreEventType.STORAGE_LIMIT_EXCEEDED,
            router_id=router_id,
            severity=Severity.WARNING,
            result=EventResult.FAILURE,
            dedup_key=str(details.get("scope", "router")),
            data={
                k: details.get(k)
                for k in (
                    "scope",
                    "used_bytes",
                    "needed_bytes",
                    "limit_bytes",
                    "reason",
                )
                if k in details
            },
        )

    # -- export ------------------------------------------------------------------------

    async def async_request_export(
        self, backup_id: str, *, actor: Actor, artifact: str = ArtifactKind.ARCHIVE
    ) -> ApprovalRequest:
        """Ask to export one artifact (CRITICAL, admin user)."""
        verified = await self._verify(actor)
        record = self.versions.get(backup_id)
        kind = ArtifactKind(artifact).value
        if kind not in record.artifacts:
            raise BackupNotFoundError(
                "The version has no such artifact",
                router_id=record.router_id,
                details={"version_id": backup_id, "artifact": kind},
            )
        approval = self._request(
            GuardedAction.EXPORT,
            record.router_id,
            verified,
            subject_id=backup_id,
            checksum=binding_checksum(backup_id, kind),
        )
        self._exports[approval.approval_id] = (backup_id, kind)
        return approval

    async def async_export_backup(
        self, approval_id: str, *, actor: Actor
    ) -> ExportHandle:
        """Export after approval; requester only; the reader works once."""
        verified = await self._verify(actor)
        approval, (backup_id, kind) = self._open_request(
            approval_id, GuardedAction.EXPORT, verified, self._exports
        )
        checksum = binding_checksum(backup_id, kind)
        authorization = self._grant(
            GuardedAction.EXPORT,
            approval.router_id,
            verified,
            approval_id=approval_id,
            checksum=checksum,
        )
        self.guard.consume(
            authorization,
            action=GuardedAction.EXPORT,
            router_id=approval.router_id,
            checksum=checksum,
        )
        self._exports.pop(approval_id, None)
        record = self.versions.get(backup_id)
        ref = record.artifacts[kind]
        store = self.versions
        downloaded = False

        async def reader() -> bytes:
            nonlocal downloaded
            if downloaded:
                raise ApprovalInvalidError(
                    "This export was downloaded already",
                    router_id=record.router_id,
                    details={"reason": "used", "approval_id": approval_id},
                )
            downloaded = True
            return await store.async_read_artifact(backup_id, kind)

        self.stats["exports"] += 1
        self._emit(
            CoreEventType.BACKUP_EXPORTED,
            router_id=record.router_id,
            actor=verified.actor,
            correlation_id=authorization.correlation_id,
            result=EventResult.SUCCESS,
            data={
                "version_id": backup_id,
                "artifact": kind,
                "approval_id": approval_id,
                "approved_by_kind": None
                if approval.decided_by is None
                else approval.decided_by.kind.value,
                "size_bytes": ref.size_bytes,
                "contains_secrets": record.contains_secrets,
            },
        )
        extension = {"archive": "tar.gz", "uci": "json", "inventory": "json"}[kind]
        return ExportHandle(
            backup_id=backup_id,
            artifact=kind,
            filename=f"{record.router_id}-{backup_id}-{kind}.{extension}",
            content_type=ref.content_type,
            size_bytes=ref.size_bytes,
            sha256=ref.sha256,
            contains_secrets=record.contains_secrets,
            reader=reader,
            expires_at=authorization.expires_at,
        )

    # -- delete ------------------------------------------------------------------------

    async def async_request_deletion(
        self, backup_ids: Sequence[str], *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to delete versions of ONE router (none protected)."""
        verified = await self._verify(actor)
        ids = tuple(sorted(set(backup_ids)))
        if not ids:
            raise ValueError("backup_ids must not be empty")
        records = [self.versions.get(v) for v in ids]
        router_id = records[0].router_id
        foreign = sorted(r.backup_id for r in records if r.router_id != router_id)
        protected = sorted(r.backup_id for r in records if r.protected)
        if foreign or protected:
            self.guard.audit_denial(
                router_id,
                GuardedAction.DELETE,
                verified,
                "router_mismatch" if foreign else "version_protected",
            )
        validate_deletion(records, router_id=router_id)
        checksum = binding_checksum(*ids)
        approval = self._request(
            GuardedAction.DELETE,
            router_id,
            verified,
            subject_id=f"versions:{len(ids)}:{checksum[:16]}",
            checksum=checksum,
        )
        self._deletions[approval.approval_id] = ids
        return approval

    async def async_delete_backups(
        self, approval_id: str, *, actor: Actor
    ) -> tuple[str, ...]:
        """Delete after approval; requester only."""
        verified = await self._verify(actor)
        approval, ids = self._open_request(
            approval_id, GuardedAction.DELETE, verified, self._deletions
        )
        async with self._locked(approval.router_id):
            authorization = self._grant(
                GuardedAction.DELETE,
                approval.router_id,
                verified,
                approval_id=approval_id,
                checksum=binding_checksum(*ids),
            )
            self._deletions.pop(approval_id, None)
            deleted = await self.versions.async_delete_versions(
                ids, authorization=authorization
            )
        self.stats["deletions"] += len(deleted)
        self._emit(
            CoreEventType.BACKUP_DELETED,
            router_id=approval.router_id,
            actor=verified.actor,
            correlation_id=authorization.correlation_id,
            result=EventResult.SUCCESS,
            data={
                "deleted": len(deleted),
                "version_ids": _ids(deleted),
                "approval_id": approval_id,
            },
        )
        return deleted

    # -- restore -----------------------------------------------------------------------

    async def async_request_restore(
        self, plan: RestorePlan, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to restore a dry-run plan (needs ``config.restore``)."""
        verified = await self._verify(actor)
        if not isinstance(plan, RestorePlan):
            raise TypeError("plan must be a RestorePlan")
        self._require(plan.target_router_id, Capability.CONFIG_RESTORE)
        self._prune_plans()
        known = self._plans.get(plan.plan_id)
        if known is None or known.checksum != plan.checksum:
            self.guard.audit_denial(
                plan.target_router_id, GuardedAction.RESTORE, verified, "unknown_plan"
            )
            raise ApprovalInvalidError(
                "The plan was not made by async_prepare_restore here",
                router_id=plan.target_router_id,
                details={"reason": "unknown_plan", "plan_id": plan.plan_id},
            )
        if not plan.compatibility.compatible:
            raise RestoreIncompatibleError(
                "The plan is not compatible with the router",
                router_id=plan.target_router_id,
                details={"issues": len(plan.compatibility.issues)},
            )
        approval = self._request(
            GuardedAction.RESTORE,
            plan.target_router_id,
            verified,
            subject_id=plan.plan_id,
            checksum=plan.checksum,
        )
        self._restores[approval.approval_id] = plan
        return approval

    async def async_execute_restore(
        self, approval_id: str, *, actor: Actor
    ) -> RestoreResult:
        """Restore after approval; the provider consumes the authorization."""
        verified = await self._verify(actor)
        approval, plan = self._open_request(
            approval_id, GuardedAction.RESTORE, verified, self._restores
        )
        provider = self._require(plan.target_router_id, Capability.CONFIG_RESTORE)
        router_id = plan.target_router_id
        started = self.now()
        async with self._locked(router_id):
            authorization = self._grant(
                GuardedAction.RESTORE,
                router_id,
                verified,
                approval_id=approval_id,
                checksum=plan.checksum,
            )
            self._restores.pop(approval_id, None)
            self.stats["restores"] += 1
            try:
                with self._settling(
                    router_id, Capability.CONFIG_RESTORE, "execute_restore"
                ):
                    conn = self._connection(router_id)
                    result = await self._call(
                        router_id,
                        "execute_restore",
                        provider.async_execute_restore(
                            conn,
                            plan,
                            authorization,
                            self._context(
                                (plan.backup_id,), authorization.correlation_id
                            ),
                        ),
                        self.restore_timeout,
                    )
                if not self.guard.used(authorization):
                    raise ProviderError(
                        "The provider wrote without consuming the authorization",
                        router_id=router_id,
                        error_class=ErrorClass.INVALID,
                        details={"reason": "authorization_not_consumed"},
                    )
                if not isinstance(result, RestoreResult):
                    raise ProviderError(
                        "Provider returned no RestoreResult",
                        router_id=router_id,
                        error_class=ErrorClass.INVALID,
                        details={"operation": "execute_restore"},
                    )
            except ConfigApiError as err:
                self._emit(
                    CoreEventType.RESTORE_FAILED,
                    router_id=router_id,
                    actor=verified.actor,
                    correlation_id=authorization.correlation_id,
                    severity=Severity.CRITICAL,
                    result=EventResult.FAILURE,
                    data={
                        "plan_id": plan.plan_id,
                        "version_id": plan.backup_id,
                        "approval_id": approval.approval_id,
                        "error_class": err.error_class.value,
                        "code": err.code,
                        "duration_s": (self.now() - started).total_seconds(),
                    },
                )
                raise
        completed = result.status is RestoreStatus.COMPLETED
        self._emit(
            CoreEventType.RESTORE_COMPLETED
            if completed
            else CoreEventType.RESTORE_FAILED,
            router_id=router_id,
            actor=verified.actor,
            correlation_id=authorization.correlation_id,
            severity=Severity.INFO if completed else Severity.CRITICAL,
            result=EventResult.SUCCESS if completed else EventResult.FAILURE,
            data={
                "plan_id": plan.plan_id,
                "version_id": plan.backup_id,
                "approval_id": approval.approval_id,
                "status": result.status.value,
                "applied_steps": result.applied_steps,
                "failed_step": result.failed_step,
                "rolled_back": result.rolled_back,
                "reboot_required": result.reboot_required,
            },
        )
        return result

    # -- approvals ---------------------------------------------------------------------

    async def async_approve(self, approval_id: str, *, actor: Actor) -> ApprovalRequest:
        """Approve (verified admin user)."""
        return self.guard.approve(approval_id, actor=await self._verify(actor))

    async def async_reject(
        self, approval_id: str, *, actor: Actor, reason: str | None = None
    ) -> ApprovalRequest:
        """Reject (verified admin user); the core's request data is dropped."""
        decided = self.guard.reject(
            approval_id, actor=await self._verify(actor), reason=reason
        )
        for store in (self._exports, self._deletions, self._restores):
            store.pop(approval_id, None)
        for store in self._security_stores():
            store.pop(approval_id, None)
        return decided

    @callback
    def _approval_ended(self, approval_id: str, reason: str) -> None:
        """Guard hook: an approval expired or was rejected -> drop its data."""
        dropped = 0
        for store in (
            self._exports,
            self._deletions,
            self._restores,
            *self._security_stores(),
        ):
            if store.pop(approval_id, None) is not None:
                dropped += 1
        if dropped and reason == "unload":
            self.stats["requests_dropped_on_close"] += dropped
        elif dropped and reason != "rejected":
            self.stats["requests_dropped_on_expiry"] += dropped
            security = self.security
            if security is not None:
                security.stats["requests_dropped_on_expiry"] += dropped

    def _prune_plans(self) -> None:
        """Forget dry-run plans older than RESTORE_PLAN_TTL (counted)."""
        limit = self.now() - RESTORE_PLAN_TTL
        for plan_id, made in list(self._plan_made.items()):
            if made <= limit:
                self._plans.pop(plan_id, None)
                del self._plan_made[plan_id]
                self.stats["plans_expired"] += 1

    def _security_stores(self) -> tuple[dict[str, Any], ...]:
        security = self.security
        return () if security is None else tuple(security.request_stores)

    def _security(self) -> Any:
        """The security flows or ConfigApiError ``security_unavailable``."""
        if self.security is None or self.closed:
            raise ConfigApiError(
                "The core's security actions are not available",
                error_class=ErrorClass.NOT_AVAILABLE,
                details={"reason": "security_unavailable"},
            )
        return self.security

    # -- lifecycle ---------------------------------------------------------------------

    @callback
    def close(self) -> None:
        """Drop the provider, cancel probes, forget request data."""
        if self.closed:
            return
        self.closed = True
        self._drop_provider()
        self._remove_approval_listener()
        dropped = len(self._exports) + len(self._deletions) + len(self._restores)
        for store in self._security_stores():
            dropped += len(store)
            store.clear()
        self.stats["requests_dropped_on_close"] += dropped
        self._exports.clear()
        self._deletions.clear()
        self._restores.clear()
        self._plans.clear()
        self._plan_made.clear()

    def summary(self) -> dict[str, Any]:
        """Counters (no ids, no actors)."""
        return {
            "closed": self.closed,
            "provider_id": self.provider_id,
            "probed_routers": len(self._probes),
            "probes_running": sum(
                1 for t in self._probe_tasks.values() if not t.done()
            ),
            "routers_locked": sum(1 for lock in self._locks.values() if lock.locked()),
            "retention_policy": self._retention_policy.to_dict(),
            "retention_module": self._retention_module,
            "failing_routers": len(self._failing),
            "open_requests": {
                "export": len(self._exports),
                "delete": len(self._deletions),
                "restore": len(self._restores),
            },
            "security": None if self.security is None else self.security.summary(),
            **self.stats,
        }

    # -- adoption seam (registry) ------------------------------------------------------

    async def async_authorize_adopt(
        self, entry_id: str, orphan_router_id: str, actor: Actor
    ) -> WriteAuthorization:
        """Registry hook: verify the actor, authorize ``adopt`` (admin user)."""
        verified = await self._verify(actor)
        return self._grant(
            GuardedAction.ADOPT,
            orphan_router_id,
            verified,
            checksum=binding_checksum(entry_id, orphan_router_id),
        )

    def consume_adopt(
        self, authorization: WriteAuthorization, entry_id: str, orphan_router_id: str
    ) -> None:
        """Registry hook: the guard consumes the adopt authorization."""
        self.guard.consume(
            authorization,
            action=GuardedAction.ADOPT,
            router_id=orphan_router_id,
            checksum=binding_checksum(entry_id, orphan_router_id),
        )


# -- public api object ----------------------------------------------------------------


class ConfigurationApi:
    """What ``async_get_configuration_api`` returns (ConfigurationApiProtocol)."""

    __slots__ = ("_guard_view", "_m", "_registry_view", "_version", "_versions_view")

    def __init__(self, manager: ConfigurationManager, version: int) -> None:
        """Bind to the manager of the running core."""
        self._m = manager
        self._version = version
        self._registry_view = RegistryReadView(manager.registry)
        self._guard_view = GuardView(manager.guard)
        self._versions_view = VersionView(manager.versions)

    @property
    def api_version(self) -> int:
        """The version this object implements."""
        return self._version

    @property
    def registry(self) -> RegistryReadView:
        """Router registry (read side + adopt)."""
        return self._registry_view

    @property
    def guard(self) -> GuardView:
        """Action guard."""
        return self._guard_view

    @property
    def versions(self) -> VersionView:
        """Read-only version index."""
        return self._versions_view

    @property
    def provider_id(self) -> str | None:
        """Registered provider or None."""
        return self._m.provider_id

    @property
    def installation_key_state(self) -> InstallationKeyState:
        """ok, lost or uninitialised."""
        return self._m.versions.key_state

    def register_provider(self, provider: ConfigBackupProvider) -> Callable[[], None]:
        """Register the provider; returns an unregister callback."""
        return self._m.register_provider(provider)

    def request_probe(self, router_id: str, reason: str) -> bool:
        """Probe a router again (e.g. after an ACL redeploy)."""
        return self._m.request_probe(router_id, reason)

    def capability(self, router_id: str, capability: str) -> CapabilityStatus:
        """Live status of one config.* capability (no router call)."""
        return self._m.capability(router_id, capability)

    async def async_get_installation_key(self) -> bytes:
        """32-byte installation key; InstallationKeyLostError while LOST."""
        return await self._m.versions.async_get_installation_key()

    async def async_get_module_key(self, module: str, purpose: str = "") -> bytes:
        """32-byte HKDF key of ``module`` for ``purpose`` (contract §11.5)."""
        return await self._m.async_get_module_key(module, purpose)

    async def async_request_installation_key_reset(
        self, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask for a new key after a loss."""
        return await self._m.async_request_installation_key_reset(actor=actor)

    async def async_reset_installation_key(
        self, approval_id: str, *, actor: Actor
    ) -> None:
        """Create the new key after approval."""
        await self._m.async_reset_installation_key(approval_id, actor=actor)

    async def async_get_baseline(
        self, router_id: str, *, baseline_backup_id: str | None = None
    ) -> Baseline | None:
        """Current drift baseline."""
        return await self._m.async_get_baseline(
            router_id, baseline_backup_id=baseline_backup_id
        )

    async def async_capture(
        self, router_id: str, *, actor: Actor, configs: tuple[str, ...] | None = None
    ) -> ConfigSnapshot:
        """Live configuration."""
        return await self._m.async_capture(router_id, actor=actor, configs=configs)

    async def async_list_backups(
        self,
        router_id: str | None = None,
        *,
        since: datetime | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> tuple[BackupRecord, ...]:
        """List versions."""
        return await self._m.async_list_backups(router_id, since=since, limit=limit)

    async def async_get_backup(self, backup_id: str) -> BackupRecord:
        """One version."""
        return await self._m.async_get_backup(backup_id)

    async def async_validate_backup(
        self, backup_id: str, *, actor: Actor | None = None
    ) -> BackupRecord:
        """Validate and store the result (with ``actor``: users must be admin)."""
        return await self._m.async_validate_backup(backup_id, actor=actor)

    async def async_compare(
        self, base: ConfigRef, other: ConfigRef, *, actor: Actor
    ) -> ConfigDiff:
        """Compare two references."""
        return await self._m.async_compare(base, other, actor=actor)

    async def async_detect_drift(
        self, router_id: str, *, actor: Actor, baseline_backup_id: str | None = None
    ) -> DriftReport:
        """Live configuration against a baseline."""
        return await self._m.async_detect_drift(
            router_id, actor=actor, baseline_backup_id=baseline_backup_id
        )

    async def async_check_restore_compatibility(
        self, backup_id: str, target_router_id: str, *, actor: Actor
    ) -> CompatibilityCheck:
        """Compatibility only."""
        return await self._m.async_check_restore_compatibility(
            backup_id, target_router_id, actor=actor
        )

    async def async_prepare_restore(
        self, backup_id: str, target_router_id: str, *, actor: Actor
    ) -> RestorePlan:
        """Dry run."""
        return await self._m.async_prepare_restore(
            backup_id, target_router_id, actor=actor
        )

    async def async_create_backup(
        self,
        router_id: str,
        *,
        reason: BackupReason,
        actor: Actor,
        backup_type: BackupType | None = None,
        note: str | None = None,
        links: BackupLinks | None = None,
    ) -> PutVersionResult:
        """Collect and store a version."""
        return await self._m.async_create_backup(
            router_id,
            reason=reason,
            actor=actor,
            backup_type=backup_type,
            note=note,
            links=links,
        )

    async def async_put_version(
        self,
        router_id: str,
        artifacts: Mapping[str, ArtifactPayload],
        meta: VersionMeta,
        *,
        authorization: WriteAuthorization,
    ) -> PutVersionResult:
        """Store a version a module collected itself."""
        return await self._m.async_put_version(
            router_id, artifacts, meta, authorization=authorization
        )

    async def async_set_protected(
        self, backup_id: str, protected: bool, *, actor: Actor
    ) -> BackupRecord:
        """Protect against retention and delete."""
        return await self._m.async_set_protected(backup_id, protected, actor=actor)

    async def async_acknowledge_drift(
        self,
        router_id: str,
        drift_id: str,
        *,
        state: DriftAckState,
        actor: Actor,
        note: str | None = None,
    ) -> DriftAck:
        """Acknowledge a drift."""
        return await self._m.async_acknowledge_drift(
            router_id, drift_id, state=state, actor=actor, note=note
        )

    async def async_list_drift_acks(self, router_id: str) -> tuple[DriftAck, ...]:
        """Acknowledgements of a router."""
        return await self._m.async_list_drift_acks(router_id)

    def set_retention_policy(self, policy: RetentionPolicy, *, module: str) -> None:
        """Supply the retention policy."""
        self._m.set_retention_policy(policy, module=module)

    async def async_apply_retention(
        self, router_id: str | None = None
    ) -> tuple[RetentionResult, ...]:
        """Run retention now (as system)."""
        return await self._m.async_apply_retention(router_id)

    async def async_request_export(
        self, backup_id: str, *, actor: Actor, artifact: str = ArtifactKind.ARCHIVE
    ) -> ApprovalRequest:
        """Ask to export one artifact."""
        return await self._m.async_request_export(
            backup_id, actor=actor, artifact=artifact
        )

    async def async_export_backup(
        self, approval_id: str, *, actor: Actor
    ) -> ExportHandle:
        """Export after approval."""
        return await self._m.async_export_backup(approval_id, actor=actor)

    async def async_request_deletion(
        self, backup_ids: Sequence[str], *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to delete versions."""
        return await self._m.async_request_deletion(backup_ids, actor=actor)

    async def async_delete_backups(
        self, approval_id: str, *, actor: Actor
    ) -> tuple[str, ...]:
        """Delete after approval."""
        return await self._m.async_delete_backups(approval_id, actor=actor)

    async def async_request_restore(
        self, plan: RestorePlan, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to restore."""
        return await self._m.async_request_restore(plan, actor=actor)

    async def async_approve(self, approval_id: str, *, actor: Actor) -> ApprovalRequest:
        """Approve a pending request."""
        return await self._m.async_approve(approval_id, actor=actor)

    async def async_reject(
        self, approval_id: str, *, actor: Actor, reason: str | None = None
    ) -> ApprovalRequest:
        """Reject a pending request."""
        return await self._m.async_reject(approval_id, actor=actor, reason=reason)

    async def async_execute_restore(
        self, approval_id: str, *, actor: Actor
    ) -> RestoreResult:
        """Restore after approval."""
        return await self._m.async_execute_restore(approval_id, actor=actor)

    # -- 1.44.0: ACL offer, SSH pin, module capability detectors -----------------

    async def async_request_acl_deploy(
        self, router_id: str, tiers: Iterable[str], *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to deploy the tiered ACL (CRITICAL, admin user)."""
        return await self._m._security().async_request_acl_deploy(
            router_id, tiers, actor=actor
        )

    def acl_offer(self, approval_id: str) -> Any:
        """Diff and risks (``AclOffer``) behind an open acl_deploy request."""
        return self._m._security().acl_offer(approval_id)

    async def async_deploy_acl_offer(
        self, approval_id: str, *, actor: Actor
    ) -> dict[str, Any]:
        """Deploy after approval; result carries command and rollback_command."""
        return await self._m._security().async_deploy_acl_offer(
            approval_id, actor=actor
        )

    def ssh_pin_status(self, router_id: str) -> dict[str, Any]:
        """SSH host key pin state of a router (fingerprints only)."""
        return self._m._security().ssh_pin_status(router_id)

    async def async_request_ssh_pin_confirm(
        self, router_id: str, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to trust the pending first-seen host key."""
        return await self._m._security().async_request_ssh_pin_confirm(
            router_id, actor=actor
        )

    async def async_confirm_ssh_pin(
        self, approval_id: str, *, actor: Actor
    ) -> dict[str, Any]:
        """Pin the pending key after approval."""
        return await self._m._security().async_confirm_ssh_pin(approval_id, actor=actor)

    async def async_request_ssh_pin_reset(
        self, router_id: str, *, actor: Actor
    ) -> ApprovalRequest:
        """Ask to forget the router's pin."""
        return await self._m._security().async_request_ssh_pin_reset(
            router_id, actor=actor
        )

    async def async_reset_ssh_pin(
        self, approval_id: str, *, actor: Actor
    ) -> dict[str, Any]:
        """Forget the pin after approval."""
        return await self._m._security().async_reset_ssh_pin(approval_id, actor=actor)

    def register_capability_detector(
        self,
        module: str,
        detector: Callable[[RouterRecord, Any], Mapping[str, CapabilityStatus]],
        *,
        prefix: str,
        signature: Callable[[Any], Any] | None = None,
    ) -> Callable[[], None]:
        """Report module capabilities below ``prefix`` (sync, no I/O)."""
        return self._m.registry.register_capability_detector(
            module, detector, prefix=prefix, signature=signature
        )

    def get_approval(self, approval_id: str) -> ApprovalRequest:
        """Request by id."""
        return self._m.guard.get_approval(approval_id)

    def pending_approvals(
        self, router_id: str | None = None
    ) -> tuple[ApprovalRequest, ...]:
        """Open requests."""
        return self._m.guard.pending_approvals(router_id)

    def events(
        self,
        *,
        router_id: str | None = None,
        types: Iterable[str] | None = None,
        since: datetime | None = None,
        ring: AuditRing | None = None,
        limit: int = DEFAULT_LIST_LIMIT,
    ) -> tuple[CoreEvent, ...]:
        """Audit entries, newest first."""
        return self._m.audit.events(
            router_id=router_id, types=types, since=since, ring=ring, limit=limit
        )

    def subscribe(self, listener: CoreEventListener) -> Callable[[], None]:
        """Listen to published events."""
        return self._m.audit.subscribe(listener)

    def register_event_prefix(self, prefix: str, *, module: str) -> Callable[[], None]:
        """Allow a module's own event types below ``prefix``; returns a remover."""
        return self._m.audit.register_event_prefix(prefix, module=module)

    def register_audit_mandatory_types(
        self, event_types: Iterable[str], *, module: str
    ) -> Callable[[], None]:
        """Make the module's own types audit-mandatory; returns a remover."""
        return self._m.audit.register_audit_mandatory_types(event_types, module=module)

    def emit(
        self,
        event_type: str,
        *,
        source: str,
        router_id: str | None = None,
        entry_id: str | None = None,
        severity: Severity = Severity.INFO,
        result: EventResult = EventResult.INFO,
        actor: Actor | None = None,
        correlation_id: str | None = None,
        dedup_key: str | None = None,
        data: Mapping[str, Any] | None = None,
        security_relevant: bool = False,
    ) -> EmitResult:
        """Module event (never as the core, never a core type).

        ``security_relevant`` puts it on the security ring (default general).
        """
        if source == CORE_SOURCE:
            raise ValueError("modules cannot emit as the core")
        return self._m.audit.emit(
            event_type,
            source=source,
            router_id=router_id,
            entry_id=entry_id,
            severity=severity,
            result=result,
            actor=actor,
            correlation_id=correlation_id,
            dedup_key=dedup_key,
            data=data,
            security_relevant=security_relevant,
        )


async def async_get_configuration_api(
    hass: HomeAssistant, version: int = 1
) -> ConfigurationApi:
    """The Configuration API of the running enterprise core.

    ApiVersionError (``details["supported_versions"]``) for an unknown
    version; ConfigApiError ``core_not_running`` while no openwrt_router
    entry is loaded.
    """
    ensure_supported_api_version(version)
    from .enterprise_core import async_get_core

    core = async_get_core(hass)
    if core is None or core.closed:
        raise ConfigApiError(
            "The enterprise core is not running (no openwrt_router entry loaded)",
            retryable=True,
            error_class=ErrorClass.NOT_AVAILABLE,
            details={
                "reason": "core_not_running",
                "supported_versions": list(SUPPORTED_API_VERSIONS),
            },
        )
    await core.async_load()
    return core.manager.api(version)


__all__ = [
    "ConfigurationApi",
    "ConfigurationManager",
    "GuardView",
    "RegistryReadView",
    "VersionView",
    "async_get_configuration_api",
]
