"""TEST configuration provider and harness for the enterprise core, part 2.

Lives only under ``tests/``: the integration ships NO provider and no
backup engine. :class:`FakeConfigProvider` implements the
``ConfigBackupProvider`` protocol over an in-memory "live configuration"
per router; it never touches the router's api object, so every call it
gets is visible in ``provider.calls`` and the coordinators' api mocks stay
empty.

Knobs a test can turn:

* ``fail[op]`` - exception the next calls of ``op`` raise
* ``gates[op]`` - asyncio.Event a call of ``op`` waits for (hang / order)
* ``entered[op]`` - set when a call of ``op`` started
* ``declined`` - router ids ``supported()`` refuses
* ``collect_status`` - VersionStatus of collected versions
* ``consume_on_restore`` - False: writes without consuming (core refuses)
* ``probe_states[name]`` - (state, reason) a probe reports instead
* ``collect_hook`` / ``drift_hook`` - rewrite what collect / drift return
  (hostile or inconsistent provider output)
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest
from core_testkit import (
    MAC_A,
    MAC_B,
    MAC_C,
    FakeCoordinator,
    FakeDisks,
    FakeEntry,
    add_users,
    core_of,
    drain,
    make_hass,
    router_data,
    setup_router,
)

from custom_components.openwrt_router.config_api import (
    ConfigurationApi,
    async_get_configuration_api,
)
from custom_components.openwrt_router.core_errors import ErrorClass
from custom_components.openwrt_router.core_models import (
    OPTION_CONFIG_BACKUP_ENABLED,
    CONFIG_CAPABILITIES,
    PLAN_ID_PREFIX,
    ArtifactKind,
    ArtifactPayload,
    BackupRecord,
    BackupType,
    Capability,
    CapabilityState,
    CapabilityStatus,
    ChangeKind,
    CollectedVersion,
    CollectRequest,
    CompatibilityCheck,
    CompatibilityIssue,
    ConfigChange,
    ConfigDiff,
    ConfigRef,
    ConfigSnapshot,
    DriftAck,
    DriftReport,
    GuardedAction,
    ProviderContext,
    RestorePlan,
    RestoreResult,
    RestoreStatus,
    RestoreStep,
    RouterConnection,
    RouterRecord,
    ValidationInfo,
    ValidationStatus,
    VersionMeta,
    VersionStatus,
    WriteAuthorization,
    canonical_checksum,
    installation_key_id,
    new_id,
    utcnow,
)

PROVIDER_ID = "test_provider"


@pytest.fixture(name="tmp_path")
def short_tmp_path() -> Any:
    """A SHORT temporary folder (replaces pytest's ``tmp_path``).

    The version store nests ``openwrt_router/config_backups/rtr_<32>/
    bkp_<32>.<kind>.partial`` below it; under a long ``--basetemp`` that
    passes Windows' 260-character path limit. Import it into a test module
    as ``tmp_path``.
    """
    with tempfile.TemporaryDirectory(
        prefix="owrt", ignore_cleanup_errors=True
    ) as folder:
        yield pathlib.Path(folder)


CRITICAL_CONFIGS = frozenset({"firewall", "dropbear"})


def sha(data: bytes) -> str:
    """sha256 hex of ``data``."""
    import hashlib

    return hashlib.sha256(data).hexdigest()


def default_configs(name: str = "gw") -> dict[str, Any]:
    """A small UCI-like configuration."""
    return {
        "system": {"@system[0]": {"hostname": name, "timezone": "UTC"}},
        "network": {"lan": {"proto": "static", "ipaddr": "192.168.1.1"}},
        "firewall": {"@defaults[0]": {"input": "ACCEPT"}},
        "wireless": {"default_radio0": {"ssid": "Home", "key": "S3cr3t-pa55"}},
    }


def uci_bytes(configs: Mapping[str, Any]) -> bytes:
    """Canonical bytes of a configuration (the ``uci`` artifact)."""
    return json.dumps(configs, sort_keys=True, separators=(",", ":")).encode()


def payload(data: bytes, content_type: str = "application/json") -> ArtifactPayload:
    """ArtifactPayload with the right sha256."""
    return ArtifactPayload(data=data, sha256=sha(data), content_type=content_type)


def diff_changes(base: Mapping[str, Any], other: Mapping[str, Any]) -> list[Any]:
    """One MODIFIED/ADDED/REMOVED change per differing config."""
    changes = []
    for name in sorted(set(base) | set(other)):
        if base.get(name) == other.get(name):
            continue
        kind = (
            ChangeKind.ADDED
            if name not in base
            else ChangeKind.REMOVED
            if name not in other
            else ChangeKind.MODIFIED
        )
        changes.append(
            ConfigChange(
                kind=kind,
                config=name,
                section="*",
                risk="critical" if name in CRITICAL_CONFIGS else "low",
            )
        )
    return changes


class FakeConfigProvider:
    """In-memory ConfigBackupProvider (tests only)."""

    provider_api_version = 1

    def __init__(
        self,
        provider_id: str = PROVIDER_ID,
        *,
        restore: bool = False,
        archive: bool = True,
    ) -> None:
        self.provider_id = provider_id
        self.restore = restore
        self.archive = archive
        self.calls: list[tuple[str, str | None]] = []
        self.configs: dict[str, dict[str, Any]] = {}
        self.fail: dict[str, BaseException] = {}
        self.gates: dict[str, asyncio.Event] = {}
        self.entered: dict[str, asyncio.Event] = {}
        self.declined: set[str] = set()
        self.collect_status = VersionStatus.OK
        self.consume_on_restore = True
        self.incompatible = False
        self.guard: Any = None  # api.guard, set by the harness
        self.contexts: list[ProviderContext] = []
        self.probe_states: dict[str, tuple[CapabilityState, str]] = {}
        self.collect_hook: Callable[[CollectedVersion], Any] | None = None
        self.drift_hook: Callable[[DriftReport], Any] | None = None
        self.active = 0
        self.max_active = 0

    # -- helpers ---------------------------------------------------------------------

    def live(self, router_id: str) -> dict[str, Any]:
        """The router's live configuration (created on first use)."""
        return self.configs.setdefault(router_id, default_configs(router_id[-6:]))

    def ops(self, op: str | None = None) -> list[tuple[str, str | None]]:
        """Calls (of one operation)."""
        return [c for c in self.calls if op is None or c[0] == op]

    async def _enter(self, op: str, router_id: str | None) -> None:
        self.calls.append((op, router_id))
        self.entered.setdefault(op, asyncio.Event()).set()
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            gate = self.gates.get(op)
            if gate is not None:
                await gate.wait()
            error = self.fail.get(op)
            if error is not None:
                raise error
        finally:
            self.active -= 1

    async def _source_configs(self, source: Any, ctx: ProviderContext) -> Any:
        if isinstance(source, ConfigSnapshot):
            return source.configs
        assert isinstance(source, BackupRecord)
        return json.loads(await ctx.read(source.backup_id, ArtifactKind.UCI))

    # -- protocol --------------------------------------------------------------------

    def supported(self, router: RouterRecord) -> bool:
        return router.router_id not in self.declined

    async def async_probe(
        self, conn: RouterConnection, ctx: ProviderContext
    ) -> Mapping[str, CapabilityStatus]:
        await self._enter("probe", conn.router_id)
        now = utcnow()
        unavailable = {
            Capability.CONFIG_SSH_ROOT: "not_detected",
            Capability.CONFIG_RESTORE: None if self.restore else "phase_1",
            Capability.CONFIG_CGI_BACKUP: None if self.archive else "not_detected",
        }
        out: dict[str, CapabilityStatus] = {}
        for name in sorted(CONFIG_CAPABILITIES):
            reason = unavailable.get(name)
            state = (
                CapabilityState.AVAILABLE
                if reason is None
                else CapabilityState.UNAVAILABLE
            )
            state, reason = self.probe_states.get(name, (state, reason or "ok"))
            out[name] = CapabilityStatus(
                capability=name,
                state=state,
                reason=reason,
                source=f"provider:{self.provider_id}",
                detected_at=now,
            )
        return out

    async def async_capture(
        self, conn: RouterConnection, request: Any, ctx: ProviderContext
    ) -> ConfigSnapshot:
        await self._enter("capture", conn.router_id)
        configs = json.loads(uci_bytes(self.live(conn.router_id)))
        return ConfigSnapshot(
            router_id=conn.router_id,
            captured_at=utcnow(),
            configs=configs,
            uci_hash=sha(uci_bytes(configs)),
        )

    async def async_collect(
        self, conn: RouterConnection, request: CollectRequest, ctx: ProviderContext
    ) -> CollectedVersion:
        self.contexts.append(ctx)
        await self._enter("collect", conn.router_id)
        key_id = installation_key_id(await ctx.installation_key())
        uci = uci_bytes(self.live(conn.router_id))
        artifacts: dict[str, ArtifactPayload] = {
            ArtifactKind.UCI: payload(uci),
        }
        content_hash = None
        if request.backup_type is BackupType.FULL_ARCHIVE:
            archive = b"ARCHIVE\0" + uci
            artifacts[ArtifactKind.ARCHIVE] = payload(archive, "application/gzip")
            content_hash = sha(archive)
        status = self.collect_status
        meta = VersionMeta(
            backup_type=request.backup_type,
            reason=request.reason,
            status=status,
            error_class=None if status is VersionStatus.OK else ErrorClass.INCOMPLETE,
            fetch_method="test",
            content_hash=content_hash,
            uci_hash=sha(uci),
            openwrt_version="24.10.2",
            board_name="glinet,gl-mt3000",
            installation_key_id=key_id,
        )
        collected = CollectedVersion(artifacts=artifacts, meta=meta)
        if self.collect_hook is not None:
            return self.collect_hook(collected)
        return collected

    async def async_validate(
        self, record: BackupRecord, ctx: ProviderContext
    ) -> ValidationInfo:
        await self._enter("validate", record.router_id)
        for kind in record.artifacts:
            await ctx.read(record.backup_id, kind)
        return ValidationInfo(status=ValidationStatus.VALID, checked_at=utcnow())

    async def async_compare(
        self,
        base: Any,
        other: Any,
        ctx: ProviderContext,
        *,
        base_router: RouterRecord,
        other_router: RouterRecord,
    ) -> ConfigDiff:
        await self._enter("compare", base_router.router_id)

        def ref(source: Any) -> ConfigRef:
            if isinstance(source, ConfigSnapshot):
                return ConfigRef.live(source.router_id)
            return ConfigRef.backup(source.backup_id)

        return ConfigDiff(
            base=ref(base),
            other=ref(other),
            compared_at=utcnow(),
            changes=tuple(
                diff_changes(
                    await self._source_configs(base, ctx),
                    await self._source_configs(other, ctx),
                )
            ),
        )

    async def async_detect_drift(
        self,
        conn: RouterConnection,
        baseline: BackupRecord,
        acks: Sequence[DriftAck],
        ctx: ProviderContext,
        *,
        router: RouterRecord,
    ) -> DriftReport:
        await self._enter("detect_drift", conn.router_id)
        base = await self._source_configs(baseline, ctx)
        live = self.live(conn.router_id)
        changes = diff_changes(base, live)
        drift_id = (
            f"drift_{canonical_checksum([baseline.backup_id, live])[:16]}"
            if changes
            else None
        )
        ack_state = next((a.state for a in acks if a.drift_id == drift_id), None)
        now = utcnow()
        report = DriftReport(
            router_id=conn.router_id,
            baseline_backup_id=baseline.backup_id,
            checked_at=now,
            drifted=bool(changes),
            diff=ConfigDiff(
                base=ConfigRef.backup(baseline.backup_id),
                other=ConfigRef.live(conn.router_id),
                compared_at=now,
                changes=tuple(changes),
            ),
            drift_id=drift_id,
            ack_state=ack_state,
            critical_count=sum(1 for c in changes if c.risk == "critical"),
        )
        if self.drift_hook is not None:
            return self.drift_hook(report)
        return report

    async def async_prepare_restore(
        self,
        conn: RouterConnection,
        record: BackupRecord,
        target: RouterRecord,
        ctx: ProviderContext,
    ) -> RestorePlan:
        await self._enter("prepare_restore", target.router_id)
        configs = await self._source_configs(record, ctx)
        issues = (
            (CompatibilityIssue(code="board_mismatch", message="other board"),)
            if self.incompatible
            else ()
        )
        return RestorePlan(
            plan_id=new_id(PLAN_ID_PREFIX),
            backup_id=record.backup_id,
            source_router_id=record.router_id,
            target_router_id=target.router_id,
            provider_id=self.provider_id,
            created_at=utcnow(),
            compatibility=CompatibilityCheck(compatible=not issues, issues=issues),
            steps=tuple(
                RestoreStep(order=i, action="uci_import", target=name)
                for i, name in enumerate(sorted(configs), start=1)
            ),
            live_checksum=canonical_checksum(self.live(target.router_id)),
        )

    async def async_execute_restore(
        self,
        conn: RouterConnection,
        plan: RestorePlan,
        authorization: WriteAuthorization,
        ctx: ProviderContext,
    ) -> RestoreResult:
        started = utcnow()
        if self.consume_on_restore:
            self.guard.consume(
                authorization,
                action=GuardedAction.RESTORE,
                router_id=plan.target_router_id,
                checksum=plan.checksum,
            )
        await self._enter("execute_restore", plan.target_router_id)
        configs = json.loads(await ctx.read(plan.backup_id, ArtifactKind.UCI))
        self.configs[plan.target_router_id] = configs
        return RestoreResult(
            approval_id=str(authorization.approval_id),
            plan_id=plan.plan_id,
            router_id=plan.target_router_id,
            status=RestoreStatus.COMPLETED,
            started_at=started,
            finished_at=utcnow(),
            applied_steps=len(plan.steps),
            correlation_id=authorization.correlation_id,
        )


# -- harness --------------------------------------------------------------------------


@dataclass
class Env:
    """A running core with routers, the API and (optionally) the provider."""

    hass: Any
    disks: FakeDisks
    api: ConfigurationApi
    provider: FakeConfigProvider | None
    entries: list[FakeEntry]
    coords: dict[str, FakeCoordinator]
    rids: list[str]
    root: str
    unregister: Any = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def core(self) -> Any:
        return core_of(self.hass)

    @property
    def manager(self) -> Any:
        return self.core.manager

    @property
    def versions(self) -> Any:
        return self.core.versions

    @property
    def rid(self) -> str:
        return self.rids[0]

    def router_calls(self) -> list[Any]:
        """Calls the core made on any coordinator's api object."""
        return [c for coord in self.coords.values() for c in coord.router_calls()]


_MACS = (MAC_A, MAC_B, MAC_C)


async def start_env(
    disks: FakeDisks,
    tmp_path: Any,
    *,
    routers: int = 1,
    provider: FakeConfigProvider | None | bool = True,
    options: dict[str, Any] | None = None,
) -> Env:
    """Core + ``routers`` polled routers (+ provider registered and probed).

    ``options`` None = config backup switched ON (the option is default OFF
    since 1.44.0; this environment exists to exercise the config API).
    """
    if options is None:
        options = {OPTION_CONFIG_BACKUP_ENABLED: True}
    hass = make_hass()
    root = str(tmp_path)
    hass.config.path = lambda *parts: os.path.join(root, *parts)
    add_users(hass)
    entries: list[FakeEntry] = []
    coords: dict[str, FakeCoordinator] = {}
    rids: list[str] = []
    for i in range(routers):
        entry = FakeEntry(f"e{i + 1}", host=f"192.168.1.{i + 1}", options=options)
        coord = await setup_router(
            hass, entry, router_data(hostname=f"r{i + 1}", macs=_MACS[i])
        )
        coord.poll()
        entries.append(entry)
        rid = core_of(hass).registry.get_by_entry(entry.entry_id).router_id
        coords[rid] = coord
        rids.append(rid)
    await drain(hass)
    api = await async_get_configuration_api(hass, 1)
    prov: FakeConfigProvider | None
    if provider is True:
        prov = FakeConfigProvider()
    elif isinstance(provider, FakeConfigProvider):
        prov = provider
    else:
        prov = None
    unregister = None
    if prov is not None:
        prov.guard = api.guard
        unregister = api.register_provider(prov)
        await drain(hass)
    return Env(
        hass=hass,
        disks=disks,
        api=api,
        provider=prov,
        entries=entries,
        coords=coords,
        rids=rids,
        root=root,
        unregister=unregister,
    )


async def approve_as(env: Env, approval_id: str, user_id: str) -> Any:
    """Approve as ``user_id``."""
    from core_testkit import user_actor

    return await env.api.async_approve(approval_id, actor=user_actor(user_id))


async def stop_env(env: Env) -> None:
    """Unload every entry like HA does (the last one closes the core)."""
    from custom_components.openwrt_router.enterprise_core import (
        async_unload_entry_core,
    )

    for entry in env.entries:
        await async_unload_entry_core(env.hass, entry)
        await entry.run_on_unload()
    await drain(env.hass)


async def restart(
    env: Env, *, provider: FakeConfigProvider | None | bool = True
) -> Env:
    """Stop the core, then set the same entries up again on the same disks."""
    await stop_env(env)
    coords: dict[str, FakeCoordinator] = {}
    rids: list[str] = []
    for i, entry in enumerate(env.entries):
        coord = await setup_router(
            env.hass, entry, router_data(hostname=f"r{i + 1}", macs=_MACS[i])
        )
        coord.poll()
        rid = core_of(env.hass).registry.get_by_entry(entry.entry_id).router_id
        coords[rid] = coord
        rids.append(rid)
    await drain(env.hass)
    api = await async_get_configuration_api(env.hass, 1)
    prov: FakeConfigProvider | None
    if provider is True:
        prov = env.provider or FakeConfigProvider()
    elif isinstance(provider, FakeConfigProvider):
        prov = provider
    else:
        prov = None
    unregister = None
    if prov is not None:
        prov.guard = api.guard
        unregister = api.register_provider(prov)
        await drain(env.hass)
    return Env(
        hass=env.hass,
        disks=env.disks,
        api=api,
        provider=prov,
        entries=env.entries,
        coords=coords,
        rids=rids,
        root=env.root,
        unregister=unregister,
    )
