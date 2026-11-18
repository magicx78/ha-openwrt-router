"""Configuration API v1 (enterprise core part 2) through the public facade.

Uses the TEST provider from ``tests/core_test_provider.py``; the
integration itself ships no provider and no backup engine. Cases 06-09 and
11 of the part-2 brief, plus: no provider = zero router calls, the full
dry-run -> request -> approve -> execute restore path, export with one
approval per download, the installation key lost / reset path and
unload/reload with a registered provider.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch

import pytest
from core_test_provider import (
    FakeConfigProvider,
    approve_as,
    restart,
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import (
    ADMIN_ID,
    OTHER_ADMIN_ID,
    USER_ID,
    FakeDisks,
    bus_events,
    drain,
    make_hass,
    user_actor,
)

from custom_components.openwrt_router import core_store
from custom_components.openwrt_router import version_store as version_store_module
from custom_components.openwrt_router.config_api import (
    ConfigurationApi,
    async_get_configuration_api,
)
from custom_components.openwrt_router.core_errors import (
    ApiVersionError,
    ApprovalInvalidError,
    ApprovalRequiredError,
    AuthorizationError,
    CapabilityUnavailableError,
    ConfigApiError,
    ErrorClass,
    InstallationKeyLostError,
    ProviderError,
)
from custom_components.openwrt_router.core_models import (
    CONFIG_CAPABILITIES,
    CONFIG_CATALOG_STORE_KEY,
    INSTALLATION_KEY_STORE_KEY,
    ISSUE_INSTALLATION_KEY_LOST,
    Actor,
    ApprovalStatus,
    ArtifactKind,
    BackupReason,
    BackupType,
    Capability,
    CapabilityReason,
    CapabilityState,
    ConfigRef,
    CoreEventType,
    InstallationKeyState,
    RestoreStatus,
    RetentionPolicy,
    ValidationStatus,
    VersionStatus,
)

ADMIN = user_actor(ADMIN_ID)


def _read(path: str) -> bytes:
    """Read a stored artifact (tests only, outside the event loop rules)."""
    with open(path, "rb") as handle:
        return handle.read()


def _overwrite_first_byte(path: str) -> None:
    """Corrupt a stored artifact in place."""
    with open(path, "r+b") as handle:
        handle.write(b"X")


OTHER_ADMIN = user_actor(OTHER_ADMIN_ID)
PLAIN_USER = user_actor(USER_ID, claims_admin=True)  # the claim is ignored


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _backup(env, reason=BackupReason.MANUAL, actor=ADMIN, router_id=None):
    result = await env.api.async_create_backup(
        router_id or env.rid, reason=reason, actor=actor
    )
    return result


def _hostname(env, value):
    env.provider.live(env.rid)["system"]["@system[0]"]["hostname"] = value


def _keep_all(env):
    """Count rules instead of the default GFS (keeps same-day versions)."""
    env.api.set_retention_policy(RetentionPolicy(max_versions=100), module="test")


def _count(env, event_type: CoreEventType) -> int:
    return len(bus_events(env.hass, event_type.value))


def _file(env, record, kind) -> str:
    return os.path.join(
        env.versions._root,
        record.router_id,
        record.artifacts[kind].storage.locator,
    )


# -- case 06: backup via the API ------------------------------------------------------


async def test_case06_backup_via_api(disks, tmp_path):
    env = await start_env(disks, tmp_path)

    result = await _backup(env)

    record = result.record
    assert result.created
    assert record.status is VersionStatus.OK
    assert record.backup_type is BackupType.FULL_ARCHIVE
    assert set(record.artifacts) == {"uci", "archive"}
    assert record.created_by.user_id == ADMIN_ID
    assert record.created_by.is_admin  # verified by the core, not claimed
    assert record.installation_key_id == env.versions.key_id
    assert record.links.correlation_id is not None
    for kind, ref in record.artifacts.items():
        data = _read(_file(env, record, kind))
        assert hashlib.sha256(data).hexdigest() == ref.sha256
        assert len(data) == ref.size_bytes
    assert _count(env, CoreEventType.BACKUP_CREATED) == 1
    assert env.provider.ops("collect") == [("collect", env.rid)]
    assert env.router_calls() == []  # the core itself never calls the router
    listed = await env.api.async_list_backups(env.rid)
    assert [r.backup_id for r in listed] == [record.backup_id]


async def test_case06_scheduled_repeat_is_deduplicated(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    first = await _backup(env, BackupReason.SCHEDULED, Actor.system())
    second = await _backup(env, BackupReason.SCHEDULED, Actor.system())
    assert first.created and not second.created
    assert second.record.backup_id == first.record.backup_id
    assert second.record.last_seen_at is not None
    assert env.manager.stats["backups_deduplicated"] == 1
    assert _count(env, CoreEventType.BACKUP_CREATED) == 1
    manual = await _backup(env)  # manual versions always create
    assert manual.created


async def test_case06_backup_needs_a_verified_admin(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    with pytest.raises(AuthorizationError) as err:
        await _backup(env, actor=PLAIN_USER)
    assert err.value.details["reason"] == "not_admin"
    with pytest.raises(AuthorizationError) as err:
        await _backup(env, actor=user_actor("nobody"))
    assert err.value.details["reason"] == "unknown_user"
    assert env.provider.ops("collect") == []
    assert env.versions.records(env.rid) == ()


# -- case 07: history -----------------------------------------------------------------


async def test_case07_history_newest_first(disks, tmp_path):
    env = await start_env(disks, tmp_path, routers=2)
    _keep_all(env)
    ids = []
    for name in ("one", "two", "three"):
        _hostname(env, name)
        ids.append((await _backup(env)).record.backup_id)
    other = (await _backup(env, router_id=env.rids[1])).record

    history = await env.api.async_list_backups(env.rid)
    assert [r.backup_id for r in history] == ids[::-1]
    limited = await env.api.async_list_backups(env.rid, limit=2)
    assert [r.backup_id for r in limited] == ids[::-1][:2]
    fleet = await env.api.async_list_backups()
    assert {r.backup_id for r in fleet} == {*ids, other.backup_id}
    newest = history[0]
    since = await env.api.async_list_backups(
        env.rid, since=newest.created_at - timedelta(microseconds=1)
    )
    assert [r.backup_id for r in since] == [newest.backup_id]
    assert await env.api.async_get_backup(ids[0]) == history[-1]
    assert (await env.api.versions.async_get_version(ids[1])).backup_id == ids[1]

    diff = await env.api.async_compare(
        ConfigRef.backup(ids[0]), ConfigRef.backup(ids[2]), actor=ADMIN
    )
    assert [c.config for c in diff.changes] == ["system"]


async def test_case07_default_gfs_thins_same_day_versions_visibly(disks, tmp_path):
    # Scheduled versions: ruling (a) of 1.44.0 keeps manual/pre_* ones.
    env = await start_env(disks, tmp_path)
    for name in ("one", "two", "three"):
        _hostname(env, name)
        newest = (await _backup(env, reason=BackupReason.SCHEDULED)).record
    history = await env.api.async_list_backups(env.rid)
    assert [r.backup_id for r in history] == [newest.backup_id]
    applied = bus_events(env.hass, CoreEventType.RETENTION_APPLIED.value)
    assert sum(e["data"]["deleted"] for e in applied) == 2
    assert env.manager.stats["retention_deleted"] == 2


# -- case 08: integrity ---------------------------------------------------------------


async def test_case08_validate_ok_corrupt_and_missing(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    _keep_all(env)
    good = (await _backup(env)).record
    validated = await env.api.async_validate_backup(good.backup_id)
    assert validated.validation.status is ValidationStatus.VALID
    assert _count(env, CoreEventType.BACKUP_VALIDATED) == 1

    _hostname(env, "corrupt-me")
    corrupt = (await _backup(env)).record
    _overwrite_first_byte(_file(env, corrupt, "uci"))
    checked = await env.api.async_validate_backup(corrupt.backup_id)
    assert checked.validation.status is ValidationStatus.CORRUPT
    assert not checked.usable

    _hostname(env, "remove-me")
    missing = (await _backup(env)).record
    os.remove(_file(env, missing, "archive"))
    checked = await env.api.async_validate_backup(missing.backup_id)
    assert checked.validation.status in (
        ValidationStatus.MISSING,
        ValidationStatus.CORRUPT,
    )
    assert _count(env, CoreEventType.INTEGRITY_FAILED) == 2
    # a corrupt version is never the drift baseline
    baseline = await env.api.async_get_baseline(env.rid)
    assert baseline.version_id == good.backup_id


# -- case 09: API versioning ----------------------------------------------------------


async def test_case09_api_versioning(disks, tmp_path):
    env = await start_env(disks, tmp_path, provider=False)
    api = await async_get_configuration_api(env.hass, version=1)
    assert isinstance(api, ConfigurationApi)
    assert api.api_version == 1
    for bad in (0, 2, 99, "1", True):
        with pytest.raises(ApiVersionError) as err:
            await async_get_configuration_api(env.hass, version=bad)
        assert tuple(err.value.details["supported_versions"]) == (1,)
    with pytest.raises(AttributeError):
        api.foo = 1  # __slots__: no ad-hoc state on the facade

    with pytest.raises(ConfigApiError) as err:
        await async_get_configuration_api(make_hass(), version=1)
    assert err.value.error_class is ErrorClass.NOT_AVAILABLE
    assert err.value.details["reason"] == "core_not_running"


# -- no provider: everything unavailable, zero router calls ---------------------------


async def test_no_provider_means_no_router_work(disks, tmp_path):
    env = await start_env(disks, tmp_path, provider=False)
    for name in sorted(CONFIG_CAPABILITIES):
        status = env.api.capability(env.rid, name)
        assert status.state is CapabilityState.UNAVAILABLE
        assert status.reason == CapabilityReason.NO_PROVIDER
    assert env.api.provider_id is None
    assert env.api.request_probe(env.rid, "test") is False
    for call in (
        env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN),
        env.api.async_capture(env.rid, actor=ADMIN),
    ):
        with pytest.raises(CapabilityUnavailableError) as err:
            await call
        assert err.value.details["reason"] == CapabilityReason.NO_PROVIDER
    for _ in range(100):  # polls: no probe, no backup, no store write
        env.coords[env.rid].poll()
    await drain(env.hass)
    assert env.router_calls() == []
    assert env.versions.records() == ()
    assert disks[CONFIG_CATALOG_STORE_KEY].saves == []
    assert disks[INSTALLATION_KEY_STORE_KEY].saves == []  # no key without use
    assert env.manager.stats["probes"] == 0
    registry_caps = env.api.registry.capabilities(env.rid)
    assert all(
        registry_caps[name].reason == CapabilityReason.NO_PROVIDER
        for name in CONFIG_CAPABILITIES
    )


# -- case 11 + full restore path ------------------------------------------------------


async def _plan(env, provider_restore=True):
    first = (await _backup(env)).record
    _hostname(env, "changed")
    plan = await env.api.async_prepare_restore(first.backup_id, env.rid, actor=ADMIN)
    return first, plan


async def test_full_restore_path_dry_run_request_approve_execute(disks, tmp_path):
    env = await start_env(disks, tmp_path, provider=FakeConfigProvider(restore=True))
    _first, plan = await _plan(env)
    assert plan.compatibility.compatible
    assert env.provider.ops("execute_restore") == []  # the dry run never writes
    assert _count(env, CoreEventType.RESTORE_CHECKED) == 1

    approval = await env.api.async_request_restore(plan, actor=ADMIN)
    assert approval.status is ApprovalStatus.PENDING
    assert _count(env, CoreEventType.RESTORE_REQUESTED) == 1
    approved = await approve_as(env, approval.approval_id, OTHER_ADMIN_ID)
    assert approved.status is ApprovalStatus.APPROVED

    result = await env.api.async_execute_restore(approval.approval_id, actor=ADMIN)

    assert result.status is RestoreStatus.COMPLETED
    assert result.applied_steps == len(plan.steps)
    live = env.provider.live(env.rid)
    assert live["system"]["@system[0]"]["hostname"] == env.rid[-6:]
    assert _count(env, CoreEventType.RESTORE_COMPLETED) == 1
    # single use
    with pytest.raises(ApprovalInvalidError):
        await env.api.async_execute_restore(approval.approval_id, actor=ADMIN)
    assert len(env.provider.ops("execute_restore")) == 1
    assert env.router_calls() == []


async def test_case11_unauthorized_restore_is_refused(disks, tmp_path):
    env = await start_env(disks, tmp_path, provider=FakeConfigProvider(restore=True))
    _, plan = await _plan(env)

    with pytest.raises(AuthorizationError) as err:
        await env.api.async_request_restore(plan, actor=PLAIN_USER)
    assert err.value.details["reason"] == "not_admin"

    forged = replace(plan, plan_id="pln_" + "f" * 32)
    with pytest.raises(ApprovalInvalidError) as err:
        await env.api.async_request_restore(forged, actor=ADMIN)
    assert err.value.details["reason"] == "unknown_plan"

    approval = await env.api.async_request_restore(plan, actor=ADMIN)
    with pytest.raises(ApprovalRequiredError):  # not approved yet
        await env.api.async_execute_restore(approval.approval_id, actor=ADMIN)
    with pytest.raises(AuthorizationError):  # a plain user cannot approve
        await env.api.async_approve(approval.approval_id, actor=PLAIN_USER)
    await approve_as(env, approval.approval_id, OTHER_ADMIN_ID)
    with pytest.raises(ApprovalInvalidError) as err:  # only the requester redeems
        await env.api.async_execute_restore(approval.approval_id, actor=OTHER_ADMIN)
    assert err.value.details["reason"] == "not_requester"
    with pytest.raises(ApprovalInvalidError):
        await env.api.async_execute_restore("apr_" + "0" * 32, actor=ADMIN)
    assert env.provider.ops("execute_restore") == []
    denied = env.api.events(types=[CoreEventType.AUTHORIZATION_DENIED.value])
    assert len(denied) >= 4


async def test_case11_rejected_or_unconsumed_restore(disks, tmp_path):
    env = await start_env(disks, tmp_path, provider=FakeConfigProvider(restore=True))
    _, plan = await _plan(env)
    approval = await env.api.async_request_restore(plan, actor=ADMIN)
    await env.api.async_reject(approval.approval_id, actor=OTHER_ADMIN, reason="no")
    with pytest.raises(ApprovalInvalidError):
        await env.api.async_execute_restore(approval.approval_id, actor=ADMIN)

    approval = await env.api.async_request_restore(plan, actor=ADMIN)
    await approve_as(env, approval.approval_id, ADMIN_ID)  # self-approval allowed
    env.provider.consume_on_restore = False  # a provider that skips consume
    with pytest.raises(ProviderError) as err:
        await env.api.async_execute_restore(approval.approval_id, actor=ADMIN)
    assert err.value.details["reason"] == "authorization_not_consumed"
    assert _count(env, CoreEventType.RESTORE_FAILED) == 1


async def test_case11_restore_needs_the_restore_capability(disks, tmp_path):
    env = await start_env(disks, tmp_path)  # provider without config.restore
    _, plan = await _plan(env)
    with pytest.raises(CapabilityUnavailableError):
        await env.api.async_request_restore(plan, actor=ADMIN)
    assert env.api.pending_approvals(env.rid) == ()


# -- export: critical, one approval per download --------------------------------------


async def test_export_is_critical_with_one_approval_per_download(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    record = (await _backup(env)).record

    with pytest.raises(AuthorizationError):
        await env.api.async_request_export(record.backup_id, actor=PLAIN_USER)
    approval = await env.api.async_request_export(
        record.backup_id, actor=ADMIN, artifact=ArtifactKind.UCI
    )
    with pytest.raises(ApprovalRequiredError):
        await env.api.async_export_backup(approval.approval_id, actor=ADMIN)
    await approve_as(env, approval.approval_id, OTHER_ADMIN_ID)
    with pytest.raises(ApprovalInvalidError):
        await env.api.async_export_backup(approval.approval_id, actor=OTHER_ADMIN)

    handle = await env.api.async_export_backup(approval.approval_id, actor=ADMIN)
    data = await handle.reader()
    assert data == _read(_file(env, record, "uci"))
    assert hashlib.sha256(data).hexdigest() == handle.sha256
    assert handle.contains_secrets
    with pytest.raises(ApprovalInvalidError):  # the reader works once
        await handle.reader()
    with pytest.raises(ApprovalInvalidError):  # the approval works once
        await env.api.async_export_backup(approval.approval_id, actor=ADMIN)
    assert _count(env, CoreEventType.BACKUP_EXPORTED) == 1

    # a second download needs a second request and approval
    again = await env.api.async_request_export(
        record.backup_id, actor=ADMIN, artifact=ArtifactKind.UCI
    )
    assert again.approval_id != approval.approval_id
    await approve_as(env, again.approval_id, ADMIN_ID)
    await (await env.api.async_export_backup(again.approval_id, actor=ADMIN)).reader()
    assert _count(env, CoreEventType.BACKUP_EXPORTED) == 2


async def test_export_is_never_for_the_system_or_automations(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    record = (await _backup(env)).record
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_request_export(record.backup_id, actor=Actor.system())
    assert err.value.details["reason"] == "not_admin"


# -- installation key lost ------------------------------------------------------------


async def _lose_key(env):
    await stop_env(env)
    disks = env.disks
    disks[INSTALLATION_KEY_STORE_KEY].data = None
    with patch.object(version_store_module, "async_raise_issue") as raise_issue:
        env = await restart(env)
    return env, raise_issue


async def test_installation_key_store_is_private_and_atomic(disks, tmp_path):
    await start_env(disks, tmp_path)
    assert disks.options[INSTALLATION_KEY_STORE_KEY] == {
        "private": True,
        "atomic_writes": True,
    }
    # metadata only, no secret: the catalog keeps HA's defaults
    assert disks.options[CONFIG_CATALOG_STORE_KEY]["private"] is False


def test_core_store_hands_private_and_atomic_to_ha_store():
    seen: dict = {}

    def fake_init(self, hass, version, key, private=False, **kwargs):
        seen.update(private=private, **kwargs)

    with patch.object(core_store.Store, "__init__", fake_init):
        core_store.create_store(
            None,
            1,
            "openwrt_router.test",
            minor_version=1,
            migrate=lambda major, minor, data: data,
            private=True,
            atomic_writes=True,
        )
    assert seen["private"] is True
    assert seen["atomic_writes"] is True
    assert seen["minor_version"] == 1


async def test_installation_key_lost_is_never_regenerated_silently(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    record = (await _backup(env)).record
    old_key_id = env.versions.key_id
    assert record.installation_key_id == old_key_id

    env, raise_issue = await _lose_key(env)

    assert env.api.installation_key_state is InstallationKeyState.LOST
    raise_issue.assert_called_once()
    assert raise_issue.call_args.args[1] == ISSUE_INSTALLATION_KEY_LOST
    assert _count(env, CoreEventType.INSTALLATION_KEY_LOST) == 1
    with pytest.raises(InstallationKeyLostError):
        await env.api.async_get_installation_key()
    with pytest.raises(InstallationKeyLostError):
        await _backup(env)  # the provider needs the key: refused, not created
    assert disks[INSTALLATION_KEY_STORE_KEY].data is None
    # versions stay listed and readable
    assert [r.backup_id for r in await env.api.async_list_backups(env.rid)] == [
        record.backup_id
    ]

    # a second start while still lost: the issue again, the event not again
    env, raise_issue = await _lose_key(env)
    raise_issue.assert_called_once()
    assert _count(env, CoreEventType.INSTALLATION_KEY_LOST) == 1
    assert env.versions.stats["key_lost_already_reported"] == 1
    assert disks[INSTALLATION_KEY_STORE_KEY].data is None


async def test_installation_key_reset_needs_approval_then_rebaselines(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    old = (await _backup(env)).record
    with pytest.raises(ConfigApiError) as err:  # nothing to reset while ok
        await env.api.async_request_installation_key_reset(actor=ADMIN)
    assert err.value.details["reason"] == "key_not_lost"
    env, _ = await _lose_key(env)

    with pytest.raises(AuthorizationError):
        await env.api.async_request_installation_key_reset(actor=PLAIN_USER)
    approval = await env.api.async_request_installation_key_reset(actor=ADMIN)
    with pytest.raises(ApprovalRequiredError):
        await env.api.async_reset_installation_key(approval.approval_id, actor=ADMIN)
    await approve_as(env, approval.approval_id, OTHER_ADMIN_ID)
    await env.api.async_reset_installation_key(approval.approval_id, actor=ADMIN)

    assert env.api.installation_key_state is InstallationKeyState.OK
    assert disks[INSTALLATION_KEY_STORE_KEY].data is not None
    assert env.versions.key_id != old.installation_key_id
    assert env.versions.needs_rebaseline(env.rid)
    assert _count(env, CoreEventType.INSTALLATION_KEY_RESET) == 1
    with pytest.raises(ApprovalInvalidError):  # single use
        await env.api.async_reset_installation_key(approval.approval_id, actor=ADMIN)

    report = await env.api.async_detect_drift(env.rid, actor=ADMIN)
    assert report.rebaseline and not report.drifted
    assert not env.versions.needs_rebaseline(env.rid)
    baseline = await env.api.async_get_backup(
        (await env.api.async_get_baseline(env.rid)).version_id
    )
    assert baseline.installation_key_id == env.versions.key_id


# -- unload / reload with a provider --------------------------------------------------


async def test_unload_and_reload_with_a_provider(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    record = (await _backup(env)).record
    pending = await env.api.async_request_export(record.backup_id, actor=ADMIN)
    old_api, old_manager, key_id = env.api, env.manager, env.versions.key_id

    await stop_env(env)

    assert old_manager.closed
    assert old_manager.provider_id is None
    assert old_manager.stats["requests_dropped_on_close"] == 1
    with pytest.raises(ConfigApiError) as err:
        await async_get_configuration_api(env.hass, 1)
    assert err.value.details["reason"] == "core_not_running"
    with pytest.raises(ConfigApiError):  # a kept old facade does nothing
        await old_api.async_create_backup(
            env.rid, reason=BackupReason.MANUAL, actor=ADMIN
        )
    env.unregister()  # unregistering after the unload is harmless
    probes_before = len(env.provider.ops("probe"))

    env = await restart(env)

    assert env.api.provider_id == env.provider.provider_id
    assert len(env.provider.ops("probe")) == probes_before + 1
    assert env.versions.key_id == key_id
    listed = await env.api.async_list_backups(env.rid)
    assert [r.backup_id for r in listed] == [record.backup_id]
    validated = await env.api.async_validate_backup(record.backup_id)
    assert validated.validation.status is ValidationStatus.VALID
    with pytest.raises(ApprovalInvalidError):  # approvals never survive
        await env.api.async_export_backup(pending.approval_id, actor=ADMIN)
    _hostname(env, "after-reload")
    assert (await _backup(env, BackupReason.SCHEDULED, Actor.system())).created
    assert env.router_calls() == []


async def test_provider_unregister_makes_everything_unavailable(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.unregister()
    status = env.api.capability(env.rid, Capability.CONFIG_BACKUP)
    assert status.reason == CapabilityReason.NO_PROVIDER
    with pytest.raises(CapabilityUnavailableError):
        await _backup(env)
    # a second provider may register now
    second = FakeConfigProvider("second")
    second.guard = env.api.guard
    env.api.register_provider(second)
    await drain(env.hass)
    assert env.api.provider_id == "second"
    assert (await _backup(env)).created
