"""Coordinator additions to part 2 (contract §19.1 rows #56-#59).

* drift: an installation key change and a real change are reported
  together; a re-baseline happens only on an all-clear (row #56)
* drift: "not comparable" is not "no drift" (comparison partial/unknown,
  no all-clear, dedup kept; row #57)
* probes do no router work beyond permission/metadata checks; capabilities
  a probe cannot determine safely are ``unknown`` +
  ``determined_on_first_use`` and the first real use settles them (row #58)
* everything a provider or module hands to the store is unchecked input
  (size before hashing, core sha256, closed kinds, no provider locators,
  bounded metadata, hostile ids; row #59)
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from unittest.mock import patch

import pytest
from core_test_provider import (
    sha,
    short_tmp_path,  # noqa: F401 - short tmp_path
    start_env,
)
from core_testkit import ADMIN_ID, FakeDisks, bus_events, user_actor

from custom_components.openwrt_router import version_store as version_store_module
from custom_components.openwrt_router.core_errors import (
    ArtifactTooLargeError,
    BackupIntegrityError,
    BackupMetadataError,
    BackupNotFoundError,
    CapabilityUnavailableError,
    ErrorClass,
    InvalidStorageRefError,
    OperationTimeoutError,
    ProviderError,
    RouterNotFoundError,
    RouterPermissionError,
)
from custom_components.openwrt_router.core_models import (
    ArtifactKind,
    ArtifactPayload,
    ArtifactRef,
    BackupReason,
    Capability,
    CapabilityReason,
    CapabilityState,
    CollectedVersion,
    CoreEventType,
    DriftAck,
    DriftAckState,
    DriftComparison,
    DriftReport,
    StorageRef,
    VersionMeta,
    check_token,
    utcnow,
)

ADMIN = user_actor(ADMIN_ID)
FIRST_USE = (CapabilityState.UNKNOWN, CapabilityReason.DETERMINED_ON_FIRST_USE.value)
OLD_KEY_ID = "0" * 16
HOSTILE_IDS = (
    "../x",
    "../../etc/passwd",
    "/etc/passwd",
    "C:\\Windows\\system32",
    "bkp_\x00" + "a" * 31,
    "rtr_\x00" + "a" * 31,
    "bkp_" + "a" * 5000,
    "x" * 100_000,
    "",
)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _backup(env, reason=BackupReason.MANUAL, **kw):
    result = await env.api.async_create_backup(
        env.rid, reason=reason, actor=ADMIN, **kw
    )
    return result.record


def _change_live(env, hostname="changed"):
    env.provider.live(env.rid)["system"]["@system[0]"]["hostname"] = hostname


def _old_key(collected: CollectedVersion) -> CollectedVersion:
    """Stamp the version with a key id other than the current one."""
    return CollectedVersion(
        artifacts=collected.artifacts,
        meta=replace(collected.meta, installation_key_id=OLD_KEY_ID),
    )


async def _baseline_under_old_key(env):
    env.provider.collect_hook = _old_key
    record = await _backup(env)
    env.provider.collect_hook = None
    assert record.installation_key_id == OLD_KEY_ID
    assert env.versions.key_id != OLD_KEY_ID
    return record


def _types(env, event_type: CoreEventType) -> int:
    return len(bus_events(env.hass, event_type.value))


# -- row #56: key change + real change ------------------------------------------------


async def test_case56_key_change_with_real_change_is_drift_not_rebaseline(
    disks, tmp_path
):
    env = await start_env(disks, tmp_path)
    baseline = await _baseline_under_old_key(env)
    _change_live(env)
    # the provider claims "only the key changed" although the hostname changed
    env.provider.drift_hook = lambda r: replace(r, rebaseline=True)
    versions_before = len(env.versions.records(env.rid))

    report = await env.api.async_detect_drift(env.rid, actor=ADMIN)

    assert report.drifted
    assert not report.rebaseline
    assert report.diff.comparable_changes
    stats = env.manager.stats
    assert stats["rebaseline_refused"] == 1
    assert stats["rebaselines"] == 0
    # the baseline stays, no re-baseline version was taken
    current = await env.api.async_get_baseline(env.rid)
    assert current.version_id == baseline.backup_id
    assert len(env.versions.records(env.rid)) == versions_before
    events = bus_events(env.hass, CoreEventType.DRIFT_DETECTED.value)
    assert len(events) == 1
    assert events[0]["data"]["installation_key_changed"] is True
    assert _types(env, CoreEventType.DRIFT_ACKNOWLEDGED) == 0


async def test_case56_key_change_with_real_change_without_provider_flag(
    disks, tmp_path
):
    env = await start_env(disks, tmp_path)
    baseline = await _baseline_under_old_key(env)
    _change_live(env)

    report = await env.api.async_detect_drift(env.rid, actor=ADMIN)

    assert report.drifted and not report.rebaseline
    assert (await env.api.async_get_baseline(env.rid)).version_id == (
        baseline.backup_id
    )
    assert env.manager.stats["rebaselines"] == 0
    assert _types(env, CoreEventType.DRIFT_DETECTED) == 1


async def test_case56_key_change_alone_rebaselines_once(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    baseline = await _baseline_under_old_key(env)

    report = await env.api.async_detect_drift(env.rid, actor=ADMIN)

    assert report.rebaseline and not report.drifted
    current = await env.api.async_get_baseline(env.rid)
    assert current.version_id != baseline.backup_id
    new = await env.api.async_get_backup(current.version_id)
    assert new.installation_key_id == env.versions.key_id
    assert env.manager.stats["rebaselines"] == 1
    assert _types(env, CoreEventType.DRIFT_DETECTED) == 0
    # the next check compares against the new baseline: no second re-baseline
    again = await env.api.async_detect_drift(env.rid, actor=ADMIN)
    assert not again.rebaseline and not again.drifted
    assert env.manager.stats["rebaselines"] == 1


async def test_case56_unconfirmed_rebaseline_claim_is_ignored(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    await _backup(env)
    env.provider.drift_hook = lambda r: replace(r, rebaseline=True)

    report = await env.api.async_detect_drift(env.rid, actor=ADMIN)

    assert not report.rebaseline
    assert env.manager.stats["rebaseline_unconfirmed"] == 1
    assert env.manager.stats["rebaselines"] == 0


async def test_case56_inconsistent_report_is_treated_as_drift(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    await _backup(env)
    _change_live(env)
    env.provider.drift_hook = lambda r: replace(r, drifted=False, drift_id=None)

    report = await env.api.async_detect_drift(env.rid, actor=ADMIN)

    assert report.drifted
    assert report.drift_id.startswith("core:")
    assert env.manager.stats["drift_inconsistent"] == 1
    assert _types(env, CoreEventType.DRIFT_DETECTED) == 1


def test_case56_model_reports_both_together():
    report = DriftReport(
        router_id="rtr_" + "a" * 32,
        baseline_backup_id="bkp_" + "b" * 32,
        checked_at=utcnow(),
        drifted=True,
        diff=_empty_diff(),
        drift_id="drift_1",
        rebaseline=True,
    )
    assert not report.rebaseline_allowed
    assert not report.all_clear
    assert CoreEventType.DRIFT_DETECTED in report_types(report)


def _empty_diff():
    from custom_components.openwrt_router.core_models import ConfigDiff, ConfigRef

    return ConfigDiff(
        base=ConfigRef.backup("bkp_" + "b" * 32),
        other=ConfigRef.live("rtr_" + "a" * 32),
        compared_at=utcnow(),
    )


def report_types(report):
    from custom_components.openwrt_router.core_models import drift_event_types

    return drift_event_types(report)


# -- row #57: not comparable is not "no drift" --------------------------------------


def _partial(not_compared=("wireless",), comparison=DriftComparison.PARTIAL):
    def hook(report):
        return replace(report, comparison=comparison, not_compared=not_compared)

    return hook


async def test_case57_partial_comparison_is_no_all_clear(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    await _backup(env)
    env.provider.drift_hook = _partial()

    report = await env.api.async_detect_drift(env.rid, actor=ADMIN)

    assert not report.drifted
    assert report.comparison is DriftComparison.PARTIAL
    assert report.not_compared == ("wireless",)
    assert not report.all_clear
    assert report.to_dict()["comparison"] == "partial"
    assert env.manager.stats["drift_incomplete"] == 1
    events = bus_events(env.hass, CoreEventType.DRIFT_INCOMPLETE.value)
    assert len(events) == 1
    assert events[0]["data"]["comparison"] == "partial"
    assert events[0]["data"]["not_compared"] == ["wireless"]
    stored = env.api.events(
        router_id=env.rid, types=[CoreEventType.DRIFT_INCOMPLETE.value]
    )
    assert stored and stored[0].data["not_compared_count"] == 1


async def test_case57_incomplete_check_keeps_the_drift_dedup(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    await _backup(env)
    _change_live(env)
    await env.api.async_detect_drift(env.rid, actor=ADMIN)
    assert _types(env, CoreEventType.DRIFT_DETECTED) == 1

    # an incomplete check that sees no comparable change is NOT an all-clear
    env.provider.drift_hook = lambda r: replace(
        r,
        drifted=False,
        drift_id=None,
        diff=replace(r.diff, changes=()),
        critical_count=0,
        comparison=DriftComparison.UNKNOWN,
        not_compared=("system", "firewall"),
    )
    report = await env.api.async_detect_drift(env.rid, actor=ADMIN)
    assert report.comparison is DriftComparison.UNKNOWN and not report.all_clear

    # the same drift again: still deduplicated (the window was not reset)
    env.provider.drift_hook = None
    await env.api.async_detect_drift(env.rid, actor=ADMIN)
    assert _types(env, CoreEventType.DRIFT_DETECTED) == 1


async def test_case57_complete_all_clear_resets_the_dedup(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    await _backup(env)
    _change_live(env)
    await env.api.async_detect_drift(env.rid, actor=ADMIN)
    _change_live(env, env.rid[-6:])  # back to the baseline state
    clear = await env.api.async_detect_drift(env.rid, actor=ADMIN)
    assert clear.all_clear
    _change_live(env)
    await env.api.async_detect_drift(env.rid, actor=ADMIN)
    assert _types(env, CoreEventType.DRIFT_DETECTED) == 2


async def test_case57_key_change_with_incomplete_comparison_keeps_baseline(
    disks, tmp_path
):
    env = await start_env(disks, tmp_path)
    baseline = await _baseline_under_old_key(env)
    env.provider.drift_hook = lambda r: replace(_partial()(r), rebaseline=True)

    report = await env.api.async_detect_drift(env.rid, actor=ADMIN)

    assert not report.rebaseline
    assert env.manager.stats["rebaseline_refused"] == 1
    assert (await env.api.async_get_baseline(env.rid)).version_id == (
        baseline.backup_id
    )
    assert _types(env, CoreEventType.DRIFT_INCOMPLETE) == 1


def test_case57_model_validation():
    base = {
        "router_id": "rtr_" + "a" * 32,
        "baseline_backup_id": "bkp_" + "b" * 32,
        "checked_at": utcnow(),
        "drifted": False,
        "diff": _empty_diff(),
    }
    with pytest.raises(ValueError):
        DriftReport(**base, comparison=DriftComparison.PARTIAL)  # nothing named
    with pytest.raises(ValueError):
        DriftReport(**base, not_compared=("wireless",))  # complete but not compared
    with pytest.raises(ValueError):
        DriftReport(**{**base, "drifted": True})  # drift without drift_id
    ok = DriftReport(
        **base, comparison=DriftComparison.UNKNOWN, not_compared=("network",)
    )
    assert not ok.all_clear
    assert CoreEventType.DRIFT_INCOMPLETE in report_types(ok)


# -- row #58: probes do no work; determined on first use ------------------------------


async def test_case58_probe_never_collects_or_writes(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    for _ in range(3):
        assert env.api.request_probe(env.rid, "test")
        await _drain(env)
    assert {op for op, _ in env.provider.calls} == {"probe"}
    assert env.versions.records(env.rid) == ()
    assert env.router_calls() == []


async def test_case58_probe_cannot_read_versions(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    record = await _backup(env)
    original = env.provider.async_probe

    async def reading_probe(conn, ctx):
        await ctx.read(record.backup_id, ArtifactKind.UCI)
        return await original(conn, ctx)

    env.provider.async_probe = reading_probe
    assert await env.manager.async_probe(env.rid, "test") is False
    assert env.manager.stats["probe_errors"] == 1


async def test_case58_first_use_capability_may_be_tried_and_settles(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.provider.probe_states[Capability.CONFIG_BACKUP] = FIRST_USE
    await env.manager.async_probe(env.rid, "test")
    status = env.api.capability(env.rid, Capability.CONFIG_BACKUP)
    assert status.state is CapabilityState.UNKNOWN
    assert status.reason == "determined_on_first_use"
    # the registry lets config.* in that state be tried (seen after a poll)
    env.coords[env.rid].poll()
    env.api.registry.require_capability(env.rid, Capability.CONFIG_BACKUP)
    assert env.versions.records(env.rid) == ()  # the probe made no backup

    await _backup(env)

    status = env.api.capability(env.rid, Capability.CONFIG_BACKUP)
    assert status.state is CapabilityState.AVAILABLE
    assert status.detail["settled_by"] == "backup"
    assert env.manager.stats["first_use_settled"] >= 1


async def test_case58_first_use_permission_failure_blocks_the_next_try(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.provider.probe_states[Capability.CONFIG_BACKUP] = FIRST_USE
    await env.manager.async_probe(env.rid, "test")
    env.provider.fail["collect"] = RouterPermissionError(
        "ACL denies backup", router_id=env.rid
    )

    with pytest.raises(RouterPermissionError):
        await _backup(env)
    status = env.api.capability(env.rid, Capability.CONFIG_BACKUP)
    assert status.state is CapabilityState.UNAVAILABLE
    assert status.reason == CapabilityReason.PERMISSION_DENIED.value
    env.coords[env.rid].poll()
    with pytest.raises(CapabilityUnavailableError):
        env.api.registry.require_capability(env.rid, Capability.CONFIG_BACKUP)

    calls = len(env.provider.ops("collect"))
    with pytest.raises(CapabilityUnavailableError):
        await _backup(env)
    assert len(env.provider.ops("collect")) == calls  # not tried again


async def test_case58_first_use_timeout_leaves_it_unknown(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.provider.probe_states[Capability.CONFIG_CAPTURE] = FIRST_USE
    await env.manager.async_probe(env.rid, "test")
    env.provider.fail["capture"] = TimeoutError()
    with pytest.raises(OperationTimeoutError):
        await env.api.async_capture(env.rid, actor=ADMIN)
    status = env.api.capability(env.rid, Capability.CONFIG_CAPTURE)
    assert status.reason == "determined_on_first_use"
    env.provider.fail.clear()
    await env.api.async_capture(env.rid, actor=ADMIN)
    assert env.api.capability(env.rid, Capability.CONFIG_CAPTURE).available


async def test_case58_first_use_archive_settles_cgi_backup(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.provider.probe_states[Capability.CONFIG_CGI_BACKUP] = FIRST_USE
    await env.manager.async_probe(env.rid, "test")
    record = await _backup(env)
    assert ArtifactKind.ARCHIVE.value in record.artifacts
    assert env.api.capability(env.rid, Capability.CONFIG_CGI_BACKUP).available


def test_case58_registry_refuses_first_use_outside_config():
    from custom_components.openwrt_router.core_models import (
        CONFIG_CAPABILITIES,
        CapabilityStatus,
    )

    status = CapabilityStatus(
        capability="net.wifi",
        state=CapabilityState.UNKNOWN,
        reason=CapabilityReason.DETERMINED_ON_FIRST_USE.value,
        source="test",
        detected_at=utcnow(),
    )
    assert "net.wifi" not in CONFIG_CAPABILITIES
    assert not status.available


# -- row #59: unchecked input ---------------------------------------------------------


async def test_case59_oversized_artifact_refused_before_hashing(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.versions.router_limit = 64
    with (
        patch.object(
            version_store_module, "_hash_payloads", side_effect=AssertionError
        ) as hashing,
        pytest.raises(ArtifactTooLargeError),
    ):
        await _backup(env)
    hashing.assert_not_called()
    assert env.versions.records(env.rid) == ()
    assert env.versions.stats["too_large"] == 1
    router_dir = os.path.join(_root(env), env.rid)
    assert not os.path.isdir(router_dir) or os.listdir(router_dir) == []
    assert _types(env, CoreEventType.BACKUP_FAILED) == 1


async def test_case59_provider_sha256_is_never_trusted(disks, tmp_path):
    env = await start_env(disks, tmp_path)

    def lying(collected):
        artifacts = dict(collected.artifacts)
        data = artifacts[ArtifactKind.UCI.value].data
        artifacts[ArtifactKind.UCI.value] = ArtifactPayload(
            data=data, sha256=sha(data + b"tampered")
        )
        return CollectedVersion(artifacts=artifacts, meta=collected.meta)

    env.provider.collect_hook = lying
    with pytest.raises(BackupIntegrityError) as err:
        await _backup(env)
    assert err.value.details["reason"] == "checksum_mismatch"
    assert env.versions.records(env.rid) == ()
    assert env.versions.stats["integrity_failures"] == 1

    env.provider.collect_hook = None
    record = await _backup(env)
    for kind, ref in record.artifacts.items():
        on_disk = _read(env, ref.storage.locator)
        assert ref.sha256 == hashlib.sha256(on_disk).hexdigest(), kind


async def test_case59_provider_locator_is_refused(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    first = await _backup(env)
    stolen = first.artifacts[ArtifactKind.UCI.value]

    def pointing(collected):
        return CollectedVersion(
            artifacts={ArtifactKind.UCI: stolen}, meta=collected.meta
        )

    env.provider.collect_hook = pointing
    with pytest.raises(ProviderError) as err:
        await _backup(env)
    assert err.value.error_class is ErrorClass.INVALID
    assert err.value.details["reason"] == "artifact_not_a_payload"
    assert len(env.versions.records(env.rid)) == 1

    # the same through the module put path: refused before the auth is used
    auth = env.api.guard.authorize(
        "backup", env.rid, await env.api.guard.async_verify_actor(ADMIN)
    ).authorization
    with pytest.raises(BackupMetadataError) as err:
        await env.api.async_put_version(
            env.rid,
            {ArtifactKind.UCI: stolen},
            VersionMeta(backup_type="uci_snapshot", reason=BackupReason.IMPORT),
            authorization=auth,
        )
    assert err.value.details["reason"] == "artifact_not_a_payload"
    assert not env.manager.guard.used(auth)


async def test_case59_unknown_artifact_kind_is_refused(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    auth = env.api.guard.authorize(
        "backup", env.rid, await env.api.guard.async_verify_actor(ADMIN)
    ).authorization
    data = b"{}"
    for kind in ("../x", "uci/../../evil", "firmware"):
        with pytest.raises(BackupMetadataError) as err:
            await env.api.async_put_version(
                env.rid,
                {kind: ArtifactPayload(data=data, sha256=sha(data))},
                VersionMeta(backup_type="uci_snapshot", reason=BackupReason.IMPORT),
                authorization=auth,
            )
        assert err.value.details["reason"] == "unknown_artifact_kind"
    assert env.versions.stats["refused_input"] == 3
    assert not env.manager.guard.used(auth)


@pytest.mark.parametrize("hostile", HOSTILE_IDS, ids=range(len(HOSTILE_IDS)))
async def test_case59_hostile_ids_are_refused_without_echo(disks, tmp_path, hostile):
    env = await start_env(disks, tmp_path)
    record = await _backup(env)
    collects = len(env.provider.ops("collect"))

    for call in (
        env.api.async_get_backup(hostile),
        env.api.versions.async_get_version(hostile),
        env.versions.async_read_artifact(hostile, "uci"),
        env.api.async_request_export(hostile, actor=ADMIN),
        env.api.async_validate_backup(hostile, actor=ADMIN),
    ):
        with pytest.raises(BackupNotFoundError) as err:
            await call
        assert hostile not in str(err.value.details) or hostile == ""
    with pytest.raises(BackupNotFoundError):
        await env.versions.async_read_artifact(record.backup_id, hostile)

    with pytest.raises(RouterNotFoundError) as err:
        await env.api.async_create_backup(
            hostile, reason=BackupReason.MANUAL, actor=ADMIN
        )
    assert err.value.router_id is None
    with pytest.raises(RouterNotFoundError):
        await env.api.async_detect_drift(hostile, actor=ADMIN)

    with pytest.raises(ValueError):
        await env.api.async_acknowledge_drift(
            env.rid, hostile, state=DriftAckState.KNOWN, actor=ADMIN
        )
    assert await env.api.async_list_drift_acks(env.rid) == ()
    assert len(env.provider.ops("collect")) == collects  # no router work
    assert env.router_calls() == []


@pytest.mark.parametrize("hostile", ["../x", "/abs", "a\x00b", "a" * 200, "", ".."])
def test_case59_metadata_strings_are_bounded(hostile):
    with pytest.raises((TypeError, ValueError)):
        check_token("id", hostile)
    with pytest.raises((TypeError, ValueError)):
        DriftAck(
            router_id="rtr_" + "a" * 32,
            drift_id=hostile,
            state=DriftAckState.KNOWN,
            actor=ADMIN,
            ts=utcnow(),
        )
    if "\x00" in hostile or len(hostile) > 128:
        with pytest.raises(ValueError):
            VersionMeta(
                backup_type="uci_snapshot",
                reason=BackupReason.IMPORT,
                fetch_method=hostile,
            )
    with pytest.raises(ValueError):
        VersionMeta(
            backup_type="uci_snapshot",
            reason=BackupReason.IMPORT,
            installation_key_id=hostile,
        )


def test_case59_store_never_takes_a_locator_from_a_ref():
    with pytest.raises(InvalidStorageRefError):
        ArtifactRef(
            storage=StorageRef(locator="../../etc/shadow"),
            sha256="a" * 64,
            size_bytes=1,
        )


# -- helpers --------------------------------------------------------------------------


async def _drain(env):
    from core_testkit import drain

    await drain(env.hass)


def _root(env) -> str:
    return env.versions._root


def _read(env, locator: str) -> bytes:
    with open(os.path.join(_root(env), env.rid, locator), "rb") as handle:
        return handle.read()
