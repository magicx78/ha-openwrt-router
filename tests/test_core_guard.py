"""Guard bypass attempts against the running core (contract §6).

Every write path must go through an authorization the guard minted for
exactly that action, router and binding, used once, by a re-verified actor.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from core_test_provider import (
    payload,
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
    add_user,
    bus_events,
    user_actor,
)

from custom_components.openwrt_router.core_errors import (
    AuthorizationError,
)
from custom_components.openwrt_router.core_models import (
    Actor,
    ArtifactKind,
    BackupReason,
    BackupType,
    CoreEventType,
    DecisionState,
    GuardedAction,
    VerifiedActor,
    VersionMeta,
    WriteAuthorization,
    _mint_write_authorization,
    binding_checksum,
    utcnow,
)

ADMIN = user_actor(ADMIN_ID)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _meta() -> VersionMeta:
    return VersionMeta(backup_type=BackupType.UCI_SNAPSHOT, reason=BackupReason.IMPORT)


def _artifacts(text: bytes = b'{"system":{}}'):
    return {ArtifactKind.UCI: payload(text)}


async def _verified(env, actor=ADMIN):
    return await env.api.guard.async_verify_actor(actor)


async def _backup_auth(env, router_id=None, actor=ADMIN):
    decision = env.api.guard.authorize(
        GuardedAction.BACKUP, router_id or env.rid, await _verified(env, actor)
    )
    assert decision.state is DecisionState.APPROVED
    return decision.authorization


def _denied(env) -> list[dict]:
    return bus_events(env.hass, CoreEventType.AUTHORIZATION_DENIED.value)


async def test_guard_bypass_direct_construction_is_impossible():
    now = utcnow()
    with pytest.raises(TypeError):
        WriteAuthorization(
            authorization_id="wau_" + "0" * 32,
            action=GuardedAction.BACKUP,
            router_id="rtr_" + "a" * 32,
            actor=Actor.system(),
            issued_at=now,
            expires_at=now + timedelta(minutes=1),
        )
    with pytest.raises(TypeError):
        VerifiedActor(actor=user_actor(ADMIN_ID, claims_admin=True), verified_at=now)


async def test_guard_bypass_minted_outside_the_guard_is_refused(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    forged = _mint_write_authorization(
        action=GuardedAction.BACKUP, router_id=env.rid, actor=Actor.system()
    )
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_put_version(
            env.rid, _artifacts(), _meta(), authorization=forged
        )
    assert err.value.details["reason"] == "unknown_authorization"
    assert env.versions.records(env.rid) == ()
    assert any(e["data"]["reason"] == "unknown_authorization" for e in _denied(env))


async def test_guard_bypass_authorization_of_a_previous_core_is_refused(
    disks, tmp_path
):
    env = await start_env(disks, tmp_path)
    old = await _backup_auth(env)
    env = await restart(env)
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_put_version(
            env.rid, _artifacts(), _meta(), authorization=old
        )
    assert err.value.details["reason"] == "unknown_authorization"
    assert env.versions.records(env.rid) == ()


async def test_guard_bypass_closed_guard_denies(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    guard_view, verified = env.api.guard, await _verified(env)
    await stop_env(env)
    decision = guard_view.authorize(GuardedAction.BACKUP, env.rid, verified)
    assert decision.state is DecisionState.DENIED
    assert decision.reason == "guard_closed"


async def test_guard_bypass_other_router_or_action_uses_it_up(disks, tmp_path):
    env = await start_env(disks, tmp_path, routers=2)
    auth = await _backup_auth(env, env.rids[0])
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_put_version(
            env.rids[1], _artifacts(), _meta(), authorization=auth
        )
    assert err.value.details["reason"] == "router_mismatch"
    # a failed attempt uses the authorization up: no second try
    with pytest.raises(AuthorizationError):
        await env.api.async_put_version(
            env.rids[0], _artifacts(), _meta(), authorization=auth
        )
    assert env.versions.records() == ()

    protect = env.api.guard.authorize(
        GuardedAction.PROTECT, env.rid, await _verified(env)
    ).authorization
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_put_version(
            env.rid, _artifacts(), _meta(), authorization=protect
        )
    assert err.value.details["reason"] == "action_mismatch"


async def test_guard_bypass_single_use(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    auth = await _backup_auth(env)
    first = await env.api.async_put_version(
        env.rid, _artifacts(), _meta(), authorization=auth
    )
    assert first.created
    with pytest.raises(AuthorizationError):
        await env.api.async_put_version(
            env.rid, _artifacts(b'{"other":{}}'), _meta(), authorization=auth
        )
    assert len(env.versions.records(env.rid)) == 1


async def test_guard_bypass_claimed_admin_and_unverified_actors(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    plain = await _verified(env, user_actor(USER_ID, claims_admin=True))
    assert not plain.is_admin  # the claim is ignored
    decision = env.api.guard.authorize(GuardedAction.BACKUP, env.rid, plain)
    assert decision.state is DecisionState.DENIED
    assert decision.reason == "not_admin"

    raw = env.api.guard.authorize(GuardedAction.BACKUP, env.rid, ADMIN)
    assert raw.state is DecisionState.DENIED
    assert raw.reason == "unverified_actor"

    add_user(env.hass, "inactive", admin=True, active=False)
    with pytest.raises(AuthorizationError):
        await _verified(env, user_actor("inactive"))
    add_user(env.hass, "sysgen", admin=True, system_generated=True)
    generated = await _verified(env, user_actor("sysgen"))
    assert not generated.is_admin
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_create_backup(
            env.rid, reason=BackupReason.MANUAL, actor=user_actor("sysgen")
        )
    assert err.value.details["reason"] == "not_admin"
    assert env.provider.ops("collect") == []


async def test_guard_bypass_system_only_and_admin_user_only(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    admin = await _verified(env)
    system = await _verified(env, Actor.system())
    assert (
        env.api.guard.authorize(GuardedAction.PRUNE, env.rid, admin).reason
        == "system_only"
    )
    for action in (GuardedAction.PROTECT, GuardedAction.DRIFT_ACK):
        decision = env.api.guard.authorize(action, env.rid, system)
        assert decision.reason == "not_admin", action


async def test_guard_bypass_approval_bound_to_its_checksum(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    first = (
        await env.api.async_create_backup(
            env.rid, reason=BackupReason.MANUAL, actor=ADMIN
        )
    ).record
    approval = await env.api.async_request_export(
        first.backup_id, actor=ADMIN, artifact=ArtifactKind.UCI
    )
    await env.api.async_approve(approval.approval_id, actor=user_actor(OTHER_ADMIN_ID))
    # redeeming the approval for different bytes is refused
    decision = env.api.guard.authorize(
        GuardedAction.EXPORT,
        env.rid,
        await _verified(env),
        approval_id=approval.approval_id,
        checksum=binding_checksum("bkp_" + "f" * 32, "uci"),
    )
    assert decision.state is DecisionState.DENIED
    assert decision.reason == "checksum_mismatch"
    # ... and for another action
    decision = env.api.guard.authorize(
        GuardedAction.DELETE,
        env.rid,
        await _verified(env),
        approval_id=approval.approval_id,
        checksum=binding_checksum(first.backup_id, "uci"),
    )
    assert decision.state is DecisionState.DENIED


async def test_guard_bypass_module_cannot_emit_as_the_core(disks, tmp_path):
    env = await start_env(disks, tmp_path, provider=False)
    with pytest.raises(ValueError):
        env.api.emit("configuration.backup_created", source="core")
    with pytest.raises(ValueError):
        env.api.emit(CoreEventType.BACKUP_CREATED.value, source="my_module")
