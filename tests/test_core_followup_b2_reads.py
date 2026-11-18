"""Follow-up B2: validate, drift and restore dry run need an admin user.

Like ``async_capture``/``async_compare`` (review PR #55, point 2): a user
actor who is not a verified admin gets ``AuthorizationError`` ``not_admin``
for ``async_validate_backup``, ``async_detect_drift`` and
``async_prepare_restore`` (and ``async_check_restore_compatibility`` on top
of it), audited on the security ring, before any lookup or provider call.
Module, system and automation actors pass. ``async_validate_backup`` takes
the actor as a keyword; since review L2 of PR #56 it is required (no
actor ⇒ ``actor_required``, see test_core_followup_l2_validate_actor).
"""

from __future__ import annotations

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import ADMIN_ID, USER_ID, FakeDisks, core_of, user_actor

from custom_components.openwrt_router.config_api import (
    READ_DRIFT,
    READ_RESTORE_DRY_RUN,
    READ_VALIDATE,
)
from custom_components.openwrt_router.core_errors import AuthorizationError
from custom_components.openwrt_router.core_guard import FLEET_ROUTER_ID
from custom_components.openwrt_router.core_models import (
    Actor,
    ActorKind,
    AuditRing,
    BackupReason,
    CoreEventType,
)

ADMIN = user_actor(ADMIN_ID)
PLAIN_USER = user_actor(USER_ID, claims_admin=True)  # the claim is ignored
MODULE = Actor.for_module("config_manager")
AUTOMATION = Actor(kind=ActorKind.AUTOMATION, parent_context_id="ctx-parent")
UNKNOWN_BACKUP = "bkp_" + "0" * 26


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _denials(env, action: str) -> list:
    return [
        e
        for e in env.api.events(
            types=[CoreEventType.AUTHORIZATION_DENIED.value], ring=AuditRing.SECURITY
        )
        if e.data.get("action") == action
    ]


async def _version(env) -> str:
    made = await env.api.async_create_backup(
        env.rid, reason=BackupReason.MANUAL, actor=ADMIN
    )
    return made.record.backup_id


def test_action_names():
    assert (READ_VALIDATE, READ_DRIFT, READ_RESTORE_DRY_RUN) == (
        "config_validate",
        "config_drift",
        "config_restore_dry_run",
    )


async def test_validate_non_admin(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    backup_id = await _version(env)
    for target in (backup_id, UNKNOWN_BACKUP):
        with pytest.raises(AuthorizationError) as err:
            await env.api.async_validate_backup(target, actor=PLAIN_USER)
        assert err.value.details["reason"] == "not_admin"
        assert err.value.details["action"] == READ_VALIDATE
    assert env.provider.ops("validate") == []
    denials = _denials(env, READ_VALIDATE)
    # router of a known version; the fleet for an unknown id (nothing echoed)
    assert sorted(d.router_id for d in denials) == sorted([env.rid, FLEET_ROUTER_ID])
    assert all(d.actor.is_admin is False for d in denials)
    await stop_env(env)


async def test_drift_non_admin(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    await _version(env)
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_detect_drift(env.rid, actor=PLAIN_USER)
    assert err.value.details["reason"] == "not_admin"
    assert err.value.details["action"] == READ_DRIFT
    with pytest.raises(AuthorizationError):
        await env.api.async_detect_drift("rtr_" + "f" * 32, actor=PLAIN_USER)
    assert env.provider.ops("detect_drift") == []
    denials = _denials(env, READ_DRIFT)
    assert {d.router_id for d in denials} == {env.rid, FLEET_ROUTER_ID}
    await stop_env(env)


async def test_restore_dry_run_non_admin(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    backup_id = await _version(env)
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_prepare_restore(backup_id, env.rid, actor=PLAIN_USER)
    assert err.value.details["reason"] == "not_admin"
    assert err.value.details["action"] == READ_RESTORE_DRY_RUN
    with pytest.raises(AuthorizationError):
        await env.api.async_check_restore_compatibility(
            UNKNOWN_BACKUP, env.rid, actor=PLAIN_USER
        )
    assert env.provider.ops("prepare_restore") == []
    assert len(_denials(env, READ_RESTORE_DRY_RUN)) == 2
    await stop_env(env)


@pytest.mark.parametrize(
    "actor",
    [ADMIN, MODULE, Actor.system(), AUTOMATION],
    ids=["admin", "module", "system", "auto"],
)
async def test_reads_allowed(disks, tmp_path, actor):
    env = await start_env(disks, tmp_path)
    backup_id = await _version(env)
    validated = await env.api.async_validate_backup(backup_id, actor=actor)
    assert validated.backup_id == backup_id
    report = await env.api.async_detect_drift(env.rid, actor=actor)
    assert report.router_id == env.rid
    plan = await env.api.async_prepare_restore(backup_id, env.rid, actor=actor)
    assert plan.backup_id == backup_id
    for action in (READ_VALIDATE, READ_DRIFT, READ_RESTORE_DRY_RUN):
        assert _denials(env, action) == []
    await stop_env(env)


async def test_validate_without_actor_refused(disks, tmp_path):
    """Review L2 of PR #56: the legacy call without an actor is gone."""
    env = await start_env(disks, tmp_path)
    backup_id = await _version(env)
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_validate_backup(backup_id, actor=None)
    assert err.value.details["reason"] == "actor_required"
    stats = core_of(env.hass).manager.stats
    assert stats["validate_refused_no_actor"] == 1
    assert "validate_without_actor" not in stats
    await env.api.async_validate_backup(backup_id, actor=ADMIN)
    assert stats["validate_refused_no_actor"] == 1
    assert env.provider.ops("validate") != []
    await stop_env(env)


async def test_validate_unknown_user(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    backup_id = await _version(env)
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_validate_backup(backup_id, actor=user_actor("nobody"))
    assert err.value.details["reason"] == "unknown_user"
    assert env.provider.ops("validate") == []
    await stop_env(env)
