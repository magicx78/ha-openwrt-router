"""Reads of live configuration content: a user must be a verified admin.

``async_capture`` returns the live configuration (secrets included) and
``async_compare`` its differences. Both verify the actor; since review
finding 2 of PR #55 they also refuse a user who is not a verified admin,
inside the function itself, so a later panel cannot offer them unprotected.
The refusal is ``AuthorizationError`` (``reason`` ``not_admin``) audited on
the security ring, before any provider call. Module, system and automation
actors pass (contract §6.2/§6.3: only users need admin rights; the same
content is what a ``backup`` by those actors reads and stores).
"""

from __future__ import annotations

import pytest
from core_test_provider import start_env, stop_env
from core_testkit import ADMIN_ID, USER_ID, FakeDisks, user_actor

from custom_components.openwrt_router.core_errors import AuthorizationError
from custom_components.openwrt_router.core_models import (
    Actor,
    ActorKind,
    AuditRing,
    BackupReason,
    ConfigRef,
    CoreEventType,
)

ADMIN = user_actor(ADMIN_ID)
PLAIN_USER = user_actor(USER_ID, claims_admin=True)  # the claim is ignored
MODULE = Actor.for_module("config_manager")
AUTOMATION = Actor(kind=ActorKind.AUTOMATION, parent_context_id="ctx-parent")


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _security_denials(env, action: str) -> list:
    return [
        e
        for e in env.api.events(
            types=[CoreEventType.AUTHORIZATION_DENIED.value], ring=AuditRing.SECURITY
        )
        if e.data.get("action") == action
    ]


async def _two_versions(env) -> tuple[str, str]:
    env.provider.live(env.rid)["system"]["@system[0]"]["hostname"] = "one"
    first = await env.api.async_create_backup(
        env.rid, reason=BackupReason.MANUAL, actor=ADMIN
    )
    env.provider.live(env.rid)["system"]["@system[0]"]["hostname"] = "two"
    second = await env.api.async_create_backup(
        env.rid, reason=BackupReason.MANUAL, actor=ADMIN
    )
    return first.record.backup_id, second.record.backup_id


async def test_capture_non_admin(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_capture(env.rid, actor=PLAIN_USER)
    assert err.value.details["reason"] == "not_admin"
    assert err.value.details["audit_id"]
    assert env.provider.ops("capture") == []  # refused before the router read
    (denied,) = _security_denials(env, "config_capture")
    assert denied.event_id == err.value.details["audit_id"]
    assert denied.router_id == env.rid
    assert denied.data["reason"] == "not_admin"
    assert denied.actor.user_id == USER_ID
    assert denied.actor.is_admin is False  # the claim is never echoed
    await stop_env(env)


async def test_compare_non_admin(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    first, second = await _two_versions(env)
    for base, other in (
        (ConfigRef.backup(first), ConfigRef.backup(second)),
        (ConfigRef.live(env.rid), ConfigRef.backup(first)),
    ):
        with pytest.raises(AuthorizationError) as err:
            await env.api.async_compare(base, other, actor=PLAIN_USER)
        assert err.value.details["reason"] == "not_admin"
    assert env.provider.ops("compare") == []
    assert env.provider.ops("capture") == []  # the live side was never read
    denials = _security_denials(env, "config_compare")
    assert len(denials) == 2
    assert {d.router_id for d in denials} == {env.rid}
    await stop_env(env)


async def test_compare_no_leak(disks, tmp_path):
    """A non-admin learns nothing about version ids: not_admin comes first."""
    env = await start_env(disks, tmp_path)
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_compare(
            ConfigRef.backup("bkp_" + "0" * 26),
            ConfigRef.backup("bkp_" + "1" * 26),
            actor=PLAIN_USER,
        )
    assert err.value.details["reason"] == "not_admin"
    await stop_env(env)


@pytest.mark.parametrize(
    "actor",
    [ADMIN, MODULE, Actor.system(), AUTOMATION],
    ids=["admin", "module", "system", "auto"],
)
async def test_read_allowed(disks, tmp_path, actor):
    env = await start_env(disks, tmp_path)
    first, second = await _two_versions(env)
    snapshot = await env.api.async_capture(env.rid, actor=actor)
    assert snapshot.router_id == env.rid
    diff = await env.api.async_compare(
        ConfigRef.backup(first), ConfigRef.backup(second), actor=actor
    )
    assert [c.config for c in diff.changes] == ["system"]
    assert _security_denials(env, "config_capture") == []
    assert _security_denials(env, "config_compare") == []
    await stop_env(env)


async def test_read_unknown_user(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    with pytest.raises(AuthorizationError) as err:
        await env.api.async_capture(env.rid, actor=user_actor("nobody"))
    assert err.value.details["reason"] == "unknown_user"
    assert env.provider.ops("capture") == []
    await stop_env(env)
