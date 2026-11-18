"""Review L2 of PR #56: ``async_validate_backup`` needs an actor.

B2 left a legacy path: without ``actor`` the validation ran unchecked
(counter ``validate_without_actor``). That was a way around the admin check
for users. Now ``actor`` is a required keyword on the manager, the facade
and ``ConfigurationApiProtocol``. ``actor=None`` or any non-``Actor``
raises ``AuthorizationError`` with reason ``actor_required`` (``details``
``action`` = ``config_validate``, ``audit_id``), audited on the security
ring and counted (``validate_refused_no_actor``) before any lookup or
provider call. The old counter is gone.
"""

from __future__ import annotations

import inspect

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import ADMIN_ID, FakeDisks, core_of, user_actor

from custom_components.openwrt_router.config_api import (
    READ_VALIDATE,
    REASON_ACTOR_REQUIRED,
    ConfigurationApi,
    ConfigurationManager,
)
from custom_components.openwrt_router.core_errors import AuthorizationError
from custom_components.openwrt_router.core_guard import FLEET_ROUTER_ID
from custom_components.openwrt_router.core_models import (
    AuditRing,
    BackupReason,
    ConfigurationApiProtocol,
    CoreEventType,
)

ADMIN = user_actor(ADMIN_ID)
UNKNOWN_BACKUP = "bkp_" + "0" * 26


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _denials(env) -> list:
    return [
        e
        for e in env.api.events(
            types=[CoreEventType.AUTHORIZATION_DENIED.value], ring=AuditRing.SECURITY
        )
        if e.data.get("action") == READ_VALIDATE
    ]


def test_actor_is_required_in_every_signature():
    assert REASON_ACTOR_REQUIRED == "actor_required"
    for owner in (ConfigurationManager, ConfigurationApi, ConfigurationApiProtocol):
        param = inspect.signature(owner.async_validate_backup).parameters["actor"]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY, owner
        assert param.default is inspect.Parameter.empty, owner


async def test_missing_actor_is_refused_and_audited(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    made = await env.api.async_create_backup(
        env.rid, reason=BackupReason.MANUAL, actor=ADMIN
    )
    backup_id = made.record.backup_id
    manager = core_of(env.hass).manager
    for target, bad in (
        (backup_id, None),
        (backup_id, "admin"),
        (backup_id, {"kind": "user", "user_id": ADMIN_ID}),
        (UNKNOWN_BACKUP, None),
    ):
        with pytest.raises(AuthorizationError) as err:
            await env.api.async_validate_backup(target, actor=bad)
        assert err.value.details["reason"] == REASON_ACTOR_REQUIRED
        assert err.value.details["action"] == READ_VALIDATE
        assert err.value.details["audit_id"]
    with pytest.raises(TypeError):
        await env.api.async_validate_backup(backup_id)  # keyword is required
    assert env.provider.ops("validate") == []
    assert manager.stats["validate_refused_no_actor"] == 4
    assert "validate_without_actor" not in manager.stats
    denials = _denials(env)
    assert len(denials) == 4
    assert {d.data["reason"] for d in denials} == {REASON_ACTOR_REQUIRED}
    # router of the known version, the fleet for an unknown id (never echoed)
    assert sorted(d.router_id for d in denials) == sorted(
        [env.rid, env.rid, env.rid, FLEET_ROUTER_ID]
    )
    record = await env.api.async_get_backup(backup_id)
    assert record.validation == made.record.validation  # nothing was validated
    # with an actor it works as before
    validated = await env.api.async_validate_backup(backup_id, actor=ADMIN)
    assert validated.backup_id == backup_id
    assert manager.stats["validate_refused_no_actor"] == 4
    await stop_env(env)
