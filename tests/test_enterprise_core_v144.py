"""Release 1.44.0 of the enterprise core: integrate items 1-7.

Mocks only: no router, no Home Assistant instance, no host. Router calls go
to MagicMock/AsyncMock objects or to the fake asyncssh router of
test_ssh_hostkey_pinning; the core's stores are FakeDisks.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import UTC, date, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from core_test_provider import (
    approve_as,
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
    FakeEntry,
    bus_events,
    core_of,
    drain,
    make_hass,
    router_data,
    setup_router,
    user_actor,
)
from test_acl_tiers import V8_TEXT
from test_acl_tiers import _api as acl_api
from test_retention_gfs import KB, V, gfs, item, plan
from test_ssh_hostkey_pinning import KEY_A, KEY_B, FakeRouter, _patched
from test_ssh_hostkey_pinning import _api as ssh_api

from custom_components.openwrt_router import config_flow as cf_module
from custom_components.openwrt_router.acl_provisioning import (
    DEFAULT_TIER_REGISTRY,
    RPCD_ACL_CONTENT,
    TIER_CONFIG_BACKUP_READ,
    TIER_RF_SCAN,
    TIER_RF_SURVEY,
    AclEnsureOutcome,
    AclOfferRefusedError,
    build_acl,
    ensure_acl,
    ensure_acl_respecting_offer,
    missing_permissions,
    observe_deployed_acl,
    render_acl,
)
from custom_components.openwrt_router.api import (
    OpenWrtConnectionError,
    OpenWrtHostKeyError,
    OpenWrtHostKeyMismatchError,
    OpenWrtMethodNotFoundError,
)
from custom_components.openwrt_router.core_errors import (
    ApprovalInvalidError,
    ApprovalRequiredError,
    AuthorizationError,
    CapabilityUnavailableError,
)
from custom_components.openwrt_router.core_models import (
    OPTION_CONFIG_BACKUP_ENABLED,
    SSH_PIN_FIRST_USE_POLICY,
    SSH_PIN_POLICY_CONFIRM,
    SSH_PIN_POLICY_TOFU,
    SSH_PIN_STORE_KEY,
    ActionClass,
    AuditRing,
    BackupReason,
    Capability,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    CoreEventType,
    KeepReason,
    ProviderContext,
    should_deduplicate,
)
from custom_components.openwrt_router.core_security import migrate_pin_store
from custom_components.openwrt_router.enterprise_core import (
    async_remove_entry_core,
)

ADMIN = user_actor(ADMIN_ID)
OTHER_ADMIN = user_actor(OTHER_ADMIN_ID)
PLAIN = user_actor(USER_ID)
RF = (Capability.RF_TXPOWERLIST, Capability.RF_SURVEY, Capability.RF_SCAN)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _count(env, event_type: CoreEventType) -> int:
    return len(bus_events(env.hass, event_type.value))


def _caps(env, rid=None):
    return env.core.registry.capabilities(rid or env.rid)


# ---------------------------------------------------------------------------
# 1. Restart-safe ACL: ensure_acl_respecting_offer, zero extra router calls
# ---------------------------------------------------------------------------


_SCENARIOS = {
    "v8_current": V8_TEXT,
    "missing": None,
    "legacy": json.dumps({"root": {"read": {"ubus": {}}}}),
    "corrupted": "{not json",
    "unreachable": OpenWrtConnectionError("down"),
    "write_blocked": "write_blocked",
}

# Literal expectations per scenario, taken from ensure_acl on origin/main
# (1.43, before the 1.44.0 changes; review finding 18): the router calls as
# (object, method, params) with a written ``data`` given by the sha256 of
# its bytes, the SSH commands by their sha256, and the result. Comparing the
# two variants with each other would not notice a change made to both.
_ACL_PATH = "/usr/share/rpcd/acl.d/ha-openwrt-router.json"
_V8_BYTES = "sha256:c774021615dbc83d2241b96666b864675383132f0147ad5496f8d1fc0bb71df1"
_READ = ("file", "read", {"path": _ACL_PATH})
_WRITE = ("file", "write", {"path": _ACL_PATH, "data": _V8_BYTES})
_RESTART = ("file", "exec", {"command": "/etc/init.d/rpcd", "params": ["restart"]})
_SSH_DEPLOY = (
    "sha256:2f6b32bd90246670829f4b0f46b7ecb48215c81bf04146d34f6512fad253eafe",
    {"timeout": 15.0},
)
_EXPECTED = {
    "v8_current": (("ok", False), [_READ], []),
    "missing": (("ok", True), [_READ, _WRITE, _RESTART], []),
    "legacy": (("ok", True), [_READ, _WRITE, _RESTART], []),
    "corrupted": (("ok", True), [_READ, _WRITE, _RESTART], []),
    "unreachable": (
        ("ok", False),
        [_READ, ("file", "stat", {"path": _ACL_PATH})],
        [],
    ),
    "write_blocked": (("ok", True), [_READ, _WRITE], [_SSH_DEPLOY]),
}


def _sha(text):
    import hashlib

    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _scenario_api(scenario):
    if scenario != "write_blocked":
        return acl_api(_SCENARIOS[scenario])
    # ACL missing and ubus file/write blocked: the SSH fallback writes it
    api = acl_api(None)
    api._run_ssh = AsyncMock(return_value="HA_ACL_DEPLOYED\n")

    def _blocked(obj, method, params):
        raise OpenWrtMethodNotFoundError("NOT_FOUND")

    api._call = AsyncMock(side_effect=_blocked)
    return api


def _seen(api):
    calls = []
    for call in api._call.await_args_list:
        obj, method, params = call.args
        params = dict(params)
        if "data" in params:
            params["data"] = _sha(params["data"])
        calls.append((obj, method, params))
    ssh = [(_sha(c.args[0]), dict(c.kwargs)) for c in api._run_ssh.await_args_list]
    return calls, ssh


@pytest.mark.parametrize("scenario", sorted(_SCENARIOS))
async def test_respecting_offer_makes_exactly_the_calls_of_ensure_acl(scenario):
    """Pin: with no tiered ACL deployed, calls and bytes equal 1.43's ensure_acl."""
    result, calls, ssh = _EXPECTED[scenario]
    for fn in (ensure_acl, ensure_acl_respecting_offer):
        api = _scenario_api(scenario)
        try:
            outcome = ("ok", await fn(api))
        except Exception as err:  # noqa: BLE001 - compare the outcome
            outcome = ("raised", type(err).__name__)
        assert outcome == result, fn.__name__
        assert _seen(api) == (calls, ssh), fn.__name__


@pytest.mark.parametrize("tiers", [[], [TIER_RF_SURVEY, TIER_RF_SCAN]])
async def test_tiered_acl_survives_a_restart_with_one_read(tiers):
    api = acl_api(render_acl(build_acl(tiers)))
    seen = []
    assert await ensure_acl_respecting_offer(api, observe=seen.append) is False
    assert [c.args[1] for c in api._call.await_args_list] == ["read"]
    api._run_ssh.assert_not_awaited()
    assert seen[0].reason == "tiered_kept" and seen[0].known


async def test_observer_error_never_changes_the_result(caplog):
    api = acl_api(V8_TEXT)

    def boom(_outcome):
        raise RuntimeError("observer")

    assert await ensure_acl_respecting_offer(api, observe=boom) is False
    assert "ACL outcome observer failed" in caplog.text


def test_init_and_config_flow_use_the_offer_respecting_variant():
    import inspect

    import custom_components.openwrt_router as init_module

    init_src = inspect.getsource(init_module.async_setup_entry)
    flow_src = inspect.getsource(cf_module)
    assert "ensure_acl_respecting_offer" in init_src
    assert "ensure_acl_respecting_offer" in flow_src
    assert "check_and_deploy_acl(" not in flow_src


# ---------------------------------------------------------------------------
# 3. rf.* capabilities from the deployed ACL
# ---------------------------------------------------------------------------


async def test_rf_unknown_until_the_acl_was_read(disks):
    hass = make_hass()
    await setup_router(hass, FakeEntry("e1"), router_data())
    caps = core_of(hass).registry.get_by_entry("e1").capabilities
    for cap in RF:
        assert caps[cap].state is CapabilityState.UNKNOWN
        assert "not read yet" in caps[cap].reason_text


async def test_rf_from_plain_v8(disks):
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data())
    registry = core_of(hass).registry
    registry.note_deployed_acl(
        "e1",
        observe_deployed_acl(
            AclEnsureOutcome(False, "current", True, RPCD_ACL_CONTENT)
        ),
    )
    coord.poll()
    caps = registry.get_by_entry("e1").capabilities
    assert caps[Capability.RF_SCAN].state is CapabilityState.AVAILABLE
    for cap in (Capability.RF_TXPOWERLIST, Capability.RF_SURVEY):
        assert caps[cap].state is CapabilityState.UNAVAILABLE
        assert caps[cap].reason == CapabilityReason.PERMISSION_DENIED
        assert caps[cap].required_permissions == missing_permissions(
            RPCD_ACL_CONTENT, str(cap)
        )
        assert caps[cap].required_permissions  # names what is missing
    assert coord.router_calls() == []  # no router call for any of this


async def test_rf_unknown_with_reason_when_the_acl_is_unknown(disks):
    hass = make_hass()
    await setup_router(hass, FakeEntry("e1"), router_data())
    registry = core_of(hass).registry
    registry.note_deployed_acl(
        "e1", observe_deployed_acl(None, failure="ensure_failed")
    )
    caps = registry.get_by_entry("e1").capabilities
    for cap in RF:
        assert caps[cap].state is CapabilityState.UNKNOWN
        assert "ensure_failed" in caps[cap].reason_text
    registry.note_deployed_acl(
        "e1", observe_deployed_acl(AclEnsureOutcome(False, "transient", False))
    )
    caps = registry.get_by_entry("e1").capabilities
    assert "transient" in caps[Capability.RF_SURVEY].reason_text


async def test_rf_from_a_tiered_acl(disks):
    hass = make_hass()
    await setup_router(hass, FakeEntry("e1"), router_data())
    registry = core_of(hass).registry
    acl = build_acl([TIER_RF_SURVEY])
    registry.note_deployed_acl(
        "e1",
        observe_deployed_acl(AclEnsureOutcome(False, "tiered_kept", True, acl)),
    )
    caps = registry.get_by_entry("e1").capabilities
    assert caps[Capability.RF_SURVEY].state is CapabilityState.AVAILABLE
    assert caps[Capability.RF_TXPOWERLIST].state is CapabilityState.AVAILABLE
    assert caps[Capability.RF_SCAN].state is CapabilityState.UNAVAILABLE


# ---------------------------------------------------------------------------
# 4. Option config_backup_enabled (default OFF)
# ---------------------------------------------------------------------------


async def test_option_default_off_provider_never_called(disks, tmp_path):
    env = await start_env(disks, tmp_path, options={})
    assert env.provider.calls == []  # not even probed
    caps = _caps(env)
    for name in (Capability.CONFIG_BACKUP, Capability.CONFIG_RESTORE):
        assert caps[name].reason == CapabilityReason.DISABLED
        assert env.api.capability(env.rid, name).reason == CapabilityReason.DISABLED
    with pytest.raises(CapabilityUnavailableError) as err:
        await env.api.async_create_backup(
            env.rid, reason=BackupReason.MANUAL, actor=ADMIN
        )
    assert err.value.reason == "disabled"
    assert env.provider.calls == []
    await stop_env(env)


async def test_option_live_on_and_off(disks, tmp_path):
    env = await start_env(disks, tmp_path, options={})
    entry = env.entries[0]
    assert cf_module._offer_config_backup_option(env.hass, entry.options) is True
    cf_module._apply_config_backup_option(env.hass, entry, True)
    await drain(env.hass)
    assert env.provider.ops("probe") == [("probe", env.rid)]
    made = await env.api.async_create_backup(
        env.rid, reason=BackupReason.MANUAL, actor=ADMIN
    )
    cf_module._apply_config_backup_option(env.hass, entry, False)
    calls = len(env.provider.calls)
    assert _caps(env)[Capability.CONFIG_BACKUP].reason == CapabilityReason.DISABLED
    with pytest.raises(CapabilityUnavailableError):
        await env.api.async_validate_backup(made.record.backup_id)
    assert len(env.provider.calls) == calls  # refused before the provider
    assert env.manager.stats["refused_disabled"] == 1
    assert env.core.registry.stats["config_option_changes"] == 2
    await stop_env(env)


async def test_option_switch_only_offered_with_a_provider(disks, tmp_path):
    env = await start_env(disks, tmp_path, provider=False, options={})
    assert cf_module._offer_config_backup_option(env.hass, {}) is False
    # ... but always while it is on, so it can be switched off again
    assert cf_module._offer_config_backup_option(
        env.hass, {OPTION_CONFIG_BACKUP_ENABLED: True}
    )
    await stop_env(env)


async def test_option_off_refuses_the_config_tier(disks, tmp_path):
    env = await start_env(disks, tmp_path, options={})
    api = acl_api(V8_TEXT)
    env.coords[env.rid].api = api
    with pytest.raises(AclOfferRefusedError) as err:
        await env.api.async_request_acl_deploy(
            env.rid, [TIER_CONFIG_BACKUP_READ], actor=ADMIN
        )
    assert err.value.reason == "option_disabled"
    api._call.assert_not_awaited()
    assert env.core.security.stats["acl_refused_option"] == 1
    await stop_env(env)


# ---------------------------------------------------------------------------
# 2. Core ACL offer deploy through the guard
# ---------------------------------------------------------------------------


def _router_api(read=V8_TEXT):
    api = acl_api(read)
    api.login = AsyncMock(return_value=True)
    api.reset_acl_blocked = MagicMock()
    api.uses_ssh_fallback = False
    return api


async def _acl_env(disks, tmp_path, read=V8_TEXT):
    env = await start_env(disks, tmp_path)
    api = _router_api(read)
    env.coords[env.rid].api = api
    env.core.security.grace_s = 0
    env.core.security.login_retry_s = 0
    env.core.registry.note_deployed_acl(
        env.entries[0].entry_id,
        observe_deployed_acl(
            AclEnsureOutcome(False, "current", True, RPCD_ACL_CONTENT)
        ),
    )
    return env, api


async def test_acl_deploy_guard_approval_deploy_reprobe_audit(disks, tmp_path):
    env, api = await _acl_env(disks, tmp_path)
    assert _caps(env)[Capability.RF_SURVEY].state is CapabilityState.UNAVAILABLE
    probes = len(env.provider.ops("probe"))

    approval = await env.api.async_request_acl_deploy(
        env.rid, [TIER_RF_SURVEY], actor=ADMIN
    )
    offer = env.api.acl_offer(approval.approval_id)
    assert approval.checksum == offer.binding_checksum(env.rid)
    assert any("survey" in r.describe() for r in offer.added)
    # not before approval
    with pytest.raises(ApprovalRequiredError):
        await env.api.async_deploy_acl_offer(approval.approval_id, actor=ADMIN)
    await approve_as(env, approval.approval_id, OTHER_ADMIN_ID)
    result = await env.api.async_deploy_acl_offer(approval.approval_id, actor=ADMIN)
    await drain(env.hass)

    assert result["changed"] and result["transport"] == "ubus"
    assert result["rollback_command"].startswith("cp -p ")
    api.reset_acl_blocked.assert_called()
    api.login.assert_awaited()
    assert _caps(env)[Capability.RF_SURVEY].state is CapabilityState.AVAILABLE
    assert len(env.provider.ops("probe")) == probes + 1  # re-probed
    deployed = env.api.events(
        types=[CoreEventType.ACL_DEPLOYED.value], ring=AuditRing.SECURITY
    )
    assert len(deployed) == 1
    assert deployed[0].data["rollback_command"] == result["rollback_command"]
    assert deployed[0].data["command"] == result["command"]
    api._run_ssh.assert_not_awaited()
    # single use
    with pytest.raises(ApprovalInvalidError):
        await env.api.async_deploy_acl_offer(approval.approval_id, actor=ADMIN)
    await stop_env(env)


async def test_acl_deploy_is_admin_only(disks, tmp_path):
    env, api = await _acl_env(disks, tmp_path)
    with pytest.raises(AuthorizationError):
        await env.api.async_request_acl_deploy(env.rid, [TIER_RF_SCAN], actor=PLAIN)
    api._call.assert_not_awaited()
    await stop_env(env)


async def test_acl_deploy_rejected_request_is_forgotten(disks, tmp_path):
    env, _api = await _acl_env(disks, tmp_path)
    approval = await env.api.async_request_acl_deploy(env.rid, [], actor=ADMIN)
    await env.api.async_reject(approval.approval_id, actor=OTHER_ADMIN)
    assert env.core.security.acl_requests == {}
    with pytest.raises(ApprovalInvalidError):
        env.api.acl_offer(approval.approval_id)
    await stop_env(env)


async def test_acl_deploy_ssh_fallback_only_over_the_pin(disks, tmp_path):
    """ubus write blocked and no confirmed pin: refused, never the shared SSH."""

    def blocked(obj, method, params):
        if method == "read":
            return {"data": V8_TEXT}
        raise OpenWrtMethodNotFoundError("ACL blocks file/write")

    env, api = await _acl_env(disks, tmp_path)
    api._call.side_effect = blocked
    api._closing = False
    api._host = "192.168.1.1"
    api._username = "root"
    api._ssh_use_key = False
    approval = await env.api.async_request_acl_deploy(env.rid, [], actor=ADMIN)
    await approve_as(env, approval.approval_id, OTHER_ADMIN_ID)
    router = FakeRouter(KEY_A, stdout=b"HA_ACL_OFFER_DEPLOYED\n")
    with _patched(router), pytest.raises(AuthorizationError) as err:
        await env.api.async_deploy_acl_offer(approval.approval_id, actor=ADMIN)
    assert err.value.details["reason"] == "ssh_pin_pending"
    # first contact: key read without credentials, no login, no command
    assert router.conns == [] and router.auth_attempts == []
    api._run_ssh.assert_not_awaited()
    failed = bus_events(env.hass, CoreEventType.ACL_DEPLOY_FAILED.value)
    assert failed[-1]["data"]["reason"] == "ssh_pin_pending"
    assert env.core.pins.status(env.rid)["state"] == "pending"
    await stop_env(env)


# ---------------------------------------------------------------------------
# 5. Per-router host-key pin store
# ---------------------------------------------------------------------------


async def _pin_env(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    api = ssh_api()
    env.coords[env.rid].api = api
    return env, api


async def _run(env, router, cmd="uci show"):
    ctx = env.manager._context()
    with _patched(router):
        return await ctx.async_ssh_run_pinned(env.rid, cmd, timeout=5)


async def test_pin_policy_is_one_constant_confirm():
    assert SSH_PIN_FIRST_USE_POLICY == SSH_PIN_POLICY_CONFIRM


async def test_pin_store_is_private_atomic_with_migration(disks, tmp_path):
    env, _api = await _pin_env(disks, tmp_path)
    assert disks.options[SSH_PIN_STORE_KEY] == {"private": True, "atomic_writes": True}
    assert migrate_pin_store(1, 0, {"routers": {}}) == {"routers": {}}
    with pytest.raises(NotImplementedError):
        migrate_pin_store(2, 1, {})
    await stop_env(env)


async def test_first_use_is_pending_not_trusted(disks, tmp_path):
    env, _api = await _pin_env(disks, tmp_path)
    router = FakeRouter(KEY_A)
    with pytest.raises(OpenWrtHostKeyError) as err:
        await _run(env, router)
    assert err.value.reason == "pin_pending"
    # no silent TOFU and (finding 2) no login before the key is confirmed
    assert router.conns == [] and router.auth_attempts == []
    status = env.api.ssh_pin_status(env.rid)
    assert status["state"] == "pending"
    assert status["pending_fingerprint"] == KEY_A.get_fingerprint("sha256")
    assert _count(env, CoreEventType.SSH_PIN_PENDING) == 1
    # Next call refuses BEFORE connecting (no second password login).
    with pytest.raises(OpenWrtHostKeyError):
        await _run(env, router)
    assert len(router.connect_kwargs) == 1
    pending = env.api.events(
        types=[CoreEventType.SSH_PIN_PENDING.value], ring=AuditRing.SECURITY
    )
    assert pending and "192.168" not in json.dumps(pending[0].to_dict())
    await stop_env(env)


async def test_confirm_then_pinned_calls_run(disks, tmp_path):
    env, _api = await _pin_env(disks, tmp_path)
    router = FakeRouter(KEY_A, stdout=b"config\n")
    with pytest.raises(OpenWrtHostKeyError):
        await _run(env, router)
    with pytest.raises(AuthorizationError):  # admin only
        await env.api.async_request_ssh_pin_confirm(env.rid, actor=PLAIN)
    approval = await env.api.async_request_ssh_pin_confirm(env.rid, actor=ADMIN)
    with pytest.raises(ApprovalRequiredError):  # not before approval
        await env.api.async_confirm_ssh_pin(approval.approval_id, actor=ADMIN)
    await approve_as(env, approval.approval_id, OTHER_ADMIN_ID)
    status = await env.api.async_confirm_ssh_pin(approval.approval_id, actor=ADMIN)
    assert status["state"] == "pinned"
    assert _count(env, CoreEventType.SSH_PIN_CONFIRMED) == 1
    result = await _run(env, router)
    assert result.stdout == "config\n" and result.pinned_now is False
    # survives a restart (own store)
    env = await restart(env)
    assert env.api.ssh_pin_status(env.rid)["state"] == "pinned"
    await stop_env(env)


async def test_mismatch_always_refuses_and_is_audited_once(disks, tmp_path):
    env, _api = await _pin_env(disks, tmp_path)
    env.core.pins.policy = SSH_PIN_POLICY_TOFU  # shortcut to a pinned router
    await _run(env, FakeRouter(KEY_A))
    assert env.api.ssh_pin_status(env.rid)["state"] == "pinned"
    impostor = FakeRouter(KEY_B)
    with pytest.raises(OpenWrtHostKeyMismatchError):
        await _run(env, impostor)
    assert impostor.auth_attempts == []  # refused before authentication
    events = env.api.events(
        types=[CoreEventType.SSH_PIN_MISMATCH.value], ring=AuditRing.SECURITY
    )
    assert len(events) == 1
    assert events[0].data["expected_fingerprint"] == KEY_A.get_fingerprint("sha256")
    assert env.api.ssh_pin_status(env.rid)["state"] == "pinned"  # unchanged
    await stop_env(env)


async def test_reset_is_a_critical_action(disks, tmp_path):
    env, _api = await _pin_env(disks, tmp_path)
    with pytest.raises(Exception) as err:
        await env.api.async_request_ssh_pin_reset(env.rid, actor=ADMIN)
    assert err.value.details["reason"] == "no_pin"
    with pytest.raises(OpenWrtHostKeyError):
        await _run(env, FakeRouter(KEY_A))
    approval = await env.api.async_request_ssh_pin_reset(env.rid, actor=ADMIN)
    await approve_as(env, approval.approval_id, OTHER_ADMIN_ID)
    before = await env.api.async_reset_ssh_pin(approval.approval_id, actor=ADMIN)
    assert before["state"] == "pending"
    assert env.api.ssh_pin_status(env.rid)["state"] == "none"
    assert _count(env, CoreEventType.SSH_PIN_RESET) == 1
    await stop_env(env)


def test_provider_context_without_pin_store_refuses():
    ctx = ProviderContext(
        registry=MagicMock(), read=AsyncMock(), installation_key=AsyncMock()
    )
    with pytest.raises(AuthorizationError) as err:
        import asyncio

        asyncio.run(ctx.async_ssh_run_pinned("rtr_x", "true"))
    assert err.value.details["reason"] == "ssh_pin_unavailable"


# ---------------------------------------------------------------------------
# 6. Rulings
# ---------------------------------------------------------------------------


def test_ruling_a_gfs_never_thins_manual_or_pre_versions():
    items = [
        item(date(2026, 11, 16), hour=1),
        item(date(2026, 11, 16), hour=8, reason=BackupReason.PRE_CHANGE),
        item(date(2026, 11, 16), hour=9, reason=BackupReason.MANUAL),
        item(date(2026, 11, 16), hour=22),
    ]
    result = plan(items, gfs(weekly=0, monthly=0))
    assert set(result.deleted) == {V("v2026-11-16T01")}
    for kept in ("v2026-11-16T08", "v2026-11-16T09"):
        assert KeepReason.MANUAL in result.reasons[V(kept)]


def test_ruling_a_size_limit_names_the_manual_versions_it_removes():
    items = [
        item(date(2026, 11, 10), hour=9, reason=BackupReason.MANUAL),
        item(date(2026, 11, 16)),
        item(date(2026, 11, 17)),
    ]
    roomy = plan(items, gfs(weekly=0, monthly=0, max_bytes=2 * KB))
    assert V("v2026-11-10T09") not in roomy.deleted  # manual evicted last
    assert roomy.limit_deleted == (V("v2026-11-16T03"),)
    assert roomy.limit_deleted_manual == ()
    tight = plan(items, gfs(weekly=0, monthly=0, max_bytes=KB))
    assert V("v2026-11-10T09") in tight.limit_deleted_manual
    assert tight.to_dict()["limit_deleted_manual"] == list(tight.limit_deleted_manual)


async def test_ruling_b_dedup_needs_byte_identical_artifacts(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    first = await env.api.async_create_backup(
        env.rid, reason=BackupReason.SCHEDULED, actor=ADMIN
    )
    same = await env.api.async_create_backup(
        env.rid, reason=BackupReason.SCHEDULED, actor=ADMIN
    )
    assert same.created is False  # provider hash and sha256 equal

    def different_bytes(collected):
        changed = {
            kind: payload(p.data + b" ", p.content_type)
            for kind, p in collected.artifacts.items()
        }
        return replace(collected, artifacts=changed)  # same provider hashes

    env.provider.collect_hook = different_bytes
    third = await env.api.async_create_backup(
        env.rid, reason=BackupReason.SCHEDULED, actor=ADMIN
    )
    assert third.created is True
    assert third.record.backup_id != first.record.backup_id
    assert env.versions.stats["dedup_refused_sha256"] == 1
    await stop_env(env)


def test_ruling_b_should_deduplicate_compares_the_core_sha256():
    from test_core_contract_hardening import _meta, _rec

    candidate = _rec(1)  # stored archive sha256 = "a" * 64
    assert should_deduplicate(candidate, _meta(), ["archive"])  # pre-1.44 call
    same = {"archive": "a" * 64}
    other = {"archive": "b" * 64}
    assert should_deduplicate(candidate, _meta(), ["archive"], artifact_sha256=same)
    assert not should_deduplicate(
        candidate, _meta(), ["archive"], artifact_sha256=other
    )
    assert not should_deduplicate(candidate, _meta(), ["archive"], artifact_sha256={})


async def test_ruling_c_entry_removal_archives_versions(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    await env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN)
    root = env.versions._root
    assert os.path.isdir(os.path.join(root, env.rid))
    await async_remove_entry_core(env.hass, env.entries[0])
    assert not os.path.isdir(os.path.join(root, env.rid))
    assert os.path.isdir(os.path.join(root, "removed", env.rid))
    archived = env.api.events(
        types=[CoreEventType.ROUTER_ARCHIVED.value], ring=AuditRing.SECURITY
    )
    assert archived[0].data == {
        "moved": True,
        "target": f"removed/{env.rid}",
        "versions": 1,
    }
    await stop_env(env)


async def test_created_at_is_strictly_monotonic_with_a_frozen_clock(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    frozen = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
    env.versions._clock = lambda: frozen
    ids = []
    for name in ("one", "two", "three"):
        env.provider.live(env.rid)["system"]["@system[0]"]["hostname"] = name
        made = await env.api.async_create_backup(
            env.rid, reason=BackupReason.MANUAL, actor=ADMIN
        )
        ids.append(made.record)
    stamps = [r.created_at for r in ids]
    assert stamps == sorted(stamps) and len(set(stamps)) == 3
    assert env.versions.stats["created_at_adjusted"] >= 2
    history = await env.api.async_list_backups(env.rid)
    assert [r.backup_id for r in history] == [r.backup_id for r in ids[::-1]]
    await stop_env(env)


# ---------------------------------------------------------------------------
# 7. Module docking: Security Center, Network Diagnostics, WiFi RF
# ---------------------------------------------------------------------------


def _status(name, state=CapabilityState.AVAILABLE):
    return CapabilityStatus(
        capability=name,
        state=state,
        reason=CapabilityReason.OK
        if state is CapabilityState.AVAILABLE
        else CapabilityReason.NOT_DETECTED,
        source="module:test",
        detected_at=datetime(2026, 11, 18, tzinfo=UTC),
    )


async def test_e2e_fake_security_center_docks_onto_the_core(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    api = env.api
    coord = env.coords[env.rid]
    runs = []

    def detector(record, data):
        runs.append(record.router_id)
        return {
            "security.firewall_audit": _status("security.firewall_audit"),
            "rf.scan": _status("rf.scan"),  # core-owned: refused
            "diag.ping": _status("diag.ping"),  # other module: refused
            "security.bad": "not a status",  # refused
        }

    api.register_event_prefix("security_center.", module="security_center")
    api.guard.register_action(
        "security_center.block_client",
        ActionClass.CRITICAL,
        module="security_center",
        admin_user_only=True,
    )
    received = []
    unsubscribe = api.subscribe(received.append)
    remove = api.register_capability_detector(
        "security_center", detector, prefix="security."
    )
    coord.poll()
    caps = api.registry.capabilities(env.rid)
    assert caps["security.firewall_audit"].state is CapabilityState.AVAILABLE
    assert caps["rf.scan"].source != "module:test"
    assert "diag.ping" not in caps
    stats = env.core.registry.stats
    assert stats["detector_entries_refused"] == 3
    # runs only when something changed: an identical poll does not run it
    before = len(runs)
    coord.poll()
    assert len(runs) == before

    api.emit(
        "security_center.audit_finished",
        source="security_center",
        router_id=env.rid,
        data={"findings": 0},
    )
    assert [e.type for e in received][-1] == "security_center.audit_finished"
    with pytest.raises(ValueError):
        api.emit("security.fake_core_event", source="security_center")
    unsubscribe()
    remove()
    await stop_env(env)


async def test_detector_namespaces_are_enforced(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    reg = env.api.register_capability_detector
    with pytest.raises(ValueError):
        reg("security_center", lambda r, d: {}, prefix="diag.")
    with pytest.raises(ValueError):
        reg("third_party", lambda r, d: {}, prefix="config.")
    with pytest.raises(ValueError):
        reg("third_party", lambda r, d: {}, prefix="rf.")  # wifi_rf's
    with pytest.raises(ValueError):
        reg("third_party", lambda r, d: {}, prefix="transport.")
    remove = reg("wifi_rf", lambda r, d: {}, prefix="rf.")
    with pytest.raises(ValueError):
        reg("wifi_rf", lambda r, d: {}, prefix="rf.")  # one per module
    remove()
    await stop_env(env)


async def test_failing_detector_never_breaks_the_poll(disks, tmp_path):
    env = await start_env(disks, tmp_path)

    def broken(record, data):
        raise RuntimeError("module bug")

    env.api.register_capability_detector(
        "net_diagnostics", broken, prefix="diag.", signature=lambda data: object()
    )
    coord = env.coords[env.rid]
    coord.poll()
    coord.poll()
    stats = env.core.registry.stats
    assert stats["detector_errors"] >= 1
    assert _caps(env)[Capability.DATA_WIRELESS] is not None  # core caps fine
    await stop_env(env)


async def test_event_prefixes_of_the_three_modules(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    for module in ("security_center", "net_diagnostics", "wifi_rf"):
        env.api.register_event_prefix(f"{module}.", module=module)
    with pytest.raises(ValueError):
        env.api.register_event_prefix("wifi_rf.", module="security_center")
    with pytest.raises(ValueError):
        env.api.register_event_prefix("rf.", module="wifi_rf")  # capability ns
    await stop_env(env)


async def test_core_load_numbers_zero_router_calls_per_poll(disks, tmp_path):
    """Polls, ACL observation, option and detectors: no router call."""
    env = await start_env(disks, tmp_path)
    coord = env.coords[env.rid]
    env.api.register_capability_detector(
        "wifi_rf",
        lambda r, d: {"rf.channel_load": _status("rf.channel_load")},
        prefix="rf.",
    )
    for _ in range(5):
        coord.poll()
    env.core.registry.note_deployed_acl(
        env.entries[0].entry_id,
        observe_deployed_acl(
            AclEnsureOutcome(False, "current", True, RPCD_ACL_CONTENT)
        ),
    )
    await drain(env.hass)
    assert coord.router_calls() == []
    assert env.core.pins.stats["store_writes"] == 0
    await stop_env(env)


@pytest.mark.parametrize("tier", [t.tier_id for t in DEFAULT_TIER_REGISTRY.tiers()])
def test_every_tier_still_builds(tier):
    assert build_acl([tier]) is not None


def test_patch_target_exists():
    with patch(
        "custom_components.openwrt_router.acl_provisioning.ensure_acl_respecting_offer"
    ):
        pass
