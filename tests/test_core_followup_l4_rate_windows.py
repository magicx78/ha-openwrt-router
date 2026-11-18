"""Review L4 of PR #56: rate windows only for routers the core knows.

B5 kept one rate window per (action, router_id) and dropped the oldest
above ``MAX_RATE_WINDOWS``. A caller could invent router ids, fill the
table and push out the window of a real router, so its limit started
again. Now the guard takes ``router_known`` (the core passes the registry
lookup); a rate limited ACTIVE action for a router id that is neither known
nor the fleet id ``-`` is DENIED with reason ``unknown_router``
(``REASON_UNKNOWN_ROUTER``), audited on the security ring under ``-`` (the
invented id is never echoed), counted (``rate_unknown_router``), and no
window is created. Without ``router_known`` only the fleet id is known
(fail closed). Actions without a rate limit are unchanged.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import FakeDisks, add_users, make_hass

from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_errors import AuthorizationError
from custom_components.openwrt_router.core_guard import (
    MAX_RATE_WINDOWS,
    REASON_RATE_LIMITED,
    REASON_UNKNOWN_ROUTER,
    ActionGuard,
    error_for_decision,
)
from custom_components.openwrt_router.core_models import (
    FLEET_ROUTER_ID,
    ActionClass,
    Actor,
    AuditRing,
    CoreEventType,
    DecisionState,
    RateLimit,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry

R1 = router_id_for_entry("e1")
R2 = router_id_for_entry("e2")
MOD = "net_diagnostics"
SCAN = f"{MOD}.scan"
PING = f"{MOD}.ping"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 18, 10, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _guard(router_known=None, clock: Clock | None = None):
    hass = make_hass()
    add_users(hass)
    audit = AuditLog(hass)
    await audit.async_load()
    kwargs = {} if router_known is None else {"router_known": router_known}
    guard = ActionGuard(hass, audit, clock=clock or Clock(), **kwargs)
    guard.register_action(
        SCAN,
        ActionClass.ACTIVE,
        module=MOD,
        rate_limit=RateLimit(max_calls=1, per=timedelta(minutes=5)),
    )
    guard.register_action(PING, ActionClass.ACTIVE, module=MOD)  # no limit
    module = await guard.async_verify_actor(Actor.for_module(MOD))
    return audit, guard, module


def _invented() -> str:
    return "rtr_" + secrets.token_hex(16)


def test_reason_constant():
    assert REASON_UNKNOWN_ROUTER == "unknown_router"


async def test_invented_ids_create_no_windows(disks):
    audit, guard, module = await _guard(lambda rid: rid in {R1, R2})
    assert guard.authorize(SCAN, R1, module).approved
    assert guard.authorize(SCAN, R1, module).reason == REASON_RATE_LIMITED
    flood = [_invented() for _ in range(MAX_RATE_WINDOWS + 50)]
    for rid in flood:
        decision = guard.authorize(SCAN, rid, module)
        assert decision.state is DecisionState.DENIED
        assert decision.reason == REASON_UNKNOWN_ROUTER
        assert decision.authorization is None
        assert decision.router_id == FLEET_ROUTER_ID  # never echoed
    assert len(guard._calls) == 1  # only R1's window
    assert guard.stats["rate_windows_dropped"] == 0
    assert guard.stats["rate_unknown_router"] == len(flood)
    # R1's limit still holds; R2 still gets its own window
    assert guard.authorize(SCAN, R1, module).reason == REASON_RATE_LIMITED
    assert guard.authorize(SCAN, R2, module).approved
    assert len(guard._calls) == 2
    # the refusal is a defined error, audited on the security ring under "-"
    err = error_for_decision(guard.authorize(SCAN, flood[0], module))
    assert isinstance(err, AuthorizationError)
    assert err.details["reason"] == REASON_UNKNOWN_ROUTER and err.details["audit_id"]
    denials = [
        e
        for e in audit.events(
            types=[CoreEventType.AUTHORIZATION_DENIED.value], ring=AuditRing.SECURITY
        )
        if e.data.get("reason") == REASON_UNKNOWN_ROUTER
    ]
    assert denials
    assert {d.router_id for d in denials} == {FLEET_ROUTER_ID}
    assert not any(rid in str(d.to_dict()) for d in denials for rid in flood[:20])


async def test_fleet_id_is_known_and_limited(disks):
    _audit, guard, module = await _guard(lambda rid: False)
    assert guard.authorize(SCAN, FLEET_ROUTER_ID, module).approved
    limited = guard.authorize(SCAN, FLEET_ROUTER_ID, module)
    assert limited.reason == REASON_RATE_LIMITED


async def test_without_router_known_only_the_fleet(disks):
    _audit, guard, module = await _guard()
    assert guard.authorize(SCAN, R1, module).reason == REASON_UNKNOWN_ROUTER
    assert guard.authorize(SCAN, FLEET_ROUTER_ID, module).approved
    assert list(guard._calls) == [(SCAN, FLEET_ROUTER_ID)]


async def test_failing_lookup_fails_closed(disks):
    def broken(_rid: str) -> bool:
        raise RuntimeError("registry gone")

    _audit, guard, module = await _guard(broken)
    assert guard.authorize(SCAN, R1, module).reason == REASON_UNKNOWN_ROUTER
    assert guard._calls == {}


async def test_actions_without_limit_unchanged(disks):
    _audit, guard, module = await _guard(lambda rid: False)
    assert guard.authorize(PING, _invented(), module).approved
    assert guard._calls == {}
    assert guard.stats["rate_unknown_router"] == 0


async def test_core_wires_the_registry(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.api.guard.register_action(
        SCAN,
        ActionClass.ACTIVE,
        module=MOD,
        rate_limit=RateLimit(max_calls=1, per=timedelta(minutes=5)),
    )
    module = await env.api.guard.async_verify_actor(Actor.for_module(MOD))
    assert env.api.guard.authorize(SCAN, env.rid, module).approved
    invented = env.api.guard.authorize(SCAN, _invented(), module)
    assert invented.reason == REASON_UNKNOWN_ROUTER
    assert env.api.guard.authorize(SCAN, env.rid, module).reason == REASON_RATE_LIMITED
    await stop_env(env)
