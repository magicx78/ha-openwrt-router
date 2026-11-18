"""Follow-up B5: guard class ``active`` and admin-only sensitive reads.

* ``ActionClass.ACTIVE`` ("active, not modifying": scan, ping, survey):
  users must be verified admins; module, system and automation actors are
  allowed; never an approval. A grant mints an authorization like any other
  and is audited as ``core.active_action_granted`` on the GENERAL ring.
* Optional ``rate_limit=RateLimit(max_calls=..., per=...)`` per
  (action, router_id), only for active actions. Over the limit: DENIED,
  reason ``rate_limited``, ``decision.retry_after``, audited as
  ``core.action_rate_limited`` (general ring, one entry per window and
  action, repeats counted), counter ``rate_limited``;
  ``error_for_decision`` gives ``RateLimitedError``.
* ``register_action(..., sensitive_read=True)`` for a READ: a user must be
  a verified admin (denial audited on the security ring); module, system
  and automation actors read as before. ``admin_user_only`` keeps its
  meaning (only an admin USER).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import (
    ADMIN_ID,
    USER_ID,
    FakeDisks,
    add_users,
    make_hass,
    user_actor,
)

from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_errors import (
    AuthorizationError,
    RateLimitedError,
)
from custom_components.openwrt_router.core_guard import (
    REASON_RATE_LIMITED,
    ActionGuard,
    error_for_decision,
    raise_for_decision,
)
from custom_components.openwrt_router.core_models import (
    ActionClass,
    Actor,
    ActorKind,
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
LEASES = f"{MOD}.read_leases"


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 11, 18, 10, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _guard(clock: Clock | None = None):
    hass = make_hass()
    add_users(hass)
    audit = AuditLog(hass)
    await audit.async_load()
    # review L4: rate windows only for known routers
    guard = ActionGuard(
        hass, audit, clock=clock or Clock(), router_known=lambda rid: rid in {R1, R2}
    )
    return hass, audit, guard


async def _actors(guard: ActionGuard) -> dict[str, object]:
    now = guard.now()
    return {
        "admin": await guard.async_verify_actor(user_actor(ADMIN_ID)),
        "user": await guard.async_verify_actor(user_actor(USER_ID)),
        "module": await guard.async_verify_actor(Actor.for_module(MOD)),
        "system": await guard.async_verify_actor(Actor.system()),
        "automation": await guard.async_verify_actor(
            Actor(kind=ActorKind.AUTOMATION, context_id="ctx-1")
        ),
        "_now": now,
    }


def _types(audit: AuditLog, ring: AuditRing) -> list[str]:
    return [e.type for e in audit.events(ring=ring)]


async def test_active_policy_and_ring(disks):
    _hass, audit, guard = await _guard()
    guard.register_action(SCAN, ActionClass.ACTIVE, module=MOD)
    actors = await _actors(guard)
    for name in ("admin", "module", "system", "automation"):
        decision = guard.authorize(SCAN, R1, actors[name])
        assert decision.state is DecisionState.APPROVED, name
        assert decision.authorization is not None
        assert decision.approval_request is None
    denied = guard.authorize(SCAN, R1, actors["user"])
    assert denied.state is DecisionState.DENIED and denied.reason == "not_admin"
    general = _types(audit, AuditRing.GENERAL)
    assert general.count(CoreEventType.ACTIVE_ACTION_GRANTED.value) == 4
    security = _types(audit, AuditRing.SECURITY)
    assert CoreEventType.AUTHORIZATION_GRANTED.value not in security
    assert security == [CoreEventType.AUTHORIZATION_DENIED.value]
    assert guard.stats["active_granted"] == 4
    granted = next(
        e
        for e in audit.events(ring=AuditRing.GENERAL)
        if e.type == CoreEventType.ACTIVE_ACTION_GRANTED.value
    )
    assert granted.data["action"] == SCAN
    assert granted.data["authorization_id"].startswith("wau_")


async def test_rate_limit(disks):
    clock = Clock()
    _hass, audit, guard = await _guard(clock)
    guard.register_action(
        SCAN,
        ActionClass.ACTIVE,
        module=MOD,
        rate_limit=RateLimit(max_calls=2, per=timedelta(minutes=1)),
    )
    actors = await _actors(guard)
    module = actors["module"]
    assert guard.authorize(SCAN, R1, module).approved
    clock.now += timedelta(seconds=20)
    assert guard.authorize(SCAN, R1, module).approved
    clock.now += timedelta(seconds=10)
    limited = guard.authorize(SCAN, R1, module)
    assert limited.state is DecisionState.DENIED
    assert limited.reason == REASON_RATE_LIMITED == "rate_limited"
    assert limited.retry_after == pytest.approx(30.0)
    assert limited.authorization is None
    assert limited.audit_id
    assert limited.to_dict()["retry_after"] == pytest.approx(30.0)
    err = error_for_decision(limited)
    assert isinstance(err, RateLimitedError)
    assert err.retry_after == pytest.approx(30.0) and err.retryable
    assert err.details["reason"] == "rate_limited"
    with pytest.raises(RateLimitedError):
        raise_for_decision(limited)
    # the limit is per router: R2 is free
    assert guard.authorize(SCAN, R2, module).approved
    # repeats inside the window: one general entry, counted
    again = guard.authorize(SCAN, R1, actors["admin"])
    assert again.reason == "rate_limited"
    assert guard.stats["rate_limited"] == 2
    limited_events = [
        e
        for e in audit.events(ring=AuditRing.GENERAL)
        if e.type == CoreEventType.ACTION_RATE_LIMITED.value
    ]
    assert len(limited_events) == 1 and limited_events[0].repeat_count == 1
    assert CoreEventType.ACTION_RATE_LIMITED.value not in _types(
        audit, AuditRing.SECURITY
    )
    # after the window the action is allowed again
    clock.now += timedelta(seconds=31)
    module = await guard.async_verify_actor(Actor.for_module(MOD))  # fresh
    assert guard.authorize(SCAN, R1, module).approved


async def test_rate_limit_counts_only_grants(disks):
    clock = Clock()
    _hass, _audit, guard = await _guard(clock)
    guard.register_action(
        SCAN,
        ActionClass.ACTIVE,
        module=MOD,
        rate_limit=RateLimit(max_calls=1, per=timedelta(minutes=1)),
    )
    actors = await _actors(guard)
    for _ in range(3):
        assert guard.authorize(SCAN, R1, actors["user"]).reason == "not_admin"
    assert guard.authorize(SCAN, R1, actors["module"]).approved


async def test_sensitive_read(disks):
    _hass, audit, guard = await _guard()
    guard.register_action(LEASES, ActionClass.READ, module=MOD, sensitive_read=True)
    actors = await _actors(guard)
    for name in ("admin", "module", "system", "automation"):
        assert guard.authorize(LEASES, R1, actors[name]).approved, name
        assert guard.denial_reason(LEASES, actors[name]) is None
    assert guard.denial_reason(LEASES, actors["user"]) == "not_admin"
    denied = guard.authorize(LEASES, R1, actors["user"])
    assert denied.reason == "not_admin"
    assert isinstance(error_for_decision(denied), AuthorizationError)
    assert CoreEventType.AUTHORIZATION_DENIED.value in _types(audit, AuditRing.SECURITY)
    # a plain read stays open to everyone
    guard.register_action(f"{MOD}.status", ActionClass.READ, module=MOD)
    assert guard.authorize(f"{MOD}.status", R1, actors["user"]).approved


async def test_registration_rules(disks):
    _hass, _audit, guard = await _guard()
    limit = RateLimit(max_calls=1, per=timedelta(seconds=10))
    with pytest.raises(ValueError):  # rate limit only for active actions
        guard.register_action(
            f"{MOD}.x", ActionClass.MUTATING, module=MOD, rate_limit=limit
        )
    with pytest.raises(ValueError):  # sensitive_read only for reads
        guard.register_action(
            f"{MOD}.y", ActionClass.ACTIVE, module=MOD, sensitive_read=True
        )
    with pytest.raises(TypeError):
        guard.register_action(
            f"{MOD}.z", ActionClass.ACTIVE, module=MOD, rate_limit=(1, 10)
        )
    guard.register_action(SCAN, ActionClass.ACTIVE, module=MOD, rate_limit=limit)
    guard.register_action(SCAN, ActionClass.ACTIVE, module=MOD, rate_limit=limit)
    with pytest.raises(ValueError):  # a different limit is a different definition
        guard.register_action(
            SCAN,
            ActionClass.ACTIVE,
            module=MOD,
            rate_limit=RateLimit(max_calls=2, per=timedelta(seconds=10)),
        )


@pytest.mark.parametrize(
    ("max_calls", "per"),
    [
        (0, timedelta(seconds=1)),
        (1, timedelta(0)),
        (True, timedelta(seconds=1)),
        (1, 10),
        (100_001, timedelta(seconds=1)),
        (1, timedelta(days=2)),
    ],
)
def test_rate_limit_validation(max_calls, per):
    with pytest.raises((TypeError, ValueError)):
        RateLimit(max_calls=max_calls, per=per)


async def test_api_surface(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.api.guard.register_action(
        SCAN,
        ActionClass.ACTIVE,
        module=MOD,
        rate_limit=RateLimit(max_calls=1, per=timedelta(minutes=5)),
    )
    env.api.guard.register_action(
        LEASES, ActionClass.READ, module=MOD, sensitive_read=True
    )
    module = await env.api.guard.async_verify_actor(Actor.for_module(MOD))
    assert env.api.guard.authorize(SCAN, env.rid, module).approved
    assert env.api.guard.authorize(SCAN, env.rid, module).reason == "rate_limited"
    assert ActionClass("active") is ActionClass.ACTIVE
    await stop_env(env)
