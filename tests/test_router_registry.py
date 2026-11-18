"""Enterprise core part 1: router registry (contract §4)."""

from __future__ import annotations

import pytest
from core_testkit import (
    ADMIN_ID,
    MAC_A,
    MAC_B,
    USER_ID,
    FakeDisks,
    FakeEntry,
    add_users,
    bus_events,
    core_of,
    make_hass,
    router_data,
    setup_router,
    user_actor,
)

from custom_components.openwrt_router.core_errors import (
    AuthorizationError,
    RouterIdentityError,
    RouterNotFoundError,
)
from custom_components.openwrt_router.core_guard import raise_for_decision
from custom_components.openwrt_router.core_models import (
    ROUTER_REGISTRY_STORE_KEY,
    Actor,
    AuditRing,
    CoreEventType,
    GuardedAction,
    IdentityStatus,
    ReachabilityState,
    RecordState,
    RouterRegistryProtocol,
    RouterRole,
    _mint_write_authorization,
    binding_checksum,
)
from custom_components.openwrt_router.enterprise_core import (
    async_remove_entry_core,
    async_setup_entry_core,
    async_unload_entry_core,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry
from custom_components.openwrt_router.router_registry import (
    migrate_registry_store,
    record_from_dict,
)

ADMIN = Actor.system("test")


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _adopt_auth(hass, entry_id: str, orphan_id: str, **kw):
    """An authorization issued by the core's guard (bound as given)."""
    add_users(hass)
    action = kw.pop("action", GuardedAction.ADOPT)
    actor = ADMIN if action is GuardedAction.PRUNE else user_actor(ADMIN_ID)
    guard = core_of(hass).guard
    verified = await guard.async_verify_actor(actor)
    return raise_for_decision(
        guard.authorize(
            action,
            kw.pop("router_id", orphan_id),
            verified,
            checksum=kw.pop("checksum", binding_checksum(entry_id, orphan_id)),
        )
    )


async def _orphan_of(hass, entry: FakeEntry, data) -> str:
    """Set up ``entry``, then remove it: returns the orphaned router id."""
    await setup_router(hass, entry, data)
    rid = core_of(hass).registry.get_by_entry(entry.entry_id).router_id
    hass.entries.remove(entry)
    await async_remove_entry_core(hass, entry)
    return rid


async def test_registry_implements_the_protocol(disks: FakeDisks) -> None:
    hass = make_hass()
    await setup_router(hass, FakeEntry("e1"), router_data())
    assert isinstance(core_of(hass).registry, RouterRegistryProtocol)


async def test_id_is_assigned_before_any_router_contact(disks: FakeDisks) -> None:
    hass = make_hass()
    entry = FakeEntry("e1")
    hass.entries.append(entry)
    record = await async_setup_entry_core(hass, entry)  # no coordinator yet
    assert record.router_id == router_id_for_entry("e1")
    assert record.identity.status is IdentityStatus.UNVERIFIED
    assert record.reachability.state is ReachabilityState.UNKNOWN
    events = bus_events(hass, CoreEventType.ROUTER_REGISTERED.value)
    assert [e["router_id"] for e in events] == [record.router_id]


async def test_poll_fills_identity_without_router_calls(disks: FakeDisks) -> None:
    hass = make_hass()
    hass.devices["e1"] = "dev-1"
    coord = await setup_router(hass, FakeEntry("e1"), router_data())
    for _ in range(20):
        coord.poll()
    record = core_of(hass).registry.get_by_entry("e1")
    ident = record.identity
    assert ident.status is IdentityStatus.CONFIRMED
    assert ident.device_id == "dev-1"
    assert ident.board_name == "glinet,gl-mt3000"
    assert ident.fingerprint.macs == frozenset(MAC_A)
    assert ident.role is RouterRole.GATEWAY
    assert record.firmware.package_manager == "apk"
    assert record.reachability.state is ReachabilityState.ONLINE
    assert coord.router_calls() == []  # zero new router calls
    stats = core_of(hass).registry.stats
    assert stats["listener_errors"] == 0
    assert stats["identity_evaluations"] == 1  # signature unchanged afterwards


async def test_listener_error_never_reaches_the_coordinator(disks: FakeDisks) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data())
    coord.data = object()  # nonsense data must not raise out of the listener
    coord.poll()
    coord.data = None
    coord.poll()
    assert core_of(hass).registry.get_by_entry("e1").state is RecordState.ACTIVE


async def test_remove_orphans_and_keeps_the_record(disks: FakeDisks) -> None:
    hass = make_hass()
    await setup_router(hass, FakeEntry("keep"), router_data(macs=MAC_B))
    rid = await _orphan_of(hass, FakeEntry("gone", host="192.168.1.9"), router_data())
    registry = core_of(hass).registry
    record = registry.get(rid)
    assert record.state is RecordState.ORPHANED
    assert record.entry_id is None
    assert record.identity.entry_id == "gone"  # last binding kept
    assert rid not in {r.router_id for r in registry.list()}
    assert rid in {r.router_id for r in registry.list(include_orphaned=True)}
    assert not registry.has_capability(rid, "data.wireless")
    with pytest.raises(RouterNotFoundError):
        registry.get_by_entry("gone")
    events = bus_events(hass, CoreEventType.ROUTER_ORPHANED.value)
    assert events[-1]["data"] == {"reason": "entry_removed"}


async def test_remove_last_entry_orphans_via_a_temporary_core(disks: FakeDisks) -> None:
    hass = make_hass()
    entry = FakeEntry("only")
    await setup_router(hass, entry, router_data())
    await async_unload_entry_core(hass, entry)
    await entry.run_on_unload()
    hass.entries.remove(entry)
    await async_remove_entry_core(hass, entry)
    saved = disks[ROUTER_REGISTRY_STORE_KEY].data["data"]["routers"]
    (record,) = saved.values()
    assert record["state"] == "orphaned"


async def test_adoption_candidates_and_authorized_adoption(disks: FakeDisks) -> None:
    hass = make_hass()
    orphan_id = await _orphan_of(hass, FakeEntry("old"), router_data())
    # the same device comes back as a new entry
    await setup_router(hass, FakeEntry("new", host="192.168.1.5"), router_data())
    registry = core_of(hass).registry
    new_default = registry.get_by_entry("new").router_id
    (cand,) = registry.adoption_candidates("new")
    assert cand.router_id == orphan_id
    assert cand.matched_macs == frozenset(MAC_A)
    assert cand.board_match and cand.model_match

    adopted = await registry.async_adopt_authorized(
        "new", orphan_id, authorization=await _adopt_auth(hass, "new", orphan_id)
    )
    assert adopted.router_id == orphan_id
    assert adopted.state is RecordState.ACTIVE
    assert adopted.entry_id == "new"
    assert adopted.previous_entry_ids == ("old",)
    assert adopted.adopted_at is not None
    assert registry.get_by_entry("new").router_id == orphan_id
    # the entry's own default record is orphaned, never merged
    assert registry.get(new_default).state is RecordState.ORPHANED
    (event,) = core_of(hass).audit.events(types=[CoreEventType.ROUTER_ADOPTED])
    assert event.audit_ring is AuditRing.SECURITY
    assert event.data["replaced_router_id"] == new_default
    # saved right away
    saved = disks[ROUTER_REGISTRY_STORE_KEY].data["data"]["routers"]
    assert saved[orphan_id]["state"] == "active"


async def test_adoption_needs_a_matching_authorization(disks: FakeDisks) -> None:
    hass = make_hass()
    orphan_id = await _orphan_of(hass, FakeEntry("old"), router_data())
    await setup_router(hass, FakeEntry("new"), router_data())
    registry = core_of(hass).registry
    wrong = await _adopt_auth(hass, "other-entry", orphan_id)  # bound to another entry
    with pytest.raises(AuthorizationError) as err:
        await registry.async_adopt_authorized("new", orphan_id, authorization=wrong)
    assert err.value.details["reason"] == "checksum_mismatch"
    assert wrong.consumed
    with pytest.raises(AuthorizationError) as err:  # single use, also when failed
        await registry.async_adopt_authorized("new", orphan_id, authorization=wrong)
    assert err.value.details["reason"] == "already_used"
    other_action = await _adopt_auth(hass, "new", orphan_id, action=GuardedAction.PRUNE)
    with pytest.raises(AuthorizationError) as err:
        await registry.async_adopt_authorized(
            "new", orphan_id, authorization=other_action
        )
    assert err.value.details["reason"] == "action_mismatch"
    assert registry.get(orphan_id).state is RecordState.ORPHANED  # nothing changed
    good = await _adopt_auth(hass, "new", orphan_id)
    await registry.async_adopt_authorized("new", orphan_id, authorization=good)
    assert registry.get(orphan_id).state is RecordState.ACTIVE
    denied = core_of(hass).audit.events(types=[CoreEventType.AUTHORIZATION_DENIED])
    assert len(denied) >= 1


async def test_adopt_without_guard_is_denied(disks: FakeDisks) -> None:
    hass = make_hass()
    orphan_id = await _orphan_of(hass, FakeEntry("old"), router_data())
    await setup_router(hass, FakeEntry("new"), router_data())
    registry = core_of(hass).registry
    registry.set_adopt_authorizer(None)  # the core wires the guard; unwire it
    with pytest.raises(AuthorizationError) as err:
        await registry.async_adopt("new", orphan_id, actor=ADMIN)
    assert err.value.details["reason"] == "guard_unavailable"


async def test_adopt_through_the_guard_needs_a_verified_admin_user(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    add_users(hass)
    orphan_id = await _orphan_of(hass, FakeEntry("old"), router_data())
    await setup_router(hass, FakeEntry("new"), router_data())
    registry = core_of(hass).registry
    for actor in (ADMIN, user_actor(USER_ID, claims_admin=True)):
        with pytest.raises(AuthorizationError) as err:
            await registry.async_adopt("new", orphan_id, actor=actor)
        assert err.value.details["reason"] in {"system_only", "not_admin"}
    assert registry.get(orphan_id).state is RecordState.ORPHANED
    adopted = await registry.async_adopt("new", orphan_id, actor=user_actor(ADMIN_ID))
    assert adopted.router_id == orphan_id
    guard = core_of(hass).guard
    assert guard.stats["consumed"] == 1
    denied = core_of(hass).audit.events(
        types=[CoreEventType.AUTHORIZATION_DENIED], ring=AuditRing.SECURITY
    )
    assert len(denied) == 2


async def test_adopt_refuses_an_authorization_the_guard_never_issued(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    orphan_id = await _orphan_of(hass, FakeEntry("old"), router_data())
    await setup_router(hass, FakeEntry("new"), router_data())
    registry = core_of(hass).registry
    forged = _mint_write_authorization(
        action=GuardedAction.ADOPT,
        router_id=orphan_id,
        actor=ADMIN,
        checksum=binding_checksum("new", orphan_id),
    )
    with pytest.raises(AuthorizationError) as err:
        await registry.async_adopt_authorized("new", orphan_id, authorization=forged)
    assert err.value.details["reason"] == "unknown_authorization"
    assert registry.get(orphan_id).state is RecordState.ORPHANED


async def test_only_orphans_can_be_adopted(disks: FakeDisks) -> None:
    hass = make_hass()
    await setup_router(hass, FakeEntry("a"), router_data())
    await setup_router(hass, FakeEntry("b"), router_data(macs=MAC_B))
    registry = core_of(hass).registry
    active = registry.get_by_entry("a").router_id
    with pytest.raises(RouterIdentityError):
        await registry.async_adopt_authorized(
            "b", active, authorization=await _adopt_auth(hass, "b", active)
        )


async def test_restored_entry_reactivates_its_orphan(disks: FakeDisks) -> None:
    hass = make_hass()
    entry = FakeEntry("e1")
    rid = await _orphan_of(hass, FakeEntry("other"), router_data(macs=MAC_B))
    rid = await _orphan_of(hass, entry, router_data())
    hass.entries.append(entry)  # HA backup restored the entry
    record = await async_setup_entry_core(hass, entry)
    assert record.router_id == rid
    assert record.state is RecordState.ACTIVE


async def test_store_round_trip(disks: FakeDisks) -> None:
    hass = make_hass()
    await setup_router(hass, FakeEntry("e1"), router_data())
    registry = core_of(hass).registry
    record = registry.get_by_entry("e1")
    await registry.async_flush()
    raw = disks[ROUTER_REGISTRY_STORE_KEY].data["data"]["routers"][record.router_id]
    again = record_from_dict(raw)
    assert again.to_dict() == record.to_dict()


async def test_steady_polls_do_not_write_the_store(disks: FakeDisks) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data())
    registry = core_of(hass).registry
    disks.flush_delayed()
    scheduled = registry.stats["store_saves_scheduled"]
    for _ in range(100):
        coord.poll()
    disks.flush_delayed()
    assert registry.stats["store_saves_scheduled"] == scheduled
    coord.poll(success=False)  # online -> offline is a state change
    assert registry.stats["store_saves_scheduled"] == scheduled + 1


def test_registry_store_migration() -> None:
    assert migrate_registry_store(1, 0, {}) == {"routers": {}}
    with pytest.raises(NotImplementedError):
        migrate_registry_store(2, 0, {"routers": {}})
