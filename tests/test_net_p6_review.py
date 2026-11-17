"""Regression tests for the P6 review (network intelligence).

The reviewer's probes, inverted: a blind log never yields score 100 (E11,
L1), a restored "unavailable" keeps maintenance on (L3), an open child
counts and fires once its root's after-window has passed (E8, K1), and a
router failing on its credentials holds no announcement (M1). Also: the
silent unload (E9, M3), fleet incidents only in the fleet entities (E10,
L4), the explicit ``cause_inherited`` flag (L2), "opened" before any
"reopened" (L5) and the fleet entities' registry move at the start of an
unload (M2). Router names are roles.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from test_net_correlation import T0, A, B, G, inc_of, level, observed_tree
from test_net_engine import FakeDisk, FakeStore, make_hass
from test_net_entities import G as EG
from test_net_entities import engine, loaded_registry, setup_all  # noqa: F401
from test_net_p6 import (  # noqa: F401
    SETTLE,
    clock,
    fired,
    full,
    intel,
    open_of,
    reconnects,
    states,
    step,
    timers,
    wan,
)

from custom_components.openwrt_router import net_engine
from custom_components.openwrt_router import net_entities as ne
from custom_components.openwrt_router.const import (
    DOMAIN,
    ERROR_TYPE_AUTH,
    NOTIFICATION_FAILURE_THRESHOLD,
    UID_FLEET_INCIDENT_CRITICAL,
    UID_FLEET_INCIDENTS_ACTIVE,
    UID_FLEET_NET_HEALTH,
)
from custom_components.openwrt_router.net_engine import NetIntelligence, area_inputs
from custom_components.openwrt_router.net_events import (
    CauseStatus,
    Incident,
    IncidentStatus,
    Scope,
    Severity,
)
from custom_components.openwrt_router.net_query import router_badges
from custom_components.openwrt_router.net_rules import (
    CHILD_RELEASE_AFTER,
    AlarmMachine,
    child_release_time,
    counted_incidents,
    counts_for_router,
    merge_settings,
    router_score,
    suppressed_child,
)

AFTER = 180.0  # router_unreachable after-window (_ROOT_WINDOWS)


# --- E11 / L1: no score 100 from a blind log ----------------------------------------


def blind_data(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "ap_interfaces": [{"ifname": "phy0-ap0"}],
        "clients": [],  # coordinator default, no reading
        "log_status": "unavailable",  # no WLAN detector sees anything
        "uptime": 1000,
        "cpu_load": 0.0,
        "memory_pressure": {},  # stats unusable
        "service_instances": None,
        "localtime": None,
        "port_stats": [{"name": "lan1"}],
        "wan_status": {},
        "dhcp_pools": [],
        "dhcp_leases": {},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_blind_log_and_unknown_memory_give_no_score_100() -> None:
    """Reviewer probe: was score 100 at coverage 0.64."""
    areas = area_inputs(blind_data(), fresh=True, gateway=False)
    assert areas["system"].fresh == 2  # reachable + cpu, memory {} unread
    assert areas["wifi"].fresh == 0  # E11: no log, no WLAN area
    score = router_score("r", areas, [], merge_settings(None))
    assert score.score != 100


def test_wifi_area_needs_the_log_even_with_clients() -> None:
    data = blind_data(clients=[{"mac": "02:00:00:00:00:01"}])
    assert area_inputs(data, fresh=True, gateway=False)["wifi"].fresh == 0
    data = blind_data(clients=[{"mac": "02:00:00:00:00:01"}], log_status="ok")
    areas = area_inputs(data, fresh=True, gateway=False)
    assert areas["wifi"].fresh == areas["wifi"].total == 2


def test_empty_client_list_is_no_reading() -> None:
    areas = area_inputs(blind_data(log_status="ok"), fresh=True, gateway=False)
    assert areas["wifi"].fresh == 1  # the log only


# --- L3: restore only on/off ---------------------------------------------------------


@pytest.mark.parametrize("last", ["unavailable", "unknown"])
async def test_restore_of_a_non_state_keeps_the_stored_maintenance(
    engine: NetIntelligence,  # noqa: F811
    last: str,
) -> None:
    [switch] = [
        e for e in setup_all(engine, EG) if e.unique_id.endswith("_maintenance_mode")
    ]
    engine.set_maintenance(EG, True)  # stored: on
    switch.async_get_last_state = AsyncMock(return_value=SimpleNamespace(state=last))
    with (
        patch.object(ne, "async_dispatcher_connect"),
        patch("homeassistant.helpers.restore_state.RestoreEntity.async_added_to_hass"),
    ):
        await switch.async_added_to_hass()
    assert engine.router_maintenance(EG) is True


# --- E8 / K1: a child counts again after its root's after-window --------------------


def live(m: AlarmMachine, key: str) -> Incident:
    """The machine's own router_unreachable incident (``inc_of`` copies)."""
    [inc] = [
        i for i in m.peek() if i.type == "router_unreachable" and i.scope_key == key
    ]
    return inc


def test_open_child_counts_once_the_root_window_has_passed() -> None:
    """gw away T0..T0+300, ap2 behind it away from T0+10 and stays away."""
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", G, since=T0)])
    m.update(T0 + 10, [level("router_unreachable", B, since=T0 + 10)])
    m.correlate(T0 + 10, observed_tree())
    gw, ap2 = live(m, G), live(m, B)
    assert ap2.parent_id == gw.id
    m.update(
        T0 + 300,
        [level("router_unreachable", G, value=0), level("router_unreachable", B)],
    )
    assert gw.status is IncidentStatus.RESOLVED
    end = gw.resolved_at + AFTER
    t = end + 60
    m.update(t, [level("router_unreachable", B)])
    m.correlate(t, observed_tree())
    assert ap2.status is IncidentStatus.ACTIVE
    assert ap2.parent_id == gw.id  # stays for the history
    assert ap2 not in counted_incidents(m.peek())  # no clock: silent
    assert ap2 not in counted_incidents(m.peek(), end - 1)
    assert ap2 in counted_incidents(m.peek(), end)
    known = {i.id: i for i in m.peek()}
    assert child_release_time(ap2, known) == end
    assert child_release_time(gw, known) is None
    assert suppressed_child(ap2, known, end - 1)
    assert not suppressed_child(ap2, known, end)


def test_child_of_an_open_root_has_no_release_time() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", G, since=T0)])
    m.update(T0 + 10, [level("router_unreachable", B, since=T0 + 10)])
    m.correlate(T0 + 10, observed_tree())
    ap2 = inc_of(m, "router_unreachable", B)
    known = {i.id: i for i in m.peek()}
    assert child_release_time(ap2, known) is None
    assert suppressed_child(ap2, known, T0 + 10_000)


async def test_released_child_fires_opened_after_the_window_not_an_hour_late(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    """Reviewer probe: ap2 fired "opened" only ~1 h after gw came back."""
    intel.register(B)
    with patch.object(intel, "_build_topology", lambda now: observed_tree()):
        step(intel, T0, level("router_unreachable", G, since=T0))
        step(intel, T0 + 10, level("router_unreachable", B, since=T0 + 10))
        step(
            intel,
            T0 + 20,
            level("router_unreachable", G),
            level("router_unreachable", B),
        )
        step(
            intel,
            T0 + 200,
            level("router_unreachable", G),
            level("router_unreachable", B),
        )
        step(
            intel,
            T0 + 300,
            level("router_unreachable", G, value=0),
            level("router_unreachable", B),
        )
        gw = live(intel.machine, G)
        end = gw.resolved_at + AFTER
        opened_at: float | None = None
        t = T0 + 300
        while t < T0 + 300 + CHILD_RELEASE_AFTER:
            t += 30
            step(intel, t, level("router_unreachable", B))
            if t < end:
                assert intel.view.routers[B].incidents_active == 0, t
            if opened_at is None and any(
                s == "opened" and i != gw.id for s, _t, i in states(intel)
            ):
                opened_at = t
    assert intel.view.routers[B].incidents_active == 1
    assert opened_at is not None
    assert end + SETTLE <= opened_at <= end + SETTLE + 60


async def test_release_time_arms_the_timer(
    intel: NetIntelligence,  # noqa: F811
    timers: Any,  # noqa: F811
) -> None:
    intel.register(B)
    with patch.object(intel, "_build_topology", lambda now: observed_tree()):
        step(intel, T0, level("router_unreachable", G, since=T0))
        step(intel, T0 + 10, level("router_unreachable", B, since=T0 + 10))
        step(
            intel,
            T0 + 400,
            level("router_unreachable", G, value=0),
            level("router_unreachable", B),
        )
    gw = live(intel.machine, G)
    [(delay, _action, _cancel)] = timers.live
    assert delay == pytest.approx(gw.resolved_at + AFTER - (T0 + 400) + 1.0)


# --- M1: an auth failure is no outage, the late band ends ----------------------------


def auth_down(router: str) -> SimpleNamespace:
    outage = SimpleNamespace(error_type=ERROR_TYPE_AUTH, reported=True)
    return SimpleNamespace(
        snapshot=lambda: SimpleNamespace(fleet_since=None, down={router: outage})
    )


async def test_auth_failed_router_holds_no_announcement(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    intel._outages = auth_down(A)
    intel._seen[A] = (T0 - 100, 60.0)  # missed its poll: late without M1
    step(intel, T0, wan())
    step(intel, T0 + SETTLE, wan())
    assert [e["state"] for e in fired(intel)] == ["opened"]


async def test_late_band_ends_after_the_failure_threshold(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    band = (NOTIFICATION_FAILURE_THRESHOLD + 1) * 60.0
    intel._seen[A] = (T0 - 100, 60.0)
    assert intel._late(T0)
    assert intel._late(T0 - 100 + band)
    assert not intel._late(T0 - 100 + band + 1)
    intel._seen[A] = (T0 - band - 1, 60.0)  # stuck longer: holds nothing
    step(intel, T0, wan())
    step(intel, T0 + SETTLE, wan())
    assert [e["state"] for e in fired(intel)] == ["opened"]


# --- E9 / M3: unload resolves silently -----------------------------------------------


async def test_unload_resolves_the_outage_silently(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    step(intel, T0, level("router_unreachable", A, since=T0))
    step(intel, T0 + SETTLE, level("router_unreachable", A))
    assert [s for s, _t, _i in states(intel)] == ["opened"]
    intel.unregister(A)
    [inc] = [i for i in intel.machine.peek() if i.type == "router_unreachable"]
    assert inc.status is IncidentStatus.RESOLVED
    step(intel, T0 + SETTLE + 600)
    assert [s for s, _t, _i in states(intel)] == ["opened"]  # no "resolved"
    assert inc.id not in intel._announced


# --- E10 / L4: fleet incidents count in the fleet entities only -----------------------


def lan_down() -> Incident:
    return Incident(
        id="lan_unreachable:fleet",
        type="lan_unreachable",
        scope=Scope.FLEET,
        scope_key="fleet",
        status=IncidentStatus.ACTIVE,
        severity=Severity.CRITICAL,
        confidence=1.0,
        routers=[G, A],
    )


def test_fleet_incident_counts_for_no_router() -> None:
    inc = lan_down()
    assert not counts_for_router(inc, G)
    assert router_badges([inc], T0) == {}
    assert inc in counted_incidents([inc], T0)


async def test_fleet_incident_leaves_router_counters(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    step(intel, T0)
    intel.machine._incidents[lan_down().id] = lan_down()
    step(intel, T0 + 10)
    assert intel.view.routers[G].incidents_active == 0
    assert not intel.view.routers[G].critical
    assert intel.view.fleet.incidents_active == 1
    assert intel.view.fleet.critical


# --- L2: explicit cause_inherited ----------------------------------------------------


async def test_link_marks_the_inherited_cause(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    step(intel, T0, *reconnects(5))
    step(intel, T0 + 60, level("router_unreachable", A, since=T0 - 30))
    [storm] = [i for i in intel.machine.peek() if i.type == "wifi_reconnect_storm"]
    assert storm.parent_id is not None and storm.cause_inherited
    assert storm.to_dict()["cause_inherited"] is True


def test_own_cause_equal_to_the_parent_cause_is_kept() -> None:
    """Old guess: the same cause as the parent counted as inherited."""
    m = AlarmMachine()
    parent = Incident(
        id="p",
        type="router_unreachable",
        scope=Scope.ROUTER,
        scope_key=A,
        status=IncidentStatus.RESOLVED,
        severity=Severity.WARNING,
        confidence=1.0,
        cause="x",
        cause_status=CauseStatus.CONFIRMED,
        routers=[A],
    )
    child = Incident(
        id="c",
        type="wifi_reconnect_storm",
        scope=Scope.CLIENT,
        scope_key="02:00:5E:10:00:01",
        status=IncidentStatus.ACTIVE,
        severity=Severity.WARNING,
        confidence=1.0,
        parent_id="p",
        cause="x",
        cause_status=CauseStatus.CONFIRMED,
        routers=[A],
    )
    m._incidents = {"p": parent, "c": child}
    m._release(child, drop_cause=True)
    assert child.cause == "x" and child.cause_status is CauseStatus.CONFIRMED


def test_legacy_store_guesses_the_flag_once() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", G, since=T0)])
    m.update(T0 + 10, [level("router_unreachable", B, since=T0 + 10)])
    m.correlate(T0 + 10, observed_tree())
    data = m.to_dict()
    for inc in data["incidents"]:
        inc.pop("cause_inherited", None)  # stored before L2
    restored = AlarmMachine.from_dict(data)
    ap2 = inc_of(restored, "router_unreachable", B)
    gw = inc_of(restored, "router_unreachable", G)
    assert ap2.cause_inherited is (ap2.cause is not None)
    assert gw.cause_inherited is False


# --- L5: "opened" before any "reopened" ----------------------------------------------


async def test_reopen_of_a_never_announced_incident_fires_opened(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    step(intel, T0, wan())
    step(intel, T0 + 60, wan(0.0))  # resolved before the settle time
    step(intel, T0 + 120, wan())  # reopened within the cooldown
    [inc] = open_of(intel, "wan_down")
    assert inc.reopen_count == 1
    step(intel, T0 + 120 + SETTLE, wan())
    assert states(intel) == [("opened", "wan_down", inc.id)]
    step(intel, T0 + 600, wan(0.0))
    step(intel, T0 + 660, wan())
    step(intel, T0 + 660 + SETTLE, wan())
    assert [s for s, _t, _i in states(intel)] == ["opened", "resolved", "reopened"]


async def test_opened_set_is_stored_and_old_stores_fall_back(clock: Any) -> None:  # noqa: F811
    disk = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        first = NetIntelligence(make_hass())
        await first.async_load()
        first.register(G)
        step(first, T0, wan())
        step(first, T0 + SETTLE, wan())
        [inc] = open_of(first, "wan_down")
        assert first._payload()["opened"] == [inc.id]
        await first.async_flush()
        second = NetIntelligence(make_hass())
        await second.async_load()
    assert second._opened == {inc.id}
    second.register(G)
    step(second, T0 + 300, wan(0.0))
    step(second, T0 + 360, wan())
    step(second, T0 + 360 + SETTLE, wan())
    assert [e["state"] for e in fired(second)] == ["resolved", "reopened"]


# --- M2: fleet entities move at the start of the unload ------------------------------


async def test_withdraw_picks_the_successor_and_create_waits_for_unregister(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    made: list[tuple[str, str]] = []
    intel.claim_fleet("sensor", A, lambda: made.append(("sensor", A)))
    intel.claim_fleet("sensor", G, lambda: made.append(("sensor", G)))
    assert intel.withdraw_fleet(A) == G
    assert intel.fleet_anchor == G
    assert made == [("sensor", A)]  # old entities still live
    intel.unregister(A)
    assert made == [("sensor", A), ("sensor", G)]
    assert intel.withdraw_fleet(G) is None  # the last one: nothing moves
    assert intel.fleet_anchor is None


async def test_withdraw_of_a_non_anchor_drops_its_claim_only(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    intel.claim_fleet("sensor", A, lambda: None)
    intel.claim_fleet("sensor", G, lambda: None)
    assert intel.withdraw_fleet(G) is None
    assert intel.fleet_anchor == A
    assert intel.withdraw_fleet(A) is None  # G withdrew: no successor


async def test_withdraw_of_the_last_router_moves_nothing(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    intel.claim_fleet("sensor", A, lambda: None)
    assert intel.withdraw_fleet(A) is None
    assert intel.fleet_anchor is None


def config_entry(entry_id: str) -> MagicMock:
    e = MagicMock()
    e.entry_id = entry_id
    e.domain = DOMAIN
    e.disabled_by = None
    e.pref_disable_new_entities = False
    return e


async def test_unload_start_rehomes_the_fleet_registry_entries(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    """M2: the registry entries move before the old platforms unload."""
    hass = engine.hass
    old, new = config_entry(EG), config_entry("01JAPENTRY000000000000000AP")
    hass.config_entries.async_get_entry.side_effect = {
        old.entry_id: old,
        new.entry_id: new,
    }.get
    registry = await loaded_registry(hass)
    ids = [
        registry.async_get_or_create(domain, DOMAIN, uid, config_entry=old).entity_id
        for domain, uid in (
            ("sensor", UID_FLEET_NET_HEALTH),
            ("sensor", UID_FLEET_INCIDENTS_ACTIVE),
            ("binary_sensor", UID_FLEET_INCIDENT_CRITICAL),
        )
    ]
    made: list[str] = []
    engine.claim_fleet("sensor", old.entry_id, lambda: made.append("old"))
    engine.claim_fleet("sensor", new.entry_id, lambda: made.append("new"))
    with patch.object(ne.er, "async_get", return_value=registry):
        ne.async_withdraw_fleet(hass, old.entry_id)
    assert [registry.async_get(i).config_entry_id for i in ids] == [new.entry_id] * 3
    assert made == ["old"]
    engine.unregister(old.entry_id)
    assert made == ["old", "new"]


async def test_withdraw_without_engine_or_move_does_nothing(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    with patch.object(ne.er, "async_get") as get:
        ne.async_withdraw_fleet(engine.hass, EG)  # never claimed: no move
        engine.hass.data.pop(net_engine._DATA_KEY)
        ne.async_withdraw_fleet(engine.hass, EG)
    get.assert_not_called()


async def test_unload_entry_withdraws_before_the_platforms() -> None:
    """Order in async_unload_entry (no full HA harness: the calls are
    recorded on mocks)."""
    from custom_components.openwrt_router import async_unload_entry

    order: list[str] = []
    hass = MagicMock()
    hass.data = {}

    async def unload_platforms(*_a: Any) -> bool:
        order.append("platforms")
        return True

    hass.config_entries.async_unload_platforms = unload_platforms
    entry = MagicMock()
    entry.entry_id = EG
    entry.data = {}
    entry.runtime_data = None
    with (
        patch.object(ne, "async_withdraw_fleet", lambda *_a: order.append("withdraw")),
        patch(
            "custom_components.openwrt_router.async_unload_net_intelligence",
            AsyncMock(side_effect=lambda *_a: order.append("intel")),
        ),
        patch(
            "custom_components.openwrt_router.topology_panel.async_teardown_topology_panel",
            AsyncMock(),
        ),
    ):
        assert await async_unload_entry(hass, entry) is True
    assert order == ["withdraw", "platforms", "intel"]


# --- L6: the timer is re-armed only when its time changes ----------------------------


async def test_timer_kept_when_the_due_time_is_unchanged(
    intel: NetIntelligence,  # noqa: F811
    timers: Any,  # noqa: F811
) -> None:
    step(intel, T0, wan())
    step(intel, T0 + 10, wan())  # same settle end: no new timer
    assert len(timers.calls) == 1 and len(timers.live) == 1
    intel.close()
    assert timers.live == []
