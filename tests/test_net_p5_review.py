"""Tests for the P5 review of the correlation (network intelligence).

The seven reviewer probes, inverted to the expected behaviour, and one test
or more per finding: a router outage takes over what happens behind it only
while that router is away itself (E5, K1), children are released after
their root (E6, K2), unloaded routers resolve their outage (E7), radio
changes confirm only their own radio (M1), a router's own problems from
before its outage stay roots (M2), remembered topology edges age (M3),
``correlate`` stays fast (M4), a root never links its own events (L1) and
new links are saved (L2). Router names are roles, MACs locally administered
test values, IPs from TEST-NET.
"""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Any
from unittest.mock import MagicMock, patch

from test_net_correlation import (
    AP_TRUNK,
    CLIENTS20,
    GW_TRUNK,
    HOST,
    T0,
    A,
    B,
    G,
    clock,  # noqa: F401  (fixture)
    dt,
    event,
    feed,
    fleet,  # noqa: F401  (fixture)
    gw_poll,
    hit,
    inc_of,
    level,
    observed_tree,
    port,
    rdata,
    storm,
)

from custom_components.openwrt_router.const import ERROR_TYPE_TIMEOUT
from custom_components.openwrt_router.net_events import (
    Category,
    CauseStatus,
    Incident,
    IncidentStatus,
    NetEvent,
    Scope,
    prune_incidents,
)
from custom_components.openwrt_router.net_rules import (
    CHILD_RELEASE_AFTER,
    LAN_UNREACHABLE_KEY,
    LAN_UNREACHABLE_KIND,
    TOPOLOGY_MEMORY,
    AlarmMachine,
    Evidence,
    RouterLinks,
    Topology,
    TransitionState,
    Uplink,
    build_topology,
    counted_incidents,
)

# a router outage ends its window 180 s after the resolve
OUTAGE_AFTER = 180.0


def cpu(router: str, value: float = 95.0) -> Evidence:
    return level("system_cpu_high", router, value=value)


def outage_with_cpu_child(m: AlarmMachine) -> tuple[Incident, Incident]:
    """ap1 away T0..T0+60; its CPU high from T0+100 links to the outage."""
    m.update(T0, [level("router_unreachable", A, since=T0)])
    m.update(T0 + 60, [level("router_unreachable", A, value=0)])
    for i in range(3):
        m.update(T0 + 100 + 60 * i, [cpu(A)])
    m.correlate(T0 + 220, Topology())
    root = inc_of(m, "router_unreachable", A)
    child = inc_of(m, "system_cpu_high", A)
    assert child.parent_id == root.id
    return root, child


# --- the reviewer probes, inverted --------------------------------------------------


def test_probe1_gateway_management_outage_takes_nothing_of_reachable_aps() -> None:
    """K1: gw unreachable from HA (rpcd hung), ap2 polled fine: a fault on
    ap2 two hours later is its own root."""
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", G, since=T0)])
    t = T0 + 7200
    m.update(t, [storm(CLIENTS20[0], B)])
    for i in range(3):
        m.update(t + 60 * i, [cpu(B)])
    m.correlate(t + 120, observed_tree())
    assert inc_of(m, "router_unreachable", G).status is IncidentStatus.ACTIVE
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[0]).parent_id is None
    assert inc_of(m, "system_cpu_high", B).parent_id is None


def test_probe2_persisting_child_is_released_after_its_root() -> None:
    """K2: a CPU problem that outlasts the outage by weeks is released and
    then a root of its own (never a child of a pruned parent)."""
    m = AlarmMachine()
    root, _child = outage_with_cpu_child(m)
    t = T0 + 220
    while t < T0 + 31 * 86400:
        t += 240
        m.update(t, [cpu(A)])
    m.correlate(t, Topology())
    child = inc_of(m, "system_cpu_high", A)
    assert child.status is IncidentStatus.ACTIVE
    assert child.parent_id is None
    assert child.cause_status is not CauseStatus.CONFIRMED
    assert root.id not in {i.id for i in m.incidents()}  # pruned by now


def test_probe3_reopened_child_drops_its_old_parent() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", A, since=T0)])
    m.update(T0 + 30, [storm(CLIENTS20[0], A)])
    m.correlate(T0 + 30, Topology())
    m.update(T0 + 60, [level("router_unreachable", A, value=0)])
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[0]).parent_id is not None
    t = T0 + 30
    for _ in range(200):
        t += 60
        m.update(t, [])
        storm_inc = inc_of(m, "wifi_reconnect_storm", CLIENTS20[0])
        if storm_inc.status is IncidentStatus.RESOLVED:
            break
    t += 600  # inside the cooldown: a reopen
    m.update(t, [storm(CLIENTS20[0], A)])
    m.correlate(t, Topology())
    storm_inc = inc_of(m, "wifi_reconnect_storm", CLIENTS20[0])
    assert storm_inc.reopen_count == 1 and storm_inc.reopened_at == t
    assert storm_inc.parent_id is None
    # the inherited cause is gone; the new evidence brought its own
    assert (storm_inc.cause, storm_inc.cause_status) == (
        "weak_signal",
        CauseStatus.HYPOTHESIS,
    )
    assert inc_of(m, "router_unreachable", A).children == 0


def lan_evidence(event_id: str | None = None) -> Evidence:
    return Evidence(
        type="lan_unreachable",
        scope_key=LAN_UNREACHABLE_KEY,
        scope=Scope.FLEET,
        kind=LAN_UNREACHABLE_KIND,
        event_id=event_id,
        value=1.0,
        cause="lan_unreachable",
        cause_status=CauseStatus.CONFIRMED,
        since=T0 if event_id else None,
    )


def test_probe4_lan_root_never_links_its_own_event() -> None:
    """L1: after 20 more steps its evidence list no longer holds the event
    id; the kind still marks the event as its own."""
    m = AlarmMachine()
    m.update(T0, [lan_evidence("fleet:1")])
    own = NetEvent(
        id="fleet:1",
        ts=T0,
        router="fleet",
        category=Category.SYSTEM,
        kind=LAN_UNREACHABLE_KIND,
    )
    assert m.correlate(T0, Topology(), [own]).events == {}
    for i in range(1, 22):
        m.update(T0 + 10 * i, [lan_evidence()])
    assert m.correlate(T0 + 220, Topology(), [own]).events == {}
    # an event of another router in the window is still a follow-up
    other = event("ap1:5", T0 + 100, A, "wifi.disconnect", Category.WIFI)
    lan = inc_of(m, "lan_unreachable", LAN_UNREACHABLE_KEY)
    assert m.correlate(T0 + 220, Topology(), [own, other]).events == {"ap1:5": lan.id}


def test_probe5_remembered_edge_is_not_observed() -> None:
    links = {
        G: RouterLinks(frozenset({"10.0.0.1"}), "10.0.0.1", gateway=True),
        A: RouterLinks(frozenset({"10.0.0.2"}), "10.0.0.2"),
    }
    prev = {A: Uplink(G, "lan3", "lan1", True)}
    topo = build_topology(links, prev)
    assert topo.uplinks[A].observed is False
    assert topo.uplinks[A].remembered is True


def test_probe6_lldp_of_a_nas_is_no_edge() -> None:
    links = {
        G: RouterLinks(
            frozenset({"10.0.0.1", "aa:aa:aa:aa:aa:01"}),
            "10.0.0.1",
            lldp=(
                {
                    "local_interface": "lan4",
                    "chassis_id": "bb:bb:bb:bb:bb:bb",
                    "management_ip": "10.0.0.50",
                    "capabilities": ["Router"],
                },
            ),
            gateway=True,
        ),
        A: RouterLinks(frozenset({"10.0.0.2"}), "10.0.0.2"),
    }
    assert build_topology(links).uplinks == {}


def perf_machine() -> tuple[AlarmMachine, float, Topology, list[NetEvent]]:
    """300 mass-disconnect roots over 30 days on 6 routers, 190 open storms,
    one open outage, 3000 events."""
    m = AlarmMachine()
    routers = ["gw", "ap2", "ap3", "ap4", "ap5", "ap6"]
    t = T0
    for i in range(300):
        t = T0 + i * 8000
        m.update(t, [hit("wifi_mass_disconnect", routers[i % 6], routers[i % 6])])
    now = t + 100
    for i in range(190):
        mac = f"02:00:5E:30:{i // 256:02X}:{i % 256:02X}"
        m.update(now, [storm(mac, routers[i % 6])])
    m.update(now, [level("router_unreachable", "ap2", since=now)])
    events = [
        NetEvent(
            id=f"e{i}",
            ts=T0 + i * 800,
            router=routers[i % 6],
            category=Category.WIFI,
            kind="wifi.disconnect",
            subject={"mac": "02:00:5e:00:00:01"},
        )
        for i in range(3000)
    ]
    topo = Topology(
        {
            "ap2": Uplink("gw", "lan2", "lan1", True),
            "ap3": Uplink("ap2", "lan3", "lan1", True),
            "ap5": Uplink("ap2", "lan4", "lan1", True),
            "ap6": Uplink("ap2", "lan5", "lan1", True),
            "ap4": Uplink("gw", "lan3", "lan1", True),
        },
        frozenset({"gw"}),
    )
    return m, now, topo, events


def correlate_ms(m: AlarmMachine, now: float, topo: Topology, events: Any) -> float:
    """Best of five batches of ten calls, per call in ms."""
    m.correlate(now, topo, events)
    best = float("inf")
    for _ in range(5):
        start = time.perf_counter()
        for _ in range(10):
            m.correlate(now, topo, events)
        best = min(best, (time.perf_counter() - start) / 10)
    return best * 1000


def test_probe7_correlate_stays_under_10_ms() -> None:
    """M4: 301 roots, 490 incidents and 3000 events."""
    m, now, topo, events = perf_machine()
    assert len(m.incidents()) == 491
    assert correlate_ms(m, now, topo, events) < 10.0


# --- E5 / K1: behind a router outage only routers that are away themselves ----------


def test_router_behind_counts_only_during_its_own_outage() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", G, since=T0)])
    # ap2 (behind ap1 behind gw) away T0+2000 .. T0+2100
    m.update(T0 + 2000, [level("router_unreachable", B, since=T0 + 2000)])
    m.update(T0 + 2030, [storm(CLIENTS20[0], B)])
    m.update(T0 + 2100, [level("router_unreachable", B, value=0)])
    events = [
        event("ap2:1", T0 + 1000, B, "wifi.disconnect", Category.WIFI),
        event("ap2:2", T0 + 2050, B, "wifi.disconnect", Category.WIFI),
        event("ap2:3", T0 + 3000, B, "wifi.disconnect", Category.WIFI),
    ]
    result = m.correlate(T0 + 3000, observed_tree(), events)
    gw = inc_of(m, "router_unreachable", G)
    ap2 = inc_of(m, "router_unreachable", B)
    assert ap2.parent_id == gw.id  # its outage overlaps the gateway's
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[0]).parent_id == ap2.id
    # reachable before and after its outage: no follow-up of the gateway
    assert "ap2:1" not in result.events and "ap2:3" not in result.events
    assert result.events["ap2:2"] == ap2.id


def test_reboot_takes_the_routers_behind_it_along() -> None:
    """A reboot of the gateway drops the APs behind it briefly; they need
    no outage of their own (its window is short)."""
    m = AlarmMachine()
    m.update(T0, [hit("system_reboot", G, G)])
    m.update(T0 + 60, [storm(CLIENTS20[0], B)])
    m.correlate(T0 + 60, observed_tree())
    child = inc_of(m, "wifi_reconnect_storm", CLIENTS20[0])
    assert child.parent_id == inc_of(m, "system_reboot", G).id
    m.update(T0 + 400, [storm(CLIENTS20[1], B)])  # after the window
    m.correlate(T0 + 400, observed_tree())
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[1]).parent_id is None


# --- E6 / K2: release of children ------------------------------------------------------


def test_open_child_is_released_after_window_plus_an_hour() -> None:
    m = AlarmMachine()
    root, child = outage_with_cpu_child(m)
    limit = root.resolved_at + OUTAGE_AFTER + CHILD_RELEASE_AFTER
    t = T0 + 220
    while t + 240 < limit:  # the CPU stays high
        t += 240
        m.update(t, [cpu(A)])
    m.update(limit, [cpu(A)])
    assert not m.correlate(limit, Topology()).released
    assert inc_of(m, "system_cpu_high", A).parent_id == root.id
    m.update(limit + 60, [cpu(A)])
    result = m.correlate(limit + 60, Topology())
    assert result.released == (child.id,) and bool(result)
    released = inc_of(m, "system_cpu_high", A)
    assert released.parent_id is None
    assert (released.cause, released.cause_status) == (
        "router_unreachable",
        CauseStatus.HYPOTHESIS,
    )
    assert inc_of(m, "router_unreachable", A).children == 0
    assert counted_incidents(m.peek()) == [m.peek()[1]]  # a root of its own now
    # not linked again to the expired root
    m.update(limit + 120, [cpu(A)])
    m.correlate(limit + 120, Topology())
    assert inc_of(m, "system_cpu_high", A).parent_id is None


def test_resolved_child_keeps_its_link() -> None:
    m = AlarmMachine()
    root, _child = outage_with_cpu_child(m)
    m.update(T0 + 400, [cpu(A, value=10)])  # clears
    far = T0 + 10 * 3600
    m.update(far, [])
    m.correlate(far, Topology())
    child = inc_of(m, "system_cpu_high", A)
    assert child.status is IncidentStatus.RESOLVED
    assert child.parent_id == root.id  # history stays


def test_confirmed_own_cause_survives_the_release() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", A, since=T0)])
    own = hit(
        "wifi_reconnect_storm",
        CLIENTS20[0],
        A,
        scope=Scope.CLIENT,
        count=5,
        cause="weak_signal",
        status=CauseStatus.CONFIRMED,
    )
    m.update(T0 + 30, [own])
    m.correlate(T0 + 30, Topology())
    m.update(T0 + 60, [level("router_unreachable", A, value=0)])
    t = T0 + 60 + OUTAGE_AFTER + CHILD_RELEASE_AFTER + 1
    m.update(t, [own])  # still storming
    m.correlate(t, Topology())
    child = inc_of(m, "wifi_reconnect_storm", CLIENTS20[0])
    assert child.parent_id is None
    assert (child.cause, child.cause_status) == ("weak_signal", CauseStatus.CONFIRMED)


def test_orphaned_parent_is_cleared_on_load_prune_and_remove() -> None:
    m = AlarmMachine()
    root, _child = outage_with_cpu_child(m)
    # load: the parent is missing from the store
    data = m.to_dict(compact=True)
    data["incidents"] = [i for i in data["incidents"] if i["id"] != root.id]
    loaded = AlarmMachine.from_dict(data)
    restored = inc_of(loaded, "system_cpu_high", A)
    assert restored.parent_id is None
    assert restored.cause_status is CauseStatus.HYPOTHESIS
    # prune: the resolved parent ages out, the open child stays
    m2 = AlarmMachine.from_dict(m.to_dict(), max_incidents=1)
    m2.update(T0 + 400, [cpu(A)])
    assert [i.type for i in m2.incidents()] == ["system_cpu_high"]
    assert m2.incidents()[0].parent_id is None
    # remove: the root's router goes, a child of another router stays
    m3 = AlarmMachine()
    m3.update(T0, [level("router_unreachable", A, since=T0)])
    m3.update(T0 + 60, [level("router_unreachable", B, since=T0 + 10)])
    m3.correlate(T0 + 60, observed_tree())
    assert inc_of(m3, "router_unreachable", B).parent_id is not None
    m3.remove_router(A)
    assert inc_of(m3, "router_unreachable", B).parent_id is None


def test_prune_incidents_alone_keeps_parent_ids() -> None:
    """The pure helper only selects; the machine clears orphans after it."""
    parent = Incident(
        id="p",
        type="router_unreachable",
        scope=Scope.ROUTER,
        scope_key=A,
        status=IncidentStatus.RESOLVED,
        last_seen=T0,
        resolved_at=T0,
    )
    child = Incident(
        id="c", type="system_cpu_high", scope=Scope.ROUTER, scope_key=A, parent_id="p"
    )
    kept = prune_incidents([parent, child], T0 + 40 * 86400)
    assert kept == [child] and child.parent_id == "p"


# --- E7: unloaded or removed routers ----------------------------------------------------


def test_resolve_router_resolves_only_its_open_outage() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", A, since=T0)])
    m.update(T0, [level("router_unreachable", B, since=T0)])
    [tr] = m.resolve_router(A, T0 + 30)
    assert tr.state is TransitionState.RESOLVED and tr.reason == "router_removed"
    assert inc_of(m, "router_unreachable", A).resolved_at == T0 + 30
    assert inc_of(m, "router_unreachable", B).status is IncidentStatus.ACTIVE
    assert m.resolve_router(A, T0 + 40) == []  # nothing open any more
    assert m.resolve_router(G, T0 + 40) == []


async def test_removed_router_drops_its_outage(fleet: Any) -> None:  # noqa: F811
    f = fleet
    feed(f, A, T0, rdata(A))
    f.clock.now = T0 + 200
    f.h.tracker.report_down(A, ERROR_TYPE_TIMEOUT, dt(T0 + 60))
    f.h.fire_timer()
    f.h.tracker.unregister(A)
    assert f.intel.remove_router(A)
    assert not [i for i in f.intel.machine.incidents() if i.scope_key == A]


# --- M1: radio change -----------------------------------------------------------------


def radio_root(m: AlarmMachine, at: float) -> None:
    m.update(at, [hit("wifi_radio_change", f"{A}:radio:phy1", A, scope=Scope.RADIO)])


def mass_event(eid: str, ts: float, *ifaces: str) -> NetEvent:
    return event(eid, ts, A, "wifi.mass_disconnect", Category.WIFI, {"ifaces": ifaces})


def test_radio_change_confirms_only_a_mass_disconnect_on_its_radio() -> None:
    for ifaces, expected in (
        (("phy1-ap0",), CauseStatus.CONFIRMED),
        (("phy0-ap0",), CauseStatus.HYPOTHESIS),  # another radio
        ((), CauseStatus.HYPOTHESIS),  # radio unknown
    ):
        m = AlarmMachine()
        radio_root(m, T0)
        m.update(T0 + 20, [hit("wifi_mass_disconnect", A, A, count=8, event_id="m1")])
        events = [mass_event("m1", T0 + 20, *ifaces)] if ifaces else []
        m.correlate(T0 + 20, Topology(), events)
        mass = inc_of(m, "wifi_mass_disconnect", A)
        assert mass.parent_id == inc_of(m, "wifi_radio_change", f"{A}:radio:phy1").id
        assert mass.cause_status is expected, ifaces


def test_radio_change_window_does_not_slide() -> None:
    """Changes at T0 and T0+500 (one incident): a disconnect between them is
    outside both ±60 s windows."""
    m = AlarmMachine()
    radio_root(m, T0)
    m.update(T0 + 250, [hit("wifi_mass_disconnect", A, A, count=8)])
    radio_root(m, T0 + 500)
    m.correlate(T0 + 500, Topology())
    radio = inc_of(m, "wifi_radio_change", f"{A}:radio:phy1")
    assert radio.status is IncidentStatus.ACTIVE and radio.last_seen == T0 + 500
    assert inc_of(m, "wifi_mass_disconnect", A).parent_id is None
    m2 = AlarmMachine()
    radio_root(m2, T0)
    radio_root(m2, T0 + 500)
    m2.update(T0 + 530, [hit("wifi_mass_disconnect", A, A, count=8)])
    m2.correlate(T0 + 530, Topology())
    assert inc_of(m2, "wifi_mass_disconnect", A).parent_id is not None


# --- M3: topology memory ---------------------------------------------------------------


def test_remembered_edge_ages_out_and_gives_no_fresh_port() -> None:
    links = {
        G: RouterLinks(frozenset({HOST[G]}), HOST[G], gateway=True),
        A: RouterLinks(frozenset({HOST[A]}), HOST[A]),
    }
    fresh = build_topology(
        {**links, G: replace(links[G], trunk={HOST[A]: "lan3"})},
        None,
        T0,
    )
    assert fresh.uplinks[A].seen == T0 and not fresh.uplinks[A].remembered
    assert fresh.ports_of(G, remembered=False) == {"lan3"}
    kept = build_topology(links, fresh.uplinks, T0 + TOPOLOGY_MEMORY)
    assert kept.uplinks[A].remembered and kept.uplinks[A].seen == T0
    assert kept.ports_of(G) == {"lan3"}  # still known for the correlation
    assert kept.ports_of(G, remembered=False) == frozenset()
    assert build_topology(links, kept.uplinks, T0 + TOPOLOGY_MEMORY + 1).uplinks == {}


async def test_stale_topology_port_opens_no_uplink_down(fleet: Any) -> None:  # noqa: F811
    """The AP left the gateway's FDB a day ago: its port is no uplink any
    more, a link down there is a plain port event."""
    f = fleet
    no_ap = {k: v for k, v in GW_TRUNK.items() if k != HOST[A]}

    def poll(t: float, lan3: bool = True) -> None:
        ports = (port("lan3", lan3), port("lan4"))
        feed(f, G, t, rdata(G, ports=ports, trunk=no_ap))

    gw_poll(f, T0)
    feed(f, A, T0 + 20, rdata(A, trunk=AP_TRUNK))
    gw_poll(f, T0 + 60)
    assert f.intel._topology.uplinks[A].parent == G
    for t in (T0 + 120, T0 + 43200, T0 + 86400 + 120):
        poll(t)  # the AP left the FDB; the gateway polls on
    assert "lan3" not in f.intel._topology.ports_of(G)
    poll(T0 + 86400 + 300, lan3=False)
    poll(T0 + 86400 + 360, lan3=False)
    assert not [i for i in f.intel.machine.incidents() if i.type == "lan_uplink_down"]
    assert not [e for e in f.intel.ring if e.kind == "lan.uplink"]


# --- L2: new links are saved -----------------------------------------------------------


async def test_new_links_schedule_a_save(fleet: Any) -> None:  # noqa: F811
    f = fleet
    feed(f, A, T0, rdata(A))
    f.clock.now = T0 + 200
    f.h.tracker.report_down(A, ERROR_TYPE_TIMEOUT, dt(T0 + 60))
    f.h.fire_timer()
    with patch.object(f.intel, "schedule_save", MagicMock()) as save:
        f.intel._run_machine(T0 + 210, [storm(CLIENTS20[0], A)])
        save.assert_called()
    child = inc_of(f.intel.machine, "wifi_reconnect_storm", CLIENTS20[0])
    assert child.parent_id == inc_of(f.intel.machine, "router_unreachable", A).id
    with patch.object(f.intel, "schedule_save", MagicMock()) as save:
        f.intel._run_machine(T0 + 220, [])  # nothing new
        save.assert_not_called()
