"""Tests for the correlation and root cause (network intelligence P5).

Pure rule tests (topology builder, ``AlarmMachine.correlate`` per root type,
also where a rule must not fire) and engine scenarios with the real
``FleetOutageTracker`` (timers and issues captured as in ``test_fleet``):
AP outage with 20 clients (AK1), all routers down (AK2), WAN down with DNS
lines, inferred edges (AK6) and staggered polls. Router names are roles,
MACs locally administered test values, IPs from TEST-NET.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from test_fleet import _Harness
from test_net_engine import FakeDisk, FakeStore, _ha_file_bytes, make_hass
from test_net_wifi import IFACES, SSID, Log, client, disc, psk

from custom_components.openwrt_router import net_engine
from custom_components.openwrt_router.const import (
    ERROR_TYPE_AUTH,
    ERROR_TYPE_TIMEOUT,
    INTEL_MAX_STORE_BYTES,
)
from custom_components.openwrt_router.coordinator import LogBatch
from custom_components.openwrt_router.log_parser import parse_entry
from custom_components.openwrt_router.net_engine import FLEET_ROUTER, NetIntelligence
from custom_components.openwrt_router.net_events import (
    STORE_EVIDENCE,
    Category,
    CauseStatus,
    Incident,
    IncidentStatus,
    NetEvent,
    Origin,
    Scope,
    Severity,
    Source,
)
from custom_components.openwrt_router.net_rules import (
    INFERRED_CONFIDENCE_CAP,
    LAN_UNREACHABLE_KEY,
    ROUTER_REACHABLE_KIND,
    ROUTER_UNREACHABLE_KIND,
    AlarmMachine,
    Evidence,
    InfraSnapshot,
    InfraState,
    RouterLinks,
    Topology,
    Uplink,
    build_topology,
    detect_infrastructure,
    log_event_evidence,
    merge_settings,
    port_key,
)

T0 = 1_763_280_000.0
MS0 = int(T0 * 1000)
G, A, B = "gw", "ap1", "ap2"
HOST = {G: "192.0.2.1", A: "192.0.2.2", B: "192.0.2.3"}
MAC = {G: "02:00:5e:00:00:01", A: "02:00:5e:00:00:02", B: "02:00:5e:00:00:03"}
CLIENTS20 = [f"02:00:5E:20:00:{i:02X}" for i in range(20)]
TH = merge_settings(None)["thresholds"]
OPEN = (IncidentStatus.ACTIVE, IncidentStatus.ACKNOWLEDGED)


# --- helpers: machine --------------------------------------------------------------


def level(
    type_: str,
    key: str,
    *,
    value: float = 1.0,
    router: str | None = None,
    scope: Scope = Scope.ROUTER,
    since: float | None = None,
    origin: Origin = Origin.OBSERVED,
    cause: str | None = None,
    status: CauseStatus | None = None,
) -> Evidence:
    return Evidence(
        type=type_,
        scope_key=key,
        scope=scope,
        kind="test",
        value=value,
        router=router if router is not None else key.split(":")[0],
        since=since,
        origin=origin,
        confidence=1.0 if origin is Origin.OBSERVED else INFERRED_CONFIDENCE_CAP,
        cause=cause,
        cause_status=status,
    )


def hit(
    type_: str,
    key: str,
    router: str,
    *,
    scope: Scope = Scope.ROUTER,
    count: int = 1,
    event_id: str | None = None,
    cause: str | None = None,
    status: CauseStatus | None = None,
) -> Evidence:
    return Evidence(
        type=type_,
        scope_key=key,
        scope=scope,
        kind="test",
        count=count,
        router=router,
        event_id=event_id,
        cause=cause,
        cause_status=status,
    )


def storm(mac: str, router: str) -> Evidence:
    """Evidence that opens a client incident (5 reconnects at once)."""
    return hit(
        "wifi_reconnect_storm",
        mac,
        router,
        scope=Scope.CLIENT,
        count=5,
        cause="weak_signal",
        status=CauseStatus.HYPOTHESIS,
    )


def inc_of(m: AlarmMachine, type_: str, key: str) -> Incident:
    [inc] = [i for i in m.incidents() if i.type == type_ and i.scope_key == key]
    return inc


def roots(m: AlarmMachine) -> list[Incident]:
    return [i for i in m.incidents() if i.status in OPEN and i.parent_id is None]


def event(
    eid: str,
    ts: float,
    router: str,
    kind: str,
    category: Category,
    subject: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> NetEvent:
    return NetEvent(
        id=eid,
        ts=ts,
        router=router,
        category=category,
        kind=kind,
        subject=subject or {},
        params=params or {},
    )


def observed_tree() -> Topology:
    """gw <- ap1 (lan3/lan1, LLDP) <- ap2 (lan2/lan1, LLDP)."""
    return Topology(
        {
            A: Uplink(G, "lan3", "lan1", True),
            B: Uplink(A, "lan2", "lan1", True),
        },
        frozenset({G}),
    )


def inferred_tree() -> Topology:
    return Topology(
        {
            A: Uplink(G, "lan3", "lan1", False),
            B: Uplink(A, "lan2", "lan1", False),
        },
        frozenset({G}),
    )


# --- topology ----------------------------------------------------------------------


def lldp(port: str, **ident: str) -> dict[str, Any]:
    return {"local_interface": port, "capabilities": ["Bridge"], **ident}


def link(router: str, **kw: Any) -> RouterLinks:
    return RouterLinks(
        ids=frozenset({MAC[router], HOST[router]}), host=HOST[router], **kw
    )


def test_topology_from_lldp_is_observed() -> None:
    links = {
        G: link(G, gateway=True, lldp=(lldp("lan3", chassis_id=MAC[A].upper()),)),
        A: link(A, lldp=(lldp("lan1", management_ip=HOST[G]),)),
    }
    topo = build_topology(links)
    assert topo.uplinks == {A: Uplink(G, "lan3", "lan1", True)}
    assert topo.chain(A) == [G] and topo.depth(A) == 1 and topo.depth(G) == 0
    assert topo.ports_of(G) == {"lan3"} and topo.ports_of(A) == {"lan1"}
    assert topo.observed_path(A, G) and topo.behind(G) == [A]


def test_topology_inferred_from_trunk_maps_picks_the_nearest_router() -> None:
    links = {
        G: link(G, gateway=True, trunk={HOST[A]: "lan2", HOST[B]: "lan2"}),
        A: link(A, trunk={HOST[G]: "lan1", HOST[B]: "lan2"}),
        B: link(B, trunk={HOST[G]: "lan1", HOST[A]: "lan1"}),
    }
    topo = build_topology(links)
    assert topo.uplinks[A] == Uplink(G, "lan2", "lan1", False)
    assert topo.uplinks[B] == Uplink(A, "lan2", "lan1", False)
    assert topo.chain(B) == [A, G]
    assert not topo.observed_path(B, G)


def test_topology_ambiguous_or_without_gateway_gives_no_edge() -> None:
    # two candidates that do not see each other on that port: no guess
    links = {
        G: link(G, gateway=True, trunk={HOST[A]: "lan2", HOST[B]: "lan3"}),
        B: link(B, trunk={HOST[G]: "lan1", HOST[A]: "lan4"}),
        A: link(A, trunk={}),
    }
    assert A not in build_topology(links).uplinks
    # the same maps without a known gateway: no topology at all
    no_gw = {r: RouterLinks(l.ids, l.host, trunk=l.trunk) for r, l in links.items()}
    assert build_topology(no_gw) == Topology()


def test_topology_identity_claimed_twice_is_ignored() -> None:
    shared = "02:00:5e:00:00:99"
    links = {
        G: RouterLinks(
            frozenset({shared}), HOST[G], (lldp("lan3", chassis_id=shared),), {}, True
        ),
        A: RouterLinks(frozenset({shared, HOST[A]}), HOST[A]),
    }
    assert build_topology(links).uplinks == {}


def test_topology_remembers_an_uplink_while_the_parent_is_known() -> None:
    before = {A: Uplink(G, "lan3", "lan1", False)}
    links = {G: link(G, gateway=True), A: link(A)}
    assert build_topology(links, before).uplinks == before
    # parent unloaded: the memory goes
    assert build_topology({G: link(G, gateway=True), B: link(B)}, before).uplinks == {}
    # a remembered cycle is not taken over
    cyc = {A: Uplink(B, "x", "y", False), B: Uplink(A, "x", "y", False)}
    topo = build_topology({G: link(G, gateway=True), A: link(A), B: link(B)}, cyc)
    assert len(topo.uplinks) == 1


# --- correlation per root type ------------------------------------------------------


def test_lan_root_takes_all_router_incidents_and_nothing_after_its_end() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", G, since=T0 - 30)])
    m.update(T0 + 1, [level("lan_unreachable", LAN_UNREACHABLE_KEY, router="")])
    m.update(T0 + 2, [level("router_unreachable", A, since=T0)])
    m.correlate(T0 + 2, observed_tree())
    lan = inc_of(m, "lan_unreachable", LAN_UNREACHABLE_KEY)
    for router in (G, A):
        child = inc_of(m, "router_unreachable", router)
        assert child.parent_id == lan.id  # lan wins over the gateway
        assert child.cause == "lan_unreachable"
        assert child.cause_status is CauseStatus.CONFIRMED
    assert inc_of(m, "lan_unreachable", LAN_UNREACHABLE_KEY).children == 2
    # after the fleet outage ended (window +0 s) nothing joins it
    # (the router outages end with it; their own window is +180 s)
    m.update(
        T0 + 60,
        [
            level("lan_unreachable", LAN_UNREACHABLE_KEY, value=0),
            level("router_unreachable", G, value=0),
            level("router_unreachable", A, value=0),
        ],
    )
    m.update(T0 + 70, [storm(CLIENTS20[0], A)])
    m.correlate(T0 + 70, observed_tree())
    storm_inc = inc_of(m, "wifi_reconnect_storm", CLIENTS20[0])
    assert storm_inc.parent_id == inc_of(m, "router_unreachable", A).id
    m.update(T0 + 300, [storm(CLIENTS20[1], A)])
    m.correlate(T0 + 300, observed_tree())
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[1]).parent_id is None


def test_router_root_takes_own_incidents_in_its_window_only() -> None:
    m = AlarmMachine()
    m.update(T0 - 200, [storm(CLIENTS20[0], A)])  # long before the outage
    m.update(T0 - 100, [storm(CLIENTS20[1], A), storm(CLIENTS20[2], G)])
    m.update(T0, [level("router_unreachable", A, since=T0)])
    m.correlate(T0, Topology())  # no topology needed for the own router
    root = inc_of(m, "router_unreachable", A)
    near = inc_of(m, "wifi_reconnect_storm", CLIENTS20[1])
    assert near.parent_id == root.id
    assert (near.cause, near.cause_status) == (
        "router_unreachable",
        CauseStatus.CONFIRMED,
    )
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[0]).parent_id is None
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[2]).parent_id is None


def test_reboot_under_the_outage_confirms_the_cause() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", A, since=T0)])
    m.update(T0 + 300, [hit("system_reboot", A, A)])
    m.correlate(T0 + 300, Topology())
    root = inc_of(m, "router_unreachable", A)
    assert inc_of(m, "system_reboot", A).parent_id == root.id
    assert (root.cause, root.cause_status) == ("router_reboot", CauseStatus.CONFIRMED)
    assert root.parent_id is None  # no cycle: the outage is not under the reboot


def test_reboot_starts_at_the_boot_and_is_a_root() -> None:
    m = AlarmMachine()
    m.update(T0, [storm(CLIENTS20[0], A)])
    m.update(T0 + 120, [replace_since(hit("system_reboot", A, A), T0 + 30)])
    m.correlate(T0 + 120, Topology())
    reboot = inc_of(m, "system_reboot", A)
    assert reboot.first_seen == T0 + 30
    child = inc_of(m, "wifi_reconnect_storm", CLIENTS20[0])
    assert child.parent_id == reboot.id and child.cause == "router_reboot"


def replace_since(item: Evidence, since: float) -> Evidence:
    from dataclasses import replace

    return replace(item, since=since)


@pytest.mark.parametrize(
    ("topo", "status", "cap"),
    [
        (observed_tree(), CauseStatus.CONFIRMED, 1.0),
        (inferred_tree(), CauseStatus.HYPOTHESIS, INFERRED_CONFIDENCE_CAP),
    ],
)
def test_downstream_router_follows_its_uplink(
    topo: Topology, status: CauseStatus, cap: float
) -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", A, since=T0)])
    m.update(T0 + 60, [level("router_unreachable", B, since=T0 + 10)])
    m.update(T0 + 60, [storm(CLIENTS20[0], B)])
    m.correlate(T0 + 60, topo)
    root = inc_of(m, "router_unreachable", A)
    down = inc_of(m, "router_unreachable", B)
    assert down.parent_id == root.id
    assert down.cause_status is status and down.confidence <= cap
    # the client on ap2 goes under ap2 (most specific), not under ap1
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[0]).parent_id == down.id
    assert [r.id for r in roots(m)] == [root.id]


def test_sibling_router_and_upstream_router_are_not_children() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", B, since=T0)])
    m.update(T0 + 30, [level("router_unreachable", G, since=T0 + 20)])
    m.correlate(T0 + 30, observed_tree())
    # the gateway is upstream of ap2: no child of it (ap2 is a child of gw)
    assert inc_of(m, "router_unreachable", G).parent_id is None
    assert inc_of(m, "router_unreachable", B).parent_id is not None
    m2 = AlarmMachine()
    topo = Topology(
        {A: Uplink(G, "lan3", "lan1", True), B: Uplink(G, "lan4", "lan1", True)},
        frozenset({G}),
    )
    m2.update(T0, [level("router_unreachable", A, since=T0)])
    m2.update(T0 + 30, [level("router_unreachable", B, since=T0 + 20)])
    m2.correlate(T0 + 30, topo)
    assert len(roots(m2)) == 2  # siblings explain nothing of each other


def test_gateway_port_facing_the_router_is_a_child() -> None:
    for topo, status in (
        (observed_tree(), CauseStatus.CONFIRMED),
        (inferred_tree(), CauseStatus.HYPOTHESIS),
    ):
        m = AlarmMachine()
        m.update(T0, [level("lan_uplink_down", port_key(G, "lan3"), router=G)])
        m.update(T0 + 90, [level("router_unreachable", A, since=T0 + 5)])
        m.update(T0 + 90, [level("lan_uplink_down", port_key(G, "lan9"), router=G)])
        m.correlate(T0 + 90, topo)
        facing = inc_of(m, "lan_uplink_down", port_key(G, "lan3"))
        assert facing.parent_id == inc_of(m, "router_unreachable", A).id
        assert facing.cause_status is status
        other = inc_of(m, "lan_uplink_down", port_key(G, "lan9"))
        assert other.parent_id is None


def test_gateway_outage_explains_missing_ip_anywhere_as_hypothesis() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", G, since=T0)])
    no_ip = level("wifi_no_ip", CLIENTS20[0], router=B, scope=Scope.CLIENT)
    m.update(T0 + 60, [no_ip])
    m.update(T0 + 120, [no_ip])  # debounce 2
    m.correlate(T0 + 120, Topology({}, frozenset({G})))
    child = inc_of(m, "wifi_no_ip", CLIENTS20[0])
    assert child.parent_id == inc_of(m, "router_unreachable", G).id
    assert child.cause_status is CauseStatus.HYPOTHESIS
    # an AP outage does not explain a client of another AP without an IP
    m2 = AlarmMachine()
    m2.update(T0, [level("router_unreachable", A, since=T0)])
    m2.update(T0 + 60, [no_ip])
    m2.update(T0 + 120, [no_ip])
    m2.correlate(T0 + 120, Topology({}, frozenset({G})))
    assert inc_of(m2, "wifi_no_ip", CLIENTS20[0]).parent_id is None


def test_wan_down_takes_wan_incidents_of_its_gateway_and_dns_events() -> None:
    m = AlarmMachine()
    m.update(T0, [level("wan_down", G)])
    m.update(T0 + 30, [hit("wan_unstable", G, G, count=3)])
    m.update(T0 + 30, [hit("wan_unstable", A, A, count=3)])
    events = [
        event("gw:1", T0 + 20, G, "dns.no_servers", Category.DNS),
        event("gw:2", T0 + 25, G, "wan.ip_changed", Category.WAN),
        event("gw:3", T0 + 1, G, "wan.down", Category.WAN),
        event("ap1:4", T0 + 25, A, "wan.ip_changed", Category.WAN),
        event("gw:5", T0 - 200, G, "dns.no_servers", Category.DNS),
    ]
    result = m.correlate(T0 + 30, Topology())
    root = inc_of(m, "wan_down", G)
    assert inc_of(m, "wan_unstable", G).parent_id == root.id
    assert inc_of(m, "wan_unstable", A).parent_id is None
    result = m.correlate(T0 + 30, Topology(), events)
    assert result.events == {"gw:1": root.id, "gw:2": root.id}


def test_radio_change_takes_mass_disconnect_and_events_of_that_radio() -> None:
    radio = f"{A}:radio:phy1"
    m = AlarmMachine()
    m.update(T0, [hit("wifi_radio_change", radio, A, scope=Scope.RADIO)])
    m.update(T0 + 20, [hit("wifi_mass_disconnect", A, A, count=8)])
    m.update(T0 + 20, [hit("wifi_mass_disconnect", B, B, count=8)])
    m.update(T0 + 200, [hit("wifi_mass_disconnect", A, A, count=8)])  # same inc
    events = [
        event(
            "e1", T0 + 10, A, "wifi.psk_mismatch", Category.WIFI, {"iface": "phy1-ap0"}
        ),
        event(
            "e2", T0 + 10, A, "wifi.psk_mismatch", Category.WIFI, {"iface": "phy0-ap0"}
        ),
        event(
            "e3", T0 + 10, B, "wifi.psk_mismatch", Category.WIFI, {"iface": "phy1-ap0"}
        ),
    ]
    result = m.correlate(T0 + 20, Topology(), events)
    root = inc_of(m, "wifi_radio_change", radio)
    mass = inc_of(m, "wifi_mass_disconnect", A)
    assert mass.parent_id == root.id and mass.cause == "radio_change"
    assert mass.cause_status is CauseStatus.CONFIRMED
    assert inc_of(m, "wifi_mass_disconnect", B).parent_id is None
    assert result.events == {"e1": root.id}


def test_dfs_line_becomes_radio_change_evidence() -> None:
    radar = event(
        "ap1:7", T0, A, "dfs.radar_detected", Category.WIFI, {"iface": "phy1-ap0"}
    )
    item = log_event_evidence(radar)
    assert item is not None
    assert (item.type, item.scope, item.scope_key) == (
        "wifi_radio_change",
        Scope.RADIO,
        f"{A}:radio:phy1",
    )
    no_iface = event("ap1:8", T0, A, "dfs.radar_detected", Category.WIFI)
    assert log_event_evidence(no_iface) is None
    cac_start = event("ap1:9", T0, A, "dfs.cac_start", Category.WIFI, {"iface": "x"})
    assert log_event_evidence(cac_start) is None  # a CAC alone moves nothing


def test_router_outage_behind_a_port_is_the_root_of_that_port() -> None:
    for origin in (Origin.OBSERVED, Origin.INFERRED):
        m = AlarmMachine()
        key = port_key(A, "lan2")
        m.update(T0, [level("lan_uplink_down", key, router=A, origin=origin)])
        m.update(T0 + 30, [storm(CLIENTS20[0], B), storm(CLIENTS20[1], A)])
        m.update(T0 + 30, [level("router_unreachable", B, since=T0 + 5)])
        m.correlate(T0 + 30, observed_tree())
        outage = inc_of(m, "router_unreachable", B)
        # ap2's outage (tier 2) is never a child of a port (tier 5); the
        # port of ap1 that faces ap2 goes under it (observed LLDP edge)
        assert outage.parent_id is None
        port_inc = inc_of(m, "lan_uplink_down", key)
        assert port_inc.parent_id == outage.id
        assert port_inc.cause_status is CauseStatus.CONFIRMED
        # the client of ap2 ends at the same root, the client of ap1 not
        behind = inc_of(m, "wifi_reconnect_storm", CLIENTS20[0])
        assert behind.parent_id in (port_inc.id, outage.id)
        assert top_of(m, behind).id == outage.id
        assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[1]).parent_id is None
        assert {r.id for r in roots(m)} == {
            outage.id,
            inc_of(m, "wifi_reconnect_storm", CLIENTS20[1]).id,
        }


def top_of(m: AlarmMachine, inc: Incident) -> Incident:
    by_id = {i.id: i for i in m.incidents()}
    while inc.parent_id is not None:
        inc = by_id[inc.parent_id]
    return inc


def test_uplink_root_cause_status_follows_root_and_edge() -> None:
    for origin, topo, status in (
        (Origin.OBSERVED, observed_tree(), CauseStatus.CONFIRMED),
        (Origin.INFERRED, observed_tree(), CauseStatus.HYPOTHESIS),
        (Origin.OBSERVED, inferred_tree(), CauseStatus.HYPOTHESIS),
    ):
        m = AlarmMachine()
        m.update(
            T0, [level("lan_uplink_down", port_key(A, "lan2"), router=A, origin=origin)]
        )
        m.update(T0 + 30, [storm(CLIENTS20[0], B)])
        m.correlate(T0 + 30, topo)
        child = inc_of(m, "wifi_reconnect_storm", CLIENTS20[0])
        assert child.parent_id == inc_of(m, "lan_uplink_down", port_key(A, "lan2")).id
        assert child.cause == "uplink_down" and child.cause_status is status
        if status is CauseStatus.HYPOTHESIS:
            assert child.confidence <= INFERRED_CONFIDENCE_CAP


def test_mass_disconnect_takes_clients_of_its_router_as_hypothesis() -> None:
    m = AlarmMachine()
    m.update(T0, [hit("wifi_mass_disconnect", A, A, count=8)])
    m.update(T0 + 20, [storm(CLIENTS20[0], A), storm(CLIENTS20[1], B)])
    m.update(T0 + 100, [storm(CLIENTS20[2], A)])  # outside +30 s
    m.correlate(T0 + 100, Topology())
    root = inc_of(m, "wifi_mass_disconnect", A)
    child = inc_of(m, "wifi_reconnect_storm", CLIENTS20[0])
    assert child.parent_id == root.id
    assert (child.cause, child.cause_status) == (
        "mass_disconnect",
        CauseStatus.HYPOTHESIS,
    )
    assert child.confidence == INFERRED_CONFIDENCE_CAP
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[1]).parent_id is None
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[2]).parent_id is None
    # the cap holds against later evidence of the child
    m.update(T0 + 110, [storm(CLIENTS20[0], A)])
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[0]).confidence <= 0.6


def test_confirmed_child_cause_is_kept_against_a_hypothesis() -> None:
    m = AlarmMachine()
    m.update(T0, [hit("wifi_mass_disconnect", A, A, count=8)])
    m.update(
        T0 + 10,
        [
            hit(
                "wifi_auth_failures",
                CLIENTS20[0],
                A,
                scope=Scope.CLIENT,
                count=3,
                cause="weak_signal",
                status=CauseStatus.CONFIRMED,
            )
        ],
    )
    m.correlate(T0 + 10, Topology())
    child = inc_of(m, "wifi_auth_failures", CLIENTS20[0])
    assert child.parent_id is not None
    assert (child.cause, child.cause_status) == ("weak_signal", CauseStatus.CONFIRMED)
    assert child.confidence == 1.0


def test_a_child_stays_linked_and_a_root_may_become_a_child() -> None:
    m = AlarmMachine()
    m.update(T0, [hit("wifi_mass_disconnect", A, A, count=8)])
    m.update(T0 + 10, [storm(CLIENTS20[0], A)])
    m.correlate(T0 + 10, Topology())
    mass = inc_of(m, "wifi_mass_disconnect", A)
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[0]).parent_id == mass.id
    # the outage of the AP is reported later (settle): mass goes under it
    m.update(T0 + 200, [level("router_unreachable", A, since=T0 + 5)])
    m.correlate(T0 + 200, Topology())
    root = inc_of(m, "router_unreachable", A)
    assert inc_of(m, "wifi_mass_disconnect", A).parent_id == root.id
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[0]).parent_id == mass.id
    assert [r.id for r in roots(m)] == [root.id]
    # a second run changes nothing
    again = m.correlate(T0 + 210, Topology())
    assert again.incidents == {} and inc_of(m, "router_unreachable", A).children == 1


def test_events_link_to_the_most_specific_root_not_to_their_own() -> None:
    m = AlarmMachine()
    m.update(T0, [hit("wifi_mass_disconnect", A, A, count=8, event_id="ap1:1")])
    m.update(T0 + 60, [level("router_unreachable", A, since=T0 + 30)])
    events = [
        event("ap1:1", T0, A, "wifi.mass_disconnect", Category.WIFI),
        event("ap1:2", T0 + 5, A, "wifi.psk_mismatch", Category.WIFI, {"mac": "x"}),
        event("ap1:3", T0 + 5, A, "system.service_restart", Category.SYSTEM),
        event(
            "ap2:4",
            T0 + 40,
            B,
            "wifi.roam",
            Category.WIFI,
            params={"from_router": A, "to_router": B},
        ),
    ]
    result = m.correlate(T0 + 60, Topology(), events)
    root = inc_of(m, "router_unreachable", A)
    assert result.events == {"ap1:1": root.id, "ap1:2": root.id, "ap2:4": root.id}


def test_correlation_without_roots_does_nothing() -> None:
    m = AlarmMachine()
    m.update(T0, [storm(CLIENTS20[0], A), storm(CLIENTS20[1], A)])
    result = m.correlate(T0, observed_tree(), [event("x", T0, A, "k", Category.WIFI)])
    assert result.incidents == {} and result.events == {}
    assert all(i.parent_id is None for i in m.incidents())


# --- machine details P5 --------------------------------------------------------------


def test_inferred_uplink_opens_as_warning_and_observed_lifts_it() -> None:
    m = AlarmMachine()
    key = port_key(G, "lan3")
    out = m.update(T0, [level("lan_uplink_down", key, origin=Origin.INFERRED)])
    inc = out[0].incident
    assert inc.severity is Severity.WARNING and inc.confidence <= 0.6
    out = m.update(T0 + 60, [level("lan_uplink_down", key)])
    assert out[0].incident.severity is Severity.CRITICAL
    assert out[0].incident.origin is Origin.OBSERVED


def test_outage_rules_are_fixed_to_stay_open() -> None:
    settings = merge_settings(
        {"thresholds": {"router_unreachable": {"stay_open": False, "severity": "info"}}}
    )
    rule = settings["thresholds"]["router_unreachable"]
    assert rule["stay_open"] is True and rule["severity"] == "info"
    assert TH["lan_unreachable"]["severity"] == "critical"
    assert TH["router_unreachable"]["severity"] == "warning"
    assert TH["wifi_radio_change"]["severity"] == "info"


def test_compact_machine_round_trip_and_old_full_format() -> None:
    m = AlarmMachine()
    m.update(T0, [hit("wifi_mass_disconnect", A, A, count=8, event_id="ap1:1")])
    m.update(T0 + 10, [storm(CLIENTS20[0], A)])
    m.update(T0 + 20, [level("router_unreachable", A, since=T0)])
    m.correlate(T0 + 20, Topology())
    full, compact = m.to_dict(), m.to_dict(compact=True)
    assert len(str(compact)) < len(str(full))
    for stored in (full, compact):
        back = AlarmMachine.from_dict(stored)
        assert back.incidents() == m.incidents()
        assert back.to_dict() == full
    # a full record written before P5 (no parent_id/children) still loads
    old = full["incidents"][0].copy()
    old.pop("parent_id")
    old.pop("children")
    restored = Incident.from_dict(old)
    assert restored is not None and restored.parent_id is None
    assert restored.children == 0
    # events: parent_id only in the record when set
    plain = event("ap1:1", T0, A, "wifi.mass_disconnect", Category.WIFI)
    assert "parent_id" not in plain.to_dict(compact=True)
    from dataclasses import replace

    linked = replace(plain, parent_id="inc-3")
    assert NetEvent.from_dict(linked.to_dict(compact=True)) == linked


# --- inferred lan_uplink_down (detector) --------------------------------------------


def port(name: str, up: bool = True) -> dict[str, Any]:
    return {"name": name, "up": up, "carrier": up, "speed_mbps": 1000}


def uplinks(found: list[Any]) -> list[Any]:
    return [f for f in found if f.kind == "lan.uplink"]


def test_inferred_uplink_down_from_the_topology_port() -> None:
    state = InfraState()

    def run(now: float, *ports: dict[str, Any], up: frozenset[str] = frozenset()):
        snap = InfraSnapshot(ports=ports, uplink_ports=up)
        return uplinks(detect_infrastructure(state, snap, now, G, TH))

    # never on the topology: nothing
    assert run(T0, port("lan3")) == []
    [ok] = run(T0 + 60, port("lan3"), up=frozenset({"lan3"}))
    assert ok.value == 0.0 and ok.origin is Origin.INFERRED
    # the FDB forgets the router once the link is down: the role stays a day
    [down] = run(T0 + 120, port("lan3", up=False))
    assert down.value == 1.0 and down.origin is Origin.INFERRED
    assert down.confidence == INFERRED_CONFIDENCE_CAP
    assert down.cause_status is CauseStatus.HYPOTHESIS
    assert down.source is Source.TOPOLOGY
    assert run(T0 + 120 + 86401, port("lan3", up=False)) == []
    # an LLDP neighbour makes it observed
    state2 = InfraState()
    lldp = (
        {"local_interface": "lan3", "chassis_id": MAC[A], "capabilities": ["Bridge"]},
    )
    detect_infrastructure(
        state2, InfraSnapshot(ports=(port("lan3"),), lldp=lldp), T0, G, TH
    )
    found = detect_infrastructure(
        state2,
        InfraSnapshot(
            ports=(port("lan3", up=False),), uplink_ports=frozenset({"lan3"})
        ),
        T0 + 60,
        G,
        TH,
    )
    [obs] = uplinks(found)
    assert obs.origin is Origin.OBSERVED and obs.cause is None


# --- engine scenarios with the real outage tracker ----------------------------------


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def time(self) -> float:
        return self.now

    def monotonic(self) -> float:
        return self.now


@pytest.fixture
def clock() -> Any:
    c = Clock()
    with patch.object(net_engine, "time", c):
        yield c


@pytest.fixture
async def fleet(clock: Clock) -> Any:
    disk = FakeDisk()
    harness = _Harness(routers=(G, A, B))
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        intel = NetIntelligence(make_hass())
        await intel.async_load()
    for router in (G, A, B):
        intel.register(router)
    intel._wan_gateways.add(G)
    intel.attach_outages(harness.tracker)
    yield SimpleNamespace(intel=intel, h=harness, clock=clock)
    harness.stop()


def dt(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, UTC)


def rdata(
    router: str,
    *,
    events: tuple[Any, ...] = (),
    clients: list[dict[str, Any]] | None = None,
    ports: tuple[dict[str, Any], ...] | None = None,
    trunk: dict[str, str] | None = None,
    wan: dict[str, Any] | None = None,
    connected: bool | None = None,
) -> SimpleNamespace:
    ids = [e.log_id for e in events]
    return SimpleNamespace(
        new_log_events=events,
        new_log_batch=LogBatch(
            baseline=False,
            missed=0,
            first_time_ms=None,
            last_id=max(ids) if ids else None,
            last_time_ms=None,
            new_lines=len(events),
        ),
        ap_interfaces=IFACES if clients is not None else [],
        clients=list(clients or []),
        log_status="ok",
        port_stats=list(ports) if ports else [],
        trunk_port_map=trunk or {},
        wan_status=wan,
        wan_connected=connected,
        router_info={"mac": MAC[router]},
    )


def feed(f: Any, router: str, now: float, data: SimpleNamespace) -> int:
    f.clock.now = now
    return f.intel.ingest(router, data, now, now, host=HOST[router], interval=60)


def open_roots(intel: NetIntelligence) -> list[Incident]:
    return roots(intel.machine)


def top(intel: NetIntelligence, inc_id: str | None) -> Incident | None:
    """Walk the parent chain of an incident to its root."""
    by_id = {i.id: i for i in intel.machine.incidents()}
    inc = by_id.get(inc_id or "")
    while inc is not None and inc.parent_id is not None:
        inc = by_id[inc.parent_id]
    return inc


def kinds(intel: NetIntelligence, kind: str) -> list[NetEvent]:
    return [e for e in intel.ring if e.kind == kind]


GW_TRUNK = {HOST[A]: "lan3", HOST[B]: "lan4"}
AP_TRUNK = {HOST[G]: "lan1"}


def gw_poll(f: Any, now: float, lan3: bool = True, **kw: Any) -> None:
    feed(
        f,
        G,
        now,
        rdata(G, ports=(port("lan3", lan3), port("lan4")), trunk=GW_TRUNK, **kw),
    )


async def test_ak1_ap_outage_with_20_clients_is_one_root(fleet: Any) -> None:
    f, log = fleet, Log()
    clients = [client(mac) for mac in CLIENTS20]
    for n in range(3):  # baseline polls: 20 clients, links up
        gw_poll(f, T0 + 60 * n)
        feed(f, A, T0 + 60 * n + 20, rdata(A, clients=clients, trunk=AP_TRUNK))
        feed(f, B, T0 + 60 * n + 40, rdata(B, clients=[], trunk=AP_TRUNK))
    # hostapd drops all 20 stations within two seconds, then the AP is gone
    lines = log.lines(*((200 + i / 10, disc(mac)) for i, mac in enumerate(CLIENTS20)))
    feed(f, A, T0 + 200, rdata(A, events=lines, clients=[], trunk=AP_TRUNK))
    [mass] = [
        i for i in f.intel.machine.incidents() if i.type == "wifi_mass_disconnect"
    ]
    assert mass.affected == 20
    # gateway sees its port to the AP go down (inferred uplink port)
    gw_poll(f, T0 + 240, lan3=False)
    # three failed AP polls (260, 320, 380); the tracker settles
    f.clock.now = T0 + 380
    f.h.tracker.report_down(A, ERROR_TYPE_TIMEOUT, dt(T0 + 260))
    gw_poll(f, T0 + 420, lan3=False)
    f.clock.now = T0 + 470
    f.h.fire_timer()
    intel = f.intel
    [root] = open_roots(intel)
    assert (root.type, root.scope_key) == ("router_unreachable", A)
    assert root.first_seen == T0 + 260
    assert root.severity is Severity.WARNING
    assert (root.cause, root.cause_status) == (
        "router_unreachable",
        CauseStatus.CONFIRMED,
    )
    for inc in intel.machine.incidents():
        if inc.status in OPEN:
            assert top(intel, inc.id).id == root.id, inc.type
    port_inc = next(i for i in intel.machine.incidents() if i.type == "lan_uplink_down")
    # AK6: the port rests on an inferred edge
    assert port_inc.cause_status is CauseStatus.HYPOTHESIS
    assert port_inc.confidence <= INFERRED_CONFIDENCE_CAP
    [mass_event] = kinds(intel, "wifi.mass_disconnect")
    assert top(intel, mass_event.parent_id).id == root.id
    [down_event] = kinds(intel, ROUTER_UNREACHABLE_KIND)
    assert down_event.router == A and down_event.source is Source.FLEET
    # the AP answers again: resolved, one "reachable" event
    f.clock.now = T0 + 600
    f.h.tracker.report_up(A)
    assert inc_of(intel.machine, "router_unreachable", A).status is (
        IncidentStatus.RESOLVED
    )
    assert len(kinds(intel, ROUTER_REACHABLE_KIND)) == 1


async def test_ak1_without_topology_the_own_router_link_is_confirmed(
    fleet: Any,
) -> None:
    f, log = fleet, Log()
    f.intel._wan_gateways.clear()  # no gateway known: no topology
    clients = [client(mac) for mac in CLIENTS20]
    for n in range(3):
        feed(f, A, T0 + 60 * n, rdata(A, clients=clients))
    lines = log.lines(*((150 + i / 10, disc(mac)) for i, mac in enumerate(CLIENTS20)))
    feed(f, A, T0 + 180, rdata(A, events=lines, clients=[]))
    f.clock.now = T0 + 360
    f.h.tracker.report_down(A, ERROR_TYPE_TIMEOUT, dt(T0 + 240))
    f.clock.now = T0 + 450
    f.h.fire_timer()
    [root] = open_roots(f.intel)
    mass = inc_of(f.intel.machine, "wifi_mass_disconnect", A)
    assert mass.parent_id == root.id
    assert (mass.cause, mass.cause_status) == (
        "router_unreachable",
        CauseStatus.CONFIRMED,
    )


async def test_ak2_all_routers_down_is_one_lan_incident(fleet: Any) -> None:
    f = fleet
    for n, router in enumerate((G, A, B)):
        feed(f, router, T0 + 20 * n, rdata(router, trunk=AP_TRUNK if n else GW_TRUNK))
    f.clock.now = T0 + 200
    for n, router in enumerate((G, A, B)):
        f.h.tracker.report_down(router, ERROR_TYPE_TIMEOUT, dt(T0 + 60 + 20 * n))
    f.clock.now = T0 + 290
    f.h.fire_timer()
    intel = f.intel
    [root] = open_roots(intel)
    assert (root.type, root.scope, root.severity) == (
        "lan_unreachable",
        Scope.FLEET,
        Severity.CRITICAL,
    )
    assert root.first_seen == T0 + 60 and root.routers == sorted((G, A, B))
    children = [i for i in intel.machine.incidents() if i.parent_id == root.id]
    assert sorted(i.scope_key for i in children) == sorted((G, A, B))
    assert all(i.cause_status is CauseStatus.CONFIRMED for i in children)
    assert len([e for e in intel.ring if e.router == FLEET_ROUTER]) == 1
    # the first router answers: the fleet outage ends, the others stay down
    f.clock.now = T0 + 400
    f.h.tracker.report_up(G)
    lan = inc_of(intel.machine, "lan_unreachable", LAN_UNREACHABLE_KEY)
    assert lan.status is IncidentStatus.RESOLVED
    states = {
        i.scope_key: i.status
        for i in intel.machine.incidents()
        if i.type == "router_unreachable"
    }
    assert states == {
        G: IncidentStatus.RESOLVED,
        A: IncidentStatus.ACTIVE,
        B: IncidentStatus.ACTIVE,
    }
    # a recovery that is not reported (no event) is seen on the next poll
    f.h.tracker.report_up(A)
    feed(f, A, T0 + 420, rdata(A, trunk=AP_TRUNK))
    assert inc_of(intel.machine, "router_unreachable", A).status is (
        IncidentStatus.RESOLVED
    )


async def test_staggered_polls_settle_into_one_root(fleet: Any) -> None:
    f = fleet
    for n, router in enumerate((G, A, B)):
        feed(f, router, T0 + 20 * n, rdata(router, trunk=AP_TRUNK if n else GW_TRUNK))
    # the gateway fails first and is reported alone
    f.clock.now = T0 + 180
    f.h.tracker.report_down(G, ERROR_TYPE_TIMEOUT, dt(T0 + 60))
    f.clock.now = T0 + 270
    f.h.fire_timer()
    [single] = open_roots(f.intel)
    assert (single.type, single.scope_key) == ("router_unreachable", G)
    # the APs follow 20 and 40 s later, the fleet outage settles
    f.clock.now = T0 + 300
    f.h.tracker.report_down(A, ERROR_TYPE_TIMEOUT, dt(T0 + 80))
    f.h.tracker.report_down(B, ERROR_TYPE_TIMEOUT, dt(T0 + 100))
    f.clock.now = T0 + 390
    f.h.fire_timer()
    [root] = open_roots(f.intel)
    assert root.type == "lan_unreachable"
    # the earlier root is now a child; the APs are not under the gateway
    assert inc_of(f.intel.machine, "router_unreachable", G).parent_id == root.id
    for router in (A, B):
        assert (
            inc_of(f.intel.machine, "router_unreachable", router).parent_id == root.id
        )


async def test_auth_errors_and_unreported_outages_open_nothing(fleet: Any) -> None:
    f = fleet
    feed(f, A, T0, rdata(A))
    f.clock.now = T0 + 200
    f.h.tracker.report_down(A, ERROR_TYPE_AUTH, dt(T0 + 60))
    f.h.fire_timer()
    assert f.intel.machine.incidents() == []
    # down below the settle: not reported yet, a poll of another router
    # does not open it either
    f.h.tracker.report_up(A)
    f.h.tracker.report_down(A, ERROR_TYPE_TIMEOUT, dt(T0 + 300))
    feed(f, G, T0 + 320, rdata(G))
    assert f.intel.machine.incidents() == []


async def test_unloaded_router_keeps_its_open_outage(fleet: Any) -> None:
    f = fleet
    feed(f, A, T0, rdata(A))
    f.clock.now = T0 + 200
    f.h.tracker.report_down(A, ERROR_TYPE_TIMEOUT, dt(T0 + 60))
    f.h.fire_timer()
    f.h.tracker.unregister(A)
    f.intel.unregister(A)
    feed(f, G, T0 + 300, rdata(G))
    assert inc_of(f.intel.machine, "router_unreachable", A).status is (
        IncidentStatus.ACTIVE
    )


async def test_wan_down_with_dns_lines_explains_them(fleet: Any) -> None:
    f, log = fleet, Log()
    wan = {
        "connected": True,
        "interface": "wan",
        "ipv4": "203.0.113.7",
        "uptime": 900,
        "proto": "dhcp",
        "wan_found": True,
    }
    feed(f, G, T0, rdata(G, wan=wan, connected=True))
    dns = (
        parse_entry(
            {
                "id": 50,
                "time": MS0 + 60_000,
                "priority": 6,
                "source": 1,
                "msg": "dnsmasq[2345]: no servers found in "
                "/tmp/resolv.conf.d/resolv.conf.auto, will retry",
            }
        ),
    )
    feed(
        f,
        G,
        T0 + 60,
        rdata(G, events=dns, wan={**wan, "connected": False}, connected=False),
    )
    root = inc_of(f.intel.machine, "wan_down", G)
    [dns_event] = [e for e in f.intel.ring if e.category is Category.DNS]
    assert dns_event.parent_id == root.id
    # with the WAN up, DNS lines stay a hypothesis of their own
    feed(f, G, T0 + 120, rdata(G, wan=wan, connected=True))
    lines = log.lines((4000, "dnsmasq[2345]: no servers found in /tmp/x, will retry"))
    feed(f, G, T0 + 4000, rdata(G, events=lines, wan=wan, connected=True))
    later = [e for e in f.intel.ring if e.category is Category.DNS][-1]
    assert later.parent_id is None
    assert later.cause_status is CauseStatus.HYPOTHESIS


async def test_outage_hook_failure_never_reaches_the_tracker(fleet: Any) -> None:
    f = fleet
    with patch.object(f.intel, "_run_machine", side_effect=RuntimeError("boom")):
        f.clock.now = T0 + 200
        f.h.tracker.report_down(A, ERROR_TYPE_TIMEOUT, dt(T0 + 60))
        f.h.fire_timer()  # no exception
    assert f.h.events[-1]["state"] == "down"
    f.intel.close()
    assert f.h.tracker._listeners == []


async def test_new_engine_follows_the_tracker_of_hass() -> None:
    disk = FakeDisk()
    hass = make_hass()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        intel = await net_engine.async_get_net_intelligence(hass)
    tracker = net_engine.async_get_outage_tracker(hass)
    assert tracker._listeners == [intel._async_outage_changed]


# --- fleet hook ----------------------------------------------------------------------


def test_fleet_listener_and_snapshot_change_no_behaviour() -> None:
    h = _Harness()
    try:
        calls: list[Any] = []
        remove = h.tracker.add_listener(lambda: calls.append(h.tracker.snapshot()))
        h.tracker.add_listener(lambda: 1 / 0)  # a broken observer is only logged
        h.tracker.report_down("ap1", ERROR_TYPE_TIMEOUT, dt(T0))
        assert calls == []  # nothing fired yet (settle)
        h.fire_timer()
        [view] = calls
        assert view.fleet_since is None
        assert view.down["ap1"].reported and view.down["ap1"].since == dt(T0)
        assert [e["state"] for e in h.events] == ["down"]
        remove()
        remove()  # twice is fine
        h.tracker.report_up("ap1")
        assert len(calls) == 1 and [e["state"] for e in h.events] == ["down", "up"]
    finally:
        h.stop()


# --- P4 review K2: no live Wi-Fi context for gap lines --------------------------------


async def test_k2_gap_lines_get_no_wifi_context(clock: Clock) -> None:
    disk = FakeDisk()
    disk.data = {"log_marks": {A: {"last_id": 5, "last_time_ms": MS0 + 5000}}}
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        intel = NetIntelligence(make_hass())
        await intel.async_load()
    intel.register(A)
    line = parse_entry(
        {
            "id": 7,
            "time": MS0 + 7000,
            "priority": 30,
            "source": 1,
            "msg": psk(CLIENTS20[0]),
        }
    )
    data = SimpleNamespace(
        new_log_events=(line,),
        new_log_batch=LogBatch(
            baseline=True,
            missed=0,
            first_time_ms=MS0 + 6000,
            last_id=7,
            last_time_ms=MS0 + 7000,
        ),
        ap_interfaces=IFACES,
        clients=[client(CLIENTS20[0], signal=-80)],
        log_status="ok",
    )
    intel.ingest(A, data, T0 + 60)
    [stored] = [e for e in intel.ring if e.kind == "wifi.psk_mismatch"]
    assert stored.signal is None
    assert "ssid" not in stored.subject and "band" not in stored.subject
    assert SSID  # the live context had one; the gap line must not take it


# --- store budget with 500 open incidents (plan c5) ----------------------------------


async def _intel_with_500_incidents(type_: str, spacing: float) -> NetIntelligence:
    """3000 realistic events and 500 open client incidents of ``type_``,
    each fed 20 polls (``spacing`` s apart): full evidence lists (20)."""
    from test_net_engine import ULID1, ULID2, _realistic_event

    disk = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        intel = NetIntelligence(make_hass())
        await intel.async_load()
    for n in range(3000):
        intel.ring.add(_realistic_event(n))
    end = T0 + 3000 * 37.123
    intel.machine.sync_clock(end)
    for round_ in range(21):
        intel.machine.update(
            end + round_ * spacing,
            [
                Evidence(
                    type_,
                    f"02:00:5E:30:{i // 256:02X}:{i % 256:02X}",
                    Scope.CLIENT,
                    kind="wifi.reconnect",
                    event_id=f"{(ULID1, ULID2)[i % 2]}:{100_000 + round_ * 500 + i}",
                    value=1.0,
                    count=5,
                    router=(ULID1, ULID2)[i % 2],
                    cause="weak_signal",
                    cause_status=CauseStatus.HYPOTHESIS,
                    affected=1,
                )
                for i in range(500)
            ],
        )
    incidents = intel.machine.incidents()
    assert len(incidents) == 500
    assert all(i.status is IncidentStatus.ACTIVE for i in incidents)
    assert all(len(i.evidence) == 20 for i in incidents)
    return intel


async def test_store_with_500_open_incidents_and_3000_events(clock: Clock) -> None:
    # 500 clients without an IP for 20 polls: open level incidents with a
    # full evidence list (the realistic long-open case)
    intel = await _intel_with_500_incidents("wifi_no_ip", 60.0)
    payload = intel._data_to_save()
    size = intel.last_save_bytes
    machine_only = {**payload, "events": []}
    full = {**machine_only, "machine": intel.machine.to_dict()}
    print(
        f"store bytes: {size}, without events {_ha_file_bytes(machine_only)}, "
        f"full machine without events {_ha_file_bytes(full)}, events kept "
        f"{len(payload['events'])}, trimmed {intel.trimmed_events}"
    )
    assert size is not None and size <= INTEL_MAX_STORE_BYTES
    assert len(payload["events"]) >= 1500  # the incidents leave room for events
    for record in payload["machine"]["incidents"]:
        assert len(record["evidence"]) == STORE_EVIDENCE
    # the restored incidents keep their newest evidence
    restored = AlarmMachine.from_dict(payload["machine"])
    before, after = intel.machine.incidents()[0], restored.incidents()[0]
    assert after.evidence == before.evidence[-STORE_EVIDENCE:]
    assert after.occurrences == before.occurrences


async def test_store_worst_case_500_storming_clients_is_written_with_a_warning(
    clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    # 500 clients storming at the same time: every window track keeps its
    # entries for the 1800 s clear time; the machine alone exceeds the limit
    intel = await _intel_with_500_incidents("wifi_reconnect_storm", 60.0)
    payload = intel._data_to_save()
    print(
        f"worst case store bytes: {intel.last_save_bytes}, "
        f"events kept {len(payload['events'])}"
    )
    assert payload["events"] == []
    assert len(payload["machine"]["incidents"]) == 500  # never trimmed
    assert "without any event" in caplog.text
