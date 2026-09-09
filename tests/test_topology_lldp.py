"""Tests for LLDP-based router-to-router topology detection (topology_mesh.py).

Core guarantees under test:
  * Router-to-router edges come ONLY from real data sources (LLDP here) — never
    from IP ordering or from the mere fact that routers are configured.
  * Router count is dynamic (1/2/3/5 config entries all work).
  * LLDP is authoritative: it wins over FDB, blocks heuristic duplicates, and a
    known router is never rendered as an ordinary client.
"""
from __future__ import annotations

from types import SimpleNamespace

from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
from custom_components.openwrt_router.topology_mesh import (
    _build_known_router_index,
    _detect_inter_router_edges,
    _detect_switch_nodes,
    _match_lldp_neighbor,
    build_mesh_snapshot,
)


def _neigh(
    local_interface: str,
    *,
    mgmt_ip: str | None = None,
    chassis_id: str = "",
    chassis_name: str | None = None,
    port_id: str = "",
    port_descr: str = "",
    capabilities: list[str] | None = None,
) -> dict:
    return {
        "local_interface": local_interface,
        "chassis_id": chassis_id,
        "chassis_name": chassis_name,
        "management_ip": mgmt_ip,
        "port_id": port_id,
        "port_descr": port_descr,
        "capabilities": capabilities or [],
    }


def _router(
    mac: str = "",
    hostname: str = "",
    *,
    lldp: list[dict] | None = None,
    wan_status: dict | None = None,
    port_fdb_map: dict | None = None,
    port_vlan_map: dict | None = None,
    clients: list | None = None,
    sta_interfaces: list | None = None,
    port_stats: list | None = None,
    trunk_port_map: dict | None = None,
) -> OpenWrtCoordinatorData:
    data = OpenWrtCoordinatorData()
    data.router_info = {"mac": mac, "hostname": hostname}
    data.lldp_neighbors = lldp or []
    data.wan_status = wan_status or {}
    data.port_fdb_map = port_fdb_map or {}
    data.port_vlan_map = port_vlan_map or {}
    data.clients = clients or []
    data.sta_interfaces = sta_interfaces or []
    data.port_stats = port_stats or []
    data.trunk_port_map = trunk_port_map or {}
    return data


def _associated_sta(ifname: str = "wlan1-sta") -> dict:
    """An STA interface that iwinfo reports as actually associated."""
    return {
        "ifname": ifname,
        "mode": "sta",
        "mac": "RP:STA:00",
        "bssid": "GW:AP:00",
        "ssid": "sECUREaP",
        "signal": -58,
    }


def _router_uplinks(edges: list[dict]) -> list[dict]:
    return [e for e in edges if e.get("relationship") == "router_uplink"]


# =====================================================================
# No artificial edges from IP order / config presence
# =====================================================================


class TestNoIpOrderAssumption:
    def test_three_entries_no_data_no_edges(self):
        """3 configured routers, no LLDP/FDB/DHCP data => NO router link invented."""
        router_data = [
            ("r1", "10.10.10.1", _router(mac="aa:bb:cc:00:00:01")),
            ("r2", "10.10.10.2", _router(mac="aa:bb:cc:00:00:02")),
            ("r4", "10.10.10.4", _router(mac="aa:bb:cc:00:00:04")),
        ]
        edges = _detect_inter_router_edges([], router_data)
        # No 1->2->4 chain conjured from IP ordering.
        assert edges == []

    def test_lldp_beats_ip_order(self):
        """LLDP says .4 <-> .1 (not .4 <-> .2). Topology must follow the data."""
        r1 = _router(mac="aa:bb:cc:00:00:01")
        r2 = _router(mac="aa:bb:cc:00:00:02")
        # r4 sees r1 via LLDP management IP, despite 1 and 4 being non-adjacent.
        r4 = _router(
            mac="aa:bb:cc:00:00:04",
            lldp=[_neigh("wan", mgmt_ip="10.10.10.1", port_id="lan4")],
        )
        router_data = [
            ("r1", "10.10.10.1", r1),
            ("r2", "10.10.10.2", r2),
            ("r4", "10.10.10.4", r4),
        ]
        uplinks = _router_uplinks(_detect_inter_router_edges([], router_data))
        assert len(uplinks) == 1
        e = uplinks[0]
        assert {e["from"], e["to"]} == {"r1", "r4"}
        assert e["attributes"]["confidence"] == "high"
        assert e["attributes"]["detection_method"] == "lldp"
        # r2 is not connected to anything.
        assert "r2" not in {e["from"], e["to"]}


# =====================================================================
# Non-linear topology
# =====================================================================


class TestNonLinearTopology:
    def test_star_not_chain(self):
        """r1<->r4 and r1<->r2, but NO r2<->r4. Follows sources, not IP sort."""
        r1 = _router(
            mac="aa:bb:cc:00:00:01",
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "1.2.3.4"},
            lldp=[
                _neigh("lan3", mgmt_ip="10.10.10.2", port_id="wan"),
                _neigh("lan4", mgmt_ip="10.10.10.4", port_id="wan"),
            ],
        )
        r2 = _router(mac="aa:bb:cc:00:00:02")
        r4 = _router(mac="aa:bb:cc:00:00:04")
        router_data = [
            ("r1", "10.10.10.1", r1),
            ("r2", "10.10.10.2", r2),
            ("r4", "10.10.10.4", r4),
        ]
        uplinks = _router_uplinks(_detect_inter_router_edges([], router_data))
        pairs = {frozenset((e["from"], e["to"])) for e in uplinks}
        assert frozenset(("r1", "r2")) in pairs
        assert frozenset(("r1", "r4")) in pairs
        assert frozenset(("r2", "r4")) not in pairs


# =====================================================================
# Dynamic router count
# =====================================================================


class TestDynamicRouterCount:
    def test_single_router_no_edges(self):
        rd = [("r1", "10.10.10.1", _router(mac="aa:bb:cc:00:00:01"))]
        assert _detect_inter_router_edges([], rd) == []

    def test_two_routers_one_link(self):
        r1 = _router(
            mac="aa:bb:cc:00:00:01",
            lldp=[_neigh("lan1", mgmt_ip="10.10.10.2", port_id="wan")],
        )
        r2 = _router(mac="aa:bb:cc:00:00:02")
        rd = [("r1", "10.10.10.1", r1), ("r2", "10.10.10.2", r2)]
        assert len(_router_uplinks(_detect_inter_router_edges([], rd))) == 1

    def test_five_routers_only_detected_links(self):
        """5 entries; only r1<->r5 has LLDP data => exactly one router uplink."""
        routers = {
            f"r{i}": _router(mac=f"aa:bb:cc:00:00:0{i}") for i in range(1, 6)
        }
        routers["r1"].lldp_neighbors = [
            _neigh("lan2", mgmt_ip="10.10.10.5", port_id="wan")
        ]
        rd = [(f"r{i}", f"10.10.10.{i}", routers[f"r{i}"]) for i in range(1, 6)]
        uplinks = _router_uplinks(_detect_inter_router_edges([], rd))
        assert len(uplinks) == 1
        assert {uplinks[0]["from"], uplinks[0]["to"]} == {"r1", "r5"}


# =====================================================================
# Bidirectional / one-way / conflict / LLDP wins over heuristics
# =====================================================================


class TestLldpMergeSemantics:
    def test_bidirectional_high_confidence_both_ports(self):
        r1 = _router(
            mac="aa:bb:cc:00:00:01",
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "1.2.3.4"},
            lldp=[_neigh("lan3", mgmt_ip="10.10.10.2", port_id="wan")],
        )
        r2 = _router(
            mac="aa:bb:cc:00:00:02",
            lldp=[_neigh("wan", mgmt_ip="10.10.10.1", port_id="lan3")],
        )
        rd = [("r1", "10.10.10.1", r1), ("r2", "10.10.10.2", r2)]
        uplinks = _router_uplinks(_detect_inter_router_edges([], rd))
        assert len(uplinks) == 1
        attrs = uplinks[0]["attributes"]
        assert attrs["direction"] == "bidirectional"
        # gateway (r1) is the 'from' side; both physical ports are carried.
        assert uplinks[0]["from"] == "r1"
        assert attrs["from_port"] == "lan3"
        assert attrs["to_port"] == "wan"

    def test_one_way_still_detected_and_marked(self):
        r1 = _router(
            mac="aa:bb:cc:00:00:01",
            lldp=[_neigh("lan3", mgmt_ip="10.10.10.2", port_id="wan")],
        )
        r2 = _router(mac="aa:bb:cc:00:00:02")  # does not see r1
        rd = [("r1", "10.10.10.1", r1), ("r2", "10.10.10.2", r2)]
        uplinks = _router_uplinks(_detect_inter_router_edges([], rd))
        assert len(uplinks) == 1
        assert uplinks[0]["attributes"]["direction"] == "one_way"

    def test_lldp_port_wins_over_fdb_conflict_recorded(self):
        """LLDP says lan3; bridge FDB says lan4 for the same peer => LLDP wins."""
        r1 = _router(
            mac="aa:bb:cc:00:00:01",
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "1.2.3.4"},
            lldp=[_neigh("lan3", mgmt_ip="10.10.10.2", port_id="wan")],
            port_fdb_map={"aa:bb:cc:00:00:02": "lan4"},
        )
        r2 = _router(mac="aa:bb:cc:00:00:02")
        rd = [("r1", "10.10.10.1", r1), ("r2", "10.10.10.2", r2)]
        attrs = _router_uplinks(_detect_inter_router_edges([], rd))[0]["attributes"]
        assert attrs["from_port"] == "lan3"  # LLDP wins
        assert attrs["conflicts"]
        assert attrs["conflicts"][0]["fdb_port"] == "lan4"
        assert attrs["conflicts"][0]["lldp_port"] == "lan3"

    def test_lldp_blocks_dhcp_duplicate_for_same_pair(self):
        """A gateway that also has the AP in DHCP must not add a 2nd lan_uplink."""
        gw = _router(
            mac="aa:bb:cc:00:00:01",
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "1.2.3.4"},
            lldp=[_neigh("lan3", mgmt_ip="10.10.10.2", port_id="wan")],
        )
        gw.dhcp_leases = {"aa:bb:cc:00:00:02": {"ip": "10.10.10.2", "hostname": "ap2"}}
        ap = _router(mac="aa:bb:cc:00:00:02")
        rd = [("r1", "10.10.10.1", gw), ("r2", "10.10.10.2", ap)]
        edges = _detect_inter_router_edges([], rd)
        # exactly one edge for the pair, and it is the LLDP router_uplink
        pair_edges = [e for e in edges if {e["from"], e["to"]} == {"r1", "r2"}]
        assert len(pair_edges) == 1
        assert pair_edges[0]["relationship"] == "router_uplink"


# =====================================================================
# Known routers / neighbor matching
# =====================================================================


class TestKnownRouterIndex:
    def test_index_maps_ip_mac_hostname(self):
        rd = [
            ("r1", "10.10.10.1", _router(mac="AA:BB:CC:00:00:01", hostname="gw")),
        ]
        tokens, meta = _build_known_router_index(rd)
        assert tokens["10.10.10.1"] == "r1"
        assert tokens["aa:bb:cc:00:00:01"] == "r1"
        assert tokens["gw"] == "r1"
        assert "aa:bb:cc:00:00:01" in meta["r1"]["macs"]

    def test_match_by_mgmt_ip(self):
        rd = [("r2", "10.10.10.2", _router(mac="aa:bb:cc:00:00:02"))]
        tokens, _ = _build_known_router_index(rd)
        assert _match_lldp_neighbor(_neigh("x", mgmt_ip="10.10.10.2"), tokens) == "r2"

    def test_match_by_chassis_mac_with_separators(self):
        rd = [("r2", "10.10.10.2", _router(mac="aa:bb:cc:00:00:02"))]
        tokens, _ = _build_known_router_index(rd)
        # chassis id reported without separators still matches the normalised MAC
        assert (
            _match_lldp_neighbor(_neigh("x", chassis_id="aabbcc000002"), tokens) == "r2"
        )

    def test_unknown_neighbor_no_match(self):
        rd = [("r1", "10.10.10.1", _router(mac="aa:bb:cc:00:00:01"))]
        tokens, _ = _build_known_router_index(rd)
        assert _match_lldp_neighbor(_neigh("x", mgmt_ip="192.168.99.99"), tokens) is None


# =====================================================================
# build_mesh_snapshot: known router is not rendered as a client
# =====================================================================


def _fake_entry(entry_id: str, host: str, data: OpenWrtCoordinatorData):
    coordinator = SimpleNamespace(data=data, last_update_success=True)
    runtime = SimpleNamespace(coordinator=coordinator)
    return SimpleNamespace(
        entry_id=entry_id,
        data={"host": host},
        options={},
        runtime_data=runtime,
    )


def _fake_hass(entries: list):
    return SimpleNamespace(
        config_entries=SimpleNamespace(async_entries=lambda _domain: entries)
    )


class TestKnownRouterNotClient:
    def test_router_mac_not_listed_as_client(self):
        """A gateway that sees AP2's MAC as a WiFi client must render AP2 as a
        router node, never as an ordinary client."""
        gw = _router(
            mac="aa:bb:cc:00:00:01",
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "1.2.3.4"},
            clients=[{"mac": "AA:BB:CC:00:00:02", "signal": -50, "radio": "phy0-ap0"}],
        )
        ap = _router(mac="aa:bb:cc:00:00:02")
        entries = [
            _fake_entry("e1", "10.10.10.1", gw),
            _fake_entry("e2", "10.10.10.2", ap),
        ]
        snap = build_mesh_snapshot(_fake_hass(entries))
        client_macs = {
            (c.get("mac") or "").lower() for c in snap.get("clients", [])
        }
        assert "aa:bb:cc:00:00:02" not in client_macs
        # And no client-type node carries that MAC either.
        for node in snap.get("nodes", []):
            if node.get("type") == "client":
                assert (
                    node.get("attributes", {}).get("mac", "").lower()
                    != "aa:bb:cc:00:00:02"
                )


# =====================================================================
# LLDP vs. the repeater override and the unmanaged-switch inference
#
# Regression cover for the two ways a `router_uplink` edge used to slip past
# rules that only ever looked at `lan_uplink` / `mesh_member`.
# =====================================================================


class TestLldpAndRepeaterOverride:
    def test_wireless_lldp_link_is_promoted_to_wifi_uplink(self):
        """A repeater running lldpd must not be rendered as "Kabel".

        LLDP also travels over a WDS/4addr backhaul. Before the fix the edge
        kept `relationship=router_uplink`, which the repeater override skipped
        and the panel maps to 'wired'.
        """
        gw = _router(
            mac="aa:bb:cc:00:00:01",
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "1.2.3.4"},
            lldp=[_neigh("wlan0-1", mgmt_ip="10.10.10.5", port_id="wlan1-sta")],
        )
        rp = _router(
            mac="aa:bb:cc:00:00:05",
            sta_interfaces=[_associated_sta()],
            # WAN port without carrier → no physical uplink
            port_stats=[{"name": "wan", "up": False, "speed_mbps": None}],
        )
        router_data = [
            ("r1", "10.10.10.1", gw),
            ("r5", "10.10.10.5", rp),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        e = edges[0]
        assert e["relationship"] == "wifi_uplink"
        assert e["attributes"]["link_type"] == "wifi"
        assert e["attributes"]["ap_port"] is None
        assert e["attributes"]["vlan_tags"] == []
        assert "repeater_override" in e["attributes"]["detection_method"]
        assert "gateway_port" not in e["attributes"]

    def test_wired_lldp_link_outranks_the_sta_heuristic(self):
        """LLDP over copper is first-hand proof of cable.

        The AP has an associated STA interface and no WAN carrier, so the
        heuristic alone would demote it to a WLAN repeater — LLDP says
        otherwise and must win, exactly like a WAN port with carrier.
        """
        gw = _router(
            mac="aa:bb:cc:00:00:01",
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "1.2.3.4"},
            port_vlan_map={"lan3": [10, 20]},
            lldp=[_neigh("lan3", mgmt_ip="10.10.10.4", port_id="lan1")],
        )
        ap = _router(
            mac="aa:bb:cc:00:00:04",
            sta_interfaces=[_associated_sta()],
            port_stats=[{"name": "wan", "up": False, "speed_mbps": None}],
        )
        router_data = [
            ("r1", "10.10.10.1", gw),
            ("r4", "10.10.10.4", ap),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        e = edges[0]
        assert e["relationship"] == "router_uplink"
        assert e["attributes"]["link_type"] == "lan"
        assert e["attributes"]["gateway_port"] == "lan3"
        assert e["attributes"]["vlan_tags"] == [10, 20]
        assert e["attributes"]["detection_method"] == "lldp"


class TestLldpFeedsSwitchInference:
    def test_two_lldp_aps_on_one_port_still_infer_a_switch(self):
        """Two APs behind an unmanaged switch, all speaking LLDP.

        The switch itself has no LLDP, so both APs report the gateway directly
        and both edges carry the same gateway port. Before the fix the switch
        node disappeared as soon as lldpd was installed.
        """
        gw = _router(
            mac="aa:bb:cc:00:00:01",
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "1.2.3.4"},
            trunk_port_map={"lan3": "trunk"},
            lldp=[
                _neigh("lan3", mgmt_ip="10.10.10.2", port_id="lan1"),
                _neigh("lan3", mgmt_ip="10.10.10.4", port_id="lan1"),
            ],
        )
        ap2 = _router(mac="aa:bb:cc:00:00:02")
        ap4 = _router(mac="aa:bb:cc:00:00:04")
        router_data = [
            ("r1", "10.10.10.1", gw),
            ("r2", "10.10.10.2", ap2),
            ("r4", "10.10.10.4", ap4),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(_router_uplinks(edges)) == 2

        nodes, switch_edges, replaced = _detect_switch_nodes(edges, router_data)
        assert [n["type"] for n in nodes] == ["switch"]
        assert nodes[0]["attributes"]["gateway_port"] == "lan3"
        assert nodes[0]["attributes"]["ap_count"] == 2
        # Both direct gateway→AP edges are rerouted through the switch.
        assert len(replaced) == 2
        assert {e["to"] for e in switch_edges if e["from"].startswith("switch:")} == {
            "r2",
            "r4",
        }

    def test_wireless_lldp_link_is_no_switch_candidate(self):
        """A wireless LLDP link carries no gateway port and must be ignored."""
        gw = _router(
            mac="aa:bb:cc:00:00:01",
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "1.2.3.4"},
            trunk_port_map={"lan3": "trunk"},
            lldp=[
                _neigh("wlan0-1", mgmt_ip="10.10.10.2", port_id="wlan1-sta"),
                _neigh("wlan0-1", mgmt_ip="10.10.10.4", port_id="wlan1-sta"),
            ],
        )
        router_data = [
            ("r1", "10.10.10.1", gw),
            ("r2", "10.10.10.2", _router(mac="aa:bb:cc:00:00:02")),
            ("r4", "10.10.10.4", _router(mac="aa:bb:cc:00:00:04")),
        ]
        edges = _detect_inter_router_edges([], router_data)
        nodes, _switch_edges, replaced = _detect_switch_nodes(edges, router_data)
        assert nodes == []
        assert replaced == set()
