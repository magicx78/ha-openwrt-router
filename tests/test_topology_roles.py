"""Tests for mesh role detection, stale routers and LLDP identity (package A12).

C2  A connected WAN makes a gateway; during an outage the gateway of the
    last snapshot keeps its role (role memory), and on a fresh start one
    configured-WAN candidate is picked. DHCP pools are no role evidence:
    OpenWrt's defaults leave them active on dumb APs.
C3  Clients/edges of a router whose last update failed are marked ``stale``
    and lose the client dedupe against any fresh observation.
C7  Hostnames identify an LLDP neighbor only when unique across the fleet;
    the chassis MAC is matched before the chassis name.
C12 Duplicate LLDP observations of one router pair are deterministic and
    flagged; every gateway gets the WAN/ping/DDNS enrichment.
"""
from __future__ import annotations

from types import SimpleNamespace

from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
from custom_components.openwrt_router.topology_mesh import (
    _build_known_router_index,
    _deduplicate_clients,
    _detect_inter_router_edges,
    _detect_router_role,
    _match_lldp_neighbor,
    _resolve_router_roles,
    build_mesh_snapshot,
)

GW_MAC = "02:00:00:00:00:01"
AP_MAC = "02:00:00:00:00:02"
AP2_MAC = "02:00:00:00:00:03"
CLIENT_MAC = "02:00:00:00:aa:01"

GW_IP = "192.0.2.1"
AP_IP = "192.0.2.2"
AP2_IP = "192.0.2.3"

LAN_POOL = {"name": "lan", "interface": "lan", "size": 150, "leases": 3, "usage_pct": 2.0}


def _router(
    mac: str,
    hostname: str = "",
    *,
    wan_status: dict | None = None,
    dhcp_pools: list | None = None,
    network_interfaces: list | None = None,
    dhcp_leases: dict | None = None,
    clients: list | None = None,
    ap_interfaces: list | None = None,
    lldp: list | None = None,
) -> OpenWrtCoordinatorData:
    data = OpenWrtCoordinatorData()
    data.router_info = {"mac": mac, "hostname": hostname}
    data.wan_status = wan_status or {}
    data.wan_connected = bool((wan_status or {}).get("connected"))
    data.dhcp_pools = dhcp_pools or []
    data.network_interfaces = network_interfaces or []
    data.dhcp_leases = dhcp_leases or {}
    data.clients = clients or []
    data.ap_interfaces = ap_interfaces or []
    data.lldp_neighbors = lldp or []
    return data


def _lan_iface(ip: str) -> dict:
    return {"logical_name": "lan", "interface": "br-lan", "ipv4_addr": ip, "prefix_len": 24}


def _wan_down(proto: str = "pppoe") -> dict:
    """A configured WAN whose link is down (outage)."""
    return {
        "connected": False,
        "interface": "wan",
        "ipv4": "",
        "proto": proto,
        "wan_found": True,
    }


def _wan_up(ipv4: str = "198.51.100.7") -> dict:
    return {
        "connected": True,
        "interface": "wan",
        "ipv4": ipv4,
        "proto": "dhcp",
        "wan_found": True,
    }


NO_WAN = {"connected": False, "interface": "", "ipv4": "", "proto": "", "wan_found": False}
# api._get_wan_status_ssh: no interface/proto, only the link state.
SSH_CONNECTED = {"connected": True, "interface": "", "ipv4": "", "proto": ""}


def _neigh(local_interface: str, **kw: object) -> dict:
    return {
        "local_interface": local_interface,
        "chassis_id": kw.get("chassis_id", ""),
        "chassis_name": kw.get("chassis_name"),
        "management_ip": kw.get("mgmt_ip"),
        "port_id": kw.get("port_id", ""),
        "port_descr": "",
        "capabilities": [],
    }


def _fake_entry(entry_id: str, host: str, data: OpenWrtCoordinatorData, *, online: bool = True):
    coordinator = SimpleNamespace(data=data, last_update_success=online)
    return SimpleNamespace(
        entry_id=entry_id,
        data={"host": host},
        options={},
        runtime_data=SimpleNamespace(coordinator=coordinator),
    )


def _fake_hass(entries: list):
    return SimpleNamespace(
        config_entries=SimpleNamespace(async_entries=lambda _domain: entries)
    )


def _router_node(snap: dict, rid: str) -> dict:
    return next(n for n in snap["nodes"] if n.get("type") == "router" and n["id"] == rid)


# =====================================================================
# C2 — role detection
# =====================================================================


class TestGatewayRoleSurvivesWanOutage:
    def test_single_router_wan_down_is_still_gateway(self):
        data = _router(GW_MAC, wan_status=_wan_down())
        assert _detect_router_role(data, GW_IP) == "gateway"

    def test_lan_dhcp_pool_without_wan_is_not_gateway(self):
        data = _router(
            GW_MAC,
            wan_status=NO_WAN,
            dhcp_pools=[LAN_POOL],
            network_interfaces=[_lan_iface(GW_IP)],
        )
        assert _detect_router_role(data, GW_IP) == "ap"

    def test_lan_dhcp_pool_does_not_beat_id_tie_break(self):
        """Default dumb AP: leftover dhcp wan AND an un-ignored lan pool. The
        pool adds nothing — the outage pick is the same as without it."""
        ap = _router(
            GW_MAC,
            wan_status=_wan_down("dhcp"),
            dhcp_pools=[LAN_POOL],
            network_interfaces=[_lan_iface(GW_IP)],
        )
        gw = _router(AP2_MAC, wan_status=_wan_down("pppoe"))
        roles = _resolve_router_roles([(GW_MAC, GW_IP, ap), (AP2_MAC, AP2_IP, gw)])
        assert roles == {GW_MAC: "ap", AP2_MAC: "gateway"}

    def test_guest_only_dhcp_pool_does_not_make_gateway(self):
        """A dumb AP serving only its guest network stays an AP."""
        data = _router(
            AP_MAC,
            wan_status=NO_WAN,
            dhcp_pools=[{"name": "guest", "interface": "guest", "size": 50}],
            network_interfaces=[
                _lan_iface(AP_IP),
                {"logical_name": "guest", "ipv4_addr": "203.0.113.1", "prefix_len": 24},
            ],
        )
        assert _detect_router_role(data, AP_IP) == "ap"

    def test_dumb_ap_without_wan_and_dhcp_is_ap(self):
        data = _router(AP_MAC, wan_status=NO_WAN)
        assert _detect_router_role(data, AP_IP) == "ap"

    def test_outage_gateway_keeps_edges_next_to_ap_with_leftover_wan(self):
        """Fresh start during an outage: the pppoe gateway is picked over a
        dumb AP with a left-over dhcp WAN; the uplink edge is still built."""
        gw = _router(
            GW_MAC,
            wan_status=_wan_down(),
            dhcp_pools=[LAN_POOL],
            network_interfaces=[_lan_iface(GW_IP)],
            dhcp_leases={AP_MAC.upper(): {"ip": AP_IP, "hostname": "ap"}},
        )
        ap = _router(AP_MAC, wan_status=_wan_down("dhcp"))
        router_data = [(GW_MAC, GW_IP, gw), (AP_MAC, AP_IP, ap)]
        assert _resolve_router_roles(router_data) == {GW_MAC: "gateway", AP_MAC: "ap"}
        edges = _detect_inter_router_edges([], router_data)
        assert [(e["from"], e["to"]) for e in edges] == [(GW_MAC, AP_MAC)]

    def test_leftover_wan_ap_stays_ap_next_to_connected_gateway(self):
        gw = _router(GW_MAC, wan_status=_wan_up())
        ap = _router(AP_MAC, wan_status=_wan_down("dhcp"))
        roles = _resolve_router_roles([(GW_MAC, GW_IP, gw), (AP_MAC, AP_IP, ap)])
        assert roles == {GW_MAC: "gateway", AP_MAC: "ap"}

    def test_outage_snapshot_keeps_gateway_role_and_enrichment(self):
        gw = _router(
            GW_MAC,
            "gw",
            wan_status=_wan_down(),
            dhcp_pools=[LAN_POOL],
            network_interfaces=[_lan_iface(GW_IP)],
            dhcp_leases={AP_MAC.upper(): {"ip": AP_IP, "hostname": "ap"}},
        )
        ap = _router(AP_MAC, "ap", wan_status=NO_WAN)
        snap = build_mesh_snapshot(
            _fake_hass([_fake_entry("e1", GW_IP, gw), _fake_entry("e2", AP_IP, ap)])
        )
        gw_node = _router_node(snap, GW_MAC)
        assert gw_node["role"] == "gateway"
        assert "ping_ms" in gw_node["attributes"]
        assert _router_node(snap, AP_MAC)["role"] == "ap"
        assert any(
            e["from"] == GW_MAC and e["to"] == AP_MAC for e in snap["edges"]
        )


class TestLegacyWanStatusWithoutWanFound:
    def test_connected_legacy_is_gateway(self):
        data = _router(
            GW_MAC,
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "198.51.100.7"},
        )
        assert _detect_router_role(data, GW_IP) == "gateway"

    def test_ssh_fallback_shape_is_ap(self):
        """SSH fallback: no interface, no proto, not connected → AP."""
        data = _router(AP_MAC, wan_status={"connected": False, "proto": "", "interface": ""})
        assert _detect_router_role(data, AP_IP) == "ap"

    def test_ssh_fallback_connected_alone_is_gateway(self):
        """SSH fallback reports connected=True but no proto: the only
        candidate of the fleet is promoted, otherwise there is no gateway."""
        data = _router(GW_MAC, wan_status=SSH_CONNECTED)
        assert _detect_router_role(data, GW_IP) == "gateway"

    def test_ssh_fallback_connected_next_to_real_gateway_is_ap(self):
        """The SSH script's ``connected`` may only mean "internet reachable",
        which a dumb AP is too — it never competes with a ubus gateway."""
        gw = _router(GW_MAC, wan_status=_wan_up())
        ssh = _router(AP_MAC, wan_status=SSH_CONNECTED)
        roles = _resolve_router_roles([(GW_MAC, GW_IP, gw), (AP_MAC, AP_IP, ssh)])
        assert roles == {GW_MAC: "gateway", AP_MAC: "ap"}

    def test_remembered_ubus_gateway_beats_ssh_tier(self):
        gw = _router(GW_MAC, wan_status=_wan_down("pppoe"))
        ssh = _router(AP_MAC, wan_status=SSH_CONNECTED)
        roles = _resolve_router_roles(
            [(GW_MAC, GW_IP, gw), (AP_MAC, AP_IP, ssh)], remembered={GW_MAC}
        )
        assert roles == {GW_MAC: "gateway", AP_MAC: "ap"}

    def test_ssh_tier_gateway_is_not_remembered(self):
        import custom_components.openwrt_router.topology_mesh as mesh

        ssh = _router(GW_MAC, "ssh", wan_status=SSH_CONNECTED)
        build_mesh_snapshot(_fake_hass([_fake_entry("e1", GW_IP, ssh)]))
        assert mesh._GATEWAY_MEMORY == {}

    def test_ssh_fallback_disconnected_next_to_ubus_gateway_is_ap(self):
        gw = _router(GW_MAC, wan_status=_wan_up())
        ssh = _router(AP_MAC, wan_status={**SSH_CONNECTED, "connected": False})
        roles = _resolve_router_roles([(GW_MAC, GW_IP, gw), (AP_MAC, AP_IP, ssh)])
        assert roles == {GW_MAC: "gateway", AP_MAC: "ap"}

    def test_two_connected_ssh_fallback_routers_promote_lowest_id(self):
        r1 = _router(GW_MAC, wan_status=SSH_CONNECTED)
        r2 = _router(AP_MAC, wan_status=SSH_CONNECTED)
        for rd in (
            [(GW_MAC, GW_IP, r1), (AP_MAC, AP_IP, r2)],
            [(AP_MAC, AP_IP, r2), (GW_MAC, GW_IP, r1)],
        ):
            assert _resolve_router_roles(rd) == {GW_MAC: "gateway", AP_MAC: "ap"}

    def test_ssh_gateway_beats_dumb_ap_with_leftover_wan(self):
        """SSH-fallback gateway (no pools, WAN up) vs. a dumb AP keeping the
        default dhcp wan section unplugged — and having the lower id."""
        ssh_gw = _router(AP2_MAC, wan_status=SSH_CONNECTED)
        ap = _router(GW_MAC, wan_status=_wan_down("dhcp"))
        roles = _resolve_router_roles([(GW_MAC, GW_IP, ap), (AP2_MAC, AP2_IP, ssh_gw)])
        assert roles == {GW_MAC: "ap", AP2_MAC: "gateway"}

    def test_legacy_bridged_wan_with_host_ip_is_ap(self):
        data = _router(
            AP_MAC, wan_status={"connected": True, "proto": "static", "ipv4": AP_IP}
        )
        assert _detect_router_role(data, AP_IP) == "ap"


# =====================================================================
# C3 — stale observations
# =====================================================================


class TestStaleClientDedupe:
    def test_fresh_beats_stale_with_better_signal(self):
        stale = {"mac": CLIENT_MAC, "ap_mac": AP_MAC, "signal": -40, "stale": True}
        fresh = {"mac": CLIENT_MAC, "ap_mac": AP2_MAC, "signal": -75}
        for order in ([stale, fresh], [fresh, stale]):
            (winner,) = _deduplicate_clients(order)
            assert winner["ap_mac"] == AP2_MAC

    def test_stale_only_observation_is_kept(self):
        stale = {"mac": CLIENT_MAC, "ap_mac": AP_MAC, "signal": -40, "stale": True}
        assert _deduplicate_clients([stale]) == [stale]

    def test_snapshot_assigns_client_to_live_ap(self):
        gw = _router(GW_MAC, "gw", wan_status=_wan_up())
        off_ap = _router(
            AP_MAC,
            "ap-off",
            wan_status=NO_WAN,
            ap_interfaces=[{"ifname": "phy0-ap0", "ssid": "net", "band": "5g"}],
            clients=[
                {"mac": CLIENT_MAC, "signal": -40, "radio": "phy0-ap0"},
                {"mac": "02:00:00:00:aa:02", "signal": -50, "radio": "phy0-ap0"},
            ],
        )
        live_ap = _router(
            AP2_MAC,
            "ap-live",
            wan_status=NO_WAN,
            clients=[{"mac": CLIENT_MAC, "signal": -78, "radio": "phy0-ap0"}],
        )
        snap = build_mesh_snapshot(
            _fake_hass(
                [
                    _fake_entry("e1", GW_IP, gw),
                    _fake_entry("e2", AP_IP, off_ap, online=False),
                    _fake_entry("e3", AP2_IP, live_ap),
                ]
            )
        )
        clients = {c["mac"]: c for c in snap["clients"]}
        assert clients[CLIENT_MAC]["ap_mac"] == AP2_MAC
        assert not clients[CLIENT_MAC].get("stale")
        # A client only the offline AP still reports is kept, but stale.
        assert clients["02:00:00:00:aa:02"]["stale"] is True

        nodes = {n["id"]: n for n in snap["nodes"] if n.get("type") == "client"}
        assert nodes[f"client:{CLIENT_MAC}"]["attributes"]["ap_mac"] == AP2_MAC
        assert nodes["client:02:00:00:00:aa:02"]["attributes"]["stale"] is True

        off_edges = [
            e for e in snap["edges"] if e["from"].startswith(f"iface:{AP_MAC}:")
        ]
        assert off_edges and all(e.get("stale") is True for e in off_edges)
        # The roamed client keeps exactly one has_client edge: the live AP's.
        client_edges = [
            e
            for e in snap["edges"]
            if e.get("relationship") == "has_client"
            and e["to"] == f"client:{CLIENT_MAC}"
        ]
        assert [e["from"] for e in client_edges] == [AP2_MAC]
        live_edges = [e for e in snap["edges"] if e["from"] == AP2_MAC]
        assert live_edges and not any(e.get("stale") for e in live_edges)


# =====================================================================
# C7 — hostname collisions
# =====================================================================


class TestHostnameCollision:
    def _fleet(self) -> list:
        gw = _router(
            GW_MAC,
            "OpenWrt",
            wan_status=_wan_up(),
            lldp=[
                _neigh("lan1", chassis_name="OpenWrt", chassis_id=AP_MAC, port_id="wan"),
                _neigh("lan2", chassis_name="OpenWrt", chassis_id=AP2_MAC, port_id="wan"),
            ],
        )
        ap = _router(AP_MAC, "OpenWrt")
        ap2 = _router(AP2_MAC, "OpenWrt")
        return [(GW_MAC, GW_IP, gw), (AP_MAC, AP_IP, ap), (AP2_MAC, AP2_IP, ap2)]

    def test_duplicate_hostname_not_indexed(self):
        tokens, _meta = _build_known_router_index(self._fleet())
        assert "openwrt" not in tokens

    def test_chassis_mac_wins_over_chassis_name(self):
        tokens = {"openwrt": GW_MAC, AP_MAC: AP_MAC}
        neigh = _neigh("lan1", chassis_name="OpenWrt", chassis_id=AP_MAC)
        assert _match_lldp_neighbor(neigh, tokens) == AP_MAC

    def test_three_same_named_routers_match_via_chassis_mac(self):
        edges = _detect_inter_router_edges([], self._fleet())
        lldp = {
            (e["from"], e["to"]): e
            for e in edges
            if e["attributes"].get("detection_method") == "lldp"
        }
        assert set(lldp) == {(GW_MAC, AP_MAC), (GW_MAC, AP2_MAC)}
        assert lldp[(GW_MAC, AP_MAC)]["attributes"]["from_port"] == "lan1"
        assert lldp[(GW_MAC, AP2_MAC)]["attributes"]["from_port"] == "lan2"


# =====================================================================
# C12 — duplicate LLDP observations, every gateway enriched
# =====================================================================


class TestLldpDuplicateObservation:
    def _edges(self, neighbors: list) -> list:
        gw = _router(GW_MAC, "gw", wan_status=_wan_up(), lldp=neighbors)
        ap = _router(AP_MAC, "ap")
        return _detect_inter_router_edges([], [(GW_MAC, GW_IP, gw), (AP_MAC, AP_IP, ap)])

    def test_double_observation_is_deterministic_and_flagged(self):
        first = _neigh("lan1", mgmt_ip=AP_IP, port_id="wan")
        second = _neigh("lan2", mgmt_ip=AP_IP, port_id="lan4")
        results = []
        for order in ([first, second], [second, first]):
            edges = [e for e in self._edges(order) if e["relationship"] == "router_uplink"]
            assert len(edges) == 1
            results.append(edges[0]["attributes"])
        for attrs in results:
            assert attrs["from_port"] == "lan1"
            dupes = attrs["lldp_duplicates"]
            assert len(dupes) == 1
            assert dupes[0]["observer"] == GW_MAC
            assert dupes[0]["local_port"] == "lan2"
        assert results[0] == results[1]

    def test_single_observation_has_no_duplicate_field(self):
        edges = self._edges([_neigh("lan1", mgmt_ip=AP_IP, port_id="wan")])
        assert "lldp_duplicates" not in edges[0]["attributes"]


class TestEveryGatewayEnriched:
    def test_two_gateways_both_enriched(self):
        gw1 = _router(GW_MAC, "gw1", wan_status=_wan_up("198.51.100.7"))
        gw2 = _router(AP_MAC, "gw2", wan_status=_wan_up("198.51.100.8"))
        gw1.ping_ms = 11.0
        gw2.ping_ms = 22.0
        snap = build_mesh_snapshot(
            _fake_hass([_fake_entry("e1", GW_IP, gw1), _fake_entry("e2", AP_IP, gw2)])
        )
        assert _router_node(snap, GW_MAC)["attributes"]["ping_ms"] == 11.0
        assert _router_node(snap, AP_MAC)["attributes"]["ping_ms"] == 22.0


# =====================================================================
# Review follow-ups: P1, P2.1, P2.3, P3.1
# =====================================================================


def _wan_port(up: bool) -> list:
    return [{"name": "wan", "up": up}]


class TestDumbApWithLanDhcpPool:
    """P1: a dumb AP without WAN whose lan pool was not set to ignore."""

    def _ap(self) -> OpenWrtCoordinatorData:
        return _router(
            AP_MAC,
            "ap",
            wan_status=NO_WAN,
            dhcp_pools=[LAN_POOL],
            network_interfaces=[_lan_iface(AP_IP)],
        )

    def test_stays_ap_next_to_connected_gateway(self):
        gw = _router(GW_MAC, "gw", wan_status=_wan_up())
        roles = _resolve_router_roles([(GW_MAC, GW_IP, gw), (AP_MAC, AP_IP, self._ap())])
        assert roles == {GW_MAC: "gateway", AP_MAC: "ap"}

    def test_stays_ap_next_to_outage_gateway_on_first_poll(self):
        """Poll 1: the gateway has no dhcp_pools yet, its WAN is down."""
        gw = _router(GW_MAC, "gw", wan_status=_wan_down())
        roles = _resolve_router_roles([(GW_MAC, GW_IP, gw), (AP_MAC, AP_IP, self._ap())])
        assert roles == {GW_MAC: "gateway", AP_MAC: "ap"}

    def test_builds_no_uplink_from_the_ap(self):
        gw = _router(GW_MAC, "gw", wan_status=_wan_up())
        ap = self._ap()
        ap.dhcp_leases = {GW_MAC.upper(): {"ip": GW_IP, "hostname": "gw"}}
        edges = _detect_inter_router_edges([], [(GW_MAC, GW_IP, gw), (AP_MAC, AP_IP, ap)])
        assert not any(e["from"] == AP_MAC for e in edges)


class TestSingleWeakGateway:
    """P2.1: poll 1 of an outage — only weak candidates, at most one wins."""

    def test_port_stats_up_flag_is_not_a_tie_break(self):
        """``port_stats[].up`` is netifd's device-active flag, not carrier."""
        gw = _router(AP2_MAC, "gw", wan_status=_wan_down("dhcp"))
        gw.port_stats = _wan_port(True)
        ap = _router(GW_MAC, "ap", wan_status=_wan_down("dhcp"))
        ap.port_stats = _wan_port(False)
        roles = _resolve_router_roles([(GW_MAC, GW_IP, ap), (AP2_MAC, AP2_IP, gw)])
        assert roles == {GW_MAC: "gateway", AP2_MAC: "ap"}

    def test_default_wan6_dhcpv6_counts_as_default_proto(self):
        gw = _router(AP2_MAC, "gw", wan_status=_wan_down("static"))
        ap = _router(GW_MAC, "ap", wan_status=_wan_down("dhcpv6"))
        roles = _resolve_router_roles([(GW_MAC, GW_IP, ap), (AP2_MAC, AP2_IP, gw)])
        assert roles == {GW_MAC: "ap", AP2_MAC: "gateway"}

    def test_deliberate_proto_wins_over_default_dhcp(self):
        gw = _router(AP2_MAC, "gw", wan_status=_wan_down("pppoe"))
        ap = _router(GW_MAC, "ap", wan_status=_wan_down("dhcp"))
        roles = _resolve_router_roles([(GW_MAC, GW_IP, ap), (AP2_MAC, AP2_IP, gw)])
        assert roles == {GW_MAC: "ap", AP2_MAC: "gateway"}

    def test_full_tie_picks_lowest_id_in_any_order(self):
        r1 = _router(GW_MAC, wan_status=_wan_down("dhcp"))
        r2 = _router(AP_MAC, wan_status=_wan_down("dhcp"))
        for rd in (
            [(GW_MAC, GW_IP, r1), (AP_MAC, AP_IP, r2)],
            [(AP_MAC, AP_IP, r2), (GW_MAC, GW_IP, r1)],
        ):
            assert _resolve_router_roles(rd) == {GW_MAC: "gateway", AP_MAC: "ap"}


class TestDualGatewayUplinks:
    """P2.3: two gateways see the same AP (and each other) in DHCP/ARP."""

    def _fleet(self, first_connected: bool = True) -> list:
        leases = {
            AP2_MAC.upper(): {"ip": AP2_IP, "hostname": "ap"},
        }
        gw1 = _router(
            GW_MAC,
            "gw1",
            wan_status=_wan_up() if first_connected else _wan_down(),
            dhcp_pools=[LAN_POOL],
            network_interfaces=[_lan_iface(GW_IP)],
            dhcp_leases={**leases, AP_MAC.upper(): {"ip": AP_IP, "hostname": "gw2"}},
        )
        gw1.trunk_port_map = {AP2_IP: "lan1", AP_IP: "lan2"}
        gw2 = _router(AP_MAC, "gw2", wan_status=_wan_up("198.51.100.8"), dhcp_leases=leases)
        gw2.trunk_port_map = {AP2_IP: "lan3"}
        ap = _router(AP2_MAC, "ap", wan_status=NO_WAN)
        return [(GW_MAC, GW_IP, gw1), (AP_MAC, AP_IP, gw2), (AP2_MAC, AP2_IP, ap)]

    def test_ap_gets_one_uplink_and_gateways_none(self):
        edges = _detect_inter_router_edges([], self._fleet())
        into_ap = [e for e in edges if e["to"] == AP2_MAC]
        assert [e["from"] for e in into_ap] == [GW_MAC]
        assert not any(e["to"] == AP_MAC for e in edges)

    def test_connected_gateway_is_preferred_over_outage(self):
        """Both are gateways (e.g. from role memory); the connected one
        claims the AP."""
        roles = {GW_MAC: "gateway", AP_MAC: "gateway", AP2_MAC: "ap"}
        edges = _detect_inter_router_edges([], self._fleet(first_connected=False), roles)
        into_ap = [e for e in edges if e["to"] == AP2_MAC]
        assert [e["from"] for e in into_ap] == [AP_MAC]

    def test_outage_gateway_is_ap_while_another_is_strong(self):
        roles = _resolve_router_roles(self._fleet(first_connected=False))
        assert roles == {GW_MAC: "ap", AP_MAC: "gateway", AP2_MAC: "ap"}


class TestRolesResolvedOnce:
    """P3.1: build_mesh_snapshot resolves the fleet roles exactly once."""

    def test_single_resolution(self, monkeypatch):
        import custom_components.openwrt_router.topology_mesh as mesh

        calls = []
        real = mesh._resolve_router_roles

        def _counting(router_data, *args, **kwargs):
            calls.append(1)
            return real(router_data, *args, **kwargs)

        monkeypatch.setattr(mesh, "_resolve_router_roles", _counting)
        gw = _router(
            GW_MAC,
            "gw",
            wan_status=_wan_up(),
            lldp=[_neigh("lan1", mgmt_ip=AP_IP, port_id="wan")],
        )
        gw.trunk_port_map = {AP_IP: "lan1"}
        ap = _router(AP_MAC, "ap", wan_status=NO_WAN)
        mesh.build_mesh_snapshot(
            _fake_hass([_fake_entry("e1", GW_IP, gw), _fake_entry("e2", AP_IP, ap)])
        )
        assert len(calls) == 1


class TestGatewayMemory:
    """Round 3: the gateway of the last snapshot survives a WAN outage."""

    def _snap(self, *routers) -> dict:
        entries = [_fake_entry(f"e{i}", ip, data) for i, (ip, data) in enumerate(routers)]
        return build_mesh_snapshot(_fake_hass(entries))

    def _roles(self, snap: dict) -> dict:
        return {n["id"]: n["role"] for n in snap["nodes"] if n.get("type") == "router"}

    def test_gateway_keeps_role_when_its_wan_drops(self):
        # The real gateway has the HIGHER id and the same default proto as
        # the dumb AP, so without memory the tie-break would pick the AP.
        gw = _router(AP2_MAC, "gw", wan_status=_wan_up())
        ap = _router(GW_MAC, "ap", wan_status=_wan_down("dhcp"))
        assert self._roles(self._snap((AP2_IP, gw), (GW_IP, ap))) == {
            AP2_MAC: "gateway",
            GW_MAC: "ap",
        }
        gw.wan_status = _wan_down("dhcp")
        snap = self._snap((AP2_IP, gw), (GW_IP, ap))
        assert self._roles(snap) == {AP2_MAC: "gateway", GW_MAC: "ap"}
        assert "ping_ms" in _router_node(snap, AP2_MAC)["attributes"]

    def test_memory_is_replaced_by_the_current_strong_set(self):
        r1 = _router(GW_MAC, "r1", wan_status=_wan_up())
        r2 = _router(AP_MAC, "r2", wan_status=_wan_down("pppoe"))
        self._snap((GW_IP, r1), (AP_IP, r2))
        # r2 comes up, r1 goes down: r2 is strong, r1 is forgotten ...
        r1.wan_status = _wan_down("pppoe")
        r2.wan_status = _wan_up("198.51.100.8")
        assert self._roles(self._snap((GW_IP, r1), (AP_IP, r2))) == {
            GW_MAC: "ap",
            AP_MAC: "gateway",
        }
        # ... so when both are down, r2 (remembered) stays gateway.
        r2.wan_status = _wan_down("pppoe")
        assert self._roles(self._snap((GW_IP, r1), (AP_IP, r2))) == {
            GW_MAC: "ap",
            AP_MAC: "gateway",
        }

    def test_remembered_router_without_wan_is_not_kept(self):
        r1 = _router(GW_MAC, "r1", wan_status=_wan_up())
        r2 = _router(AP_MAC, "r2", wan_status=_wan_down("dhcp"))
        self._snap((GW_IP, r1), (AP_IP, r2))
        r1.wan_status = NO_WAN
        assert self._roles(self._snap((GW_IP, r1), (AP_IP, r2))) == {
            GW_MAC: "ap",
            AP_MAC: "gateway",
        }

    def test_remembered_gateway_blocks_other_candidates(self):
        roles = _resolve_router_roles(
            [
                (GW_MAC, GW_IP, _router(GW_MAC, wan_status=_wan_down("pppoe"))),
                (AP_MAC, AP_IP, _router(AP_MAC, wan_status=_wan_down("dhcp"))),
            ],
            remembered={AP_MAC},
        )
        assert roles == {GW_MAC: "ap", AP_MAC: "gateway"}

    def test_two_strong_gateways_are_both_remembered(self):
        import custom_components.openwrt_router.topology_mesh as mesh

        r1 = _router(GW_MAC, "r1", wan_status=_wan_up())
        r2 = _router(AP_MAC, "r2", wan_status=_wan_up("198.51.100.8"))
        assert self._roles(self._snap((GW_IP, r1), (AP_IP, r2))) == {
            GW_MAC: "gateway",
            AP_MAC: "gateway",
        }
        assert set(mesh._GATEWAY_MEMORY) == {GW_MAC, AP_MAC}
        r1.wan_status = _wan_down("dhcp")
        r2.wan_status = _wan_down("dhcp")
        assert self._roles(self._snap((GW_IP, r1), (AP_IP, r2))) == {
            GW_MAC: "gateway",
            AP_MAC: "gateway",
        }
