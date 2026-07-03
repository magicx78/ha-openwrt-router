"""Tests for topology_mesh.py — Multi-router mesh topology aggregator."""
from __future__ import annotations

import pytest

from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
from custom_components.openwrt_router.topology_mesh import (
    _deduplicate_clients,
    _detect_inter_router_edges,
    _detect_router_role,
    _has_active_sta_interface,
    _is_private_ip,
)


def _make_data(
    router_info: dict | None = None,
    wan_status: dict | None = None,
    wan_connected: bool = False,
    clients: list | None = None,
    dhcp_leases: dict | None = None,
    sta_interfaces: list | None = None,
    port_vlan_map: dict | None = None,
    port_fdb_map: dict | None = None,
    trunk_port_map: dict | None = None,
    port_stats: list | None = None,
) -> OpenWrtCoordinatorData:
    """Create minimal OpenWrtCoordinatorData for mesh tests."""
    data = OpenWrtCoordinatorData()
    data.router_info = router_info or {}
    data.wan_status = wan_status or {}
    data.wan_connected = wan_connected
    data.clients = clients or []
    data.dhcp_leases = dhcp_leases or {}
    data.sta_interfaces = sta_interfaces or []
    data.port_vlan_map = port_vlan_map or {}
    data.port_fdb_map = port_fdb_map or {}
    data.trunk_port_map = trunk_port_map or {}
    data.port_stats = port_stats or []
    return data


# =====================================================================
# _is_private_ip
# =====================================================================

class TestIsPrivateIp:
    def test_private_10(self):
        assert _is_private_ip("10.10.10.1") is True

    def test_private_192(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_public(self):
        assert _is_private_ip("185.220.100.1") is False

    def test_invalid(self):
        assert _is_private_ip("not-an-ip") is True

    def test_empty(self):
        assert _is_private_ip("") is True


# =====================================================================
# _detect_router_role
# =====================================================================

class TestDetectRouterRole:
    def test_gateway_with_public_wan_ip(self):
        """Gateway: WAN connected + dhcp proto + public IP."""
        data = _make_data(
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.220.100.1"},
            wan_connected=True,
        )
        assert _detect_router_role(data, "10.10.10.1") == "gateway"

    def test_gateway_with_different_private_wan_ip(self):
        """Gateway: WAN IP differs from host LAN IP (even if private)."""
        data = _make_data(
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "172.16.1.71"},
            wan_connected=True,
        )
        assert _detect_router_role(data, "10.10.10.1") == "gateway"

    def test_ap_no_wan(self):
        """AP: WAN not connected."""
        data = _make_data(
            wan_status={"connected": False, "proto": "none"},
            wan_connected=False,
        )
        assert _detect_router_role(data, "10.10.10.2") == "ap"

    def test_ap_empty_wan(self):
        """AP: Empty WAN status."""
        data = _make_data()
        assert _detect_router_role(data, "10.10.10.3") == "ap"

    def test_ap_wan_connected_but_same_ip(self):
        """AP: WAN says connected but IP equals host IP (loopback-like)."""
        data = _make_data(
            wan_status={"connected": True, "proto": "static", "ipv4": "10.10.10.2"},
            wan_connected=True,
        )
        assert _detect_router_role(data, "10.10.10.2") == "ap"

    def test_ap_wan_no_proto(self):
        """AP: WAN connected but proto not a WAN type."""
        data = _make_data(
            wan_status={"connected": True, "proto": "none", "ipv4": "10.10.10.2"},
            wan_connected=True,
        )
        assert _detect_router_role(data, "10.10.10.2") == "ap"

    def test_gateway_pppoe(self):
        """Gateway: PPPoE connection."""
        data = _make_data(
            wan_status={"connected": True, "proto": "pppoe", "ipv4": "95.90.100.1"},
            wan_connected=True,
        )
        assert _detect_router_role(data, "10.10.10.1") == "gateway"


# =====================================================================
# _detect_inter_router_edges
# =====================================================================

class TestDetectInterRouterEdges:
    def test_dhcp_ip_match(self):
        """Gateway's DHCP leases contain AP's host IP → LAN uplink edge."""
        gw_data = _make_data(
            router_info={"mac": "AA:BB:CC:DD:EE:01", "hostname": "gateway"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={
                "AA:BB:CC:DD:EE:02": {"ip": "10.10.10.2", "hostname": "ap2"},
            },
        )
        ap_data = _make_data(
            router_info={"mac": "AA:BB:CC:DD:EE:02", "hostname": "ap2"},
        )
        router_data = [
            ("AA:BB:CC:DD:EE:01", "10.10.10.1", gw_data),
            ("AA:BB:CC:DD:EE:02", "10.10.10.2", ap_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        assert edges[0]["relationship"] == "lan_uplink"
        assert edges[0]["from"] == "AA:BB:CC:DD:EE:01"
        assert edges[0]["to"] == "AA:BB:CC:DD:EE:02"

    def test_dhcp_mac_match(self):
        """Gateway's DHCP leases contain AP's MAC → LAN uplink edge."""
        gw_data = _make_data(
            router_info={"mac": "GW:00:00:00:00:01"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={
                "AP:00:00:00:00:02": {"ip": "10.10.10.99", "hostname": "ap2"},
            },
        )
        ap_data = _make_data(
            router_info={"mac": "AP:00:00:00:00:02"},
        )
        router_data = [
            ("GW:00:00:00:00:01", "10.10.10.1", gw_data),
            ("AP:00:00:00:00:02", "10.10.10.2", ap_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        assert edges[0]["relationship"] == "lan_uplink"

    def test_wifi_client_cross_reference(self):
        """AP's MAC appears as WiFi client on another router → WiFi uplink."""
        router1_data = _make_data(
            router_info={"mac": "R1:00:00:00:00:01"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            clients=[
                {"mac": "R2:00:00:00:00:02", "signal": -55, "radio": "phy0-ap0"},
            ],
        )
        router2_data = _make_data(
            router_info={"mac": "R2:00:00:00:00:02"},
        )
        router_data = [
            ("R1:00:00:00:00:01", "10.10.10.1", router1_data),
            ("R2:00:00:00:00:02", "10.10.10.2", router2_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        wifi_edges = [e for e in edges if e["relationship"] == "wifi_uplink"]
        assert len(wifi_edges) == 1
        assert wifi_edges[0]["from"] == "R1:00:00:00:00:01"
        assert wifi_edges[0]["to"] == "R2:00:00:00:00:02"
        assert wifi_edges[0]["attributes"]["signal"] == -55

    def test_subnet_fallback(self):
        """Unconnected AP on same subnet → mesh_member (inferred)."""
        gw_data = _make_data(
            router_info={"mac": "GW:MAC"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={},
        )
        ap_data = _make_data(
            router_info={"mac": "AP:MAC"},
        )
        router_data = [
            ("GW:MAC", "10.10.10.1", gw_data),
            ("AP:MAC", "10.10.10.5", ap_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        assert edges[0]["relationship"] == "mesh_member"
        assert edges[0]["inferred"] is True

    def test_no_duplicate_edges(self):
        """Same AP found via both DHCP and WiFi → only one edge."""
        gw_data = _make_data(
            router_info={"mac": "GW:00"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={
                "AP:00": {"ip": "10.10.10.2", "hostname": "ap2"},
            },
            clients=[
                {"mac": "AP:00", "signal": -60, "radio": "phy0-ap0"},
            ],
        )
        ap_data = _make_data(router_info={"mac": "AP:00"})
        router_data = [
            ("GW:00", "10.10.10.1", gw_data),
            ("AP:00", "10.10.10.2", ap_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        # DHCP match wins (checked first), WiFi is skipped due to seen_edges
        assert len(edges) == 1

    def test_multiple_aps(self):
        """Gateway with 3 APs → 3 uplink edges."""
        gw_data = _make_data(
            router_info={"mac": "GW:00"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={
                "AP:01": {"ip": "10.10.10.2", "hostname": "ap2"},
                "AP:02": {"ip": "10.10.10.3", "hostname": "ap3"},
                "AP:03": {"ip": "10.10.10.4", "hostname": "ap4"},
            },
        )
        router_data = [
            ("GW:00", "10.10.10.1", gw_data),
            ("AP:01", "10.10.10.2", _make_data(router_info={"mac": "AP:01"})),
            ("AP:02", "10.10.10.3", _make_data(router_info={"mac": "AP:02"})),
            ("AP:03", "10.10.10.4", _make_data(router_info={"mac": "AP:03"})),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 3
        assert all(e["from"] == "GW:00" for e in edges)

    # ---- WLAN-Repeater detection (sta_interfaces) -----------------------

    def test_sta_mac_added_to_lookup(self):
        """STA-MAC of repeater router is found in gateway client list →
        Method 2 produces a wifi_uplink edge even though the repeater's
        LAN MAC differs from the STA MAC."""
        gw_data = _make_data(
            router_info={"mac": "GW:LAN:00:00:00:01"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            clients=[
                {"mac": "RP:STA:00:00:00:02", "signal": -58, "radio": "phy0-ap0"},
            ],
        )
        # Repeater's LAN MAC differs from its STA-mode wireless MAC
        rp_data = _make_data(
            router_info={"mac": "RP:LAN:00:00:00:02"},
            sta_interfaces=[
                {"ifname": "wlan1-sta", "mode": "sta",
                 "mac": "RP:STA:00:00:00:02", "bssid": "GW:AP:00:00:00:01",
                 "ssid": "sECUREaP", "signal": -58},
            ],
        )
        router_data = [
            ("GW:LAN:00:00:00:01", "10.10.10.1", gw_data),
            ("RP:LAN:00:00:00:02", "10.10.10.2", rp_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        assert edges[0]["relationship"] == "wifi_uplink"
        assert edges[0]["from"] == "GW:LAN:00:00:00:01"
        assert edges[0]["to"] == "RP:LAN:00:00:00:02"
        assert edges[0]["attributes"]["ap_port"] is None
        assert edges[0]["attributes"]["vlan_tags"] == []

    def test_repeater_override_promotes_lan_to_wifi_uplink(self):
        """When the gateway hands out a DHCP lease to a repeater router, an
        *associated* STA interface (bssid + signal present) without WAN-port
        carrier forces the edge to wifi_uplink."""
        gw_data = _make_data(
            router_info={"mac": "GW:00"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={
                "RP:00": {"ip": "10.10.10.5", "hostname": "repeater"},
            },
            port_fdb_map={"rp:00": "lan3"},
            port_vlan_map={"lan3": [10, 20, 30]},
        )
        rp_data = _make_data(
            router_info={"mac": "RP:00"},
            # Real association: bssid + signal present
            sta_interfaces=[
                {"ifname": "wlan1-sta", "mode": "sta",
                 "mac": "RP:STA:00", "bssid": "GW:AP:00",
                 "ssid": "sECUREaP", "signal": -58},
            ],
            # WAN port without carrier → wireless backhaul
            port_stats=[
                {"name": "wan", "up": False, "speed_mbps": None},
                {"name": "lan1", "up": False, "speed_mbps": None},
            ],
        )
        router_data = [
            ("GW:00", "10.10.10.1", gw_data),
            ("RP:00", "10.10.10.5", rp_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        e = edges[0]
        assert e["relationship"] == "wifi_uplink"
        assert e["attributes"]["link_type"] == "wifi"
        assert e["attributes"]["ap_port"] is None
        assert e["attributes"]["vlan_tags"] == []
        # Override marker preserved for diagnostics
        assert "repeater_override" in e["attributes"]["detection_method"]
        # gateway_port stripped — wireless link has none
        assert "gateway_port" not in e["attributes"]

    def test_repeater_override_skipped_when_wan_carrier_up(self):
        """AP3 case: a router has a STA interface configured AND iwinfo data,
        but the WAN port is plugged in (carrier=True). Override must be
        skipped — physical Ethernet wins over wireless backhaul."""
        gw_data = _make_data(
            router_info={"mac": "GW:00"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={
                "AP3:00": {"ip": "10.10.10.3", "hostname": "ap3"},
            },
            port_fdb_map={"ap3:00": "lan3"},
            port_vlan_map={"lan3": [10, 20, 30]},
        )
        ap3_data = _make_data(
            router_info={"mac": "AP3:00"},
            # Even associated STA: cable trumps wireless
            sta_interfaces=[
                {"ifname": "wlan1-sta", "mode": "sta",
                 "mac": "AP3:STA:00", "bssid": "GW:AP:00",
                 "ssid": "sECUREaP", "signal": -55},
            ],
            port_stats=[
                {"name": "wan", "up": True, "speed_mbps": 1000},
                {"name": "lan1", "up": False, "speed_mbps": None},
            ],
        )
        router_data = [
            ("GW:00", "10.10.10.1", gw_data),
            ("AP3:00", "10.10.10.3", ap3_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        e = edges[0]
        assert e["relationship"] == "lan_uplink", (
            "WAN-port carrier=True must keep the wired edge intact"
        )
        assert e["attributes"]["link_type"] == "lan"
        assert e["attributes"]["ap_port"] == "wan"
        assert e["attributes"]["gateway_port"] == "lan3"
        assert e["attributes"]["vlan_tags"] == [10, 20, 30]

    def test_repeater_override_skipped_when_sta_inactive(self):
        """A stale UCI sta-mode entry without iwinfo association (no bssid,
        no signal) must NOT trigger the repeater override."""
        gw_data = _make_data(
            router_info={"mac": "GW:00"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={
                "AP:STALE": {"ip": "10.10.10.6", "hostname": "ap-stale"},
            },
            port_fdb_map={"ap:stale": "lan2"},
            port_vlan_map={"lan2": [20]},
        )
        ap_stale = _make_data(
            router_info={"mac": "AP:STALE"},
            # UCI-fallback shape: mode=sta but no association
            sta_interfaces=[
                {"ifname": "default_radio0", "mode": "sta",
                 "mac": "", "bssid": "", "ssid": "leftover", "signal": None},
            ],
            # port_stats omitted on purpose — even without WAN-carrier
            # information the inactive STA must still be ignored
        )
        router_data = [
            ("GW:00", "10.10.10.1", gw_data),
            ("AP:STALE", "10.10.10.6", ap_stale),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        e = edges[0]
        assert e["relationship"] == "lan_uplink"
        assert e["attributes"]["ap_port"] == "wan"
        assert e["attributes"]["gateway_port"] == "lan2"

    def test_repeater_override_active_when_sta_assoc_and_wan_down(self):
        """Regression guard: a genuine repeater (associated STA + WAN port
        without carrier) must still be promoted to wifi_uplink."""
        gw_data = _make_data(
            router_info={"mac": "GW:00"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={
                "RP:GENUINE": {"ip": "10.10.10.50", "hostname": "openwrt"},
            },
            port_fdb_map={"rp:genuine": "lan1"},
            port_vlan_map={"lan1": [30]},
        )
        repeater = _make_data(
            router_info={"mac": "RP:GENUINE"},
            sta_interfaces=[
                {"ifname": "wlan0-sta", "mode": "sta",
                 "mac": "RP:STA:GENUINE", "bssid": "GW:AP:5G",
                 "ssid": "sECUREaP", "signal": -65},
            ],
            port_stats=[
                {"name": "wan", "up": False, "speed_mbps": None},
            ],
        )
        router_data = [
            ("GW:00", "10.10.10.1", gw_data),
            ("RP:GENUINE", "10.10.10.50", repeater),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        e = edges[0]
        assert e["relationship"] == "wifi_uplink"
        assert "repeater_override" in e["attributes"]["detection_method"]
        assert e["attributes"]["ap_port"] is None

    # ---- Mesh backhaul (802.11s) — the 10.10.30.50 case -----------------

    def test_mesh_ap_promoted_to_wifi_uplink(self):
        """A wirelessly-meshed AP (mode=mesh point, no client-style bssid/signal)
        that got a lan_uplink via ARP/FDB must be promoted to wifi_uplink — not
        left as 'Kabel'. Regression for the VLAN-30 mesh AP 10.10.30.50.
        """
        gw_data = _make_data(
            router_info={"mac": "GW:00"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            # AP reached via the gateway's ARP+FDB trunk map (static IP, no DHCP).
            trunk_port_map={"10.10.30.50": "lan4"},
            port_vlan_map={"lan4": [30]},
        )
        mesh_ap = _make_data(
            router_info={"mac": "AP:MESH30"},
            # 802.11s backhaul: mode present, but NO client bssid/signal.
            sta_interfaces=[
                {"ifname": "mesh0", "mode": "mesh point",
                 "mac": "", "bssid": "", "ssid": "backhaul", "signal": None},
            ],
            # No 'wan'-named port with carrier → not a wired uplink.
            port_stats=[{"name": "lan1", "up": True, "speed_mbps": 1000}],
        )
        router_data = [
            ("GW:00", "10.10.10.1", gw_data),
            ("AP:MESH30", "10.10.30.50", mesh_ap),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        e = edges[0]
        assert e["relationship"] == "wifi_uplink"
        assert "repeater_override" in e["attributes"]["detection_method"]
        assert e["attributes"]["ap_port"] is None
        assert e["attributes"]["vlan_tags"] == []

    def test_mesh_ap_with_wan_carrier_stays_wired(self):
        """A mesh-capable device that IS cabled (wan port carrier up) must stay
        lan_uplink — a plugged cable still wins over a mesh iface."""
        gw_data = _make_data(
            router_info={"mac": "GW:00"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            trunk_port_map={"10.10.30.51": "lan5"},
            port_vlan_map={"lan5": [30]},
        )
        cabled = _make_data(
            router_info={"mac": "AP:CABLED"},
            sta_interfaces=[
                {"ifname": "mesh0", "mode": "mesh point",
                 "mac": "", "bssid": "", "ssid": "backhaul", "signal": None},
            ],
            port_stats=[{"name": "wan", "up": True, "speed_mbps": 1000}],
        )
        router_data = [
            ("GW:00", "10.10.10.1", gw_data),
            ("AP:CABLED", "10.10.30.51", cabled),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        assert edges[0]["relationship"] == "lan_uplink"

    def test_cross_subnet_mesh_ap_gets_wifi_uplink_fallback(self):
        """A mesh AP on a DIFFERENT subnet/VLAN (no DHCP/trunk/subnet match) but
        with an active mesh iface must still get a wifi_uplink — not fall through
        to the frontend's 'wired' default. Cross-subnet mesh backhaul case."""
        gw_data = _make_data(
            router_info={"mac": "GW:00"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            # No DHCP lease, no trunk_port_map entry for the AP.
        )
        mesh_ap = _make_data(
            router_info={"mac": "AP:MESH30"},
            sta_interfaces=[
                {"ifname": "mesh0", "mode": "mesh", "mac": "",
                 "bssid": "", "ssid": "backhaul", "signal": None},
            ],
            port_stats=[{"name": "lan1", "up": True, "speed_mbps": 1000}],
        )
        router_data = [
            ("GW:00", "10.10.10.1", gw_data),
            ("AP:MESH30", "10.10.30.50", mesh_ap),  # different /24
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        e = edges[0]
        assert e["relationship"] == "wifi_uplink"
        assert e["attributes"]["detection_method"] == "sta_iface_fallback"
        assert e["inferred"] is True

    def test_cross_subnet_router_without_sta_gets_no_edge(self):
        """Regression guard: a plain router on a different subnet with NO wireless
        uplink iface still gets no inferred edge (unchanged behaviour)."""
        gw_data = _make_data(
            router_info={"mac": "GW:00"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
        )
        other = _make_data(router_info={"mac": "R:OTHER"})
        router_data = [
            ("GW:00", "10.10.10.1", gw_data),
            ("R:OTHER", "10.99.99.2", other),  # different /24, no sta iface
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert edges == []


class TestHasActiveStaInterface:
    def test_mesh_point_counts_without_bssid_signal(self):
        data = _make_data(
            sta_interfaces=[
                {"ifname": "mesh0", "mode": "mesh point",
                 "mac": "", "bssid": "", "signal": None},
            ]
        )
        assert _has_active_sta_interface(data) is True

    def test_mesh_mode_variants_count(self):
        for mode in ("mesh", "mesh point", "mesh_point"):
            data = _make_data(
                sta_interfaces=[{"ifname": "m", "mode": mode, "signal": None}]
            )
            assert _has_active_sta_interface(data) is True, mode

    def test_associated_client_sta_counts(self):
        data = _make_data(
            sta_interfaces=[
                {"ifname": "wlan0", "mode": "sta",
                 "bssid": "AA:BB:CC:00:11:22", "signal": -60},
            ]
        )
        assert _has_active_sta_interface(data) is True

    def test_inactive_client_sta_does_not_count(self):
        data = _make_data(
            sta_interfaces=[
                {"ifname": "wlan0", "mode": "sta",
                 "bssid": "", "signal": None},
            ]
        )
        assert _has_active_sta_interface(data) is False

    def test_no_sta_interfaces(self):
        assert _has_active_sta_interface(_make_data()) is False

    # ---- Edge enrichment: ap_port + vlan_tags ---------------------------

    def test_lan_uplink_has_ap_port_and_vlan_tags(self):
        """A confirmed Ethernet uplink carries ap_port='wan' plus the VLAN
        tags of the gateway port (Trunk = >1 entries)."""
        gw_data = _make_data(
            router_info={"mac": "GW:01"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={
                "AP:01": {"ip": "10.10.10.2", "hostname": "ap1"},
            },
            port_fdb_map={"ap:01": "lan3"},
            port_vlan_map={"lan3": [10, 20, 30]},
        )
        ap_data = _make_data(router_info={"mac": "AP:01"})
        router_data = [
            ("GW:01", "10.10.10.1", gw_data),
            ("AP:01", "10.10.10.2", ap_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        attrs = edges[0]["attributes"]
        assert attrs["gateway_port"] == "lan3"
        assert attrs["ap_port"] == "wan"
        assert attrs["vlan_tags"] == [10, 20, 30]

    def test_lan_uplink_without_vlan_data(self):
        """Without port_vlan_map, vlan_tags falls back to []."""
        gw_data = _make_data(
            router_info={"mac": "GW:02"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
            dhcp_leases={
                "AP:02": {"ip": "10.10.10.3", "hostname": "ap2"},
            },
            port_fdb_map={"ap:02": "lan2"},
            # No port_vlan_map provided
        )
        ap_data = _make_data(router_info={"mac": "AP:02"})
        router_data = [
            ("GW:02", "10.10.10.1", gw_data),
            ("AP:02", "10.10.10.3", ap_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        assert edges[0]["attributes"]["ap_port"] == "wan"
        assert edges[0]["attributes"]["vlan_tags"] == []

    def test_subnet_fallback_carries_empty_port_info(self):
        """mesh_member edges always have ap_port=None + vlan_tags=[]."""
        gw_data = _make_data(
            router_info={"mac": "GW:03"},
            wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.1.1.1"},
            wan_connected=True,
        )
        ap_data = _make_data(router_info={"mac": "AP:03"})
        router_data = [
            ("GW:03", "10.10.10.1", gw_data),
            ("AP:03", "10.10.10.6", ap_data),
        ]
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) == 1
        assert edges[0]["relationship"] == "mesh_member"
        assert edges[0]["attributes"]["ap_port"] is None
        assert edges[0]["attributes"]["vlan_tags"] == []


# =====================================================================
# _deduplicate_clients
# =====================================================================

class TestDeduplicateClients:
    def test_no_duplicates(self):
        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "signal": -50},
            {"mac": "aa:bb:cc:dd:ee:02", "signal": -60},
        ]
        result = _deduplicate_clients(clients)
        assert len(result) == 2

    def test_duplicate_keeps_stronger_signal(self):
        """Same MAC on two APs — keep the one with stronger signal."""
        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "signal": -70, "ap_mac": "router1"},
            {"mac": "aa:bb:cc:dd:ee:01", "signal": -50, "ap_mac": "router2"},
        ]
        result = _deduplicate_clients(clients)
        assert len(result) == 1
        assert result[0]["signal"] == -50

    def test_duplicate_none_signal_loses(self):
        """One entry has signal, other has None — keep the one with signal."""
        clients = [
            {"mac": "aa:bb:cc:dd:ee:01", "signal": None},
            {"mac": "aa:bb:cc:dd:ee:01", "signal": -65},
        ]
        result = _deduplicate_clients(clients)
        assert len(result) == 1
        assert result[0]["signal"] == -65

    def test_empty_list(self):
        assert _deduplicate_clients([]) == []

    def test_no_mac_kept(self):
        """Clients without MAC are kept (can't deduplicate)."""
        clients = [
            {"mac": "", "signal": -50},
        ]
        result = _deduplicate_clients(clients)
        assert len(result) == 0  # Empty MAC is skipped
