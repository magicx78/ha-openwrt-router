"""Tests for topology_mesh.py — Multi-router mesh topology aggregator."""
from __future__ import annotations

import pytest

from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
from custom_components.openwrt_router.topology_mesh import (
    _deduplicate_clients,
    _detect_inter_router_edges,
    _detect_router_role,
    _is_private_ip,
)


def _make_data(
    router_info: dict | None = None,
    wan_status: dict | None = None,
    wan_connected: bool = False,
    clients: list | None = None,
    dhcp_leases: dict | None = None,
) -> OpenWrtCoordinatorData:
    """Create minimal OpenWrtCoordinatorData for mesh tests."""
    data = OpenWrtCoordinatorData()
    data.router_info = router_info or {}
    data.wan_status = wan_status or {}
    data.wan_connected = wan_connected
    data.clients = clients or []
    data.dhcp_leases = dhcp_leases or {}
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
