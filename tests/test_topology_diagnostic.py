"""Tests for topology_diagnostic.py — HA-side topology snapshot builder."""
from __future__ import annotations

import pytest

from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
from custom_components.openwrt_router.topology_diagnostic import build_topology_snapshot


def _make_data(
    router_info: dict | None = None,
    wan_status: dict | None = None,
    clients: list | None = None,
    ap_interfaces: list | None = None,
    network_interfaces: list | None = None,
) -> OpenWrtCoordinatorData:
    """Create minimal OpenWrtCoordinatorData for topology tests."""
    data = OpenWrtCoordinatorData()
    data.router_info = router_info or {}
    data.wan_status = wan_status or {}
    data.clients = clients or []
    data.ap_interfaces = ap_interfaces or []
    data.network_interfaces = network_interfaces or []
    return data


# =====================================================================
# Fix 5: Router-ID hostname fallback when MAC is absent
# =====================================================================

class TestRouterIdFallback:
    """Fix 5: Router-ID uses hostname fallback when MAC is missing."""

    def test_mac_used_when_present(self):
        """Standard case: MAC available → use MAC as router node ID."""
        data = _make_data(router_info={
            "mac": "AA:BB:CC:DD:EE:FF",
            "hostname": "my-router",
        })
        snapshot = build_topology_snapshot(data)
        router_node = next(n for n in snapshot["nodes"] if n["type"] == "router")
        assert router_node["id"] == "AA:BB:CC:DD:EE:FF"

    def test_hostname_used_when_mac_absent(self):
        """Fix 5: No MAC field → fall back to hostname."""
        data = _make_data(router_info={
            "hostname": "sECUREaP-gATEWAy",
        })
        snapshot = build_topology_snapshot(data)
        router_node = next(n for n in snapshot["nodes"] if n["type"] == "router")
        assert router_node["id"] == "sECUREaP-gATEWAy"

    def test_hostname_used_when_mac_empty_string(self):
        """Fix 5: Empty MAC string → fall back to hostname, not empty string."""
        data = _make_data(router_info={
            "mac": "",
            "hostname": "sECUREaP-gATEWAy",
        })
        snapshot = build_topology_snapshot(data)
        router_node = next(n for n in snapshot["nodes"] if n["type"] == "router")
        assert router_node["id"] == "sECUREaP-gATEWAy"
        # Must not be empty string — that would break all edges
        assert router_node["id"] != ""

    def test_router_literal_used_when_both_absent(self):
        """Fix 5: Neither MAC nor hostname → fall back to 'router' literal."""
        data = _make_data(router_info={})
        snapshot = build_topology_snapshot(data)
        router_node = next(n for n in snapshot["nodes"] if n["type"] == "router")
        assert router_node["id"] == "router"

    def test_edges_use_correct_router_id(self):
        """Fix 5: AP-interface edges must reference the correct router_id."""
        data = _make_data(
            router_info={"hostname": "my-ap"},
            ap_interfaces=[
                {"ifname": "phy0-ap0", "ssid": "TestNet", "band": "2.4g",
                 "mode": "Master", "channel": 6},
            ],
        )
        snapshot = build_topology_snapshot(data)
        router_node = next(n for n in snapshot["nodes"] if n["type"] == "router")
        router_id = router_node["id"]
        assert router_id == "my-ap"

        # Every edge that leads to the router must use the correct ID
        router_edges = [e for e in snapshot["edges"] if e.get("to") == router_id
                        or e.get("from") == router_id]
        assert len(router_edges) > 0, "At least one edge should connect to router"
        for edge in router_edges:
            assert edge.get("from") == router_id or edge.get("to") == router_id


# =====================================================================
# Snapshot schema sanity
# =====================================================================

class TestSnapshotSchema:
    """Validate the top-level snapshot structure."""

    def test_schema_version_present(self):
        data = _make_data()
        snapshot = build_topology_snapshot(data)
        assert snapshot["meta"]["schema_version"] == "1.0"

    def test_source_present(self):
        data = _make_data()
        snapshot = build_topology_snapshot(data)
        assert snapshot["meta"]["source"] == "ha-openwrt.coordinator"

    def test_nodes_edges_interfaces_clients_keys_present(self):
        data = _make_data()
        snapshot = build_topology_snapshot(data)
        assert "nodes" in snapshot
        assert "edges" in snapshot
        assert "interfaces" in snapshot
        assert "clients" in snapshot

    def test_always_has_one_router_node(self):
        data = _make_data(router_info={"hostname": "test-router"})
        snapshot = build_topology_snapshot(data)
        router_nodes = [n for n in snapshot["nodes"] if n["type"] == "router"]
        assert len(router_nodes) == 1

    def test_no_empty_router_id(self):
        """Router node ID must never be an empty string."""
        data = _make_data(router_info={"mac": "", "hostname": ""})
        snapshot = build_topology_snapshot(data)
        router_node = next(n for n in snapshot["nodes"] if n["type"] == "router")
        assert router_node["id"]  # truthy — not empty string


# =====================================================================
# AP interface nodes
# =====================================================================

class TestAPInterfaceNodes:
    def test_ap_interface_creates_node(self):
        data = _make_data(
            router_info={"hostname": "test-router"},
            ap_interfaces=[
                {"ifname": "phy0-ap0", "ssid": "HomeNet", "band": "2.4g",
                 "mode": "Master", "channel": 6},
            ],
        )
        snapshot = build_topology_snapshot(data)
        iface_nodes = [n for n in snapshot["nodes"] if n["type"] != "router" and n["type"] != "client"]
        assert any("phy0-ap0" in n.get("id", "") or n.get("label") == "phy0-ap0"
                   for n in snapshot["nodes"])

    def test_client_creates_node(self):
        from custom_components.openwrt_router.const import (
            CLIENT_KEY_MAC, CLIENT_KEY_IP, CLIENT_KEY_SIGNAL, CLIENT_KEY_RADIO,
        )
        data = _make_data(
            router_info={"hostname": "test-router"},
            clients=[
                {
                    CLIENT_KEY_MAC: "11:22:33:44:55:66",
                    CLIENT_KEY_IP: "192.168.1.50",
                    CLIENT_KEY_SIGNAL: -60,
                    CLIENT_KEY_RADIO: "phy0-ap0",
                },
            ],
        )
        snapshot = build_topology_snapshot(data)
        client_nodes = [n for n in snapshot["nodes"] if n.get("type") == "client"]
        assert len(client_nodes) == 1
        # Client node id is "client:{mac_lowercase}"
        assert client_nodes[0]["id"] == "client:11:22:33:44:55:66"
