"""Integration tests for the v1.21 port-device mapping across layers.

Covers _slim_port_stats (legacy contract + new fields + lease-case fix),
build_topology_snapshot (unassigned bucket, opt-in debug), the mesh
gateway-port enrichment (AP grouping, nearest-switch rule) and the
diagnostics redaction of arp_table + port_mapping summary.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock

import pytest

from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
from custom_components.openwrt_router.diagnostics import (
    async_get_config_entry_diagnostics,
)
from custom_components.openwrt_router.topology_diagnostic import (
    _slim_port_stats,
    build_topology_snapshot,
)
from custom_components.openwrt_router.topology_mesh import _enrich_gateway_ports

PORT_STATS = [
    {"name": "wan", "up": True, "speed_mbps": 1000, "duplex": "full"},
    {"name": "lan1", "up": True, "speed_mbps": 100, "duplex": "full"},
    {"name": "lan2", "up": True, "speed_mbps": 1000, "duplex": "full"},
    {"name": "lan3", "up": False, "speed_mbps": None, "duplex": None},
]

LEGACY_KEYS = {
    "name",
    "up",
    "speed_mbps",
    "duplex",
    "vlan_ids",
    "connected_device",
    "rx_bytes",
    "tx_bytes",
}


def _make_data(**overrides) -> OpenWrtCoordinatorData:
    data = OpenWrtCoordinatorData()
    data.router_info = {"mac": "DE:AD:BE:EF:00:00", "hostname": "gateway"}
    data.wan_status = {"interface": "wan"}
    data.port_stats = [dict(p) for p in PORT_STATS]
    for key, value in overrides.items():
        setattr(data, key, value)
    return data


# =====================================================================
# _slim_port_stats — legacy contract + new fields
# =====================================================================


class TestSlimPortStats:
    def test_port_stats_new_fields_present_and_legacy_intact(self):
        result = _slim_port_stats(
            PORT_STATS,
            port_vlan_map={"lan1": [10, 20], "lan2": [30, 40]},
            bridge_fdb={"aa:bb:cc:dd:ee:01": "lan1"},
            dhcp_leases={"AA:BB:CC:DD:EE:01": {"ip": "10.0.0.5", "hostname": "cam"}},
            arp_table={"aa:bb:cc:dd:ee:01": "10.0.0.5"},
        )
        lan1 = next(p for p in result if p["name"] == "lan1")
        # legacy keys unchanged in shape
        assert LEGACY_KEYS.issubset(lan1.keys())
        assert lan1["vlan_ids"] == [10, 20]  # case 5: VLANs preserved
        assert lan1["connected_device"] == "cam"
        # new model fields
        assert lan1["port_label"] == "LAN1"
        assert lan1["logical_name"] == "lan1"
        assert lan1["role"] == "lan"
        assert lan1["link_up"] is True
        assert lan1["device_count"] == 1
        assert lan1["primary_device"]["name"] == "cam"
        assert lan1["web_url"] == "http://10.0.0.5"
        assert lan1["mapping_confidence"] == "high"
        lan2 = next(p for p in result if p["name"] == "lan2")
        assert lan2["vlan_ids"] == [30, 40]

    def test_lease_case_mismatch_fixed(self):
        """Root cause 2 regression: UPPER lease keys + lower FDB MACs resolve."""
        result = _slim_port_stats(
            PORT_STATS,
            bridge_fdb={"aa:bb:cc:dd:ee:02": "lan2"},
            dhcp_leases={
                "AA:BB:CC:DD:EE:02": {"ip": "10.0.0.9", "hostname": "printer"}
            },
        )
        lan2 = next(p for p in result if p["name"] == "lan2")
        # before the fix this fell back to the raw lowercase MAC
        assert lan2["connected_device"] == "printer"

    def test_legacy_call_without_new_kwargs(self):
        """Case 12 (python side): the pre-v1.21 call form still works."""
        result = _slim_port_stats(
            PORT_STATS,
            port_vlan_map={"lan1": [10]},
            bridge_fdb=None,
            dhcp_leases=None,
        )
        lan1 = next(p for p in result if p["name"] == "lan1")
        assert lan1["connected_device"] is None
        assert lan1["connected_devices"] == []
        assert lan1["mapping_confidence"] == "none"

    def test_deterministic_primary_choice(self):
        """Root cause 3 regression: primary device no longer flaps."""
        fdb = {
            "aa:bb:cc:dd:ee:0a": "lan1",
            "aa:bb:cc:dd:ee:0b": "lan1",
        }
        leases = {
            "AA:BB:CC:DD:EE:0A": {"ip": "10.0.0.10", "hostname": "alpha"},
            "AA:BB:CC:DD:EE:0B": {"ip": "10.0.0.11", "hostname": "beta"},
        }
        arp = {"aa:bb:cc:dd:ee:0a": "10.0.0.10", "aa:bb:cc:dd:ee:0b": "10.0.0.11"}
        first = _slim_port_stats(
            PORT_STATS, bridge_fdb=fdb, dhcp_leases=leases, arp_table=arp
        )
        second = _slim_port_stats(
            PORT_STATS,
            bridge_fdb=dict(reversed(list(fdb.items()))),
            dhcp_leases=leases,
            arp_table=arp,
        )
        lan1_first = next(p for p in first if p["name"] == "lan1")
        lan1_second = next(p for p in second if p["name"] == "lan1")
        assert lan1_first["connected_device"] == lan1_second["connected_device"]
        assert lan1_first["connected_device"] == "alpha"


# =====================================================================
# build_topology_snapshot — unassigned bucket + opt-in debug
# =====================================================================


class TestSnapshotIntegration:
    def test_unassigned_bucket_on_router_node(self):
        data = _make_data(
            dhcp_leases={"AA:BB:CC:DD:EE:33": {"ip": "10.0.0.33", "hostname": "iot"}},
            arp_table={"aa:bb:cc:dd:ee:33": "10.0.0.33"},
            port_fdb_map={},
        )
        snapshot = build_topology_snapshot(data)
        router = next(n for n in snapshot["nodes"] if n["type"] == "router")
        unassigned = router["attributes"]["unassigned_devices"]
        assert len(unassigned) == 1
        assert unassigned[0]["name"] == "iot"
        assert unassigned[0]["reason"] == "unknown_port"

    def test_port_debug_absent_by_default(self):
        snapshot = build_topology_snapshot(_make_data())
        router = next(n for n in snapshot["nodes"] if n["type"] == "router")
        assert "port_mapping_debug" not in router["attributes"]

    def test_port_debug_present_when_enabled(self):
        data = _make_data(port_fdb_map={"aa:bb:cc:dd:ee:44": "lan1"})
        snapshot = build_topology_snapshot(data, include_port_debug=True)
        router = next(n for n in snapshot["nodes"] if n["type"] == "router")
        debug = router["attributes"]["port_mapping_debug"]
        assert debug["lan1"]["fdb_macs"] == ["aa:bb:cc:dd:ee:44"]
        assert debug["lan1"]["reason"]

    def test_wifi_client_not_attributed_to_lan_port(self):
        """Case 3 at snapshot level: hostapd client MAC in FDB is excluded."""
        data = _make_data(
            clients=[{"mac": "AA:BB:CC:DD:EE:55", "ip": "10.0.0.55"}],
            port_fdb_map={"aa:bb:cc:dd:ee:55": "lan1"},
            dhcp_leases={"AA:BB:CC:DD:EE:55": {"ip": "10.0.0.55", "hostname": "phone"}},
        )
        snapshot = build_topology_snapshot(data)
        router = next(n for n in snapshot["nodes"] if n["type"] == "router")
        lan1 = next(
            p for p in router["attributes"]["port_stats"] if p["name"] == "lan1"
        )
        assert lan1["connected_devices"] == []
        assert lan1["connected_device"] is None


# =====================================================================
# Mesh gateway-port enrichment — AP grouping + nearest-switch rule
# =====================================================================


def _enriched_port(name: str, devices: list[dict]) -> dict:
    return {
        "name": name,
        "up": True,
        "speed_mbps": 1000,
        "connected_device": None,
        "connected_devices": devices,
        "primary_device": devices[0] if devices else None,
        "device_count": len(devices),
        "has_downstream_switch": len(devices) > 1,
        "web_url": None,
        "mapping_confidence": "medium" if devices else "none",
        "role": "wan" if name.startswith("wan") else "lan",
        "port_label": name.upper(),
        "logical_name": name,
        "link_up": True,
        "vlan_ids": [],
    }


class TestMeshEnrichment:
    def _setup(self):
        gw_data = OpenWrtCoordinatorData()
        gw_data.router_info = {"mac": "DE:AD:BE:EF:00:00", "hostname": "gateway"}
        gw_data.trunk_port_map = {"10.10.10.2": "lan3"}
        gw_data.port_fdb_map = {
            "aa:aa:aa:00:00:01": "lan3",  # AP board MAC
            "bb:bb:bb:00:00:01": "lan3",  # client behind the AP
            "cc:cc:cc:00:00:01": "lan1",  # direct gateway device
        }

        ap_data = OpenWrtCoordinatorData()
        ap_data.router_info = {"mac": "AA:AA:AA:00:00:01", "hostname": "ap-og"}
        ap_data.clients = [{"mac": "BB:BB:BB:00:00:01"}]  # WiFi client of the AP
        ap_data.port_fdb_map = {"de:ad:be:ef:00:00": "wan"}  # sees gateway on wan

        attrs = {
            "port_stats": [
                _enriched_port(
                    "lan3",
                    [
                        {
                            "mac": "aa:aa:aa:00:00:01",
                            "ip": None,
                            "name": None,
                            "source": "fdb",
                            "confidence": "medium",
                            "web_url": None,
                        },
                        {
                            "mac": "bb:bb:bb:00:00:01",
                            "ip": None,
                            "name": None,
                            "source": "fdb",
                            "confidence": "medium",
                            "web_url": None,
                        },
                    ],
                ),
                _enriched_port(
                    "lan1",
                    [
                        {
                            "mac": "cc:cc:cc:00:00:01",
                            "ip": "10.10.10.40",
                            "name": "nas",
                            "source": "fdb+dhcp",
                            "confidence": "high",
                            "web_url": "http://10.10.10.40",
                        }
                    ],
                ),
            ]
        }
        router_data = [
            ("DE:AD:BE:EF:00:00", "10.10.10.1", gw_data),
            ("AA:AA:AA:00:00:01", "10.10.10.2", ap_data),
        ]
        return attrs, gw_data, router_data

    def test_gateway_trunk_port_groups_ap(self):
        attrs, gw_data, router_data = self._setup()
        _enrich_gateway_ports(attrs, gw_data, router_data, "DE:AD:BE:EF:00:00")
        lan3 = next(p for p in attrs["port_stats"] if p["name"] == "lan3")
        # AP entry is primary, marked as router, high confidence
        assert lan3["primary_device"]["name"] == "ap-og"
        assert lan3["primary_device"]["is_router"] is True
        assert lan3["primary_device"]["confidence"] == "high"
        assert lan3["primary_device"]["router_node_id"] == "AA:AA:AA:00:00:01"
        assert lan3["web_url"] == "http://10.10.10.2"
        # legacy string preserved for the old UI contract
        assert lan3["connected_device"] == "ap-og"

    def test_foreign_macs_removed_from_trunk_port(self):
        """Nearest-switch rule: the AP's WiFi client leaves the trunk port."""
        attrs, gw_data, router_data = self._setup()
        _enrich_gateway_ports(attrs, gw_data, router_data, "DE:AD:BE:EF:00:00")
        lan3 = next(p for p in attrs["port_stats"] if p["name"] == "lan3")
        macs = [d["mac"] for d in lan3["connected_devices"]]
        assert "bb:bb:bb:00:00:01" not in macs
        assert macs == ["aa:aa:aa:00:00:01"]
        assert lan3["device_count"] == 1
        assert lan3["has_downstream_switch"] is False

    def test_direct_gateway_device_untouched(self):
        attrs, gw_data, router_data = self._setup()
        _enrich_gateway_ports(attrs, gw_data, router_data, "DE:AD:BE:EF:00:00")
        lan1 = next(p for p in attrs["port_stats"] if p["name"] == "lan1")
        assert lan1["primary_device"]["name"] == "nas"
        assert lan1["connected_device"] == "nas"


# =====================================================================
# Diagnostics — arp_table redacted + PII-free port_mapping section
# =====================================================================

_MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")


class TestDiagnosticsPortMapping:
    @pytest.mark.asyncio
    async def test_arp_table_redacted_with_count(self, mock_config_entry_with_runtime):
        entry = mock_config_entry_with_runtime
        entry.runtime_data.coordinator.data.arp_table = {
            "aa:bb:cc:dd:ee:01": "192.168.1.23",
            "aa:bb:cc:dd:ee:02": "192.168.1.24",
        }
        result = await async_get_config_entry_diagnostics(MagicMock(), entry)
        assert result["coordinator"]["data"]["arp_table"] == "<2 entries redacted>"

    @pytest.mark.asyncio
    async def test_port_mapping_summary_contains_no_pii(
        self, mock_config_entry_with_runtime
    ):
        entry = mock_config_entry_with_runtime
        data = entry.runtime_data.coordinator.data
        data.port_stats = [dict(p) for p in PORT_STATS]
        data.port_fdb_map = {"aa:bb:cc:dd:ee:01": "lan1"}
        data.arp_table = {"aa:bb:cc:dd:ee:01": "192.168.1.23"}
        result = await async_get_config_entry_diagnostics(MagicMock(), entry)
        port_mapping = result["port_mapping"]
        serialized = str(port_mapping)
        assert not _MAC_RE.search(serialized)
        assert not _IP_RE.search(serialized)
        lan1 = next(p for p in port_mapping["ports"] if p["name"] == "lan1")
        assert lan1["device_count"] == 1
