"""Tests for topology_ports.py — port → connected-device mapping model.

Covers the required mapping cases:
  single device on LAN1, multiple devices behind LAN2, WiFi exclusion,
  WAN exclusion, no-hostname→IP, no-IP→MAC, router-own MAC filtering,
  FDB+DHCP+ARP consistency, missing-FDB fallback (no fake mapping),
  Cudy WR3000 realistic layout, and the PII-free diagnostics summary.
"""

from __future__ import annotations

import re

from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
from custom_components.openwrt_router.topology_ports import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_NONE,
    build_port_connections,
    collect_own_macs,
    collect_wifi_client_macs,
    normalize_mac,
    redacted_port_summary,
    safe_web_url,
)

PORT_STATS = [
    {"name": "wan", "up": True, "speed_mbps": 1000},
    {"name": "lan1", "up": True, "speed_mbps": 100},
    {"name": "lan2", "up": True, "speed_mbps": 1000},
    {"name": "lan3", "up": False, "speed_mbps": None},
]


def _build(**overrides):
    kwargs = {
        "port_stats": PORT_STATS,
        "fdb": {},
        "dhcp_leases": {},
        "arp_table": {},
        "wifi_client_macs": set(),
        "own_macs": set(),
    }
    kwargs.update(overrides)
    return build_port_connections(**kwargs)


# =====================================================================
# Helpers: normalize_mac / safe_web_url
# =====================================================================


class TestNormalizeMac:
    def test_uppercase_colon(self):
        assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"

    def test_dash_and_dot_separators(self):
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
        assert normalize_mac("aabb.ccdd.eeff") == "aabb:ccdd:eeff"

    def test_none_and_empty(self):
        assert normalize_mac(None) == ""
        assert normalize_mac("") == ""


class TestSafeWebUrl:
    def test_valid_ipv4(self):
        assert safe_web_url("192.168.10.23") == "http://192.168.10.23"

    def test_rejects_hostname(self):
        assert safe_web_url("evil.example.com") is None

    def test_rejects_injection(self):
        assert safe_web_url("192.168.1.1/../../etc") is None
        assert safe_web_url('"><script>alert(1)</script>') is None

    def test_rejects_ipv6(self):
        assert safe_web_url("fe80::1") is None

    def test_rejects_none_and_empty(self):
        assert safe_web_url(None) is None
        assert safe_web_url("") is None


# =====================================================================
# Case 1: single device on LAN1 — high confidence
# =====================================================================


class TestSingleDeviceLan1:
    def test_single_device_lan1_high_confidence(self):
        result = _build(
            fdb={"aa:bb:cc:dd:ee:01": "lan1"},
            dhcp_leases={
                "AA:BB:CC:DD:EE:01": {"ip": "192.168.10.23", "hostname": "camera"}
            },
            arp_table={"aa:bb:cc:dd:ee:01": "192.168.10.23"},
        )
        port = result["ports"]["lan1"]
        assert port["device_count"] == 1
        device = port["primary_device"]
        assert device["name"] == "camera"
        assert device["ip"] == "192.168.10.23"
        assert device["confidence"] == CONFIDENCE_HIGH
        assert device["source"] == "fdb+dhcp+arp"
        assert device["web_url"] == "http://192.168.10.23"
        assert port["web_url"] == "http://192.168.10.23"
        assert port["mapping_confidence"] == CONFIDENCE_HIGH
        assert port["has_downstream_switch"] is False
        assert port["role"] == "lan"
        assert port["port_label"] == "LAN1"
        assert result["unassigned"] == []


# =====================================================================
# Case 2: multiple devices behind LAN2 (switch) — deterministic order
# =====================================================================


class TestMultipleDevicesLan2:
    def test_multiple_devices_lan2_sorted_and_counted(self):
        fdb = {
            "aa:bb:cc:dd:ee:03": "lan2",  # no identity → medium, sorts last
            "aa:bb:cc:dd:ee:01": "lan2",  # named → high
            "aa:bb:cc:dd:ee:02": "lan2",  # ip only → medium
        }
        leases = {"AA:BB:CC:DD:EE:01": {"ip": "192.168.1.10", "hostname": "nas"}}
        arp = {"aa:bb:cc:dd:ee:02": "192.168.1.11", "aa:bb:cc:dd:ee:01": "192.168.1.10"}
        result = _build(fdb=fdb, dhcp_leases=leases, arp_table=arp)
        port = result["ports"]["lan2"]
        assert port["device_count"] == 3
        assert port["has_downstream_switch"] is True
        macs = [d["mac"] for d in port["connected_devices"]]
        # high-confidence named device first, then deterministic MAC order
        assert macs == [
            "aa:bb:cc:dd:ee:01",
            "aa:bb:cc:dd:ee:02",
            "aa:bb:cc:dd:ee:03",
        ]
        assert port["primary_device"]["name"] == "nas"

    def test_order_independent_of_input_dict_order(self):
        leases = {"AA:BB:CC:DD:EE:01": {"ip": "192.168.1.10", "hostname": "nas"}}
        fdb_a = {
            "aa:bb:cc:dd:ee:01": "lan2",
            "aa:bb:cc:dd:ee:02": "lan2",
            "aa:bb:cc:dd:ee:03": "lan2",
        }
        fdb_b = {
            "aa:bb:cc:dd:ee:03": "lan2",
            "aa:bb:cc:dd:ee:02": "lan2",
            "aa:bb:cc:dd:ee:01": "lan2",
        }
        result_a = _build(fdb=fdb_a, dhcp_leases=leases)
        result_b = _build(fdb=fdb_b, dhcp_leases=leases)
        assert (
            result_a["ports"]["lan2"]["connected_devices"]
            == result_b["ports"]["lan2"]["connected_devices"]
        )


# =====================================================================
# Case 3: WiFi client MAC must never appear on a LAN port
# =====================================================================


class TestWifiExclusion:
    def test_wifi_client_mac_excluded_from_ports(self):
        result = _build(
            fdb={"aa:bb:cc:dd:ee:99": "lan1"},
            dhcp_leases={
                "AA:BB:CC:DD:EE:99": {"ip": "192.168.1.50", "hostname": "phone"}
            },
            arp_table={"aa:bb:cc:dd:ee:99": "192.168.1.50"},
            wifi_client_macs={"AA:BB:CC:DD:EE:99"},  # any casing
        )
        assert result["ports"]["lan1"]["device_count"] == 0
        assert result["ports"]["lan1"]["mapping_confidence"] == CONFIDENCE_NONE
        # not smuggled into the unassigned bucket either
        assert all(d["mac"] != "aa:bb:cc:dd:ee:99" for d in result["unassigned"])


# =====================================================================
# Case 4: WAN port never gets FDB devices
# =====================================================================


class TestWanExclusion:
    def test_wan_port_never_gets_devices(self):
        result = _build(
            fdb={"aa:bb:cc:dd:ee:10": "wan"},  # FDB anomaly
            dhcp_leases={
                "AA:BB:CC:DD:EE:10": {"ip": "192.168.1.60", "hostname": "modem"}
            },
        )
        wan = result["ports"]["wan"]
        assert wan["role"] == "wan"
        assert wan["connected_devices"] == []
        assert wan["mapping_confidence"] == CONFIDENCE_NONE
        # the identity is preserved honestly as unassigned instead
        entry = next(d for d in result["unassigned"] if d["mac"] == "aa:bb:cc:dd:ee:10")
        assert entry["reason"] == "wan_port_excluded"
        assert entry["confidence"] == CONFIDENCE_LOW


# =====================================================================
# Case 6/7: identity fallbacks — IP without hostname, MAC without IP
# =====================================================================


class TestIdentityFallbacks:
    def test_device_without_hostname_uses_ip(self):
        result = _build(
            fdb={"aa:bb:cc:dd:ee:20": "lan1"},
            arp_table={"aa:bb:cc:dd:ee:20": "192.168.1.77"},
        )
        device = result["ports"]["lan1"]["primary_device"]
        assert device["name"] is None
        assert device["ip"] == "192.168.1.77"
        assert device["confidence"] == CONFIDENCE_MEDIUM
        assert device["web_url"] == "http://192.168.1.77"
        assert device["source"] == "fdb+arp"

    def test_device_mac_only_medium_no_weburl(self):
        result = _build(fdb={"aa:bb:cc:dd:ee:21": "lan1"})
        device = result["ports"]["lan1"]["primary_device"]
        assert device["name"] is None
        assert device["ip"] is None
        assert device["web_url"] is None
        assert device["confidence"] == CONFIDENCE_MEDIUM
        assert device["source"] == "fdb"


# =====================================================================
# Case 8: router-own / multicast / broadcast MACs filtered
# =====================================================================


class TestOwnAndMulticastFiltering:
    def test_router_own_macs_and_is_local_filtered(self):
        result = _build(
            fdb={
                "de:ad:be:ef:00:01": "lan1",  # router board MAC
                "de:ad:be:ef:00:02": "lan2",  # AP BSSID
                "aa:bb:cc:dd:ee:30": "lan1",  # real device
            },
            own_macs={"DE:AD:BE:EF:00:01", "de:ad:be:ef:00:02"},
        )
        lan1_macs = [d["mac"] for d in result["ports"]["lan1"]["connected_devices"]]
        assert lan1_macs == ["aa:bb:cc:dd:ee:30"]
        assert result["ports"]["lan2"]["device_count"] == 0

    def test_multicast_broadcast_and_zero_macs_filtered(self):
        result = _build(
            fdb={
                "01:00:5e:00:00:fb": "lan1",  # multicast
                "ff:ff:ff:ff:ff:ff": "lan1",  # broadcast
                "33:33:00:00:00:01": "lan1",  # IPv6 multicast
                "00:00:00:00:00:00": "lan1",  # zero
            },
        )
        assert result["ports"]["lan1"]["device_count"] == 0

    def test_collect_own_macs(self):
        own = collect_own_macs(
            {"mac": "AA:AA:AA:00:00:01"},
            [{"bssid": "AA:AA:AA:00:00:02", "mac": "AA:AA:AA:00:00:03"}],
            [{"mac": "AA:AA:AA:00:00:04", "bssid": "BB:BB:BB:00:00:99"}],
        )
        assert own == {
            "aa:aa:aa:00:00:01",
            "aa:aa:aa:00:00:02",
            "aa:aa:aa:00:00:03",
            "aa:aa:aa:00:00:04",
        }
        # peer BSSID (the AP a STA is associated to) is NOT own
        assert "bb:bb:bb:00:00:99" not in own

    def test_collect_wifi_client_macs(self):
        macs = collect_wifi_client_macs([{"mac": "AA:BB:CC:11:22:33"}, {"mac": ""}, {}])
        assert macs == {"aa:bb:cc:11:22:33"}


# =====================================================================
# Case 9: FDB + DHCP + ARP consistency and conflict downgrade
# =====================================================================


class TestSourceConsistency:
    def test_fdb_dhcp_arp_consistent_high(self):
        result = _build(
            fdb={"aa:bb:cc:dd:ee:40": "lan1"},
            dhcp_leases={
                "AA:BB:CC:DD:EE:40": {"ip": "192.168.1.40", "hostname": "printer"}
            },
            arp_table={"aa:bb:cc:dd:ee:40": "192.168.1.40"},
        )
        device = result["ports"]["lan1"]["primary_device"]
        assert device["confidence"] == CONFIDENCE_HIGH
        assert device["ip"] == "192.168.1.40"

    def test_dhcp_arp_ip_conflict_downgrades_to_medium(self):
        result = _build(
            fdb={"aa:bb:cc:dd:ee:41": "lan1"},
            dhcp_leases={
                "AA:BB:CC:DD:EE:41": {"ip": "192.168.1.41", "hostname": "printer"}
            },
            arp_table={"aa:bb:cc:dd:ee:41": "192.168.1.99"},  # stale lease
        )
        device = result["ports"]["lan1"]["primary_device"]
        assert device["confidence"] == CONFIDENCE_MEDIUM
        # ARP is the live observation and wins
        assert device["ip"] == "192.168.1.99"


# =====================================================================
# Case 10: missing FDB → clean fallback, never a fake port mapping
# =====================================================================


class TestNoFdbFallback:
    def test_no_fdb_no_fake_mapping(self):
        result = _build(
            fdb={},
            dhcp_leases={
                "AA:BB:CC:DD:EE:50": {"ip": "192.168.1.50", "hostname": "camera"}
            },
            arp_table={"aa:bb:cc:dd:ee:50": "192.168.1.50"},
        )
        for port in result["ports"].values():
            assert port["connected_devices"] == []
            assert port["mapping_confidence"] == CONFIDENCE_NONE
            assert port["primary_device"] is None
        entry = next(d for d in result["unassigned"] if d["mac"] == "aa:bb:cc:dd:ee:50")
        assert entry["reason"] == "unknown_port"
        assert entry["confidence"] == CONFIDENCE_LOW
        assert entry["name"] == "camera"

    def test_lease_only_ghost_dropped(self):
        """A DHCP lease without ARP/FDB proof is not a connected device."""
        result = _build(
            fdb={},
            dhcp_leases={
                "AA:BB:CC:DD:EE:51": {"ip": "192.168.1.51", "hostname": "old-laptop"}
            },
            arp_table={},
        )
        assert result["unassigned"] == []


# =====================================================================
# Case 11: Cudy WR3000 v1 realistic layout (DSA: wan + lan1..lan3)
# =====================================================================


class TestCudyWr3000:
    def test_cudy_wr3000_realistic_fdb(self):
        """Realistic Cudy WR3000: router MACs filtered, wan not bridged."""
        port_stats = [
            {"name": "wan", "up": True, "speed_mbps": 1000},
            {"name": "lan1", "up": True, "speed_mbps": 100},
            {"name": "lan2", "up": True, "speed_mbps": 100},
            {"name": "lan3", "up": True, "speed_mbps": 1000},
        ]
        # what a fixed 16-byte brforward parse yields: only learned,
        # non-local entries on lan ports (wan is not a br-lan member)
        fdb = {
            "e0:22:33:44:55:66": "lan1",  # camera
            "76:88:99:aa:bb:cc": "lan3",  # AP uplink
        }
        result = build_port_connections(
            port_stats=port_stats,
            fdb=fdb,
            dhcp_leases={
                "E0:22:33:44:55:66": {"ip": "10.10.10.23", "hostname": "camera"},
                "76:88:99:AA:BB:CC": {"ip": "10.10.10.2", "hostname": "ap-og"},
            },
            arp_table={
                "e0:22:33:44:55:66": "10.10.10.23",
                "76:88:99:aa:bb:cc": "10.10.10.2",
            },
            wifi_client_macs=set(),
            own_macs={"de:ad:be:ef:00:00"},
        )
        assert result["ports"]["lan1"]["primary_device"]["name"] == "camera"
        assert result["ports"]["lan2"]["device_count"] == 0
        assert result["ports"]["lan3"]["primary_device"]["name"] == "ap-og"
        assert result["ports"]["wan"]["connected_devices"] == []
        assert result["unassigned"] == []


# =====================================================================
# VLAN sub-interface normalisation feeds physical tiles (case 5 support)
# =====================================================================


class TestDebugTrace:
    def test_debug_absent_by_default(self):
        assert _build()["debug"] is None

    def test_debug_trace_explains_assignment(self):
        result = _build(
            fdb={"aa:bb:cc:dd:ee:60": "lan1"},
            dhcp_leases={
                "AA:BB:CC:DD:EE:60": {"ip": "192.168.1.60", "hostname": "camera"}
            },
            include_debug=True,
        )
        trace = result["debug"]["lan1"]
        assert trace["fdb_macs"] == ["aa:bb:cc:dd:ee:60"]
        assert trace["dhcp_matches"][0]["hostname"] == "camera"
        assert trace["final"] == ["aa:bb:cc:dd:ee:60"]
        # ip + hostname resolved → high, regardless of ARP presence
        assert trace["confidence"] == CONFIDENCE_HIGH
        assert "bridge FDB" in trace["reason"]

    def test_debug_reason_for_silent_link(self):
        result = _build(include_debug=True)
        assert "no FDB entries" in result["debug"]["lan1"]["reason"]
        assert result["debug"]["lan3"]["reason"] == "link down"
        assert "wan uplink" in result["debug"]["wan"]["reason"]


# =====================================================================
# redacted_port_summary — PII-free diagnostics section
# =====================================================================

_MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", re.IGNORECASE)
_IP_RE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")


class TestRedactedPortSummary:
    def _make_data(self) -> OpenWrtCoordinatorData:
        data = OpenWrtCoordinatorData()
        data.port_stats = PORT_STATS
        data.port_fdb_map = {"aa:bb:cc:dd:ee:70": "lan1"}
        data.dhcp_leases = {
            "AA:BB:CC:DD:EE:70": {"ip": "192.168.1.70", "hostname": "secret-host"}
        }
        data.arp_table = {
            "aa:bb:cc:dd:ee:70": "192.168.1.70",
            "aa:bb:cc:dd:ee:71": "192.168.1.71",
        }
        data.clients = []
        data.router_info = {"mac": "DE:AD:BE:EF:00:00"}
        data.ap_interfaces = []
        data.sta_interfaces = []
        return data

    def test_port_mapping_summary_contains_no_pii(self):
        summary = redacted_port_summary(self._make_data())
        serialized = str(summary)
        assert not _MAC_RE.search(serialized)
        assert not _IP_RE.search(serialized)
        assert "secret-host" not in serialized

    def test_summary_counts_and_confidence(self):
        summary = redacted_port_summary(self._make_data())
        lan1 = next(p for p in summary["ports"] if p["name"] == "lan1")
        assert lan1["device_count"] == 1
        assert lan1["mapping_confidence"] == CONFIDENCE_HIGH
        assert lan1["sources"] == ["arp", "dhcp", "fdb"]
        assert summary["unassigned_count"] == 1
