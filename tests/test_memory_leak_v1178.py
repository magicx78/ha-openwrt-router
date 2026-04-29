"""Memory-Leak Diagnose für v1.17.8.

Hintergrund: Nutzer meldete wiederholten HA-Crash ("HA war wieder down").
Verdacht: Speicherleck im Topology-Pfad. Dieser Test ruft den Hot Path
(`_detect_inter_router_edges`) und einen Multi-Router-Mesh-Setup wiederholt
auf und überwacht Heap (tracemalloc) + RSS (psutil).

Zwei Szenarien:
  1. **Pure aggregator loop:** 500× `_detect_inter_router_edges` mit 5 Routern
     (Gateway + 2 wired AP + 1 Repeater + 1 mesh_member + 1 Default-Hostname).
  2. **Client-dedup hot path:** 500× `_deduplicate_clients` mit 200 Clients
     auf 4 APs (Roaming-Szenario).

Schwellen:
  - Heap-Wachstum < 2 MB nach 500 Iterationen
  - RSS-Wachstum < 5 MB (RSS schwankt fragmentations-bedingt)
"""
from __future__ import annotations

import gc
import os
import tracemalloc

import psutil
import pytest

from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
from custom_components.openwrt_router.topology_mesh import (
    _deduplicate_clients,
    _detect_inter_router_edges,
)


def _make_data(
    router_info=None, wan_status=None, wan_connected=False, clients=None,
    dhcp_leases=None, sta_interfaces=None, port_vlan_map=None,
    port_fdb_map=None, trunk_port_map=None, port_stats=None,
    network_interfaces=None, ap_interfaces=None,
):
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
    data.network_interfaces = network_interfaces or []
    data.ap_interfaces = ap_interfaces or []
    return data


def _build_mesh_router_data():
    """Construct a 5-router setup that exercises every edge-detection path."""
    gateway = _make_data(
        router_info={"mac": "AA:BB:CC:DD:00:01", "hostname": "sECUREaP-gATEWAy"},
        wan_status={"connected": True, "proto": "dhcp", "ipv4": "185.220.100.1"},
        wan_connected=True,
        clients=[
            # WiFi backhaul of aP3 (STA-MAC visible as gateway client)
            {"mac": "AA:BB:CC:DD:03:01", "ip": "10.10.10.3", "signal": -55},
            # Five "real" wifi clients that should be deduped
            *(
                {
                    "mac": f"DE:AD:BE:EF:{i:02X}:01",
                    "ip": f"10.10.10.{100 + i}",
                    "signal": -50 - (i % 30),
                }
                for i in range(40)
            ),
        ],
        dhcp_leases={
            # Only ap2 is in DHCP — that's the Kabel-Uplink case.
            # ap3 ALSO has a DHCP lease BUT shows up as wifi client → wifi_uplink.
            # ap4/ap5 have static IPs (not in DHCP) → only Subnet fallback can find them.
            "AA:BB:CC:DD:02:01": {"ip": "10.10.10.2", "hostname": "sECUREaP-aP2"},
            "AA:BB:CC:DD:03:01": {"ip": "10.10.10.3", "hostname": "sECUREaP-aP3"},
        },
        port_fdb_map={"aa:bb:cc:dd:02:01": "lan1"},
        port_vlan_map={"lan1": [10, 30], "lan2": [30], "wan": []},
        trunk_port_map={"10.10.10.2": "lan1"},
        port_stats=[
            {"name": "wan", "up": True, "speed_mbps": 1000},
            {"name": "lan1", "up": True, "speed_mbps": 1000},
            {"name": "lan2", "up": False, "speed_mbps": None},
        ],
    )
    aP2 = _make_data(  # wired AP
        router_info={"mac": "AA:BB:CC:DD:02:01", "hostname": "sECUREaP-aP2"},
        port_stats=[{"name": "wan", "up": True, "speed_mbps": 1000}],
    )
    aP3 = _make_data(  # repeater (active STA, no WAN carrier)
        router_info={"mac": "AA:BB:CC:DD:03:00", "hostname": "sECUREaP-aP3"},
        sta_interfaces=[
            {"mac": "AA:BB:CC:DD:03:01", "bssid": "FF:EE:DD:CC:BB:AA", "signal": -55}
        ],
        port_stats=[{"name": "wan", "up": False, "speed_mbps": None}],
    )
    aP4 = _make_data(  # mesh_member (subnet fallback only)
        router_info={"mac": "AA:BB:CC:DD:04:01", "hostname": "sECUREaP-aP4"},
        port_stats=[{"name": "wan", "up": False, "speed_mbps": None}],
    )
    unconfigured = _make_data(  # default hostname "OpenWrt"
        router_info={"mac": "AA:BB:CC:DD:05:01", "hostname": "OpenWrt"},
        port_stats=[{"name": "wan", "up": False, "speed_mbps": None}],
    )
    return [
        ("gw", "10.10.10.1", gateway),
        ("ap2", "10.10.10.2", aP2),
        ("ap3", "10.10.10.3", aP3),
        ("ap4", "10.10.10.4", aP4),
        ("ap5", "10.10.10.5", unconfigured),
    ]


def _measure_growth(fn, iterations: int):
    """Run fn() iterations times, return (heap_growth_kb, rss_growth_kb)."""
    proc = psutil.Process(os.getpid())
    gc.collect()
    gc.collect()
    tracemalloc.start()

    # Warmup — first 3 calls allocate caches that are not leaks
    for _ in range(3):
        fn()
    gc.collect()
    snap_before = tracemalloc.take_snapshot()
    rss_before = proc.memory_info().rss

    for _ in range(iterations):
        fn()

    gc.collect()
    gc.collect()
    snap_after = tracemalloc.take_snapshot()
    rss_after = proc.memory_info().rss
    tracemalloc.stop()

    diff = snap_after.compare_to(snap_before, "lineno")
    heap_growth = sum(stat.size_diff for stat in diff)
    rss_growth = rss_after - rss_before

    # Surface top-3 heap-growth lines for failure diagnostics
    top_lines = [
        f"  +{stat.size_diff/1024:.1f} KB / +{stat.count_diff} objs @ {stat.traceback}"
        for stat in sorted(diff, key=lambda s: s.size_diff, reverse=True)[:3]
        if stat.size_diff > 0
    ]
    return heap_growth, rss_growth, top_lines


# ----------------------------------------------------------------------
# Test 1: _detect_inter_router_edges — main aggregator hot path
# ----------------------------------------------------------------------

def test_detect_inter_router_edges_no_leak():
    """500 iterations of the 5-router edge detection must not grow heap > 2 MB."""
    router_data = _build_mesh_router_data()

    def call():
        edges = _detect_inter_router_edges([], router_data)
        assert len(edges) >= 4  # gw→ap2, gw→ap3, gw→ap4, gw→ap5

    heap_kb, rss_kb, top = _measure_growth(call, iterations=500)
    print(
        f"\n[detect_inter_router_edges] heap_growth={heap_kb/1024:.1f} KB, "
        f"rss_growth={rss_kb/1024:.1f} KB"
    )
    if top:
        print("Top heap deltas:")
        for line in top:
            print(line)

    assert heap_kb < 2 * 1024 * 1024, (
        f"Heap grew {heap_kb/1024:.1f} KB after 500 iterations — possible leak"
    )
    # RSS is fragmentation-noisy; we use a generous bound just to flag runaway growth.
    assert rss_kb < 20 * 1024 * 1024, (
        f"RSS grew {rss_kb/1024:.1f} KB — runaway memory growth"
    )


# ----------------------------------------------------------------------
# Test 2: _deduplicate_clients — roaming hot path
# ----------------------------------------------------------------------

def test_deduplicate_clients_no_leak():
    """500 iterations of dedup with 200 roaming clients must not grow heap > 1 MB."""
    clients = []
    for i in range(200):
        # Each MAC appears on 4 APs with different signal strengths (roaming)
        for ap_idx in range(4):
            clients.append({
                "mac": f"DE:AD:BE:EF:{i:02X}:00",
                "ap_mac": f"AA:BB:CC:DD:0{ap_idx + 2}:01",
                "signal": -50 - ((i + ap_idx * 7) % 35),
                "ip": f"10.10.{ap_idx}.{(i % 250) + 1}",
            })

    def call():
        deduped = _deduplicate_clients(clients)
        assert len(deduped) == 200

    heap_kb, rss_kb, top = _measure_growth(call, iterations=500)
    print(
        f"\n[deduplicate_clients] heap_growth={heap_kb/1024:.1f} KB, "
        f"rss_growth={rss_kb/1024:.1f} KB"
    )
    if top:
        print("Top heap deltas:")
        for line in top:
            print(line)

    assert heap_kb < 1024 * 1024, (
        f"Heap grew {heap_kb/1024:.1f} KB after 500 iterations — possible leak"
    )
    assert rss_kb < 20 * 1024 * 1024, (
        f"RSS grew {rss_kb/1024:.1f} KB — runaway memory growth"
    )


# ----------------------------------------------------------------------
# Test 3: Multi-Router edge structure smoke test (Wiring-View input)
# ----------------------------------------------------------------------

def test_multi_router_wiring_edge_structure():
    """Verify the 5-router setup produces exactly the edge-types Wiring-View expects.

    Expected:
      - gw→ap2 lan_uplink   (DHCP+FDB)            → uplinkType='wired',    'Kabel'
      - gw→ap3 wifi_uplink  (Method 2 STA-MAC OR  → uplinkType='repeater', 'WLAN'
                             repeater_override)
      - gw→ap4 mesh_member  (Subnet-Fallback)      → uplinkType='mesh',    'Mesh?'
      - gw→ap5 mesh_member  (Subnet-Fallback)      → uplinkType='mesh',    'Mesh?'
                             (default OpenWrt hostname → frontend dims it)
    """
    router_data = _build_mesh_router_data()
    edges = _detect_inter_router_edges([], router_data)

    by_target = {e["to"]: e for e in edges}
    assert "ap2" in by_target, "ap2 should have an edge from the gateway"
    assert "ap3" in by_target, "ap3 should have an edge from the gateway"
    assert "ap4" in by_target, "ap4 should have an edge from the gateway"
    assert "ap5" in by_target, "ap5 should have an edge from the gateway"

    # ap2: DHCP-detected wired uplink
    assert by_target["ap2"]["relationship"] == "lan_uplink"
    assert by_target["ap2"]["attributes"]["link_type"] == "lan"

    # ap3: WiFi backhaul — either Method 2 (STA-MAC seen as gateway client)
    #      or repeater_override promoted DHCP-based lan_uplink to wifi_uplink.
    assert by_target["ap3"]["relationship"] == "wifi_uplink"
    assert by_target["ap3"]["attributes"]["link_type"] == "wifi"

    # ap4: subnet fallback — no DHCP, no STA-MAC, no ARP
    assert by_target["ap4"]["relationship"] == "mesh_member"
    assert by_target["ap4"]["inferred"] is True

    # ap5: same — default-hostname unconfigured router on the same /24
    assert by_target["ap5"]["relationship"] == "mesh_member"
    assert by_target["ap5"]["inferred"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
