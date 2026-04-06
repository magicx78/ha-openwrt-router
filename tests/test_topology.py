"""Unit tests for topology.py — the network topology builder."""

from __future__ import annotations

import json

import pytest

from custom_components.openwrt_router.topology import build_topology, topology_to_json


# ─── Fixtures ────────────────────────────────────────────────────────────────

ROUTER_INFO = {
    "hostname": "TestRouter",
    "model": "Test Model X",
    "release": {"version": "OpenWrt 24.10"},
}

WAN_STATUS = {
    "interface": "wan",
    "ipv4": "1.2.3.4",
    "proto": "dhcp",
    "uptime": 12345,
}

WIFI_RADIOS = [
    {
        "ifname": "phy0-ap0",
        "band": "2.4g",
        "ssid": "HomeNet",
        "enabled": True,
    },
    {
        "ifname": "phy1-ap0",
        "band": "5g",
        "ssid": "HomeNet5",
        "enabled": True,
    },
]

AP_INTERFACES = [
    {
        "ifname": "phy0-ap0",
        "channel": 6,
        "frequency": 2437,
        "txpower": 20,
    },
    {
        "ifname": "phy1-ap0",
        "channel": 36,
        "frequency": 5180,
        "txpower": 17,
    },
]

CLIENTS = [
    {
        "mac": "AA:BB:CC:DD:EE:01",
        "ip": "192.168.1.10",
        "hostname": "Laptop",
        "ssid": "HomeNet",
        "signal": -60,
        "radio": "phy0-ap0",
    },
    {
        "mac": "AA:BB:CC:DD:EE:02",
        "ip": "192.168.1.11",
        "hostname": "Phone",
        "ssid": "HomeNet5",
        "signal": -72,
        "radio": "phy1-ap0",
    },
]

DHCP_LEASES = {
    "aa:bb:cc:dd:ee:03": {"ip": "192.168.1.20", "hostname": "Desktop-LAN"},
}

NETWORK_INTERFACES = [
    {"interface": "lan", "rx_bytes": 100000, "tx_bytes": 50000, "status": "up"},
    {"interface": "wan", "rx_bytes": 500000, "tx_bytes": 200000, "status": "up"},
]


# ─── Helper ───────────────────────────────────────────────────────────────────

def _build(**kwargs):
    """Build topology with defaults, overridable via kwargs."""
    defaults = dict(
        router_info=ROUTER_INFO,
        wan_status=WAN_STATUS,
        wan_connected=True,
        wifi_radios=WIFI_RADIOS,
        ap_interfaces=AP_INTERFACES,
        clients=CLIENTS,
        dhcp_leases=DHCP_LEASES,
        network_interfaces=NETWORK_INTERFACES,
    )
    defaults.update(kwargs)
    return build_topology(**defaults)


# ─── Tests: structure ────────────────────────────────────────────────────────

def test_returns_expected_keys():
    topo = _build()
    assert set(topo.keys()) == {"nodes", "links", "meta"}


def test_meta_fields_present():
    topo = _build()
    meta = topo["meta"]
    assert "updated" in meta
    assert meta["client_count"] == 3  # 2 WiFi + 1 LAN
    assert meta["radio_count"] == 2
    assert meta["wan_ip"] == "1.2.3.4"
    assert meta["wan_connected"] is True
    assert meta["hostname"] == "TestRouter"


# ─── Tests: gateway node ─────────────────────────────────────────────────────

def test_gateway_node_present():
    topo = _build()
    gw = next((n for n in topo["nodes"] if n["type"] == "gateway"), None)
    assert gw is not None


def test_gateway_fields():
    topo = _build()
    gw = next(n for n in topo["nodes"] if n["type"] == "gateway")
    assert gw["id"] == "gateway"
    assert gw["name"] == "TestRouter"
    assert gw["model"] == "Test Model X"
    assert gw["wan_connected"] is True
    assert gw["parent_id"] is None


def test_gateway_wan_disconnected():
    topo = _build(wan_connected=False)
    gw = next(n for n in topo["nodes"] if n["type"] == "gateway")
    assert gw["wan_connected"] is False


# ─── Tests: radio nodes ──────────────────────────────────────────────────────

def test_radio_nodes_count():
    topo = _build()
    radios = [n for n in topo["nodes"] if n["type"] == "radio"]
    assert len(radios) == 2


def test_radio_2g_fields():
    topo = _build()
    r = next(n for n in topo["nodes"] if n["type"] == "radio" and "2" in n["band"])
    assert r["band_label"] == "2,4 GHz"
    assert r["ssid"] == "HomeNet"
    assert r["channel"] == 6
    assert r["parent_id"] == "gateway"


def test_radio_5g_fields():
    topo = _build()
    r = next(n for n in topo["nodes"] if n["type"] == "radio" and "5" in n["band"])
    assert r["band_label"] == "5 GHz"
    assert r["ssid"] == "HomeNet5"
    assert r["channel"] == 36


def test_radio_no_ap_details_fallback():
    """build_topology must not crash when ap_interfaces is empty."""
    topo = _build(ap_interfaces=[])
    radios = [n for n in topo["nodes"] if n["type"] == "radio"]
    assert len(radios) == 2
    for r in radios:
        assert r["channel"] is None


# ─── Tests: WiFi client nodes ────────────────────────────────────────────────

def test_wifi_clients_count():
    topo = _build()
    clients = [n for n in topo["nodes"] if n["type"] == "client" and n["connection_type"] == "wifi"]
    assert len(clients) == 2


def test_wifi_client_fields():
    topo = _build()
    c = next(n for n in topo["nodes"] if n.get("hostname") == "Laptop")
    assert c["mac"] == "AA:BB:CC:DD:EE:01"
    assert c["ip"] == "192.168.1.10"
    assert c["signal"] == -60
    assert c["signal_quality"] == "good"
    assert c["connection_type"] == "wifi"
    assert c["parent_id"] == "radio_phy0-ap0"


def test_wifi_client_signal_fair():
    topo = _build()
    c = next(n for n in topo["nodes"] if n.get("hostname") == "Phone")
    assert c["signal"] == -72
    assert c["signal_quality"] == "fair"


# ─── Tests: LAN client nodes ─────────────────────────────────────────────────

def test_lan_client_present():
    topo = _build()
    lan = [n for n in topo["nodes"] if n.get("connection_type") == "lan"]
    assert len(lan) == 1
    assert lan[0]["hostname"] == "Desktop-LAN"
    assert lan[0]["parent_id"] == "gateway"


def test_no_duplicate_mac():
    """A MAC that appears both in clients and dhcp_leases must not create duplicate nodes."""
    leases_with_wifi_mac = dict(DHCP_LEASES)
    leases_with_wifi_mac["aa:bb:cc:dd:ee:01"] = {"ip": "192.168.1.10", "hostname": "Laptop"}
    topo = _build(dhcp_leases=leases_with_wifi_mac)
    ids = [n["id"] for n in topo["nodes"]]
    assert len(ids) == len(set(ids)), "Duplicate node IDs detected"


# ─── Tests: links ────────────────────────────────────────────────────────────

def test_links_count():
    topo = _build()
    # gateway→radio0, gateway→radio1, radio0→client0, radio1→client1,
    # gateway→lan_client1
    assert len(topo["links"]) == 5


def test_wifi_link_medium():
    topo = _build()
    wifi_links = [l for l in topo["links"] if l["medium"] == "wifi"]
    assert len(wifi_links) == 2
    for lnk in wifi_links:
        assert lnk["confidence"] == "confirmed"


def test_lan_link_confidence():
    topo = _build()
    lan_links = [l for l in topo["links"] if l["medium"] == "lan"]
    assert len(lan_links) == 1
    assert lan_links[0]["confidence"] == "probable"


# ─── Tests: edge cases ───────────────────────────────────────────────────────

def test_empty_clients_no_crash():
    topo = _build(clients=[], dhcp_leases={})
    assert topo["meta"]["client_count"] == 0
    assert len([n for n in topo["nodes"] if n["type"] == "client"]) == 0


def test_empty_radios_no_crash():
    topo = _build(wifi_radios=[], ap_interfaces=[], clients=[])
    gateway = next(n for n in topo["nodes"] if n["type"] == "gateway")
    assert gateway is not None


def test_missing_hostname_falls_back_to_ip():
    clients_no_hostname = [
        {**CLIENTS[0], "hostname": ""},
    ]
    topo = _build(clients=clients_no_hostname, dhcp_leases={})
    c = next(n for n in topo["nodes"] if n["type"] == "client")
    assert c["name"] == "192.168.1.10"


def test_unknown_radio_falls_back_to_gateway():
    """Client with unknown radio ifname must still be created, parented to gateway."""
    clients_unknown_radio = [
        {**CLIENTS[0], "radio": "phy99-ap0"},
    ]
    topo = _build(clients=clients_unknown_radio)
    c = next(n for n in topo["nodes"] if n["type"] == "client" and n["connection_type"] == "wifi")
    assert c["parent_id"] == "gateway"


# ─── Tests: JSON serialisation ───────────────────────────────────────────────

def test_topology_to_json_is_valid_json():
    topo = _build()
    result = topology_to_json(topo)
    parsed = json.loads(result)
    assert "nodes" in parsed
    assert "links" in parsed
    assert "meta" in parsed


def test_topology_to_json_compact():
    """Result must not contain pretty-print whitespace."""
    topo = _build()
    result = topology_to_json(topo)
    assert "\n" not in result
    assert "  " not in result
