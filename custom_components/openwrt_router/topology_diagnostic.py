"""topology_diagnostic.py — HA-side topology snapshot builder.

Builds a topology snapshot from OpenWrtCoordinatorData that mirrors
the schema produced by the provisioning server (magicx78/openwrt
/api/topology/snapshot). Purpose: validate semantics and data quality
of the live router data inside Home Assistant.

Rules (match provisioning server exactly — do NOT change):
  signal=None   → unknown, NEVER substitute -60
  bitrate=None  → unknown, NEVER substitute 0
  status="inactive" → 0/0 rx/tx, not an error
  valid=False   → data error (negative rx or tx)
  interface_type="unknown" → no classification possible, neutral

Known limitations (transparent, not hidden):
  - signal can be None when iw station dump produces bracket notation
    (e.g. '-65, -68') — ValueError → null; correct per semantics
  - inactive is strict: 0 rx AND 0 tx only
  - rx_bytes/tx_bytes per AP interface: not available from coordinator;
    falls back to None/None → no validation possible
  - without SSH key in provisioning server, wifi_iface_status stays {}
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .coordinator import OpenWrtCoordinatorData


def _seconds_since(value: Any) -> int | None:
    """Convert connected_since to elapsed seconds.

    The coordinator stores connected_since as:
    - int/float: seconds (from hostapd connected_time, initial api.py value)
    - str: ISO timestamp (coordinator.py overwrites with isoformat())

    Returns elapsed seconds as int, or None if not parseable.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)) and value > 0:
        return int(value)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            diff = (datetime.now(timezone.utc) - dt).total_seconds()
            return max(0, int(diff))
        except (ValueError, TypeError):
            pass
    return None


def _band_for_radio(ifname: str, band_map: dict[str, str]) -> str:
    """Resolve band for a client's radio interface name.

    Two lookup strategies:
    1. Direct match (iwinfo path): ifname = 'phy0-ap0' → band_map['phy0-ap0']
    2. phy→radio mapping (UCI path): 'phy0-ap0' → phy0 index 0 → 'radio0'
       UCI radios have name='radio0' but ifname='' so band_map is keyed by name.
    """
    if not ifname:
        return ""
    band = band_map.get(ifname, "")
    if band:
        return band
    # UCI fallback: phy0-ap0 → extract phy index → radio<N>
    m = re.match(r"^phy(\d+)", ifname)
    if m:
        band = band_map.get(f"radio{m.group(1)}", "")
        if band:
            return band
    return ""


# Topology schema version — stays in sync with provisioning server
TOPOLOGY_SCHEMA_VERSION = "1.0"
TOPOLOGY_SOURCE = "ha-openwrt.coordinator"

# Static limitations text — surfaced verbatim in topology_debug attribute
KNOWN_LIMITATIONS: list[str] = [
    "signal=null when iw station dump returns bracket-format signal line",
    "inactive = strict 0/0 rx/tx only; 0-rx/non-zero-tx is NOT inactive",
    "rx_bytes/tx_bytes per AP interface: not available from HA coordinator",
    "wifi_iface_status={} when provisioning server has no SSH key configured",
]


def _calc_mem_usage(memory: dict) -> float | None:
    """Return memory usage as percentage (0-100), or None if data missing."""
    total = memory.get("total") if memory else None
    free = memory.get("free") if memory else None
    if not total:
        return None
    return round((1 - free / total) * 100, 1)


def _classify_iface_type(ifname: str, wan_ifname: str = "") -> str:
    """Classify a network interface name into a topology type.

    Mirrors the logic of _classify_interface() in topology_mapper.py
    (magicx78/openwrt). Only the ifname is available here — no proto
    or device fields.

    Returns one of: wifi, uplink, lan, vpn, unknown
    """
    if not ifname:
        return "unknown"
    # WiFi AP virtual interfaces: phy0-ap0, phy1-ap1, etc.
    if re.match(r"^phy\d+-ap\d+$", ifname):
        return "wifi"
    # WAN uplink: matched by name from wan_status or common patterns
    if ifname == wan_ifname or ifname in ("wan", "wan6") or ifname.startswith("pppoe-"):
        return "uplink"
    # VPN / WireGuard
    if re.match(r"^wg\d*$", ifname) or ifname.startswith("wg"):
        return "vpn"
    # VLAN-bridged LAN (br-lan.X)
    if re.match(r"^br-lan\.\d+$", ifname):
        return "lan"
    # Main LAN bridge
    if ifname == "br-lan":
        return "lan"
    return "unknown"


def _validate_rx_tx(
    rx: int | None,
    tx: int | None,
) -> tuple[bool, str | None]:
    """Validate an (rx_bytes, tx_bytes) pair.

    Mirrors _validate_rx_tx() in topology_mapper.py exactly.

    Returns:
        (valid, warning) where:
          (True,  None)              — valid, active traffic
          (True,  "inactive")        — both 0, no traffic (not an error)
          (False, "invalid_negative")— one or both negative (data error)
          (True,  None)              — both None: no data, not invalid
    """
    if rx is None and tx is None:
        return (True, None)
    if (rx is not None and rx < 0) or (tx is not None and tx < 0):
        return (False, "invalid_negative")
    if rx == 0 and tx == 0:
        return (True, "inactive")
    return (True, None)


def _extract_vlans(network_interfaces: list[dict]) -> list[dict]:
    """Extract VLAN sub-interfaces from network_interfaces.

    Detects interfaces named br-lan.N, eth0.N, etc. (IEEE 802.1Q VLANs).
    Returns a list of {id, interface, status} dicts sorted by VLAN ID.
    Only includes numeric VLAN IDs (VLAN 1 is native/untagged, skip it).
    """
    vlans: list[dict] = []
    seen: set[int] = set()
    for iface in (network_interfaces or []):
        name: str = iface.get("interface", "") or ""
        # Match patterns: br-lan.10, eth0.20, lan0.100, etc.
        m = re.match(r"^[a-zA-Z][a-zA-Z0-9_-]*\.(\d+)$", name)
        if not m:
            continue
        vlan_id = int(m.group(1))
        if vlan_id <= 1 or vlan_id in seen:  # skip native VLAN and duplicates
            continue
        seen.add(vlan_id)
        vlans.append({
            "id": vlan_id,
            "interface": name,
            "status": iface.get("status", "unknown"),
        })
    return sorted(vlans, key=lambda v: v["id"])


def _slim_port_stats(port_stats: list[dict]) -> list[dict]:
    """Strip bulky byte counters from port_stats for the frontend snapshot.

    Only name, up, speed_mbps and duplex are needed for the PortStrip UI.
    rx/tx byte totals are large integers that inflate the snapshot payload.
    """
    return [
        {
            "name": p.get("name", ""),
            "up": bool(p.get("up", False)),
            "speed_mbps": p.get("speed_mbps"),
            "duplex": p.get("duplex"),
        }
        for p in (port_stats or [])
    ]


def build_topology_snapshot(
    data: OpenWrtCoordinatorData,
    role: str = "unknown",
    host_ip: str = "",
) -> dict[str, Any]:
    """Build a topology snapshot from coordinator data.

    Output schema matches /api/topology/snapshot from the provisioning
    server so both can be compared side-by-side.

    Args:
        data: Coordinator data for a single router.
        role: Router role — "gateway", "ap", or "unknown".
        host_ip: Config entry host IP (LAN IP of this router).

    Null semantics:
        signal=None  → preserved as None
        bitrate=None → preserved as None
    """
    now = datetime.now(timezone.utc).isoformat()

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    interfaces: list[dict[str, Any]] = []
    clients: list[dict[str, Any]] = []

    router_info = data.router_info
    # Use MAC if available; fall back to hostname then host IP as stable node ID
    _mac = router_info.get("mac", "")
    router_id: str = _mac or router_info.get("hostname") or "router"
    wan_ifname: str = data.wan_status.get("interface", "")

    # ── Router node ────────────────────────────────────────────────
    nodes.append({
        "id": router_id,
        "type": "router",
        "label": router_info.get("hostname") or router_id,
        "source": TOPOLOGY_SOURCE,
        "inferred": False,
        "status": "provisioned",
        "project": None,
        "role": role,
        "ip": data.wan_status.get("ipv4") or host_ip,
        "attributes": {
            "board_name": router_info.get("board_name"),
            "model": router_info.get("model"),
            "firmware": (router_info.get("release") or {}).get("version"),
            "mac": router_id,
            "host_ip": host_ip,
            "wan_proto": data.wan_status.get("proto", ""),
            "wan_connected": data.wan_connected,
            "uptime": data.uptime if data.uptime else None,
            "cpu_load": data.cpu_load,
            "mem_usage": _calc_mem_usage(data.memory),
            "port_stats": _slim_port_stats(data.port_stats),
            "vlans": _extract_vlans(data.network_interfaces),
        },
    })

    # ── Build rx/tx lookup from network_interfaces ─────────────────
    # AP-interface names like phy0-ap0 may or may not appear in
    # network_interfaces depending on OpenWrt version.
    net_iface_map: dict[str, dict[str, Any]] = {
        iface.get("interface", ""): iface
        for iface in (data.network_interfaces or [])
        if iface.get("interface")
    }

    # ── Build ifname→ssid/band lookup from wifi_radios for consistent labels ──
    # Keys: physical ifname (iwinfo path, e.g. 'phy0-ap0') AND radio name
    # (UCI path, e.g. 'radio0'). UCI path leaves ifname='', so we key by name
    # to support the phy→radio fallback in _band_for_radio().
    _radio_ssid_map: dict[str, str] = {}
    _radio_section_map: dict[str, str] = {}
    _radio_band_map: dict[str, str] = {}
    for _radio in data.wifi_radios or []:
        _rif = _radio.get("ifname", "")
        _rname = _radio.get("name", "")
        _band = _radio.get("band", "")
        if _rif:
            _radio_ssid_map[_rif] = _radio.get("ssid", "")
            _radio_section_map[_rif] = _radio.get("uci_section", "")
            _radio_band_map[_rif] = _band
        # Also key by radio name (UCI path: 'radio0', 'radio1')
        if _rname and _rname not in _radio_band_map:
            _radio_band_map[_rname] = _band

    # ── AP interface nodes ─────────────────────────────────────────
    for ap in data.ap_interfaces or []:
        ifname: str = ap.get("ifname", "")
        if not ifname:
            continue

        iface_type = _classify_iface_type(ifname, wan_ifname)
        iface_id = f"iface:{router_id}:{ifname}"

        # Build human-readable label: prefer SSID+band, then UCI section, then ifname
        _ssid = ap.get("ssid") or _radio_ssid_map.get(ifname, "")
        _band = ap.get("band", "")
        _section = _radio_section_map.get(ifname, "")
        if _ssid and _band:
            iface_label = f"{_ssid} ({_band})"
        elif _ssid:
            iface_label = _ssid
        elif _section:
            iface_label = _section
        else:
            iface_label = ifname

        # rx/tx: try network_interfaces; AP ifnames often absent → None/None
        net = net_iface_map.get(ifname, {})
        rx_bytes: int | None = net.get("rx_bytes")
        tx_bytes: int | None = net.get("tx_bytes")
        valid, warning = _validate_rx_tx(rx_bytes, tx_bytes)

        if not valid:
            iface_status = "error"
        elif warning == "inactive":
            iface_status = "inactive"
        else:
            iface_status = "active"

        # signal / bitrate: keep as-is (None stays None)
        signal: int | None = ap.get("signal")
        bitrate: str | None = ap.get("bitrate")  # string like "867 Mbit/s" or None
        inferred = iface_type == "unknown"

        interfaces.append({
            "id": iface_id,
            "ap_mac": router_id,
            "name": ifname,
            "interface_type": iface_type,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "valid": valid,
            "status": iface_status,
            "warning": warning,
            "source": TOPOLOGY_SOURCE,
            "inferred": inferred,
            "inference_reason": "interface_type_unknown" if inferred else None,
        })

        nodes.append({
            "id": iface_id,
            "type": "interface",
            "label": iface_label,
            "source": TOPOLOGY_SOURCE,
            "inferred": inferred,
            "inference_reason": "interface_type_unknown" if inferred else None,
            "status": iface_status,
            "valid": valid,
            "attributes": {
                "ap_mac": router_id,
                "interface_type": iface_type,
                "ssid": ap.get("ssid"),
                "band": ap.get("band"),
                "channel": ap.get("channel"),
                "rx_bytes": rx_bytes,
                "tx_bytes": tx_bytes,
                "warning": warning,
                "signal": signal,
                "bitrate": bitrate,
            },
        })
        edges.append({
            "id": f"{router_id}--{iface_id}",
            "from": router_id,
            "to": iface_id,
            "relationship": "has_interface",
            "source": TOPOLOGY_SOURCE,
            "inferred": False,
        })

    # ── Build AP-interface id lookup keyed by ifname ───────────────
    # Used to connect clients to their AP interface node.
    ifname_to_node_id: dict[str, str] = {
        f"iface:{router_id}:{ap.get('ifname', '')}": ap.get("ifname", "")
        for ap in (data.ap_interfaces or [])
        if ap.get("ifname")
    }
    # Reverse: ifname → iface_id
    ifname_to_iface_id: dict[str, str] = {
        v: k for k, v in ifname_to_node_id.items()
    }

    # ── Client nodes ───────────────────────────────────────────────
    for client in data.clients or []:
        mac: str = (client.get("mac") or "").lower()
        if not mac:
            continue

        client_id = f"client:{mac}"
        # signal stays None if not available — NEVER substitute -60
        c_signal: int | None = client.get("signal")
        c_radio: str = client.get("radio") or ""

        # Try to connect client to its AP interface node
        c_iface_id: str = ifname_to_iface_id.get(c_radio, router_id)
        c_inferred = c_iface_id == router_id  # True if we couldn't find the AP iface

        c_rx_bytes: int | None = client.get("rx_bytes")
        c_tx_bytes: int | None = client.get("tx_bytes")

        clients.append({
            "id": client_id,
            "mac": mac,
            "ap_mac": router_id,
            "signal": c_signal,           # None stays None
            "bitrate": None,              # not provided by coordinator
            "connected": True,
            "last_seen": client.get("connected_since"),
            "rx_bytes": c_rx_bytes,
            "tx_bytes": c_tx_bytes,
            "source": TOPOLOGY_SOURCE,
            "inferred": c_inferred,
            "inference_reason": (
                "client_ap_interface_unknown" if c_inferred else None
            ),
        })
        nodes.append({
            "id": client_id,
            "type": "client",
            "label": client.get("hostname") or mac,
            "source": TOPOLOGY_SOURCE,
            "inferred": c_inferred,
            "inference_reason": (
                "client_ap_interface_unknown" if c_inferred else None
            ),
            "status": "active",
            "attributes": {
                "ap_mac": router_id,
                "mac": mac,
                "ip": client.get("ip"),
                "hostname": client.get("hostname"),
                "ssid": client.get("ssid"),
                "radio": c_radio,
                "band": _band_for_radio(c_radio, _radio_band_map),
                "signal": c_signal,       # None stays None
                "connected_since": _seconds_since(client.get("connected_since")),
                "dhcp_expires": client.get("dhcp_expires"),
                "rx_bytes": c_rx_bytes,
                "tx_bytes": c_tx_bytes,
            },
        })
        edges.append({
            "id": f"{c_iface_id}--{client_id}",
            "from": c_iface_id,
            "to": client_id,
            "relationship": "has_client",
            "source": TOPOLOGY_SOURCE,
            "inferred": c_inferred,
            "inference_reason": (
                "client_ap_interface_unknown" if c_inferred else None
            ),
        })

    inference_used = any(
        bool(x.get("inferred"))
        for x in [*nodes, *edges, *interfaces, *clients]
    )

    return {
        "generated_at": now,
        "nodes": nodes,
        "edges": edges,
        "interfaces": interfaces,
        "clients": clients,
        "meta": {
            "source": TOPOLOGY_SOURCE,
            "schema_version": TOPOLOGY_SCHEMA_VERSION,
            "inference_used": inference_used,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "interface_count": len(interfaces),
            "client_count": len(clients),
        },
    }


def get_topology_status(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Compute diagnostic counts from a topology snapshot.

    Used as the attributes of OpenWrtTopologyStatusSensor.
    All counts are additive — no interpretation of "good" vs "bad".
    """
    ifaces = snapshot.get("interfaces", [])
    nodes = snapshot.get("nodes", [])
    edges = snapshot.get("edges", [])
    clients = snapshot.get("clients", [])

    active_ifaces = sum(1 for i in ifaces if i.get("status") == "active")
    inactive_ifaces = sum(1 for i in ifaces if i.get("status") == "inactive")
    invalid_data = sum(1 for i in ifaces if not i.get("valid", True))
    inferred_nodes = sum(
        1 for x in [*nodes, *edges] if x.get("inferred")
    )
    clients_no_signal = sum(
        1 for c in clients if c.get("signal") is None
    )
    unknown_iface_types = sum(
        1 for i in ifaces if i.get("interface_type") == "unknown"
    )

    return {
        "active_interfaces": active_ifaces,
        "inactive_interfaces": inactive_ifaces,
        "invalid_data": invalid_data,
        "inferred_nodes": inferred_nodes,
        "clients_without_signal": clients_no_signal,
        "unknown_interface_types": unknown_iface_types,
        "known_limitations": KNOWN_LIMITATIONS,
    }
