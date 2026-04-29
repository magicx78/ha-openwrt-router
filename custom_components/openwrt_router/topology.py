"""Network topology builder for the OpenWrt Router integration.

Converts coordinator data (clients, radios, interfaces, wan_status) into a
deterministic JSON topology model suitable for Lovelace visualisation.

Model schema:
    nodes:  list of node dicts (gateway, radio, client)
    links:  list of link dicts (connections between nodes)
    meta:   metadata (timestamp, client count, wan_ip)

Node types:
    "gateway"  — the OpenWrt router itself
    "radio"    — a WiFi radio / access point (one per band/SSID)
    "client"   — an associated WiFi or LAN client

Link media types:
    "wifi"     — wireless association
    "lan"      — wired LAN
    "internal" — internal (gateway → radio) connection

All fields are present on every node/link even if empty, so the frontend
never has to do defensive checks on missing keys.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from .const import (
    CLIENT_KEY_IP,
    CLIENT_KEY_MAC,
    CLIENT_KEY_HOSTNAME,
    CLIENT_KEY_SIGNAL,
    CLIENT_KEY_SSID,
    CLIENT_KEY_RADIO,
    RADIO_KEY_BAND,
    RADIO_KEY_CHANNEL,
    RADIO_KEY_ENABLED,
    RADIO_KEY_FREQUENCY,
    RADIO_KEY_IFNAME,
    RADIO_KEY_SSID,
    RADIO_KEY_TXPOWER,
)

_LOGGER = logging.getLogger(__name__)

# Signal quality thresholds (dBm)
_SIGNAL_GOOD = -65
_SIGNAL_FAIR = -75


def _signal_quality(signal_dbm: int | None) -> str:
    """Return 'good', 'fair', or 'poor' based on dBm value."""
    if signal_dbm is None or signal_dbm == 0:
        return "unknown"
    if signal_dbm >= _SIGNAL_GOOD:
        return "good"
    if signal_dbm >= _SIGNAL_FAIR:
        return "fair"
    return "poor"


def _radio_id(radio_ifname: str) -> str:
    """Return a stable node ID for a radio interface."""
    return f"radio_{radio_ifname}" if radio_ifname else "radio_unknown"


def _client_id(mac: str) -> str:
    """Return a stable node ID for a client."""
    return mac.lower().replace(":", "") if mac else "client_unknown"


def build_topology(
    router_info: dict[str, Any],
    wan_status: dict[str, Any],
    wan_connected: bool,
    wifi_radios: list[dict[str, Any]],
    ap_interfaces: list[dict[str, Any]],
    clients: list[dict[str, Any]],
    dhcp_leases: dict[str, dict[str, str]],
    network_interfaces: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a topology dict from coordinator data.

    Args:
        router_info:        Static board info (hostname, model, release).
        wan_status:         WAN interface status dict.
        wan_connected:      Convenience bool for WAN connectivity.
        wifi_radios:        List of normalised radio descriptors.
        ap_interfaces:      List of AP interface detail dicts (channel, freq, etc.).
        clients:            List of currently associated WiFi clients.
        dhcp_leases:        MAC → {ip, hostname} from the DHCP lease table.
        network_interfaces: List of network interface stats dicts.

    Returns:
        Topology dict with keys "nodes", "links", "meta".
    """
    nodes: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # 1. Gateway node
    # ------------------------------------------------------------------
    gateway_id = "gateway"
    hostname = router_info.get("hostname") or router_info.get("system", {}).get(
        "hostname", "OpenWrt"
    )
    model = router_info.get("model") or router_info.get("system", {}).get("model", "")
    release = router_info.get("release", {})
    firmware = release.get("version", "") if isinstance(release, dict) else str(release)

    wan_ip = wan_status.get("ipv4", "") or wan_status.get("wan_ip", "")

    nodes.append(
        {
            "id": gateway_id,
            "name": hostname,
            "type": "gateway",
            "model": model,
            "firmware": firmware,
            "ip": wan_ip,
            "wan_connected": wan_connected,
            "status": "online",
            "icon": "mdi:router-wireless",
            "parent_id": None,
            "attributes": {},
        }
    )

    # ------------------------------------------------------------------
    # 2. Build AP interface detail lookup: ifname → detail dict
    # ------------------------------------------------------------------
    ap_detail: dict[str, dict[str, Any]] = {}
    for ap in ap_interfaces or []:
        ifname = ap.get(RADIO_KEY_IFNAME, "")
        if ifname:
            ap_detail[ifname] = ap

    # ------------------------------------------------------------------
    # 3. Radio nodes (one per enabled radio / SSID entry)
    # ------------------------------------------------------------------
    # Map ifname → radio_node_id for client assignment later
    ifname_to_radio_id: dict[str, str] = {}

    for radio in wifi_radios or []:
        ifname = radio.get(RADIO_KEY_IFNAME, "")
        band = radio.get(RADIO_KEY_BAND, "")
        ssid = radio.get(RADIO_KEY_SSID, "")
        enabled = radio.get(RADIO_KEY_ENABLED, True)

        radio_node_id = _radio_id(ifname)
        ifname_to_radio_id[ifname] = radio_node_id

        # Enrich with AP detail if available
        detail = ap_detail.get(ifname, {})
        channel = detail.get(RADIO_KEY_CHANNEL) or radio.get(RADIO_KEY_CHANNEL)
        frequency = detail.get(RADIO_KEY_FREQUENCY) or radio.get(RADIO_KEY_FREQUENCY)
        txpower = detail.get(RADIO_KEY_TXPOWER)

        # Human-readable band label
        if "5g" in band or "5" in band:
            band_label = "5 GHz"
        elif "6g" in band or "6" in band:
            band_label = "6 GHz"
        else:
            band_label = "2,4 GHz"

        nodes.append(
            {
                "id": radio_node_id,
                "name": f"{band_label} · {ssid}" if ssid else band_label,
                "type": "radio",
                "band": band,
                "band_label": band_label,
                "ssid": ssid,
                "ifname": ifname,
                "channel": channel,
                "frequency": frequency,
                "txpower": txpower,
                "enabled": enabled,
                "status": "online" if enabled else "disabled",
                "icon": "mdi:wifi",
                "parent_id": gateway_id,
                "attributes": {},
            }
        )

        links.append(
            {
                "source": gateway_id,
                "target": radio_node_id,
                "medium": "internal",
                "band": band,
                "speed": None,
                "signal": None,
                "signal_quality": "good",
                "label": band_label,
                "confidence": "confirmed",
                "is_backhaul": False,
            }
        )

    # ------------------------------------------------------------------
    # 4. Client nodes
    # ------------------------------------------------------------------
    # Build MAC-normalised DHCP lease lookup for hostname resolution
    lease_lookup: dict[str, dict[str, str]] = {
        k.upper(): v for k, v in (dhcp_leases or {}).items()
    }

    # Track which MACs we've already added (avoid duplicates)
    seen_macs: set[str] = set()

    # Collect LAN clients: MACs in DHCP leases but NOT in wifi_clients
    wifi_macs: set[str] = {c.get(CLIENT_KEY_MAC, "").upper() for c in (clients or [])}

    # --- WiFi clients ---
    for client in clients or []:
        mac = client.get(CLIENT_KEY_MAC, "").upper()
        if not mac or mac in seen_macs:
            continue
        seen_macs.add(mac)

        ip = client.get(CLIENT_KEY_IP, "")
        hostname_client = client.get(CLIENT_KEY_HOSTNAME, "")
        ssid = client.get(CLIENT_KEY_SSID, "")
        signal = client.get(CLIENT_KEY_SIGNAL)
        radio_ifname = client.get(CLIENT_KEY_RADIO, "")
        band = ""

        # Resolve hostname from DHCP lease if not already set
        if not hostname_client:
            lease = lease_lookup.get(mac, {})
            hostname_client = lease.get("hostname", "") or lease.get("name", "")
            if not ip:
                ip = lease.get("ip", "")

        # Find matching radio for band info
        for radio in wifi_radios or []:
            if radio.get(RADIO_KEY_IFNAME, "") == radio_ifname:
                band = radio.get(RADIO_KEY_BAND, "")
                break

        # Determine parent radio node
        parent_radio_id = ifname_to_radio_id.get(radio_ifname, gateway_id)

        client_id = _client_id(mac)
        display_name = hostname_client or ip or mac

        nodes.append(
            {
                "id": client_id,
                "name": display_name,
                "type": "client",
                "mac": mac,
                "ip": ip,
                "hostname": hostname_client,
                "ssid": ssid,
                "signal": signal,
                "signal_quality": _signal_quality(signal),
                "band": band,
                "radio": radio_ifname,
                "connection_type": "wifi",
                "status": "online",
                "icon": "mdi:laptop",
                "parent_id": parent_radio_id,
                "attributes": {},
            }
        )

        links.append(
            {
                "source": parent_radio_id,
                "target": client_id,
                "medium": "wifi",
                "band": band,
                "speed": None,
                "signal": signal,
                "signal_quality": _signal_quality(signal),
                "label": f"{signal} dBm" if signal else "",
                "confidence": "confirmed",
                "is_backhaul": False,
            }
        )

    # --- LAN clients (DHCP lease present, no WiFi association) ---
    for mac_upper, lease in lease_lookup.items():
        if mac_upper in wifi_macs or mac_upper in seen_macs:
            continue
        seen_macs.add(mac_upper)

        ip = lease.get("ip", "")
        hostname_client = lease.get("hostname", "") or lease.get("name", "")
        client_id = _client_id(mac_upper)
        display_name = hostname_client or ip or mac_upper

        nodes.append(
            {
                "id": client_id,
                "name": display_name,
                "type": "client",
                "mac": mac_upper,
                "ip": ip,
                "hostname": hostname_client,
                "ssid": "",
                "signal": None,
                "signal_quality": "unknown",
                "band": "",
                "radio": "",
                "connection_type": "lan",
                "status": "online",
                "icon": "mdi:desktop-classic",
                "parent_id": gateway_id,
                "attributes": {},
            }
        )

        links.append(
            {
                "source": gateway_id,
                "target": client_id,
                "medium": "lan",
                "band": "",
                "speed": None,
                "signal": None,
                "signal_quality": "good",
                "label": "LAN",
                "confidence": "probable",
                "is_backhaul": False,
            }
        )

    # ------------------------------------------------------------------
    # 5. Metadata
    # ------------------------------------------------------------------
    meta = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "client_count": len([n for n in nodes if n["type"] == "client"]),
        "radio_count": len([n for n in nodes if n["type"] == "radio"]),
        "wan_ip": wan_ip,
        "wan_connected": wan_connected,
        "hostname": hostname,
        "model": model,
    }

    return {
        "nodes": nodes,
        "links": links,
        "meta": meta,
    }


def topology_to_json(topology: dict[str, Any]) -> str:
    """Serialise topology dict to compact JSON string."""
    return json.dumps(topology, separators=(",", ":"))
