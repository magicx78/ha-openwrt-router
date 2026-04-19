"""topology_mesh.py — Multi-router mesh topology aggregator.

Collects per-router topology snapshots from all loaded openwrt_router
config entries, detects roles (gateway vs AP), finds inter-router
connections, and merges everything into a single unified mesh snapshot.

Architecture:
    coordinator.data (per entry)
        → topology_diagnostic.build_topology_snapshot()  (per router)
        → topology_mesh.build_mesh_snapshot()             (aggregated)
        → /api/openwrt_topology/snapshot                  (served to panel)
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any

from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import OpenWrtCoordinatorData
from .topology_diagnostic import build_topology_snapshot

_LOGGER = logging.getLogger(__name__)

MESH_SOURCE = "ha-openwrt.mesh_aggregator"


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address is RFC1918 private."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except (ValueError, TypeError):
        return True  # Can't parse → treat as private (not a gateway indicator)


def _detect_router_role(data: OpenWrtCoordinatorData, host_ip: str) -> str:
    """Classify a router as 'gateway' or 'ap' based on WAN status.

    Gateway: WAN connected with a WAN-type protocol and a non-private IP,
             or WAN IP differs from the host LAN IP.
    AP:      Everything else.
    """
    wan = data.wan_status
    if not wan.get("connected"):
        return "ap"

    proto = wan.get("proto", "")
    if proto not in ("dhcp", "pppoe", "static"):
        return "ap"

    ipv4 = wan.get("ipv4", "")
    if not ipv4:
        return "ap"

    # Public WAN IP → definitely a gateway
    if not _is_private_ip(ipv4):
        return "gateway"

    # WAN IP exists and differs from host LAN IP → likely gateway
    if ipv4 != host_ip:
        return "gateway"

    return "ap"


def _detect_inter_router_edges(
    router_snapshots: list[dict[str, Any]],
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
) -> list[dict[str, Any]]:
    """Detect connections between routers.

    Args:
        router_snapshots: Per-router topology snapshots.
        router_data: List of (router_id, host_ip, coordinator_data) tuples.

    Strategy:
        1. DHCP lease cross-reference: AP's host IP in gateway's DHCP leases → LAN uplink
        2. WiFi client cross-reference: AP's MAC in another router's client list → WiFi uplink
        3. Subnet fallback: Same /24 subnet → mesh_member (inferred)
    """
    edges: list[dict[str, Any]] = []
    seen_edges: set[str] = set()

    # Build lookup maps
    router_macs: dict[str, str] = {}  # MAC → router_id
    router_ips:  dict[str, str] = {}  # host_ip → router_id
    for rid, hip, data in router_data:
        mac = (data.router_info.get("mac") or "").upper()
        if mac:
            router_macs[mac] = rid
        if hip:
            router_ips[hip] = rid

    # Find gateway(s) for directed edges
    gateways = [
        (rid, hip, data)
        for rid, hip, data in router_data
        if _detect_router_role(data, hip) == "gateway"
    ]

    # Method 2 (WiFi client cross-reference) runs FIRST — more precise than DHCP.
    # A router seen as a WiFi client on another router is definitively a wifi_uplink.
    # Running this first means Method 1 (DHCP) cannot overwrite it via seen_edges.
    for src_rid, src_hip, src_data in router_data:
        for client in src_data.clients or []:
            client_mac = (client.get("mac") or "").upper()
            client_ip  = (client.get("ip") or "")
            # Match by MAC first, fall back to host IP (covers cases where the AP
            # registers with a different MAC than router_info.mac, e.g. wlan0 vs br-lan)
            target_rid = router_macs.get(client_mac) or router_ips.get(client_ip)
            if not target_rid or target_rid == src_rid:
                continue
            edge_id = f"{src_rid}--uplink--{target_rid}"
            if edge_id in seen_edges:
                continue
            edges.append({
                "id": edge_id,
                "from": src_rid,
                "to": target_rid,
                "relationship": "wifi_uplink",
                "source": MESH_SOURCE,
                "inferred": False,
                "inference_reason": None,
                "attributes": {
                    "link_type": "wifi",
                    "detection_method": "wifi_client_mac",
                    "client_mac": client_mac,
                    "signal": client.get("signal"),
                },
            })
            seen_edges.add(edge_id)

    # Method 1: DHCP lease cross-reference (LAN connections).
    # Runs after Method 2 so that WiFi uplinks already in seen_edges are not
    # downgraded to lan_uplink just because the AP also has a DHCP lease.
    for gw_rid, gw_hip, gw_data in gateways:
        dhcp = gw_data.dhcp_leases or {}
        for ap_rid, ap_hip, ap_data in router_data:
            if ap_rid == gw_rid:
                continue
            edge_id = f"{gw_rid}--uplink--{ap_rid}"
            if edge_id in seen_edges:
                continue

            # Check if AP's host IP appears in gateway's DHCP leases
            ap_mac = (ap_data.router_info.get("mac") or "").upper()
            found_via = None
            for lease_mac, lease_info in dhcp.items():
                if lease_info.get("ip") == ap_hip:
                    found_via = "dhcp_ip"
                    break
                if lease_mac == ap_mac:
                    found_via = "dhcp_mac"
                    break

            if found_via:
                # Resolve gateway switch port via bridge FDB (MAC → port)
                fdb: dict[str, str] = getattr(gw_data, "port_fdb_map", {})
                gateway_port: str | None = fdb.get(ap_mac.lower())
                edges.append({
                    "id": edge_id,
                    "from": gw_rid,
                    "to": ap_rid,
                    "relationship": "lan_uplink",
                    "source": MESH_SOURCE,
                    "inferred": False,
                    "inference_reason": None,
                    "attributes": {
                        "link_type": "lan",
                        "detection_method": found_via,
                        "ap_host_ip": ap_hip,
                        "gateway_port": gateway_port,
                    },
                })
                seen_edges.add(edge_id)

    # Method 3: Subnet fallback for routers with no detected uplink
    connected_aps = {
        e["to"] for e in edges
    } | {
        e["from"] for e in edges
    }

    unconnected = [
        (rid, hip, data)
        for rid, hip, data in router_data
        if rid not in connected_aps and _detect_router_role(data, hip) != "gateway"
    ]

    if unconnected and gateways:
        gw_rid, gw_hip_fallback, _ = gateways[0]
        try:
            gw_subnet = ipaddress.ip_network(f"{gw_hip_fallback}/24", strict=False)
        except (ValueError, TypeError):
            gw_subnet = None

        for ap_rid, ap_hip, _ in unconnected:
            # Only infer an uplink if the AP is on the same /24 as the gateway.
            # Routers on different subnets (e.g. VPN, WireGuard) are excluded.
            if gw_subnet is not None:
                try:
                    ap_net = ipaddress.ip_network(f"{ap_hip}/24", strict=False)
                    if not gw_subnet.overlaps(ap_net):
                        _LOGGER.debug(
                            "Subnet fallback: skipping %s (%s) — not in gateway subnet %s",
                            ap_rid, ap_hip, gw_subnet,
                        )
                        continue
                except (ValueError, TypeError):
                    pass  # Can't parse AP IP → include it anyway

            edge_id = f"{gw_rid}--uplink--{ap_rid}"
            if edge_id not in seen_edges:
                edges.append({
                    "id": edge_id,
                    "from": gw_rid,
                    "to": ap_rid,
                    "relationship": "mesh_member",
                    "source": MESH_SOURCE,
                    "inferred": True,
                    "inference_reason": "subnet_inference",
                    "attributes": {
                        "link_type": "unknown",
                        "detection_method": "subnet_fallback",
                        "ap_host_ip": ap_hip,
                    },
                })
                seen_edges.add(edge_id)

    return edges


def _deduplicate_clients(
    all_clients: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate clients by MAC — keep the entry with the strongest signal.

    A roaming client may briefly appear on two APs. Keep one occurrence.
    """
    best: dict[str, dict[str, Any]] = {}
    for client in all_clients:
        mac = client.get("mac", "")
        if not mac:
            continue
        existing = best.get(mac)
        if existing is None:
            best[mac] = client
            continue
        # Keep stronger signal (less negative = better)
        new_sig = client.get("signal")
        old_sig = existing.get("signal")
        if new_sig is not None and (old_sig is None or new_sig > old_sig):
            best[mac] = client
    return list(best.values())


def build_mesh_snapshot(hass: HomeAssistant) -> dict[str, Any]:
    """Build a unified mesh topology from all loaded openwrt_router entries.

    Collects per-router snapshots, detects roles, finds inter-router
    connections, merges into a single snapshot.

    Returns:
        Unified snapshot dict compatible with the topology panel schema.
    """
    now = datetime.now(timezone.utc).isoformat()

    entries = hass.config_entries.async_entries(DOMAIN)
    if not entries:
        return _empty_mesh(now)

    all_nodes: list[dict[str, Any]] = []
    all_edges: list[dict[str, Any]] = []
    all_interfaces: list[dict[str, Any]] = []
    all_clients: list[dict[str, Any]] = []
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]] = []

    for entry in entries:
        runtime = getattr(entry, "runtime_data", None)
        if runtime is None:
            continue
        coordinator = getattr(runtime, "coordinator", None)
        if coordinator is None or coordinator.data is None:
            continue

        data: OpenWrtCoordinatorData = coordinator.data
        host_ip = str(entry.data.get("host", ""))
        role = _detect_router_role(data, host_ip)

        # Build per-router snapshot with role and host_ip
        snapshot = build_topology_snapshot(data, role=role, host_ip=host_ip)

        # Extract router_id from the first router node
        router_node = next(
            (n for n in snapshot.get("nodes", []) if n.get("type") == "router"),
            None,
        )
        router_id = router_node["id"] if router_node else host_ip

        router_data.append((router_id, host_ip, data))
        all_nodes.extend(snapshot.get("nodes", []))
        all_edges.extend(snapshot.get("edges", []))
        all_interfaces.extend(snapshot.get("interfaces", []))
        all_clients.extend(snapshot.get("clients", []))

    if not all_nodes:
        return _empty_mesh(now)

    # Detect inter-router connections
    inter_router_edges = _detect_inter_router_edges(
        [],  # snapshots not needed — router_data has the coordinator data
        router_data,
    )
    all_edges.extend(inter_router_edges)

    # Deduplicate clients (same MAC on multiple APs during roaming)
    deduped_clients = _deduplicate_clients(all_clients)

    # Build MAC → winning ap_mac map from the deduplicated client list.
    # _deduplicate_clients() picks the router with the strongest signal.
    # We must match client *nodes* to this winner so that ap_mac in the
    # topology correctly reflects which router the client is associated with.
    winning_ap_mac: dict[str, str] = {
        c["mac"]: c.get("ap_mac", "")
        for c in deduped_clients
        if c.get("mac")
    }

    # Deduplicate client nodes — prefer the node whose ap_mac matches the
    # dedup winner (strongest-signal router).  If we encounter a duplicate
    # node ID and the new node has the winning ap_mac, replace the earlier one.
    seen_client_ids: dict[str, int] = {}  # node_id → index in deduped_nodes
    deduped_nodes: list[dict[str, Any]] = []
    for node in all_nodes:
        if node.get("type") == "client":
            node_id = node["id"]
            mac = (node.get("attributes", {}).get("mac") or "").lower()

            if node_id in seen_client_ids:
                # Replace the stored node if this one has the winning ap_mac
                node_ap_mac = (node.get("attributes", {}).get("ap_mac") or "")
                if mac and node_ap_mac == winning_ap_mac.get(mac, ""):
                    deduped_nodes[seen_client_ids[node_id]] = node
                continue

            if mac and mac in winning_ap_mac:
                seen_client_ids[node_id] = len(deduped_nodes)
                deduped_nodes.append(node)
            elif not mac:
                deduped_nodes.append(node)
        else:
            deduped_nodes.append(node)

    # Also deduplicate client edges
    seen_edge_ids: set[str] = set()
    deduped_edges: list[dict[str, Any]] = []
    for edge in all_edges:
        if edge["id"] not in seen_edge_ids:
            seen_edge_ids.add(edge["id"])
            deduped_edges.append(edge)

    # Cross-enrich client nodes with DHCP leases from ALL routers.
    # Secondary APs don't run DHCP — their clients have no IP/hostname from
    # their own coordinator. The gateway's DHCP table covers all LAN clients.
    merged_leases: dict[str, dict[str, Any]] = {}
    for _, _, data in router_data:
        for lease_mac, lease_info in (data.dhcp_leases or {}).items():
            key = lease_mac.lower().replace("-", ":").replace(".", ":")
            if key not in merged_leases:
                merged_leases[key] = lease_info

    for node in deduped_nodes:
        if node.get("type") != "client":
            continue
        attrs = node.get("attributes", {})
        mac = (attrs.get("mac") or "").lower()
        if not mac:
            continue
        lease = merged_leases.get(mac)
        if not lease:
            continue
        if not attrs.get("ip") and lease.get("ip"):
            attrs["ip"] = lease["ip"]
        if not attrs.get("hostname") and lease.get("hostname"):
            attrs["hostname"] = lease["hostname"]
            # Also update the node label if it was falling back to MAC
            if node.get("label") == mac:
                node["label"] = attrs["hostname"]
        if not attrs.get("dhcp_expires") and lease.get("expires"):
            attrs["dhcp_expires"] = int(lease["expires"])

    # Inject DSL history + ping + DuckDNS into the gateway router node.
    # Only the coordinator with role=gateway has this data (others return empty).
    # ping_ms and ddns_status are always polled (independent of Fritz!Box).
    # dsl_stats / wan_traffic are only present when Fritz!Box is configured and reachable.
    for rid, hip, data in router_data:
        if _detect_router_role(data, hip) != "gateway":
            continue
        for node in deduped_nodes:
            if node.get("type") == "router" and node.get("id") == rid:
                attrs = node.setdefault("attributes", {})
                dsl_stats = getattr(data, "dsl_stats", {}) or {}
                wan_traffic = getattr(data, "wan_traffic", {}) or {}
                if dsl_stats:
                    attrs["dsl_stats"] = dsl_stats
                # Always include wan_traffic so frontend can show native OpenWrt throughput
                attrs["wan_traffic"] = wan_traffic
                attrs["ping_ms"] = getattr(data, "ping_ms", None)
                attrs["dsl_history"] = getattr(data, "dsl_history", []) or []
                attrs["ddns_status"] = getattr(data, "ddns_status", []) or []
                break
        break  # only one gateway

    router_count = sum(1 for n in deduped_nodes if n.get("type") == "router")
    client_count = sum(1 for n in deduped_nodes if n.get("type") == "client")
    iface_count = len(all_interfaces)
    inference_used = any(
        bool(x.get("inferred"))
        for x in [*deduped_nodes, *deduped_edges, *all_interfaces, *deduped_clients]
    )

    return {
        "generated_at": now,
        "nodes": deduped_nodes,
        "edges": deduped_edges,
        "interfaces": all_interfaces,
        "clients": deduped_clients,
        "meta": {
            "source": MESH_SOURCE,
            "schema_version": "1.0",
            "inference_used": inference_used,
            "node_count": len(deduped_nodes),
            "edge_count": len(deduped_edges),
            "interface_count": iface_count,
            "client_count": client_count,
            "router_count": router_count,
            "mesh": True,
        },
    }


def _empty_mesh(now: str) -> dict[str, Any]:
    """Return an empty mesh snapshot."""
    return {
        "generated_at": now,
        "nodes": [],
        "edges": [],
        "interfaces": [],
        "clients": [],
        "meta": {
            "source": MESH_SOURCE,
            "schema_version": "1.0",
            "inference_used": False,
            "node_count": 0,
            "edge_count": 0,
            "interface_count": 0,
            "client_count": 0,
            "router_count": 0,
            "mesh": True,
        },
    }
