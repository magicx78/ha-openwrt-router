"""topology_ports.py — Physical-port → connected-device mapping.

Pure functions that combine the bridge FDB, DHCP leases and the ARP
table into a per-port device model with an explicit confidence level.

Design rules (never fake a mapping):
  - Identities without a reliable FDB port observation go to the
    "unassigned" bucket instead of being pinned to an arbitrary port.
  - Wireless clients are never attributed to LAN ports.
  - Router-own MACs (bridge/AP/STA interfaces) are filtered out.
  - WAN ports never receive FDB devices — wan is not a br-lan member,
    so any FDB match there would be fabrication.
  - DHCP leases without a live FDB/ARP observation are dropped
    (a stale lease is not a connected device).

Confidence model:
  high   = MAC seen in bridge FDB on a physical port + full identity
           (IP and hostname) from DHCP/ARP
  medium = FDB port match, but identity only partial (IP-only,
           hostname-only, bare MAC, or DHCP/ARP IP conflict)
  low    = identity known (DHCP/ARP) but no reliable port → unassigned
  none   = no mapping possible
"""

from __future__ import annotations

import ipaddress
from typing import Any

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CONFIDENCE_NONE = "none"

_CONFIDENCE_RANK = {
    CONFIDENCE_HIGH: 0,
    CONFIDENCE_MEDIUM: 1,
    CONFIDENCE_LOW: 2,
    CONFIDENCE_NONE: 3,
}

# Payload guards — device_count always reports the uncapped total.
_MAX_DEVICES_PER_PORT = 16
_MAX_UNASSIGNED = 32
_MAX_DEBUG_LIST = 32


def normalize_mac(mac: str | None) -> str:
    """Normalise a MAC address to lowercase colon-separated form."""
    return (mac or "").strip().lower().replace("-", ":").replace(".", ":")


def safe_web_url(ip: str | None) -> str | None:
    """Return ``http://<ip>`` for a valid IPv4 address, else None.

    The URL is built from a validated address literal only — never from
    an arbitrary string. Plain http on purpose: LAN device UIs rarely
    serve HTTPS and the link is an optional quick access, no credentials.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return f"http://{addr}"


def _is_multicast_or_broadcast(mac: str) -> bool:
    """True for multicast/broadcast (bit 0 of first octet) or garbage MACs."""
    try:
        first_octet = int(mac.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return True
    return bool(first_octet & 0x01)


def _port_role(name: str) -> str:
    """Classify a physical port name as wan or lan."""
    return "wan" if name.startswith("wan") else "lan"


def collect_wifi_client_macs(clients: list[dict[str, Any]] | None) -> set[str]:
    """Normalised MACs of all associated WiFi clients (hostapd/iwinfo)."""
    return {
        normalize_mac(client.get("mac"))
        for client in (clients or [])
        if client.get("mac")
    }


def collect_own_macs(
    router_info: dict[str, Any] | None,
    ap_interfaces: list[dict[str, Any]] | None,
    sta_interfaces: list[dict[str, Any]] | None,
) -> set[str]:
    """Normalised MACs owned by this router (never connected devices).

    Includes the board MAC, own AP BSSIDs/MACs and own STA-interface
    MACs. The BSSID a STA is *associated to* belongs to a peer router
    and is intentionally NOT included — the mesh stage recognises peers
    as router devices instead.
    """
    own: set[str] = set()
    board_mac = normalize_mac((router_info or {}).get("mac"))
    if board_mac:
        own.add(board_mac)
    for ap in ap_interfaces or []:
        for key in ("bssid", "mac"):
            mac = normalize_mac(ap.get(key))
            if mac:
                own.add(mac)
    for sta in sta_interfaces or []:
        mac = normalize_mac(sta.get("mac"))
        if mac:
            own.add(mac)
    return own


def _sort_key(device: dict[str, Any]) -> tuple[int, int, str]:
    """Deterministic device ordering: confidence, named-first, MAC."""
    return (
        _CONFIDENCE_RANK.get(device.get("confidence", ""), 3),
        0 if device.get("name") else 1,
        device.get("mac", ""),
    )


def best_confidence(devices: list[dict[str, Any]]) -> str:
    """Best (highest) confidence across a device list, none when empty."""
    if not devices:
        return CONFIDENCE_NONE
    return min(
        (device.get("confidence", CONFIDENCE_NONE) for device in devices),
        key=lambda c: _CONFIDENCE_RANK.get(c, 3),
    )


def apply_devices_to_port(port: dict[str, Any], devices: list[dict[str, Any]]) -> None:
    """Write the summary fields for a final device list onto a port dict.

    Caps the stored list at _MAX_DEVICES_PER_PORT while device_count
    keeps reporting the uncapped total.
    """
    port["connected_devices"] = devices[:_MAX_DEVICES_PER_PORT]
    port["device_count"] = len(devices)
    port["primary_device"] = devices[0] if devices else None
    port["web_url"] = devices[0].get("web_url") if devices else None
    port["has_downstream_switch"] = len(devices) > 1
    port["mapping_confidence"] = best_confidence(devices)


def build_port_connections(
    *,
    port_stats: list[dict[str, Any]] | None,
    fdb: dict[str, str] | None,
    dhcp_leases: dict[str, dict[str, str]] | None,
    arp_table: dict[str, str] | None,
    wifi_client_macs: set[str] | None = None,
    own_macs: set[str] | None = None,
    include_debug: bool = False,
) -> dict[str, Any]:
    """Build the per-port device mapping from FDB + DHCP + ARP.

    Args:
        port_stats: Raw port stats from the coordinator (name/up/speed…).
        fdb: MAC → physical port name (bridge FDB, is_local pre-filtered).
        dhcp_leases: MAC → {ip, hostname, expires} (any MAC casing).
        arp_table: MAC → IPv4 (complete ARP entries only).
        wifi_client_macs: MACs of associated WiFi clients to exclude.
        own_macs: Router-own MACs to exclude.
        include_debug: Attach a per-port debug trace explaining the mapping.

    Returns:
        {"ports": {port_name: port_dict}, "unassigned": [device...],
         "debug": {port_name: trace} | None}
    """
    leases_by_mac = {
        normalize_mac(mac): lease for mac, lease in (dhcp_leases or {}).items()
    }
    arp_by_mac = {normalize_mac(mac): ip for mac, ip in (arp_table or {}).items()}
    wifi_macs = {normalize_mac(mac) for mac in (wifi_client_macs or set())}
    own = {normalize_mac(mac) for mac in (own_macs or set())}

    ports: dict[str, dict[str, Any]] = {}
    for stat in port_stats or []:
        name = stat.get("name", "")
        if not name:
            continue
        ports[name] = {
            "port_label": name.upper(),
            "logical_name": name,
            "role": _port_role(name),
            "link_up": bool(stat.get("up", False)),
            "speed_mbps": stat.get("speed_mbps"),
            "connected_devices": [],
            "primary_device": None,
            "device_count": 0,
            "has_downstream_switch": False,
            "web_url": None,
            "mapping_confidence": CONFIDENCE_NONE,
        }

    debug: dict[str, dict[str, Any]] = {}
    if include_debug:
        for name in ports:
            debug[name] = {
                "fdb_macs": [],
                "dhcp_matches": [],
                "arp_matches": [],
                "filtered_own": [],
                "filtered_wireless": [],
                "filtered_multicast": 0,
                "final": [],
                "confidence": CONFIDENCE_NONE,
                "reason": None,
            }

    def _debug_list(port: str, key: str, value: Any) -> None:
        if include_debug and port in debug:
            bucket = debug[port][key]
            if isinstance(bucket, list) and len(bucket) < _MAX_DEBUG_LIST:
                bucket.append(value)

    unassigned: list[dict[str, Any]] = []
    assigned_macs: set[str] = set()

    def _identity(mac: str) -> tuple[str | None, str | None, list[str], str | None]:
        """Resolve (ip, name, extra_sources, conflict_reason) for a MAC."""
        lease = leases_by_mac.get(mac) or {}
        lease_ip = lease.get("ip") or None
        hostname = lease.get("hostname") or lease.get("name") or None
        arp_ip = arp_by_mac.get(mac)
        sources: list[str] = []
        if lease:
            sources.append("dhcp")
        if arp_ip:
            sources.append("arp")
        conflict: str | None = None
        ip = lease_ip or arp_ip
        if lease_ip and arp_ip and lease_ip != arp_ip:
            # ARP is the live observation; a stale lease loses.
            ip = arp_ip
            conflict = "ip_conflict"
        return ip, hostname, sources, conflict

    # ── Pass 1: FDB-observed MACs → port assignment ────────────────
    for mac, port_name in sorted((fdb or {}).items()):
        mac = normalize_mac(mac)
        if not mac:
            continue
        if include_debug and port_name in debug:
            _debug_list(port_name, "fdb_macs", mac)
        if _is_multicast_or_broadcast(mac) or mac == "00:00:00:00:00:00":
            if include_debug and port_name in debug:
                debug[port_name]["filtered_multicast"] += 1
            continue
        if mac in own:
            _debug_list(port_name, "filtered_own", mac)
            continue
        if mac in wifi_macs:
            _debug_list(port_name, "filtered_wireless", mac)
            continue

        ip, hostname, extra_sources, conflict = _identity(mac)
        port = ports.get(port_name)
        if port is None or port["role"] == "wan":
            # FDB names a port the UI does not know, or claims a device on
            # the WAN uplink — never attribute; keep the identity honest.
            if ip or hostname:
                unassigned.append(
                    {
                        "mac": mac,
                        "ip": ip,
                        "name": hostname,
                        "source": "+".join(["fdb", *extra_sources]),
                        "confidence": CONFIDENCE_LOW,
                        "web_url": safe_web_url(ip),
                        "reason": (
                            "wan_port_excluded" if port is not None else "unknown_port"
                        ),
                    }
                )
            continue

        if include_debug:
            lease = leases_by_mac.get(mac)
            if lease:
                _debug_list(
                    port_name,
                    "dhcp_matches",
                    {
                        "mac": mac,
                        "ip": lease.get("ip"),
                        "hostname": lease.get("hostname"),
                    },
                )
            if mac in arp_by_mac:
                _debug_list(
                    port_name, "arp_matches", {"mac": mac, "ip": arp_by_mac[mac]}
                )

        if ip and hostname and not conflict:
            confidence = CONFIDENCE_HIGH
        else:
            confidence = CONFIDENCE_MEDIUM

        port["connected_devices"].append(
            {
                "mac": mac,
                "ip": ip,
                "name": hostname,
                "source": "+".join(["fdb", *extra_sources]),
                "confidence": confidence,
                "web_url": safe_web_url(ip),
            }
        )
        assigned_macs.add(mac)

    # ── Pass 2: identities without any FDB port → unassigned ──────
    # Only ARP-reachable MACs qualify: a DHCP lease alone is no proof the
    # device is currently connected (stale leases would fake presence).
    for mac in sorted(set(leases_by_mac) | set(arp_by_mac)):
        if (
            not mac
            or mac in assigned_macs
            or mac in own
            or mac in wifi_macs
            or mac in (fdb or {})
            or _is_multicast_or_broadcast(mac)
        ):
            continue
        if mac not in arp_by_mac:
            continue  # lease-only ghost → drop
        if len(unassigned) >= _MAX_UNASSIGNED:
            break
        ip, hostname, extra_sources, _conflict = _identity(mac)
        unassigned.append(
            {
                "mac": mac,
                "ip": ip,
                "name": hostname,
                "source": "+".join(extra_sources),
                "confidence": CONFIDENCE_LOW,
                "web_url": safe_web_url(ip),
                "reason": "unknown_port",
            }
        )

    # ── Finalise per-port: sort, cap, derive summary fields ───────
    for name, port in ports.items():
        devices = sorted(port["connected_devices"], key=_sort_key)
        total = len(devices)
        apply_devices_to_port(port, devices)

        if include_debug and name in debug:
            trace = debug[name]
            trace["final"] = [d["mac"] for d in port["connected_devices"]]
            trace["confidence"] = port["mapping_confidence"]
            if port["role"] == "wan":
                trace["reason"] = "wan uplink — FDB cannot observe the WAN side"
            elif total:
                trace["reason"] = (
                    f"{total} MAC(s) seen in bridge FDB on {name}; identity "
                    "resolved via DHCP/ARP where available"
                )
            elif port["link_up"]:
                trace["reason"] = (
                    "link up but no FDB entries — device silent or FDB aged out"
                )
            else:
                trace["reason"] = "link down"

    return {
        "ports": ports,
        "unassigned": unassigned[:_MAX_UNASSIGNED],
        "debug": debug if include_debug else None,
    }


def redacted_port_summary(data: Any) -> dict[str, Any]:
    """PII-free per-port mapping summary for HA diagnostics.

    Contains only port names, counts, confidence and source flags —
    never MAC addresses, IPs or hostnames. Full raw mapping data is
    available via the auth-protected topology snapshot endpoint.
    """
    result = build_port_connections(
        port_stats=getattr(data, "port_stats", None),
        fdb=getattr(data, "port_fdb_map", None),
        dhcp_leases=getattr(data, "dhcp_leases", None),
        arp_table=getattr(data, "arp_table", None),
        wifi_client_macs=collect_wifi_client_macs(getattr(data, "clients", None)),
        own_macs=collect_own_macs(
            getattr(data, "router_info", None),
            getattr(data, "ap_interfaces", None),
            getattr(data, "sta_interfaces", None),
        ),
    )
    ports_summary = []
    for name in sorted(result["ports"]):
        port = result["ports"][name]
        sources = sorted(
            {
                source
                for device in port["connected_devices"]
                for source in (device.get("source") or "").split("+")
                if source
            }
        )
        ports_summary.append(
            {
                "name": name,
                "link_up": port["link_up"],
                "device_count": port["device_count"],
                "mapping_confidence": port["mapping_confidence"],
                "has_downstream_switch": port["has_downstream_switch"],
                "sources": sources,
            }
        )
    return {
        "ports": ports_summary,
        "unassigned_count": len(result["unassigned"]),
    }
