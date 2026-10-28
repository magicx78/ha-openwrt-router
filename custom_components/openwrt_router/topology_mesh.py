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
from collections.abc import Collection
from datetime import UTC, datetime
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import (
    CONF_TOPOLOGY_PORT_DEBUG,
    CONNECTION_TYPE_ROUTER_UPLINK,
    DEFAULT_TOPOLOGY_PORT_DEBUG,
    DOMAIN,
    LLDP_KEY_CAPABILITIES,
    LLDP_KEY_CHASSIS_ID,
    LLDP_KEY_CHASSIS_NAME,
    LLDP_KEY_LOCAL_INTERFACE,
    LLDP_KEY_MGMT_IP,
    LLDP_KEY_PORT_DESCR,
    LLDP_KEY_PORT_ID,
    SOURCE_LLDP,
    WAN_PROTOS,
)

# Aliased: topology_ports exports a CONFIDENCE_HIGH of its own.
from .const import CONFIDENCE_HIGH as CONF_HIGH
from .coordinator import OpenWrtCoordinatorData
from .topology_diagnostic import build_topology_snapshot, router_node_id
from .topology_ports import (
    CONFIDENCE_HIGH,
    apply_devices_to_port,
    collect_own_macs,
    collect_wifi_client_macs,
    normalize_mac,
    safe_web_url,
)

_LOGGER = logging.getLogger(__name__)

MESH_SOURCE = "ha-openwrt.mesh_aggregator"


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address is RFC1918 private."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except (ValueError, TypeError):
        return True  # Can't parse → treat as private (not a gateway indicator)


# ISP-uplink protocols that make a connected WAN a gateway (see
# _detect_router_role): IPv4, IPv6-only and transition protocols, plus the
# upstream-only ones shared with the WAN detection. VPN protocols are not here.
_GATEWAY_PROTOS: frozenset[str] = (
    frozenset(
        {"dhcp", "static", "pppoe", "dhcpv6", "dslite", "map", "6in4", "6rd", "6to4"}
    )
    | WAN_PROTOS
)


# Role memory: router id → ISO time of the last snapshot in which it was a
# gateway with a connected WAN. Process-wide (one mesh per HA instance), not
# persisted across restarts. See _resolve_router_roles / _remember_gateways.
_GATEWAY_MEMORY: dict[str, str] = {}

# Role evidence levels (see _gateway_evidence).
_EVIDENCE_STRONG = 2
_EVIDENCE_WEAK = 1
_EVIDENCE_NONE = 0

# OpenWrt's default wan/wan6 protocols. A dumb AP that keeps its unplugged
# default sections reports these; pppoe/static/cellular are set up by hand.
_DEFAULT_WAN_PROTOS: frozenset[str] = frozenset({"dhcp", "dhcpv6"})


def _gateway_evidence(data: OpenWrtCoordinatorData, host_ip: str) -> int:
    """Return how strongly the router's own WAN status marks it as a gateway.

    Strong: a connected WAN with an ISP-uplink protocol (dhcp, static, pppoe,
            the IPv6-only and transition protocols dhcpv6, dslite, map, 6in4,
            6rd, 6to4, or one of the upstream-only protocols in WAN_PROTOS:
            cellular qmi/mbim/ncm/modemmanager/3g/wwan, pppoa), or the SSH
            fallback shape (no ``wan_found``, no interface, no proto) with
            ``connected`` True. Private vs. public WAN IP does NOT matter —
            many gateways sit behind an ISP modem.
    Weak:   a *configured* WAN (``wan_found`` True, or — data without
            ``wan_found`` — a named WAN interface) with an ISP-uplink protocol
            whose link is down: the gateway during an outage, but just as
            well a dumb AP with OpenWrt's default, unplugged ``wan`` section.
    None:   no WAN (``wan_found`` False), a protocol that is not an ISP uplink
            (VPN tunnels, none, a ubus-found WAN without proto), or a "WAN"
            carrying the router's own host IP (bridged port on a dumb AP).

    DHCP pools are deliberately NOT evidence: OpenWrt's defaults leave the
    lan pool active on a dumb AP (dnsmasq defers to the real server), and an
    SSH-fallback gateway cannot read its pools at all.
    """
    wan = data.wan_status or {}
    if wan.get("wan_found") is False:
        return _EVIDENCE_NONE
    proto = wan.get("proto") or ""
    if not proto:
        ssh_shape = "wan_found" not in wan and not wan.get("interface")
        return (
            _EVIDENCE_STRONG if ssh_shape and wan.get("connected") else _EVIDENCE_NONE
        )
    if proto not in _GATEWAY_PROTOS:
        return _EVIDENCE_NONE
    if wan.get("ipv4") and wan.get("ipv4") == host_ip:
        return _EVIDENCE_NONE
    if wan.get("connected"):
        return _EVIDENCE_STRONG
    if wan.get("wan_found") is True or wan.get("interface"):
        return _EVIDENCE_WEAK
    return _EVIDENCE_NONE


def _resolve_router_roles(
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
    remembered: Collection[str] = (),
) -> dict[str, str]:
    """Classify every router of the fleet as 'gateway' or 'ap'.

    1. Every router with strong evidence (connected WAN) is a gateway —
       several sites or dual gateways are possible.
    2. Without any strong router (WAN outage), every ``remembered`` gateway
       (gateway of the last snapshot) that is still in the fleet and still
       has a configured WAN (``wan_found`` not False) stays gateway; nothing
       else is promoted.
    3. Without strong and remembered routers (fresh start during an outage),
       exactly ONE weak candidate becomes gateway: a non-default protocol
       before OpenWrt's default dhcp/dhcpv6, then the lowest router id.
    """
    evidence = {rid: _gateway_evidence(data, hip) for rid, hip, data in router_data}
    roles = dict.fromkeys(evidence, "ap")
    strong = [rid for rid, level in evidence.items() if level == _EVIDENCE_STRONG]
    if strong:
        roles.update(dict.fromkeys(strong, "gateway"))
        return roles
    kept = [
        rid
        for rid, _hip, data in router_data
        if rid in remembered and (data.wan_status or {}).get("wan_found") is not False
    ]
    if kept:
        roles.update(dict.fromkeys(kept, "gateway"))
        return roles
    candidates = [
        (
            (data.wan_status or {}).get("proto") in _DEFAULT_WAN_PROTOS,
            rid,
        )
        for rid, _hip, data in router_data
        if evidence[rid] == _EVIDENCE_WEAK
    ]
    if candidates:
        roles[min(candidates)[1]] = "gateway"
    return roles


def _remember_gateways(
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]], now: str
) -> None:
    """Replace the role memory by the strong gateways of this snapshot.

    Left untouched when no router is strong, so the gateway of the last
    connected snapshot keeps its role for the whole outage.
    """
    strong = [
        rid
        for rid, hip, data in router_data
        if _gateway_evidence(data, hip) == _EVIDENCE_STRONG
    ]
    if strong:
        _GATEWAY_MEMORY.clear()
        _GATEWAY_MEMORY.update(dict.fromkeys(strong, now))


def _detect_router_role(data: OpenWrtCoordinatorData, host_ip: str) -> str:
    """Classify a single router as 'gateway' or 'ap' (fleet of one, no memory).

    See :func:`_gateway_evidence`; mesh code uses :func:`_resolve_router_roles`
    so a candidate is weighed against the rest of the fleet and the memory.
    """
    return _resolve_router_roles([("", host_ip, data)])[""]


def _ordered_gateways(
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
    roles: dict[str, str],
) -> list[tuple[str, str, OpenWrtCoordinatorData]]:
    """Gateways in a stable order: connected WAN before outage, then router id.

    Wherever a single gateway is used (subnet fallback, switch inference) or
    the first gateway claims an AP, the connected one wins deterministically.
    """
    return sorted(
        (item for item in router_data if roles.get(item[0]) == "gateway"),
        key=lambda item: (not (item[2].wan_status or {}).get("connected"), item[0]),
    )


# 802.11s mesh-backhaul modes. A mesh point is a wireless uplink even though
# iwinfo/UCI expose neither a client-style BSSID nor a per-peer signal the way
# mode=sta does — so its mere (enabled) presence counts as an active uplink.
# get_sta_interface_details() already drops *disabled* wifi-ifaces, so a mesh
# entry reaching here is a real, configured backhaul.
_MESH_STA_MODES: frozenset[str] = frozenset({"mesh", "mesh point", "mesh_point"})


def _has_active_sta_interface(data: OpenWrtCoordinatorData) -> bool:
    """Return True if the router has at least one active wireless-uplink iface.

    Two shapes count as an active wireless uplink:

    * A **client STA-mode** interface that is actually associated — indicated by
      a non-empty BSSID together with a numeric signal value.  A bare UCI
      sta-mode entry without iwinfo data is not enough (it might be disabled or
      never brought up), so those are ignored.
    * A **mesh-point (802.11s)** backhaul interface.  A mesh link does not
      report a client-style BSSID/signal, so requiring them would misclassify a
      wirelessly-meshed AP as wired ("Kabel").  Its presence alone counts.
    """
    for sta in getattr(data, "sta_interfaces", None) or []:
        mode = (sta.get("mode") or "").strip().lower()
        if mode in _MESH_STA_MODES:
            return True
        bssid = (sta.get("bssid") or "").strip()
        signal = sta.get("signal")
        if bssid and signal is not None:
            return True
    return False


def _has_wan_carrier(data: OpenWrtCoordinatorData) -> bool:
    """Return True if any port whose name starts with 'wan' has link carrier.

    Used to short-circuit the repeater override: if the WAN port shows
    ``up=True`` the router is physically uplinked via Ethernet, even if a
    STA-mode wireless interface is also configured.
    """
    for port in getattr(data, "port_stats", None) or []:
        name = (port.get("name") or "").lower()
        if name.startswith("wan") and port.get("up") is True:
            return True
    return False


# Interface-name prefixes that identify a wireless netdev on OpenWrt. lldpd
# reports the bridge member it received the frame on, so a WDS/4addr or mesh
# backhaul shows up as e.g. "wlan0-1" / "mesh0" while a cabled link shows up as
# "lan1" / "eth0.20".
_WIRELESS_IFACE_PREFIXES = ("wlan", "wl", "wds", "mesh", "ath", "phy", "sta", "radio")


def _lldp_link_is_wireless(*ifaces: str) -> bool:
    """Return True if any of the given LLDP interface names is a wireless netdev.

    LLDP knows the medium first-hand, which is stronger evidence than the
    STA-interface heuristic used by the repeater override further down.
    """
    for iface in ifaces:
        name = (iface or "").strip().lower()
        if name.startswith(_WIRELESS_IFACE_PREFIXES):
            return True
    return False


def _is_wired_uplink_edge(edge: dict[str, Any]) -> bool:
    """Return True for edges that represent a physical Ethernet uplink.

    Covers plain ``lan_uplink`` edges and LLDP-verified ``router_uplink`` edges
    over copper — both carry a real gateway port and therefore both are valid
    input for the unmanaged-switch inference.
    """
    relationship = edge.get("relationship")
    if relationship == "lan_uplink":
        return True
    if relationship != CONNECTION_TYPE_ROUTER_UPLINK:
        return False
    return ((edge.get("attributes") or {}).get("link_type")) != "wifi"


# ---------------------------------------------------------------------------
# LLDP: preferred, authoritative source for router-to-router wiring
# ---------------------------------------------------------------------------
# LLDP gives real link-layer neighbors plus the local and remote physical
# ports. Crucially, a router-to-router link is only ever created when a real
# data source shows one router actually seeing another — never merely because
# two routers are configured, and never from IP ordering. Router count is
# whatever the config entries yield (router_data), so 1/2/3/N all work.


def _normalize_lldp_port(iface: str) -> str:
    """Reduce an LLDP local interface to a physical port name (strip VLAN)."""
    return (iface or "").split(".")[0].strip().lower()


def _lldp_neighbor_sort_key(neigh: dict[str, Any]) -> tuple[str, ...]:
    """Stable order for one router's LLDP neighbor table (local port first)."""
    return tuple(
        str(neigh.get(key) or "").lower()
        for key in (
            LLDP_KEY_LOCAL_INTERFACE,
            LLDP_KEY_PORT_ID,
            LLDP_KEY_CHASSIS_ID,
            LLDP_KEY_MGMT_IP,
            LLDP_KEY_CHASSIS_NAME,
        )
    )


def _mac_norm(value: str | None) -> str:
    """Normalise a MAC-like token to ``aa:bb:...`` lower-case, else ''."""
    if not value:
        return ""
    hexonly = "".join(c for c in str(value).lower() if c in "0123456789abcdef")
    if len(hexonly) != 12:
        return ""
    return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))


def _build_known_router_index(
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    """Build identity lookup maps for the configured (known) routers.

    Returns ``(token_to_rid, meta)`` where ``token_to_rid`` maps every known
    identity token (management IP, LAN/bridge/interface MAC, hostname) to its
    router_id, and ``meta[rid]`` holds ``{host_ip, hostname, macs}``. This is
    the basis for classifying an LLDP neighbor (or an FDB/ARP hit) as a *known
    router* rather than an ordinary client. Derived entirely from the live
    config entries — no hard-coded router list, no IP-order assumptions.
    """
    token_to_rid: dict[str, str] = {}
    meta: dict[str, dict[str, Any]] = {}

    def _add(token: str | None, rid: str) -> None:
        if token:
            token_to_rid.setdefault(str(token).lower(), rid)

    # A hostname identifies a router only when no other router of the fleet
    # carries it: three factory-named "OpenWrt" routers would otherwise all
    # resolve to the first one and break LLDP matching.
    hostname_owners: dict[str, set[str]] = {}
    for rid, _hip, data in router_data:
        name = str((data.router_info or {}).get("hostname") or "").lower()
        if name:
            hostname_owners.setdefault(name, set()).add(rid)

    for rid, hip, data in router_data:
        info = data.router_info or {}
        entry_meta = meta.setdefault(
            rid,
            {"host_ip": hip, "hostname": info.get("hostname", ""), "macs": set()},
        )
        _add(hip, rid)
        mac = _mac_norm(info.get("mac"))
        if mac:
            _add(mac, rid)
            entry_meta["macs"].add(mac)
        hostname = str(info.get("hostname") or "").lower()
        if len(hostname_owners.get(hostname, ())) == 1:
            _add(hostname, rid)
        for iface in data.network_interfaces or []:
            _add(iface.get("ipv4_addr"), rid)
            imac = _mac_norm(iface.get("mac"))
            if imac:
                _add(imac, rid)
                entry_meta["macs"].add(imac)
        for ap_iface in data.ap_interfaces or []:
            bssid = _mac_norm(ap_iface.get("bssid"))
            if bssid:
                _add(bssid, rid)
                entry_meta["macs"].add(bssid)
        for sta in getattr(data, "sta_interfaces", None) or []:
            smac = _mac_norm(sta.get("mac"))
            if smac:
                _add(smac, rid)
                entry_meta["macs"].add(smac)
    return token_to_rid, meta


def _match_lldp_neighbor(
    neigh: dict[str, Any], token_to_rid: dict[str, str]
) -> str | None:
    """Return the router_id a neighbor matches, or None if it is not a known router.

    Order: management IP, chassis ID (usually the MAC), chassis name (only
    indexed when unique across the fleet), port ID. The chassis ID comes
    before the name because hostnames are often left at "OpenWrt".
    """

    def _lookup(key: str, *, as_mac: bool) -> str | None:
        tok = neigh.get(key)
        if not tok:
            return None
        raw = str(tok).lower()
        if raw in token_to_rid:
            return token_to_rid[raw]
        if as_mac:
            norm = _mac_norm(tok)
            if norm and norm in token_to_rid:
                return token_to_rid[norm]
        return None

    return (
        _lookup(LLDP_KEY_MGMT_IP, as_mac=False)
        or _lookup(LLDP_KEY_CHASSIS_ID, as_mac=True)
        or _lookup(LLDP_KEY_CHASSIS_NAME, as_mac=False)
        or _lookup(LLDP_KEY_PORT_ID, as_mac=True)
    )


def _lldp_hop_depths(
    pairs: set[frozenset[str]],
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
    roles: dict[str, str] | None = None,
) -> dict[str, int]:
    """Hop distance of every router from the nearest gateway, over LLDP links.

    Consumers point an uplink edge at exactly one downstream router, so the
    orientation of a router↔router edge has to follow the actual cabling: in a
    chain (gateway → A → B) the edge between A and B must run A→B, not the
    other way round. Alphabetical order cannot know that; hop distance can.
    """
    adjacency: dict[str, set[str]] = {}
    for pair in pairs:
        a, b = tuple(pair)
        adjacency.setdefault(a, set()).add(b)
        adjacency.setdefault(b, set()).add(a)

    depths: dict[str, int] = {}
    if roles is None:
        roles = _resolve_router_roles(router_data)
    frontier = [rid for rid, _hip, _data in router_data if roles[rid] == "gateway"]
    for rid in frontier:
        depths[rid] = 0
    depth = 0
    while frontier:
        depth += 1
        nxt: list[str] = []
        for rid in frontier:
            for peer in adjacency.get(rid, ()):
                if peer not in depths:
                    depths[peer] = depth
                    nxt.append(peer)
        frontier = nxt
    return depths


def _lldp_wan_side(a_iface: str, b_iface: str) -> int | None:
    """Return which side (0 = a, 1 = b) faces the link through its WAN port.

    On OpenWrt a downstream router is wired through its ``wan`` port, so a
    link seen on ``wan`` on exactly one side points *to* that side. None when
    neither or both sides report a WAN port (or the names are unknown).
    """

    def _is_wan(name: str) -> bool:
        lowered = (name or "").strip().lower()
        return lowered.startswith("wan") and not _lldp_link_is_wireless(lowered)

    a_wan, b_wan = _is_wan(a_iface), _is_wan(b_iface)
    if a_wan and not b_wan:
        return 0
    if b_wan and not a_wan:
        return 1
    return None


def _orient_lldp_pair(
    rid_a: str,
    rid_b: str,
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
    depths: dict[str, int] | None = None,
    a_iface: str = "",
    b_iface: str = "",
    roles: dict[str, str] | None = None,
) -> tuple[str, str, bool]:
    """Choose a from/to orientation for a router-to-router LLDP edge.

    Orientation is presentation-only (both physical port sides are always
    carried on the edge), but it decides which endpoint downstream consumers
    treat as the *uplink target* — so it must point away from the gateway.
    A gateway endpoint always becomes ``from``; otherwise the endpoint closer
    to a gateway (in LLDP hops) wins; otherwise the side that reports its
    WAN port on the link is the downstream one; only a genuine tie falls back
    to a stable router_id sort. This is deliberately NOT based on IP ordering —
    the cabling itself is what LLDP reports.

    The third element says whether the orientation is *anchored* in evidence
    (gateway role, hop depth or WAN port) or merely the sort fallback. Only an
    anchored ``to`` side counts as "has its uplink" for the heuristics: a
    guessed orientation must not cost a router its (correct) gateway edge.
    """
    if roles is None:
        roles = _resolve_router_roles(router_data)
    a_gw = roles.get(rid_a) == "gateway"
    b_gw = roles.get(rid_b) == "gateway"
    if a_gw and not b_gw:
        return rid_a, rid_b, True
    if b_gw and not a_gw:
        return rid_b, rid_a, True
    if depths:
        unreachable = len(router_data) + 1
        depth_a = depths.get(rid_a, unreachable)
        depth_b = depths.get(rid_b, unreachable)
        if depth_a != depth_b:
            return ((rid_a, rid_b) if depth_a < depth_b else (rid_b, rid_a)) + (True,)
    wan_side = _lldp_wan_side(a_iface, b_iface)
    if wan_side == 0:
        return rid_b, rid_a, True  # a is wired through its WAN port → downstream
    if wan_side == 1:
        return rid_a, rid_b, True
    return ((rid_a, rid_b) if rid_a <= rid_b else (rid_b, rid_a)) + (False,)


def _orient_lldp_edge(
    rid_a: str,
    rid_b: str,
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
    depths: dict[str, int] | None = None,
) -> tuple[str, str]:
    """Orientation only (see :func:`_orient_lldp_pair`), kept for callers/tests."""
    from_rid, to_rid, _anchored = _orient_lldp_pair(rid_a, rid_b, router_data, depths)
    return from_rid, to_rid


def _detect_lldp_edges(
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
    token_to_rid: dict[str, str],
    meta: dict[str, dict[str, Any]],
    roles: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], set[str], set[str]]:
    """Detect router-to-router edges from LLDP neighbor tables.

    Runs before every heuristic. Returns ``(edges, blocked_ids, uplinked)``:
    ``blocked_ids`` contains BOTH orientations of every detected pair so the
    downstream heuristics (DHCP / WiFi / ARP / subnet) cannot add a competing —
    and possibly wrong-port — edge for the same pair, and ``uplinked`` is the
    set of routers that already have an LLDP uplink (the ``to`` side), so no
    heuristic adds a *second* uplink to them from another router. The latter
    matters in a chain gateway → AP-A → AP-B: the gateway is the DHCP server
    for AP-B too and sees it behind the same port as AP-A in its FDB, which
    used to produce a competing gateway → AP-B edge and, through the switch
    inference, a phantom switch replacing the whole LLDP chain. LLDP always
    wins.
    """
    # Collect directed observations a→b (a saw b as an LLDP neighbor). The
    # neighbor table is walked in a stable order (local port first), so with
    # parallel links (LAG / redundancy) the same one wins on every poll; the
    # other observations of the pair are recorded on the edge instead of
    # silently overwriting it.
    obs: dict[tuple[str, str], dict[str, Any]] = {}
    duplicates: dict[frozenset[str], list[dict[str, Any]]] = {}
    for a_rid, _a_hip, a_data in router_data:
        neighbors = [
            n
            for n in getattr(a_data, "lldp_neighbors", None) or []
            if isinstance(n, dict)
        ]
        neighbors.sort(key=_lldp_neighbor_sort_key)
        for neigh in neighbors:
            b_rid = _match_lldp_neighbor(neigh, token_to_rid)
            if not b_rid or b_rid == a_rid:
                continue
            if (a_rid, b_rid) in obs:
                duplicates.setdefault(frozenset((a_rid, b_rid)), []).append(
                    {
                        "observer": a_rid,
                        "local_interface": neigh.get(LLDP_KEY_LOCAL_INTERFACE, ""),
                        "local_port": _normalize_lldp_port(
                            neigh.get(LLDP_KEY_LOCAL_INTERFACE, "")
                        ),
                        "neighbor_port_id": neigh.get(LLDP_KEY_PORT_ID, ""),
                    }
                )
                continue
            obs[(a_rid, b_rid)] = {
                "local_interface": neigh.get(LLDP_KEY_LOCAL_INTERFACE, ""),
                "local_port": _normalize_lldp_port(
                    neigh.get(LLDP_KEY_LOCAL_INTERFACE, "")
                ),
                "neighbor_port_id": neigh.get(LLDP_KEY_PORT_ID, ""),
                "neighbor_port_descr": neigh.get(LLDP_KEY_PORT_DESCR, ""),
                "neighbor_chassis_id": neigh.get(LLDP_KEY_CHASSIS_ID, ""),
                "neighbor_name": neigh.get(LLDP_KEY_CHASSIS_NAME)
                or meta.get(b_rid, {}).get("hostname", ""),
                "management_ip": neigh.get(LLDP_KEY_MGMT_IP),
                "capabilities": neigh.get(LLDP_KEY_CAPABILITIES, []),
            }

    edges: list[dict[str, Any]] = []
    blocked_ids: set[str] = set()
    uplinked: set[str] = set()
    handled: set[frozenset[str]] = set()

    # Orientation needs the whole graph, so hop distances are computed up front.
    if roles is None:
        roles = _resolve_router_roles(router_data)
    depths = _lldp_hop_depths({frozenset(pair) for pair in obs}, router_data, roles)
    gateway_rids = {rid for rid, depth in depths.items() if depth == 0}

    for (a_rid, b_rid), fwd in obs.items():
        pair = frozenset((a_rid, b_rid))
        if pair in handled:
            continue
        handled.add(pair)
        rev = obs.get((b_rid, a_rid))
        bidirectional = rev is not None

        # Each side's own local interface on the link; when only one side
        # reported, the observer's view of the peer port stands in.
        a_iface = (
            fwd.get("local_interface") or (rev or {}).get("neighbor_port_id") or ""
        )
        b_iface = (
            (rev or {}).get("local_interface") or fwd.get("neighbor_port_id") or ""
        )
        from_rid, to_rid, anchored = _orient_lldp_pair(
            a_rid, b_rid, router_data, depths, a_iface, b_iface, roles
        )
        # Map each router's OWN self-reported local port to the from/to side.
        if from_rid == a_rid:
            from_obs, to_obs = fwd, rev
        else:
            from_obs, to_obs = rev, fwd

        from_port = (from_obs or {}).get("local_port") or ""
        from_iface = (from_obs or {}).get("local_interface") or ""
        # Prefer the peer's OWN self-report for the to-side port; otherwise fall
        # back to what the from-side saw as the neighbor's port.
        if to_obs:
            to_port = to_obs.get("local_port") or ""
            to_iface = to_obs.get("local_interface") or ""
        else:
            to_port = (from_obs or {}).get("neighbor_port_id") or ""
            to_iface = to_port

        # Conflict check: does the from-router's bridge FDB place the peer on a
        # different port than LLDP reports? LLDP wins; record for diagnostics.
        conflicts: list[dict[str, Any]] = []
        from_data = next((d for r, _h, d in router_data if r == from_rid), None)
        if from_data is not None and from_port:
            fdb = getattr(from_data, "port_fdb_map", {}) or {}
            for peer_mac in meta.get(to_rid, {}).get("macs", set()):
                fdb_port = fdb.get(peer_mac)
                if fdb_port and fdb_port.lower() != from_port.lower():
                    conflicts.append(
                        {"source": "fdb", "fdb_port": fdb_port, "lldp_port": from_port}
                    )
                    break

        # VLAN tags on the from-side port, if known.
        from_vlan_map = (
            getattr(from_data, "port_vlan_map", {}) if from_data is not None else {}
        )
        vlan_tags = list(from_vlan_map.get(from_port, [])) if from_port else []

        neighbor_meta = meta.get(to_rid, {})
        neighbor_mac = min(neighbor_meta.get("macs", set()), default="")
        # Preserve the actual neighbor-observed values regardless of orientation.
        observed = fwd if from_rid == a_rid else (rev or fwd)

        # The medium comes from the LLDP interface names, not from a heuristic:
        # a wireless backhaul has no physical port, so the port/VLAN compat keys
        # stay empty and the repeater override below may promote the edge.
        wireless = _lldp_link_is_wireless(from_iface, to_iface)

        edge_id = f"{from_rid}--uplink--{to_rid}"
        edges.append(
            {
                "id": edge_id,
                "from": from_rid,
                "to": to_rid,
                "relationship": CONNECTION_TYPE_ROUTER_UPLINK,
                "source": MESH_SOURCE,
                "inferred": False,
                "inference_reason": None,
                "attributes": {
                    "link_type": "wifi" if wireless else "lan",
                    "detection_method": SOURCE_LLDP,
                    "confidence": CONF_HIGH,
                    "direction": "bidirectional" if bidirectional else "one_way",
                    "from_port": from_port,
                    "from_interface": from_iface,
                    "to_port": to_port,
                    "to_interface": to_iface,
                    # Compat keys so gateway-port rendering keeps working. They
                    # describe a GATEWAY port: the panel looks ``gateway_port``
                    # up in the gateway's port stats, so a hop whose ``from`` is
                    # an AP carries none (its ports stay in from_port/to_port).
                    "gateway_port": (
                        None
                        if wireless or from_rid not in gateway_rids
                        else (from_port or None)
                    ),
                    "ap_port": (
                        None
                        if wireless or from_rid not in gateway_rids
                        else (to_port or None)
                    ),
                    "vlan_tags": [] if wireless else vlan_tags,
                    # Rich LLDP neighbor detail (from the from-side observation):
                    "neighbor_name": observed.get("neighbor_name", ""),
                    "neighbor_host": neighbor_meta.get("host_ip", ""),
                    "neighbor_mac": neighbor_mac,
                    "neighbor_chassis_id": observed.get("neighbor_chassis_id", ""),
                    "neighbor_port_id": observed.get("neighbor_port_id", ""),
                    "neighbor_port_description": observed.get(
                        "neighbor_port_descr", ""
                    ),
                    "management_ip": observed.get("management_ip"),
                    "capabilities": observed.get("capabilities", []),
                    "conflicts": conflicts,
                    # Optional: further observations of the same router pair
                    # (parallel links); only present when there are any.
                    **(
                        {"lldp_duplicates": duplicates[pair]}
                        if pair in duplicates
                        else {}
                    ),
                },
            }
        )
        if pair in duplicates:
            _LOGGER.debug(
                "LLDP: %d extra observation(s) of %s <-> %s ignored (parallel links)",
                len(duplicates[pair]),
                from_rid,
                to_rid,
            )
        # Block BOTH orientations so no heuristic can add a competing edge.
        blocked_ids.add(f"{a_rid}--uplink--{b_rid}")
        blocked_ids.add(f"{b_rid}--uplink--{a_rid}")
        # Only an evidence-based orientation marks the to-side as "uplinked";
        # a sort-fallback guess must not cost a router its gateway edge.
        if anchored:
            uplinked.add(to_rid)

    if edges:
        _LOGGER.debug("LLDP: detected %d router-to-router edge(s)", len(edges))
    return edges, blocked_ids, uplinked


def _detect_inter_router_edges(
    router_snapshots: list[dict[str, Any]],
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
    roles: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Detect connections between routers.

    Args:
        router_snapshots: Per-router topology snapshots.
        router_data: List of (router_id, host_ip, coordinator_data) tuples.

    Strategy (priority order):
        0. LLDP neighbors: authoritative router-to-router links + physical ports
           (runs first; blocks both orientations so heuristics cannot override,
           and a router with an anchored LLDP uplink gets no further uplink).
        1. DHCP lease cross-reference: AP's host IP in gateway's DHCP leases → LAN uplink
        2. WiFi client cross-reference: AP's MAC in another router's client list → WiFi uplink
        3. Subnet fallback: Same /24 subnet → mesh_member (inferred)
    """
    edges: list[dict[str, Any]] = []
    seen_edges: set[str] = set()

    # Method 0: LLDP — the preferred, authoritative source. It runs first and
    # seeds seen_edges with BOTH orientations of every detected pair so the
    # heuristics below cannot add a competing (possibly wrong-port) edge.
    router_roles = roles if roles is not None else _resolve_router_roles(router_data)
    token_to_rid, known_meta = _build_known_router_index(router_data)
    lldp_edges, lldp_blocked, lldp_uplinked = _detect_lldp_edges(
        router_data, token_to_rid, known_meta, router_roles
    )
    edges.extend(lldp_edges)
    seen_edges.update(lldp_blocked)
    # lldp_uplinked: routers whose uplink LLDP established with anchored
    # orientation; methods 1, 2.5, 2 and 3 add no second uplink to them
    # (chain gateway → AP-A → AP-B, see _detect_lldp_edges).

    # Build lookup maps
    # Includes router_info.mac + ALL interface IPs/MACs so an AP that connects
    # to the gateway via a secondary interface (e.g. wireless-STA backhaul with
    # a different MAC/IP than the management LAN) can still be matched.
    router_macs: dict[str, str] = {}  # MAC → router_id
    router_ips: dict[str, str] = {}  # IP → router_id
    for rid, hip, data in router_data:
        mac = (data.router_info.get("mac") or "").upper()
        if mac:
            router_macs[mac] = rid
        if hip:
            router_ips[hip] = rid
        # Add all interface IPs (secondary IPs on STA/mesh interfaces are common)
        for iface in data.network_interfaces or []:
            ipv4 = iface.get("ipv4_addr")
            if ipv4 and ipv4 not in router_ips:
                router_ips[ipv4] = rid
        # Add all AP-interface BSSIDs (in case an AP appears as a WiFi client
        # of a peer using its hostapd BSSID instead of the LAN MAC)
        for ap_iface in data.ap_interfaces or []:
            bssid = (ap_iface.get("bssid") or "").upper()
            if bssid and bssid not in router_macs:
                router_macs[bssid] = rid
        # Add STA-mode wireless interface MACs so a router that uplinks via
        # WiFi (repeater / mesh backhaul) is matched in Method 2 even when
        # its STA MAC differs from the LAN router_info.mac.
        for sta_iface in getattr(data, "sta_interfaces", None) or []:
            sta_mac = (sta_iface.get("mac") or "").upper()
            if sta_mac and sta_mac not in router_macs:
                router_macs[sta_mac] = rid

    # Find gateway(s) for directed edges, connected before outage, then by
    # id: with several gateways the first one that sees an AP claims it.
    gateways = _ordered_gateways(router_data, router_roles)

    # ========================================================================
    # Detection order: LAN (physical) first, then WiFi (wireless).
    #
    # A router connected via cable ALWAYS takes precedence over WiFi.
    # This fixes cases where a cabled AP also appears as a WiFi client
    # on the gateway (e.g. dual-band router with active STA interface).
    # ========================================================================

    # Method 1: DHCP lease cross-reference (LAN connections) — HIGHEST priority.
    claimed_aps: set[str] = set()
    for gw_rid, gw_hip, gw_data in gateways:
        dhcp = gw_data.dhcp_leases or {}
        for ap_rid, ap_hip, ap_data in router_data:
            if ap_rid == gw_rid:
                continue
            edge_id = f"{gw_rid}--uplink--{ap_rid}"
            if edge_id in seen_edges or ap_rid in lldp_uplinked:
                continue
            # Another gateway is not an AP of this one, and an AP already
            # claimed by an earlier gateway gets no second uplink.
            if router_roles.get(ap_rid) == "gateway" or ap_rid in claimed_aps:
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
                port_vlan_map: dict[str, list[int]] = getattr(
                    gw_data, "port_vlan_map", {}
                )
                vlan_tags: list[int] = (
                    list(port_vlan_map.get(gateway_port, [])) if gateway_port else []
                )
                edges.append(
                    {
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
                            "ap_port": "wan",  # inter-router LAN-uplink → AP-WAN
                            "vlan_tags": vlan_tags,
                        },
                    }
                )
                seen_edges.add(edge_id)
                claimed_aps.add(ap_rid)

    # Method 2.5: ARP/trunk_port_map — IP-based port lookup (no DHCP needed)
    # Matches AP host_ip directly against gateway's trunk_port_map {ip → port}.
    # Used when APs have static IPs not appearing in DHCP leases.
    for gw_rid, gw_hip, gw_data in gateways:
        trunk_map: dict[str, str] = getattr(gw_data, "trunk_port_map", {})
        if not trunk_map:
            continue
        for ap_rid, ap_hip, ap_data in router_data:
            if ap_rid == gw_rid:
                continue
            edge_id = f"{gw_rid}--uplink--{ap_rid}"
            if edge_id in seen_edges or ap_rid in lldp_uplinked:
                continue
            if router_roles.get(ap_rid) == "gateway" or ap_rid in claimed_aps:
                continue
            gateway_port = trunk_map.get(ap_hip)
            if gateway_port:
                port_vlan_map: dict[str, list[int]] = getattr(
                    gw_data, "port_vlan_map", {}
                )
                vlan_tags: list[int] = list(port_vlan_map.get(gateway_port, []))
                edges.append(
                    {
                        "id": edge_id,
                        "from": gw_rid,
                        "to": ap_rid,
                        "relationship": "lan_uplink",
                        "source": MESH_SOURCE,
                        "inferred": False,
                        "inference_reason": None,
                        "attributes": {
                            "link_type": "lan",
                            "detection_method": "arp_port",
                            "ap_host_ip": ap_hip,
                            "gateway_port": gateway_port,
                            "ap_port": "wan",
                            "vlan_tags": vlan_tags,
                        },
                    }
                )
                seen_edges.add(edge_id)
                claimed_aps.add(ap_rid)

    # Method 2: WiFi client cross-reference — ONLY for routers with no LAN edge.
    # A router seen as a WiFi client on another router is a wifi_uplink,
    # but ONLY if no physical (DHCP/ARP) connection was already detected.
    #
    # Edge direction is ALWAYS gateway → ap.  If an AP sees the gateway in its
    # client list (possible in mesh setups) we reverse the direction so the
    # topology graph stays consistent.
    for src_rid, src_hip, src_data in router_data:
        src_role = router_roles.get(src_rid, "ap")
        for client in src_data.clients or []:
            client_mac = (client.get("mac") or "").upper()
            client_ip = client.get("ip") or ""
            # Match by MAC first, fall back to host IP (covers cases where the AP
            # registers with a different MAC than router_info.mac, e.g. wlan0 vs br-lan)
            target_rid = router_macs.get(client_mac) or router_ips.get(client_ip)
            if not target_rid or target_rid == src_rid:
                continue

            # Determine correct edge direction: gateway is always the source
            target_role = router_roles.get(target_rid, "ap")
            if src_role == "gateway" and target_role == "ap":
                from_rid, to_rid = src_rid, target_rid
            elif src_role == "ap" and target_role == "gateway":
                from_rid, to_rid = target_rid, src_rid
            else:
                # Same role (ap↔ap or gateway↔gateway) — default to src→target
                from_rid, to_rid = src_rid, target_rid

            edge_id = f"{from_rid}--uplink--{to_rid}"
            if edge_id in seen_edges or to_rid in lldp_uplinked:
                continue
            edges.append(
                {
                    "id": edge_id,
                    "from": from_rid,
                    "to": to_rid,
                    "relationship": "wifi_uplink",
                    "source": MESH_SOURCE,
                    "inferred": False,
                    "inference_reason": None,
                    "attributes": {
                        "link_type": "wifi",
                        "detection_method": "wifi_client_mac",
                        "client_mac": client_mac,
                        "signal": client.get("signal"),
                        "ap_port": None,  # wireless uplink → no physical AP port
                        "vlan_tags": [],
                    },
                }
            )
            seen_edges.add(edge_id)

    # Repeater override: a router with an active wireless STA-mode interface
    # is a WLAN repeater — even if Method 1 / 2.5 produced a `lan_uplink` edge
    # (which can happen because the gateway's DHCP server also leases an IP
    # via WiFi) or Method 3 produced a `mesh_member` edge.
    #
    # We promote those edges to `wifi_uplink` so the UI shows "WLAN Repeater"
    # instead of "Kabel" or "Mesh?".
    #
    # Exception: a WAN port with link carrier (up=True) is authoritative —
    # physical Ethernet wins over a configured wireless backhaul. A concrete
    # gateway_port from FDB is NOT proof of cable: wirelessly meshed APs show
    # up behind the gateway's trunk ports in the FDB just the same.
    #
    # LLDP edges take part as well: an LLDP link over a wireless netdev is a
    # repeater link and must be promoted, while an LLDP link over copper is
    # first-hand proof of cable and outranks the STA heuristic — same as a WAN
    # carrier. Without this, a repeater running lldpd stayed `router_uplink`
    # and the UI rendered it as "Kabel".
    repeater_rids = {
        rid for rid, _hip, data in router_data if _has_active_sta_interface(data)
    }
    wired_rids = {rid for rid, _hip, data in router_data if _has_wan_carrier(data)}
    for edge in edges:
        if edge["relationship"] not in (
            "lan_uplink",
            "mesh_member",
            CONNECTION_TYPE_ROUTER_UPLINK,
        ):
            continue
        if edge["to"] not in repeater_rids:
            continue
        if edge["to"] in wired_rids:
            continue
        edge_attrs = edge.get("attributes") or {}
        if (
            edge_attrs.get("detection_method") == SOURCE_LLDP
            and edge_attrs.get("link_type") != "wifi"
        ):
            continue

        edge["relationship"] = "wifi_uplink"
        attrs = edge.setdefault("attributes", {})
        attrs["link_type"] = "wifi"
        attrs["detection_method"] = (
            f"repeater_override({attrs.get('detection_method', '')})"
        )
        attrs["ap_port"] = None
        attrs["vlan_tags"] = []
        attrs.pop("gateway_port", None)

    # Method 3: Subnet fallback for routers with no detected uplink
    connected_aps = {e["to"] for e in edges} | {e["from"] for e in edges}

    unconnected = [
        (rid, hip, data)
        for rid, hip, data in router_data
        if rid not in connected_aps and router_roles[rid] != "gateway"
    ]

    if unconnected and gateways:
        gw_rid, gw_hip_fallback, _ = gateways[0]
        try:
            gw_subnet = ipaddress.ip_network(f"{gw_hip_fallback}/24", strict=False)
        except (ValueError, TypeError):
            gw_subnet = None

        for ap_rid, ap_hip, ap_data in unconnected:
            edge_id = f"{gw_rid}--uplink--{ap_rid}"
            if edge_id in seen_edges or ap_rid in lldp_uplinked:
                continue

            # Wireless-backhaul fallback: an AP that no other method matched but
            # that has an active mesh-point/STA uplink iface is a wireless
            # backhaul. Emit a verified wifi_uplink even across subnets/VLANs —
            # a mesh link legitimately spans VLANs (e.g. a VLAN-30 mesh AP under
            # a VLAN-10 gateway), so the same-/24 guard below must NOT apply here.
            # The medium (wireless) is known; the gateway as the peer is inferred.
            if _has_active_sta_interface(ap_data):
                edges.append(
                    {
                        "id": edge_id,
                        "from": gw_rid,
                        "to": ap_rid,
                        "relationship": "wifi_uplink",
                        "source": MESH_SOURCE,
                        "inferred": True,
                        "inference_reason": "wireless_backhaul_iface",
                        "attributes": {
                            "link_type": "wifi",
                            "detection_method": "sta_iface_fallback",
                            "ap_host_ip": ap_hip,
                            "ap_port": None,
                            "vlan_tags": [],
                        },
                    }
                )
                seen_edges.add(edge_id)
                continue

            # Only infer an uplink if the AP is on the same /24 as the gateway.
            # Routers on different subnets (e.g. VPN, WireGuard) are excluded.
            if gw_subnet is not None:
                try:
                    ap_net = ipaddress.ip_network(f"{ap_hip}/24", strict=False)
                    if not gw_subnet.overlaps(ap_net):
                        _LOGGER.debug(
                            "Subnet fallback: skipping %s (%s) — not in gateway subnet %s",
                            ap_rid,
                            ap_hip,
                            gw_subnet,
                        )
                        continue
                except (ValueError, TypeError):
                    pass  # Can't parse AP IP → include it anyway

            edge_id = f"{gw_rid}--uplink--{ap_rid}"
            if edge_id not in seen_edges:
                edges.append(
                    {
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
                            "ap_port": None,
                            "vlan_tags": [],
                        },
                    }
                )
                seen_edges.add(edge_id)

    return edges


def _deduplicate_clients(
    all_clients: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate clients by MAC — keep the best observation.

    A roaming client may briefly appear on two APs. Keep one occurrence: a
    fresh observation always beats a ``stale`` one (from a router whose last
    update failed — its client list is old); among equally fresh ones the
    stronger signal wins. A stale observation therefore only survives when no
    router currently reports the client.
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
        new_stale = bool(client.get("stale"))
        old_stale = bool(existing.get("stale"))
        if new_stale != old_stale:
            if old_stale:
                best[mac] = client
            continue
        # Keep stronger signal (less negative = better)
        new_sig = client.get("signal")
        old_sig = existing.get("signal")
        if new_sig is not None and (old_sig is None or new_sig > old_sig):
            best[mac] = client
    return list(best.values())


def _detect_switch_nodes(
    inter_router_edges: list[dict[str, Any]],
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
    roles: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    """Detect implicit switch nodes between gateway and APs via Bridge FDB.

    If multiple APs are connected via the same gateway port, an unmanaged
    switch is likely sitting between them. We insert an inferred switch node
    and reroute the AP edges through it. APs that hang behind another router
    (LLDP chain) and ports that mix LLDP-verified with heuristic uplinks are
    left alone.

    Returns:
        (switch_nodes, new_edges_replacing_direct_ap_edges, replaced_edge_ids)
        replaced_edge_ids: set of edge IDs that should be removed from the
        original edge list (the direct gateway→AP edges now routed through switch).
    """
    switch_nodes: list[dict[str, Any]] = []
    switch_edges: list[dict[str, Any]] = []
    replaced_ids: set[str] = set()

    # Find gateway coordinator data for trunk_port_map
    if roles is None:
        roles = _resolve_router_roles(router_data)
    gw_trunk_map: dict[str, str] = {}
    gw_rid = ""
    for rid, _hip, data in _ordered_gateways(router_data, roles):
        gw_trunk_map = getattr(data, "trunk_port_map", {})
        gw_rid = rid
        break

    if not gw_trunk_map or not gw_rid:
        return [], [], set()

    # APs that hang behind ANOTHER router (LLDP-verified router_uplink from a
    # non-gateway) are part of a chain, not members of a switch on a gateway
    # port — even if a stray gateway → AP edge names the same port.
    gateway_rids = {rid for rid, role in roles.items() if role == "gateway"}
    chained_aps = {
        edge.get("to")
        for edge in inter_router_edges
        if edge.get("relationship") == CONNECTION_TYPE_ROUTER_UPLINK
        and edge.get("from") not in gateway_rids
    }

    # Group APs by gateway port, remembering whether each edge is LLDP-verified.
    port_members: dict[str, list[tuple[str, bool]]] = {}
    for edge in inter_router_edges:
        if _is_wired_uplink_edge(edge):
            attrs = edge.get("attributes") or {}
            gw_port = attrs.get("gateway_port")
            ap_id = edge.get("to")
            if (
                gw_port
                and ap_id
                and edge.get("from") == gw_rid
                and ap_id not in chained_aps
            ):
                port_members.setdefault(gw_port, []).append(
                    (ap_id, attrs.get("detection_method") == SOURCE_LLDP)
                )

    # A port with an LLDP-verified AP AND a heuristically found AP is
    # ambiguous: the second AP may hang behind the first (no lldpd on it) or
    # behind an unmanaged switch. Neither reading justifies dropping the LLDP
    # edge, so no switch is inferred there. All-LLDP or all-heuristic ports
    # keep the inference (two APs reporting the gateway on one port = switch).
    port_to_aps: dict[str, list[str]] = {}
    for port, members in port_members.items():
        if len({is_lldp for _ap, is_lldp in members}) > 1:
            _LOGGER.debug(
                "Switch inference: port %s mixes LLDP and heuristic uplinks — "
                "keeping the direct edges",
                port,
            )
            continue
        port_to_aps[port] = [ap for ap, _is_lldp in members]

    # For each port with >1 AP: insert a switch node and collect replaced edge IDs
    for port, ap_ids in port_to_aps.items():
        if len(ap_ids) < 2:
            continue
        switch_id = f"switch:{gw_rid}:{port}"
        switch_nodes.append(
            {
                "id": switch_id,
                "type": "switch",
                "label": f"Switch ({port.upper()})",
                "source": MESH_SOURCE,
                "inferred": True,
                "inference_reason": f"multiple_aps_on_{port}",
                "role": "switch",
                "attributes": {
                    "gateway_port": port,
                    "ap_count": len(ap_ids),
                },
            }
        )
        # Edge: gateway → switch
        switch_edges.append(
            {
                "id": f"{gw_rid}--switch--{switch_id}",
                "from": gw_rid,
                "to": switch_id,
                "relationship": "lan_uplink",
                "source": MESH_SOURCE,
                "inferred": True,
                "inference_reason": f"switch_inferred_{port}",
                "attributes": {
                    "link_type": "lan",
                    "detection_method": "fdb_multi_ap",
                    "gateway_port": port,
                },
            }
        )
        # Collect IDs of direct gateway→AP edges that are being replaced
        for edge in inter_router_edges:
            if (
                _is_wired_uplink_edge(edge)
                and edge.get("from") == gw_rid
                and edge.get("to") in ap_ids
                and (edge.get("attributes") or {}).get("gateway_port") == port
            ):
                replaced_ids.add(edge["id"])
        # Edges: switch → each AP (replace direct gateway→AP edges)
        for ap_id in ap_ids:
            switch_edges.append(
                {
                    "id": f"{switch_id}--trunk--{ap_id}",
                    "from": switch_id,
                    "to": ap_id,
                    "relationship": "lan_uplink",
                    "source": MESH_SOURCE,
                    "inferred": True,
                    "inference_reason": "switch_inferred",
                    "attributes": {
                        "link_type": "lan",
                        "detection_method": "fdb_multi_ap",
                    },
                }
            )

    return switch_nodes, switch_edges, replaced_ids


def _enrich_gateway_ports(
    attrs: dict[str, Any],
    gw_data: OpenWrtCoordinatorData,
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]],
    gw_rid: str,
) -> None:
    """Enrich the gateway's port_stats with mesh knowledge.

    - Inserts each AP as a router-type device entry at the front of its
      trunk port's connected_devices (legacy ``connected_device`` string
      keeps showing the AP hostname — DetailPanel matches on it).
    - Nearest-switch rule: MACs the AP itself observes on its own access
      side (WiFi clients, own interfaces, access-port FDB entries) are
      removed from the gateway trunk port — those devices belong to the
      AP node; the gateway FDB only proves "somewhere behind this port".
    """
    trunk_map: dict[str, str] = getattr(gw_data, "trunk_port_map", {}) or {}
    gw_fdb: dict[str, str] = getattr(gw_data, "port_fdb_map", {}) or {}
    gw_mac = normalize_mac(gw_data.router_info.get("mac"))

    port_to_aps: dict[str, list[dict[str, Any]]] = {}
    foreign_macs: set[str] = set()

    for ap_rid, ap_hip, ap_data in router_data:
        if ap_rid == gw_rid:
            continue
        ap_name = ap_data.router_info.get("hostname") or ap_hip
        ap_mac = normalize_mac(ap_data.router_info.get("mac"))
        # Trunk port via ARP+FDB map (IP-based); FDB MAC lookup as fallback.
        port = trunk_map.get(ap_hip) or (gw_fdb.get(ap_mac) if ap_mac else None)
        if port:
            port_to_aps.setdefault(port, []).append(
                {
                    "name": ap_name,
                    "ip": ap_hip,
                    "mac": ap_mac,
                    "router_node_id": ap_rid,
                }
            )

        # Everything the AP sees on its access side hangs behind the AP.
        foreign_macs.update(collect_wifi_client_macs(ap_data.clients))
        foreign_macs.update(
            collect_own_macs(
                ap_data.router_info,
                ap_data.ap_interfaces,
                getattr(ap_data, "sta_interfaces", None),
            )
        )
        # AP FDB entries count as "behind the AP" only when we can tell
        # which AP port faces the gateway (the port where the AP sees the
        # gateway MAC). Without that anchor, skip — removing devices based
        # on the towards-gateway port would wrongly hide direct gateway
        # clients that the AP merely sees through its uplink.
        ap_fdb: dict[str, str] = getattr(ap_data, "port_fdb_map", {}) or {}
        uplink_port = ap_fdb.get(gw_mac) if gw_mac else None
        if uplink_port:
            for mac, ap_port in ap_fdb.items():
                if ap_port != uplink_port:
                    foreign_macs.add(normalize_mac(mac))

    for port in attrs.get("port_stats") or []:
        port_name = port.get("name", "")
        aps = port_to_aps.get(port_name, [])
        devices: list[dict[str, Any]] = list(port.get("connected_devices") or [])
        if not aps and not devices:
            continue

        if foreign_macs:
            devices = [
                d for d in devices if normalize_mac(d.get("mac")) not in foreign_macs
            ]
        ap_macs = {ap["mac"] for ap in aps if ap["mac"]}
        devices = [d for d in devices if normalize_mac(d.get("mac")) not in ap_macs]

        ap_entries = [
            {
                "mac": ap["mac"],
                "ip": ap["ip"],
                "name": ap["name"],
                "source": "trunk_map",
                "confidence": CONFIDENCE_HIGH,
                "web_url": safe_web_url(ap["ip"]),
                "is_router": True,
                "router_node_id": ap["router_node_id"],
            }
            for ap in aps
        ]
        merged = ap_entries + devices
        apply_devices_to_port(port, merged)

        # Legacy single-string field: AP hostname wins on trunk ports.
        if ap_entries:
            port["connected_device"] = ap_entries[0]["name"]
        elif merged:
            first = merged[0]
            port["connected_device"] = (
                first.get("name") or first.get("ip") or first.get("mac")
            )
        else:
            port["connected_device"] = None


def _is_mac_like(value: str) -> bool:
    """True for a bare MAC address, with or without separators."""
    hexonly = value.strip().lower().replace(":", "").replace("-", "").replace(".", "")
    return len(hexonly) == 12 and all(c in "0123456789abcdef" for c in hexonly)


def _device_for_mac(dev_reg: dr.DeviceRegistry, mac: str) -> dr.DeviceEntry | None:
    """Return the device any integration registered for a client MAC, or None.

    Since HA 2026.8 a device belongs to one config entry, so several
    integrations can register the same MAC; ``async_get_devices`` returns all
    of them; the one the user renamed wins, then one with a real (non-MAC)
    name, otherwise the first. Cores
    before 2026.8 (floor 2026.2) only have ``async_get_device``, which is
    deprecated since 2026.9 and ends in 2027.8.
    """
    connections = {(dr.CONNECTION_NETWORK_MAC, mac)}
    get_devices = getattr(dev_reg, "async_get_devices", None)
    if get_devices is None:
        return dev_reg.async_get_device(connections=connections)
    devices = get_devices(connections=connections)
    if not devices:
        return None
    return (
        next((device for device in devices if device.name_by_user), None)
        or next((d for d in devices if d.name and not _is_mac_like(d.name)), None)
        or devices[0]
    )


def _apply_ha_names(
    hass: HomeAssistant, nodes: list[dict[str, Any]], entries: list[Any]
) -> None:
    """Attach names known to Home Assistant to client nodes (read-only).

    Sources, best first: a name the user set on the device (``name_by_user``)
    or on this integration's tracker entity, then the name another
    integration registered for the MAC (ESPHome, Shelly, Cast, …). Sets
    ``ha_name``, ``ha_name_source`` (``user``/``device``), ``ha_manufacturer``
    and ``ha_model``. ``hostname`` and ``label`` stay the router's own data.
    """
    # dr/er.async_get create a registry when none is loaded — only read the
    # ones HA already has (bare hass stubs in unit tests have none).
    hass_data = getattr(hass, "data", None)
    if (
        not isinstance(hass_data, dict)
        or dr.DATA_REGISTRY not in hass_data
        or er.DATA_REGISTRY not in hass_data
    ):
        return
    dev_reg = dr.async_get(hass)
    ent_reg = er.async_get(hass)

    # Tracker unique_id is either the MAC (newer cores) or
    # "<entry_id>_tracker_<mac hex>" (older cores).
    tracker_names: dict[str, str] = {}
    for entry in entries:
        for ent in er.async_entries_for_config_entry(ent_reg, entry.entry_id):
            if ent.domain != "device_tracker" or not ent.name:
                continue
            mac = _mac_norm(ent.unique_id.rsplit("_tracker_", 1)[-1])
            if mac:
                tracker_names[mac] = ent.name

    for node in nodes:
        if node.get("type") != "client":
            continue
        attrs = node.setdefault("attributes", {})
        mac = _mac_norm(attrs.get("mac"))
        if not mac:
            continue
        device = _device_for_mac(dev_reg, mac)
        if device is not None and device.name_by_user:
            attrs["ha_name"], attrs["ha_name_source"] = device.name_by_user, "user"
        elif mac in tracker_names:
            attrs["ha_name"], attrs["ha_name_source"] = tracker_names[mac], "user"
        elif device is not None and device.name and not _is_mac_like(device.name):
            # Some integrations name a device after its MAC — that is no
            # better than the DHCP hostname, so it does not win over it.
            attrs["ha_name"], attrs["ha_name_source"] = device.name, "device"
        if device is not None:
            if device.manufacturer:
                attrs["ha_manufacturer"] = device.manufacturer
            if device.model:
                attrs["ha_model"] = device.model


def _mark_snapshot_stale(snapshot: dict[str, Any]) -> None:
    """Mark the clients, client nodes and edges of an offline router's snapshot.

    Adds ``stale: True`` to every client entry and edge, and
    ``attributes.stale: True`` to every client node. The router node itself
    already carries ``node_status: offline``.
    """
    for client in snapshot.get("clients", []):
        client["stale"] = True
    for edge in snapshot.get("edges", []):
        edge["stale"] = True
    for node in snapshot.get("nodes", []):
        if node.get("type") == "client":
            node.setdefault("attributes", {})["stale"] = True


def build_mesh_snapshot(hass: HomeAssistant) -> dict[str, Any]:
    """Build a unified mesh topology from all loaded openwrt_router entries.

    Collects per-router snapshots, detects roles, finds inter-router
    connections, merges into a single snapshot.

    Returns:
        Unified snapshot dict compatible with the topology panel schema.
    """
    now = datetime.now(UTC).isoformat()

    entries = hass.config_entries.async_entries(DOMAIN)
    if not entries:
        return _empty_mesh(now)

    all_nodes: list[dict[str, Any]] = []
    all_edges: list[dict[str, Any]] = []
    all_interfaces: list[dict[str, Any]] = []
    all_clients: list[dict[str, Any]] = []
    router_data: list[tuple[str, str, OpenWrtCoordinatorData]] = []

    # Fleet-wide identity, collected before the per-router snapshots are built:
    # only the gateway runs a DHCP server, so a dumb AP has no way to put a name
    # or IP on the devices its own ports see and rendered them all as
    # "Unbekannt". Naming source only — never a device source.
    fleet_leases: dict[str, dict[str, str]] = {}
    fleet_arp: dict[str, str] = {}
    for entry in entries:
        runtime = getattr(entry, "runtime_data", None)
        coordinator = getattr(runtime, "coordinator", None) if runtime else None
        entry_data = getattr(coordinator, "data", None)
        if entry_data is None:
            continue
        for mac, lease in (entry_data.dhcp_leases or {}).items():
            fleet_leases.setdefault(mac, lease)
        for mac, ip in (getattr(entry_data, "arp_table", None) or {}).items():
            fleet_arp.setdefault(mac, ip)

    # Roles are a fleet decision (see _resolve_router_roles): resolved ONCE,
    # before the per-router snapshots, and passed down to every consumer.
    loaded: list[tuple[Any, Any, OpenWrtCoordinatorData, str, str]] = []
    for entry in entries:
        runtime = getattr(entry, "runtime_data", None)
        if runtime is None:
            continue
        coordinator = getattr(runtime, "coordinator", None)
        if coordinator is None or coordinator.data is None:
            continue
        host_ip = str(entry.data.get("host", ""))
        data = coordinator.data
        loaded.append(
            (
                entry,
                coordinator,
                data,
                host_ip,
                router_node_id(data.router_info or {}, host_ip),
            )
        )
    fleet = [(rid, hip, data) for _e, _c, data, hip, rid in loaded]
    roles = _resolve_router_roles(fleet, _GATEWAY_MEMORY)
    _remember_gateways(fleet, now)
    offline_rids: set[str] = set()

    for entry, coordinator, data, host_ip, router_id in loaded:
        role = roles[router_id]

        # Determine online/offline from last coordinator update success
        is_online = getattr(coordinator, "last_update_success", True)

        # Build per-router snapshot with role and host_ip
        snapshot = build_topology_snapshot(
            data,
            role=role,
            host_ip=host_ip,
            include_port_debug=entry.options.get(
                CONF_TOPOLOGY_PORT_DEBUG, DEFAULT_TOPOLOGY_PORT_DEBUG
            ),
            identity_leases=fleet_leases,
            identity_arp=fleet_arp,
        )

        # Inject online/offline status into the router node attributes
        for node in snapshot.get("nodes", []):
            if node.get("type") == "router":
                node.setdefault("attributes", {})["node_status"] = (
                    "online" if is_online else "offline"
                )

        # A router whose last update failed still serves its previous data.
        # Its clients and edges are marked stale so they lose the client
        # dedupe against any fresh observation (optional field, only set
        # when True).
        if not is_online:
            offline_rids.add(router_id)
            _mark_snapshot_stale(snapshot)

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
        roles,
    )
    # An inter-router edge is stale when one of its routers is offline: the
    # link was derived (at least partly) from that router's old data.
    for edge in inter_router_edges:
        if edge.get("from") in offline_rids or edge.get("to") in offline_rids:
            edge["stale"] = True
    all_edges.extend(inter_router_edges)

    # Detect implicit switch nodes via Bridge FDB:
    # If multiple APs share the same gateway port → a switch sits between them.
    switch_nodes, switch_edges, replaced_ids = _detect_switch_nodes(
        inter_router_edges, router_data, roles
    )
    all_nodes.extend(switch_nodes)
    # Remove direct gateway→AP edges that are now routed through the switch
    if replaced_ids:
        all_edges = [e for e in all_edges if e.get("id") not in replaced_ids]
    all_edges.extend(switch_edges)

    # A configured (known) router must never be shown as an ordinary client,
    # even when its MAC/STA-MAC appears in a peer's association/FDB table — it
    # is rendered as a router/AP node from its own entry instead. Build the set
    # of known-router MACs from the live config entries and filter clients by it.
    _known_tokens, _known_meta = _build_known_router_index(router_data)
    known_router_macs: set[str] = set()
    for _m in _known_meta.values():
        known_router_macs |= {m.lower() for m in _m.get("macs", set())}

    def _is_known_router_mac(mac: str) -> bool:
        norm = _mac_norm(mac)
        return bool(norm and norm in known_router_macs)

    # Deduplicate clients (same MAC on multiple APs during roaming)
    deduped_clients = [
        c
        for c in _deduplicate_clients(all_clients)
        if not _is_known_router_mac(c.get("mac", ""))
    ]

    # Build MAC → winning ap_mac map from the deduplicated client list.
    # _deduplicate_clients() picks the router with the strongest signal.
    # We must match client *nodes* to this winner so that ap_mac in the
    # topology correctly reflects which router the client is associated with.
    winning_ap_mac: dict[str, str] = {
        c["mac"]: c.get("ap_mac", "") for c in deduped_clients if c.get("mac")
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

            # Never render a known router as a client node.
            if mac and _is_known_router_mac(mac):
                continue

            if node_id in seen_client_ids:
                # Replace the stored node if this one has the winning ap_mac
                node_ap_mac = node.get("attributes", {}).get("ap_mac") or ""
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

    # Owner router of every edge source that can carry a has_client edge
    # (the router node itself or one of its AP-interface nodes).
    edge_owner: dict[str, str] = {rid: rid for rid, _hip, _data in router_data}
    for node in all_nodes:
        if node.get("type") == "interface":
            owner = (node.get("attributes") or {}).get("ap_mac")
            if owner:
                edge_owner[node["id"]] = owner

    def _is_losing_client_edge(edge: dict[str, Any]) -> bool:
        """True for a has_client edge from a router that lost the dedupe.

        A roamed client (or one still listed by an offline router) must hang
        off the winning router only, not off every router that reported it.
        """
        if edge.get("relationship") != "has_client":
            return False
        target = str(edge.get("to") or "")
        if not target.startswith("client:"):
            return False
        winner = winning_ap_mac.get(target.removeprefix("client:"))
        owner = edge_owner.get(str(edge.get("from") or ""))
        return bool(winner and owner and owner != winner)

    # Also deduplicate client edges
    seen_edge_ids: set[str] = set()
    deduped_edges: list[dict[str, Any]] = []
    for edge in all_edges:
        if _is_losing_client_edge(edge):
            continue
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

    # Display names the user already knows from Home Assistant.
    _apply_ha_names(hass, deduped_nodes, entries)

    # Inject native WAN throughput + ping + DuckDNS into every gateway router
    # node (multi-site / dual-gateway fleets have more than one). Only
    # coordinators with role=gateway have this data (others return empty).
    # wan_traffic is derived natively from OpenWrt rx/tx byte deltas.
    for rid, _hip, data in router_data:
        if roles.get(rid) != "gateway":
            continue
        for node in deduped_nodes:
            if node.get("type") == "router" and node.get("id") == rid:
                attrs = node.setdefault("attributes", {})
                wan_traffic = getattr(data, "wan_traffic", {}) or {}
                # Native OpenWrt throughput (rx/tx byte deltas)
                attrs["wan_traffic"] = wan_traffic
                attrs["ping_ms"] = getattr(data, "ping_ms", None)
                if not getattr(data, "ping_checked", True):
                    # First poll after start skips the ping — not "offline"
                    attrs["ping_pending"] = True
                attrs["ddns_status"] = getattr(data, "ddns_status", []) or []
                attrs["topology_snapshots"] = (
                    getattr(data, "topology_snapshots", []) or []
                )

                # Enrich port_stats with mesh knowledge: AP device entries on
                # trunk ports, nearest-switch foreign-MAC removal.
                _enrich_gateway_ports(attrs, data, router_data, rid)
                break

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
