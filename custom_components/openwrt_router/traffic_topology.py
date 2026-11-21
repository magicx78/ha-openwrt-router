"""Traffic values on the topology snapshot (Phase J, plan 2026-11-20 §7).

:func:`annotate_snapshot` adds measured traffic to the nodes and edges the
mesh snapshot already has; it never adds a node or an edge and never calls
a router: every value comes from the engine's latest rates.

* **Off means untouched.** While the engine is missing or not active the
  snapshot is returned as it came (the same object, no new key), so the
  topology behaves exactly as before.
* **Router nodes** get ``attributes.traffic``: WAN rate (download/upload
  where the area names them, else rx/tx), per measured port or interface
  the rate, the utilisation against a known link speed (else the reason)
  and the coverage.
* **Router uplink edges** get ``attributes.traffic`` with the rate the
  upstream router measured on ``from_port`` and the downstream router on
  ``to_port`` (None with a reason when that port is not measured).
* **Meta** gets ``traffic``: status, reasons and ``flow_relations``
  (unavailable: there is no flow source in Phase J).
* **No new identity.** The Core router id and the point ids stay out of the
  topology: the nodes are keyed by the topology's own ids already, and the
  pseudonyms are not linked to them here.

Annotation is built completely before it is applied; a failure leaves the
snapshot as it was (the caller logs it).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from .const import DATA_TRAFFIC_ANALYTICS, DOMAIN
from .topology_diagnostic import router_node_id
from .traffic_accounting import direction_map
from .traffic_model import Rate, Scope
from .traffic_output import status_of

_LOGGER = logging.getLogger(__name__)

TRAFFIC_KEY = "traffic"
MAX_PORTS_PER_ROUTER = 32
_PORT_SCOPES = frozenset({Scope.PORT, Scope.INTERFACE})
REASON_PORT_NOT_MEASURED = "port_not_measured"
REASON_ROUTER_NOT_MEASURED = "router_not_measured"
REASON_LINK_UNKNOWN = "link_speed_unknown"
REASON_NO_RATE = "no_rate_yet"


def _engine(hass: Any) -> Any | None:
    engine = getattr(hass, "data", {}).get(DATA_TRAFFIC_ANALYTICS)
    if engine is None or not getattr(engine, "active", False):
        return None
    return engine


def _value(rate: Rate, counter: str | None) -> float | None:
    if counter == "rx":
        return rate.rx_bps
    if counter == "tx":
        return rate.tx_bps
    return None


def _rate(rate: Rate, link: Any = None) -> dict[str, Any]:
    """The values of one point (no point id, no router id)."""
    mapping = direction_map(rate.point)
    out: dict[str, Any] = {
        "rx_bps": rate.rx_bps,
        "tx_bps": rate.tx_bps,
        "down_bps": _value(rate, mapping.download),
        "up_bps": _value(rate, mapping.upload),
        "direction_reason": mapping.reason,
        "quality": rate.quality.value,
        "coverage": rate.coverage.value,
        "coverage_reason": None
        if rate.coverage_reason is None
        else rate.coverage_reason.value,
        "measured_at": rate.wall_s,
    }
    if rate.point.scope in _PORT_SCOPES:
        mbps = getattr(link, "link_mbps", None)
        known = [v for v in (rate.rx_bps, rate.tx_bps) if v is not None]
        pct = None
        reason = None
        if not mbps:
            reason = REASON_LINK_UNKNOWN
        elif not known:
            reason = REASON_NO_RATE
        else:
            pct = round(max(known) / (mbps * 1_000_000) * 100, 2)
        out["link_mbps"] = mbps or None
        out["utilization_pct"] = pct
        out["utilization_reason"] = reason
    return out


def _router_traffic(rates: Iterable[Rate], links: Mapping[str, Any]) -> dict[str, Any]:
    wan: list[dict[str, Any]] = []
    ports: dict[str, dict[str, Any]] = {}
    # a port counter wins over an interface counter of the same name
    ordered = sorted(
        rates,
        key=lambda r: (
            r.point.device or "",
            r.point.scope is not Scope.PORT,
            r.point.point_id,
        ),
    )
    for rate in ordered:
        point = rate.point
        if point.scope is Scope.WAN:
            wan.append(_rate(rate))
            continue
        usable = point.scope in _PORT_SCOPES and point.device and point.vlan_id is None
        if usable and point.device not in ports and len(ports) < MAX_PORTS_PER_ROUTER:
            ports[point.device] = _rate(rate, links.get(point.point_id))
    return {
        "wan": wan[0] if len(wan) == 1 else None,
        "wan_points": len(wan),
        "ports": ports,
    }


def _entry_router_ids(hass: Any, engine: Any) -> dict[str, str]:
    """Topology node id -> Core router id, for the loaded entries."""
    out: dict[str, str] = {}
    for entry in hass.config_entries.async_entries(DOMAIN):
        runtime = getattr(entry, "runtime_data", None)
        coordinator = getattr(runtime, "coordinator", None) if runtime else None
        data = getattr(coordinator, "data", None)
        if data is None:
            continue
        rid = engine.router_id_for_entry(entry.entry_id)
        if rid is None:
            continue
        host_ip = str(entry.data.get("host", ""))
        out[router_node_id(getattr(data, "router_info", None) or {}, host_ip)] = rid
    return out


def _edge_port(
    port: Any, router: Mapping[str, Any] | None
) -> tuple[dict[str, Any] | None, str | None]:
    if router is None:
        return None, REASON_ROUTER_NOT_MEASURED
    if not isinstance(port, str) or not port:
        return None, REASON_PORT_NOT_MEASURED
    found = router["ports"].get(port)
    return (found, None) if found is not None else (None, REASON_PORT_NOT_MEASURED)


def annotate_snapshot(hass: Any, snapshot: dict[str, Any]) -> dict[str, Any]:
    """``snapshot`` with traffic values on its routers and uplinks.

    Returns ``snapshot`` itself, unchanged, while Traffic Analytics is off.
    """
    engine = _engine(hass)
    if engine is None:
        return snapshot
    status, reasons = status_of(engine)
    node_rids = _entry_router_ids(hass, engine)
    links = engine.link_facts()
    by_router: dict[str, list[Rate]] = {}
    for rate in engine.latest.values():
        rid = rate.point.router_id
        if rid is not None:
            by_router.setdefault(rid, []).append(rate)

    node_traffic: dict[str, dict[str, Any]] = {}
    for node in snapshot.get("nodes") or ():
        if not isinstance(node, dict) or node.get("type") != "router":
            continue
        rid = node_rids.get(node.get("id"))
        if rid is None or rid not in by_router:
            node_traffic[node["id"]] = {
                "state": "unavailable",
                "reason": REASON_ROUTER_NOT_MEASURED,
            }
            continue
        node_traffic[node["id"]] = {
            "state": "available",
            "reason": None,
            **_router_traffic(by_router[rid], links),
        }

    edge_traffic: dict[int, dict[str, Any]] = {}
    for index, edge in enumerate(snapshot.get("edges") or ()):
        if not isinstance(edge, dict) or edge.get("relationship") != "router_uplink":
            continue
        attrs = edge.get("attributes") or {}
        upper = node_traffic.get(edge.get("from"))
        lower = node_traffic.get(edge.get("to"))
        upper = upper if upper and upper.get("state") == "available" else None
        lower = lower if lower and lower.get("state") == "available" else None
        from_port, from_reason = _edge_port(attrs.get("from_port"), upper)
        to_port, to_reason = _edge_port(attrs.get("to_port"), lower)
        edge_traffic[index] = {
            "from_port": from_port,
            "from_port_reason": from_reason,
            "to_port": to_port,
            "to_port_reason": to_reason,
        }

    # apply (nothing above touched the snapshot); attribute dicts are
    # replaced, never changed in place, in case one is shared
    for node in snapshot.get("nodes") or ():
        if isinstance(node, dict) and node.get("id") in node_traffic:
            attrs = node.get("attributes") or {}
            node["attributes"] = {**attrs, TRAFFIC_KEY: node_traffic[node["id"]]}
    edges = snapshot.get("edges") or []
    for index, value in edge_traffic.items():
        attrs = edges[index].get("attributes") or {}
        edges[index]["attributes"] = {**attrs, TRAFFIC_KEY: value}
    snapshot["meta"] = {
        **(snapshot.get("meta") or {}),
        TRAFFIC_KEY: {
            "status": status,
            "reasons": reasons,
            "flow_relations": {"state": "unavailable", "reason": "needs_flow_source"},
        },
    }
    return snapshot


__all__ = ["TRAFFIC_KEY", "annotate_snapshot"]
