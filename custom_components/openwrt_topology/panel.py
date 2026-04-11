"""Native Home Assistant panel + API view for OpenWrt topology."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any

from aiohttp import web
from homeassistant.components.http import StaticPathConfig
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.components.panel_custom import async_register_panel
from homeassistant.core import HomeAssistant

from .const import DOMAIN


def _empty_snapshot(source: str) -> dict[str, Any]:
    return {
        "generated_at": None,
        "nodes": [],
        "edges": [],
        "interfaces": [],
        "clients": [],
        "meta": {
            "source": source,
            "schema_version": "1.0",
            "inference_used": False,
        },
    }


def _is_snapshot_dict(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and "generated_at" in data
        and isinstance(data.get("nodes"), list)
        and isinstance(data.get("edges"), list)
        and isinstance(data.get("interfaces"), list)
        and isinstance(data.get("clients"), list)
        and isinstance(data.get("meta"), dict)
    )


def _is_empty_snapshot(data: dict[str, Any] | None) -> bool:
    if not isinstance(data, dict):
        return True
    return (
        len(data.get("nodes", [])) == 0
        and len(data.get("edges", [])) == 0
        and len(data.get("interfaces", [])) == 0
        and len(data.get("clients", [])) == 0
    )


def _search_snapshot_in_object(obj: Any, seen: set[int], depth: int = 0) -> dict[str, Any] | None:
    if depth > 6:
        return None
    oid = id(obj)
    if oid in seen:
        return None
    seen.add(oid)

    if _is_snapshot_dict(obj):
        return obj

    if isinstance(obj, dict):
        for value in obj.values():
            found = _search_snapshot_in_object(value, seen, depth + 1)
            if found is not None:
                return found
    elif isinstance(obj, (list, tuple, set)):
        for value in obj:
            found = _search_snapshot_in_object(value, seen, depth + 1)
            if found is not None:
                return found

    return None


def _snapshot_from_states(hass: HomeAssistant) -> dict[str, Any] | None:
    # Bridge mode: allow snapshot discovery from other integrations (e.g. openwrt_router)
    # as long as they expose the canonical snapshot fields in state attributes.
    for state in hass.states.async_all("sensor"):
        attrs = state.attributes
        # Fix 1: check nested topology_snapshot attribute first (openwrt_router stores data there)
        snap = attrs.get("topology_snapshot") if isinstance(attrs, dict) else None
        if isinstance(snap, dict) and _is_snapshot_dict(snap):
            return snap
        if _is_snapshot_dict(attrs):
            return attrs
        if (
            isinstance(attrs, dict)
            and isinstance(attrs.get("nodes"), list)
            and isinstance(attrs.get("edges"), list)
            and isinstance(attrs.get("interfaces"), list)
            and isinstance(attrs.get("clients"), list)
        ):
            return {
                "generated_at": attrs.get("generated_at"),
                "nodes": attrs.get("nodes", []),
                "edges": attrs.get("edges", []),
                "interfaces": attrs.get("interfaces", []),
                "clients": attrs.get("clients", []),
                "meta": attrs.get("meta") or {"source": "entity_attributes", "schema_version": "1.0", "inference_used": False},
            }
    return None


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (value or "").lower()).strip("_")


def _snapshot_from_openwrt_router_entities(hass: HomeAssistant) -> dict[str, Any] | None:
    """Build a minimal inferred graph from openwrt_router entries + device_trackers.

    This fallback is intentionally explicit and marks every object as inferred,
    so we don't silently present guessed topology as measured truth.
    """
    entries = hass.config_entries.async_entries("openwrt_router")
    if not entries:
        return None

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    clients: list[dict[str, Any]] = []
    node_ids: set[str] = set()
    edge_ids: set[str] = set()

    def _add_tracker_to_graph(state, router_id: str) -> None:
        mac = str(state.attributes.get("mac_address") or state.entity_id.split(".", 1)[-1]).lower()
        client_id = f"client:{mac.replace('-', ':')}"
        if client_id not in node_ids:
            status = "inactive" if state.state in ("not_home", "unavailable", "unknown") else "active"
            nodes.append(
                {
                    "id": client_id,
                    "type": "client",
                    "label": state.name or mac,
                    "source": "openwrt_router.device_tracker",
                    "inferred": True,
                    "inference_reason": "device_tracker_bridge_fallback",
                    "status": status,
                    "attributes": {
                        "mac": mac,
                        "entity_id": state.entity_id,
                        "state": state.state,
                    },
                }
            )
            node_ids.add(client_id)
            clients.append(
                {
                    "id": client_id,
                    "mac": mac,
                    "ap_mac": None,
                    "signal": None,
                    "bitrate": None,
                    "connected": state.state not in ("not_home", "unavailable", "unknown"),
                    "last_seen": None,
                    "source": "openwrt_router.device_tracker",
                    "inferred": True,
                    "inference_reason": "device_tracker_bridge_fallback",
                }
            )

        edge_id = f"{router_id}--{client_id}"
        if edge_id not in edge_ids:
            edges.append(
                {
                    "id": edge_id,
                    "from": router_id,
                    "to": client_id,
                    "relationship": "has_client",
                    "source": "openwrt_router.device_tracker",
                    "inferred": True,
                    "inference_reason": "client_to_router_inferred_from_entity_prefix",
                }
            )
            edge_ids.add(edge_id)

    for entry in entries:
        host = str(entry.data.get("host") or "").strip()
        if not host:
            continue
        title = entry.title or host
        router_id = f"router:{host}"
        if router_id not in node_ids:
            nodes.append(
                {
                    "id": router_id,
                    "type": "router",
                    "label": title,
                    "ip": host,
                    "source": "openwrt_router.config_entry",
                    "inferred": True,
                    "inference_reason": "router_entry_bridge_fallback",
                    "status": "active",
                    "attributes": {
                        "entry_id": entry.entry_id,
                        "host": host,
                        "protocol": entry.data.get("protocol"),
                        "port": entry.data.get("port"),
                    },
                }
            )
            node_ids.add(router_id)

        prefix = f"device_tracker.{_slug(title)}_"
        for state in hass.states.async_all("device_tracker"):
            if not state.entity_id.startswith(prefix):
                continue
            _add_tracker_to_graph(state, router_id)

    # Safety fallback: if no per-entry prefix matches, use any gateway-like trackers.
    if len(clients) == 0 and len(nodes) > 0:
        first_router_id = next((n["id"] for n in nodes if n["type"] == "router"), None)
        if first_router_id:
            for state in hass.states.async_all("device_tracker"):
                entity_id = state.entity_id.lower()
                if "gateway_" in entity_id:
                    _add_tracker_to_graph(state, first_router_id)

    if not nodes:
        return None

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "nodes": nodes,
        "edges": edges,
        "interfaces": [],
        "clients": clients,
        "meta": {
            "source": "openwrt_router_bridge",
            "schema_version": "1.0",
            "inference_used": True,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "interface_count": 0,
            "client_count": len(clients),
        },
    }


class OpenWrtTopologySnapshotView(HomeAssistantView):
    """Return latest topology snapshot from loaded coordinators."""

    url = "/api/openwrt_topology/snapshot"
    name = "api:openwrt_topology:snapshot"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        hass: HomeAssistant = request.app["hass"]
        data: dict[str, Any] | None = None

        # ── Primary: Mesh aggregation from all openwrt_router entries ──
        try:
            from custom_components.openwrt_router.topology_mesh import build_mesh_snapshot
            candidate = build_mesh_snapshot(hass)
            if _is_snapshot_dict(candidate) and not _is_empty_snapshot(candidate):
                data = candidate
        except Exception:  # noqa: BLE001
            pass  # Fall through to legacy fallbacks

        # ── Fallback 1: openwrt_topology coordinator data ──
        if data is None or _is_empty_snapshot(data):
            domain_data = hass.data.get(DOMAIN, {})
            entry_id = request.query.get("entry_id")
            if entry_id:
                coordinator = domain_data.get(entry_id)
                if coordinator is not None and isinstance(getattr(coordinator, "data", None), dict):
                    data = coordinator.data
            if data is None:
                for key, value in domain_data.items():
                    if key.startswith("_"):
                        continue
                    if isinstance(getattr(value, "data", None), dict):
                        data = value.data
                        break

        # ── Fallback 2: sensor state attributes (topology_snapshot) ──
        if data is None or _is_empty_snapshot(data):
            candidate = _snapshot_from_states(hass)
            if _is_snapshot_dict(candidate) and not _is_empty_snapshot(candidate):
                data = candidate

        # ── Fallback 3: inferred graph from device_tracker entities ──
        if data is None or _is_empty_snapshot(data):
            candidate = _snapshot_from_openwrt_router_entities(hass)
            if _is_snapshot_dict(candidate):
                data = candidate

        if not _is_snapshot_dict(data):
            data = _empty_snapshot("openwrt_topology_bridge")

        return self.json(data)


async def async_setup_panel(hass: HomeAssistant) -> None:
    """Register static frontend assets, API view and sidebar panel once."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get("_panel_registered"):
        return

    frontend_dir = Path(__file__).resolve().parent / "frontend"
    static_url = "/openwrt_topology"

    if hasattr(hass.http, "async_register_static_paths"):
        await hass.http.async_register_static_paths(
            [StaticPathConfig(static_url, str(frontend_dir), False)]
        )
    else:
        hass.http.register_static_path(static_url, str(frontend_dir), cache_headers=False)

    hass.http.register_view(OpenWrtTopologySnapshotView())

    await async_register_panel(
        hass,
        frontend_url_path="openwrt-topology",
        webcomponent_name="openwrt-topology-panel",
        sidebar_title="Network Topology",
        sidebar_icon="mdi:graph-outline",
        module_url=f"{static_url}/topology-panel-v2.js",
        require_admin=False,
        config={"apiBase": "/api/openwrt_topology/snapshot"},
    )

    domain_data["_panel_registered"] = True
