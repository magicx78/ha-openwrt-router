"""topology_panel.py — Topology panel registration and API view.

Registers:
  1. Static frontend path: /openwrt_router_topology → frontend/topology-panel.js
  2. API endpoint: GET /api/openwrt_topology/snapshot → mesh snapshot JSON
  3. Sidebar panel: "Network Topology" with mesh visualization

Called once from __init__.async_setup_entry() — idempotent.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from aiohttp import web
from homeassistant.components.http import StaticPathConfig
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.components.panel_custom import async_register_panel
from homeassistant.components.frontend import async_remove_panel
from homeassistant.core import HomeAssistant

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

_PANEL_VERSION = "20260419c"
_PANEL_REGISTERED_KEY = f"{DOMAIN}_panel_registered_{_PANEL_VERSION}"
_STATIC_URL = "/openwrt_router_topology"


class OpenWrtMeshSnapshotView(HomeAssistantView):
    """Return aggregated mesh topology snapshot from all router entries."""

    url = "/api/openwrt_topology/snapshot"
    name = "api:openwrt_topology:snapshot"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        """Build and return mesh snapshot."""
        hass: HomeAssistant = request.app["hass"]
        try:
            from .topology_mesh import build_mesh_snapshot

            snapshot = build_mesh_snapshot(hass)
        except Exception:  # noqa: BLE001
            _LOGGER.debug("Mesh snapshot build failed", exc_info=True)
            snapshot = _empty_snapshot()
        return self.json(snapshot)


async def async_setup_topology_panel(hass: HomeAssistant) -> None:
    """Register static frontend assets, API view and sidebar panel.

    Safe to call multiple times — registers only once per HA session.
    """
    if hass.data.get(_PANEL_REGISTERED_KEY):
        return
    # Set flag immediately (before any await) to prevent race condition when
    # multiple config entries call this function concurrently at startup.
    hass.data[_PANEL_REGISTERED_KEY] = True

    frontend_dir = Path(__file__).resolve().parent / "frontend"

    # Register static path for JS assets
    if hasattr(hass.http, "async_register_static_paths"):
        await hass.http.async_register_static_paths(
            [StaticPathConfig(_STATIC_URL, str(frontend_dir), False)]
        )
    else:
        hass.http.register_static_path(
            _STATIC_URL, str(frontend_dir), cache_headers=False
        )

    # Register API endpoint
    hass.http.register_view(OpenWrtMeshSnapshotView())

    # Remove existing panel registration if present from a previous HA session.
    # async_register_panel raises if the URL path is already registered.
    async_remove_panel(hass, "openwrt-topology")

    # Register sidebar panel
    await async_register_panel(
        hass,
        frontend_url_path="openwrt-topology",
        webcomponent_name="openwrt-topology-panel",
        sidebar_title="Network Topology",
        sidebar_icon="mdi:graph-outline",
        module_url=f"{_STATIC_URL}/dist/topology-bundle.js?v={_PANEL_VERSION}",
        require_admin=False,
        config={"apiBase": "/api/openwrt_topology/snapshot"},
    )

    _LOGGER.debug("Topology panel registered")


def _empty_snapshot() -> dict[str, Any]:
    """Return an empty mesh snapshot."""
    return {
        "generated_at": None,
        "nodes": [],
        "edges": [],
        "interfaces": [],
        "clients": [],
        "meta": {
            "source": "ha-openwrt.mesh_aggregator",
            "schema_version": "1.0",
            "inference_used": False,
            "node_count": 0,
            "edge_count": 0,
            "router_count": 0,
            "mesh": True,
        },
    }
