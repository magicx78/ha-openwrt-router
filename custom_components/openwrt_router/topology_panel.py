"""topology_panel.py — Topology panel registration and API view.

Registers (idempotent, once per HA session):
  1. Static frontend path: /openwrt_router_topology → frontend/topology-panel.js
  2. API endpoint:        GET /api/openwrt_topology/snapshot → mesh snapshot JSON
  3. Sidebar panel:       "Network Topology" with mesh visualization

Lifecycle (v1.18.0 — F3):
  Setup and teardown use **reference counting** — each ``async_setup_entry``
  bumps a counter, each ``async_unload_entry`` decrements it.  When the last
  config entry is unloaded:

  - the sidebar panel is removed (HA exposes ``async_remove_panel``),
  - the snapshot view is **soft-disabled** (HA does not expose
    ``unregister_view`` / ``unregister_static_path`` — see HA aiohttp router
    semantics) — subsequent GETs return ``410 Gone``,
  - the static path stays registered (bytes-constant; not a memory leak —
    just a dead URL until HA restart).

  When a fresh entry is added later, the soft-disable flag is cleared so
  GETs return live data again — no full HA restart required.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from aiohttp import web
from homeassistant.components.frontend import async_remove_panel
from homeassistant.components.http import StaticPathConfig
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.components.panel_custom import async_register_panel
from homeassistant.core import HomeAssistant

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

_PANEL_VERSION = "20260429-v1.18.0"
# Master flag: set ONLY after every registration step completed.  Until then,
# a partial setup must still allow re-entry to register the missing pieces.
_PANEL_REGISTERED_KEY = f"{DOMAIN}_panel_registered"
# Per-entry refcount: a fresh entry +1, each unload -1.  Cleanup when 0.
_PANEL_REFCOUNT_KEY = f"{DOMAIN}_panel_refcount"
# Soft-disable flag for the snapshot view (set on last-entry unload).
_PANEL_VIEW_DISABLED_KEY = f"{DOMAIN}_panel_view_disabled"
# Per-stage flags so a retry after a partial failure skips already-bound
# resources (HA aiohttp router does NOT permit re-registering a path/view).
_PANEL_STATIC_BOUND_KEY = f"{DOMAIN}_panel_static_bound"
_PANEL_VIEW_BOUND_KEY = f"{DOMAIN}_panel_view_bound"
# asyncio.Lock that serialises concurrent setup attempts (4 entries spinning
# up at HA boot would otherwise race the static/view registrations).
_PANEL_SETUP_LOCK_KEY = f"{DOMAIN}_panel_setup_lock"
# Sidebar panel URL path — used for both register and remove.
_PANEL_URL_PATH = "openwrt-topology"
_STATIC_URL = "/openwrt_router_topology"


class OpenWrtMeshSnapshotView(HomeAssistantView):
    """Return aggregated mesh topology snapshot from all router entries.

    When all config entries have been unloaded, the soft-disable flag is set
    by ``async_teardown_topology_panel`` and this view returns ``410 Gone``
    until a new entry is set up — at which point the flag is cleared.
    """

    url = "/api/openwrt_topology/snapshot"
    name = "api:openwrt_topology:snapshot"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        """Build and return mesh snapshot."""
        hass: HomeAssistant = request.app["hass"]

        # Soft-disable: last entry was unloaded; static-path/view are still
        # bound to aiohttp's router (no unregister API), so we explicitly
        # answer Gone instead of serving stale snapshot data.
        if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
            return web.Response(
                status=410,
                text="OpenWrt Router integration not loaded",
            )

        try:
            from .topology_mesh import build_mesh_snapshot

            snapshot = build_mesh_snapshot(hass)
        except Exception:  # noqa: BLE001
            _LOGGER.debug("Mesh snapshot build failed", exc_info=True)
            snapshot = _empty_snapshot()
        return self.json(snapshot)


async def async_setup_topology_panel(hass: HomeAssistant) -> None:
    """Register static assets, API view and sidebar panel; bump refcount.

    Idempotent and concurrency-safe:

    * concurrent setup calls (multiple config entries spinning up at HA
      boot) are serialised by an ``asyncio.Lock`` stored in ``hass.data``;
    * each registration stage has its own flag so a retry after a partial
      failure skips already-bound resources;
    * if any stage raises, refcount is rolled back and the exception is
      re-raised so HA marks the entry as failed.

    The master ``_PANEL_REGISTERED_KEY`` flag is set ONLY after every stage
    succeeded, so a permanent half-broken state is no longer possible.
    """
    # Acquire the per-hass setup lock; create lazily on first call.
    lock = hass.data.get(_PANEL_SETUP_LOCK_KEY)
    if lock is None:
        lock = asyncio.Lock()
        hass.data[_PANEL_SETUP_LOCK_KEY] = lock

    async with lock:
        # Bump refcount unconditionally — a fresh entry is alive even if a
        # previous attempt left registrations behind.  Rolled back on
        # exception below.
        hass.data[_PANEL_REFCOUNT_KEY] = hass.data.get(_PANEL_REFCOUNT_KEY, 0) + 1

        # Re-arm the snapshot view if it was soft-disabled by a previous
        # full unload — fresh entry → live data again.
        hass.data[_PANEL_VIEW_DISABLED_KEY] = False

        if hass.data.get(_PANEL_REGISTERED_KEY):
            # Already fully registered in this HA session — refcount is enough.
            return

        try:
            frontend_dir = Path(__file__).resolve().parent / "frontend"

            # Stage 1: static path — append-only on aiohttp's router; once
            # bound, never re-bind.
            if not hass.data.get(_PANEL_STATIC_BOUND_KEY):
                if hasattr(hass.http, "async_register_static_paths"):
                    await hass.http.async_register_static_paths(
                        [StaticPathConfig(_STATIC_URL, str(frontend_dir), False)]
                    )
                else:
                    hass.http.register_static_path(
                        _STATIC_URL, str(frontend_dir), cache_headers=False
                    )
                hass.data[_PANEL_STATIC_BOUND_KEY] = True

            # Stage 2: HTTP view — also append-only on aiohttp's router.
            if not hass.data.get(_PANEL_VIEW_BOUND_KEY):
                hass.http.register_view(OpenWrtMeshSnapshotView())
                hass.data[_PANEL_VIEW_BOUND_KEY] = True

            # Stage 3: sidebar panel — async_register_panel raises if the
            # path is already registered.  We rely on _PANEL_REGISTERED_KEY
            # below to gate re-entry, plus async_remove_panel on teardown.
            await async_register_panel(
                hass,
                frontend_url_path=_PANEL_URL_PATH,
                webcomponent_name="openwrt-topology-panel",
                sidebar_title="Network Topology",
                sidebar_icon="mdi:graph-outline",
                module_url=(
                    f"{_STATIC_URL}/dist/topology-bundle.js?v={_PANEL_VERSION}"
                ),
                require_admin=False,
                config={"apiBase": "/api/openwrt_topology/snapshot"},
            )
        except Exception:
            # Roll back the refcount we bumped above so the entry's failed
            # setup does not leak it.  Stage flags are intentionally NOT
            # rolled back — the resources they describe are still bound to
            # aiohttp's router and a retry must skip them.
            hass.data[_PANEL_REFCOUNT_KEY] = max(
                0, hass.data.get(_PANEL_REFCOUNT_KEY, 1) - 1
            )
            raise

        # Master flag set only after every stage succeeded.
        hass.data[_PANEL_REGISTERED_KEY] = True
        _LOGGER.debug("Topology panel registered (version %s)", _PANEL_VERSION)


async def async_teardown_topology_panel(hass: HomeAssistant) -> None:
    """Decrement refcount; on last unload remove the panel and soft-disable view.

    Call this from ``async_unload_entry`` AFTER platform unload but BEFORE
    dropping ``runtime_data``, so the snapshot view never observes a half-torn
    entry.

    HA / aiohttp do not expose ``unregister_view`` or ``unregister_static_path``
    — both registrations are append-only on the URL dispatcher.  We therefore
    accept that the static path stays bound (bytes-constant, not a leak) and
    use a soft-disable flag to make the snapshot view answer ``410 Gone`` once
    the last entry is gone.
    """
    refcount = hass.data.get(_PANEL_REFCOUNT_KEY, 0) - 1
    hass.data[_PANEL_REFCOUNT_KEY] = max(0, refcount)

    if refcount > 0:
        # Other entries still loaded — leave panel/view alive.
        _LOGGER.debug(
            "Topology panel refcount=%d after unload, keeping panel alive",
            refcount,
        )
        return

    # Last entry — remove what we can, soft-disable the rest.
    try:
        async_remove_panel(hass, _PANEL_URL_PATH)
    except Exception:  # noqa: BLE001
        _LOGGER.debug("async_remove_panel failed (already gone?)", exc_info=True)

    hass.data[_PANEL_VIEW_DISABLED_KEY] = True
    # Clear the master flag so a future setup re-registers the sidebar panel.
    # Stage flags for static path / view stay set — those resources are still
    # bound to aiohttp's append-only router and must NOT be re-registered.
    hass.data[_PANEL_REGISTERED_KEY] = False
    _LOGGER.debug("Topology panel torn down — view soft-disabled until next setup")


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
