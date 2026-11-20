"""topology_panel.py — Topology panel registration and API view.

Registers (idempotent, once per HA session):
  1. Static frontend path: /openwrt_router_topology → frontend/topology-panel.js
  2. API endpoint:        GET /api/openwrt_topology/snapshot → mesh snapshot JSON,
     plus (P7) the network intelligence routes under
     /api/openwrt_topology/intelligence/ (summary, events, incidents,
     incidents/{id}, settings)
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

Access control (v1.39.0):
  The snapshot carries DHCP leases, ARP/FDB tables, WAN IP, DDNS and web
  URLs, so the panel and the API are **admin-only by default**.  The option
  ``topology_panel_all_users`` opens both to every HA user.  There is only one
  panel for all config entries, so the options combine with OR: the panel is
  public if ANY entry that set it up has the option on.  The combined value is
  re-evaluated on every entry setup, unload and options change; the sidebar
  panel is re-registered only when ``require_admin`` actually flips.  The API
  view checks the combined value on every request, so it follows immediately.

  The intelligence routes (P7) check the same way.  Their writing requests
  (POST incident status, POST settings) are for administrators only, also
  when the panel is open to all users.  They read the engine's memory
  (``net_query``); none of them talks to a router.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from aiohttp import web
from homeassistant.components.frontend import async_remove_panel
from homeassistant.components.http import KEY_HASS_USER, StaticPathConfig
from homeassistant.components.http.view import HomeAssistantView
from homeassistant.components.panel_custom import async_register_panel
from homeassistant.config_entries import ConfigEntry, ConfigEntryState
from homeassistant.core import HomeAssistant

from .const import (
    CONF_TOPOLOGY_PANEL_ALL_USERS,
    DEFAULT_TOPOLOGY_PANEL_ALL_USERS,
    DOMAIN,
)

try:
    from homeassistant.helpers.http import KEY_HASS
except ImportError:  # pragma: no cover - older HA cores keyed the app by str
    KEY_HASS = "hass"  # type: ignore[assignment]

_LOGGER = logging.getLogger(__name__)

# Cache-busting query for the bundle URL — bump on every frontend rebuild.
_PANEL_VERSION = "20261120-config-partial2"
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
# Names of the views already bound (P7: several views; a retry after a
# failure part-way binds only the missing ones).
_PANEL_VIEWS_BOUND_KEY = f"{DOMAIN}_panel_views_bound"
# asyncio.Lock that serialises concurrent setup attempts (4 entries spinning
# up at HA boot would otherwise race the static/view registrations).
_PANEL_SETUP_LOCK_KEY = f"{DOMAIN}_panel_setup_lock"
# entry_id → "show to all users" option of every entry with a live panel setup.
_PANEL_ACCESS_KEY = f"{DOMAIN}_panel_access"
# require_admin value the sidebar panel is currently registered with.
_PANEL_REQUIRE_ADMIN_KEY = f"{DOMAIN}_panel_require_admin"
# Sidebar panel URL path — used for both register and remove.
_PANEL_URL_PATH = "openwrt-topology"
_STATIC_URL = "/openwrt_router_topology"


def _entry_allows_all_users(entry: ConfigEntry) -> bool:
    """Return the entry's "show topology panel to all users" option."""
    return bool(
        entry.options.get(
            CONF_TOPOLOGY_PANEL_ALL_USERS, DEFAULT_TOPOLOGY_PANEL_ALL_USERS
        )
    )


def _panel_access(hass: HomeAssistant) -> dict[str, bool]:
    """Return the per-entry access map (created lazily)."""
    access: dict[str, bool] | None = hass.data.get(_PANEL_ACCESS_KEY)
    if access is None:
        access = {}
        hass.data[_PANEL_ACCESS_KEY] = access
    return access


def _panel_open_to_all(hass: HomeAssistant) -> bool:
    """Return True if any entry with a live panel setup opens it to all users."""
    return any(_panel_access(hass).values())


def _setup_lock(hass: HomeAssistant) -> asyncio.Lock:
    """Return the per-hass panel lock (created lazily)."""
    lock: asyncio.Lock | None = hass.data.get(_PANEL_SETUP_LOCK_KEY)
    if lock is None:
        lock = asyncio.Lock()
        hass.data[_PANEL_SETUP_LOCK_KEY] = lock
    return lock


class OpenWrtMeshSnapshotView(HomeAssistantView):
    """Return aggregated mesh topology snapshot from all router entries.

    Admin-only unless an entry enables ``topology_panel_all_users``; other
    users get ``403``.  When all config entries have been unloaded, the
    soft-disable flag is set by ``async_teardown_topology_panel`` and this
    view returns ``410 Gone`` until a new entry is set up.
    """

    url = "/api/openwrt_topology/snapshot"
    name = "api:openwrt_topology:snapshot"
    requires_auth = True

    async def get(self, request: web.Request) -> web.Response:
        """Build and return mesh snapshot."""
        hass: HomeAssistant = request.app[KEY_HASS]

        user = request.get(KEY_HASS_USER)
        if not getattr(user, "is_admin", False) and not _panel_open_to_all(hass):
            return self.json_message(
                "The network topology is available to administrators only",
                status_code=403,
            )

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
        except Exception as err:
            # Report every failure as 500.  Never mask a failure as an empty topology (looks like "all
            # routers gone").  The body names only the exception type — the
            # message may carry router data, the trace stays in the debug log.
            _LOGGER.warning("Mesh snapshot build failed: %s", type(err).__name__)
            _LOGGER.debug("Mesh snapshot build failed", exc_info=True)
            body = _empty_snapshot()
            body["meta"]["error"] = f"snapshot build failed ({type(err).__name__})"
            return self.json(body, status_code=500)
        return self.json(snapshot)


_INTEL_URL = "/api/openwrt_topology/intelligence"

type _NameOf = Callable[[str], str]


def _router_names(hass: HomeAssistant) -> _NameOf:
    """Entry id -> config entry title (the id itself for a removed router)."""
    cache: dict[str, str] = {}

    def name_of(entry_id: str) -> str:
        name = cache.get(entry_id)
        if name is None:
            entry = hass.config_entries.async_get_entry(entry_id)
            title = getattr(entry, "title", None) if entry is not None else None
            name = title if isinstance(title, str) and title else entry_id
            cache[entry_id] = name
        return name

    return name_of


class _IntelView(HomeAssistantView):
    """Common access checks of the network intelligence routes (P7).

    Reading: like the snapshot (admin, or every user while an entry opens
    the panel to all; 410 after the last unload).  Writing: admin only.
    503 while the engine is not running or has not read its store yet.
    """

    requires_auth = True

    def _check(
        self, request: web.Request, *, write: bool = False
    ) -> web.Response | None:
        hass: HomeAssistant = request.app[KEY_HASS]
        is_admin = self._is_admin(request)
        if write and not is_admin:
            return self.json_message(
                "Changes are available to administrators only", status_code=403
            )
        if not is_admin and not _panel_open_to_all(hass):
            return self.json_message(
                "The network topology is available to administrators only",
                status_code=403,
            )
        if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
            return web.Response(
                status=410, text="OpenWrt Router integration not loaded"
            )
        return None

    @staticmethod
    def _is_admin(request: web.Request) -> bool:
        return bool(getattr(request.get(KEY_HASS_USER), "is_admin", False))

    @staticmethod
    def _engine(hass: HomeAssistant) -> Any:
        """The running engine once it has read its store, else None."""
        from .net_engine import async_get_engine

        engine = async_get_engine(hass)
        if engine is None or not engine.loaded:
            return None
        return engine

    def _unavailable(self) -> web.Response:
        return self.json_message(
            "Network intelligence is not running yet", status_code=503
        )

    def _failed(self, err: Exception) -> web.Response:
        # Only the exception type: the message may carry router data.
        what = self.name.rsplit(":", 1)[-1]
        return self.json_message(
            f"{what} failed ({type(err).__name__})", status_code=500
        )

    async def _read(
        self, request: web.Request, build: Callable[[Any, _NameOf, float], Any]
    ) -> web.Response:
        """Shared GET: checks, engine, ``build(engine, name_of, now)``;
        ``None`` from ``build`` is an unknown incident (404)."""
        from .net_query import QueryError, engine_now

        if (blocked := self._check(request)) is not None:
            return blocked
        hass: HomeAssistant = request.app[KEY_HASS]
        engine = self._engine(hass)
        if engine is None:
            return self._unavailable()
        try:
            body = build(engine, _router_names(hass), engine_now(engine, time.time()))
        except QueryError as err:
            return self.json_message(str(err), status_code=400)
        except Exception as err:
            # The trace stays in the debug log (it may carry router data).
            _LOGGER.warning("Intelligence request failed: %s", type(err).__name__)
            _LOGGER.debug("Intelligence request failed", exc_info=True)
            return self._failed(err)
        if body is None:
            return self.json_message("Unknown incident", status_code=404)
        return self.json(body)

    @staticmethod
    async def _body(request: web.Request) -> Any:
        """JSON body; raises ``QueryError`` when it is not JSON.

        ``RecursionError``: too deeply nested for the parser (a bad body,
        not a server error).
        """
        from .net_query import QueryError

        try:
            return await request.json()
        except (ValueError, RecursionError):
            raise QueryError("body: JSON expected") from None


class OpenWrtIntelSummaryView(_IntelView):
    """Score and coverage per router and fleet, incidents by severity,
    event counts of the last 24 h."""

    url = f"{_INTEL_URL}/summary"
    name = "api:openwrt_topology:intelligence:summary"

    async def get(self, request: web.Request) -> web.Response:
        """Return the summary."""
        from .net_query import summary

        return await self._read(request, summary)


class OpenWrtIntelEventsView(_IntelView):
    """Event timeline with filters; ``limit`` <= 500, cursor ``before``."""

    url = f"{_INTEL_URL}/events"
    name = "api:openwrt_topology:intelligence:events"

    async def get(self, request: web.Request) -> web.Response:
        """Return one page of events, newest first."""
        from .net_query import events_page, parse_events_query

        query = request.query

        def build(engine: Any, name_of: _NameOf, _now: float) -> Any:
            return events_page(engine, name_of, parse_events_query(query))

        return await self._read(request, build)


class OpenWrtIntelIncidentsView(_IntelView):
    """Incident list; filters ``status``, ``router``, ``severity``; ``limit`` <= 200."""

    url = f"{_INTEL_URL}/incidents"
    name = "api:openwrt_topology:intelligence:incidents"

    async def get(self, request: web.Request) -> web.Response:
        """Return the incidents, open ones first."""
        from .net_query import incidents_page, parse_incidents_query

        query = request.query

        def build(engine: Any, name_of: _NameOf, now: float) -> Any:
            return incidents_page(engine, name_of, parse_incidents_query(query), now)

        return await self._read(request, build)


class OpenWrtIntelIncidentView(_IntelView):
    """One incident: GET detail; POST a new status (admin only)."""

    url = f"{_INTEL_URL}/incidents/{{incident_id}}"
    name = "api:openwrt_topology:intelligence:incident"

    async def get(self, request: web.Request, incident_id: str) -> web.Response:
        """Return the incident with evidence, parent, children and chain."""
        from .net_query import incident_detail

        def build(engine: Any, name_of: _NameOf, now: float) -> Any:
            return incident_detail(engine, incident_id, name_of, now)

        return await self._read(request, build)

    async def post(self, request: web.Request, incident_id: str) -> web.Response:
        """Acknowledge, ignore (``ignore_days`` optional) or re-activate."""
        from .net_query import QueryError, parse_status_body

        if (blocked := self._check(request, write=True)) is not None:
            return blocked
        engine = self._engine(request.app[KEY_HASS])
        if engine is None:
            return self._unavailable()
        try:
            status, days = parse_status_body(await self._body(request))
        except QueryError as err:
            return self.json_message(str(err), status_code=400)
        done = engine.set_incident_status(incident_id, status, ignore_days=days)
        if done is None:
            return self.json_message("Unknown incident", status_code=404)
        if not done:
            return self.json_message(
                f"Incident cannot be set to {status} in its current status",
                status_code=409,
            )
        return await self.get(request, incident_id)


class OpenWrtIntelSettingsView(_IntelView):
    """Thresholds, exclusions, maintenance: GET for readers, POST admin only."""

    url = f"{_INTEL_URL}/settings"
    name = "api:openwrt_topology:intelligence:settings"

    def _answer(self, hass: HomeAssistant, engine: Any, is_admin: bool) -> web.Response:
        from .net_rules import (
            DEFAULT_SETTINGS,
            SETTINGS_LIST_MAX,
            SETTINGS_STRING_MAX,
        )

        name_of = _router_names(hass)
        excluded = engine.settings.get("exclusions", {}).get("routers") or []
        routers = sorted(
            set(engine.routers) | {r for r in excluded if isinstance(r, str)}
        )
        return self.json(
            {
                "settings": engine.settings,
                "defaults": DEFAULT_SETTINGS,
                "can_edit": is_admin,
                "routers": [
                    {
                        "id": router,
                        "name": name_of(router),
                        "maintenance": engine.router_maintenance(router),
                    }
                    for router in routers
                ],
                "limits": {
                    "list_max": SETTINGS_LIST_MAX,
                    "string_max": SETTINGS_STRING_MAX,
                },
            }
        )

    async def get(self, request: web.Request) -> web.Response:
        """Return the settings with the defaults and the known routers."""
        if (blocked := self._check(request)) is not None:
            return blocked
        hass: HomeAssistant = request.app[KEY_HASS]
        engine = self._engine(hass)
        if engine is None:
            return self._unavailable()
        return self._answer(hass, engine, self._is_admin(request))

    async def post(self, request: web.Request) -> web.Response:
        """Apply a (partial) settings change; 400 with ``errors`` if invalid."""
        from .net_query import QueryError

        if (blocked := self._check(request, write=True)) is not None:
            return blocked
        hass: HomeAssistant = request.app[KEY_HASS]
        engine = self._engine(hass)
        if engine is None:
            return self._unavailable()
        try:
            patch = await self._body(request)
        except QueryError as err:
            return self.json_message(str(err), status_code=400)
        errors = engine.apply_settings(patch)
        if errors:
            return self.json(
                {"message": "Invalid settings", "errors": errors}, status_code=400
            )
        return self._answer(hass, engine, True)


def _api_views() -> tuple[HomeAssistantView, ...]:
    """Every API view of the panel (bound once per HA session)."""
    # Imported here: client_views builds on this module's base view.
    from .client_views import client_api_views

    return (
        OpenWrtMeshSnapshotView(),
        OpenWrtIntelSummaryView(),
        OpenWrtIntelEventsView(),
        OpenWrtIntelIncidentsView(),
        OpenWrtIntelIncidentView(),
        OpenWrtIntelSettingsView(),
        *client_api_views(),
    )


async def _async_register_sidebar_panel(
    hass: HomeAssistant, require_admin: bool
) -> None:
    """Register the sidebar panel and remember its ``require_admin`` value."""
    await async_register_panel(
        hass,
        frontend_url_path=_PANEL_URL_PATH,
        webcomponent_name="openwrt-topology-panel",
        sidebar_title="Network Topology",
        sidebar_icon="mdi:graph-outline",
        module_url=f"{_STATIC_URL}/dist/topology-bundle.js?v={_PANEL_VERSION}",
        require_admin=require_admin,
    )
    hass.data[_PANEL_REQUIRE_ADMIN_KEY] = require_admin


async def _async_apply_panel_access(hass: HomeAssistant) -> None:
    """Re-register the sidebar panel if its audience changed.

    HA has no "update panel" call for custom panels, so a change of
    ``require_admin`` means remove + register.  Must run under the setup lock.
    """
    if not hass.data.get(_PANEL_REGISTERED_KEY):
        return
    require_admin = not _panel_open_to_all(hass)
    if hass.data.get(_PANEL_REQUIRE_ADMIN_KEY) == require_admin:
        return
    async_remove_panel(hass, _PANEL_URL_PATH, warn_if_unknown=False)
    try:
        await _async_register_sidebar_panel(hass, require_admin)
    except Exception:
        # Panel is gone now — let the next setup register it from scratch.
        hass.data[_PANEL_REGISTERED_KEY] = False
        raise
    _LOGGER.debug("Topology panel re-registered (require_admin=%s)", require_admin)


async def async_setup_topology_panel(
    hass: HomeAssistant, entry: ConfigEntry | None = None
) -> None:
    """Register static assets, API view and sidebar panel; bump refcount.

    Idempotent and concurrency-safe:

    * concurrent setup calls (multiple config entries spinning up at HA
      boot) are serialised by an ``asyncio.Lock`` stored in ``hass.data``;
    * each registration stage has its own flag so a retry after a partial
      failure skips already-bound resources;
    * if any stage raises, refcount is rolled back and the exception is
      re-raised so the caller can decide how to handle it.

    The master ``_PANEL_REGISTERED_KEY`` flag is set ONLY after every stage
    succeeded, so a permanent half-broken state is no longer possible.

    When ``entry`` is given, its access option joins the combined panel
    audience and a second setup for the same entry is not counted twice.
    """
    async with _setup_lock(hass):
        await _async_setup_locked(hass, entry)


async def _async_setup_locked(
    hass: HomeAssistant, entry: ConfigEntry | None, all_users: bool | None = None
) -> None:
    """Body of ``async_setup_topology_panel``; caller holds the setup lock.

    ``all_users`` overrides the entry's stored option (options flow: the new
    value is not stored yet).
    """
    access = _panel_access(hass)
    already_counted = entry is not None and entry.entry_id in access
    previous_access = access.get(entry.entry_id) if entry is not None else None

    # Bump refcount for a fresh entry — it is alive even if a previous
    # attempt left registrations behind.  Rolled back on exception below.
    if not already_counted:
        hass.data[_PANEL_REFCOUNT_KEY] = hass.data.get(_PANEL_REFCOUNT_KEY, 0) + 1
    if entry is not None:
        access[entry.entry_id] = (
            _entry_allows_all_users(entry) if all_users is None else all_users
        )

    # Re-arm the snapshot view if it was soft-disabled by a previous
    # full unload — fresh entry → live data again.
    hass.data[_PANEL_VIEW_DISABLED_KEY] = False

    try:
        if hass.data.get(_PANEL_REGISTERED_KEY):
            # Already registered in this HA session — the refcount is
            # enough, unless this entry changes the panel's audience.
            await _async_apply_panel_access(hass)
            return

        frontend_dir = Path(__file__).resolve().parent / "frontend"

        # Stage 1: static path — append-only on aiohttp's router; once
        # bound, never re-bind.
        if not hass.data.get(_PANEL_STATIC_BOUND_KEY):
            await hass.http.async_register_static_paths(
                [StaticPathConfig(_STATIC_URL, str(frontend_dir), False)]
            )
            hass.data[_PANEL_STATIC_BOUND_KEY] = True

        # Stage 2: HTTP views — also append-only on aiohttp's router.  Each
        # view is remembered by name, so a retry after a failure part-way
        # binds only the missing ones.
        if not hass.data.get(_PANEL_VIEW_BOUND_KEY):
            bound: set[str] = hass.data.setdefault(_PANEL_VIEWS_BOUND_KEY, set())
            for view in _api_views():
                if view.name not in bound:
                    hass.http.register_view(view)
                    bound.add(view.name)
            hass.data[_PANEL_VIEW_BOUND_KEY] = True

        # Stage 3: sidebar panel — async_register_panel raises if the
        # path is already registered.  We rely on _PANEL_REGISTERED_KEY
        # below to gate re-entry, plus async_remove_panel on teardown.
        await _async_register_sidebar_panel(
            hass, require_admin=not _panel_open_to_all(hass)
        )
    except Exception:
        # Roll back what this call added so the entry's failed setup does
        # not leak it.  Stage flags are intentionally NOT rolled back —
        # the resources they describe are still bound to aiohttp's router
        # and a retry must skip them.
        if not already_counted:
            hass.data[_PANEL_REFCOUNT_KEY] = max(
                0, hass.data.get(_PANEL_REFCOUNT_KEY, 1) - 1
            )
            if entry is not None:
                access.pop(entry.entry_id, None)
        elif entry is not None and previous_access is not None:
            access[entry.entry_id] = previous_access
        raise

    # Master flag set only after every stage succeeded.
    hass.data[_PANEL_REGISTERED_KEY] = True
    _LOGGER.debug("Topology panel registered (version %s)", _PANEL_VERSION)


async def async_update_topology_panel_access(
    hass: HomeAssistant, entry: ConfigEntry, all_users: bool | None = None
) -> None:
    """Apply a changed "show to all users" option of ``entry``.

    Called from the options flow with the new value (the options are stored
    only after the flow step returns); ``None`` reads ``entry.options``.  There
    is deliberately no update listener — it would clash with the reauth
    steps' ``async_update_reload_and_abort``.

    A loaded entry without a live panel setup (its setup failed and was
    rolled back) gets a fresh panel setup here, so the option still applies
    without a reload.  Entries that are not loaded are ignored — their option
    is picked up by their next setup.
    """
    async with _setup_lock(hass):
        access = _panel_access(hass)
        if entry.entry_id not in access:
            if getattr(entry, "state", None) is ConfigEntryState.LOADED:
                await _async_setup_locked(hass, entry, all_users)
            return
        access[entry.entry_id] = (
            _entry_allows_all_users(entry) if all_users is None else all_users
        )
        await _async_apply_panel_access(hass)


async def async_teardown_topology_panel(
    hass: HomeAssistant, entry: ConfigEntry | None = None
) -> None:
    """Decrement refcount; on last unload remove the panel and soft-disable view.

    Call this from ``async_unload_entry`` AFTER platform unload but BEFORE
    dropping ``runtime_data``, so the snapshot view never observes a half-torn
    entry.

    When ``entry`` is given and it never completed a panel setup (e.g. the
    setup failed and was rolled back), nothing is decremented.  Otherwise its
    access option leaves the combined audience, which may restrict the panel
    to admins again.

    HA / aiohttp do not expose ``unregister_view`` or ``unregister_static_path``
    — both registrations are append-only on the URL dispatcher.  We therefore
    accept that the static path stays bound (bytes-constant, not a leak) and
    use a soft-disable flag to make the snapshot view answer ``410 Gone`` once
    the last entry is gone.
    """
    async with _setup_lock(hass):
        if entry is not None:
            access = _panel_access(hass)
            if entry.entry_id not in access:
                _LOGGER.debug(
                    "Topology panel teardown skipped — entry had no panel setup"
                )
                return
            access.pop(entry.entry_id)

        refcount = hass.data.get(_PANEL_REFCOUNT_KEY, 0) - 1
        hass.data[_PANEL_REFCOUNT_KEY] = max(0, refcount)

        if refcount > 0:
            # Other entries still loaded — leave panel/view alive, but the
            # departing entry may have been the one that opened it to all.
            _LOGGER.debug(
                "Topology panel refcount=%d after unload, keeping panel alive",
                refcount,
            )
            try:
                await _async_apply_panel_access(hass)
            except Exception:
                _LOGGER.warning(
                    "Could not re-register the topology panel after unload",
                    exc_info=True,
                )
            return

        # Last entry — remove what we can, soft-disable the rest.
        try:
            async_remove_panel(hass, _PANEL_URL_PATH)
        except Exception:
            _LOGGER.debug("async_remove_panel failed (already gone?)", exc_info=True)

        hass.data[_PANEL_VIEW_DISABLED_KEY] = True
        hass.data.pop(_PANEL_REQUIRE_ADMIN_KEY, None)
        # Clear the master flag so a future setup re-registers the sidebar
        # panel.  Stage flags for static path / view stay set — those
        # resources are still bound to aiohttp's append-only router and must
        # NOT be re-registered.
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
