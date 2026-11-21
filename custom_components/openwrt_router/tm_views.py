"""Network Time Machine: the HTTP routes (GET only).

``GET /api/openwrt_router/enterprise/timemachine/timeline`` (Phase A, own
index since Phases B/C), ``GET …/timemachine/sessions`` (Phase C, client
sessions; administrators only, also while the panel is open to all) and,
since 1.52.0, ``GET …/timemachine/state`` and ``…/compare`` (Phase D,
``tm_state``; like the timeline) and ``GET …/timemachine/export`` (Phase E,
``tm_export``; administrators only, audited, an attachment).

Checks in the order of the sister routes (``traffic_views``, ``rf_views``):
403 for no user or a non-admin while the panel is not open to all users
(before anything else), 410 while the panel view is disabled, no body,
then the strict query (known keys only, each once, short values; 400 with
field and reason, never the input). Off (the default): 200 with
``status: "off"``, no source is read. On: the answer of
``tm_query.async_timeline``. Any other failure is a 500 whose log line names
the error type only.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from aiohttp import web
from homeassistant.components.http import KEY_HASS, KEY_HASS_USER, HomeAssistantView
from homeassistant.core import HomeAssistant, callback

from .const import DATA_TIME_MACHINE_STATS, DATA_TIME_MACHINE_VIEWS_BOUND
from .security_views import NO_STORE, RequestError, error_response, read_body
from .tm_export import EXPORT_QUERY_KEYS, ExportRefused, async_export
from .tm_query import (
    QUERY_KEYS,
    QUERY_VALUE_MAX,
    SESSION_QUERY_KEYS,
    QueryError,
    Stats,
    async_timeline,
    off_body,
    parse_query,
    parse_sessions_query,
    sessions_page,
    time_machine_enabled,
)
from .tm_state import (
    COMPARE_QUERY_KEYS,
    STATE_QUERY_KEYS,
    async_compare,
    async_state,
    parse_compare_query,
    parse_state_query,
)
from .topology_panel import _PANEL_VIEW_DISABLED_KEY, _panel_open_to_all

_LOGGER = logging.getLogger(__name__)

BASE_URL = "/api/openwrt_router/enterprise/timemachine"
VIEW_NAME_PREFIX = "api:openwrt_router:enterprise:timemachine:"


def _bad(field: str, reason: str = "invalid") -> RequestError:
    return RequestError(400, "invalid_request", field=field, reason=reason)


def _query(request: web.Request, keys: frozenset[str] = QUERY_KEYS) -> dict[str, str]:
    """Known keys only, each once, short values."""
    found: dict[str, str] = {}
    for key, value in request.query.items():
        if key not in keys:
            raise _bad("query", "unknown_key")
        if key in found:
            raise _bad(key, "repeated")
        if len(value) > QUERY_VALUE_MAX:
            raise _bad(key, "too_long")
        found[key] = value
    return found


def _stats(hass: HomeAssistant) -> Stats:
    stats = hass.data.get(DATA_TIME_MACHINE_STATS)
    if not isinstance(stats, Stats):
        stats = hass.data[DATA_TIME_MACHINE_STATS] = Stats()
    return stats


class TimeMachineTimelineView(HomeAssistantView):
    """The merged timeline of one window (Phase A sources)."""

    url = f"{BASE_URL}/timeline"
    name = f"{VIEW_NAME_PREFIX}timeline"
    requires_auth = True

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read (no body, strict query)."""
        try:
            hass: HomeAssistant = request.app[KEY_HASS]
            user = request.get(KEY_HASS_USER)
            admin = user is not None and getattr(user, "is_admin", False) is True
            if user is None or (not admin and not _panel_open_to_all(hass)):
                raise RequestError(403, "authorization_denied")
            if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
                raise RequestError(410, "integration_not_loaded")
            await read_body(request, {})  # a GET takes no body
            now = time.time()
            raw = _query(request)
            if "client" in raw and not admin:
                # 1.52.0: a client filter is for administrators; refused
                # before the value is looked at (it reveals nothing)
                raise _bad("client", "admin_only")
            try:
                query = parse_query(raw, now)
            except QueryError as err:
                raise _bad(err.field, err.reason) from None
            if not time_machine_enabled(hass):
                body: dict[str, Any] = off_body(now)
            else:
                body = await async_timeline(
                    hass, query, admin=admin, now=now, stats=_stats(hass)
                )
        except RequestError as err:
            return error_response(err)
        except Exception as err:
            # Only the type: the message may carry router data.
            _LOGGER.warning(
                "Time Machine route %s failed: %s", self.name, type(err).__name__
            )
            _LOGGER.debug("Time Machine route error", exc_info=err)
            return error_response(RequestError(500, "internal"))
        return self.json(body, headers=dict(NO_STORE))


class TimeMachineSessionsView(HomeAssistantView):
    """Client sessions of one window (administrators only)."""

    url = f"{BASE_URL}/sessions"
    name = f"{VIEW_NAME_PREFIX}sessions"
    requires_auth = True

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read (no body, strict query); 403 for every non-admin."""
        try:
            hass: HomeAssistant = request.app[KEY_HASS]
            user = request.get(KEY_HASS_USER)
            if user is None or getattr(user, "is_admin", False) is not True:
                raise RequestError(403, "authorization_denied")
            if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
                raise RequestError(410, "integration_not_loaded")
            await read_body(request, {})
            now = time.time()
            try:
                query = parse_sessions_query(_query(request, SESSION_QUERY_KEYS), now)
            except QueryError as err:
                raise _bad(err.field, err.reason) from None
            body = sessions_page(hass, query, now=now)
        except RequestError as err:
            return error_response(err)
        except Exception as err:
            _LOGGER.warning(
                "Time Machine route %s failed: %s", self.name, type(err).__name__
            )
            _LOGGER.debug("Time Machine route error", exc_info=err)
            return error_response(RequestError(500, "internal"))
        return self.json(body, headers=dict(NO_STORE))


def _reader(request: web.Request) -> tuple[HomeAssistant, bool]:
    """The rights of the timeline: 403 for no user or a non-admin while the
    panel is not open to all, then 410 while the panel view is disabled."""
    hass: HomeAssistant = request.app[KEY_HASS]
    user = request.get(KEY_HASS_USER)
    admin = user is not None and getattr(user, "is_admin", False) is True
    if user is None or (not admin and not _panel_open_to_all(hass)):
        raise RequestError(403, "authorization_denied")
    if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
        raise RequestError(410, "integration_not_loaded")
    return hass, admin


def _failed(name: str, err: Exception) -> web.StreamResponse:
    # Only the type: the message may carry router data.
    _LOGGER.warning("Time Machine route %s failed: %s", name, type(err).__name__)
    _LOGGER.debug("Time Machine route error", exc_info=err)
    return error_response(RequestError(500, "internal"))


class TimeMachineStateView(HomeAssistantView):
    """The state at one moment (Phase D, ``tm_state``)."""

    url = f"{BASE_URL}/state"
    name = f"{VIEW_NAME_PREFIX}state"
    requires_auth = True

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read (no body, strict query)."""
        try:
            hass, admin = _reader(request)
            await read_body(request, {})
            now = time.time()
            try:
                query = parse_state_query(
                    _query(request, STATE_QUERY_KEYS), now, admin=admin
                )
            except QueryError as err:
                raise _bad(err.field, err.reason) from None
            body = await async_state(hass, query, admin=admin, now=now)
        except RequestError as err:
            return error_response(err)
        except Exception as err:  # noqa: BLE001 - logged by type, a 500
            return _failed(self.name, err)
        return self.json(body, headers=dict(NO_STORE))


class TimeMachineCompareView(HomeAssistantView):
    """Two moments side by side (Phase D, ``tm_state``)."""

    url = f"{BASE_URL}/compare"
    name = f"{VIEW_NAME_PREFIX}compare"
    requires_auth = True

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read (no body, strict query)."""
        try:
            hass, admin = _reader(request)
            await read_body(request, {})
            now = time.time()
            try:
                query = parse_compare_query(_query(request, COMPARE_QUERY_KEYS), now)
            except QueryError as err:
                raise _bad(err.field, err.reason) from None
            body = await async_compare(hass, query, admin=admin, now=now)
        except RequestError as err:
            return error_response(err)
        except Exception as err:  # noqa: BLE001 - logged by type, a 500
            return _failed(self.name, err)
        return self.json(body, headers=dict(NO_STORE))


class TimeMachineExportView(HomeAssistantView):
    """The marks of one window as a file (Phase E, administrators only)."""

    url = f"{BASE_URL}/export"
    name = f"{VIEW_NAME_PREFIX}export"
    requires_auth = True

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read (no body, strict query); 403 for every non-admin."""
        try:
            hass: HomeAssistant = request.app[KEY_HASS]
            user = request.get(KEY_HASS_USER)
            if user is None or getattr(user, "is_admin", False) is not True:
                raise RequestError(403, "authorization_denied")
            if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
                raise RequestError(410, "integration_not_loaded")
            await read_body(request, {})
            now = time.time()
            try:
                query = parse_query(_query(request, EXPORT_QUERY_KEYS), now)
            except QueryError as err:
                raise _bad(err.field, err.reason) from None
            try:
                body = await async_export(
                    hass, query, now=now, user_id=getattr(user, "id", None)
                )
            except ExportRefused:
                raise RequestError(503, "refused", reason="audit_unavailable") from None
        except RequestError as err:
            return error_response(err)
        except Exception as err:  # noqa: BLE001 - logged by type, a 500
            return _failed(self.name, err)
        headers = dict(NO_STORE)
        headers["Content-Disposition"] = (
            'attachment; filename="openwrt-router-time-machine.json"'
        )
        return self.json(body, headers=headers)


TIME_MACHINE_VIEWS: tuple[type[HomeAssistantView], ...] = (
    TimeMachineTimelineView,
    TimeMachineSessionsView,
    TimeMachineStateView,
    TimeMachineCompareView,
    TimeMachineExportView,
)


@callback
def async_register_time_machine_views(hass: HomeAssistant) -> None:
    """Register the route once per HA instance (also while off: it says so)."""
    if getattr(hass, "http", None) is None:
        return
    bound: set[str] = hass.data.setdefault(DATA_TIME_MACHINE_VIEWS_BOUND, set())
    for view_class in TIME_MACHINE_VIEWS:
        if view_class.name not in bound:
            hass.http.register_view(view_class())
            bound.add(view_class.name)
