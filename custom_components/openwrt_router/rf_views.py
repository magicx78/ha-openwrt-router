"""HTTP routes of WiFi RF Intelligence (release 1.48.0 part 1, read only).

Base ``/api/openwrt_router/enterprise/wifi``: ``overview``, ``radios``,
``channel_map``, ``timeline``, ``roaming``, ``recommendations``. GET only:
there is no write route and no scan route.

Order of the checks (same plumbing as ``security_views``):

1. a logged-in HA user (``requires_auth``: 401 from HA itself);
2. administrators, and other users only while an entry opens the topology
   panel to all users (else 403) -- before the RF switch is looked at and
   before any body is read;
3. 410 after the last entry unloaded, 503 while no center runs;
4. the body: a GET takes none (``security_views.read_body`` with no known
   key: > 4 KiB 413, nested or any key 400);
5. the query: known keys only, ``window`` from the fixed list, ids by the
   Core token rule (400 otherwise);
6. RF off or not ready: 200 with ``status`` ``off`` / ``not_ready``.

The client roaming history (``roaming``) is a sensitive read: only for an
administrator whose panel session the Core guard approved
(``RfCenter.async_authorize_sensitive``); a Core ``AuthorizationError`` is a
403. Everybody else gets the counts only.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

from aiohttp import web
from homeassistant.components.http import (
    KEY_HASS_REFRESH_TOKEN_ID,
    KEY_HASS_USER,
    HomeAssistantView,
)
from homeassistant.core import Context, HomeAssistant, callback

from .const import DATA_WIFI_RF_VIEWS_BOUND
from .core_models import async_actor_from_context
from .rf_identity import require_radio_id, require_router_id
from .rf_output import (
    RESTRICTED_ADMIN_ONLY,
    TIMELINE_WINDOWS,
    channel_map,
    overview,
    radios,
    recommendations,
    roaming,
    timeline,
)
from .rf_store import SERIES
from .security_views import NO_STORE, RequestError, error_response, read_body
from .topology_panel import _PANEL_VIEW_DISABLED_KEY, _panel_open_to_all

try:
    from homeassistant.helpers.http import KEY_HASS
except ImportError:  # pragma: no cover - older HA cores keyed the app by str
    KEY_HASS = "hass"  # type: ignore[assignment]

_LOGGER = logging.getLogger(__name__)

BASE_URL = "/api/openwrt_router/enterprise/wifi"
VIEW_NAME_PREFIX = "api:openwrt_router:enterprise:wifi:"
ROAM_ACTION = "wifi_rf.client_roam_history"
QUERY_VALUE_MAX = 128
_SESSION_PART = re.compile(r"[A-Za-z0-9_.:-]{1,128}")

# RfCenterError.reason -> (status, code)
_REASONS: Mapping[str, tuple[int, str]] = {
    "no_core": (503, "no_core"),
    "not_admin": (403, "authorization_denied"),
    "refused": (403, "authorization_denied"),
}


def _bad(field: str, reason: str = "invalid") -> RequestError:
    return RequestError(400, "invalid_request", field=field, reason=reason)


def _query(request: web.Request, allowed: frozenset[str]) -> dict[str, str]:
    """Known keys only, each once, short values."""
    out: dict[str, str] = {}
    for key, value in request.query.items():
        if key not in allowed:
            raise _bad("query", "unknown_key")
        if key in out:
            raise _bad(key, "repeated")
        if len(value) > QUERY_VALUE_MAX:
            raise _bad(key, "too_long")
        out[key] = value
    return out


def _session_id(request: web.Request, user_id: str) -> str:
    """DECIDED: one panel session = one HA login (refresh token) of the user."""
    token = request.get(KEY_HASS_REFRESH_TOKEN_ID)
    token = token if isinstance(token, str) and _SESSION_PART.fullmatch(token) else "-"
    return f"{user_id}:{token}"


class _RfView(HomeAssistantView):
    """Access checks, error mapping and output of every RF route."""

    requires_auth = True

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read."""
        try:
            hass: HomeAssistant = request.app[KEY_HASS]
            user = request.get(KEY_HASS_USER)
            admin = user is not None and getattr(user, "is_admin", False) is True
            if user is None or (not admin and not _panel_open_to_all(hass)):
                raise RequestError(403, "authorization_denied")
            if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
                raise RequestError(410, "integration_not_loaded")
            from .rf_center import async_get_rf_center

            center = async_get_rf_center(hass)
            if center is None or not center.loaded:
                raise RequestError(503, "not_running")
            await read_body(request, {})  # a GET takes no body
            user_id = getattr(user, "id", None)
            user_id = user_id if isinstance(user_id, str) and user_id else None
            context = {"hass": hass, "user_id": user_id, "admin": admin}
            body = await self.handle(center, request, context)
        except RequestError as err:
            return error_response(err)
        except Exception as err:  # noqa: BLE001 - mapped to a fixed answer
            return self._error(err)
        return self.json(body, headers=dict(NO_STORE))

    def _error(self, err: Exception) -> web.Response:
        from .core_errors import AuthorizationError
        from .rf_center import RfCenterError

        if isinstance(err, RfCenterError):
            status, code = _REASONS.get(err.reason, (403, "refused"))
            return error_response(RequestError(status, code, reason=err.reason))
        if isinstance(err, AuthorizationError):
            # Any Core refusal is a 403 with a fixed body.
            return error_response(RequestError(403, "authorization_denied"))
        # Only the type: the message may carry router data.
        _LOGGER.warning("WiFi RF route %s failed: %s", self.name, type(err).__name__)
        _LOGGER.debug("WiFi RF route error", exc_info=err)
        return error_response(RequestError(500, "internal"))

    async def handle(
        self, center: Any, request: web.Request, context: dict[str, Any]
    ) -> Any:
        """The route itself (after the access checks)."""
        raise NotImplementedError


class _PlainView(_RfView):
    """A route without query parameters."""

    builder: Any = None

    async def handle(self, center, request, context):  # type: ignore[override]
        _query(request, frozenset())
        return type(self).builder(center)


class RfOverviewView(_PlainView):
    """Fleet status, coverage, health, counts."""

    url = f"{BASE_URL}/overview"
    name = f"{VIEW_NAME_PREFIX}overview"
    builder = staticmethod(overview)


class RfRadiosView(_PlainView):
    """Every radio with metrics, capabilities, health and load."""

    url = f"{BASE_URL}/radios"
    name = f"{VIEW_NAME_PREFIX}radios"
    builder = staticmethod(radios)


class RfChannelMapView(_PlainView):
    """Channels per band and the conflicts."""

    url = f"{BASE_URL}/channel_map"
    name = f"{VIEW_NAME_PREFIX}channel_map"
    builder = staticmethod(channel_map)


class RfRecommendationsView(_PlainView):
    """Recommendations, load and distribution."""

    url = f"{BASE_URL}/recommendations"
    name = f"{VIEW_NAME_PREFIX}recommendations"
    builder = staticmethod(recommendations)


class RfTimelineView(_RfView):
    """History: ``window`` (required, fixed list), ``radio_id``, ``router_id``,
    ``series`` (optional)."""

    url = f"{BASE_URL}/timeline"
    name = f"{VIEW_NAME_PREFIX}timeline"

    async def handle(self, center, request, context):  # type: ignore[override]
        query = _query(
            request, frozenset({"window", "radio_id", "router_id", "series"})
        )
        window = query.get("window")
        if window is None:
            raise _bad("window", "missing")
        if window not in TIMELINE_WINDOWS:
            raise _bad("window", "unknown")
        radio_id = query.get("radio_id")
        if radio_id is not None:
            try:
                require_radio_id(radio_id)
            except ValueError:
                raise _bad("radio_id") from None
        router_id = query.get("router_id")
        if router_id is not None:
            try:
                require_router_id(router_id)
            except ValueError:
                raise _bad("router_id") from None
        series = query.get("series")
        if series is not None and series not in SERIES:
            raise _bad("series", "unknown")
        return timeline(
            center, window=window, radio_id=radio_id, router_id=router_id, series=series
        )


class RfRoamingView(_RfView):
    """Roam counts; the client history for an approved admin session."""

    url = f"{BASE_URL}/roaming"
    name = f"{VIEW_NAME_PREFIX}roaming"

    async def handle(self, center, request, context):  # type: ignore[override]
        _query(request, frozenset())
        if center.status != "ready":  # off / not ready: no history is kept
            return roaming(center, events=None, restricted=None)
        if not context["admin"] or context["user_id"] is None:
            return roaming(center, events=None, restricted=RESTRICTED_ADMIN_ONLY)
        actor = await async_actor_from_context(
            context["hass"], Context(user_id=context["user_id"])
        )
        await center.async_authorize_sensitive(
            ROAM_ACTION, actor, _session_id(request, context["user_id"])
        )
        return roaming(center, events=list(center.roams), restricted=None)


RF_VIEWS: tuple[type[HomeAssistantView], ...] = (
    RfOverviewView,
    RfRadiosView,
    RfChannelMapView,
    RfTimelineView,
    RfRoamingView,
    RfRecommendationsView,
)


@callback
def async_register_rf_views(hass: HomeAssistant) -> None:
    """Bind the routes once per HA run (aiohttp cannot unbind them)."""
    bound: set[str] = hass.data.setdefault(DATA_WIFI_RF_VIEWS_BOUND, set())
    for view_class in RF_VIEWS:
        if view_class.name in bound:
            continue
        hass.http.register_view(view_class())
        bound.add(view_class.name)
