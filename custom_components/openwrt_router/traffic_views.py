"""HTTP routes of Traffic Analytics (Phase J, plan 2026-11-20 §7, read only).

Base ``/api/openwrt_topology/traffic``: ``overview``, ``points``,
``series``, ``talkers``, ``clients``, ``vlans``, ``capacity``,
``anomalies``, ``recommendations``, ``flows``, ``evidence/{evidence_ref}``
and ``settings``. GET only: there is no write route in this phase (the
switch and the collector intake follow in Phase K).

Order of the checks (the plumbing of ``rf_views`` / ``security_views``):

1. a logged-in HA user (``requires_auth``: 401 from HA itself);
2. administrators, and other users only while an entry opens the topology
   panel to all users (else 403); ``flows`` and ``settings`` are for
   administrators only -- all before the traffic switch is looked at and
   before any body is read;
3. 410 after the last entry unloaded, 503 while no engine is loaded;
4. the body: a GET takes none (``security_views.read_body`` with no known
   key: > 4 KiB 413, nested or any key 400);
5. the query: known keys only, each once, windows / scopes / directions /
   states from the fixed lists, ids by their fixed patterns, limits as
   whole numbers in range (400 otherwise); nothing is ever used as a path;
6. traffic off: 200 with ``status: off`` -- the builders then read neither
   the history, nor the store, nor any rate (``traffic_output.off_answer``).

Errors carry a fixed message, a code and at most a field name and a reason
token; a failing builder is a 500 ``internal`` and only the exception type
is logged. No route talks to a router.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any

from aiohttp import web
from homeassistant.components.http import KEY_HASS_USER, HomeAssistantView
from homeassistant.core import HomeAssistant, callback

from . import traffic_output as out
from .const import DATA_TRAFFIC_VIEWS_BOUND
from .security_views import NO_STORE, RequestError, error_response, read_body
from .topology_panel import _PANEL_VIEW_DISABLED_KEY, _panel_open_to_all
from .traffic_correlate import valid_evidence_ref
from .traffic_model import valid_client_ref, valid_point_id, valid_router_id

try:
    from homeassistant.helpers.http import KEY_HASS
except ImportError:  # pragma: no cover - older HA cores keyed the app by str
    KEY_HASS = "hass"  # type: ignore[assignment]

_LOGGER = logging.getLogger(__name__)

BASE_URL = "/api/openwrt_topology/traffic"
VIEW_NAME_PREFIX = "api:openwrt_topology:traffic:"
QUERY_VALUE_MAX = 64
_INT = re.compile(r"[0-9]{1,4}")
FLOW_PROTOS = frozenset({"tcp", "udp", "icmp", "other"})
DEFAULT_TALKER_LIMIT = 10
DEFAULT_ANOMALY_LIMIT = 50
MAX_FLOW_LIMIT = 200


def _bad(field: str, reason: str = "invalid") -> RequestError:
    return RequestError(400, "invalid_request", field=field, reason=reason)


def _query(request: web.Request, allowed: frozenset[str]) -> dict[str, str]:
    """Known keys only, each once, short values."""
    found: dict[str, str] = {}
    for key, value in request.query.items():
        if key not in allowed:
            raise _bad("query", "unknown_key")
        if key in found:
            raise _bad(key, "repeated")
        if len(value) > QUERY_VALUE_MAX:
            raise _bad(key, "too_long")
        found[key] = value
    return found


def _choice(
    query: Mapping[str, str], key: str, allowed: Any, default: str | None = None
) -> str | None:
    value = query.get(key, default)
    if value is not None and value not in allowed:
        raise _bad(key, "unknown")
    return value


def _router_id(query: Mapping[str, str]) -> str | None:
    value = query.get("router_id")
    if value is not None and not valid_router_id(value):
        raise _bad("router_id")
    return value


def _limit(query: Mapping[str, str], default: int, maximum: int) -> int:
    raw = query.get("limit")
    if raw is None:
        return default
    if not _INT.fullmatch(raw) or not 1 <= int(raw) <= maximum:
        raise _bad("limit", "out_of_range")
    return int(raw)


class _TrafficView(HomeAssistantView):
    """Access checks, error mapping and output of every traffic route."""

    requires_auth = True
    admin_only = False

    async def get(self, request: web.Request, **match: str) -> web.StreamResponse:
        """Read."""
        try:
            hass: HomeAssistant = request.app[KEY_HASS]
            user = request.get(KEY_HASS_USER)
            admin = user is not None and getattr(user, "is_admin", False) is True
            if user is None or (
                not admin and (self.admin_only or not _panel_open_to_all(hass))
            ):
                raise RequestError(403, "authorization_denied")
            if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
                raise RequestError(410, "integration_not_loaded")
            from .traffic_engine import async_get_traffic_engine

            engine = async_get_traffic_engine(hass)
            if engine is None or not engine.loaded:
                raise RequestError(503, "not_running")
            await read_body(request, {})  # a GET takes no body
            body = self.handle(engine, request, match)
        except RequestError as err:
            return error_response(err)
        except Exception as err:
            # Only the type: the message may carry router data.
            _LOGGER.warning(
                "Traffic route %s failed: %s", self.name, type(err).__name__
            )
            _LOGGER.debug("Traffic route error", exc_info=err)
            return error_response(RequestError(500, "internal"))
        return self.json(body, headers=dict(NO_STORE))

    def handle(
        self, engine: Any, request: web.Request, match: Mapping[str, str]
    ) -> Any:
        """The route itself (after the access checks)."""
        raise NotImplementedError


class TrafficOverviewView(_TrafficView):
    """Traffic overview: WAN, coverage, talkers, anomalies, VLANs, sources."""

    url = f"{BASE_URL}/overview"
    name = f"{VIEW_NAME_PREFIX}overview"

    def handle(self, engine, request, match):  # type: ignore[override]
        _query(request, frozenset())
        return out.overview(engine)


class TrafficPointsView(_TrafficView):
    """Measuring points: ``router_id``, ``scope`` (optional)."""

    url = f"{BASE_URL}/points"
    name = f"{VIEW_NAME_PREFIX}points"

    def handle(self, engine, request, match):  # type: ignore[override]
        query = _query(request, frozenset({"router_id", "scope"}))
        return out.points(
            engine,
            router_id=_router_id(query),
            scope=_choice(query, "scope", out.TALKER_SCOPES),
        )


class TrafficSeriesView(_TrafficView):
    """History of one point: ``point_id`` and ``window`` (both required)."""

    url = f"{BASE_URL}/series"
    name = f"{VIEW_NAME_PREFIX}series"

    def handle(self, engine, request, match):  # type: ignore[override]
        query = _query(request, frozenset({"point_id", "window"}))
        point_id = query.get("point_id")
        if point_id is None:
            raise _bad("point_id", "missing")
        if not valid_point_id(point_id):
            raise _bad("point_id")
        window = query.get("window")
        if window is None:
            raise _bad("window", "missing")
        _choice(query, "window", out.SERIES_WINDOWS)
        return out.series(engine, point_id=point_id, window=window)


class TrafficTalkersView(_TrafficView):
    """Top talkers: ``window``, ``scope``, ``direction``, ``limit``, ``kind``."""

    url = f"{BASE_URL}/talkers"
    name = f"{VIEW_NAME_PREFIX}talkers"

    def handle(self, engine, request, match):  # type: ignore[override]
        query = _query(
            request, frozenset({"window", "scope", "direction", "limit", "kind"})
        )
        return out.talkers(
            engine,
            window=_choice(query, "window", out.TALKER_WINDOWS, "1h"),
            scope=_choice(query, "scope", out.TALKER_SCOPES, "client"),
            direction=_choice(query, "direction", out.TALKER_DIRECTIONS, "download"),
            limit=_limit(query, DEFAULT_TALKER_LIMIT, out.MAX_TALKERS),
            kind=_choice(query, "kind", out.TALKER_KINDS, "window"),
        )


class TrafficClientsView(_TrafficView):
    """Client traffic (WLAN station counters at the AP, pseudonyms only)."""

    url = f"{BASE_URL}/clients"
    name = f"{VIEW_NAME_PREFIX}clients"

    def handle(self, engine, request, match):  # type: ignore[override]
        _query(request, frozenset())
        return out.clients(engine)


class TrafficVlansView(_TrafficView):
    """Measured and configured VLANs: ``router_id`` (optional)."""

    url = f"{BASE_URL}/vlans"
    name = f"{VIEW_NAME_PREFIX}vlans"

    def handle(self, engine, request, match):  # type: ignore[override]
        query = _query(request, frozenset({"router_id"}))
        return out.vlans(engine, router_id=_router_id(query))


class TrafficCapacityView(_TrafficView):
    """Capacity rows: ``router_id`` (optional)."""

    url = f"{BASE_URL}/capacity"
    name = f"{VIEW_NAME_PREFIX}capacity"

    def handle(self, engine, request, match):  # type: ignore[override]
        query = _query(request, frozenset({"router_id"}))
        return out.capacity(engine, router_id=_router_id(query))


class TrafficAnomaliesView(_TrafficView):
    """Anomaly candidates: ``state``, ``limit`` (optional)."""

    url = f"{BASE_URL}/anomalies"
    name = f"{VIEW_NAME_PREFIX}anomalies"

    def handle(self, engine, request, match):  # type: ignore[override]
        query = _query(request, frozenset({"state", "limit"}))
        return out.anomalies(
            engine,
            state=_choice(query, "state", out.ANOMALY_STATES),
            limit=_limit(query, DEFAULT_ANOMALY_LIMIT, out.MAX_ANOMALIES),
        )


class TrafficRecommendationsView(_TrafficView):
    """Possible bottlenecks (Phase H correlation): ``router_id`` (optional)."""

    url = f"{BASE_URL}/recommendations"
    name = f"{VIEW_NAME_PREFIX}recommendations"

    def handle(self, engine, request, match):  # type: ignore[override]
        query = _query(request, frozenset({"router_id"}))
        return out.recommendations(engine, router_id=_router_id(query))


class TrafficFlowsView(_TrafficView):
    """Flow explorer (administrators only); filters are checked, not used yet."""

    url = f"{BASE_URL}/flows"
    name = f"{VIEW_NAME_PREFIX}flows"
    admin_only = True

    def handle(self, engine, request, match):  # type: ignore[override]
        query = _query(
            request, frozenset({"router_id", "client_ref", "proto", "limit"})
        )
        _router_id(query)
        client_ref = query.get("client_ref")
        if client_ref is not None and not valid_client_ref(client_ref):
            raise _bad("client_ref")
        _choice(query, "proto", FLOW_PROTOS)
        _limit(query, MAX_FLOW_LIMIT, MAX_FLOW_LIMIT)
        return out.flows(engine)


class TrafficEvidenceView(_TrafficView):
    """The bucket excerpt behind an ``evr_<16 hex>`` reference."""

    url = BASE_URL + "/evidence/{evidence_ref}"
    name = f"{VIEW_NAME_PREFIX}evidence"

    def handle(self, engine, request, match):  # type: ignore[override]
        _query(request, frozenset())
        ref = match.get("evidence_ref")
        if not valid_evidence_ref(ref):
            raise _bad("evidence_ref")
        found = out.evidence(engine, evidence_ref=ref)
        if found is None:
            raise RequestError(404, "not_found", reason="unknown_evidence")
        return found


class TrafficSettingsView(_TrafficView):
    """The module settings (administrators only, read only in Phase J)."""

    url = f"{BASE_URL}/settings"
    name = f"{VIEW_NAME_PREFIX}settings"
    admin_only = True

    def handle(self, engine, request, match):  # type: ignore[override]
        _query(request, frozenset())
        return out.settings(engine)


TRAFFIC_VIEWS: tuple[type[HomeAssistantView], ...] = (
    TrafficOverviewView,
    TrafficPointsView,
    TrafficSeriesView,
    TrafficTalkersView,
    TrafficClientsView,
    TrafficVlansView,
    TrafficCapacityView,
    TrafficAnomaliesView,
    TrafficRecommendationsView,
    TrafficFlowsView,
    TrafficEvidenceView,
    TrafficSettingsView,
)


@callback
def async_register_traffic_views(hass: HomeAssistant) -> None:
    """Bind the routes once per HA run (aiohttp cannot unbind them)."""
    bound: set[str] = hass.data.setdefault(DATA_TRAFFIC_VIEWS_BOUND, set())
    for view_class in TRAFFIC_VIEWS:
        if view_class.name in bound:
            continue
        hass.http.register_view(view_class())
        bound.add(view_class.name)


__all__ = ["BASE_URL", "TRAFFIC_VIEWS", "async_register_traffic_views"]
