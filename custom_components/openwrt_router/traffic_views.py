"""HTTP routes of Traffic Analytics (Phases J and K, plan 2026-11-20 §7 and §8).

Base ``/api/openwrt_topology/traffic``: ``overview``, ``points``,
``series``, ``talkers``, ``clients``, ``vlans``, ``capacity``,
``anomalies``, ``recommendations``, ``flows``, ``evidence/{evidence_ref}``
and ``settings`` (GET). Phase K adds two writing routes:

* ``POST settings`` (administrators only, like the Security Center's
  settings route): the fleet settings ``collector`` and ``client_sensors``
  only while the module runs (409 ``disabled`` otherwise, so nothing is
  read from or written to the store while off). The switch itself is the
  router option ``traffic_enabled`` (options flow), not this route.
* ``POST collector/ingest``: the external collector (``traffic_collector``),
  only for the one configured non-admin user, only over HTTPS.

Phase L adds ``GET collector/users`` (administrators only) for the settings
form of the panel: the users that may be chosen as the collector (active,
not an administrator, not system generated), each with its display name and
a ``usr_<16 hex>`` reference that ``POST settings`` takes as
``collector.user_ref``. The reference is keyed by a random key of this HA
run, so no HA user id ever leaves a route.

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

import hashlib
import hmac
import logging
import re
import secrets
from collections.abc import Mapping
from typing import Any

from aiohttp import web
from homeassistant.components.http import KEY_HASS_USER, HomeAssistantView
from homeassistant.core import HomeAssistant, callback

from . import traffic_output as out
from .const import DATA_TRAFFIC_VIEWS_BOUND
from .security_views import NO_STORE, RequestError, read_body
from .topology_panel import _PANEL_VIEW_DISABLED_KEY, _panel_open_to_all
from .traffic_collector import (
    BODY_MAX_BYTES as INGEST_MAX_BYTES,
)
from .traffic_collector import (
    INGEST_PATH,
    REJECT_AUTH,
    REJECT_BODY_TOO_LARGE,
    REJECT_COLLECTOR_OFF,
    REJECT_TRANSPORT,
    CollectorRejected,
    rejected_body,
)
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
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_USER_ID = re.compile(r"[0-9a-f]{32}")
_USER_REF = re.compile(r"usr_[0-9a-f]{16}")
CLIENT_SENSORS_MAX = 20
COLLECTOR_USERS_PATH = "/collector/users"
COLLECTOR_USERS_MAX = 100
USER_NAME_MAX = 64
# hass.data key of the per-run key behind the ``usr_`` references.
_USER_REF_KEY = "openwrt_router_traffic_user_ref_key"

_MESSAGES: Mapping[str, str] = {
    "invalid_request": "The request is not valid",
    "body_too_large": "The request body is too large",
    "authorization_denied": "This is not allowed for this user",
    "insecure_transport": "This needs HTTPS",
    "integration_not_loaded": "OpenWrt Router integration not loaded",
    "not_running": "Traffic analytics is not running",
    "disabled": "Traffic analytics is off",
    "not_found": "Not found",
    "rate_limited": "Too many requests",
    "store_full": "The flow store is full",
    "internal": "The request failed",
}


def error_response(
    err: RequestError, headers: Mapping[str, str] | None = None
) -> web.Response:
    """The fixed error body of a traffic route (``Cache-Control: no-store``)."""
    details: dict[str, str] = {}
    for key, value in (("field", err.field), ("reason", err.reason)):
        if isinstance(value, str) and _TOKEN.fullmatch(value):
            details[key] = value
    body = {
        "message": _MESSAGES.get(err.code, _MESSAGES["internal"]),
        "code": err.code,
        "details": details,
    }
    return HomeAssistantView.json(
        body, err.status, headers={**NO_STORE, **(headers or {})}
    )


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
        return await self._respond(request, match, write=False)

    async def _respond(
        self, request: web.Request, match: Mapping[str, str], *, write: bool
    ) -> web.StreamResponse:
        from .traffic_engine import TrafficSettingsError

        try:
            hass: HomeAssistant = request.app[KEY_HASS]
            user = request.get(KEY_HASS_USER)
            admin = user is not None and getattr(user, "is_admin", False) is True
            if user is None or (
                not admin and (write or self.admin_only or not _panel_open_to_all(hass))
            ):
                raise RequestError(403, "authorization_denied")
            if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
                raise RequestError(410, "integration_not_loaded")
            from .traffic_engine import async_get_traffic_engine

            engine = async_get_traffic_engine(hass)
            if engine is None or not engine.loaded:
                raise RequestError(503, "not_running")
            if write:
                body = await self.handle_write(hass, engine, request)
            else:
                await read_body(request, {})  # a GET takes no body
                body = await self.handle_async(hass, engine, request, match)
        except RequestError as err:
            return error_response(err)
        except TrafficSettingsError as err:
            if err.reason == "disabled":
                return error_response(RequestError(409, "disabled"))
            return error_response(_bad("settings", err.reason))
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

    async def handle_async(
        self,
        hass: HomeAssistant,
        engine: Any,
        request: web.Request,
        match: Mapping[str, str],
    ) -> Any:
        """A reading route that awaits (default: the plain ``handle``)."""
        return self.handle(engine, request, match)

    async def handle_write(
        self, hass: HomeAssistant, engine: Any, request: web.Request
    ) -> Any:
        """A writing route (administrators only, after the access checks)."""
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
        router_id = _router_id(query)
        client_ref = query.get("client_ref")
        if client_ref is not None and not valid_client_ref(client_ref):
            raise _bad("client_ref")
        return out.flows(
            engine,
            router_id=router_id,
            client_ref=client_ref,
            proto=_choice(query, "proto", FLOW_PROTOS),
            limit=_limit(query, MAX_FLOW_LIMIT, MAX_FLOW_LIMIT),
        )


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


def _collector_field(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - {"enabled", "user_id", "user_ref"}:
        raise _bad("collector")
    if "enabled" in value and not isinstance(value["enabled"], bool):
        raise _bad("collector", "enabled")
    if "user_id" in value and "user_ref" in value:
        raise _bad("collector", "user_id_and_ref")
    user_id = value.get("user_id")
    if user_id is not None and (
        not isinstance(user_id, str) or not _USER_ID.fullmatch(user_id)
    ):
        raise _bad("collector", "user_id")
    user_ref = value.get("user_ref")
    if "user_ref" in value and (
        not isinstance(user_ref, str) or not _USER_REF.fullmatch(user_ref)
    ):
        raise _bad("collector", "user_ref")
    return dict(value)


def user_ref(hass: HomeAssistant, user_id: str) -> str:
    """``usr_<16 hex>`` for a HA user id, keyed by a random key of this run."""
    key = hass.data.get(_USER_REF_KEY)
    if not isinstance(key, bytes):
        key = hass.data[_USER_REF_KEY] = secrets.token_bytes(32)
    digest = hmac.new(
        key, b"traffic_collector_user\x00" + user_id.encode(), hashlib.sha256
    ).hexdigest()
    return "usr_" + digest[:16]


def _collector_candidate(user: Any) -> bool:
    return (
        isinstance(getattr(user, "id", None), str)
        and _USER_ID.fullmatch(user.id) is not None
        and getattr(user, "is_active", False) is True
        and getattr(user, "is_admin", True) is False
        and getattr(user, "system_generated", True) is False
    )


async def _collector_candidates(hass: HomeAssistant) -> list[Any]:
    """Users that may be the collector, by display name (at most 100)."""
    try:
        found = await hass.auth.async_get_users()
    except Exception:  # noqa: BLE001 - unreadable users: nobody to choose
        return []
    users = [u for u in found or () if _collector_candidate(u)]
    users.sort(key=lambda u: (str(getattr(u, "name", "") or "").casefold(), u.id))
    return users[:COLLECTOR_USERS_MAX]


def _display_name(user: Any) -> str:
    name = getattr(user, "name", None)
    if not isinstance(name, str) or not name.strip():
        return ""
    return name.strip()[:USER_NAME_MAX]


async def _resolve_user_ref(hass: HomeAssistant, ref: str) -> str:
    """The user id behind a ``usr_`` reference of the user list (400 if none)."""
    for user in await _collector_candidates(hass):
        if hmac.compare_digest(user_ref(hass, user.id), ref):
            return str(user.id)
    raise _bad("collector", "user_unknown")


def _client_sensors_field(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > CLIENT_SENSORS_MAX:
        raise _bad("client_sensors")
    if not all(valid_client_ref(v) for v in value):
        raise _bad("client_sensors", "client_ref")
    return list(value)


SETTINGS_FIELDS: Mapping[str, Any] = {
    "collector": _collector_field,
    "client_sensors": _client_sensors_field,
}


async def _check_collector_user(hass: HomeAssistant, user_id: str) -> None:
    """The collector user must exist, be active, and not be an administrator."""
    try:
        user = await hass.auth.async_get_user(user_id)
    except Exception:  # noqa: BLE001 - an unreadable user is an unknown one
        user = None
    if user is None:
        raise _bad("collector", "user_unknown")
    if getattr(user, "is_active", True) is not True:
        raise _bad("collector", "user_inactive")
    if getattr(user, "system_generated", False) is True:
        raise _bad("collector", "user_system")
    if getattr(user, "is_admin", False) is True:
        raise _bad("collector", "user_is_admin")


class TrafficSettingsView(_TrafficView):
    """GET: the settings; POST: the fleet settings (administrators only).

    Body ``{"collector": {"enabled": bool, "user_id": "<32 hex>"|null},
    "client_sensors": ["cli_..."]}`` (each key optional, at most 4 KiB,
    depth 3, unknown keys 400). Instead of ``user_id`` the collector may
    name ``user_ref`` (``usr_<16 hex>`` from ``GET collector/users``).
    """

    url = f"{BASE_URL}/settings"
    name = f"{VIEW_NAME_PREFIX}settings"
    admin_only = True

    def handle(self, engine, request, match):  # type: ignore[override]
        _query(request, frozenset())
        return out.settings(engine)

    async def post(self, request: web.Request, **match: str) -> web.StreamResponse:
        """Change the fleet settings (administrators only)."""
        return await self._respond(request, match, write=True)

    async def handle_write(self, hass, engine, request):  # type: ignore[override]
        _query(request, frozenset())
        if not engine.active:
            raise RequestError(409, "disabled")
        update = await read_body(request, SETTINGS_FIELDS)
        if not update:
            raise _bad("body", "empty")
        collector = update.get("collector")
        if isinstance(collector, dict) and "user_ref" in collector:
            collector["user_id"] = await _resolve_user_ref(
                hass, collector.pop("user_ref")
            )
        user_id = (update.get("collector") or {}).get("user_id")
        if user_id is not None:
            await _check_collector_user(hass, user_id)
        await engine.async_update_settings(update)
        return out.settings(engine)


class TrafficCollectorUsersView(_TrafficView):
    """Users an administrator may choose as the collector (no user id)."""

    url = BASE_URL + COLLECTOR_USERS_PATH
    name = f"{VIEW_NAME_PREFIX}collector_users"
    admin_only = True

    async def handle_async(self, hass, engine, request, match):  # type: ignore[override]
        _query(request, frozenset())
        if out.is_off(engine):
            return out.off_answer(engine, users=[])
        configured = (engine.settings.get("collector") or {}).get("user_id")
        users = await _collector_candidates(hass)
        rows = [
            {
                "user_ref": user_ref(hass, u.id),
                "name": _display_name(u),
                "selected": u.id == configured,
            }
            for u in users
        ]
        return {
            **out.off_answer(engine),  # the status envelope (v, status, reasons)
            "users": rows,
            "selected_listed": any(r["selected"] for r in rows),
            "user_configured": configured is not None,
        }


class TrafficCollectorIngestView(HomeAssistantView):
    """The push intake of the external collector (see ``traffic_collector``).

    Order: a user (``requires_auth``) -> integration loaded -> module on
    (409 ``disabled``, like a switched-off module) -> collector on and this
    is its non-admin user (403) -> HTTPS (403 ``insecure_transport``) ->
    rate (429) -> body size (413) -> schema and records (400, all or
    nothing) -> store space (503). The body is read only after all checks.
    """

    requires_auth = True
    url = BASE_URL + INGEST_PATH
    name = f"{VIEW_NAME_PREFIX}collector_ingest"

    async def post(self, request: web.Request) -> web.StreamResponse:
        """Take one call of the collector."""
        engine: Any = None
        try:
            hass: HomeAssistant = request.app[KEY_HASS]
            user = request.get(KEY_HASS_USER)
            if user is None:
                raise RequestError(403, "authorization_denied")
            if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
                raise RequestError(410, "integration_not_loaded")
            from .traffic_engine import async_get_traffic_engine

            engine = async_get_traffic_engine(hass)
            if engine is None or not engine.loaded:
                raise RequestError(503, "not_running")
            if not engine.active:
                raise RequestError(409, "disabled")
            wall = engine.wall()
            if not engine.collector_enabled:
                engine.collector.auth_refused(
                    REJECT_COLLECTOR_OFF, wall, user_id=getattr(user, "id", None)
                )
                raise RequestError(403, "authorization_denied")
            if (
                not engine.is_collector_user(getattr(user, "id", None))
                or getattr(user, "is_admin", False) is not False
                or getattr(user, "is_active", True) is not True
            ):
                engine.collector.auth_refused(
                    REJECT_AUTH, wall, user_id=getattr(user, "id", None)
                )
                raise RequestError(403, "authorization_denied")
            if not request.secure:
                engine.collector.auth_refused(
                    REJECT_TRANSPORT, wall, user_id=getattr(user, "id", None)
                )
                raise RequestError(403, "insecure_transport")
            engine.collector.check_rate(engine.clock())
            raw = await _read_limited(request, INGEST_MAX_BYTES)
            if raw is None:
                engine.collector.refused(REJECT_BODY_TOO_LARGE)
                raise RequestError(413, "body_too_large")
            answer = engine.ingest_collector(raw, user_id=getattr(user, "id", None))
        except RequestError as err:
            return error_response(err)
        except CollectorRejected as err:
            headers = {}
            if err.retry_after is not None:
                headers["Retry-After"] = str(err.retry_after)
            return self.json(
                rejected_body(err), err.status, headers={**NO_STORE, **headers}
            )
        except Exception as err:
            # Only the type: the message may carry collector data.
            _LOGGER.warning("Traffic collector intake failed: %s", type(err).__name__)
            _LOGGER.debug("Traffic collector intake error", exc_info=err)
            return error_response(RequestError(500, "internal"))
        return self.json(answer, headers=dict(NO_STORE))


async def _read_limited(request: web.Request, limit: int) -> bytes | None:
    """The body, or None as soon as it is larger than ``limit``."""
    length = request.content_length
    if length is not None and length > limit:
        return None
    chunks: list[bytes] = []
    size = 0
    while chunk := await request.content.read(min(65536, limit + 1 - size)):
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


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
    TrafficCollectorUsersView,
    TrafficCollectorIngestView,
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
