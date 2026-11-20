"""HTTP routes of the Security Center (release 1.46.0 part 2).

Base ``/api/openwrt_topology/security``; every route needs a logged-in HA
user (``requires_auth``: 401 from HA itself). Pattern of ``config_views`` and
the intelligence routes of ``topology_panel``:

* Reading (overview, incident details, detection availability, settings):
  administrators, and every other user only while an entry opens the
  topology panel to all users (``topology_panel_all_users``; else 403).
  Non-admins get pseudonyms (or the mask) instead of MAC, IP and host name,
  and the subnet map only as a count.
* Writing (settings, confirm/name a device, incident status): HA
  administrators only (403 before the body is read); the center then asks
  the core guard (admin users only, audited). The device routes take the
  MAC from the JSON body, never from the path: a path ends up in the access
  logs of proxies (review 2, N4).
* 410 after the last entry unloaded (``_PANEL_VIEW_DISABLED_KEY``), 503
  while no center runs.

Input is checked strictly: known query keys and body keys only, types,
lengths and ranges, at most 4 KiB of JSON, nesting deeper than the parser
follows or deeper than the settings need is a 400. Errors carry a fixed
message, a code and at most a field name and a reason token, never an
exception text or a trace (those stay in the debug log). None of the routes
talks to a router.
"""

from __future__ import annotations

import json
import logging
import math
import re
from collections.abc import Callable, Mapping
from typing import Any

from aiohttp import web
from homeassistant.components.http import KEY_HASS_USER, HomeAssistantView
from homeassistant.core import Context, HomeAssistant, callback

from .const import DATA_SECURITY_VIEWS_BOUND
from .core_models import async_actor_from_context
from .security_model import LogPath, SecCategory, normalize_mac, valid_router_id
from .topology_panel import _PANEL_VIEW_DISABLED_KEY, _panel_open_to_all

try:
    from homeassistant.helpers.http import KEY_HASS
except ImportError:  # pragma: no cover - older HA cores keyed the app by str
    KEY_HASS = "hass"  # type: ignore[assignment]

_LOGGER = logging.getLogger(__name__)

BASE_URL = "/api/openwrt_topology/security"
VIEW_NAME_PREFIX = "api:openwrt_topology:security:"
BODY_MAX_BYTES = 4096
# Deepest JSON a settings body needs: {"thresholds": {"x": 1}} is depth 2.
BODY_MAX_DEPTH = 3
LIST_LIMIT_DEFAULT = 200
LIST_LIMIT_MAX = 500
NAME_MAX = 64
ZONES_MAX = 64
THRESHOLDS_MAX = 32
NO_STORE = {"Cache-Control": "no-store"}
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_INCIDENT_ID = re.compile(r"sec_[A-Za-z0-9_-]{1,60}")
_CLIENT_REF = re.compile(r"cli_[A-Za-z0-9_-]{1,60}")
_EPOCH_MAX = 4_102_444_800.0  # 2100-01-01
_SEVERITIES = frozenset({"info", "warning", "critical"})
_STATUSES = frozenset({"open", "resolved", "confirmed"})
_LOG_PATHS = frozenset(p.value for p in LogPath)

_MESSAGES: Mapping[str, str] = {
    "invalid_request": "The request is not valid",
    "body_too_large": "The request body is too large",
    "authorization_denied": "This is available to administrators only",
    "integration_not_loaded": "OpenWrt Router integration not loaded",
    "not_running": "The Security Center is not running",
    "unknown_incident": "Unknown incident",
    "unknown_device": "Unknown device",
    "disabled": "The Security Center is off",
    "no_core": "The enterprise core is not running",
    "refused": "The action was refused",
    "internal": "The request failed",
}

# SecurityCenterError.reason -> (status, code)
_REASONS: Mapping[str, tuple[int, str]] = {
    "invalid_settings": (400, "invalid_request"),
    "invalid_mac": (400, "invalid_request"),
    "invalid_status": (400, "invalid_request"),
    "unknown_device": (404, "unknown_device"),
    "unknown_incident": (404, "unknown_incident"),
    "disabled": (409, "disabled"),
    "no_core": (503, "no_core"),
    "not_admin": (403, "authorization_denied"),
    "actor_required": (403, "authorization_denied"),
}


class RequestError(Exception):
    """A rejected request (fixed message per code)."""

    def __init__(
        self,
        status: int,
        code: str,
        *,
        field: str | None = None,
        reason: str | None = None,
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.field = field
        self.reason = reason


def _bad(field: str, reason: str = "invalid") -> RequestError:
    return RequestError(400, "invalid_request", field=field, reason=reason)


def error_response(err: RequestError) -> web.Response:
    """The masked error body (``Cache-Control: no-store``)."""
    details: dict[str, str] = {}
    for key, value in (("field", err.field), ("reason", err.reason)):
        if isinstance(value, str) and _TOKEN.fullmatch(value):
            details[key] = value
    body = {
        "message": _MESSAGES.get(err.code, _MESSAGES["internal"]),
        "code": err.code,
        "details": details,
    }
    return HomeAssistantView.json(body, err.status, headers=dict(NO_STORE))


def center_error(err: Exception) -> RequestError:
    """A ``SecurityCenterError`` as a request error (reason token only)."""
    reason = getattr(err, "reason", None)
    reason = reason if isinstance(reason, str) else "refused"
    status, code = _REASONS.get(reason, (403, "refused"))
    return RequestError(status, code, reason=reason)


# --- validation -------------------------------------------------------------------


def _depth(value: Any, limit: int, level: int = 0) -> bool:
    """True if ``value`` nests no deeper than ``limit`` (iterative bound)."""
    if level > limit:
        return False
    if isinstance(value, dict):
        return all(_depth(v, limit, level + 1) for v in value.values())
    if isinstance(value, list):
        return all(_depth(v, limit, level + 1) for v in value)
    return True


async def read_body(
    request: web.Request,
    fields: Mapping[str, Callable[[Any], Any]],
    *,
    required: tuple[str, ...] = (),
) -> dict[str, Any]:
    """A JSON object of at most 4 KiB with known keys only, each checked."""
    length = request.content_length
    if length is not None and length > BODY_MAX_BYTES:
        raise RequestError(413, "body_too_large")
    chunks: list[bytes] = []
    size = 0
    while chunk := await request.content.read(BODY_MAX_BYTES + 1 - size):
        size += len(chunk)
        if size > BODY_MAX_BYTES:  # also a chunked body without a length
            raise RequestError(413, "body_too_large")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw.strip():
        data: Any = {}
    else:
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise _bad("body", "not_json") from None
        except RecursionError:
            # "[" * 4000 fits in 4 KiB: a bad body, not a server error
            raise _bad("body", "invalid_body") from None
    if not isinstance(data, dict):
        raise _bad("body", "not_an_object")
    if not _depth(data, BODY_MAX_DEPTH):
        raise _bad("body", "too_deep")
    if any(key not in fields for key in data):
        raise _bad("body", "unknown_key")
    for key in required:
        if key not in data:
            raise _bad(key, "missing")
    return {key: fields[key](value) for key, value in data.items()}


def _bool(field: str) -> Callable[[Any], bool]:
    def check(value: Any) -> bool:
        if not isinstance(value, bool):
            raise _bad(field)
        return value

    return check


def _choice(field: str, choices: frozenset[str]) -> Callable[[Any], str]:
    def check(value: Any) -> str:
        if not isinstance(value, str) or value not in choices:
            raise _bad(field)
        return value

    return check


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _bad("syslog_port")
    if not 1024 <= value <= 65535:
        raise _bad("syslog_port", "out_of_range")
    return value


def _name(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _bad("name")
    text = value.strip()
    if (
        not text
        or len(text) > NAME_MAX
        or any(ord(c) < 32 or ord(c) == 127 for c in text)
    ):
        raise _bad("name")
    return text


def _thresholds(value: Any) -> dict[str, float]:
    if not isinstance(value, dict) or len(value) > THRESHOLDS_MAX:
        raise _bad("thresholds")
    out: dict[str, float] = {}
    for key, number in value.items():
        if not isinstance(key, str) or not _TOKEN.fullmatch(key):
            raise _bad("thresholds", "key")
        if isinstance(number, bool) or not isinstance(number, int | float):
            raise _bad("thresholds", "value")
        if not math.isfinite(number) or not 0 < number <= 1_000_000:
            raise _bad("thresholds", "out_of_range")
        out[key] = number
    return out


def _zones(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or len(value) > ZONES_MAX:
        raise _bad("subnet_zones")
    out: dict[str, str] = {}
    for key, zone in value.items():
        if not isinstance(key, str) or not 0 < len(key) <= 64:
            raise _bad("subnet_zones", "key")
        if not isinstance(zone, str) or not _TOKEN.fullmatch(zone) or len(zone) > 32:
            raise _bad("subnet_zones", "value")
        out[key] = zone
    return out


SETTINGS_FIELDS: Mapping[str, Callable[[Any], Any]] = {
    "enabled": _bool("enabled"),
    "log_path": _choice("log_path", _LOG_PATHS),
    "syslog_port": _port,
    "keep_dns_names": _bool("keep_dns_names"),
    "thresholds": _thresholds,
    "subnet_zones": _zones,
}


def _epoch(value: str, field: str) -> float:
    if len(value) > 20:
        raise _bad(field)
    try:
        number = float(value)
    except ValueError:
        raise _bad(field) from None
    if not math.isfinite(number) or not 0 <= number <= _EPOCH_MAX:
        raise _bad(field, "out_of_range")
    return number


def _limit(value: str) -> int:
    if not value.isdigit() or len(value) > 4:
        raise _bad("limit")
    limit = int(value)
    if not 1 <= limit <= LIST_LIMIT_MAX:
        raise _bad("limit", "out_of_range")
    return limit


def _client(value: str) -> str:
    if _CLIENT_REF.fullmatch(value):
        return value
    mac = normalize_mac(value) if len(value) <= 17 else None
    if mac is None:
        raise _bad("client")
    return mac


def _router_id(value: str) -> str:
    router_id = valid_router_id(value)
    if router_id is None:
        raise _bad("router_id")
    return router_id


_CATEGORIES = frozenset(c.value for c in SecCategory)
_QUERY: Mapping[str, Callable[[str], Any]] = {
    "since": lambda v: _epoch(v, "since"),
    "until": lambda v: _epoch(v, "until"),
    "router_id": _router_id,
    "client": _client,
    "category": lambda v: _choice("category", _CATEGORIES)(v),
    "severity": lambda v: _choice("severity", _SEVERITIES)(v),
    "limit": _limit,
}


def overview_filters(query: Mapping[str, str]) -> dict[str, Any]:
    """The overview's filters from the query string (unknown keys: 400)."""
    out: dict[str, Any] = {}
    for key, value in query.items():  # a repeated key comes twice
        if key not in _QUERY:
            raise _bad("query", "unknown_key")
        if key in out:
            raise _bad(key, "repeated")
        out[key] = _QUERY[key](value)
    if "since" in out and "until" in out and out["since"] > out["until"]:
        raise _bad("since", "after_until")
    return out


def _incident_id(value: Any) -> str:
    if not isinstance(value, str) or not _INCIDENT_ID.fullmatch(value):
        raise _bad("incident_id")
    return value


def _mac(value: Any) -> str:
    mac = normalize_mac(value) if isinstance(value, str) and len(value) <= 17 else None
    if mac is None:
        raise _bad("mac")
    return mac


# --- views ------------------------------------------------------------------------


class _SecurityView(HomeAssistantView):
    """Access checks, error mapping and output of every route."""

    requires_auth = True

    async def _respond(
        self, request: web.Request, match: Mapping[str, str], *, write: bool
    ) -> web.StreamResponse:
        try:
            hass: HomeAssistant = request.app[KEY_HASS]
            user = request.get(KEY_HASS_USER)
            admin = user is not None and getattr(user, "is_admin", False) is True
            if user is None or (write and not admin):
                raise RequestError(403, "authorization_denied")
            if not admin and not _panel_open_to_all(hass):
                raise RequestError(403, "authorization_denied")
            if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
                raise RequestError(410, "integration_not_loaded")
            from .security_center import async_get_security_center

            center = async_get_security_center(hass)
            if center is None or not center.loaded:
                raise RequestError(503, "not_running")
            user_id = getattr(user, "id", None)
            user_id = user_id if isinstance(user_id, str) and user_id else None
            actor = await async_actor_from_context(hass, Context(user_id=user_id))
            body = await self.handle(center, request, actor, admin, **match)
        except RequestError as err:
            return error_response(err)
        except Exception as err:
            from .security_center import SecurityCenterError

            if isinstance(err, SecurityCenterError):
                return error_response(center_error(err))
            # Only the type: the message may carry router data.
            _LOGGER.warning(
                "Security Center route %s failed: %s", self.name, type(err).__name__
            )
            _LOGGER.debug("Security Center route error", exc_info=True)
            return error_response(RequestError(500, "internal"))
        return self.json(body, headers=dict(NO_STORE))

    async def handle(
        self,
        center: Any,
        request: web.Request,
        actor: Any,
        admin: bool,
        **match: str,
    ) -> Any:
        """The route itself (after the access checks)."""
        raise NotImplementedError


class _GetView(_SecurityView):
    async def get(self, request: web.Request, **match: str) -> web.StreamResponse:
        """Read."""
        return await self._respond(request, match, write=False)


class _PostView(_SecurityView):
    async def post(self, request: web.Request, **match: str) -> web.StreamResponse:
        """Act (administrators only)."""
        return await self._respond(request, match, write=True)


class SecurityOverviewView(_GetView):
    """Score, coverage, incidents, timeline, devices; filters as query."""

    url = f"{BASE_URL}/overview"
    name = f"{VIEW_NAME_PREFIX}overview"

    async def handle(self, center, request, actor, admin, **match):  # type: ignore[override]
        filters = overview_filters(request.query)
        viewer = await center.async_viewer(actor) if admin else actor
        return center.overview(actor=viewer, **filters)


class SecurityIncidentView(_GetView):
    """One own incident (``sec_*``) with its timeline entries."""

    url = f"{BASE_URL}/incidents/{{incident_id}}"
    name = f"{VIEW_NAME_PREFIX}incident"

    async def handle(self, center, request, actor, admin, **match):  # type: ignore[override]
        if request.query:
            raise _bad("query", "unknown_key")
        incident_id = _incident_id(match.get("incident_id"))
        viewer = await center.async_viewer(actor) if admin else actor
        detail = center.incident_detail(incident_id, actor=viewer)
        if detail is None:
            raise RequestError(404, "unknown_incident")
        return detail


class SecurityIncidentStatusView(_PostView):
    """Set open / resolved / confirmed of an own incident."""

    url = f"{BASE_URL}/incidents/{{incident_id}}/status"
    name = f"{VIEW_NAME_PREFIX}incident_status"

    async def handle(self, center, request, actor, admin, **match):  # type: ignore[override]
        incident_id = _incident_id(match.get("incident_id"))
        body = await read_body(
            request, {"status": _choice("status", _STATUSES)}, required=("status",)
        )
        return {
            "incident": await center.async_set_incident_status(
                incident_id, body["status"], actor=actor
            )
        }


class SecurityDetectionsView(_GetView):
    """Availability of every detection, per-router sources, the log path."""

    url = f"{BASE_URL}/detections"
    name = f"{VIEW_NAME_PREFIX}detections"

    async def handle(self, center, request, actor, admin, **match):  # type: ignore[override]
        if request.query:
            raise _bad("query", "unknown_key")
        return center.detections_view()


class SecuritySettingsView(_SecurityView):
    """GET: the settings (all readers); POST: change them (admin only).

    Turning the center on (``enabled``) and choosing the log path happen
    here; there is no options flow and no service for it.
    """

    url = f"{BASE_URL}/settings"
    name = f"{VIEW_NAME_PREFIX}settings"

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read the settings."""
        return await self._respond(request, {}, write=False)

    async def post(self, request: web.Request) -> web.StreamResponse:
        """Change the settings (administrators only)."""
        return await self._respond(request, {}, write=True)

    async def handle(self, center, request, actor, admin, **match):  # type: ignore[override]
        if request.query:
            raise _bad("query", "unknown_key")
        if request.method == "POST":
            update = await read_body(request, SETTINGS_FIELDS)
            if not update:
                raise _bad("body", "empty")
            await center.async_update_settings(update, actor=actor)
        return center.settings_view(admin=admin)


class SecurityDeviceConfirmView(_PostView):
    """Mark a device as known (optionally with a display name).

    Body ``{"mac": "...", "name": "..."}`` (``name`` optional).
    """

    url = f"{BASE_URL}/devices/confirm"
    name = f"{VIEW_NAME_PREFIX}device_confirm"

    async def handle(self, center, request, actor, admin, **match):  # type: ignore[override]
        if request.query:
            raise _bad("query", "unknown_key")
        body = await read_body(request, {"mac": _mac, "name": _name}, required=("mac",))
        await center.async_confirm_device(
            body["mac"], actor=actor, name=body.get("name")
        )
        return {"confirmed": True}


class SecurityDeviceNameView(_PostView):
    """Set (or clear with null) a tracked device's display name.

    Body ``{"mac": "...", "name": "..." | null}`` (both required).
    """

    url = f"{BASE_URL}/devices/name"
    name = f"{VIEW_NAME_PREFIX}device_name"

    async def handle(self, center, request, actor, admin, **match):  # type: ignore[override]
        if request.query:
            raise _bad("query", "unknown_key")
        body = await read_body(
            request, {"mac": _mac, "name": _name}, required=("mac", "name")
        )
        await center.async_set_device_name(body["mac"], body["name"], actor=actor)
        return {"named": body["name"] is not None}


SECURITY_VIEWS: tuple[type[HomeAssistantView], ...] = (
    SecurityOverviewView,
    SecurityIncidentView,
    SecurityIncidentStatusView,
    SecurityDetectionsView,
    SecuritySettingsView,
    SecurityDeviceConfirmView,
    SecurityDeviceNameView,
)


@callback
def async_register_security_views(hass: HomeAssistant) -> None:
    """Bind the routes once per HA run (aiohttp cannot unbind them)."""
    bound: set[str] = hass.data.setdefault(DATA_SECURITY_VIEWS_BOUND, set())
    for view_class in SECURITY_VIEWS:
        if view_class.name in bound:
            continue
        hass.http.register_view(view_class())
        bound.add(view_class.name)


__all__ = [
    "BASE_URL",
    "SECURITY_VIEWS",
    "SecurityDetectionsView",
    "SecurityDeviceConfirmView",
    "SecurityDeviceNameView",
    "SecurityIncidentStatusView",
    "SecurityIncidentView",
    "SecurityOverviewView",
    "SecuritySettingsView",
    "async_register_security_views",
    "overview_filters",
    "read_body",
]
