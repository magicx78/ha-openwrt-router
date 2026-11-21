"""HTTP routes of the network diagnostics (release 1.47.0, part 2).

Base ``/api/openwrt_topology/diagnostics``; every route needs a logged-in HA
user (``requires_auth``: 401 from HA itself). Pattern of ``security_views``
and ``config_views``:

* ``GET overview``: score, coverage, active findings, the chain per router
  and for HA, the last run. ``GET history``: the four windows (1 h, 24 h,
  7 d, 30 d) per series. ``GET details?router_id=``: one finding with its
  context (no ``router_id``: the HA point). Readable by administrators, and
  by every other user only while an entry opens the topology panel to all
  users (else 403); non-admins always get the brief, masked output.
  Details beyond that only for an admin after the core's
  ``authorize_sensitive_read`` (audited by the core).
* ``GET``/``POST settings``: administrators only (403 before anything
  else); targets only through the module's validated registry
  (``merge_settings`` -> ``make_target``), the core guard decides and
  audits the change.
* ``POST run``: a manual diagnosis. Administrators only; the module must be
  on (else 409 with ``state: off``); body ``{"target_ids": [...]}``
  (configured target ids only, never a host); the core guard (mode ACTIVE,
  rate limit, audit) decides in the module.
* Order of the checks: user and admin -> panel access -> integration
  loaded -> module running -> module on (run only) -> query / body.
* Module off: the read routes answer ``{"state": "off", ...}``.

Input is checked strictly: known query and body keys only, at most 8 KiB
of JSON, nesting deeper than the parser follows or deeper than the
settings need is a 400. Errors carry a fixed message, a code and at most a
field name and a reason token: never the input, an exception text, an
address, a host or a domain (logs above DEBUG carry the exception type
only). None of the routes talks to a router; only ``run`` sends packets,
from Home Assistant, to confirmed targets.
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

from .const import DATA_DIAG_VIEWS_BOUND, DIAG_MAX_TARGETS
from .core_errors import (
    AuthorizationError,
    ConfigApiError,
    ErrorClass,
    RateLimitedError,
    SafetyRefusedError,
)
from .core_models import ROUTER_ID_PREFIX, async_actor_from_context, is_valid_id
from .topology_panel import _PANEL_VIEW_DISABLED_KEY, _panel_open_to_all

try:
    from homeassistant.helpers.http import KEY_HASS
except ImportError:  # pragma: no cover - older HA cores keyed the app by str
    KEY_HASS = "hass"  # type: ignore[assignment]

_LOGGER = logging.getLogger(__name__)

BASE_URL = "/api/openwrt_topology/diagnostics"
VIEW_NAME_PREFIX = "api:openwrt_topology:diagnostics:"
# 16 targets with a full host name each fit; nothing else is that large
BODY_MAX_BYTES = 8192
# Deepest JSON the settings need: {"targets": [{"id": "x"}]} is depth 3.
BODY_MAX_DEPTH = 3
NO_STORE = {"Cache-Control": "no-store"}
STATE_OFF = "off"
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_TARGET_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_SETTING_KEYS = frozenset(
    {
        "enabled",
        "periodic",
        "interval_s",
        "targets",
        "internal_networks",
        "local_domains",
        "dns_query_name",
        "http_path",
        "ha_resolver_internal",
    }
)

_MESSAGES: Mapping[str, str] = {
    "invalid_request": "The request is not valid",
    "body_too_large": "The request body is too large",
    "authorization_denied": "This is available to administrators only",
    "integration_not_loaded": "OpenWrt Router integration not loaded",
    "not_running": "Network diagnostics is not running",
    "disabled": "Network diagnostics is off",
    "unknown_target": "Unknown target",
    "unknown_router": "Unknown router",
    "refused": "The target was refused",
    "rate_limited": "Too many diagnoses; try again later",
    "busy": "A diagnosis is already running",
    "conflict": "The request conflicts with the current state",
    "not_available": "Not available",
    "no_core": "The enterprise core is not running",
    "internal": "The request failed",
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
        retry_after: float | None = None,
        state: str | None = None,
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.field = field
        self.reason = reason
        self.retry_after = retry_after
        self.state = state


def _bad(field: str, reason: str = "invalid") -> RequestError:
    return RequestError(400, "invalid_request", field=field, reason=reason)


def error_response(err: RequestError) -> web.Response:
    """The masked error body (``no-store``; 429 carries ``Retry-After``)."""
    details: dict[str, str] = {}
    for key, value in (("field", err.field), ("reason", err.reason)):
        if isinstance(value, str) and _TOKEN.fullmatch(value):
            details[key] = value
    body: dict[str, Any] = {
        "message": _MESSAGES.get(err.code, _MESSAGES["internal"]),
        "code": err.code,
        "details": details,
    }
    if err.state is not None:
        body["state"] = err.state
    headers = dict(NO_STORE)
    if err.retry_after is not None:
        headers["Retry-After"] = str(max(1, math.ceil(err.retry_after)))
    return HomeAssistantView.json(body, err.status, headers=headers)


def _reason(err: ConfigApiError) -> str | None:
    reason = err.details.get("reason") if isinstance(err.details, Mapping) else None
    return reason if isinstance(reason, str) else None


def api_error(err: ConfigApiError) -> RequestError:
    """A core / module error as a request error (codes only, never input)."""
    if isinstance(err, RateLimitedError) or err.error_class is ErrorClass.RATE_LIMITED:
        retry_after = getattr(err, "retry_after", None)
        if isinstance(retry_after, bool) or not isinstance(retry_after, int | float):
            retry_after = 1.0
        return RequestError(
            429, "rate_limited", reason="rate_limited", retry_after=retry_after
        )
    if (
        isinstance(err, SafetyRefusedError)
        or err.error_class is ErrorClass.SAFETY_REFUSED
    ):
        # a refused target: the reason code, never the target or its host
        reason = getattr(err, "reason", None)
        return RequestError(
            422, "refused", reason=reason if isinstance(reason, str) else _reason(err)
        )
    if isinstance(err, AuthorizationError) or err.error_class in (
        ErrorClass.DENIED,
        ErrorClass.APPROVAL,
    ):
        return RequestError(403, "authorization_denied")
    reason = _reason(err)
    match err.error_class:
        case ErrorClass.INVALID:
            return RequestError(400, "invalid_request", reason=reason)
        case ErrorClass.NOT_FOUND:
            code = "unknown_router" if reason == "unknown_router" else "unknown_target"
            return RequestError(404, code, reason=reason)
        case ErrorClass.TOO_LARGE:
            return RequestError(413, "body_too_large", reason=reason)
        case ErrorClass.BUSY:
            return RequestError(409, "busy", reason=reason)
        case ErrorClass.CONFLICT:
            return RequestError(409, "conflict", reason=reason)
        case ErrorClass.NOT_AVAILABLE:
            if reason == "disabled":
                return RequestError(409, "disabled", reason=reason, state=STATE_OFF)
            if reason == "core_unavailable":
                return RequestError(503, "no_core", reason=reason)
            return RequestError(409, "not_available", reason=reason)
    return RequestError(500, "internal")


# --- validation -------------------------------------------------------------------


def _depth(value: Any, limit: int, level: int = 0) -> bool:
    """True if ``value`` nests no deeper than ``limit``."""
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
) -> dict[str, Any]:
    """A JSON object of at most 8 KiB with known keys only, each checked."""
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
            # "[" * 8000 fits in 8 KiB: a bad body, not a server error
            raise _bad("body", "invalid_body") from None
    if not isinstance(data, dict):
        raise _bad("body", "not_an_object")
    if not _depth(data, BODY_MAX_DEPTH):
        raise _bad("body", "too_deep")
    if any(key not in fields for key in data):
        raise _bad("body", "unknown_key")
    return {key: fields[key](value) for key, value in data.items()}


def _target_ids(value: Any) -> list[str]:
    """Configured target ids only (never a host or an address)."""
    if not isinstance(value, list) or not 0 < len(value) <= DIAG_MAX_TARGETS:
        raise _bad("target_ids")
    for item in value:
        if not isinstance(item, str) or not _TARGET_ID.fullmatch(item):
            raise _bad("target_ids", "invalid_id")
    return list(dict.fromkeys(value))


def _raw(value: Any) -> Any:
    """Passed on as is: the module validates every setting itself."""
    return value


SETTINGS_FIELDS: Mapping[str, Callable[[Any], Any]] = dict.fromkeys(_SETTING_KEYS, _raw)
RUN_FIELDS: Mapping[str, Callable[[Any], Any]] = {"target_ids": _target_ids}


def _no_query(request: web.Request) -> None:
    if request.query:
        raise _bad("query", "unknown_key")


def _router_query(request: web.Request) -> str | None:
    """``router_id`` (a core router id) or None for the HA point."""
    router_id = None
    for key, value in request.query.items():
        if key != "router_id":
            raise _bad("query", "unknown_key")
        if router_id is not None:
            raise _bad("router_id", "repeated")
        if not is_valid_id(value, ROUTER_ID_PREFIX):
            raise _bad("router_id")
        router_id = value
    return router_id


# --- views ------------------------------------------------------------------------


class _DiagView(HomeAssistantView):
    """Access checks, error mapping and output of every route."""

    requires_auth = True
    # True: administrators only, also for reading (settings, run)
    admin_only = False
    # True: refused with 409 "disabled" while the module is off (run)
    needs_on = False

    async def _respond(
        self, request: web.Request, match: Mapping[str, str], *, write: bool
    ) -> web.StreamResponse:
        try:
            hass: HomeAssistant = request.app[KEY_HASS]
            user = request.get(KEY_HASS_USER)
            admin = user is not None and getattr(user, "is_admin", False) is True
            # 1. the user, before the feature switch and before any body
            if user is None or ((write or self.admin_only) and not admin):
                raise RequestError(403, "authorization_denied")
            if not admin and not _panel_open_to_all(hass):
                raise RequestError(403, "authorization_denied")
            if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
                raise RequestError(410, "integration_not_loaded")
            from .diag_runtime import async_get_net_diagnostics

            diag = async_get_net_diagnostics(hass)
            if diag is None or not getattr(diag, "loaded", False):
                raise RequestError(503, "not_running")
            # 2. the feature switch, still before the body
            if self.needs_on and not (diag.enabled and diag.active):
                raise RequestError(409, "disabled", reason="disabled", state=STATE_OFF)
            user_id = getattr(user, "id", None)
            user_id = user_id if isinstance(user_id, str) and user_id else None
            actor = await async_actor_from_context(hass, Context(user_id=user_id))
            body = await self.handle(diag, request, actor, admin, **match)
        except RequestError as err:
            return error_response(err)
        except ConfigApiError as err:
            mapped = api_error(err)
            if mapped.status == 500:
                _LOGGER.warning(
                    "Network diagnostics route %s failed: %s",
                    self.name,
                    type(err).__name__,
                )
            return error_response(mapped)
        except Exception as err:
            # Only the type: the message may carry an address or a host.
            _LOGGER.warning(
                "Network diagnostics route %s failed: %s", self.name, type(err).__name__
            )
            _LOGGER.debug("Network diagnostics route error", exc_info=True)
            return error_response(RequestError(500, "internal"))
        return self.json(body, headers=dict(NO_STORE))

    async def handle(
        self,
        diag: Any,
        request: web.Request,
        actor: Any,
        admin: bool,
        **match: str,
    ) -> Any:
        """The route itself (after the access checks)."""
        raise NotImplementedError


class DiagOverviewView(_DiagView):
    """Score, coverage, active findings, chains, last run (brief, masked)."""

    url = f"{BASE_URL}/overview"
    name = f"{VIEW_NAME_PREFIX}overview"

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read."""
        return await self._respond(request, {}, write=False)

    async def handle(self, diag, request, actor, admin, **match):  # type: ignore[override]
        _no_query(request)
        return diag.overview()


class DiagHistoryView(_DiagView):
    """The four windows of every series (point, target id, kind, family)."""

    url = f"{BASE_URL}/history"
    name = f"{VIEW_NAME_PREFIX}history"

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read."""
        return await self._respond(request, {}, write=False)

    async def handle(self, diag, request, actor, admin, **match):  # type: ignore[override]
        _no_query(request)
        return diag.history_view()


class DiagDetailsView(_DiagView):
    """One finding with its context; full detail after the sensitive read."""

    url = f"{BASE_URL}/details"
    name = f"{VIEW_NAME_PREFIX}details"

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read."""
        return await self._respond(request, {}, write=False)

    async def handle(self, diag, request, actor, admin, **match):  # type: ignore[override]
        router_id = _router_query(request)
        return await diag.async_detail(router_id, actor=actor, admin=admin)


class DiagSettingsView(_DiagView):
    """GET: the settings; POST: change them. Administrators only.

    Switching the module on and off happens here; there is no options flow
    and no service for it.
    """

    url = f"{BASE_URL}/settings"
    name = f"{VIEW_NAME_PREFIX}settings"
    admin_only = True

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read the settings (administrators only)."""
        return await self._respond(request, {}, write=False)

    async def post(self, request: web.Request) -> web.StreamResponse:
        """Change the settings (administrators only)."""
        return await self._respond(request, {}, write=True)

    async def handle(self, diag, request, actor, admin, **match):  # type: ignore[override]
        _no_query(request)
        if request.method == "POST":
            update = await read_body(request, SETTINGS_FIELDS)
            if not update:
                raise _bad("body", "empty")
            await diag.async_update_settings(update, actor=actor)
        state = diag.status()
        return {
            "state": state["state"],
            "reasons": state["reasons"],
            "settings": diag.settings_view(),
            "targets": state["targets"],
            "load": state["load"],
        }


class DiagRunView(_DiagView):
    """A manual diagnosis from Home Assistant (administrators only)."""

    url = f"{BASE_URL}/run"
    name = f"{VIEW_NAME_PREFIX}run"
    admin_only = True
    needs_on = True

    async def post(self, request: web.Request) -> web.StreamResponse:
        """Run (administrators only, guard decides)."""
        return await self._respond(request, {}, write=True)

    async def handle(self, diag, request, actor, admin, **match):  # type: ignore[override]
        _no_query(request)
        body = await read_body(request, RUN_FIELDS)
        return await diag.async_run_manual(
            actor=actor, target_ids=body.get("target_ids")
        )


DIAG_VIEWS: tuple[type[HomeAssistantView], ...] = (
    DiagOverviewView,
    DiagHistoryView,
    DiagDetailsView,
    DiagSettingsView,
    DiagRunView,
)


@callback
def async_register_diag_views(hass: HomeAssistant) -> None:
    """Bind the routes once per HA run (aiohttp cannot unbind them)."""
    http = getattr(hass, "http", None)
    if http is None:
        return  # no HTTP server (tests without one)
    bound: set[str] = hass.data.setdefault(DATA_DIAG_VIEWS_BOUND, set())
    for view_class in DIAG_VIEWS:
        if view_class.name in bound:
            continue
        http.register_view(view_class())
        bound.add(view_class.name)


__all__ = [
    "BASE_URL",
    "DIAG_VIEWS",
    "DiagDetailsView",
    "DiagHistoryView",
    "DiagOverviewView",
    "DiagRunView",
    "DiagSettingsView",
    "api_error",
    "async_register_diag_views",
    "read_body",
]
