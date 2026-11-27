"""Self-Healing (Phase 7), package C1: the read-only HTTP routes.

Base ``/api/openwrt_router/enterprise/selfhealing/v1`` (versioned, design
§11). GET only; there is no route that writes, approves, executes, releases
a hold or changes a setting in this package (those come with C2, admin
only). Registered once per HA instance when the engine first starts, so
with the module off from the start no route exists; switched off later the
routes answer 503 ``not_running`` and read nothing.

Rights, checked on the server in the order of the sister routes
(``tm_views``): every route needs a logged-in user (``requires_auth``: 401
from HA itself).

* ``overview``: administrators, and other users only while an entry opens
  the topology panel to all users (like the Time Machine timeline and the
  Security Center overview); a non-admin gets counts only (no router id,
  no action id, no hold detail; design §13 "masked short version").
* ``actions``, ``actions/{action_id}``, ``settings``, ``plans``:
  administrators only (403 for everyone else, also while the panel is open
  to all): they name routers, incidents, causes and the per-router modes,
  which is more than the existing enterprise read routes show non-admins.

Then 410 while the panel view is disabled (last entry unloaded), 503 while
no engine runs, a body is refused (a GET takes none; 4 KiB cap, ``read_body``
of the Security Center), and the strict query: known keys only, each once,
at most ``QUERY_VALUE_MAX`` characters, ids by their exact pattern, paging
bounded (``LIMIT_MAX``, ``OFFSET_MAX``); a 400 names field and reason,
never the input. Errors carry a fixed message and are logged by type and
place only. Router-supplied strings (incident type, cause code, component
names) are returned as JSON data and never interpreted. No route talks to a
router; ``plans`` calls the decision interface read-only and creates no
approval and no state.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Mapping
from typing import Any, Final

from aiohttp import web
from homeassistant.components.http import KEY_HASS, KEY_HASS_USER, HomeAssistantView
from homeassistant.core import HomeAssistant, callback

from .const import DATA_SELF_HEALING_VIEWS_BOUND
from .heal_engine import (
    OBSERVE_ACTION,
    WRITE_PATH_AVAILABLE,
    HealEngine,
    async_get_self_healing,
    count_by_state,
    open_count,
    self_healing_enabled,
)
from .heal_model import (
    TERMINAL_STATES,
    ActionState,
    RemediationAction,
    RouterHold,
)
from .heal_store import (
    MAX_ACTIONS,
    MAX_OPEN_PER_ROUTER,
    STORE_MAX_BYTES,
    TERMINAL_RETENTION_S,
)
from .security_views import NO_STORE, RequestError, read_body
from .topology_panel import _PANEL_VIEW_DISABLED_KEY, _panel_open_to_all

_LOGGER = logging.getLogger(__name__)

API_VERSION: Final = 1
BASE_URL: Final = "/api/openwrt_router/enterprise/selfhealing/v1"
VIEW_NAME_PREFIX: Final = "api:openwrt_router:enterprise:selfhealing:v1:"
QUERY_VALUE_MAX: Final = 64
LIMIT_DEFAULT: Final = 50
LIMIT_MAX: Final = 200
OFFSET_MAX: Final = 10_000
PLANS_MAX: Final = 200
_ROUTER_ID: Final = re.compile(r"rtr_[0-9a-f]{32}")
_ACTION_ID: Final = re.compile(r"rem_[0-9a-f]{32}")
_INT: Final = re.compile(r"[0-9]{1,6}")
_STATES: Final = frozenset(s.value for s in ActionState)
_ERROR_TOKEN: Final = re.compile(r"[A-Za-z0-9_.:-]{1,64}")

ACTIONS_QUERY_KEYS: Final = frozenset({"router_id", "state", "open", "limit", "offset"})
PLANS_QUERY_KEYS: Final = frozenset({"router_id", "action_id"})

_MESSAGES: Final[Mapping[str, str]] = {
    "invalid_request": "The request is not valid",
    "body_too_large": "The request body is too large",
    "authorization_denied": "This is available to administrators only",
    "integration_not_loaded": "OpenWrt Router integration not loaded",
    "not_running": "Self-Healing is not running",
    "unknown_action": "Unknown action",
    "internal": "The request failed",
}


def _bad(field: str, reason: str = "invalid") -> RequestError:
    return RequestError(400, "invalid_request", field=field, reason=reason)


def error_response(err: RequestError) -> web.Response:
    """The masked error body (``Cache-Control: no-store``)."""
    details: dict[str, str] = {}
    for key, value in (("field", err.field), ("reason", err.reason)):
        if isinstance(value, str) and _ERROR_TOKEN.fullmatch(value):
            details[key] = value
    body = {
        "message": _MESSAGES.get(err.code, _MESSAGES["internal"]),
        "code": err.code if err.code in _MESSAGES else "internal",
        "details": details,
    }
    return HomeAssistantView.json(body, err.status, headers=dict(NO_STORE))


def _where(err: BaseException) -> str:
    """File and line that raised (never the message: it may carry data)."""
    tb = err.__traceback__
    while tb is not None and tb.tb_next is not None:
        tb = tb.tb_next
    if tb is None:
        return "-"
    return f"{tb.tb_frame.f_code.co_filename.rsplit('/', 1)[-1]}:{tb.tb_lineno}"


def _failed(name: str, err: Exception) -> web.Response:
    _LOGGER.warning(
        "Self-Healing route %s failed: %s at %s", name, type(err).__name__, _where(err)
    )
    return error_response(RequestError(500, "internal"))


def _query(request: web.Request, keys: frozenset[str]) -> dict[str, str]:
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


def _int(raw: dict[str, str], key: str, default: int, lo: int, hi: int) -> int:
    value = raw.get(key)
    if value is None:
        return default
    if _INT.fullmatch(value) is None:
        raise _bad(key)
    number = int(value)
    if not lo <= number <= hi:
        raise _bad(key, "out_of_range")
    return number


def _router_id(raw: dict[str, str]) -> str | None:
    value = raw.get("router_id")
    if value is not None and _ROUTER_ID.fullmatch(value) is None:
        raise _bad("router_id")
    return value


def _is_admin(user: Any) -> bool:
    return user is not None and getattr(user, "is_admin", False) is True


def _reader(request: web.Request) -> tuple[HomeAssistant, bool]:
    """Overview rights: 403 for no user or a non-admin while the panel is
    not open to all, then 410 while the panel view is disabled."""
    hass: HomeAssistant = request.app[KEY_HASS]
    user = request.get(KEY_HASS_USER)
    admin = _is_admin(user)
    if user is None or (not admin and not _panel_open_to_all(hass)):
        raise RequestError(403, "authorization_denied")
    if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
        raise RequestError(410, "integration_not_loaded")
    return hass, admin


def _admin(request: web.Request) -> HomeAssistant:
    """Admin-only rights: 403 for every non-admin, then 410."""
    hass: HomeAssistant = request.app[KEY_HASS]
    if not _is_admin(request.get(KEY_HASS_USER)):
        raise RequestError(403, "authorization_denied")
    if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
        raise RequestError(410, "integration_not_loaded")
    return hass


def _engine(hass: HomeAssistant) -> HealEngine:
    engine = async_get_self_healing(hass)
    if engine is None or not engine.loaded:
        raise RequestError(503, "not_running")
    return engine


def _hold(hold: RouterHold | None, safe: float) -> dict[str, Any] | None:
    """A hold without wall times: reason, scope and seconds left (safety
    clock; None: only an administrator ends it)."""
    if hold is None:
        return None
    return {
        "reason": hold.reason.value,
        "fleet": hold.router_id is None,
        "no_end": hold.until is None,
        "remaining_s": None if hold.until is None else max(0, round(hold.until - safe)),
        "action_id": hold.action_id,
    }


def _summary(action: RemediationAction) -> dict[str, Any]:
    """One list row: ids, codes, counts and wall times only."""
    return {
        "action_id": action.action_id,
        "router_id": action.router_id,
        "state": action.state.value,
        "terminal": action.state in TERMINAL_STATES,
        "created_at": action.created_at,
        "updated_at": action.updated_at,
        "action_type": action.action_type,
        "incident_id": action.incident_id,
        "incident_type": action.incident_type,
        "incident_reopen": action.incident_reopen,
        "cause_code": action.cause.code if action.cause is not None else None,
        "cause_level": action.cause.level.value if action.cause is not None else None,
        "decision": action.decision.outcome.value
        if action.decision is not None
        else None,
        "risk_class": int(action.risk.risk_class),
        "flags": action.flags.to_dict(),
    }


def overview_body(engine: HealEngine, *, admin: bool, now: float) -> dict[str, Any]:
    """The overview; for a non-admin only counts (no ids, no hold detail)."""
    store = engine.store
    safe = store.now()
    actions = list(store.actions.values())
    fleet_hold = store.loop.holds.get("")
    fleet_hold = (
        fleet_hold if fleet_hold is not None and fleet_hold.active(safe) else None
    )
    fleet = store.loop.fleet
    paused = fleet.paused(safe)
    routers: list[dict[str, Any]] = []
    held = 0
    for rid in engine.router_ids():
        hold = store.loop.hold_on(rid, safe)
        own = store.loop.holds.get(rid)
        if hold is not None:
            held += 1
        routers.append(
            {
                "router_id": rid,
                "loaded": engine.entry_for_router(rid) in engine.entries,
                "configured_mode": store.settings.router(rid).mode.value,
                "effective_mode": store.effective_mode(rid).value,
                "held": hold is not None,
                "hold": _hold(
                    own if own is not None and own.active(safe) else None, safe
                ),
                "open": open_count(a for a in actions if a.router_id == rid),
            }
        )
    counts = {
        "total": len(actions),
        "open": open_count(actions),
        "by_state": count_by_state(actions),
        "routers": len(routers),
        "routers_held": held,
    }
    body: dict[str, Any] = {
        "v": API_VERSION,
        "status": "on" if engine.module_enabled() else "module_disabled",
        "generated_at": now,
        "release_mode": "observe_only",
        "write_path": WRITE_PATH_AVAILABLE,
        "automatic_rollback": "not_available",
        "fleet": {
            "paused": paused,
            "held": fleet_hold is not None,
        },
        "counts": counts,
        "last_activity": engine.last_activity(),
    }
    if not admin:
        return body
    body["fleet"].update(
        {
            "pause_reason": fleet.reason if paused else None,
            "pause_remaining_s": max(0, round(fleet.paused_until - safe))
            if paused and fleet.paused_until is not None
            else None,
            "hold": _hold(fleet_hold, safe),
        }
    )
    body["routers"] = routers
    body["pending_incidents"] = engine.pending_count()
    return body


class _View(HomeAssistantView):
    requires_auth = True


class SelfHealingOverviewView(_View):
    """Mode per router, counts, holds, fleet pause, last activity."""

    url = f"{BASE_URL}/overview"
    name = f"{VIEW_NAME_PREFIX}overview"

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read (no body, no query)."""
        try:
            hass, admin = _reader(request)
            engine = _engine(hass)
            await read_body(request, {})
            _query(request, frozenset())
            body = overview_body(engine, admin=admin, now=time.time())
        except RequestError as err:
            return error_response(err)
        except Exception as err:  # noqa: BLE001 - logged by type, a 500
            return _failed(self.name, err)
        return self.json(body, headers=dict(NO_STORE))


class SelfHealingActionsView(_View):
    """The records, newest first, with filters and paging (admins)."""

    url = f"{BASE_URL}/actions"
    name = f"{VIEW_NAME_PREFIX}actions"

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read (no body, strict query)."""
        try:
            hass = _admin(request)
            engine = _engine(hass)
            await read_body(request, {})
            raw = _query(request, ACTIONS_QUERY_KEYS)
            router_id = _router_id(raw)
            states: set[str] | None = None
            if "state" in raw:
                states = set(raw["state"].split(","))
                if not states or not states <= _STATES:
                    raise _bad("state", "unknown")
            open_only: bool | None = None
            if "open" in raw:
                if raw["open"] not in ("0", "1"):
                    raise _bad("open")
                open_only = raw["open"] == "1"
            limit = _int(raw, "limit", LIMIT_DEFAULT, 1, LIMIT_MAX)
            offset = _int(raw, "offset", 0, 0, OFFSET_MAX)
            rows = [
                a
                for a in engine.store.actions.values()
                if (router_id is None or a.router_id == router_id)
                and (states is None or a.state.value in states)
                and (open_only is None or (a.state not in TERMINAL_STATES) is open_only)
            ]
            rows.sort(key=lambda a: (-a.created_at, a.action_id))
            body = {
                "v": API_VERSION,
                "generated_at": time.time(),
                "total": len(rows),
                "limit": limit,
                "offset": offset,
                "actions": [_summary(a) for a in rows[offset : offset + limit]],
            }
        except RequestError as err:
            return error_response(err)
        except Exception as err:  # noqa: BLE001 - logged by type, a 500
            return _failed(self.name, err)
        return self.json(body, headers=dict(NO_STORE))


class SelfHealingActionView(_View):
    """One record with its whole history (admins)."""

    url = BASE_URL + "/actions/{action_id}"
    name = f"{VIEW_NAME_PREFIX}action"

    async def get(self, request: web.Request, action_id: str) -> web.StreamResponse:
        """Read (no body, no query)."""
        try:
            hass = _admin(request)
            engine = _engine(hass)
            await read_body(request, {})
            _query(request, frozenset())
            if _ACTION_ID.fullmatch(action_id) is None:
                raise _bad("action_id")
            action = engine.store.get(action_id)
            if action is None:
                raise RequestError(404, "unknown_action")
            safe = engine.store.now()
            body = {
                "v": API_VERSION,
                "generated_at": time.time(),
                "action": action.to_dict(),
                "router_hold": _hold(
                    engine.store.loop.hold_on(action.router_id, safe), safe
                ),
                "effective_mode": engine.store.effective_mode(action.router_id).value,
            }
        except RequestError as err:
            return error_response(err)
        except Exception as err:  # noqa: BLE001 - logged by type, a 500
            return _failed(self.name, err)
        return self.json(body, headers=dict(NO_STORE))


class SelfHealingSettingsView(_View):
    """The settings as stored, the module switch and the fixed limits."""

    url = f"{BASE_URL}/settings"
    name = f"{VIEW_NAME_PREFIX}settings"

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read (no body, no query)."""
        try:
            hass = _admin(request)
            engine = _engine(hass)
            await read_body(request, {})
            _query(request, frozenset())
            body = {
                "v": API_VERSION,
                "generated_at": time.time(),
                "module_switch": self_healing_enabled(hass),
                "release_mode": "observe_only",
                "write_path": WRITE_PATH_AVAILABLE,
                "settings": engine.store.settings.to_dict(),
                "limits": {
                    "max_actions": MAX_ACTIONS,
                    "max_open_per_router": MAX_OPEN_PER_ROUTER,
                    "store_max_bytes": STORE_MAX_BYTES,
                    "terminal_retention_s": TERMINAL_RETENTION_S,
                },
            }
        except RequestError as err:
            return error_response(err)
        except Exception as err:  # noqa: BLE001 - logged by type, a 500
            return _failed(self.name, err)
        return self.json(body, headers=dict(NO_STORE))


class SelfHealingPlansView(_View):
    """What would be proposed and what would block (read only, admins)."""

    url = f"{BASE_URL}/plans"
    name = f"{VIEW_NAME_PREFIX}plans"

    async def get(self, request: web.Request) -> web.StreamResponse:
        """Read (no body, strict query). Creates nothing, changes nothing."""
        try:
            hass = _admin(request)
            engine = _engine(hass)
            await read_body(request, {})
            raw = _query(request, PLANS_QUERY_KEYS)
            router_id = _router_id(raw)
            action_id = raw.get("action_id")
            if action_id is not None and _ACTION_ID.fullmatch(action_id) is None:
                raise _bad("action_id")
            if action_id is not None:
                found = engine.store.get(action_id)
                if found is None:
                    raise RequestError(404, "unknown_action")
                candidates = [found]
            else:
                candidates = engine.store.open_actions(router_id)
            candidates = [
                a
                for a in candidates
                if (router_id is None or a.router_id == router_id)
                and a.action_type == OBSERVE_ACTION
            ][:PLANS_MAX]
            body = {
                "v": API_VERSION,
                "generated_at": time.time(),
                "write_path": WRITE_PATH_AVAILABLE,
                "plans": [engine.plan_for(a).to_dict() for a in candidates],
            }
        except RequestError as err:
            return error_response(err)
        except Exception as err:  # noqa: BLE001 - logged by type, a 500
            return _failed(self.name, err)
        return self.json(body, headers=dict(NO_STORE))


SELF_HEALING_VIEWS: Final[tuple[type[HomeAssistantView], ...]] = (
    SelfHealingOverviewView,
    SelfHealingActionsView,
    SelfHealingActionView,
    SelfHealingSettingsView,
    SelfHealingPlansView,
)
# The route table with the right each route needs ("reader": admins, and
# other users while the panel is open to all; "admin": admins only).
ROUTE_ACCESS: Final[Mapping[str, str]] = {
    SelfHealingOverviewView.url: "reader",
    SelfHealingActionsView.url: "admin",
    SelfHealingActionView.url: "admin",
    SelfHealingSettingsView.url: "admin",
    SelfHealingPlansView.url: "admin",
}


@callback
def async_register_self_healing_views(hass: HomeAssistant) -> None:
    """Register the routes once per HA instance (only once the engine ran)."""
    if getattr(hass, "http", None) is None:
        return
    bound: set[str] = hass.data.setdefault(DATA_SELF_HEALING_VIEWS_BOUND, set())
    for view_class in SELF_HEALING_VIEWS:
        if view_class.name not in bound:
            hass.http.register_view(view_class())
            bound.add(view_class.name)


__all__ = [
    "API_VERSION",
    "BASE_URL",
    "ROUTE_ACCESS",
    "SELF_HEALING_VIEWS",
    "async_register_self_healing_views",
    "overview_body",
]
