"""Self-Healing, package C1 (1.53.0): the read-only HTTP routes.

Order test 31 (API authorisation): every route needs a logged-in user
(401 from HA itself); ``actions``, ``actions/{id}``, ``settings`` and
``plans`` answer 403 to every non-admin, also while the panel is open to
all; ``overview`` serves a non-admin only while the panel is open to all
and then only counts. The route table has GET routes only: no route
writes, approves, executes or changes a setting. Further: 410 while the
panel view is off, 503 while no engine runs, a body is refused, the strict
query (400 names field and reason, never the input), filters and paging,
the action detail with its history, ``plans`` changes nothing, holds and
the fleet pause are shown, and no body carries a secret, address or name.

The aiohttp test server of the Time Machine route tests; the engine and
its stand-ins come from ``test_heal_engine_v1530``.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from core_testkit import ADMIN_ID, SECRET, USER_ID, FakeDisks, add_users
from homeassistant.components.http import KEY_HASS_USER
from homeassistant.helpers.http import KEY_AUTHENTICATED, KEY_HASS
from test_heal_engine_v1530 import (
    E1,
    E2,
    R1,
    R2,
    Clock,
    FakeNI,
    Registry,
    World,
    heal_hass,
    make_entries,
    patched,
)
from test_heal_store_v1530 import disks

from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_views as hv
from custom_components.openwrt_router.const import CONF_HOST, DATA_SELF_HEALING_ENGINE
from custom_components.openwrt_router.topology_panel import (
    _PANEL_ACCESS_KEY,
    _PANEL_VIEW_DISABLED_KEY,
)

__all__ = ["disks"]  # fixture used here

URLS = {
    "overview": f"{hv.BASE_URL}/overview",
    "actions": f"{hv.BASE_URL}/actions",
    "settings": f"{hv.BASE_URL}/settings",
    "plans": f"{hv.BASE_URL}/plans",
}
ADMIN_ONLY = ("actions", "settings", "plans")
# entry ids are short and appear inside hex ids: looked for as JSON strings
HOST = make_entries(E1)[0].data[CONF_HOST]  # the test entry's address
FORBIDDEN = (SECRET, HOST, "Router e1", "Router e2", f'"{E1}"', f'"{E2}"')


def _auth_middleware(hass: Any) -> Any:
    @web.middleware
    async def middleware(request: web.Request, handler: Any) -> Any:
        user_id = request.headers.get("X-Test-User")
        if user_id:
            request[KEY_AUTHENTICATED] = True
            request[KEY_HASS_USER] = hass.users.get(user_id)
        return await handler(request)

    return middleware


class Http:
    def __init__(self, test_client: TestClient) -> None:
        self.client = test_client
        self.texts: list[str] = []

    async def request(
        self,
        method: str,
        url: str,
        *,
        user: str | None = ADMIN_ID,
        params: Any = None,
        data: Any = None,
    ) -> tuple[int, Any]:
        headers = {"X-Test-User": user} if user else {}
        resp = await self.client.request(
            method, url, headers=headers, params=params, data=data
        )
        text = await resp.text()
        self.texts.append(text)
        if resp.status in (200, 400, 403, 404, 410, 413, 500, 503):
            assert resp.headers.get("Cache-Control") == "no-store"
        try:
            return resp.status, json.loads(text)
        except ValueError:
            return resp.status, text

    async def get(self, url: str, **kw: Any) -> tuple[int, Any]:
        return await self.request("GET", url, **kw)


@pytest.fixture
async def world(disks: FakeDisks) -> Any:
    hass = heal_hass(make_entries(E1, E2))
    add_users(hass)
    w = World(hass, Clock(), FakeNI(), Registry({E1: R1, E2: R2}))
    with patched(w.ni, w.registry, w.ticks):
        await w.start()
        yield w
        if w.engine is not None and not w.engine.closed:
            await w.engine.async_stop()


@pytest.fixture
async def http(world: World) -> Any:
    world.hass.is_stopping = False  # HA's view wrapper answers 503 while stopping
    app = web.Application(middlewares=[_auth_middleware(world.hass)])
    app[KEY_HASS] = world.hass
    for view_class in hv.SELF_HEALING_VIEWS:
        view_class().register(world.hass, app, app.router)
    async with TestClient(TestServer(app)) as test_client:
        h = Http(test_client)
        h.app = app  # type: ignore[attr-defined]
        yield h
    for text in h.texts:
        for needle in FORBIDDEN:
            assert needle not in text, needle


def detail_url(action_id: str) -> str:
    return f"{hv.BASE_URL}/actions/{action_id}"


# --- order test 31: the route table and the rights --------------------------------------


def test_the_route_table_has_no_writing_route() -> None:
    """Order test 31: GET only, every route versioned, each with its right."""
    writers = ("post", "put", "patch", "delete")
    assert len(hv.SELF_HEALING_VIEWS) == 5
    for view_class in hv.SELF_HEALING_VIEWS:
        assert view_class.requires_auth is True
        assert view_class.url.startswith(hv.BASE_URL + "/")
        assert hv.BASE_URL.endswith("/selfhealing/v1")
        assert view_class.name.startswith(hv.VIEW_NAME_PREFIX)
        assert callable(getattr(view_class, "get", None))
        for method in writers:
            assert not hasattr(view_class, method), (view_class.url, method)
    assert set(hv.ROUTE_ACCESS) == {v.url for v in hv.SELF_HEALING_VIEWS}
    assert {k for k, v in hv.ROUTE_ACCESS.items() if v == "reader"} == {
        URLS["overview"]
    }
    assert set(hv.ROUTE_ACCESS.values()) == {"reader", "admin"}


async def test_the_registered_routes_are_get_only(http: Http) -> None:
    methods = {route.method for route in http.app.router.routes()}  # type: ignore[attr-defined]
    assert methods <= {"GET", "HEAD"} and "GET" in methods
    for url in (*URLS.values(), detail_url("rem_" + "0" * 32)):
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            status, _ = await http.request(method, url, data="{}")
            assert status == 405, (method, url)


async def test_every_route_needs_a_user(http: Http) -> None:
    for url in (*URLS.values(), detail_url("rem_" + "0" * 32)):
        status, _ = await http.get(url, user=None)
        assert status == 401


async def test_admin_routes_refuse_every_non_admin(world: World, http: Http) -> None:
    """Order test 31: 403 for a non-admin, also while the panel is open."""
    world.open("inc-1")
    record = world.of("inc-1")
    for panel_open in (False, True):
        world.hass.data[_PANEL_ACCESS_KEY] = {E1: panel_open}
        for name in ADMIN_ONLY:
            status, body = await http.get(URLS[name], user=USER_ID)
            assert status == 403 and body["code"] == "authorization_denied"
        status, _ = await http.get(detail_url(record.action_id), user=USER_ID)
        assert status == 403
    # an unknown user id (no user object) is refused as well
    for url in (*URLS.values(), detail_url(record.action_id)):
        status, _ = await http.get(url, user="user-unknown")
        assert status == 403


async def test_overview_for_a_non_admin_only_while_open_and_masked(
    world: World, http: Http
) -> None:
    world.open("inc-1")
    status, body = await http.get(URLS["overview"], user=USER_ID)
    assert status == 403 and body["code"] == "authorization_denied"
    world.hass.data[_PANEL_ACCESS_KEY] = {E1: True}
    status, body = await http.get(URLS["overview"], user=USER_ID)
    assert status == 200
    assert "routers" not in body and "pending_incidents" not in body
    assert set(body["fleet"]) == {"paused", "held"}
    assert body["counts"]["open"] == 1 and body["counts"]["routers"] == 2
    text = json.dumps(body)
    for needle in ("rtr_", "rem_", "inc-1", "dns_failure"):
        assert needle not in text


async def test_overview_for_an_admin(world: World, http: Http) -> None:
    world.open("inc-1")
    status, body = await http.get(URLS["overview"])
    assert status == 200
    assert body["v"] == 1 and body["status"] == "on"
    assert body["release_mode"] == "observe_only"
    assert body["write_path"] is False
    assert body["automatic_rollback"] == "not_available"
    assert body["counts"]["by_state"]["proposed"] == 1
    assert body["last_activity"] is not None
    routers = {r["router_id"]: r for r in body["routers"]}
    assert set(routers) == {R1, R2}
    assert routers[R1]["open"] == 1 and routers[R2]["open"] == 0
    assert routers[R1]["loaded"] is True
    assert routers[R1]["configured_mode"] == routers[R1]["effective_mode"] == "observe"
    assert body["pending_incidents"] == 0


async def test_holds_and_the_fleet_pause_are_shown(world: World, http: Http) -> None:
    """An unknown state holds the router: the overview says so (an admin
    gets the detail, a non-admin the counts)."""
    store = world.engine.store
    store.set_settings(
        hm.HealSettings(routers={R2: hm.RouterSettings(mode=hm.HealMode.AUTO_HEAL)})
    )
    safe = store.now()
    store.loop.place_hold(
        hm.RouterHold(
            router_id=R1, reason=hm.HoldReason.OUTCOME_UNKNOWN, since=safe, until=None
        )
    )
    store.loop.fleet = hm.FleetPause(
        paused_until=safe + 3600, since=safe, reason="store_lost"
    )
    status, body = await http.get(URLS["overview"])
    assert status == 200
    routers = {r["router_id"]: r for r in body["routers"]}
    assert routers[R1]["held"] is True
    assert routers[R1]["hold"] == {
        "reason": "outcome_unknown",
        "fleet": False,
        "no_end": True,
        "remaining_s": None,
        "action_id": None,
    }
    assert routers[R1]["effective_mode"] == "observe"
    assert routers[R2]["held"] is False
    assert routers[R2]["configured_mode"] == "auto_heal"
    assert routers[R2]["effective_mode"] == "approval"
    assert body["fleet"]["paused"] is True
    assert body["fleet"]["pause_reason"] == "store_lost"
    assert body["fleet"]["pause_remaining_s"] == 3600
    assert body["counts"]["routers_held"] == 1
    world.hass.data[_PANEL_ACCESS_KEY] = {E1: True}
    status, body = await http.get(URLS["overview"], user=USER_ID)
    assert status == 200 and body["fleet"] == {"paused": True, "held": False}
    assert body["counts"]["routers_held"] == 1


async def test_panel_off_is_410_and_no_engine_is_503(world: World, http: Http) -> None:
    world.hass.data[_PANEL_VIEW_DISABLED_KEY] = True
    for url in URLS.values():
        status, body = await http.get(url)
        assert status == 410 and body["code"] == "integration_not_loaded"
    world.hass.data[_PANEL_VIEW_DISABLED_KEY] = False
    await world.engine.async_stop()
    for url in (*URLS.values(), detail_url("rem_" + "0" * 32)):
        status, body = await http.get(url)
        assert status == 503 and body["code"] == "not_running"
    world.hass.data.pop(DATA_SELF_HEALING_ENGINE)
    status, _ = await http.get(URLS["overview"])
    assert status == 503


# --- requests ---------------------------------------------------------------------------


async def test_a_get_takes_no_body(http: Http) -> None:
    for url in URLS.values():
        status, body = await http.request("GET", url, data='{"x": 1}')
        assert status == 400 and body["details"]["field"] == "body"
        status, body = await http.request("GET", url, data="x" * 5000)
        assert status == 413 and body["code"] == "body_too_large"


@pytest.mark.parametrize(
    ("url", "params", "field", "reason"),
    [
        ("overview", {"x": "1"}, "query", "unknown_key"),
        ("settings", {"limit": "1"}, "query", "unknown_key"),
        ("actions", {"bogus": "1"}, "query", "unknown_key"),
        ("actions", [("limit", "1"), ("limit", "2")], "limit", "repeated"),
        ("actions", {"router_id": "x" * 65}, "router_id", "too_long"),
        ("actions", {"router_id": "<script>"}, "router_id", "invalid"),
        ("actions", {"state": "proposed,hacked"}, "state", "unknown"),
        ("actions", {"open": "yes"}, "open", "invalid"),
        ("actions", {"limit": "0"}, "limit", "out_of_range"),
        ("actions", {"limit": "201"}, "limit", "out_of_range"),
        ("actions", {"limit": "-1"}, "limit", "invalid"),
        ("actions", {"offset": "10001"}, "offset", "out_of_range"),
        ("plans", {"action_id": "rem_XYZ"}, "action_id", "invalid"),
        ("plans", {"router_id": "rtr_1"}, "router_id", "invalid"),
    ],
)
async def test_a_bad_query_is_a_400_without_the_input(
    http: Http, url: str, params: Any, field: str, reason: str
) -> None:
    status, body = await http.get(URLS[url], params=params)
    assert status == 400
    assert body == {
        "message": "The request is not valid",
        "code": "invalid_request",
        "details": {"field": field, "reason": reason},
    }
    assert "script" not in http.texts[-1] and "hacked" not in http.texts[-1]


async def test_actions_filters_and_paging(world: World, http: Http) -> None:
    world.open("inc-1", router=E1)
    world.clock.now += 10
    world.open("inc-2", router=E2)
    world.clock.now += 10
    world.resolve("inc-1")
    status, body = await http.get(URLS["actions"])
    assert status == 200 and body["total"] == 2
    assert body["limit"] == hv.LIMIT_DEFAULT and body["offset"] == 0
    newest, oldest = body["actions"]
    assert newest["incident_id"] == "inc-2" and oldest["incident_id"] == "inc-1"
    assert oldest["state"] == "cancelled" and oldest["terminal"] is True
    assert newest == {
        "action_id": world.of("inc-2").action_id,
        "router_id": R2,
        "state": "proposed",
        "terminal": False,
        "created_at": world.of("inc-2").created_at,
        "updated_at": world.of("inc-2").updated_at,
        "action_type": "observe.evaluate",
        "incident_id": "inc-2",
        "incident_type": "dns_failure",
        "incident_reopen": 0,
        "cause_code": None,
        "cause_level": None,
        "decision": "insufficient_evidence",
        "risk_class": 3,
        "flags": world.of("inc-2").flags.to_dict(),
    }
    _, body = await http.get(URLS["actions"], params={"router_id": R1})
    assert [a["incident_id"] for a in body["actions"]] == ["inc-1"]
    _, body = await http.get(URLS["actions"], params={"open": "1"})
    assert [a["incident_id"] for a in body["actions"]] == ["inc-2"]
    _, body = await http.get(URLS["actions"], params={"open": "0"})
    assert [a["incident_id"] for a in body["actions"]] == ["inc-1"]
    _, body = await http.get(URLS["actions"], params={"state": "cancelled,proposed"})
    assert body["total"] == 2
    _, body = await http.get(URLS["actions"], params={"limit": "1", "offset": "1"})
    assert body["total"] == 2 and [a["incident_id"] for a in body["actions"]] == [
        "inc-1"
    ]
    _, body = await http.get(URLS["actions"], params={"offset": "5"})
    assert body["actions"] == []


async def test_action_detail_with_history(world: World, http: Http) -> None:
    world.open("inc-1")
    record = world.of("inc-1")
    status, body = await http.get(detail_url(record.action_id))
    assert status == 200
    assert body["action"] == json.loads(json.dumps(record.to_dict()))
    assert [h["to_state"] for h in body["action"]["history"]] == [
        "detected",
        "analyzed",
        "proposed",
    ]
    assert body["router_hold"] is None and body["effective_mode"] == "observe"
    status, body = await http.get(detail_url("rem_" + "f" * 32))
    assert status == 404 and body["code"] == "unknown_action"
    status, body = await http.get(detail_url("not-an-id"))
    assert status == 400 and body["details"] == {
        "field": "action_id",
        "reason": "invalid",
    }
    status, _ = await http.get(detail_url(record.action_id), params={"x": "1"})
    assert status == 400


async def test_settings_route(world: World, http: Http) -> None:
    status, body = await http.get(URLS["settings"])
    assert status == 200
    assert body["module_switch"] is True
    assert body["release_mode"] == "observe_only" and body["write_path"] is False
    assert body["settings"] == world.engine.store.settings.to_dict()
    assert body["settings"]["enabled"] is True
    assert body["limits"]["max_open_per_router"] >= 1


async def test_plans_are_read_only(world: World, http: Http, disks: FakeDisks) -> None:
    """``plans`` asks the decision interface and changes nothing."""
    world.open("inc-1", router=E1)
    world.open("inc-2", router=E2)
    store = world.engine.store
    store.schedule = lambda *a, **kw: pytest.fail("plans wrote")  # type: ignore[method-assign]
    before = {aid: a.to_dict() for aid, a in store.actions.items()}
    loop_before = (
        dict(store.loop.attempts),
        dict(store.loop.locks),
        dict(store.loop.holds),
        dict(store.loop.idempotency),
    )
    status, body = await http.get(URLS["plans"])
    assert status == 200 and body["write_path"] is False
    assert len(body["plans"]) == 2
    for plan in body["plans"]:
        assert plan["executable"] is False
        assert "no_write_path" in plan["blockers"]
        assert plan["decision"]["outcome"] == "insufficient_evidence"
    _, body = await http.get(URLS["plans"], params={"router_id": R2})
    assert [p["incident_id"] for p in body["plans"]] == ["inc-2"]
    record = world.of("inc-1")
    _, body = await http.get(URLS["plans"], params={"action_id": record.action_id})
    assert [p["action_id"] for p in body["plans"]] == [record.action_id]
    status, _ = await http.get(URLS["plans"], params={"action_id": "rem_" + "a" * 32})
    assert status == 404
    assert {aid: a.to_dict() for aid, a in store.actions.items()} == before
    assert loop_before == (
        dict(store.loop.attempts),
        dict(store.loop.locks),
        dict(store.loop.holds),
        dict(store.loop.idempotency),
    )
    world.hass.services.async_call.assert_not_called()
    assert world.hass.fired == []


async def test_router_strings_are_returned_as_data(world: World, http: Http) -> None:
    """Strings from outside reach a body only as JSON data, and only when
    the model accepts them as codes; anything else makes no record."""
    nasty = "<img src=x onerror=1>"
    world.open("inc-1", type=nasty, cause=nasty, cause_status="confirmed")
    assert world.engine.counters["refused_invalid"] == 1
    world.open("inc-2", router=E2, type="wan_down", cause="dns_upstream")
    status, body = await http.get(URLS["actions"])
    assert status == 200
    [row] = body["actions"]
    assert row["incident_type"] == "wan_down" and row["cause_code"] == "dns_upstream"
    assert all(nasty not in text for text in http.texts)


async def test_a_failure_is_a_masked_500(world: World, http: Http) -> None:
    def boom(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError(SECRET)

    world.engine.router_ids = boom  # type: ignore[method-assign]
    status, body = await http.get(URLS["overview"])
    assert status == 500
    assert body == {"message": "The request failed", "code": "internal", "details": {}}
