"""HTTP routes of the Security Center (release 1.46.0 part 2).

A real aiohttp application with HA's own view plumbing
(``HomeAssistantView.register``: 401 without login) and the fake login
middleware of ``test_config_views`` (header ``X-Test-User``). The center
runs on in-memory stores; the write tests use the enterprise core on
FakeDisks (``cm_env``). No Home Assistant instance, no router.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from config_manager_kit import cm_env, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import ADMIN_ID, USER_ID, FakeDisks, add_users
from homeassistant.components.http import KEY_HASS_USER
from homeassistant.helpers.http import KEY_AUTHENTICATED, KEY_HASS
from test_net_engine import FakeDisk, make_hass
from test_security_center import (
    M1,
    M2,
    NO_SCHEDULE,
    RID1,
    T0,
    _core_center,
    center_for,
    coordinator,
    disks,  # noqa: F401 - fixture
    security_event,
)

from custom_components.openwrt_router import security_center
from custom_components.openwrt_router import security_views as sv
from custom_components.openwrt_router.const import DATA_SECURITY_VIEWS_BOUND
from custom_components.openwrt_router.security_center import (
    async_release_security_center,
    async_setup_security_center,
)
from custom_components.openwrt_router.topology_panel import (
    _PANEL_ACCESS_KEY,
    _PANEL_VIEW_DISABLED_KEY,
)

SECRETS = (M1, M2, M1.lower(), M2.lower(), "192.0.2.10", "Laptop")


@pytest.fixture
def core_disks() -> Any:
    with FakeDisks().patch() as fake:
        yield fake


def users(hass: Any) -> Any:
    """hass.auth with an admin and a plain user (make_hass has none)."""
    hass.is_stopping = False  # HA's view wrapper answers 503 while stopping
    if not isinstance(getattr(hass, "users", None), dict):
        hass.users = {}
        hass.auth.async_get_user = AsyncMock(side_effect=hass.users.get)
        add_users(hass)
    return hass


class Http:
    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.bodies: list[bytes] = []

    async def call(
        self,
        method: str,
        path: str,
        *,
        user: str | None = ADMIN_ID,
        body: Any = None,
        raw: Any = None,
        params: Any = None,
    ) -> Any:
        headers = {"X-Test-User": user} if user else {}
        kwargs: dict[str, Any] = {}
        if body is not None:
            kwargs["json"] = body
        if raw is not None:
            kwargs["data"] = raw
        resp = await self.client.request(
            method.upper(), sv.BASE_URL + path, headers=headers, params=params, **kwargs
        )
        data = await resp.read()
        self.bodies.append(data)
        return SimpleNamespace(
            status=resp.status,
            headers=resp.headers,
            body=data,
            data=json.loads(data) if data[:1] in (b"{", b"[") else None,
        )

    async def get(self, path: str, **kw: Any) -> Any:
        return await self.call("get", path, **kw)

    async def post(self, path: str, **kw: Any) -> Any:
        return await self.call("post", path, **kw)

    def assert_no_secret(self, *needles: str) -> None:
        for needle in needles:
            for body in self.bodies:
                assert needle.encode() not in body, (needle, body[:300])


def _auth_middleware(hass: Any) -> Any:
    @web.middleware
    async def middleware(request: web.Request, handler: Any) -> Any:
        user_id = request.headers.get("X-Test-User")
        if user_id:
            request[KEY_AUTHENTICATED] = True
            request[KEY_HASS_USER] = hass.users.get(user_id)
        return await handler(request)

    return middleware


@asynccontextmanager
async def http(hass: Any) -> AsyncIterator[Http]:
    app = web.Application(middlewares=[_auth_middleware(hass)])
    app[KEY_HASS] = hass
    for view_class in sv.SECURITY_VIEWS:
        view_class().register(hass, app, app.router)
    async with TestClient(TestServer(app)) as client:
        yield Http(client)


INCIDENT = "sec_" + "a" * 16
ROUTES: tuple[tuple[str, str], ...] = (
    ("get", "/overview"),
    ("get", f"/incidents/{INCIDENT}"),
    ("post", f"/incidents/{INCIDENT}/status"),
    ("get", "/detections"),
    ("get", "/settings"),
    ("post", "/settings"),
    ("post", "/devices/confirm"),
    ("post", "/devices/name"),
)
WRITES = [(m, p) for m, p in ROUTES if m == "post"]
READS = [(m, p) for m, p in ROUTES if m == "get"]


async def seeded_center(hass: Any, *, enabled: bool = True) -> Any:
    """A center with a device (M1, named) and one own incident."""
    center = await center_for(hass, "r1", enabled=enabled)
    center.trust.observe(
        SimpleNamespace(mac=M1, private_mac=None, ip="192.0.2.10", hostname="pc"),
        T0,
    )
    center.trust.set_name(M1, "Laptop")
    center._record(security_event("wifi_assoc_burst", T0), T0)
    return center


def test_every_route_is_listed_once_and_needs_auth() -> None:
    names = [v.name for v in sv.SECURITY_VIEWS]
    assert len(names) == len(set(names)) == 7
    for view in sv.SECURITY_VIEWS:
        assert view.requires_auth is True
        assert view.url.startswith(sv.BASE_URL)
    covered = {(m, sv.BASE_URL + p) for m, p in ROUTES}
    assert len(covered) == 8


# --- access ---------------------------------------------------------------------------


async def test_no_route_answers_without_login(disks) -> None:  # noqa: F811
    hass = users(make_hass())
    await seeded_center(hass)
    async with http(hass) as h:
        for method, path in ROUTES:
            resp = await h.call(method, path, user=None, body={"status": "resolved"})
            assert resp.status == 401, (method, path)
    h.assert_no_secret(*SECRETS, "Laptop", RID1)


async def test_non_admin_writes_are_403_before_the_body_is_read(
    disks,  # noqa: F811
) -> None:
    hass = users(make_hass())
    center = await seeded_center(hass)
    hass.data[_PANEL_ACCESS_KEY] = {"e1": True}  # open panel: still no writes
    settings = dict(center.settings)
    with patch.object(sv, "read_body", AsyncMock(side_effect=AssertionError)):
        async with http(hass) as h:
            for method, path in WRITES:
                resp = await h.call(method, path, user=USER_ID, body={"enabled": False})
                assert resp.status == 403, path
                assert resp.data["code"] == "authorization_denied"
    assert center.settings == settings and center.enabled


async def test_non_admin_reads_only_with_an_open_panel_and_sees_pseudonyms(
    disks,  # noqa: F811
) -> None:
    hass = users(make_hass())
    center = await seeded_center(hass)
    center.settings = security_center.merge_settings(
        center.settings, {"subnet_zones": {"192.168.20.0/24": "iot"}}
    )
    async with http(hass) as h:
        for method, path in READS:
            resp = await h.call(method, path, user=USER_ID)
            assert resp.status == 403, path
        hass.data[_PANEL_ACCESS_KEY] = {"e1": True}
        overview = await h.get("/overview", user=USER_ID)
        assert overview.status == 200
        assert overview.headers["Cache-Control"] == "no-store"
        assert overview.data["admin_view"] is False
        settings = await h.get("/settings", user=USER_ID)
        assert settings.data["settings"]["subnet_zones"] == {}
        assert settings.data["subnet_zone_count"] == 1
        assert settings.data["can_edit"] is False
        assert (await h.get("/detections", user=USER_ID)).status == 200
    h.assert_no_secret(*SECRETS, "192.168.20.0", '"pc"')


async def test_unknown_user_is_403(disks) -> None:  # noqa: F811
    hass = users(make_hass())
    await seeded_center(hass)
    async with http(hass) as h:
        resp = await h.get("/overview", user="nobody")
    assert resp.status == 403


async def test_unloaded_integration_is_410_and_missing_center_503(
    disks,  # noqa: F811
) -> None:
    hass = users(make_hass())
    async with http(hass) as h:
        assert (await h.get("/overview")).status == 503
        center = await seeded_center(hass)
        hass.data[_PANEL_VIEW_DISABLED_KEY] = True
        for method, path in ROUTES:
            resp = await h.call(method, path, body={"status": "resolved"})
            assert resp.status == 410, path
        hass.data[_PANEL_VIEW_DISABLED_KEY] = False
        center.loaded = False
        assert (await h.get("/overview")).status == 503
    h.assert_no_secret(*SECRETS)


# --- input validation -------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "nope=1",
        "since=abc",
        "since=nan",
        "since=-1",
        "since=99999999999",
        "since=20&until=10",
        "limit=0",
        "limit=501",
        "limit=1e3",
        "severity=high",
        "category=everything",
        "client=not-a-mac",
        "router_id=../../etc",
        "limit=5&limit=6",
    ],
)
async def test_bad_overview_queries_are_400(disks, query: str) -> None:  # noqa: F811
    hass = users(make_hass())
    await seeded_center(hass)
    async with http(hass) as h:
        resp = await h.get(f"/overview?{query}")
    assert resp.status == 400, query
    assert resp.data["code"] == "invalid_request"
    assert set(resp.data) == {"message", "code", "details"}


async def test_good_overview_filters_pass(disks) -> None:  # noqa: F811
    hass = users(make_hass())
    await seeded_center(hass)
    async with http(hass) as h:
        resp = await h.get(
            "/overview",
            params={
                "since": "0",
                "until": str(T0 + 10),
                "limit": "5",
                "severity": "warning",
                "router_id": RID1,
                "client": M1,
            },
        )
    assert resp.status == 200
    assert len(resp.data["timeline"]) <= 5


async def test_bad_paths_and_unknown_ids(disks) -> None:  # noqa: F811
    hass = users(make_hass())
    await seeded_center(hass)
    async with http(hass) as h:
        assert (await h.get("/incidents/not_an_id")).status == 400
        assert (await h.get(f"/incidents/{INCIDENT}")).status == 404
        assert (await h.get(f"/incidents/{INCIDENT}?x=1")).status == 400
        assert (await h.get("/detections?x=1")).status == 400
        assert (await h.get("/settings?x=1")).status == 400
        resp = await h.post("/devices/confirm", body={"mac": "zz:zz"})
        assert resp.status == 400 and resp.data["details"]["field"] == "mac"
        resp = await h.post("/devices/confirm?mac=x", body={"mac": M1})
        assert resp.status == 400 and resp.data["details"]["field"] == "query"


# Both fit in 4 KiB. Whether the parser gives up (RecursionError) or the
# depth check refuses it, deep nesting is a 400 and never a 500.
DEEP_LIST = "[" * 2000 + "]" * 2000
DEEP_OBJECT = '{"a":' * 600 + "1" + "}" * 600


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"not json", "not_json"),
        (b"\xff\xfe", "not_json"),
        (DEEP_LIST.encode(), ("invalid_body", "not_an_object")),
        (DEEP_OBJECT.encode(), ("invalid_body", "too_deep")),
        (b"[1, 2]", "not_an_object"),
        (b'{"thresholds": {"a": {"b": {"c": 1}}}}', "too_deep"),
        (b'{"enabled": true, "admin": true}', "unknown_key"),
        (b"{}", "empty"),
        (b'{"enabled": "yes"}', "invalid"),
        (b'{"syslog_port": 80}', "out_of_range"),
        (b'{"syslog_port": 5514.5}', "invalid"),
        (b'{"syslog_port": true}', "invalid"),
        (b'{"log_path": "ftp"}', "invalid"),
        (b'{"thresholds": {"wifi_auth_repeat": -1}}', "out_of_range"),
        (b'{"thresholds": {"wifi_auth_repeat": 1e999}}', "out_of_range"),
        (b'{"subnet_zones": {"192.168.1.0/24": "a b"}}', "value"),
    ],
    ids=lambda v: v[:24].decode("utf-8", "replace") if isinstance(v, bytes) else None,
)
async def test_bad_settings_bodies_are_400(
    disks,  # noqa: F811
    body: bytes,
    reason: str | tuple[str, ...],
) -> None:
    hass = users(make_hass())
    center = await seeded_center(hass)
    before = dict(center.settings)
    async with http(hass) as h:
        resp = await h.post("/settings", raw=body)
    assert resp.status == 400, (body[:40], resp.body)
    accepted = reason if isinstance(reason, tuple) else (reason,)
    assert resp.data["details"].get("reason") in accepted
    assert center.settings == before


async def test_large_bodies_are_413(disks) -> None:  # noqa: F811
    hass = users(make_hass())
    await seeded_center(hass)
    big = json.dumps({"subnet_zones": {f"10.{i}.0.0/16": "x" * 30 for i in range(200)}})
    assert len(big) > sv.BODY_MAX_BYTES

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(10):
            yield b" " * 1000

    async with http(hass) as h:
        assert (await h.post("/settings", raw=big.encode())).status == 413
        assert (await h.post("/settings", raw=chunks())).status == 413  # no length


async def test_semantic_settings_error_is_400_without_internals(
    disks,  # noqa: F811
) -> None:
    hass = users(make_hass())
    await seeded_center(hass)
    async with http(hass) as h:
        # passes the route's shape check, refused by the center's schema
        resp = await h.post("/settings", body={"thresholds": {"no_such_detector": 3}})
    assert resp.status == 400
    assert resp.data["details"] == {"reason": "invalid_settings"}
    assert "no_such_detector" not in resp.body.decode()


# --- errors never leave anything ---------------------------------------------------------


async def test_a_throwing_route_is_500_without_text(
    disks,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass = users(make_hass())
    center = await seeded_center(hass)
    with patch.object(
        type(center), "overview", side_effect=RuntimeError(f"boom {M1} 192.0.2.10")
    ):
        async with http(hass) as h:
            resp = await h.get("/overview")
    assert resp.status == 500
    assert resp.data == {
        "message": "The request failed",
        "code": "internal",
        "details": {},
    }
    h.assert_no_secret(*SECRETS, "boom", "Traceback")
    for record in caplog.records:
        if record.levelno >= 30:
            assert M1 not in record.getMessage()


async def test_off_center_refuses_actions_with_409(disks) -> None:  # noqa: F811
    hass = users(make_hass())
    await seeded_center(hass, enabled=False)
    async with http(hass) as h:
        resp = await h.post("/devices/confirm", body={"mac": M1})
        assert resp.status == 409 and resp.data["code"] == "disabled"
        # reading the settings works while off (the switch lives there)
        resp = await h.get("/settings")
        assert resp.status == 200 and resp.data["settings"]["enabled"] is False


async def test_routes_register_once_and_failures_never_fail_the_setup(
    disks,  # noqa: F811
) -> None:
    hass = make_hass()
    sv.async_register_security_views(hass)
    sv.async_register_security_views(hass)
    assert hass.http.register_view.call_count == len(sv.SECURITY_VIEWS)
    assert len(hass.data[DATA_SECURITY_VIEWS_BOUND]) == len(sv.SECURITY_VIEWS)

    hass = make_hass()
    with patch.object(
        sv, "async_register_security_views", MagicMock(side_effect=RuntimeError("x"))
    ):
        center = await async_setup_security_center(
            hass, SimpleNamespace(entry_id="r1"), coordinator()
        )
    assert center is not None and center.loaded
    assert center.counters["errors"] >= 1
    await async_release_security_center(hass, "r1")


# --- admin writes with the core ----------------------------------------------------------


async def test_admin_writes_go_through_the_center(core_disks, tmp_path) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    center = await _core_center(env, FakeDisk(), enabled=False)
    hass = env.hass
    async with http(hass) as h:
        resp = await h.post(
            "/settings", body={"enabled": True, "log_path": "collector"}
        )
        assert resp.status == 200, resp.body
        assert resp.data["settings"]["enabled"] is True and center.active
        assert resp.data["can_edit"] is True

        center.trust.observe(
            SimpleNamespace(mac=M1, private_mac=None, ip="192.0.2.10"), T0
        )
        resp = await h.post(
            "/devices/confirm", body={"mac": M1.lower(), "name": "Laptop"}
        )
        assert resp.status == 200 and resp.data == {"confirmed": True}
        assert center.trust.get(M1).name == "Laptop"
        resp = await h.post("/devices/name", body={"mac": M1, "name": None})
        assert resp.status == 200 and resp.data == {"named": False}
        assert (await h.post("/devices/name", body={"mac": M1})).status == 400
        unknown = await h.post("/devices/name", body={"mac": M2, "name": "x"})
        assert unknown.status == 404
        bad = await h.post("/devices/name", body={"mac": M1, "name": "a\nb"})
        assert bad.status == 400

        center._record(security_event("wifi_assoc_burst", T0, router_id=env.rid), T0)
        inc_id = next(iter(center.incidents))
        resp = await h.post(f"/incidents/{inc_id}/status", body={"status": "resolved"})
        assert resp.status == 200 and resp.data["incident"]["status"] == "resolved"
        bad = await h.post(f"/incidents/{inc_id}/status", body={"status": "deleted"})
        assert bad.status == 400
        detail = await h.get(f"/incidents/{inc_id}")
        assert detail.status == 200 and detail.data["incident"]["id"] == inc_id

        # a second admin is still an admin; a plain user is not
        denied = await h.post("/settings", user=USER_ID, body={"enabled": False})
        assert denied.status == 403 and center.enabled
    h.assert_no_secret("192.0.2.10", ADMIN_ID, USER_ID)
    await stop(env)
    await async_release_security_center(hass, env.entries[0].entry_id)
