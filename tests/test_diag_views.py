"""HTTP routes of the network diagnostics (release 1.47.0, part 2).

A real aiohttp application with HA's own view plumbing
(``HomeAssistantView.register``: 401 without login) and the fake login
middleware of ``test_security_views`` (header ``X-Test-User``). The module
runs on the in-memory store fakes of ``test_diag_runtime``; the end-to-end
test uses the enterprise core on FakeDisks (``cm_env``) and loopback probe
servers. No Home Assistant instance, no router, no real network.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from config_manager_kit import cm_env
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import ADMIN_ID, USER_ID, add_users, make_hass
from homeassistant.helpers.http import KEY_HASS
from test_diag_runtime import (
    GLOBAL_IP,
    RID1,
    RID2,
    T0,
    core_diag,
    core_disks,  # noqa: F401 - fixture
    disk,  # noqa: F401 - fixture
    facts,
    loopback,
    make_diag,
    poll,
    release_all,
    target,
    tcp_server,
    wan_status,
)
from test_security_views import _auth_middleware

from custom_components.openwrt_router import diag_runtime
from custom_components.openwrt_router import diag_views as dv
from custom_components.openwrt_router.const import DATA_DIAG_VIEWS_BOUND
from custom_components.openwrt_router.core_errors import (
    AuthorizationError,
    ConfigApiError,
    ErrorClass,
    RateLimitedError,
    SafetyRefusedError,
)
from custom_components.openwrt_router.diag_core import EVENT_MANUAL_RUN
from custom_components.openwrt_router.diag_runtime import NetDiagnostics
from custom_components.openwrt_router.diag_scheduler import Outcome
from custom_components.openwrt_router.topology_panel import (
    _PANEL_ACCESS_KEY,
    _PANEL_VIEW_DISABLED_KEY,
)

# addresses of the fixtures (gateway, WAN, DNS, external target)
SECRETS = ("192.0.2.", "203.0.113.", GLOBAL_IP)

ROUTES: tuple[tuple[str, str], ...] = (
    ("get", "/overview"),
    ("get", "/history"),
    ("get", "/details"),
    ("get", "/settings"),
    ("post", "/settings"),
    ("post", "/run"),
)
WRITES = [(m, p) for m, p in ROUTES if m == "post"]
READS = [(m, p) for m, p in ROUTES if m == "get"]
PANEL_READS = [("get", "/overview"), ("get", "/history"), ("get", "/details")]


def with_users(hass: Any) -> Any:
    hass.is_stopping = False  # HA's view wrapper answers 503 while stopping
    if ADMIN_ID not in hass.users:
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
            method.upper(), dv.BASE_URL + path, headers=headers, params=params, **kwargs
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


@asynccontextmanager
async def http(hass: Any) -> AsyncIterator[Http]:
    app = web.Application(middlewares=[_auth_middleware(hass)])
    app[KEY_HASS] = hass
    for view_class in dv.DIAG_VIEWS:
        view_class().register(hass, app, app.router)
    async with TestClient(TestServer(app)) as client:
        yield Http(client)


async def module(*, enabled: bool = True) -> tuple[Any, NetDiagnostics]:
    """A module for r1 (no core) with a WAN-down finding of the router."""
    hass = with_users(make_hass())
    diag = await make_diag(hass, "r1", enabled=enabled)
    poll(diag, "r1", T0, uptime=5000, wan_status=wan_status(connected=False))
    return hass, diag


# --- the route list -------------------------------------------------------------------


def test_every_route_is_listed_once_and_needs_auth() -> None:
    names = [v.name for v in dv.DIAG_VIEWS]
    assert len(names) == len(set(names)) == 5
    methods: set[tuple[str, str]] = set()
    for view in dv.DIAG_VIEWS:
        assert view.requires_auth is True
        assert view.url.startswith(dv.BASE_URL + "/")
        for method in ("get", "post", "put", "patch", "delete"):
            if callable(getattr(view, method, None)):
                methods.add((method, view.url[len(dv.BASE_URL) :]))
    assert methods == set(ROUTES)
    # administrators only: settings (also reading) and the manual run
    admin_only = {v.url[len(dv.BASE_URL) :] for v in dv.DIAG_VIEWS if v.admin_only}
    assert admin_only == {"/settings", "/run"}
    assert [v.url for v in dv.DIAG_VIEWS if v.needs_on] == [dv.BASE_URL + "/run"]


def test_routes_register_once_and_without_http_server_not_at_all() -> None:
    hass = make_hass()
    dv.async_register_diag_views(hass)
    dv.async_register_diag_views(hass)
    assert hass.http.register_view.call_count == len(dv.DIAG_VIEWS)
    assert len(hass.data[DATA_DIAG_VIEWS_BOUND]) == len(dv.DIAG_VIEWS)
    hass = make_hass()
    hass.http = None
    dv.async_register_diag_views(hass)
    assert DATA_DIAG_VIEWS_BOUND not in hass.data


# --- access ---------------------------------------------------------------------------


async def test_no_route_answers_without_login(disk) -> None:  # noqa: F811
    hass, _diag = await module()
    async with http(hass) as h:
        for method, path in ROUTES:
            resp = await h.call(method, path, user=None, body={"enabled": False})
            assert resp.status == 401, (method, path)
    h.assert_no_secret(*SECRETS, RID1)


async def test_non_admin_is_403_before_the_switch_and_before_the_body(
    disk,  # noqa: F811
) -> None:
    hass, diag = await module()
    hass.data[_PANEL_ACCESS_KEY] = {"e1": True}  # open panel: still no writes
    settings = json.dumps(diag.settings, sort_keys=True)
    with (
        patch.object(dv, "read_body", AsyncMock(side_effect=AssertionError)),
        patch.object(
            diag_runtime,
            "async_get_net_diagnostics",
            MagicMock(side_effect=AssertionError),
        ),
    ):
        async with http(hass) as h:
            for method, path in [*WRITES, ("get", "/settings")]:
                resp = await h.call(method, path, user=USER_ID, body={"enabled": False})
                assert resp.status == 403, (method, path)
                assert resp.data["code"] == "authorization_denied"
                assert resp.headers["Cache-Control"] == "no-store"
    assert json.dumps(diag.settings, sort_keys=True) == settings and diag.enabled


async def test_non_admin_reads_only_with_an_open_panel_and_only_brief(
    disk,  # noqa: F811
) -> None:
    hass, _diag = await module()
    async with http(hass) as h:
        for method, path in READS:
            resp = await h.call(method, path, user=USER_ID)
            assert resp.status == 403, path
        hass.data[_PANEL_ACCESS_KEY] = {"e1": True}
        overview = await h.get("/overview", user=USER_ID)
        assert overview.status == 200, overview.body
        assert overview.headers["Cache-Control"] == "no-store"
        assert overview.data["routers"][RID1]["finding"] is not None
        assert (await h.get("/history", user=USER_ID)).status == 200
        detail = await h.get("/details", user=USER_ID, params={"router_id": RID1})
        assert detail.status == 200
        assert detail.data["detail"] == "brief"
        assert "down_interfaces" not in detail.data
        # still no settings for a plain user, not even reading them
        assert (await h.get("/settings", user=USER_ID)).status == 403
    h.assert_no_secret(*SECRETS)


async def test_unknown_user_is_403(disk) -> None:  # noqa: F811
    hass, _diag = await module()
    async with http(hass) as h:
        assert (await h.get("/overview", user="nobody")).status == 403


async def test_unloaded_integration_is_410_and_missing_module_503(
    disk,  # noqa: F811
) -> None:
    hass = with_users(make_hass())
    async with http(hass) as h:
        assert (await h.get("/overview")).status == 503
        diag = await make_diag(hass, "r1")
        hass.data[_PANEL_VIEW_DISABLED_KEY] = True
        for method, path in ROUTES:
            resp = await h.call(method, path, body={"target_ids": ["t1"]})
            assert resp.status == 410, path
        hass.data[_PANEL_VIEW_DISABLED_KEY] = False
        diag.loaded = False
        resp = await h.get("/overview")
        assert resp.status == 503 and resp.data["code"] == "not_running"


async def test_module_off_answers_with_state_off(disk) -> None:  # noqa: F811
    hass, diag = await module(enabled=False)
    assert not diag.active
    run = AsyncMock()
    with patch.object(NetDiagnostics, "async_run_manual", run):
        async with http(hass) as h:
            overview = await h.get("/overview")
            assert overview.status == 200 and overview.data["state"] == "off"
            assert overview.data["fleet"] is None
            history = await h.get("/history")
            assert history.status == 200 and history.data["state"] == "off"
            detail = await h.get("/details", params={"router_id": RID1})
            assert detail.status == 200 and detail.data["state"] == "off"
            settings = await h.get("/settings")
            assert settings.status == 200 and settings.data["state"] == "off"
            assert settings.data["settings"]["enabled"] is False
            resp = await h.post("/run", body={"target_ids": ["t1"]})
            assert resp.status == 409
            assert resp.data["code"] == "disabled" and resp.data["state"] == "off"
    run.assert_not_called()


# --- input validation -------------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        {"x": "1"},
        {"router_id": "r1"},
        {"router_id": "192.0.2.1"},
        {"router_id": RID1, "x": "1"},
    ],
)
async def test_bad_detail_queries_are_400(disk, query: dict[str, str]) -> None:  # noqa: F811
    hass, _diag = await module()
    async with http(hass) as h:
        resp = await h.get("/details", params=query)
        assert resp.status == 400, resp.body
        assert (await h.get("/overview", params={"x": "1"})).status == 400
        assert (await h.get("/history", params={"x": "1"})).status == 400
    h.assert_no_secret("192.0.2.1")


async def test_unknown_router_is_404_and_no_router_is_the_ha_point(
    disk,  # noqa: F811
) -> None:
    hass, _diag = await module()
    async with http(hass) as h:
        resp = await h.get("/details", params={"router_id": RID2})
        assert resp.status == 404 and resp.data["code"] == "unknown_router"
        ha = await h.get("/details")
        assert ha.status == 200 and ha.data["router_id"] is None
        # an admin without the core: no sensitive read, so no detail
        assert ha.data["detail"] == "core_unavailable"
    h.assert_no_secret(*SECRETS)


# Both fit in 8 KiB. Whether the parser gives up (RecursionError) or the
# depth check refuses it, deep nesting is a 400 and never a 500.
DEEP_LIST = "[" * 2000 + "]" * 2000
DEEP_OBJECT = '{"a":' * 600 + "1" + "}" * 600
UNCLOSED = "[" * 8000


@pytest.mark.parametrize(
    ("path", "body", "reason"),
    [
        ("/run", b"not json", "not_json"),
        ("/run", b"\xff\xfe", "not_json"),
        ("/run", DEEP_LIST.encode(), ("invalid_body", "not_an_object")),
        ("/run", DEEP_OBJECT.encode(), ("invalid_body", "too_deep")),
        ("/run", UNCLOSED.encode(), ("invalid_body", "not_json")),
        ("/run", b"[1, 2]", "not_an_object"),
        ("/run", b'{"target_ids": ["t1"], "host": "9.9.9.9"}', "unknown_key"),
        ("/run", b'{"target_ids": ["9.9.9.9"]}', "invalid_id"),
        ("/run", b'{"target_ids": "t1"}', "invalid"),
        ("/run", b'{"target_ids": []}', "invalid"),
        ("/run", json.dumps({"target_ids": ["t"] * 17}).encode(), "invalid"),
        ("/settings", b'{"targets": [{"a": {"b": 1}}]}', "too_deep"),
        ("/settings", b'{"enabled": true, "admin": true}', "unknown_key"),
        ("/settings", b"{}", "empty"),
        ("/settings", b'{"interval_s": 1}', None),
    ],
    ids=lambda v: v[:24].decode("utf-8", "replace") if isinstance(v, bytes) else None,
)
async def test_bad_bodies_are_400_without_the_input(
    disk,  # noqa: F811
    path: str,
    body: bytes,
    reason: str | tuple[str, ...] | None,
) -> None:
    hass, diag = await module()
    assert diag.active
    settings = json.dumps(diag.settings, sort_keys=True)
    run = AsyncMock()
    with patch.object(NetDiagnostics, "async_run_manual", run):
        async with http(hass) as h:
            resp = await h.post(path, raw=body)
    assert resp.status == 400, (body[:40], resp.body)
    if reason is not None:
        accepted = reason if isinstance(reason, tuple) else (reason,)
        assert resp.data["details"].get("reason") in accepted
    run.assert_not_called()
    assert json.dumps(diag.settings, sort_keys=True) == settings
    h.assert_no_secret(GLOBAL_IP, "admin", 'interval_s":')


async def test_large_bodies_are_413(disk) -> None:  # noqa: F811
    hass, _diag = await module()
    big = json.dumps({"target_ids": ["x" * 60] * 200})
    assert len(big) > dv.BODY_MAX_BYTES

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(10):
            yield b" " * 1000

    run = AsyncMock()
    with patch.object(NetDiagnostics, "async_run_manual", run):
        async with http(hass) as h:
            assert (await h.post("/run", raw=big.encode())).status == 413
            assert (await h.post("/run", raw=chunks())).status == 413  # no length
            assert (await h.post("/settings", raw=big.encode())).status == 413
    run.assert_not_called()


# --- core errors -------------------------------------------------------------------------


async def test_core_authorization_error_is_403_never_500(disk) -> None:  # noqa: F811
    hass, _diag = await module()
    denied = AuthorizationError(
        f"denied for {GLOBAL_IP}", details={"reason": "not_admin"}
    )
    approval = ConfigApiError("x", error_class=ErrorClass.APPROVAL)
    with (
        patch.object(NetDiagnostics, "async_run_manual", AsyncMock(side_effect=denied)),
        patch.object(
            NetDiagnostics, "async_update_settings", AsyncMock(side_effect=approval)
        ),
        patch.object(NetDiagnostics, "async_detail", AsyncMock(side_effect=denied)),
    ):
        async with http(hass) as h:
            for method, path in (
                ("post", "/run"),
                ("post", "/settings"),
                ("get", "/details"),
            ):
                body = {"target_ids": ["t1"]} if path == "/run" else {"enabled": True}
                resp = await h.call(method, path, body=body)
                assert resp.status == 403, (path, resp.body)
                assert resp.data["code"] == "authorization_denied"
    h.assert_no_secret(GLOBAL_IP, "not_admin")


@pytest.mark.parametrize(
    ("error", "retry_after"),
    [
        (RateLimitedError(f"limited {GLOBAL_IP}", retry_after=12.3), "13"),
        (RateLimitedError("limited", retry_after=0.0), "1"),
        # a module error of the rate limited class without the attribute
        (ConfigApiError("limited", error_class=ErrorClass.RATE_LIMITED), "1"),
    ],
)
async def test_rate_limited_is_429_with_retry_after(
    disk,  # noqa: F811
    error: ConfigApiError,
    retry_after: str,
) -> None:
    hass, _diag = await module()
    with patch.object(NetDiagnostics, "async_run_manual", AsyncMock(side_effect=error)):
        async with http(hass) as h:
            resp = await h.post("/run", body={"target_ids": ["t1"]})
    assert resp.status == 429
    assert resp.headers["Retry-After"] == retry_after
    assert resp.data["code"] == "rate_limited"
    h.assert_no_secret(GLOBAL_IP)


async def test_safety_refusal_is_422_with_the_reason_and_without_the_input(
    disk,  # noqa: F811
) -> None:
    hass, _diag = await module()
    refused = SafetyRefusedError(
        f"Target secret-target-77 ({GLOBAL_IP}) refused",
        reason="target.not_confirmed",
    )
    with patch.object(
        NetDiagnostics, "async_run_manual", AsyncMock(side_effect=refused)
    ):
        async with http(hass) as h:
            resp = await h.post("/run", body={"target_ids": ["secret-target-77"]})
    assert resp.status == 422
    assert resp.data == {
        "message": "The target was refused",
        "code": "refused",
        "details": {"reason": "target.not_confirmed"},
    }
    h.assert_no_secret(GLOBAL_IP, "secret-target-77")


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (ConfigApiError("x", error_class=ErrorClass.INVALID), 400, "invalid_request"),
        (
            ConfigApiError(
                "x",
                error_class=ErrorClass.NOT_FOUND,
                details={"reason": "target.unknown"},
            ),
            404,
            "unknown_target",
        ),
        (ConfigApiError("x", error_class=ErrorClass.BUSY), 409, "busy"),
        (
            ConfigApiError(
                "x",
                error_class=ErrorClass.NOT_AVAILABLE,
                details={"reason": "disabled"},
            ),
            409,
            "disabled",
        ),
        (
            ConfigApiError(
                "x",
                error_class=ErrorClass.NOT_AVAILABLE,
                details={"reason": "core_unavailable"},
            ),
            503,
            "no_core",
        ),
        (ConfigApiError("x"), 500, "internal"),
    ],
)
async def test_module_errors_map_to_fixed_codes(
    disk,  # noqa: F811
    error: ConfigApiError,
    status: int,
    code: str,
) -> None:
    hass, _diag = await module()
    with patch.object(NetDiagnostics, "async_run_manual", AsyncMock(side_effect=error)):
        async with http(hass) as h:
            resp = await h.post("/run", body={"target_ids": ["t1"]})
    assert resp.status == status and resp.data["code"] == code


async def test_a_throwing_route_is_500_without_text_and_logs_no_address(
    disk,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass, _diag = await module()
    caplog.set_level(logging.DEBUG)
    boom = RuntimeError(f"boom {GLOBAL_IP} 192.0.2.1 example.org")
    with patch.object(NetDiagnostics, "overview", side_effect=boom):
        async with http(hass) as h:
            resp = await h.get("/overview")
    assert resp.status == 500
    assert resp.data == {
        "message": "The request failed",
        "code": "internal",
        "details": {},
    }
    h.assert_no_secret(*SECRETS, "boom", "example.org", "Traceback")
    warnings = [r for r in caplog.records if r.levelno > logging.DEBUG]
    assert any("RuntimeError" in r.getMessage() for r in warnings)
    for record in warnings:
        text = record.getMessage() + str(record.exc_text or "")
        assert record.exc_info is None
        for needle in (*SECRETS, "example.org", "boom"):
            assert needle not in text


# --- end to end with the core ------------------------------------------------------------


async def test_e2e_route_manual_diagnosis(
    disk,  # noqa: F811
    core_disks,  # noqa: F811
    tmp_path,
) -> None:
    """Admin HTTP request -> guard -> run time -> loopback probe -> audit."""
    env = await cm_env(core_disks, tmp_path, options={})
    hass = with_users(env.hass)
    diag = await core_diag(env)
    seen: list[Any] = []
    async with tcp_server() as port, http(hass) as h:
        # off: the run is refused before the guard, without any packet
        off = await h.post("/run", body={"target_ids": ["t1"]})
        assert off.status == 409 and off.data["state"] == "off"
        # the switch and the target through the validated settings route
        resp = await h.post(
            "/settings", body={"enabled": True, "targets": [target("t1", "tcp", 443)]}
        )
        assert resp.status == 200, resp.body
        assert resp.data["settings"]["enabled"] is True and diag.active
        assert resp.data["settings"]["targets"][0]["id"] == "t1"
        assert "host" not in resp.data["settings"]["targets"][0]
        diag.transport = loopback({443: port}, seen)
        coord = env.coords[env.rid]  # one passive poll: the router is known
        coord.data.uptime = 5000
        coord.data.wan_status = wan_status()
        diag.on_poll(facts(env, T0))

        # a plain user: 403 at the route, no probe, no run event
        denied = await h.post("/run", user=USER_ID, body={"target_ids": ["t1"]})
        assert denied.status == 403 and seen == []
        assert not env.core.audit.events(types=[EVENT_MANUAL_RUN])
        assert diag.counters["probes"] == 0

        # an unknown or refused target: no packet either
        unknown = await h.post("/run", body={"target_ids": ["t9"]})
        assert unknown.status in (404, 422), unknown.body
        assert seen == []

        # the admin: guard -> run time -> loopback probe -> audit
        resp = await h.post("/run", body={"target_ids": ["t1"]})
        assert resp.status == 200, resp.body
        assert resp.data["status"] == Outcome.SUCCESS.value
        assert seen == [(GLOBAL_IP, 443)]
        runs = env.core.audit.events(types=[EVENT_MANUAL_RUN])
        accepted = [e for e in runs if e.data["status"] == "accepted"]
        assert len(accepted) == 1
        assert accepted[0].correlation_id == resp.data["correlation_id"]

        # the result is visible in the overview and the history
        overview = await h.get("/overview")
        assert overview.status == 200 and overview.data["last_run"] is not None
        history = await h.get("/history")
        assert any(s["target_id"] == "t1" for s in history.data["series"])
        assert history.data["windows"] == ["1h", "24h", "7d", "30d"]
        # the details: full for an admin after the core's sensitive read
        detail = await h.get("/details")
        assert detail.status == 200 and detail.data["detail"] == "full"
        detail = await h.get("/details", params={"router_id": env.rid})
        assert detail.status == 200 and detail.data["detail"] == "full"
        assert detail.data["context"] is not None
        # a plain user with an open panel: brief only
        hass.data[_PANEL_ACCESS_KEY] = {env.entries[0].entry_id: True}
        brief = await h.get("/details", user=USER_ID, params={"router_id": env.rid})
        assert brief.status == 200 and brief.data["detail"] == "brief"
    h.assert_no_secret(*SECRETS)
    stored = json.dumps([e.to_dict() for e in env.core.audit.events()], default=str)
    for secret in SECRETS:
        assert secret not in stored
    assert env.router_calls() == []  # no route talked to a router
    await release_all(env)
