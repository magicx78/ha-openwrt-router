"""HTTP routes of WiFi RF Intelligence (rf_views + rf_output, 1.48.0 part 1).

A real aiohttp application with HA's own view plumbing (401 without login)
and a fake login middleware (headers ``X-Test-User``, ``X-Test-Token`` for
the refresh token id). The RF center runs on the in-memory store with fake
poll data; the guard tests use the real Core ``ActionGuard`` (and one test
the whole enterprise core on FakeDisks). No router, no HA instance.
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
from config_manager_kit import cm_env, drain, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - fixture "tmp_path" (Windows path limit)
)
from core_testkit import ADMIN_ID, USER_ID, FakeDisks
from homeassistant.components.http import KEY_HASS_REFRESH_TOKEN_ID, KEY_HASS_USER
from homeassistant.helpers.http import KEY_AUTHENTICATED, KEY_HASS
from rf_center_kit import (
    MAC_A,
    MAC_B,
    RID1,
    FakeCoordinator,
    client,
    entry,
    new_center,
    options,
    poll,
    poll_data,
    rf_disk,
    rf_hass,
)
from test_security_views import users

from custom_components.openwrt_router import rf_views as rv
from custom_components.openwrt_router.config_api import GuardView
from custom_components.openwrt_router.const import (
    DATA_WIFI_RF_CENTER,
    DATA_WIFI_RF_VIEWS_BOUND,
)
from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_errors import AuthorizationError
from custom_components.openwrt_router.core_guard import ActionGuard
from custom_components.openwrt_router.rf_center import (
    _Binding,
    async_release_rf_center,
    async_setup_rf_center,
)
from custom_components.openwrt_router.topology_panel import (
    _PANEL_ACCESS_KEY,
    _PANEL_VIEW_DISABLED_KEY,
)

ROUTES = (
    "/overview",
    "/radios",
    "/channel_map",
    "/timeline",
    "/roaming",
    "/recommendations",
)
# The Core router id is the agreed identity (as in the Security Center routes);
# MACs, SSIDs and kernel interface names never leave the center.
SECRETS = (MAC_A, MAC_A.upper(), MAC_B, "example-ssid", "phy1-ap0")
QUERY = {"/timeline": {"window": "1h"}}


@pytest.fixture
def disk() -> Any:
    with rf_disk() as fake:
        yield fake


@pytest.fixture
def core_disks() -> Any:
    with FakeDisks().patch() as fake:
        yield fake


def _auth_middleware(hass: Any) -> Any:
    @web.middleware
    async def middleware(request: web.Request, handler: Any) -> Any:
        user_id = request.headers.get("X-Test-User")
        if user_id:
            request[KEY_AUTHENTICATED] = True
            request[KEY_HASS_USER] = hass.users.get(user_id)
            request[KEY_HASS_REFRESH_TOKEN_ID] = request.headers.get(
                "X-Test-Token", "token-1"
            )
        return await handler(request)

    return middleware


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
        token: str = "token-1",
        params: Any = None,
        **kwargs: Any,
    ) -> Any:
        headers = {"X-Test-User": user, "X-Test-Token": token} if user else {}
        if params is None:
            params = QUERY.get(path)
        resp = await self.client.request(
            method.upper(), rv.BASE_URL + path, headers=headers, params=params, **kwargs
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

    def assert_no_secret(self, *needles: str) -> None:
        for needle in needles:
            for body in self.bodies:
                assert needle.encode() not in body, (needle, body[:300])


@asynccontextmanager
async def http(hass: Any) -> AsyncIterator[Http]:
    app = web.Application(middlewares=[_auth_middleware(hass)])
    app[KEY_HASS] = hass
    for view_class in rv.RF_VIEWS:
        view_class().register(hass, app, app.router)
    async with TestClient(TestServer(app)) as test_client:
        yield Http(test_client)


async def seeded(opts: dict[str, Any] | None = None, **kw: Any) -> Any:
    """hass with users and a center that saw one poll of RID1."""
    hass = users(rf_hass())
    coordinator = FakeCoordinator()
    center, _clock, _reader = await new_center(
        hass, (entry("e1", options() if opts is None else opts), coordinator), **kw
    )
    hass.data[DATA_WIFI_RF_CENTER] = center
    await poll(center, coordinator, poll_data(uptime=1000, clients=[client(MAC_A)]))
    return hass, center, coordinator


async def real_guard(hass: Any, center: Any) -> ActionGuard:
    """The Core guard (real decisions and audit) as the center's binding."""
    audit = AuditLog(hass)
    await audit.async_load()
    guard = ActionGuard(hass, audit)
    api = MagicMock()
    api.guard = GuardView(guard)
    center._binding = _Binding(api=api, events_ok=True)
    return guard


# --- routes ---------------------------------------------------------------------------


def test_every_route_is_listed_once_needs_auth_and_only_reads() -> None:
    names = [v.name for v in rv.RF_VIEWS]
    assert len(names) == len(set(names)) == len(ROUTES)
    assert {v.url for v in rv.RF_VIEWS} == {rv.BASE_URL + p for p in ROUTES}
    for view in rv.RF_VIEWS:
        assert view.requires_auth is True
        for method in ("post", "put", "patch", "delete"):
            assert not hasattr(view, method), (view.name, method)
    assert not any("scan" in v.url for v in rv.RF_VIEWS)


async def test_no_route_answers_without_login(disk) -> None:
    hass, _center, _c = await seeded()
    async with http(hass) as h:
        for path in ROUTES:
            assert (await h.get(path, user=None)).status == 401, path
    h.assert_no_secret(*SECRETS)


async def test_writes_and_scans_have_no_route(disk) -> None:
    hass, _center, _c = await seeded()
    async with http(hass) as h:
        for path in ROUTES:
            assert (await h.call("post", path, json={})).status == 405, path
        assert (await h.get("/scan")).status == 404


async def test_non_admin_is_403_before_the_switch_and_the_body(disk) -> None:
    hass, center, _c = await seeded(options(enabled=False))
    with patch.object(rv, "read_body", AsyncMock(side_effect=AssertionError)):
        async with http(hass) as h:
            for path in ROUTES:
                resp = await h.get(path, user=USER_ID, data=b'{"a": {"b": 1}}')
                assert resp.status == 403, path
                assert resp.data["code"] == "authorization_denied"
            assert (await h.get("/overview", user="nobody")).status == 403
    assert center.counters["polls"] == 0  # nothing looked at the RF switch


async def test_non_admin_reads_with_an_open_panel_but_no_roam_history(disk) -> None:
    hass, _center, _c = await seeded()
    hass.data[_PANEL_ACCESS_KEY] = {"e1": True}
    async with http(hass) as h:
        overview = await h.get("/overview", user=USER_ID)
        assert overview.status == 200
        assert overview.headers["Cache-Control"] == "no-store"
        roaming = await h.get("/roaming", user=USER_ID)
        assert roaming.status == 200
        assert roaming.data["events"] is None
        assert roaming.data["events_restricted"] == "admin_only"
    h.assert_no_secret(*SECRETS)


async def test_unloaded_integration_is_410_and_missing_center_503(disk) -> None:
    hass = users(rf_hass())
    async with http(hass) as h:
        assert (await h.get("/overview")).status == 503
        _hass, center, _c = await seeded()
        hass.data[DATA_WIFI_RF_CENTER] = center
        hass.data[_PANEL_VIEW_DISABLED_KEY] = True
        for path in ROUTES:
            assert (await h.get(path)).status == 410, path
        hass.data[_PANEL_VIEW_DISABLED_KEY] = False
        center.loaded = False
        assert (await h.get("/overview")).status == 503


# --- input validation -----------------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        {},
        {"window": "2h"},
        {"window": "1H"},
        {"window": "1h", "radio_id": "../radio0"},
        {"window": "1h", "radio_id": "radio 0"},
        {"window": "1h", "router_id": "rtr_x"},
        {"window": "1h", "series": "everything"},
        {"window": "1h", "nope": "1"},
        {"window": "1h", "radio_id": "r" * 200},
    ],
)
async def test_bad_timeline_queries_are_400(disk, query: dict[str, str]) -> None:
    hass, _center, _c = await seeded()
    async with http(hass) as h:
        resp = await h.get("/timeline", params=query)
    assert resp.status == 400, (query, resp.body)
    assert resp.data["code"] == "invalid_request"


async def test_repeated_and_unknown_keys_are_400(disk) -> None:
    hass, _center, _c = await seeded()
    async with http(hass) as h:
        twice = await h.get("/timeline", params=[("window", "1h"), ("window", "7d")])
        assert twice.status == 400
        for path in ("/overview", "/radios", "/roaming", "/recommendations"):
            assert (await h.get(path, params={"x": "1"})).status == 400, path


async def test_good_timeline_queries_pass(disk) -> None:
    hass, _center, _c = await seeded()
    async with http(hass) as h:
        for window in ("1h", "24h", "7d", "30d"):
            resp = await h.get("/timeline", params={"window": window})
            assert resp.status == 200 and resp.data["window"] == window
        resp = await h.get(
            "/timeline",
            params={
                "window": "24h",
                "radio_id": "radio1",
                "router_id": RID1,
                "series": "noise",
            },
        )
        assert resp.status == 200
        assert [list(r["series"]) for r in resp.data["radios"]] == [["noise"]]
    h.assert_no_secret(*SECRETS)


async def test_bodies_nested_json_400_and_large_413(disk) -> None:
    hass, _center, _c = await seeded()
    async with http(hass) as h:
        nested = await h.get("/overview", data=b'{"a": {"b": {"c": {"d": 1}}}}')
        assert nested.status == 400
        assert (await h.get("/overview", data=b'{"a": 1}')).status == 400
        assert (await h.get("/overview", data=b"not json")).status == 400
        large = await h.get("/overview", data=b'{"a": "' + b"x" * 5000 + b'"}')
        assert large.status == 413


async def test_a_throwing_route_is_500_without_text(disk) -> None:
    hass, _center, _c = await seeded()
    boom = MagicMock(side_effect=RuntimeError(f"secret {RID1} {MAC_A}"))
    with patch.object(rv.RfOverviewView, "builder", staticmethod(boom)):
        async with http(hass) as h:
            resp = await h.get("/overview")
    assert resp.status == 500 and resp.data["code"] == "internal"
    assert resp.data["details"] == {}
    h.assert_no_secret(*SECRETS, RID1, "secret")


# --- status ---------------------------------------------------------------------------


async def test_off_is_200_off_on_every_route(disk) -> None:
    hass, _center, _c = await seeded(options(enabled=False))
    async with http(hass) as h:
        for path in ROUTES:
            resp = await h.get(path)
            assert resp.status == 200, path
            assert resp.data["status"] == "off"
    h.assert_no_secret(*SECRETS)


async def test_without_key_200_not_ready_and_no_rating(disk) -> None:
    hass, _center, _c = await seeded(key=None)
    async with http(hass) as h:
        for path in ROUTES:
            resp = await h.get(path)
            assert resp.status == 200, path
            assert resp.data["status"] == "not_ready"
            assert "module_key_missing" in resp.data["reasons"]
        overview = (await h.get("/overview")).data
        assert overview["network_health"]["score"] is None
        assert overview["network_health"]["grade"] == "unknown"
        radios = (await h.get("/radios")).data["radios"]
        assert radios and all(r["health"]["score"] is None for r in radios)
        roaming = (await h.get("/roaming")).data
        assert roaming["events"] is None and roaming["events_restricted"] is None


# --- test case 28 ---------------------------------------------------------------------

BASE_KEYS = {"schema", "status", "reasons", "generated_at"}
SCHEMA: dict[str, set[str]] = {
    "/overview": BASE_KEYS
    | {"routers", "monitoring_coverage", "network_health", "counts"},
    "/radios": BASE_KEYS | {"radios"},
    "/channel_map": BASE_KEYS | {"bands", "conflicts"},
    "/timeline": BASE_KEYS | {"window", "radios"},
    "/roaming": BASE_KEYS | {"window_s", "per_radio", "events", "events_restricted"},
    "/recommendations": BASE_KEYS | {"recommendations", "load", "distribution"},
}
HEALTH_KEYS = {"score", "grade", "coverage", "capped", "withheld"}
RADIO_KEYS = {
    "router_id",
    "radio_id",
    "radio_id_source",
    "band",
    "channel",
    "width_mhz",
    "center_channel",
    "htmode",
    "backhaul",
    "country",
    "interfaces",
    "measured_at",
    "metrics",
    "utilization",
    "clients",
    "capabilities",
    "health",
    "load",
    "sources",
    "roams_1h",
}
METRIC_KEYS = {"value", "state", "source", "measured_at"}
COUNT_KEYS = {"radios", "clients", "conflicts", "conflicts_measured", "recommendations"}


async def test_case_28_dashboard_data_contracts_schema_is_pinned(
    disk, core_disks
) -> None:
    """Every route keeps its keys whatever the status (off, not ready,
    ready); unknown values are None with a state, never 0."""
    for opts, kw, status in (
        (options(enabled=False), {}, "off"),
        (options(), {"key": None}, "not_ready"),
        (options(), {}, "ready"),
    ):
        hass, center, _c = await seeded(opts, **kw)
        await real_guard(hass, center)  # roaming: the admin's history read
        async with http(hass) as h:
            for path, keys in SCHEMA.items():
                data = (await h.get(path)).data
                assert set(data) == keys, (status, path, set(data) ^ keys)
                assert data["schema"] == 1 and data["status"] == status
            overview = (await h.get("/overview")).data
            assert set(overview["counts"]) == COUNT_KEYS
            assert set(overview["network_health"]) >= HEALTH_KEYS
            radios = (await h.get("/radios")).data["radios"]
        if status == "off":
            assert radios == [] and overview["routers"] == []
            continue
        (radio,) = radios
        assert set(radio) == RADIO_KEYS
        assert set(radio["health"]) >= HEALTH_KEYS
        for name, metric in radio["metrics"].items():
            if metric is None:
                continue  # not assessed (its read is off)
            assert set(metric) == METRIC_KEYS, name
            if metric["state"] != "measured" and metric["state"] != "stale":
                assert metric["value"] is None, name
        assert radio["metrics"]["utilization"] is None  # read off: not 0
        assert radio["router_id"] == RID1  # the Core router id
        assert radio["radio_id_source"] == "uci"


# --- roaming: sensitive read through the Core guard -----------------------------------


async def test_roaming_history_once_approved_per_panel_session(
    disk, core_disks
) -> None:
    hass, center, _c = await seeded()
    center.roams.append({"client_ref": "cli_" + "a" * 16, "at": center.clock()})
    guard = await real_guard(hass, center)
    async with http(hass) as h:
        first = await h.get("/roaming")
        assert first.status == 200, first.body
        assert first.data["events_restricted"] is None
        assert len(first.data["events"]) == 1
        assert (await h.get("/roaming")).status == 200
        assert guard.stats["decisions_approved"] == 1  # once per session
        assert guard.stats["consumed"] == 1
        assert (await h.get("/roaming", token="token-2")).status == 200
        assert guard.stats["decisions_approved"] == 2  # a new HA login
        plain = await h.get("/roaming", user=USER_ID)
        assert plain.status == 403  # panel closed for plain users
    assert center.counters["sensitive_reads"] == 3


async def test_core_authorization_error_is_403(disk) -> None:
    hass, center, _c = await seeded()
    api = MagicMock()
    api.guard.async_verify_actor = AsyncMock(
        side_effect=AuthorizationError(
            "unknown_user", details={"reason": "unknown_user"}
        )
    )
    center._binding = _Binding(api=api, events_ok=True)
    async with http(hass) as h:
        resp = await h.get("/roaming")
    assert resp.status == 403 and resp.data["code"] == "authorization_denied"


async def test_roaming_without_core_is_503(disk) -> None:
    hass, _center, _c = await seeded()
    async with http(hass) as h:
        resp = await h.get("/roaming")
    assert resp.status == 503 and resp.data["code"] == "no_core"


# --- registration and the real core ---------------------------------------------------


async def test_routes_register_once_per_run(disk) -> None:
    hass = rf_hass()
    rv.async_register_rf_views(hass)
    rv.async_register_rf_views(hass)
    assert hass.http.register_view.call_count == len(rv.RF_VIEWS)
    assert len(hass.data[DATA_WIFI_RF_VIEWS_BOUND]) == len(rv.RF_VIEWS)


async def test_with_the_enterprise_core_binding_key_and_roaming(
    core_disks, tmp_path
) -> None:
    """The real core: router id from the registry, module key, events and
    the guard actions; the roaming route asks the real guard."""
    env = await cm_env(core_disks, tmp_path, options=options(), attach=False)
    with rf_disk():
        center = await async_setup_rf_center(
            env.hass, env.entries[0], env.coords[env.rid]
        )
        await center.async_bind_core()
        await drain(env.hass)
        assert center.router_id_of("e1") == env.rid
        assert center.module_key is not None
        assert center._binding.events_ok and center._binding.actions_ok
        center.auto_bind = False
        coordinator = FakeCoordinator()
        center.remove_entry("e1")
        center.add_entry(env.entries[0], coordinator)
        await poll(center, coordinator, poll_data(uptime=1000))
        assert center.status == "ready"
        async with http(env.hass) as h:
            overview = await h.get("/overview")
            assert overview.status == 200 and overview.data["status"] == "ready"
            roaming = await h.get("/roaming")
            assert roaming.status == 200, roaming.body
            assert roaming.data["events"] == []
        h.assert_no_secret(*SECRETS)
        await async_release_rf_center(env.hass, "e1")
    await stop(env)
