"""HTTP routes of Traffic Analytics (Phase J): traffic_views + traffic_output.

Task §21 areas 28 (dashboard data contracts) and 32 (privacy and access).
A real aiohttp application with HA's own view plumbing (401 without login)
and a fake login middleware (header ``X-Test-User``), as in
``test_rf_views``. The engine runs on FakeDisks with FakeCoordinator polls;
no router, no HA instance, no network. Ids and MACs are synthetic.
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
from core_testkit import ADMIN_ID, USER_ID, FakeDisks, add_users, drain
from core_testkit import make_hass as core_make_hass
from homeassistant.components.http import KEY_HASS_USER
from homeassistant.helpers.http import KEY_AUTHENTICATED, KEY_HASS
from test_security_views import users as _users
from test_traffic_engine import (
    MAC1,
    MAC2,
    RID,
    enabled,
    poll_data,
    start,
    station,
    two_polls,
)

from custom_components.openwrt_router import traffic_output as out
from custom_components.openwrt_router import traffic_views as tv
from custom_components.openwrt_router.const import (
    DATA_TRAFFIC_ANALYTICS,
    DATA_TRAFFIC_VIEWS_BOUND,
    TRAFFIC_COARSE_STORE_KEY,
    TRAFFIC_FINE_STORE_KEY,
)
from custom_components.openwrt_router.topology_panel import (
    _PANEL_ACCESS_KEY,
    _PANEL_VIEW_DISABLED_KEY,
)
from custom_components.openwrt_router.traffic_engine import TrafficEngine
from custom_components.openwrt_router.traffic_model import (
    Bucket,
    Coverage,
    MeasurementPoint,
    Scope,
)
from custom_components.openwrt_router.traffic_series import SeriesWindow

ROUTES = (
    "/overview",
    "/points",
    "/series",
    "/talkers",
    "/clients",
    "/vlans",
    "/capacity",
    "/anomalies",
    "/recommendations",
    "/flows",
    "/evidence/{evidence_ref}",
    "/settings",
)
GET_PATHS = tuple(
    p.replace("{evidence_ref}", "evr_" + "a" * 16) for p in ROUTES
)  # concrete paths
ADMIN_ONLY = ("/flows", "/settings")
POINT = "tpt_" + "0" * 16
QUERY = {"/series": {"point_id": POINT, "window": "1h"}}
# No MAC, host name or AP netdev name may leave the module.
SECRETS = (MAC1, MAC1.upper(), MAC2, "gw-office", "phy0-ap0")


def users(hass: Any) -> Any:
    """hass with an admin and a plain user (core_make_hass starts with none)."""
    hass = _users(hass)
    if ADMIN_ID not in hass.users:
        add_users(hass)
    return hass


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


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
    def __init__(self, client: TestClient) -> None:
        self.client = client
        self.bodies: list[bytes] = []

    async def call(
        self,
        method: str,
        path: str,
        *,
        user: str | None = ADMIN_ID,
        params: Any = None,
        **kwargs: Any,
    ) -> Any:
        headers = {"X-Test-User": user} if user else {}
        if params is None:
            params = QUERY.get(path)
        resp = await self.client.request(
            method.upper(), tv.BASE_URL + path, headers=headers, params=params, **kwargs
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
    for view_class in tv.TRAFFIC_VIEWS:
        view_class().register(hass, app, app.router)
    async with TestClient(TestServer(app)) as test_client:
        yield Http(test_client)


async def seeded(disks: FakeDisks, *, on: bool = True) -> tuple[Any, Any, Any]:
    """hass with users and an engine that saw two polls (when on)."""
    hass = users(core_make_hass())
    if on:
        enabled(disks)
    engine, coord = await start(hass)
    if on:
        await two_polls(engine, coord, hass)
    return hass, engine, coord


# --- routes -----------------------------------------------------------------------------


def test_every_route_is_listed_once_needs_auth_and_only_reads() -> None:
    names = [v.name for v in tv.TRAFFIC_VIEWS]
    assert len(names) == len(set(names)) == len(ROUTES)
    assert {v.url for v in tv.TRAFFIC_VIEWS} == {tv.BASE_URL + p for p in ROUTES}
    for view in tv.TRAFFIC_VIEWS:
        assert view.requires_auth is True
        for method in ("post", "put", "patch", "delete"):
            assert not hasattr(view, method), (view.name, method)
    assert {v.url for v in tv.TRAFFIC_VIEWS if v.admin_only} == {
        tv.BASE_URL + p for p in ADMIN_ONLY
    }


async def test_no_route_answers_without_login(disks) -> None:
    hass, _engine, _c = await seeded(disks)
    async with http(hass) as h:
        for path in GET_PATHS:
            assert (await h.get(path, user=None)).status == 401, path


async def test_writes_have_no_route(disks) -> None:
    hass, _engine, _c = await seeded(disks)
    async with http(hass) as h:
        for path in GET_PATHS:
            assert (await h.call("post", path, json={})).status == 405, path
        assert (await h.get("/collector/ingest")).status == 404


async def test_non_admin_is_403_before_the_switch_and_the_body(disks) -> None:
    hass, _engine, _c = await seeded(disks, on=False)
    with (
        patch.object(tv, "read_body", AsyncMock(side_effect=AssertionError)),
        patch.object(out, "status_of", MagicMock(side_effect=AssertionError)),
    ):
        async with http(hass) as h:
            for path in GET_PATHS:
                resp = await h.get(path, user=USER_ID, data=b'{"a": {"b": 1}}')
                assert resp.status == 403, path
                assert resp.data["code"] == "authorization_denied"
            assert (await h.get("/overview", user="nobody")).status == 403


async def test_open_panel_lets_users_read_but_not_flows_or_settings(disks) -> None:
    hass, _engine, _c = await seeded(disks)
    hass.data[_PANEL_ACCESS_KEY] = {"e1": True}
    async with http(hass) as h:
        overview = await h.get("/overview", user=USER_ID)
        assert overview.status == 200
        assert overview.headers["Cache-Control"] == "no-store"
        for path in ADMIN_ONLY:
            resp = await h.get(path, user=USER_ID)
            assert resp.status == 403, path
        for path in ADMIN_ONLY:
            assert (await h.get(path)).status == 200, path
    h.assert_no_secret(*SECRETS)


async def test_unloaded_integration_is_410_and_missing_engine_503(disks) -> None:
    hass = users(core_make_hass())
    async with http(hass) as h:
        assert (await h.get("/overview")).status == 503
        _hass, engine, _c = await seeded(disks)
        hass.data[DATA_TRAFFIC_ANALYTICS] = engine
        hass.data[_PANEL_VIEW_DISABLED_KEY] = True
        for path in GET_PATHS:
            assert (await h.get(path)).status == 410, path
        hass.data[_PANEL_VIEW_DISABLED_KEY] = False
        engine.loaded = False
        assert (await h.get("/overview")).status == 503


# --- input validation ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "query"),
    [
        ("/series", {}),
        ("/series", {"point_id": POINT}),
        ("/series", {"window": "1h"}),
        ("/series", {"point_id": "../etc/passwd", "window": "1h"}),
        ("/series", {"point_id": "tpt_XYZ", "window": "1h"}),
        ("/series", {"point_id": POINT, "window": "5m"}),
        ("/series", {"point_id": POINT, "window": "1H"}),
        ("/talkers", {"window": "2h"}),
        ("/talkers", {"scope": "station"}),
        ("/talkers", {"direction": "sideways"}),
        ("/talkers", {"limit": "0"}),
        ("/talkers", {"limit": "51"}),
        ("/talkers", {"limit": "-1"}),
        ("/talkers", {"limit": "1e3"}),
        ("/talkers", {"kind": "all"}),
        ("/points", {"router_id": "rtr_x"}),
        ("/points", {"scope": "everything"}),
        ("/vlans", {"router_id": RID.upper()}),
        ("/capacity", {"router_id": "../" + RID}),
        ("/anomalies", {"state": "closed"}),
        ("/anomalies", {"limit": "101"}),
        ("/flows", {"client_ref": "02:00:5e:10:00:01"}),
        ("/flows", {"proto": "gre"}),
        ("/flows", {"limit": "201"}),
        ("/overview", {"x": "1"}),
        ("/talkers", {"window": "1" * 100}),
    ],
)
async def test_bad_queries_are_400(disks, path: str, query: dict[str, str]) -> None:
    hass, _engine, _c = await seeded(disks)
    async with http(hass) as h:
        resp = await h.get(path, params=query)
    assert resp.status == 400, (path, query, resp.body)
    assert resp.data["code"] == "invalid_request"


async def test_repeated_keys_and_bad_evidence_refs(disks) -> None:
    hass, _engine, _c = await seeded(disks)
    async with http(hass) as h:
        twice = await h.get("/talkers", params=[("window", "1h"), ("window", "7d")])
        assert twice.status == 400
        assert (await h.get("/evidence/evr_zz")).status == 400
        assert (await h.get("/evidence/" + "evr_" + "A" * 16)).status == 400
        unknown = await h.get("/evidence/evr_" + "a" * 16)
        assert unknown.status == 404 and unknown.data["details"]["reason"] == (
            "unknown_evidence"
        )


async def test_bodies_nested_json_400_and_large_413(disks) -> None:
    hass, _engine, _c = await seeded(disks)
    async with http(hass) as h:
        assert (await h.get("/overview", data=b'{"a": {"b": {"c": 1}}}')).status == 400
        assert (await h.get("/overview", data=b'{"a": 1}')).status == 400
        assert (await h.get("/overview", data=b"not json")).status == 400
        large = await h.get("/overview", data=b'{"a": "' + b"x" * 5000 + b'"}')
        assert large.status == 413


async def test_a_throwing_builder_is_500_without_text(disks) -> None:
    hass, _engine, _c = await seeded(disks)
    boom = MagicMock(side_effect=RuntimeError(f"secret {RID} {MAC1}"))
    with patch.object(out, "overview", boom):
        async with http(hass) as h:
            resp = await h.get("/overview")
    assert resp.status == 500 and resp.data["code"] == "internal"
    assert resp.data["details"] == {}
    h.assert_no_secret(*SECRETS, RID, "secret")


# --- off ------------------------------------------------------------------------------------


async def test_off_is_200_off_without_history_store_or_router(disks) -> None:
    hass, engine, coord = await seeded(disks, on=False)
    # nothing behind the status may be read while the module is off
    for name in ("series", "store", "talkers", "anomalies", "correlator", "clients"):
        setattr(engine, name, None)
    untouchable = property(lambda _s: (_ for _ in ()).throw(AssertionError("read")))
    with patch.object(TrafficEngine, "history_source", untouchable):
        async with http(hass) as h:
            for path in GET_PATHS:
                resp = await h.get(path)
                assert resp.status == 200, (path, resp.body)
                assert resp.data["status"] == "off"
                assert resp.data["reasons"] == ["disabled"]
    assert coord.router_calls() == []
    assert TRAFFIC_FINE_STORE_KEY not in disks.options  # never opened
    assert disks[TRAFFIC_COARSE_STORE_KEY].saves == []
    h.assert_no_secret(*SECRETS)


# --- data contracts (area 28) -------------------------------------------------------------


async def test_overview_contract_and_unknown_is_none(disks) -> None:
    hass, _engine, coord = await seeded(disks)
    calls_before = len(coord.router_calls())
    async with http(hass) as h:
        resp = await h.get("/overview")
    assert resp.status == 200
    data = resp.data
    assert data["v"] == 1 and data["status"] == "not_ready"  # no core in the test
    assert data["reasons"] == ["core_missing"]
    for key in (
        "coverage",
        "wan",
        "wan_total",
        "wan_24h",
        "talkers_top",
        "anomalies",
        "interfaces",
        "vlans",
        "flow_sources",
        "correlation_sources",
        "routers",
        "drops",
        "history",
    ):
        assert key in data, key
    (wan,) = data["wan"]
    assert wan["router_id"] == RID and wan["scope"] == "wan"
    assert wan["down_bps"] == pytest.approx(1_000_000.0)  # 1.25 MB in 10 s
    assert wan["coverage"] == "partial"  # offload state unknown
    assert data["wan_total"]["coverage"] == "partial"
    assert data["history"]["day_boundary"] == "utc"
    states = {s["module"]: s for s in data["correlation_sources"]}
    assert states["security_center"]["state"] == "not_connected"
    assert states["wifi_rf"]["state"] in {"module_missing", "not_ready"}
    flow = {s["source"]: s for s in data["flow_sources"]}
    assert flow["collector"]["state"] == "unavailable"
    assert data["coverage"]["points"] >= 2
    # interface load: a known link gives a share, never an assumed one
    for row in data["interfaces"]:
        if row["link_mbps"] is None:
            assert row["utilization_pct"] is None
            assert row["utilization_reason"] == "link_speed_unknown"
        else:
            assert row["utilization_pct"] is not None
    assert len(coord.router_calls()) == calls_before  # a route calls no router


async def test_series_points_talkers_and_lists(disks) -> None:
    hass, _engine, coord = await seeded(disks)
    coord.poll(
        data=poll_data(
            120.0,
            (1_000 + 2_500_000, 500 + 250_000),
            uptime=5_020,
            clients=[station(MAC1, 1_000, 2_000)],
        )
    )
    await drain(hass)
    async with http(hass) as h:
        pts = await h.get("/points", params={"router_id": RID})
        assert pts.status == 200 and pts.data["total"] >= 2
        assert all("radio_id" not in p for p in pts.data["points"])
        wan = next(p for p in pts.data["points"] if p["scope"] == "wan")
        for window in ("1h", "24h", "7d", "30d", "90d"):
            resp = await h.get(
                "/series", params={"point_id": wan["point_id"], "window": window}
            )
            assert resp.status == 200, window
            assert len(resp.data["buckets"]) <= 500
            assert resp.data["utc_days"] is (resp.data["resolution_s"] == 86400)
            for b in resp.data["buckets"]:
                assert set(b) == {
                    "ts",
                    "rx_bytes",
                    "tx_bytes",
                    "rx_peak_bps",
                    "tx_peak_bps",
                    "coverage",
                }
        unknown = await h.get("/series", params={"point_id": POINT, "window": "1h"})
        assert unknown.status == 200 and unknown.data["state"] == "unavailable"
        for kind in ("window", "current", "peaks"):
            resp = await h.get(
                "/talkers", params={"kind": kind, "scope": "wan", "limit": "50"}
            )
            assert resp.status == 200 and resp.data["kind"] == kind
            assert len(resp.data["rows"]) <= 50
        for path in ("/clients", "/vlans", "/capacity", "/anomalies"):
            assert (await h.get(path)).status == 200, path
        rec = await h.get("/recommendations")
        assert rec.status == 200 and "findings" in rec.data and "sources" in rec.data
        flows = await h.get("/flows")
        assert flows.data["rows"] == [] and flows.data["source"]["state"] == (
            "unavailable"
        )
        assert "empty_is_not_no_traffic" in flows.data["notes"]
        settings = await h.get("/settings")
        assert settings.data["enabled"] is True and settings.data["writable"] is False
        assert settings.data["history_profile"] == "compact"
    h.assert_no_secret(*SECRETS)


def test_series_is_capped_at_500_buckets() -> None:
    point = MeasurementPoint(RID, Scope.WAN, device="wan")
    buckets = tuple(Bucket(start=i * 300, resolution_s=300) for i in range(700))
    window = SeriesWindow(
        point=point,
        window_s=700 * 300,
        end=700 * 300.0,
        resolution_s=300,
        buckets=buckets,
        depth_s=700 * 300.0,
        area_coverage=Coverage.FULL,
    )
    source = SimpleNamespace(points=lambda: (point,), window=lambda *a, **k: window)
    engine = SimpleNamespace(
        active=True,
        not_ready_reason=None,
        wall=lambda: 700 * 300.0,
        history_source=source,
    )
    answer = out.series(engine, point_id=point.point_id, window="90d")
    assert len(answer["buckets"]) == 500
    assert answer["buckets"][-1]["ts"] == 699 * 300  # the newest are kept
    assert answer["buckets"][0]["rx_bytes"] is None  # unknown stays None


async def test_routes_register_once_per_run(disks) -> None:
    hass = users(core_make_hass())
    hass.http = MagicMock()
    tv.async_register_traffic_views(hass)
    tv.async_register_traffic_views(hass)
    assert hass.http.register_view.call_count == len(tv.TRAFFIC_VIEWS)
    assert len(hass.data[DATA_TRAFFIC_VIEWS_BOUND]) == len(tv.TRAFFIC_VIEWS)


async def test_setup_binds_the_routes_even_while_off(disks) -> None:
    hass = users(core_make_hass())
    hass.http = MagicMock()
    await start(hass)
    assert hass.http.register_view.call_count == len(tv.TRAFFIC_VIEWS)
