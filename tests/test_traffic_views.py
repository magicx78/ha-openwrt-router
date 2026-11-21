"""HTTP routes of Traffic Analytics (Phases J, K): traffic_views + traffic_output.

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
    _reset_pending,  # noqa: F401 - autouse fixture
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
    "/collector/users",
    "/collector/ingest",
)
READ_ROUTES = ROUTES[:-1]
GET_PATHS = tuple(
    p.replace("{evidence_ref}", "evr_" + "a" * 16) for p in READ_ROUTES
)  # concrete paths
COLLECTOR_ID = "c" * 32  # a plain (non-admin) user for the collector
ADMIN_HEX_ID = "a" * 32
ADMIN_ONLY = ("/flows", "/settings", "/collector/users")
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
        if request.headers.get("X-Test-Https"):
            request = request.clone(scheme="https")
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
        headers.update(kwargs.pop("headers", None) or {})
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


WRITES = {"/settings": "post", "/collector/ingest": "post"}


def test_every_route_is_listed_once_needs_auth_and_writes_only_where_known() -> None:
    names = [v.name for v in tv.TRAFFIC_VIEWS]
    assert len(names) == len(set(names)) == len(ROUTES)
    assert {v.url for v in tv.TRAFFIC_VIEWS} == {tv.BASE_URL + p for p in ROUTES}
    for view in tv.TRAFFIC_VIEWS:
        assert view.requires_auth is True
        path = view.url.removeprefix(tv.BASE_URL)
        for method in ("post", "put", "patch", "delete"):
            assert hasattr(view, method) == (WRITES.get(path) == method), (
                view.name,
                method,
            )
    assert {v.url for v in tv.TRAFFIC_VIEWS if getattr(v, "admin_only", False)} == {
        tv.BASE_URL + p for p in ADMIN_ONLY
    }
    assert not hasattr(tv.TrafficCollectorIngestView, "get")


async def test_no_route_answers_without_login(disks) -> None:
    hass, _engine, _c = await seeded(disks)
    async with http(hass) as h:
        for path in GET_PATHS:
            assert (await h.get(path, user=None)).status == 401, path


async def test_only_settings_and_the_intake_take_writes(disks) -> None:
    hass, _engine, _c = await seeded(disks)
    async with http(hass) as h:
        for path in GET_PATHS:
            if path == "/settings":
                continue
            assert (await h.call("post", path, json={})).status == 405, path
        assert (await h.get("/collector/ingest")).status == 405
        assert (await h.call("put", "/settings", json={})).status == 405


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
            # the envelope keeps the module's status; the window's own
            # reasons have their own key
            assert resp.data["status"] == "not_ready", window
            assert resp.data["reasons"] == ["core_missing"], window
            assert isinstance(resp.data["window_reasons"], list), window
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
        assert settings.data["enabled"] is True and settings.data["writable"] is True
        assert settings.data["history_profile"] == "compact"
        assert settings.data["switch"]["option"] == "traffic_enabled"
        assert settings.data["collector"]["enabled"] is False
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


# --- Phase K: POST settings ----------------------------------------------------------


def collector_users(hass: Any) -> Any:
    from core_testkit import add_user

    add_user(hass, COLLECTOR_ID, admin=False)
    add_user(hass, ADMIN_HEX_ID, admin=True)
    add_user(hass, "d" * 32, admin=False, active=False)
    add_user(hass, "e" * 32, admin=False, system_generated=True)
    return hass


async def test_settings_post_is_admin_only_before_the_body(disks) -> None:
    hass, engine, _c = await seeded(disks)
    with patch.object(tv, "read_body", AsyncMock(side_effect=AssertionError)):
        async with http(hass) as h:
            resp = await h.call(
                "post", "/settings", user=USER_ID, json={"client_sensors": []}
            )
            assert resp.status == 403 and resp.data["code"] == "authorization_denied"
            assert (await h.call("post", "/settings", user=None, json={})).status == 401
    hass.data[_PANEL_ACCESS_KEY] = {"e1": True}  # an open panel changes nothing
    async with http(hass) as h:
        resp = await h.call("post", "/settings", user=USER_ID, json={})
        assert resp.status == 403
    assert engine.settings["collector"]["enabled"] is False


async def test_settings_post_while_off_is_409_and_touches_no_store(disks) -> None:
    hass, _engine, _c = await seeded(disks, on=False)
    async with http(hass) as h:
        resp = await h.call("post", "/settings", json={"client_sensors": []})
        assert resp.status == 409 and resp.data["code"] == "disabled"
        assert "Security Center" not in resp.body.decode()
    assert TRAFFIC_COARSE_STORE_KEY not in disks.options


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"enabled": True},
        {"collector": {"enabled": "yes"}},
        {"collector": {"enabled": True, "token": "x"}},
        {"collector": {"user_id": "user-plain"}},
        {"collector": {"enabled": True}},  # on without a user
        {"client_sensors": ["aa:bb:cc:dd:ee:ff"]},
        {"client_sensors": "cli_x"},
        {"client_sensors": ["cli_" + "0" * 16] * 21},
        {"history_profile": "standard"},
    ],
)
async def test_settings_post_refuses_invalid_input_and_keeps_the_settings(
    disks, body
) -> None:
    hass, engine, _c = await seeded(disks)
    before = json.dumps(engine.settings, sort_keys=True)
    async with http(hass) as h:
        resp = await h.call("post", "/settings", json=body)
        assert resp.status == 400, resp.data
        assert resp.data["code"] == "invalid_request"
    assert json.dumps(engine.settings, sort_keys=True) == before


async def test_settings_post_refuses_non_json_and_large_bodies(disks) -> None:
    hass, _engine, _c = await seeded(disks)
    async with http(hass) as h:
        assert (await h.call("post", "/settings", data=b"{nope")).status == 400
        big = b'{"client_sensors": ["' + b"x" * 5000 + b'"]}'
        assert (await h.call("post", "/settings", data=big)).status in (400, 413)


@pytest.mark.parametrize(
    ("user_id", "reason"),
    [
        ("b" * 32, "user_unknown"),
        (ADMIN_HEX_ID, "user_is_admin"),
        ("d" * 32, "user_inactive"),
        ("e" * 32, "user_system"),
    ],
)
async def test_settings_post_checks_the_collector_user(disks, user_id, reason) -> None:
    hass, engine, _c = await seeded(disks)
    collector_users(hass)
    async with http(hass) as h:
        resp = await h.call(
            "post",
            "/settings",
            json={"collector": {"enabled": True, "user_id": user_id}},
        )
        assert resp.status == 400 and resp.data["details"]["reason"] == reason
    assert engine.collector_enabled is False


async def test_settings_post_stores_and_answers_without_the_user_id(disks) -> None:
    hass, engine, _c = await seeded(disks)
    collector_users(hass)
    ref = "cli_" + "1" * 16
    async with http(hass) as h:
        resp = await h.call(
            "post",
            "/settings",
            json={
                "collector": {"enabled": True, "user_id": COLLECTOR_ID},
                "client_sensors": [ref, ref],
            },
        )
        assert resp.status == 200, resp.data
        assert resp.data["collector"]["enabled"] is True
        assert resp.data["collector"]["user_configured"] is True
        assert resp.data["client_sensors"] == [ref]
        assert COLLECTOR_ID not in resp.body.decode()
        again = await h.get("/settings")
        assert COLLECTOR_ID not in again.body.decode()
    await drain(hass)
    assert engine.collector_enabled and engine.is_collector_user(COLLECTOR_ID)
    assert list(engine.client_sensor_refs) == [ref]
    assert TRAFFIC_COARSE_STORE_KEY in disks.options


# --- Phase L: collector users and ``user_ref`` --------------------------------------


def named_users(hass: Any) -> Any:
    """collector_users plus names and ``hass.auth.async_get_users``."""
    collector_users(hass)
    names = {COLLECTOR_ID: "Collector", "f" * 32: "  b-feeder  "}
    from core_testkit import add_user

    add_user(hass, "f" * 32, admin=False)
    for uid, user in hass.users.items():
        user.name = names.get(uid, "x" * 80)
    hass.auth.async_get_users = AsyncMock(side_effect=lambda: list(hass.users.values()))
    return hass


async def test_collector_users_lists_only_choosable_users_without_ids(disks) -> None:
    hass, engine, _c = await seeded(disks)
    named_users(hass)
    async with http(hass) as h:
        resp = await h.get("/collector/users")
        assert resp.status == 200, resp.data
        assert resp.headers["Cache-Control"] == "no-store"
        rows = resp.data["users"]
        # active, not admin, not system generated, with a 32-hex id; by name
        assert [r["name"] for r in rows] == ["b-feeder", "Collector"]
        assert all(re_user_ref(r["user_ref"]) for r in rows)
        assert len({r["user_ref"] for r in rows}) == 2
        assert [r["selected"] for r in rows] == [False, False]
        assert resp.data["user_configured"] is False
        for uid in hass.users:
            assert uid not in resp.body.decode()
        # the same run gives the same reference
        again = await h.get("/collector/users")
        assert again.data["users"] == rows
        # non-admins never, even with an open panel
        hass.data[_PANEL_ACCESS_KEY] = {"e1": True}
        assert (await h.get("/collector/users", user=USER_ID)).status == 403
        assert (await h.get("/collector/users", params={"x": "1"})).status == 400
    assert engine.collector_enabled is False


def re_user_ref(value: Any) -> bool:
    import re

    return (
        isinstance(value, str) and re.fullmatch(r"usr_[0-9a-f]{16}", value) is not None
    )


async def test_collector_users_while_off_reads_no_user(disks) -> None:
    hass, _engine, _c = await seeded(disks, on=False)
    named_users(hass)
    async with http(hass) as h:
        resp = await h.get("/collector/users")
        assert resp.status == 200 and resp.data["status"] == "off"
        assert resp.data["users"] == []
    hass.auth.async_get_users.assert_not_called()


async def test_settings_post_takes_the_user_ref_and_marks_it_selected(disks) -> None:
    hass, engine, _c = await seeded(disks)
    named_users(hass)
    async with http(hass) as h:
        rows = (await h.get("/collector/users")).data["users"]
        ref = next(r["user_ref"] for r in rows if r["name"] == "Collector")
        resp = await h.call(
            "post", "/settings", json={"collector": {"enabled": True, "user_ref": ref}}
        )
        assert resp.status == 200, resp.data
        assert resp.data["collector"] == {
            **resp.data["collector"],
            "enabled": True,
            "user_configured": True,
        }
        listed = (await h.get("/collector/users")).data
        assert [r["selected"] for r in listed["users"]] == [False, True]
        assert listed["selected_listed"] is True
        h.assert_no_secret(COLLECTOR_ID)
        # switching off keeps the user; a null reference clears it
        resp = await h.call(
            "post",
            "/settings",
            json={"collector": {"enabled": False, "user_ref": None}},
        )
        assert resp.status == 400  # null is not a reference
        resp = await h.call("post", "/settings", json={"collector": {"enabled": False}})
        assert resp.status == 200 and resp.data["collector"]["enabled"] is False
    await drain(hass)
    assert engine.is_collector_user(COLLECTOR_ID) is False  # off: nobody may push
    assert engine.settings["collector"]["user_id"] == COLLECTOR_ID


@pytest.mark.parametrize(
    ("collector", "reason"),
    [
        ({"enabled": True, "user_ref": "usr_" + "0" * 16}, "user_unknown"),
        ({"enabled": True, "user_ref": "cli_" + "0" * 16}, "user_ref"),
        ({"enabled": True, "user_ref": 5}, "user_ref"),
        ({"user_ref": "usr_" + "0" * 16, "user_id": COLLECTOR_ID}, "user_id_and_ref"),
    ],
)
async def test_settings_post_refuses_unknown_or_bad_user_refs(
    disks, collector, reason
) -> None:
    hass, engine, _c = await seeded(disks)
    named_users(hass)
    before = json.dumps(engine.settings, sort_keys=True)
    async with http(hass) as h:
        resp = await h.call("post", "/settings", json={"collector": collector})
        assert resp.status == 400, resp.data
        assert resp.data["details"] == {"field": "collector", "reason": reason}
    assert json.dumps(engine.settings, sort_keys=True) == before


async def test_a_reference_of_an_admin_or_inactive_user_is_never_resolved(
    disks,
) -> None:
    hass, _engine, _c = await seeded(disks)
    named_users(hass)
    for uid in (ADMIN_HEX_ID, "d" * 32, "e" * 32):
        ref = tv.user_ref(hass, uid)
        async with http(hass) as h:
            resp = await h.call(
                "post",
                "/settings",
                json={"collector": {"enabled": True, "user_ref": ref}},
            )
            assert resp.status == 400
            assert resp.data["details"]["reason"] == "user_unknown"


def test_user_refs_depend_on_a_random_key_per_run() -> None:
    a, b = core_make_hass(), core_make_hass()
    assert tv.user_ref(a, COLLECTOR_ID) == tv.user_ref(a, COLLECTOR_ID)
    assert tv.user_ref(a, COLLECTOR_ID) != tv.user_ref(b, COLLECTOR_ID)


# --- Phase K: collector intake -------------------------------------------------------


def envelope(now: float, **over: Any) -> dict[str, Any]:
    record = {
        "kind": "flow",
        "router_id": RID,
        "window": {"start": now - 60, "end": now},
        "direction": "orig",
        "proto": "tcp",
        "src": "192.0.2.10",
        "dst": "198.51.100.5",
        "src_port": 50000,
        "dst_port": 443,
        "client_mac": MAC1,
        "bytes": 1200,
        "packets": 10,
        "observation": "observed",
    }
    body: dict[str, Any] = {
        "schema": "traffic.collector.v1",
        "collector": "edge-1",
        "sent_at": now,
        "records": [record],
    }
    body.update(over)
    return body


async def collector_on(disks) -> tuple[Any, Any]:
    hass, engine, _c = await seeded(disks)
    collector_users(hass)
    await engine.async_update_settings(
        {"collector": {"enabled": True, "user_id": COLLECTOR_ID}}
    )
    engine._module_key = bytes(range(32))  # what the core hands out
    return hass, engine


async def ingest(h: Http, body: Any, *, user: str = COLLECTOR_ID, https=True) -> Any:
    headers = {"X-Test-Https": "1"} if https else {}
    kwargs: dict[str, Any] = (
        {"data": body} if isinstance(body, bytes) else {"json": body}
    )
    return await h.call(
        "post", "/collector/ingest", user=user, headers=headers, **kwargs
    )


async def test_intake_off_by_default_answers_like_a_switched_off_module(disks) -> None:
    hass, engine, _c = await seeded(disks, on=False)
    collector_users(hass)
    async with http(hass) as h:
        resp = await ingest(h, envelope(engine.wall()))
        assert resp.status == 409 and resp.data["code"] == "disabled"
    hass, engine, _c = await seeded(disks)
    collector_users(hass)
    async with http(hass) as h:
        resp = await ingest(h, envelope(engine.wall()))
        assert resp.status == 403 and resp.data["code"] == "authorization_denied"
    assert engine.collector.counters["rejected_collector_off"] == 1
    assert len(engine.flows) == 0


async def test_intake_takes_only_the_collector_user_over_https(disks) -> None:
    hass, engine = await collector_on(disks)
    async with http(hass) as h:
        for user in (USER_ID, ADMIN_ID, ADMIN_HEX_ID):
            resp = await ingest(h, envelope(engine.wall()), user=user)
            assert resp.status == 403, user
        hass.users[COLLECTOR_ID].is_admin = True  # promoted later: refused
        assert (await ingest(h, envelope(engine.wall()))).status == 403
        hass.users[COLLECTOR_ID].is_admin = False
        resp = await ingest(h, envelope(engine.wall()), https=False)
        assert resp.status == 403 and resp.data["code"] == "insecure_transport"
        assert len(engine.flows) == 0
        resp = await ingest(h, envelope(engine.wall()))
        assert resp.status == 200, resp.data
        assert resp.data == {
            "v": 1,
            "schema": "traffic.collector.v1",
            "accepted": 1,
            "rejected": [],
        }
        retry = await ingest(h, envelope(engine.wall()))
        assert retry.status == 429 and int(retry.headers["Retry-After"]) >= 1
        flows = await h.get("/flows")
        assert flows.status == 200
        assert flows.data["source"]["state"] == "ready"
        assert len(flows.data["rows"]) == 1
    h.assert_no_secret(MAC1, MAC1.upper(), COLLECTOR_ID)
    assert engine.collector.counters["accepted_records"] == 1


async def test_intake_is_all_or_nothing(disks) -> None:
    hass, engine = await collector_on(disks)
    now = engine.wall()
    good = envelope(now)["records"][0]
    bad = {**good, "proto": "icmp6x"}

    async def fresh(body: Any) -> Any:
        engine.collector._last_call = None  # past the rate gate
        return await ingest(h, body)

    async with http(hass) as h:
        resp = await fresh(envelope(now, records=[good, bad, good]))
        assert resp.status == 400 and resp.data["code"] == "records_rejected"
        assert resp.data["accepted"] == 0
        assert resp.data["rejected"] == [{"index": 1, "reason": "invalid_field"}]
        for body in (
            b"not json",
            envelope(now, schema="traffic.collector.v2"),
            envelope(now, extra=1),
            envelope(now, records=[good] * 501),
        ):
            resp = await fresh(body)
            assert resp.status == 400, (
                resp.data,
                body if isinstance(body, bytes) else "",
            )
        resp = await fresh(b"x" * (256 * 1024 + 1))
        assert resp.status == 413
    assert len(engine.flows) == 0
    assert engine.collector.counters["accepted_calls"] == 0


# --- Phase K: diagnostics -------------------------------------------------------------


async def test_diagnostics_block_off_reads_nothing(disks) -> None:
    from custom_components.openwrt_router import diagnostics

    hass, _engine, _c = await seeded(disks, on=False)
    with patch.object(out, "status_of", MagicMock(side_effect=AssertionError)):
        block = diagnostics._traffic_summary(hass, "e1")
    assert block == {"loaded": True, "entry_enabled": False, "active": False}
    assert TRAFFIC_COARSE_STORE_KEY not in disks.options
    assert diagnostics._traffic_summary(core_make_hass(), "e1") == {"loaded": False}


async def test_diagnostics_block_has_counts_and_no_identities(disks) -> None:
    from custom_components.openwrt_router import diagnostics

    hass, engine = await collector_on(disks)
    await engine.async_update_settings({"client_sensors": ["cli_" + "1" * 16]})
    block = diagnostics._traffic_summary(hass, "e1")
    assert block["entry_enabled"] is True and block["active"] is True
    assert block["collector"]["enabled"] is True
    assert block["client_sensors"] == 1
    assert "history_store" in block and "capabilities" in block
    text = json.dumps(block, default=str)
    for needle in (*SECRETS, COLLECTOR_ID, "cli_" + "1" * 16):
        assert needle not in text, needle


async def test_diagnostics_wrapper_adds_the_block_and_never_fails(disks) -> None:
    from custom_components.openwrt_router import diagnostics

    hass, engine, _c = await seeded(disks)
    entry = SimpleNamespace(entry_id="e1")
    with patch.object(
        diagnostics,
        "_async_get_config_entry_diagnostics_rf",
        AsyncMock(return_value={"base": 1}),
    ):
        result = await diagnostics.async_get_config_entry_diagnostics(hass, entry)
        assert result["base"] == 1 and result["traffic_analytics"]["active"] is True
        with patch.object(engine, "summary", MagicMock(side_effect=RuntimeError)):
            result = await diagnostics.async_get_config_entry_diagnostics(hass, entry)
    assert result["traffic_analytics"] == {"loaded": False, "error": True}
