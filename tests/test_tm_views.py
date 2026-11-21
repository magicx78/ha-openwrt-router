"""Network Time Machine, Phase A: the route, the wiring and "off stays off".

A real aiohttp application with HA's own view plumbing (401 without login)
and a fake login middleware (header ``X-Test-User``), as in
``test_traffic_views``. Behind it the real sources: enterprise core,
configuration manager and Security Center of the VLAN drift scenario
(``test_tm_sources.drift_env``) plus Network Intelligence fed with WAN
flaps and a client with a wrong key. The router call list comes from the
real ``OpenWrtAPI`` / ``OpenWrtCoordinator`` of ``full_router_kit``. No
router, no HA instance, no network; MACs locally administered, IPs TEST-NET.
"""

from __future__ import annotations

import inspect
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import full_router_kit as kit
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from config_manager_kit import macs, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import ADMIN_ID, USER_ID, FakeDisks
from homeassistant.components.http import KEY_HASS_USER
from homeassistant.helpers.http import KEY_AUTHENTICATED, KEY_HASS
from test_client_engine import client, data
from test_net_correlation import rdata
from test_net_engine import FakeDisk, FakeStore
from test_security_center import ADMIN, wifi
from test_tm_sources import drift_env

import custom_components.openwrt_router as integration
from custom_components.openwrt_router import net_engine, tm_query, tm_sources, tm_views
from custom_components.openwrt_router.config_api import ConfigurationApi
from custom_components.openwrt_router.const import (
    DATA_TIME_MACHINE_STATS,
    DATA_TIME_MACHINE_VIEWS_BOUND,
    OPTION_TIME_MACHINE_ENABLED,
)
from custom_components.openwrt_router.core_models import (
    BackupReason,
    CoreEventType,
    RetentionPolicy,
)
from custom_components.openwrt_router.log_parser import WIFI_PSK_MISMATCH
from custom_components.openwrt_router.net_engine import async_get_net_intelligence
from custom_components.openwrt_router.security_center import (
    async_release_security_center,
)
from custom_components.openwrt_router.topology_panel import (
    _PANEL_ACCESS_KEY,
    _PANEL_VIEW_DISABLED_KEY,
)

GUEST = "02:00:5E:40:00:01"
WAN_UP = {"wan_found": True, "interface": "wan", "up": True, "proto": "dhcp"}
WAN_DOWN = {"wan_found": True, "interface": "wan", "up": False, "proto": "dhcp"}
# No MAC, IP, host name, SSID or WLAN netdev name may leave the route.
SECRETS = (
    GUEST,
    GUEST.lower(),
    *macs(0),
    "10.0.1.1",  # the drifted LAN address (a configuration value)
    "192.168.1.1",  # the router's host
    "192.0.2.",
    "phy1-ap0",
    "phy0-ap0",
    '"Test"',  # the SSID of the NI test interfaces
    '"r1"',  # the router's host name
)


@pytest.fixture
def core_disks():
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
    def __init__(self, test_client: TestClient) -> None:
        self.client = test_client
        self.bodies: list[bytes] = []

    async def get(
        self, *, user: str | None = ADMIN_ID, params: Any = None, **kw: Any
    ) -> Any:
        headers = {"X-Test-User": user} if user else {}
        headers.update(kw.pop("headers", None) or {})
        resp = await self.client.get(
            tm_views.BASE_URL + "/timeline", headers=headers, params=params, **kw
        )
        body = await resp.read()
        self.bodies.append(body)
        return SimpleNamespace(
            status=resp.status,
            headers=resp.headers,
            body=body,
            data=json.loads(body) if body[:1] == b"{" else None,
        )

    def assert_private(self) -> None:
        for needle in SECRETS:
            for body in self.bodies:
                assert needle.encode() not in body, (needle, body[:300])


@asynccontextmanager
async def http(hass: Any) -> AsyncIterator[Http]:
    hass.is_stopping = False
    app = web.Application(middlewares=[_auth_middleware(hass)])
    app[KEY_HASS] = hass
    for view_class in tm_views.TIME_MACHINE_VIEWS:
        view_class().register(hass, app, app.router)
    async with TestClient(TestServer(app)) as test_client:
        yield Http(test_client)


def flap_wan(engine: Any, start: float, polls: int) -> None:
    """WAN up and down on every other poll: ``wan.up`` / ``wan.down`` events."""
    for n in range(polls):
        poll = rdata("gw", wan=WAN_UP if n % 2 == 0 else WAN_DOWN, connected=n % 2 == 0)
        engine.ingest("e1", poll, start + 60 * n, interval=60.0)


def wrong_keys(engine: Any, at: float, count: int, first: int = 1000) -> None:
    """``count`` clients with a wrong key in one poll: client events only."""
    lines = tuple(
        wifi(
            WIFI_PSK_MISMATCH,
            first + i,
            f"02:00:5E:41:{i // 256:02X}:{i % 256:02X}",
            at,
        )
        for i in range(count)
    )
    engine.ingest("e1", data([client(GUEST)], lines), at + 5, interval=60.0)


async def full_env(core_disks: Any, tmp_path: Any, *, on: bool = True) -> Any:
    env, center = await drift_env(core_disks, tmp_path)
    start = env.clock.utc().timestamp()
    with patch.object(
        net_engine, "Store", lambda *a, **kw: FakeStore(FakeDisk(), *a, **kw)
    ):
        engine = await async_get_net_intelligence(env.hass)
    engine.register("e1")
    flap_wan(engine, start, 6)
    wrong_keys(engine, start + 400, 1)
    env.entries[0].options[OPTION_TIME_MACHINE_ENABLED] = on
    return SimpleNamespace(env=env, center=center, engine=engine, start=start)


def around(world: Any, days: float = 1.0) -> dict[str, str]:
    return {
        "from": str(int(world.start - 3600)),
        "until": str(int(world.start + days * 86_400)),
    }


async def close(world: Any) -> None:
    await stop(world.env)
    await async_release_security_center(world.env.hass, world.env.entries[0].entry_id)


def listeners(world: Any) -> tuple[int, ...]:
    return (
        world.env.core.audit.listener_count,
        *(c.listener_count for c in world.env.coords.values()),
        len(getattr(world.engine, "_poll_observers", ())),
    )


# --- route ------------------------------------------------------------------------------


def test_one_get_route_that_needs_a_login() -> None:
    [view] = tm_views.TIME_MACHINE_VIEWS
    assert view.url == "/api/openwrt_router/enterprise/timemachine/timeline"
    assert view.name == "api:openwrt_router:enterprise:timemachine:timeline"
    assert view.requires_auth is True
    for method in ("post", "put", "patch", "delete"):
        assert not hasattr(view, method), method


async def test_access_order_401_403_410(core_disks, tmp_path) -> None:
    world = await full_env(core_disks, tmp_path)
    hass = world.env.hass
    async with http(hass) as h:
        assert (await h.get(user=None)).status == 401
        denied = await h.get(user=USER_ID, params={"mac": "x"})
        assert denied.status == 403  # before the query check
        assert denied.data["code"] == "authorization_denied"
        assert denied.headers["Cache-Control"] == "no-store"
        hass.data[_PANEL_VIEW_DISABLED_KEY] = True
        assert (await h.get(user=USER_ID)).status == 403  # 403 before 410
        gone = await h.get(params={"mac": "x"})
        assert (gone.status, gone.data["code"]) == (410, "integration_not_loaded")
        del hass.data[_PANEL_VIEW_DISABLED_KEY]
        hass.data[_PANEL_ACCESS_KEY] = {"e1": True}
        assert (await h.get(user=USER_ID, params=around(world))).status == 200
    await close(world)


@pytest.mark.parametrize(
    ("params", "field", "reason"),
    [
        ({"mac": "02:00:5e:40:00:01"}, "query", "unknown_key"),
        ([("limit", "5"), ("limit", "6")], "limit", "repeated"),
        ({"kind": "k" * 200}, "kind", "too_long"),
        ({"from": "<script>alert(1)</script>"}, "from", "invalid"),
        ({"from": "1000", "until": "999"}, "window", "empty"),
        ({"from": "1000", "until": "2000000"}, "window", "too_large"),
        ({"source": "ni_events,recorder"}, "source", "unknown"),
        ({"router_id": "e1-and-more"}, "router_id", "invalid"),
        ({"kind": "client_secret"}, "kind", "unknown"),
        ({"min_severity": "loud"}, "min_severity", "unknown"),
        ({"limit": "501"}, "limit", "out_of_range"),
    ],
)
async def test_bad_queries_are_400_without_echo(
    core_disks, tmp_path, params: Any, field: str, reason: str
) -> None:
    world = await full_env(core_disks, tmp_path, on=False)  # checked while off too
    async with http(world.env.hass) as h:
        resp = await h.get(params=params)
    assert resp.status == 400
    assert resp.data == {
        "message": "The request is not valid",
        "code": "invalid_request",
        "details": {"field": field, "reason": reason},
    }
    for value in params.values() if isinstance(params, dict) else []:
        if len(value) > 4:
            assert value.encode() not in resp.body
    await close(world)


async def test_a_body_is_refused(core_disks, tmp_path) -> None:
    world = await full_env(core_disks, tmp_path)
    async with http(world.env.hass) as h:
        resp = await h.get(
            data=b'{"x": 1}', headers={"Content-Type": "application/json"}
        )
    assert resp.status == 400
    assert resp.data["details"] == {"field": "body", "reason": "unknown_key"}
    await close(world)


async def test_a_body_over_4_kib_is_413(core_disks, tmp_path) -> None:
    world = await full_env(core_disks, tmp_path)
    async with http(world.env.hass) as h:
        resp = await h.get(
            data=b"{" + b" " * 5000 + b"}",
            headers={"Content-Type": "application/json"},
        )
    assert resp.status == 413
    assert resp.data["code"] == "body_too_large"
    assert resp.headers["Cache-Control"] == "no-store"
    await close(world)


# --- off stays off ----------------------------------------------------------------------


async def test_off_answers_off_and_reads_registers_and_stores_nothing(
    core_disks, tmp_path
) -> None:
    world = await full_env(core_disks, tmp_path, on=False)
    hass = world.env.hass
    before = (listeners(world), set(core_disks.disks), set(hass.data))

    async def no_read(*_a: Any) -> Any:
        raise AssertionError("a source was read while off")

    with (
        patch.dict(tm_sources.READERS, dict.fromkeys(tm_sources.SOURCE_IDS, no_read)),
        patch.object(tm_query, "build_router_map", side_effect=AssertionError),
        patch.object(
            ConfigurationApi,
            "async_get_module_key",
            AsyncMock(side_effect=AssertionError),
        ),
    ):
        async with http(hass) as h:
            resp = await h.get(params=around(world))
            hass.data[_PANEL_ACCESS_KEY] = {"e1": True}
            plain = await h.get(user=USER_ID)
    assert resp.status == 200 and plain.status == 200
    assert resp.data == {
        "v": 1,
        "status": "off",
        "generated_at": resp.data["generated_at"],
        "window": {"from": None, "until": None},
        "marks": [],
        "sources": [],
        "omitted_client_marks": 0,
        "truncated": False,
        "next_until": None,
    }
    assert plain.data["status"] == "off"
    hass.data.pop(_PANEL_ACCESS_KEY)
    assert listeners(world) == before[0]
    assert set(core_disks.disks) == before[1]
    assert DATA_TIME_MACHINE_STATS not in hass.data
    assert set(hass.data) == before[2]
    await close(world)


# --- on -------------------------------------------------------------------------------


async def test_admin_gets_every_source_merged_and_private(core_disks, tmp_path) -> None:
    world = await full_env(core_disks, tmp_path)
    hass = world.env.hass
    before = (listeners(world), set(core_disks.disks))
    with patch.object(
        ConfigurationApi, "async_get_module_key", AsyncMock(side_effect=AssertionError)
    ) as key:
        async with http(hass) as h:
            resp = await h.get(params=around(world))
            h.assert_private()
    key.assert_not_called()
    assert resp.status == 200 and resp.headers["Cache-Control"] == "no-store"
    body = resp.data
    assert body["v"] == 1 and body["status"] == "ok"
    states = {s["id"]: s["state"] for s in body["sources"]}
    assert states == dict.fromkeys(tm_sources.SOURCE_IDS, "ok")
    kinds = {m["kind"] for m in body["marks"]}
    assert {"config_drift", "config_version", "config_event", "wan_event"} <= kinds
    assert body["omitted_client_marks"] >= 1  # the client with the wrong key
    assert {s["id"]: s["count"] for s in body["sources"]} == {
        src: sum(1 for m in body["marks"] if m["source"] == src)
        for src in tm_sources.SOURCE_IDS
    }
    routers = {m["router_id"] for m in body["marks"]} - {None}
    assert routers == {world.env.rid}
    assert {m["router_name"] for m in body["marks"] if m["router_id"]} == {"Router e1"}
    ts = [m["ts"] for m in body["marks"]]
    assert ts == sorted(ts, reverse=True)
    # still no listener, no store, no router call
    assert listeners(world) == before[0]
    assert set(core_disks.disks) == before[1]
    assert world.env.router_calls() == []
    assert hass.data[DATA_TIME_MACHINE_STATS].requests == 1
    await close(world)


async def test_non_admin_with_an_open_panel_sees_infrastructure_and_disruptions(
    core_disks, tmp_path
) -> None:
    world = await full_env(core_disks, tmp_path)
    world.env.hass.data[_PANEL_ACCESS_KEY] = {"e1": True}
    async with http(world.env.hass) as h:
        resp = await h.get(user=USER_ID, params=around(world))
        admin = await h.get(params=around(world))
        h.assert_private()
    assert resp.status == 200
    by_id = {s["id"]: s for s in resp.data["sources"]}
    for source in ("core_audit", "config_versions"):
        assert (by_id[source]["state"], by_id[source]["reason"]) == (
            "off",
            "admin_only",
        )
    groups = {m["group"] for m in resp.data["marks"]}
    assert groups and groups <= tm_sources.NON_ADMIN_GROUPS
    assert not [m for m in resp.data["marks"] if m["kind"].startswith("config_")]
    assert len(resp.data["marks"]) < len(admin.data["marks"])
    # 1.50.0: the count of left-out client entries is for administrators only
    assert admin.data["omitted_client_marks"] >= 1
    assert resp.data["omitted_client_marks"] == 0
    await close(world)


async def test_filters_reach_the_answer(core_disks, tmp_path) -> None:
    world = await full_env(core_disks, tmp_path)
    async with http(world.env.hass) as h:
        only = await h.get(
            params={**around(world), "source": "ni_events", "kind": "wan_event"}
        )
        sev = await h.get(params={**around(world), "min_severity": "warning"})
        other = await h.get(params={**around(world), "router_id": "rtr_" + "f" * 32})
        page = await h.get(params={**around(world), "limit": "2"})
    assert [s["id"] for s in only.data["sources"]] == ["ni_events"]
    assert only.data["marks"] and {m["kind"] for m in only.data["marks"]} == {
        "wan_event"
    }
    assert all(m["severity"] in ("warning", "critical") for m in sev.data["marks"])
    assert other.data["marks"] == []
    assert len(page.data["marks"]) <= 2 and page.data["truncated"] is True
    assert page.data["next_until"] == page.data["marks"][-1]["ts"]
    await close(world)


async def test_a_failing_source_leaves_a_partial_answer(
    core_disks, tmp_path, caplog
) -> None:
    world = await full_env(core_disks, tmp_path)
    with (
        caplog.at_level("DEBUG"),
        patch.object(world.center, "overview", side_effect=RuntimeError(GUEST)),
    ):
        async with http(world.env.hass) as h:
            resp = await h.get(params=around(world))
    assert resp.status == 200 and resp.data["status"] == "partial"
    by_id = {s["id"]: s for s in resp.data["sources"]}
    assert (
        by_id["security_timeline"]["state"],
        by_id["security_timeline"]["reason"],
    ) == (
        "unreadable",
        "error",
    )
    assert by_id["core_audit"]["state"] == "ok"
    assert GUEST not in caplog.text and "RuntimeError" in caplog.text
    assert world.env.hass.data[DATA_TIME_MACHINE_STATS].unreadable == {
        "security_timeline": 1
    }
    await close(world)


async def test_an_internal_error_is_a_500_that_logs_the_type_only(
    core_disks, tmp_path, caplog
) -> None:
    world = await full_env(core_disks, tmp_path)
    with (
        caplog.at_level("WARNING"),
        patch.object(tm_views, "async_timeline", side_effect=ValueError(GUEST)),
    ):
        async with http(world.env.hass) as h:
            resp = await h.get(params=around(world))
    assert (resp.status, resp.data["code"]) == (500, "internal")
    assert "ValueError" in caplog.text and GUEST not in caplog.text
    await close(world)


def test_the_time_machine_never_asks_for_a_module_key_or_listens() -> None:
    """Static guard: no module key, no listener, no task, no store, no dispatcher."""
    for module in (tm_sources, tm_query, tm_views):
        code = inspect.getsource(module)
        for needle in (
            "async_get_module_key",
            "async_dispatcher_connect",
            "async_add_listener",
            "async_track_",
            "subscribe(",
            "create_task",
            "create_background_task",
            "Store(",
            "bus.async_listen",
        ):
            assert needle not in code, (module.__name__, needle)


# --- router calls -------------------------------------------------------------------------


async def test_two_polls_make_the_same_router_calls_with_the_time_machine_on(
    core_disks, tmp_path
) -> None:
    off_calls: list[Any] = []
    await kit.full_polls(kit.make_coordinator(MagicMock(), kit.make_api(off_calls)))

    world = await full_env(core_disks, tmp_path)
    on_calls: list[Any] = []
    coordinator = kit.make_coordinator(world.env.hass, kit.make_api(on_calls))
    async with http(world.env.hass) as h:
        assert (await h.get(params=around(world))).data["status"] == "ok"
        await kit.full_polls(coordinator)
        polled = len(on_calls)
        assert (await h.get(params=around(world))).data["status"] == "ok"
    assert len(on_calls) == polled  # a timeline request makes no router call
    assert on_calls == off_calls
    assert coordinator._listeners == {}
    await close(world)


# --- response time with realistically filled sources --------------------------------


async def test_response_time_with_filled_sources(core_disks, tmp_path, capsys) -> None:
    world = await full_env(core_disks, tmp_path)
    env, base = world.env, env_now(world)
    # audit: the general ring full (1000)
    for i in range(1000):
        env.core.audit.emit(
            CoreEventType.ROUTER_CAPABILITIES_CHANGED,
            router_id=env.rid,
            dedup_key=f"p{i}",
            now=base + timedelta(seconds=30 * i),
        )
    # configuration versions: three dozen, each a real backup of a changed config
    env.api.set_retention_policy(RetentionPolicy(max_versions=100), module="test")
    for i in range(36):
        env.clock.advance(minutes=20)
        env.provider.live(env.rid)["system"]["@system[0]"]["hostname"] = f"h{i}"
        await env.api.async_create_backup(
            env.rid, reason=BackupReason.MANUAL, actor=ADMIN
        )
    # Security Center timeline: 2000 entries (a quarter about a client)
    start = base.timestamp()
    for i in range(2000):
        world.center._timeline(
            start + 20 * i,
            "notice" if i % 4 == 0 else "status",
            category="device" if i % 4 == 0 else "system",
            severity="warning",
            router_id=env.rid,
            text="Status: resolved",
            client=GUEST if i % 4 == 0 else None,
        )
    # Network Intelligence: a few hundred events
    flap_wan(world.engine, start + 7200, 200)
    wrong_keys(world.engine, start + 20_000, 150, first=5000)
    assert len(env.core.audit.events(limit=None)) >= 1000
    assert len(world.center.timeline) == 2000
    assert len(world.engine.ring) >= 300
    params = {
        "from": str(int(start - 3600)),
        "until": str(int(start + 13 * 86_400)),
        "limit": "500",
    }
    async with http(env.hass) as h:
        began = time.perf_counter()
        resp = await h.get(params=params)
        elapsed = time.perf_counter() - began
    assert resp.status == 200 and resp.data["status"] == "ok"
    # a full page (one second is never split, so a few marks may wait)
    assert 450 <= len(resp.data["marks"]) <= 500
    assert resp.data["truncated"] is True and resp.data["next_until"] is not None
    stats = env.hass.data[DATA_TIME_MACHINE_STATS]
    with capsys.disabled():
        print(
            f"\n[time machine] {elapsed * 1000:.0f} ms over HTTP "
            f"({stats.last_duration_ms} ms reading and merging), "
            f"{len(resp.body)} bytes, {len(resp.data['marks'])} marks"
        )
    assert elapsed < 2.0  # generous: measured ~0.1 s on the dev VM
    await close(world)


def env_now(world: Any) -> Any:
    return world.env.clock.utc()


# --- wiring -------------------------------------------------------------------------


async def test_setup_registers_the_route_once_and_never_fails() -> None:
    hass = MagicMock()
    hass.data = {}
    entry = MagicMock()
    with patch.object(
        integration, "_async_setup_entry_traffic", AsyncMock(return_value=True)
    ):
        assert await integration.async_setup_entry(hass, entry) is True
        assert await integration.async_setup_entry(hass, entry) is True
        assert hass.http.register_view.call_count == 1
        assert hass.data[DATA_TIME_MACHINE_VIEWS_BOUND] == {
            tm_views.TimeMachineTimelineView.name
        }
        broken = MagicMock()
        broken.data = {}
        broken.http.register_view.side_effect = RuntimeError("boom")
        assert await integration.async_setup_entry(broken, entry) is True
    with patch.object(
        integration, "_async_setup_entry_traffic", AsyncMock(return_value=False)
    ):
        fresh = MagicMock()
        fresh.data = {}
        assert await integration.async_setup_entry(fresh, entry) is False
        fresh.http.register_view.assert_not_called()


def test_no_http_no_route() -> None:
    hass = SimpleNamespace(data={})
    tm_views.async_register_time_machine_views(hass)  # type: ignore[arg-type]
    assert hass.data == {}
